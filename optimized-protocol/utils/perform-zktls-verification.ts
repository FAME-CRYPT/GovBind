import { spawn } from 'node:child_process';
import path from 'node:path';

import type { PreparedVerificationSession } from './prepare-verification-session';
import {
  getDocumentProfileByTlsProfile,
  type PrivateRangeKind,
  type TlsPdfProfile,
} from './document-profiles';

const projectDirectory = path.resolve(__dirname, '..', '..');
const proverPath = path.join(
  projectDirectory,
  'native',
  'zktls',
  'target',
  'release',
  'govbind-optimized-zktls-prover',
);
const DEFAULT_NOTARY_ADDRESS = '127.0.0.1:8000';
const PROCESS_TIMEOUT_MS = 15 * 60_000;
const MAX_STDOUT_BYTES = 4 * 1024 * 1024;
const MAX_CAPTURE_STDOUT_BYTES = 24 * 1024 * 1024;
const MAX_STDERR_BYTES = 64 * 1024;

export interface AuthenticatedPrivateRange {
  kind: PrivateRangeKind;
  offset: number;
  length: number;
  commitmentHex: string;
}

export interface ZkTlsVerificationResult {
  profile: TlsPdfProfile;
  responseBodyBytes: number;
  contentStream: Buffer;
  contentBlinderHex: string;
  cityEncodingHex?: string;
  privateRanges: AuthenticatedPrivateRange[];
  presentation: Buffer;
  peakRssBytes?: number;
}

export interface ZkTlsBenchmarkResult extends ZkTlsVerificationResult {
  benchmarkMs: number;
}

export interface ZkTlsBenchmarkCapture {
  captureIdHex: string;
  proverCaptureBase64: string;
}

export interface ZkTlsPerformanceOptions {
  measurePeakRss?: boolean;
}

interface NativeVerificationResult {
  version: string;
  profile: string;
  responseBodyBytes: number;
  cityEncodingHex?: string | null;
  contentStreamBase64: string;
  contentBlinderHex: string;
  privateRanges: unknown;
  presentationBase64: string;
  benchmarkMs?: number;
}

interface NativeBenchmarkCapture {
  version: string;
  captureIdHex: string;
  proverCaptureBase64: string;
}

function decodeArtifact(
  value: unknown,
  name: string,
  maximumBytes = MAX_STDOUT_BYTES,
): Buffer {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > Math.ceil(maximumBytes * 4 / 3) + 4 ||
    !/^[A-Za-z0-9+/]+={0,2}$/.test(value)
  ) {
    throw new Error(`TLSNotary returned an invalid ${name}.`);
  }
  const artifact = Buffer.from(value, 'base64');
  if (artifact.length === 0 || artifact.length > maximumBytes) {
    throw new Error(`TLSNotary returned an invalid ${name}.`);
  }
  return artifact;
}

function parsePrivateRanges(
  value: unknown,
  expectedKinds: readonly PrivateRangeKind[],
): AuthenticatedPrivateRange[] {
  if (!Array.isArray(value) || value.length !== expectedKinds.length) {
    throw new Error('TLSNotary returned an invalid private-range partition.');
  }
  return value.map((candidate, index) => {
    if (!candidate || typeof candidate !== 'object') {
      throw new Error('TLSNotary returned an invalid private range.');
    }
    const range = candidate as Partial<AuthenticatedPrivateRange>;
    if (
      range.kind !== expectedKinds[index] ||
      !Number.isSafeInteger(range.offset) ||
      range.offset! < 0 ||
      !Number.isSafeInteger(range.length) ||
      range.length! <= 0 ||
      !/^[0-9a-f]{64}$/.test(range.commitmentHex ?? '')
    ) {
      throw new Error('TLSNotary returned an invalid private range.');
    }
    return range as AuthenticatedPrivateRange;
  });
}

function parseNativeValue(
  parsed: unknown,
  profile: TlsPdfProfile,
): ZkTlsVerificationResult & { benchmarkMs?: number } {
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('TLSNotary prover returned invalid verification metadata.');
  }
  const value = parsed as NativeVerificationResult;
  if (
    value.version !== 'zk-devlet-zktls-verification-v2' ||
    value.profile !== profile ||
    !Number.isSafeInteger(value.responseBodyBytes) ||
    value.responseBodyBytes < 1 ||
    value.responseBodyBytes > 4 * 1024 * 1024 ||
    !/^[0-9a-f]{32}$/.test(value.contentBlinderHex)
  ) {
    throw new Error('TLSNotary prover returned invalid verification metadata.');
  }
  const profileDefinition = getDocumentProfileByTlsProfile(profile);
  const privateRanges = parsePrivateRanges(
    value.privateRanges,
    profileDefinition.privateRangeKinds,
  );
  const contentRange = privateRanges.find((range) => range.kind === 'content-stream');
  if (!contentRange) throw new Error('TLSNotary returned no content-stream range.');
  const contentStream = decodeArtifact(
    value.contentStreamBase64,
    'private content stream',
    profileDefinition.maximumCompressedLength,
  );
  if (contentStream.length !== contentRange.length) {
    throw new Error('TLSNotary content stream does not match its signed range.');
  }
  const cityEncodingHex = value.cityEncodingHex ?? undefined;
  if (profileDefinition.documentType === 'residence') {
    if (!/^(?:[0-9a-f]{4}){1,16}$/.test(cityEncodingHex ?? '')) {
      throw new Error('TLSNotary returned an invalid residence city encoding.');
    }
  } else if (cityEncodingHex !== undefined) {
    throw new Error('TLSNotary returned unexpected city metadata.');
  }
  return {
    profile,
    responseBodyBytes: value.responseBodyBytes,
    contentStream,
    contentBlinderHex: value.contentBlinderHex,
    ...(cityEncodingHex ? { cityEncodingHex } : {}),
    privateRanges,
    presentation: decodeArtifact(value.presentationBase64, 'presentation'),
    ...(value.benchmarkMs !== undefined ? { benchmarkMs: value.benchmarkMs } : {}),
  };
}

function parseNativeResult(
  stdout: string,
  profile: TlsPdfProfile,
): ZkTlsVerificationResult & { benchmarkMs?: number } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    throw new Error('TLSNotary prover returned invalid JSON.');
  }
  return parseNativeValue(parsed, profile);
}

function parseBenchmarkCapture(stdout: string): ZkTlsBenchmarkCapture {
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    throw new Error('TLSNotary prover returned invalid benchmark capture JSON.');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('TLSNotary prover returned invalid benchmark capture metadata.');
  }
  const value = parsed as NativeBenchmarkCapture;
  if (
    value.version !== 'zk-devlet-zktls-benchmark-capture-v1' ||
    !/^[0-9a-f]{64}$/.test(value.captureIdHex) ||
    typeof value.proverCaptureBase64 !== 'string' ||
    value.proverCaptureBase64.length === 0 ||
    value.proverCaptureBase64.length > MAX_CAPTURE_STDOUT_BYTES ||
    !/^[A-Za-z0-9+/]+={0,2}$/.test(value.proverCaptureBase64)
  ) {
    throw new Error('TLSNotary prover returned invalid benchmark capture metadata.');
  }
  return {
    captureIdHex: value.captureIdHex,
    proverCaptureBase64: value.proverCaptureBase64,
  };
}

function parsePeakRss(stderr: string): number {
  const match = stderr.match(/(?:^|\n)\s*(\d+)\s+maximum resident set size(?:\s|$)/u);
  if (!match) throw new Error('Could not read peak memory from /usr/bin/time -l output.');
  return Number(match[1]);
}

async function runZkTlsProver(
  session: PreparedVerificationSession,
  options: { profile: TlsPdfProfile; city?: string; identityNumber?: string },
  performance: ZkTlsPerformanceOptions = {},
  benchmarkMode?: 'capture' | 'replay',
  capture?: ZkTlsBenchmarkCapture,
): Promise<(ZkTlsVerificationResult & { benchmarkMs?: number }) | ZkTlsBenchmarkCapture> {
  const notaryAddress = process.env.TLSN_NOTARY_ADDR ?? DEFAULT_NOTARY_ADDRESS;
  const notaryPublicKey = process.env.TLSN_NOTARY_PUBLIC_KEY;
  if (!notaryPublicKey || !/^[0-9a-f]{66}$/i.test(notaryPublicKey)) {
    throw new Error('The trusted TLSNotary public key has not been initialized.');
  }

  return new Promise((resolve, reject) => {
    const measurePeakRss = performance.measurePeakRss === true;
    const child = spawn(
      measurePeakRss ? '/usr/bin/time' : proverPath,
      measurePeakRss
        ? [
          '-l', proverPath, '--notary', notaryAddress,
          ...(benchmarkMode === 'capture' ? ['--benchmark-capture'] : []),
          ...(benchmarkMode === 'replay' ? ['--benchmark-replay'] : []),
        ]
        : [
          '--notary', notaryAddress,
          ...(benchmarkMode === 'capture' ? ['--benchmark-capture'] : []),
          ...(benchmarkMode === 'replay' ? ['--benchmark-replay'] : []),
        ],
      {
        stdio: ['pipe', 'pipe', 'pipe'],
      },
    );
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let stdoutLength = 0;
    let stderrLength = 0;
    let settled = false;

    const finish = (error?: Error): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) {
        reject(error);
        return;
      }
      try {
        const output = Buffer.concat(stdout).toString('utf8');
        if (benchmarkMode === 'capture') {
          resolve(parseBenchmarkCapture(output));
          return;
        }
        const result = parseNativeResult(output, options.profile);
        if (benchmarkMode === 'replay' &&
          (!Number.isFinite(result.benchmarkMs) || result.benchmarkMs! < 0)) {
          throw new Error('TLSNotary prover returned invalid benchmark timing metadata.');
        }
        const peakRssBytes = measurePeakRss
          ? parsePeakRss(Buffer.concat(stderr).toString('utf8'))
          : undefined;
        resolve({
          ...result,
          ...(peakRssBytes !== undefined ? { peakRssBytes } : {}),
        });
      } catch (parseError) {
        reject(parseError);
      }
    };

    const timeoutMs = PROCESS_TIMEOUT_MS;
    const timer = setTimeout(() => {
      child.kill('SIGTERM');
      finish(new Error('TLSNotary prover timed out.'));
    }, timeoutMs);
    child.once('error', (error) =>
      finish(new Error(`Could not start the TLSNotary prover: ${error.message}`)),
    );
    child.stdin.once('error', (error) =>
      finish(new Error(`Could not send input to the TLSNotary prover: ${error.message}`)),
    );
    child.stdout.on('data', (chunk: Buffer) => {
      stdoutLength += chunk.length;
      const maximumStdout = benchmarkMode === 'capture'
        ? MAX_CAPTURE_STDOUT_BYTES
        : MAX_STDOUT_BYTES;
      if (stdoutLength > maximumStdout) {
        child.kill('SIGTERM');
        finish(new Error('TLSNotary prover output exceeded its size limit.'));
      } else {
        stdout.push(chunk);
      }
    });
    child.stderr.on('data', (chunk: Buffer) => {
      stderrLength += chunk.length;
      if (stderrLength <= MAX_STDERR_BYTES) stderr.push(chunk);
    });
    child.once('close', (code, signal) => {
      if (code !== 0) {
        const details = Buffer.concat(stderr).toString('utf8').trim();
        finish(
          new Error(
            `TLSNotary prover failed${
              signal ? ` with signal ${signal}` : ` with exit code ${code ?? 'unknown'}`
            }${details ? `: ${details}` : ''}`,
          ),
        );
      } else {
        finish();
      }
    });

    child.stdin.end(JSON.stringify({
      profile: options.profile,
      ...(options.city ? { city: options.city } : {}),
      ...(options.identityNumber ? { identityNumber: options.identityNumber } : {}),
      cookie: session.cookie,
      referer: session.referer,
      ...(session.requestTarget ? { requestTarget: session.requestTarget } : {}),
      notaryPublicKeyHex: notaryPublicKey.toLowerCase(),
      ...(capture ? { benchmarkCaptureBase64: capture.proverCaptureBase64 } : {}),
    }));
  });
}

export async function performZkTlsVerification(
  session: PreparedVerificationSession,
  options: { profile: TlsPdfProfile; city?: string; identityNumber?: string },
  performance: ZkTlsPerformanceOptions = {},
): Promise<ZkTlsVerificationResult> {
  return runZkTlsProver(session, options, performance) as Promise<ZkTlsVerificationResult>;
}

export async function captureZkTlsBenchmark(
  session: PreparedVerificationSession,
  options: { profile: TlsPdfProfile; city?: string; identityNumber?: string },
): Promise<ZkTlsBenchmarkCapture> {
  return runZkTlsProver(session, options, {}, 'capture') as Promise<ZkTlsBenchmarkCapture>;
}

export async function performZkTlsBenchmark(
  session: PreparedVerificationSession,
  options: { profile: TlsPdfProfile; city?: string; identityNumber?: string },
  capture: ZkTlsBenchmarkCapture,
  performance: ZkTlsPerformanceOptions = {},
): Promise<ZkTlsBenchmarkResult> {
  return runZkTlsProver(
    session,
    options,
    performance,
    'replay',
    capture,
  ) as Promise<ZkTlsBenchmarkResult>;
}
