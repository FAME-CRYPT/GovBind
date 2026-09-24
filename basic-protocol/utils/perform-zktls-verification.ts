import { spawn } from 'node:child_process';
import { mkdir, unlink } from 'node:fs/promises';
import path from 'node:path';

import type { PreparedVerificationSession } from './prepare-verification-session';
import { computeVerificationContentHash } from './compute-verification-content-hash';

const projectDirectory = path.resolve(__dirname, '..', '..');
const proverPath = path.join(
  projectDirectory,
  'native',
  'zktls',
  'target',
  'release',
  'govbind-basic-zktls-prover',
);
const verificationDirectory = path.join(
  projectDirectory,
  'uploads',
  'verification',
);
const DEFAULT_NOTARY_ADDRESS = '127.0.0.1:8000';
const PROCESS_TIMEOUT_MS = 15 * 60_000;
const MAX_STDOUT_BYTES = 2 * 1024 * 1024;
const MAX_STDERR_BYTES = 64 * 1024;

export interface PerformZkTlsVerificationOptions {
  session: PreparedVerificationSession;
  expectedContentHash: string;
}

export interface ZkTlsVerificationResult {
  pdfPath: string;
  commitmentHex: string;
  blinderHex: string;
  pdfSha256Hex: string;
  attestation: Buffer;
  presentation: Buffer;
}

interface NativeVerificationResult {
  version: string;
  commitmentHex: string;
  blinderHex: string;
  pdfSha256Hex: string;
  attestationBase64: string;
  presentationBase64: string;
}

function decodeArtifact(value: unknown, name: string): Buffer {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > MAX_STDOUT_BYTES ||
    !/^[A-Za-z0-9+/]+={0,2}$/.test(value)
  ) {
    throw new Error(`TLSNotary returned an invalid ${name}.`);
  }

  const artifact = Buffer.from(value, 'base64');
  if (artifact.length === 0 || artifact.length > MAX_STDOUT_BYTES) {
    throw new Error(`TLSNotary returned an invalid ${name}.`);
  }
  return artifact;
}

function parseNativeResult(stdout: string): Omit<ZkTlsVerificationResult, 'pdfPath'> {
  let parsed: unknown;

  try {
    parsed = JSON.parse(stdout);
  } catch {
    throw new Error('TLSNotary prover returned invalid JSON.');
  }

  if (!parsed || typeof parsed !== 'object') {
    throw new Error('TLSNotary prover returned invalid verification metadata.');
  }
  const value = parsed as NativeVerificationResult;

  if (
    value.version !== 'zk-devlet-zktls-verification-v1' ||
    !/^[0-9a-f]{64}$/.test(value.commitmentHex) ||
    !/^[0-9a-f]{32}$/.test(value.blinderHex) ||
    !/^[0-9a-f]{64}$/.test(value.pdfSha256Hex)
  ) {
    throw new Error('TLSNotary prover returned invalid verification metadata.');
  }

  return {
    commitmentHex: value.commitmentHex,
    blinderHex: value.blinderHex,
    pdfSha256Hex: value.pdfSha256Hex,
    attestation: decodeArtifact(value.attestationBase64, 'attestation'),
    presentation: decodeArtifact(value.presentationBase64, 'presentation'),
  };
}

async function runProver(
  session: PreparedVerificationSession,
  outputPath: string,
): Promise<Omit<ZkTlsVerificationResult, 'pdfPath'>> {
  const notaryAddress = process.env.TLSN_NOTARY_ADDR ?? DEFAULT_NOTARY_ADDRESS;
  const notaryPublicKey = process.env.TLSN_NOTARY_PUBLIC_KEY;

  if (!notaryPublicKey || !/^[0-9a-f]{66}$/i.test(notaryPublicKey)) {
    throw new Error('The trusted TLSNotary public key has not been initialized.');
  }

  return new Promise((resolve, reject) => {
    const child = spawn(proverPath, ['--notary', notaryAddress], {
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let stdoutLength = 0;
    let stderrLength = 0;
    let settled = false;

    const finish = (error?: Error): void => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);

      if (error) {
        reject(error);
        return;
      }

      try {
        resolve(parseNativeResult(Buffer.concat(stdout).toString('utf8')));
      } catch (parseError) {
        reject(parseError);
      }
    };

    const timer = setTimeout(() => {
      child.kill('SIGTERM');
      finish(new Error('TLSNotary prover timed out.'));
    }, PROCESS_TIMEOUT_MS);

    child.once('error', (error) => {
      finish(new Error(`Could not start the TLSNotary prover: ${error.message}`));
    });
    child.stdin.once('error', (error) => {
      finish(new Error(`Could not send input to the TLSNotary prover: ${error.message}`));
    });
    child.stdout.on('data', (chunk: Buffer) => {
      stdoutLength += chunk.length;
      if (stdoutLength > MAX_STDOUT_BYTES) {
        child.kill('SIGTERM');
        finish(new Error('TLSNotary prover output exceeded its size limit.'));
        return;
      }
      stdout.push(chunk);
    });
    child.stderr.on('data', (chunk: Buffer) => {
      stderrLength += chunk.length;
      if (stderrLength <= MAX_STDERR_BYTES) {
        stderr.push(chunk);
      }
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
        return;
      }
      finish();
    });

    child.stdin.end(
      JSON.stringify({
        cookie: session.cookie,
        referer: session.referer,
        outputPath,
        notaryPublicKeyHex: notaryPublicKey.toLowerCase(),
      }),
    );
  });
}

export async function performZkTlsVerification({
  session,
  expectedContentHash,
}: PerformZkTlsVerificationOptions): Promise<ZkTlsVerificationResult> {
  if (!/^[0-9a-f]{64}$/.test(expectedContentHash)) {
    throw new Error('The expected zkPDF content hash is invalid.');
  }

  await mkdir(verificationDirectory, { recursive: true });
  const pdfPath = path.join(verificationDirectory, `${expectedContentHash}.pdf`);

  try {
    const result = await runProver(session, pdfPath);
    const actualContentHash = await computeVerificationContentHash(pdfPath);
    if (actualContentHash !== expectedContentHash) {
      throw new Error(
        'The TLSNotary-authenticated PDF does not match the uploaded document content.',
      );
    }

    return { pdfPath, ...result };
  } catch (error) {
    await unlink(pdfPath).catch(() => undefined);
    throw error;
  }
}
