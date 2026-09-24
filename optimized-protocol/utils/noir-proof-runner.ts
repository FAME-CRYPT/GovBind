import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, readFile, rm, unlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import type { NoirProgram } from './document-profiles';
import {
  isNoirProgramIdentity,
  type NoirProgramIdentity,
} from './proof-record-types';
import { serializeProving } from './proving-queue';

const projectDirectory = path.resolve(__dirname, '..', '..');
const runtimeDirectory = path.join(projectDirectory, '.runtime', 'proving');
const PROCESS_TIMEOUT_MS = 15 * 60_000;
const MAX_PROCESS_OUTPUT = 128 * 1024;

export interface CommitmentOpening {
  contentStream: Buffer;
  blinderHex: string;
  commitmentHex: string;
}

export interface NoirProofResult<Program extends NoirProgram> {
  proof: Buffer;
  publicInputs: Buffer;
  programIdentity: NoirProgramIdentity & { program: Program };
  performance: {
    generationMs: number;
    selfVerificationMs: number;
    totalMs: number;
    peakRssBytes?: number;
  };
}

export interface NoirPerformanceOptions {
  measurePeakRss?: boolean;
}

interface CircuitConfig<Program extends NoirProgram> {
  circuitDirectory: string;
  artifactName: string;
  witnessBuilderName: string;
  noirProgram: Program;
  maximumCompressedLength: number;
}

interface RunProofOptions extends CommitmentOpening {
  witnessArguments: string[];
  claimPublicU64s: bigint[];
}

function sha256(bytes: Buffer): string {
  return createHash('sha256').update(bytes).digest('hex');
}

function toolPath(environmentName: 'NARGO_BIN' | 'BB_BIN'): string {
  const configured = process.env[environmentName];
  if (configured) return configured;
  const candidate = environmentName === 'NARGO_BIN'
    ? path.join(os.homedir(), '.nargo', 'bin', 'nargo')
    : path.join(os.homedir(), '.bb', 'bb');
  return existsSync(candidate)
    ? candidate
    : environmentName === 'NARGO_BIN' ? 'nargo' : 'bb';
}

interface ProcessResult {
  elapsedMs: number;
  peakRssBytes?: number;
}

function parsePeakRss(stderr: string): number {
  const match = stderr.match(/(?:^|\n)\s*(\d+)\s+maximum resident set size(?:\s|$)/u);
  if (!match) throw new Error('Could not read peak memory from /usr/bin/time -l output.');
  return Number(match[1]);
}

function runProcess(
  executable: string,
  args: string[],
  cwd: string,
  measurePeakRss = false,
): Promise<ProcessResult> {
  return new Promise((resolve, reject) => {
    const startedAt = process.hrtime.bigint();
    const child = spawn(
      measurePeakRss ? '/usr/bin/time' : executable,
      measurePeakRss ? ['-l', executable, ...args] : args,
      {
        cwd,
        stdio: ['ignore', 'ignore', 'pipe'],
      },
    );
    const stderr: Buffer[] = [];
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
        resolve(measurePeakRss
          ? {
            elapsedMs: Number(process.hrtime.bigint() - startedAt) / 1_000_000,
            peakRssBytes: parsePeakRss(Buffer.concat(stderr).toString('utf8')),
          }
          : { elapsedMs: Number(process.hrtime.bigint() - startedAt) / 1_000_000 });
      } catch (parseError) {
        reject(parseError);
      }
    };
    const timer = setTimeout(() => {
      child.kill('SIGTERM');
      finish(new Error(`${path.basename(executable)} timed out.`));
    }, PROCESS_TIMEOUT_MS);
    child.once('error', (error) =>
      finish(new Error(`Could not start ${path.basename(executable)}: ${error.message}`)),
    );
    child.stderr.on('data', (chunk: Buffer) => {
      stderrLength += chunk.length;
      if (stderrLength <= MAX_PROCESS_OUTPUT) stderr.push(chunk);
    });
    child.once('close', (code, signal) => {
      if (code === 0) {
        finish();
        return;
      }
      const details = Buffer.concat(stderr).toString('utf8').trim();
      finish(new Error(
        `${path.basename(executable)} failed${
          signal ? ` with signal ${signal}` : ` with exit code ${code ?? 'unknown'}`
        }${details ? `: ${details}` : ''}`,
      ));
    });
  });
}

function encodeField(value: bigint): Buffer {
  if (value < 0n || value >= 1n << 64n) {
    throw new Error('A Noir public input is outside its supported range.');
  }
  const result = Buffer.alloc(32);
  result.writeBigUInt64BE(value, 24);
  return result;
}

function commitmentPublicInputs(commitmentHex: string): bigint[] {
  const digest = Buffer.from(commitmentHex, 'hex');
  return Array.from({ length: 4 }, (_, index) =>
    digest.readBigUInt64BE(index * 8),
  );
}

async function readProgramIdentity<Program extends NoirProgram>(
  identityPath: string,
  bytecodePath: string,
  verificationKeyPath: string,
  expectedProgram: Program,
): Promise<NoirProgramIdentity & { program: Program }> {
  const [identityBytes, bytecode, verificationKey] = await Promise.all([
    readFile(identityPath),
    readFile(bytecodePath),
    readFile(verificationKeyPath),
  ]);
  let identity: unknown;
  try {
    identity = JSON.parse(identityBytes.toString('utf8'));
  } catch {
    throw new Error('The Noir program identity is invalid; rebuild version 2.');
  }
  if (
    !isNoirProgramIdentity(identity, expectedProgram) ||
    identity.bytecodeSha256 !== sha256(bytecode) ||
    identity.verificationKeySha256 !== sha256(verificationKey)
  ) {
    throw new Error('The Noir artifacts do not match their pinned program identity.');
  }
  return identity as NoirProgramIdentity & { program: Program };
}

async function prove<Program extends NoirProgram>(
  config: CircuitConfig<Program>,
  options: RunProofOptions,
  performance: NoirPerformanceOptions,
): Promise<NoirProofResult<Program>> {
  if (
    options.contentStream.length === 0 ||
    options.contentStream.length > config.maximumCompressedLength ||
    !/^[0-9a-f]{32}$/.test(options.blinderHex) ||
    !/^[0-9a-f]{64}$/.test(options.commitmentHex)
  ) {
    throw new Error('The private TLSNotary commitment opening is invalid.');
  }
  const actualCommitment = createHash('sha256')
    .update(options.contentStream)
    .update(Buffer.from(options.blinderHex, 'hex'))
    .digest('hex');
  if (actualCommitment !== options.commitmentHex) {
    throw new Error('The content stream does not open its TLSNotary commitment.');
  }

  const circuitDirectory = path.join(
    projectDirectory,
    'circuits',
    config.circuitDirectory,
  );
  const targetDirectory = path.join(circuitDirectory, 'target');
  const bytecodePath = path.join(targetDirectory, config.artifactName);
  const evmDirectory = path.join(targetDirectory, 'evm');
  const verificationKeyPath = path.join(evmDirectory, 'vk');
  const identity = await readProgramIdentity(
    path.join(evmDirectory, 'identity.json'),
    bytecodePath,
    verificationKeyPath,
    config.noirProgram,
  );

  const identifier = randomUUID().replaceAll('-', '');
  const proverName = `Prover-${identifier}`;
  const witnessName = `witness-${identifier}`;
  const proverPath = path.join(circuitDirectory, `${proverName}.toml`);
  const witnessPath = path.join(targetDirectory, `${witnessName}.gz`);
  const runDirectory = path.join(runtimeDirectory, identifier);
  const streamPath = path.join(runDirectory, 'content-stream.bin');
  const proofPath = path.join(runDirectory, 'proof');
  const publicInputsPath = path.join(runDirectory, 'public_inputs');

  await mkdir(runDirectory, { recursive: true, mode: 0o700 });
  await writeFile(streamPath, options.contentStream, { mode: 0o600 });
  try {
    const witnessPreparation = await runProcess(process.execPath, [
      path.join(projectDirectory, 'dist', 'scripts', config.witnessBuilderName),
      '--stream', streamPath,
      '--blinder', options.blinderHex,
      '--output', proverPath,
      ...options.witnessArguments,
    ], projectDirectory, performance.measurePeakRss);
    const nargoExecute = await runProcess(toolPath('NARGO_BIN'), [
      'execute', '--prover-name', proverName, witnessName,
    ], circuitDirectory, performance.measurePeakRss);
    const bbProve = await runProcess(toolPath('BB_BIN'), [
      'prove', '-b', bytecodePath, '-w', witnessPath, '-k', verificationKeyPath,
      '-o', runDirectory, '-t', 'evm',
    ], circuitDirectory, performance.measurePeakRss);
    const bbVerify = await runProcess(toolPath('BB_BIN'), [
      'verify', '-p', proofPath, '-i', publicInputsPath, '-k', verificationKeyPath,
      '-t', 'evm',
    ], circuitDirectory, performance.measurePeakRss);

    const [proof, publicInputs] = await Promise.all([
      readFile(proofPath),
      readFile(publicInputsPath),
    ]);
    const expectedPublicInputs = Buffer.concat([
      ...commitmentPublicInputs(options.commitmentHex),
      BigInt(options.contentStream.length),
      ...options.claimPublicU64s,
    ].map(encodeField));
    if (!publicInputs.equals(expectedPublicInputs)) {
      throw new Error('UltraHonk proof public inputs do not match the request.');
    }
    const peakRssBytes = Math.max(...[
      witnessPreparation, nargoExecute, bbProve, bbVerify,
    ].flatMap((result) => result.peakRssBytes ?? []));
    const generationMs = witnessPreparation.elapsedMs + nargoExecute.elapsedMs +
      bbProve.elapsedMs;
    return {
      proof,
      publicInputs,
      programIdentity: identity,
      performance: {
        generationMs,
        selfVerificationMs: bbVerify.elapsedMs,
        totalMs: generationMs + bbVerify.elapsedMs,
        ...(Number.isFinite(peakRssBytes) ? { peakRssBytes } : {}),
      },
    };
  } finally {
    await Promise.all([
      unlink(proverPath).catch(() => undefined),
      unlink(witnessPath).catch(() => undefined),
      rm(runDirectory, { recursive: true, force: true }),
    ]);
  }
}

export function runNoirProof<Program extends NoirProgram>(
  config: CircuitConfig<Program>,
  options: RunProofOptions,
  performance: NoirPerformanceOptions = {},
): Promise<NoirProofResult<Program>> {
  return serializeProving(() => prove(config, options, performance));
}
