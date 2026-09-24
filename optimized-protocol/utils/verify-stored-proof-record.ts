import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';

import type { StoredProofRecord } from './proof-record-types';
import { getDocumentProfile } from './document-profiles';

const projectDirectory = path.resolve(__dirname, '..', '..');
const verifierPath = path.join(
  projectDirectory,
  'native',
  'zktls',
  'target',
  'release',
  'govbind-optimized-zktls-verifier',
);
const runtimeDirectory = path.join(projectDirectory, '.runtime', 'verification');
const MAX_OUTPUT_BYTES = 64 * 1024;

export interface StoredProofVerificationMetrics {
  tlsNotaryMs: number;
  noirMs: number;
}

function elapsedMilliseconds(startedAt: bigint): number {
  return Number(process.hrtime.bigint() - startedAt) / 1_000_000;
}

function sha256(bytes: Buffer): string {
  return createHash('sha256').update(bytes).digest('hex');
}

function barretenbergPath(): string {
  if (process.env.BB_BIN) return process.env.BB_BIN;
  const candidate = path.join(os.homedir(), '.bb', 'bb');
  return existsSync(candidate) ? candidate : 'bb';
}

function run(
  executable: string,
  args: string[],
  stdin?: string,
  cwd = projectDirectory,
): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, {
      cwd,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
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
      } else {
        resolve(Buffer.concat(stdout).toString('utf8'));
      }
    };
    const timer = setTimeout(() => {
      child.kill('SIGTERM');
      finish(new Error(`${path.basename(executable)} timed out.`));
    }, 60_000);
    child.once('error', (error) =>
      finish(new Error(`Could not start ${path.basename(executable)}: ${error.message}`)),
    );
    child.stdout.on('data', (chunk: Buffer) => {
      stdoutLength += chunk.length;
      if (stdoutLength > MAX_OUTPUT_BYTES) {
        child.kill('SIGTERM');
        finish(new Error(`${path.basename(executable)} output is too large.`));
      } else {
        stdout.push(chunk);
      }
    });
    child.stderr.on('data', (chunk: Buffer) => {
      stderrLength += chunk.length;
      if (stderrLength <= MAX_OUTPUT_BYTES) stderr.push(chunk);
    });
    child.once('close', (code, signal) => {
      if (code === 0) {
        finish();
      } else {
        const details = Buffer.concat(stderr).toString('utf8').trim();
        finish(new Error(
          `${path.basename(executable)} failed${
            signal ? ` with signal ${signal}` : ` with exit code ${code ?? 'unknown'}`
          }${details ? `: ${details}` : ''}`,
        ));
      }
    });
    child.stdin.end(stdin);
  });
}

export async function verifyStoredProofRecord(
  record: StoredProofRecord,
): Promise<StoredProofVerificationMetrics> {
  const profile = getDocumentProfile(record.documentType);
  const circuitDirectory = path.join(
    projectDirectory,
    'circuits',
    profile.circuitDirectory,
  );
  const bytecodePath = path.join(circuitDirectory, 'target', profile.artifactName);
  const evmDirectory = path.join(circuitDirectory, 'target', 'evm');
  const verificationKeyPath = path.join(evmDirectory, 'vk');
  const solidityVerifierPath = path.join(evmDirectory, 'Verifier.sol');
  const identityPath = path.join(evmDirectory, 'identity.json');
  const [
    identityContents,
    bytecode,
    verificationKey,
    solidityVerifier,
  ] = await Promise.all([
    readFile(identityPath, 'utf8'),
    readFile(bytecodePath),
    readFile(verificationKeyPath),
    readFile(solidityVerifierPath),
  ]);
  const localIdentity = JSON.parse(identityContents) as unknown;
  if (JSON.stringify(localIdentity) !== JSON.stringify(record.noir.programIdentity)) {
    throw new Error('Proof record uses an unknown Noir program identity.');
  }
  const identity = record.noir.programIdentity;
  if (
    sha256(bytecode) !== identity.bytecodeSha256 ||
    sha256(verificationKey) !== identity.verificationKeySha256 ||
    sha256(solidityVerifier) !== identity.solidityVerifierSha256
  ) {
    throw new Error('Local Noir artifacts do not match the pinned program identity.');
  }

  const tlsNotaryStartedAt = process.hrtime.bigint();
  const presentationOutput = await run(
    verifierPath,
    [],
    JSON.stringify({
      profile: record.profile,
      ...(record.documentType === 'residence' ? {
        city: record.publicInputs.city,
        cityEncodingHex: record.publicInputs.cityEncodingHex,
      } : {}),
      ...(record.documentType === 'criminal-record' ? {
        identityNumber: record.publicInputs.identityNumber,
      } : {}),
      ...(record.documentType === 'tax-debt' ? {
        identityNumber: record.publicInputs.identityNumber,
      } : {}),
      notaryPublicKeyHex: record.tlsNotary.notaryPublicKeyHex,
      presentationBase64: record.tlsNotary.presentationBase64,
    }),
  );
  let parsedPresentation: unknown;
  try {
    parsedPresentation = JSON.parse(presentationOutput);
  } catch {
    throw new Error('TLSNotary presentation verifier returned invalid JSON.');
  }
  const output = parsedPresentation as {
    version?: unknown;
    privateRanges?: unknown;
  };
  if (
    output.version !== 'zk-devlet-zktls-presentation-verification-v2' ||
    (output as { profile?: unknown }).profile !== record.profile ||
    JSON.stringify(output.privateRanges) !== JSON.stringify(record.tlsNotary.privateRanges)
  ) {
    throw new Error('TLSNotary presentation does not match the proof record ranges.');
  }
  const tlsNotaryMs = elapsedMilliseconds(tlsNotaryStartedAt);

  const identifier = randomUUID().replaceAll('-', '');
  const directory = path.join(runtimeDirectory, identifier);
  const proofPath = path.join(directory, 'proof');
  const publicInputsPath = path.join(directory, 'public_inputs');
  await mkdir(directory, { recursive: true, mode: 0o700 });
  try {
    await Promise.all([
      writeFile(proofPath, Buffer.from(record.noir.proofBase64, 'base64'), {
        mode: 0o600,
      }),
      writeFile(
        publicInputsPath,
        Buffer.from(record.noir.publicInputsBase64, 'base64'),
        { mode: 0o600 },
      ),
    ]);
    const noirStartedAt = process.hrtime.bigint();
    await run(barretenbergPath(), [
      'verify',
      '-p',
      proofPath,
      '-i',
      publicInputsPath,
      '-k',
      verificationKeyPath,
      '-t',
      'evm',
    ], undefined, circuitDirectory);
    return {
      tlsNotaryMs,
      noirMs: elapsedMilliseconds(noirStartedAt),
    };
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}
