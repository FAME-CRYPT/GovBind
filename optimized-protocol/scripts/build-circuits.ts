import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { documentProfiles } from '../utils/document-profiles';

const projectDirectory = path.resolve(__dirname, '..', '..');
const defaultNargo = path.join(os.homedir(), '.nargo', 'bin', 'nargo');
const defaultBb = path.join(os.homedir(), '.bb', 'bb');
const nargo = process.env.NARGO_BIN ??
  (existsSync(defaultNargo) ? defaultNargo : 'nargo');
const bb = process.env.BB_BIN ?? (existsSync(defaultBb) ? defaultBb : 'bb');

function run(binary: string, args: string[], cwd: string): void {
  execFileSync(binary, args, {
    cwd,
    stdio: 'inherit',
    timeout: 15 * 60_000,
  });
}

function sha256(bytes: Buffer): string {
  return createHash('sha256').update(bytes).digest('hex');
}

async function buildCircuits(): Promise<void> {
  const requestedDocumentType = process.argv[2];
  const profiles = requestedDocumentType === undefined
    ? Object.values(documentProfiles)
    : [documentProfiles[requestedDocumentType as keyof typeof documentProfiles]];
  if (profiles[0] === undefined) {
    throw new Error(
      `Unknown document profile: ${requestedDocumentType}. Expected one of: ${Object.keys(documentProfiles).join(', ')}.`,
    );
  }

  const toolchain = JSON.parse(
    await readFile(path.join(projectDirectory, 'toolchain.json'), 'utf8'),
  ) as unknown;

  for (const profile of profiles) {
    const circuitDirectory = path.join(
      projectDirectory,
      'circuits',
      profile.circuitDirectory,
    );
    const targetDirectory = path.join(circuitDirectory, 'target');
    const evmDirectory = path.join(targetDirectory, 'evm');
    const bytecodePath = path.join(targetDirectory, profile.artifactName);
    const verificationKeyPath = path.join(evmDirectory, 'vk');
    const solidityVerifierPath = path.join(evmDirectory, 'Verifier.sol');

    await mkdir(evmDirectory, { recursive: true });
    run(nargo, ['compile'], circuitDirectory);
    run(bb, [
      'write_vk',
      '-b',
      bytecodePath,
      '-o',
      evmDirectory,
      '-t',
      'evm',
    ], circuitDirectory);
    run(bb, [
      'write_solidity_verifier',
      '-k',
      verificationKeyPath,
      '-o',
      solidityVerifierPath,
      '-t',
      'evm',
      '--optimized',
    ], circuitDirectory);

    const [bytecode, verificationKey, verifier] = await Promise.all([
      readFile(bytecodePath),
      readFile(verificationKeyPath),
      readFile(solidityVerifierPath),
    ]);
    const identity = {
      version: 'zk-devlet-noir-program-identity-v1',
      program: profile.noirProgram,
      verifierTarget: 'evm',
      bytecodeSha256: sha256(bytecode),
      verificationKeySha256: sha256(verificationKey),
      solidityVerifierSha256: sha256(verifier),
      toolchain,
    };
    await writeFile(
      path.join(evmDirectory, 'identity.json'),
      `${JSON.stringify(identity, null, 2)}\n`,
      { mode: 0o644 },
    );
  }
}

buildCircuits().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
