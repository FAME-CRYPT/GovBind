import { execFile } from 'node:child_process';
import path from 'node:path';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const projectDirectory = path.resolve(__dirname, '..', '..');
const extractorPath = path.join(
  projectDirectory,
  'native',
  'text-extractor',
  'target',
  'release',
  'zkpdf-text-hash',
);

export async function computeVerificationContentHash(
  inputPath: string,
): Promise<string> {
  const { stdout } = await execFileAsync(extractorPath, [inputPath], {
    encoding: 'utf8',
    maxBuffer: 1024,
    timeout: 30_000,
  });
  const hash = stdout.trim().toLowerCase();

  if (!/^[0-9a-f]{64}$/.test(hash)) {
    throw new Error('The zkPDF text extractor returned an invalid content hash.');
  }

  return hash;
}
