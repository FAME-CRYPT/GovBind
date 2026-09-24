import { createHash } from 'node:crypto';
import path from 'node:path';

export const proofsDirectory = path.resolve(__dirname, '..', '..', 'proofs');

export function isProofHash(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

export function computeProofHash(contents: Buffer): string {
  return createHash('sha256').update(contents).digest('hex');
}

export function getProofPath(hash: string): string {
  return path.join(proofsDirectory, `${hash}.json`);
}
