import { readFile } from 'node:fs/promises';

import { computeProofHash, getProofPath } from './proof-record-hash';

export async function getProofRecordFile(hash: string): Promise<Buffer | undefined> {
  let contents: Buffer;
  try {
    contents = await readFile(getProofPath(hash));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return undefined;
    }
    throw error;
  }

  if (computeProofHash(contents) !== hash) {
    throw new Error(`Stored proof ${hash}.json does not match its hash.`);
  }
  return contents;
}
