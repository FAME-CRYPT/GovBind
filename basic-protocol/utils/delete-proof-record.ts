import { unlink } from 'node:fs/promises';

import { removeProofRecord } from './get-proof-records';
import { getProofPath } from './proof-record-hash';

export async function deleteProofRecord(hash: string): Promise<boolean> {
  try {
    await unlink(getProofPath(hash));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return false;
    }
    throw error;
  }

  removeProofRecord(hash);
  return true;
}
