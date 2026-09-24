import { readFile, readdir } from 'node:fs/promises';
import path from 'node:path';

import {
  computeProofHash,
  isProofHash,
  proofsDirectory,
} from './proof-record-hash';
import {
  isStoredProofRecord,
  summarizeProofRecord,
  type ProofRecordSummary,
} from './proof-record-types';

let availableProofs: ProofRecordSummary[] | undefined;

export async function getProofRecords(): Promise<ProofRecordSummary[]> {
  if (availableProofs) {
    return availableProofs;
  }

  const entries = await readdir(proofsDirectory, { withFileTypes: true });
  const proofFiles = entries.filter(
    (entry) => entry.isFile() && entry.name.endsWith('.json'),
  );

  const proofs = await Promise.all(
    proofFiles.map(async (entry): Promise<ProofRecordSummary> => {
      const hash = entry.name.slice(0, -'.json'.length);
      if (!isProofHash(hash)) {
        throw new Error(`Stored proof ${entry.name} has an invalid filename.`);
      }

      const contents = await readFile(path.join(proofsDirectory, entry.name));
      if (computeProofHash(contents) !== hash) {
        throw new Error(`Stored proof ${entry.name} does not match its hash.`);
      }

      let parsed: unknown;
      try {
        parsed = JSON.parse(contents.toString('utf8'));
      } catch {
        throw new Error(`Stored proof ${entry.name} contains invalid JSON.`);
      }
      if (!isStoredProofRecord(parsed)) {
        throw new Error(`Stored proof ${entry.name} has an invalid format.`);
      }

      return summarizeProofRecord(hash, parsed);
    }),
  );

  availableProofs = proofs.sort(
    (left, right) => right.createdAt.localeCompare(left.createdAt),
  );
  return availableProofs;
}

export function addProofRecord(proof: ProofRecordSummary): void {
  availableProofs?.unshift(proof);
}

export function removeProofRecord(hash: string): void {
  if (availableProofs) {
    availableProofs = availableProofs.filter((proof) => proof.hash !== hash);
  }
}
