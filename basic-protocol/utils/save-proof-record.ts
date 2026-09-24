import { rename, unlink, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { addProofRecord } from './get-proof-records';
import {
  computeProofHash,
  getProofPath,
  proofsDirectory,
} from './proof-record-hash';
import {
  summarizeProofRecord,
  type ProofRecordSummary,
  type StoredProofRecord,
} from './proof-record-types';

export interface SaveProofRecordOptions {
  documentType: 'military-service';
  tlsBodyCommitmentHex: string;
  today: string;
  assertionMonths: number;
  publicValuesHex: string;
  totalInstructionCount: number;
  proverGas: number;
}

export async function saveProofRecord(
  options: SaveProofRecordOptions,
): Promise<ProofRecordSummary> {
  const record: StoredProofRecord = {
    version: 'zk-devlet-proof-record-v2',
    documentType: options.documentType,
    program: 'zk-devlet-military-service-v1',
    createdAt: new Date().toISOString(),
    mode: 'execute',
    publicInputs: {
      tlsBodyCommitmentHex: options.tlsBodyCommitmentHex,
      today: options.today,
      assertionMonths: options.assertionMonths,
    },
    execution: {
      publicValuesHex: options.publicValuesHex,
      totalInstructionCount: options.totalInstructionCount,
      proverGas: options.proverGas,
    },
    proof: null,
  };

  const contents = Buffer.from(`${JSON.stringify(record, null, 2)}\n`, 'utf8');
  const hash = computeProofHash(contents);
  const temporaryPath = path.join(proofsDirectory, `.${hash}.tmp`);
  try {
    await writeFile(temporaryPath, contents, { mode: 0o600, flag: 'wx' });
    await rename(temporaryPath, getProofPath(hash));
  } catch (error) {
    await unlink(temporaryPath).catch(() => undefined);
    throw error;
  }

  const summary = summarizeProofRecord(hash, record);
  addProofRecord(summary);
  return summary;
}
