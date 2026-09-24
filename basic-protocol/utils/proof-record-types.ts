export interface StoredProofRecord {
  version: 'zk-devlet-proof-record-v1' | 'zk-devlet-proof-record-v2';
  documentType: 'military-service';
  program: 'zk-devlet-military-service-v1';
  createdAt: string;
  mode: 'execute';
  publicInputs: {
    tlsBodyCommitmentHex: string;
    today: string;
    assertionMonths: number;
  };
  execution: {
    publicValuesHex: string;
    totalInstructionCount: number;
    proverGas?: number;
  };
  proof: null;
}

export interface ProofRecordSummary {
  hash: string;
  documentType: StoredProofRecord['documentType'];
  program: StoredProofRecord['program'];
  createdAt: string;
  mode: StoredProofRecord['mode'];
  assertion: {
    today: string;
    months: number;
  };
  totalInstructionCount: number;
  proverGas?: number;
}

export function isStoredProofRecord(value: unknown): value is StoredProofRecord {
  if (!value || typeof value !== 'object') {
    return false;
  }

  const record = value as Partial<StoredProofRecord>;
  const hasValidShape = (
    (record.version === 'zk-devlet-proof-record-v1' ||
      record.version === 'zk-devlet-proof-record-v2') &&
    record.documentType === 'military-service' &&
    record.program === 'zk-devlet-military-service-v1' &&
    typeof record.createdAt === 'string' &&
    !Number.isNaN(Date.parse(record.createdAt)) &&
    record.mode === 'execute' &&
    !!record.publicInputs &&
    /^[0-9a-f]{64}$/.test(record.publicInputs.tlsBodyCommitmentHex) &&
    /^\d{2}\/\d{2}\/\d{4}$/.test(record.publicInputs.today) &&
    Number.isSafeInteger(record.publicInputs.assertionMonths) &&
    record.publicInputs.assertionMonths >= 0 &&
    record.publicInputs.assertionMonths <= 0xffff_ffff &&
    !!record.execution &&
    /^[0-9a-f]{92}$/.test(record.execution.publicValuesHex) &&
    Number.isSafeInteger(record.execution.totalInstructionCount) &&
    record.execution.totalInstructionCount >= 0 &&
    record.proof === null
  );

  if (!hasValidShape) {
    return false;
  }

  const validRecord = record as StoredProofRecord;
  const hasValidProverGas =
    validRecord.version === 'zk-devlet-proof-record-v1'
      ? validRecord.execution.proverGas === undefined
      : Number.isSafeInteger(validRecord.execution.proverGas) &&
        validRecord.execution.proverGas! >= 0;
  if (!hasValidProverGas) {
    return false;
  }

  const months = Buffer.alloc(4);
  months.writeUInt32BE(validRecord.publicInputs.assertionMonths);
  const expectedPublicValuesHex =
    validRecord.publicInputs.tlsBodyCommitmentHex +
    Buffer.from(validRecord.publicInputs.today, 'ascii').toString('hex') +
    months.toString('hex');
  return validRecord.execution.publicValuesHex === expectedPublicValuesHex;
}

export function summarizeProofRecord(
  hash: string,
  record: StoredProofRecord,
): ProofRecordSummary {
  return {
    hash,
    documentType: record.documentType,
    program: record.program,
    createdAt: record.createdAt,
    mode: record.mode,
    assertion: {
      today: record.publicInputs.today,
      months: record.publicInputs.assertionMonths,
    },
    totalInstructionCount: record.execution.totalInstructionCount,
    proverGas: record.execution.proverGas,
  };
}
