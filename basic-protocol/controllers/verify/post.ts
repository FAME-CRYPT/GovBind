import type { RequestHandler } from 'express';
import { chmod, rename, unlink } from 'node:fs/promises';
import path from 'node:path';

import { computeVerificationContentHash } from '../../utils/compute-verification-content-hash';
import {
  extractVerificationInfo,
  type VerificationInfo,
} from '../../utils/extract-verification-info';
import {
  performMilitaryServiceProof,
  type MilitaryServiceProofExecutionResult,
} from '../../utils/perform-military-service-proof';
import {
  performZkTlsVerification,
  type ZkTlsVerificationResult,
} from '../../utils/perform-zktls-verification';
import {
  prepareVerificationSession,
  type PreparedVerificationSession,
} from '../../utils/prepare-verification-session';
import { saveProofRecord } from '../../utils/save-proof-record';
import type { ProofRecordSummary } from '../../utils/proof-record-types';
import { withProcessLogging } from '../../utils/process-logger';

const originalDirectory = path.resolve(__dirname, '..', '..', '..', 'uploads', 'original');

interface VerificationRequestBody {
  documentType?: string;
  generationDate?: string;
  assertionMonths?: string;
}

function parsePublicParameters(body: VerificationRequestBody): {
  today: string;
  assertionMonths: number;
} {
  if (body.documentType !== 'military-service') {
    throw new Error('The selected document type is not supported.');
  }
  if (!body.generationDate || !/^\d{4}-\d{2}-\d{2}$/.test(body.generationDate)) {
    throw new Error('The generation date must use YYYY-MM-DD format.');
  }
  if (!body.assertionMonths || !/^\d+$/.test(body.assertionMonths)) {
    throw new Error('The time assertion must be a non-negative integer.');
  }

  const assertionMonths = Number(body.assertionMonths);
  if (!Number.isSafeInteger(assertionMonths) || assertionMonths > 0xffff_ffff) {
    throw new Error('The time assertion must fit in an unsigned 32-bit integer.');
  }

  const [year, month, day] = body.generationDate.split('-');
  return { today: `${day}/${month}/${year}`, assertionMonths };
}

const handler: RequestHandler = async (request, response) => {
  if (!request.file) {
    response.status(400).json({ error: 'A PDF document is required.' });
    return;
  }

  const { today, assertionMonths } = parsePublicParameters(
    request.body as VerificationRequestBody,
  );
  const verificationInfo: VerificationInfo = await withProcessLogging(
    'verification',
    'extract document information',
    () => extractVerificationInfo(request.file!.path),
  );
  const contentHash: string = await withProcessLogging(
    'verification',
    'compute canonical document hash',
    () => computeVerificationContentHash(request.file!.path),
  );
  const originalPath = path.join(originalDirectory, `${contentHash}.pdf`);
  await withProcessLogging('verification', 'store uploaded document', async () => {
    await rename(request.file!.path, originalPath);
    await chmod(originalPath, 0o600);
  });

  const preparedSession: PreparedVerificationSession = await withProcessLogging(
    'verification',
    'prepare verification session',
    () => prepareVerificationSession(verificationInfo),
  );
  const zkTlsVerification: ZkTlsVerificationResult = await withProcessLogging(
    'verification',
    'perform zkTLS verification',
    () => performZkTlsVerification({
      session: preparedSession,
      expectedContentHash: contentHash,
    }),
  );

  const proofExecution: MilitaryServiceProofExecutionResult =
    await withProcessLogging(
      'verification',
      'execute military-service proof program',
      () => performMilitaryServiceProof({
        pdfPath: zkTlsVerification.pdfPath,
        commitmentHex: zkTlsVerification.commitmentHex,
        blinderHex: zkTlsVerification.blinderHex,
        documentDate: verificationInfo.documentDate,
        today,
        assertionMonths,
      }),
    );

  const proof: ProofRecordSummary = await withProcessLogging(
    'verification',
    'save proof record',
    () => saveProofRecord({
      documentType: 'military-service',
      tlsBodyCommitmentHex: zkTlsVerification.commitmentHex,
      today,
      assertionMonths,
      publicValuesHex: proofExecution.publicValuesHex,
      totalInstructionCount: proofExecution.totalInstructionCount,
      proverGas: proofExecution.proverGas,
    }),
  );

  await withProcessLogging(
    'verification',
    'remove processed documents',
    () => Promise.all([
      unlink(originalPath),
      unlink(zkTlsVerification.pdfPath),
    ]).then(() => undefined),
  );

  response.status(200).json({
    message: 'TLSNotary verification and SP1 constraint execution completed.',
    proof,
  });
};

export = handler;
