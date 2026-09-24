import type { RequestHandler } from 'express';
import { chmod, unlink } from 'node:fs/promises';

import {
  extractVerificationInfo,
  type VerificationInfo,
} from '../../utils/extract-verification-info';
import {
  performZkTlsVerification,
  type ZkTlsVerificationResult,
} from '../../utils/perform-zktls-verification';
import {
  prepareVerificationSession,
  type PreparedVerificationSession,
} from '../../utils/prepare-verification-session';
import {
  saveStoredProofRecord,
} from '../../utils/save-proof-record';
import type { ProofRecordSummary } from '../../utils/proof-record-types';
import { withProcessLogging } from '../../utils/process-logger';
import { getResidenceCity } from '../../utils/residence-cities';
import { getDocumentProfile } from '../../utils/document-profiles';
import { prepareTaxDebtVerificationSession } from '../../utils/prepare-tax-debt-verification-session';
import {
  contentStreamRange,
  createGeneratedProofRecord,
  generateNoirProof,
  type PublicParameters,
} from '../../utils/document-proof';

interface VerificationRequestBody {
  documentType?: string;
  generationDate?: string;
  assertionMonths?: string;
  cityCode?: string;
  maximumTrafficTickets?: string;
  maximumTotalPenaltyPoints?: string;
  maximumActivePenaltyPoints?: string;
}

type ParsedParameters = Exclude<PublicParameters, { documentType: 'criminal-record' }> |
  { documentType: 'criminal-record' } | { documentType: 'tax-debt' };

function parsePublicParameters(body: VerificationRequestBody): ParsedParameters {
  if (body.documentType === 'residence') {
    const city = getResidenceCity(body.cityCode);
    if (!city) throw new Error('A supported residence city must be selected.');
    return { documentType: 'residence', cityCode: city.code, city: city.name };
  }
  if (body.documentType === 'criminal-record') {
    return { documentType: 'criminal-record' };
  }
  if (body.documentType === 'tax-debt') return { documentType: 'tax-debt' };
  if (body.documentType === 'driver-license') {
    const parseThreshold = (value: string | undefined): number => {
      if (!/^\d+$/.test(value ?? '')) {
        throw new Error('Traffic penalty thresholds must be positive integers.');
      }
      const parsed = Number(value);
      if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > 0xffff_ffff) {
        throw new Error('Traffic penalty thresholds must be positive 32-bit integers.');
      }
      return parsed;
    };
    return {
      documentType: 'driver-license',
      maximumTrafficTickets: parseThreshold(body.maximumTrafficTickets),
      maximumTotalPenaltyPoints: parseThreshold(body.maximumTotalPenaltyPoints),
      maximumActivePenaltyPoints: parseThreshold(body.maximumActivePenaltyPoints),
    };
  }
  if (body.documentType !== 'military-service') throw new Error('The selected document type is not supported.');
  const dateMatch = body.generationDate?.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!dateMatch) {
    throw new Error('The comparison date must use YYYY-MM-DD format.');
  }
  const year = Number(dateMatch[1]);
  const month = Number(dateMatch[2]);
  const day = Number(dateMatch[3]);
  const timestamp = Date.UTC(year, month - 1, day);
  const parsed = new Date(timestamp);
  if (
    parsed.getUTCFullYear() !== year ||
    parsed.getUTCMonth() !== month - 1 ||
    parsed.getUTCDate() !== day
  ) {
    throw new Error('The comparison date must be a real Gregorian date.');
  }
  const todayInIstanbul = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Europe/Istanbul',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  }).format(new Date());
  const [todayYear, todayMonth, todayDay] = todayInIstanbul.split('-').map(Number);
  const ageInDays =
    (Date.UTC(todayYear, todayMonth - 1, todayDay) - timestamp) / 86_400_000;
  if (!Number.isInteger(ageInDays) || ageInDays < 0 || ageInDays > 2) {
    throw new Error('The comparison date must be today or one of the preceding two days.');
  }
  if (!/^\d+$/.test(body.assertionMonths ?? '')) {
    throw new Error('The time assertion must be a positive integer.');
  }
  const assertionMonths = Number(body.assertionMonths);
  if (
    !Number.isSafeInteger(assertionMonths) ||
    assertionMonths < 1 ||
    assertionMonths > 1200
  ) {
    throw new Error('The time assertion must be between 1 and 1200 months.');
  }
  return {
    documentType: 'military-service',
    comparisonDate: body.generationDate!,
    comparisonDateYyyymmdd: year * 10_000 + month * 100 + day,
    assertionMonths,
  };
}

const handler: RequestHandler = async (request, response) => {
  if (!request.file) {
    response.status(400).json({ error: 'A PDF document is required.' });
    return;
  }
  const uploadedPath = request.file.path;
  await chmod(uploadedPath, 0o600);
  try {
    const parsedParameters = parsePublicParameters(request.body as VerificationRequestBody);
    const documentProfile = getDocumentProfile(parsedParameters.documentType);
    const verificationInfo: VerificationInfo = await withProcessLogging(
      'verification',
      'extract navigation information',
      () => extractVerificationInfo(request.file!.path, parsedParameters.documentType),
    );
    const parameters: PublicParameters = parsedParameters.documentType === 'criminal-record' ||
      parsedParameters.documentType === 'tax-debt'
      ? parsedParameters.documentType === 'tax-debt'
        ? {
          documentType: 'tax-debt',
          identityNumber: verificationInfo.idNumber,
          issuanceDate: verificationInfo.issuanceDate ?? '',
          issuanceDateYyyymmdd: verificationInfo.issuanceDateYyyymmdd ?? 0,
        }
        : { documentType: 'criminal-record', identityNumber: verificationInfo.idNumber }
      : parsedParameters;
    const preparedSession: PreparedVerificationSession = await withProcessLogging(
      'verification',
      'prepare verification session',
      () => parsedParameters.documentType === 'tax-debt'
        ? prepareTaxDebtVerificationSession(
          verificationInfo.petitionNumber ?? '', verificationInfo.idNumber,
        )
        : prepareVerificationSession({
          barcode: verificationInfo.barcode ?? '', idNumber: verificationInfo.idNumber,
        }),
    );
    const zkTls: ZkTlsVerificationResult = await withProcessLogging(
      'verification',
      'authenticate selective PDF ranges',
      () => performZkTlsVerification(preparedSession, {
        profile: documentProfile.tlsProfile,
        ...(parameters.documentType === 'residence' ? { city: parameters.city } : {}),
        ...(parameters.documentType === 'criminal-record'
          ? { identityNumber: parameters.identityNumber }
          : {}),
        ...(parameters.documentType === 'tax-debt'
          ? { identityNumber: parameters.identityNumber }
          : {}),
      }),
    );
    const contentRange = contentStreamRange(zkTls);
    const noir = await withProcessLogging(
      'verification',
      'generate and verify UltraHonk proof',
      () => generateNoirProof(parameters, zkTls, contentRange),
    );
    if (noir.programIdentity.program !== documentProfile.noirProgram) {
      throw new Error('The generated proof used the wrong document program.');
    }
    const notaryPublicKeyHex = process.env.TLSN_NOTARY_PUBLIC_KEY;
    if (!notaryPublicKeyHex || !/^[0-9a-f]{66}$/.test(notaryPublicKeyHex)) {
      throw new Error('The trusted TLSNotary public key is unavailable.');
    }
    const proof: ProofRecordSummary = await withProcessLogging(
      'verification',
      'save proof record',
      () => saveStoredProofRecord(createGeneratedProofRecord(
        parameters, zkTls, contentRange, noir, notaryPublicKeyHex,
      )),
    );
    response.status(200).json({
      message: 'TLSNotary attestation and UltraHonk proof generated and verified.',
      proof,
    });
  } finally {
    await withProcessLogging(
      'verification',
      'remove navigation document',
      () => unlink(uploadedPath).catch(() => undefined),
    );
  }
};

export = handler;
