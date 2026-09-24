import { rename, unlink, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { addProofRecord } from './get-proof-records';
import {
  computeProofHash,
  getProofPath,
  proofsDirectory,
} from './proof-record-hash';
import {
  isStoredProofRecord,
  summarizeProofRecord,
  type CriminalRecordStoredProofRecord,
  type DriverLicenseStoredProofRecord,
  type MilitaryStoredProofRecord,
  type NoirProgramIdentity,
  type ProofRecordSummary,
  type ResidenceStoredProofRecord,
  type StoredProofRecord,
  type TaxDebtStoredProofRecord,
} from './proof-record-types';
import type { AuthenticatedPrivateRange } from './perform-zktls-verification';
import { documentProfiles } from './document-profiles';

export interface SaveMilitaryServiceProofRecordOptions {
  contentStreamCommitmentHex: string;
  compressedLength: number;
  comparisonDateYyyymmdd: number;
  comparisonDate: string;
  assertionMonths: number;
  notaryPublicKeyHex: string;
  privateRanges: AuthenticatedPrivateRange[];
  presentation: Buffer;
  programIdentity: NoirProgramIdentity;
  publicInputs: Buffer;
  proof: Buffer;
}

export async function saveStoredProofRecord(
  record: StoredProofRecord,
): Promise<ProofRecordSummary> {
  if (!isStoredProofRecord(record)) {
    throw new Error('Refusing to save an invalid proof record.');
  }
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

export function createMilitaryServiceProofRecord(
  options: SaveMilitaryServiceProofRecordOptions,
): MilitaryStoredProofRecord {
  const profile = documentProfiles['military-service'];
  return {
    version: profile.recordVersion,
    documentType: profile.documentType,
    profile: profile.tlsProfile,
    createdAt: new Date().toISOString(),
    mode: 'ultrahonk',
    publicInputs: {
      contentStreamCommitmentHex: options.contentStreamCommitmentHex,
      compressedLength: options.compressedLength,
      comparisonDateYyyymmdd: options.comparisonDateYyyymmdd,
      comparisonDate: options.comparisonDate,
      assertionMonths: options.assertionMonths,
    },
    tlsNotary: {
      notaryPublicKeyHex: options.notaryPublicKeyHex,
      privateRanges: options.privateRanges,
      presentationBase64: options.presentation.toString('base64'),
    },
    noir: {
      programIdentity: options.programIdentity,
      publicInputsBase64: options.publicInputs.toString('base64'),
      proofBase64: options.proof.toString('base64'),
    },
  };
}

export async function saveMilitaryServiceProofRecord(
  options: SaveMilitaryServiceProofRecordOptions,
): Promise<ProofRecordSummary> {
  return saveStoredProofRecord(createMilitaryServiceProofRecord(options));
}

export interface SaveResidenceProofRecordOptions {
  contentStreamCommitmentHex: string;
  compressedLength: number;
  cityCode: number;
  city: string;
  cityEncodingHex: string;
  notaryPublicKeyHex: string;
  privateRanges: AuthenticatedPrivateRange[];
  presentation: Buffer;
  programIdentity: NoirProgramIdentity;
  publicInputs: Buffer;
  proof: Buffer;
}

export function createResidenceProofRecord(
  options: SaveResidenceProofRecordOptions,
): ResidenceStoredProofRecord {
  const profile = documentProfiles.residence;
  return {
    version: profile.recordVersion,
    documentType: profile.documentType,
    profile: profile.tlsProfile,
    createdAt: new Date().toISOString(),
    mode: 'ultrahonk',
    publicInputs: {
      contentStreamCommitmentHex: options.contentStreamCommitmentHex,
      compressedLength: options.compressedLength,
      cityCode: options.cityCode,
      city: options.city,
      cityEncodingHex: options.cityEncodingHex,
    },
    tlsNotary: {
      notaryPublicKeyHex: options.notaryPublicKeyHex,
      privateRanges: options.privateRanges,
      presentationBase64: options.presentation.toString('base64'),
    },
    noir: {
      programIdentity: options.programIdentity,
      publicInputsBase64: options.publicInputs.toString('base64'),
      proofBase64: options.proof.toString('base64'),
    },
  };
}

export async function saveResidenceProofRecord(
  options: SaveResidenceProofRecordOptions,
): Promise<ProofRecordSummary> {
  return saveStoredProofRecord(createResidenceProofRecord(options));
}

export interface SaveCriminalRecordProofRecordOptions {
  contentStreamCommitmentHex: string;
  compressedLength: number;
  identityNumber: string;
  notaryPublicKeyHex: string;
  privateRanges: AuthenticatedPrivateRange[];
  presentation: Buffer;
  programIdentity: NoirProgramIdentity;
  publicInputs: Buffer;
  proof: Buffer;
}

export function createCriminalRecordProofRecord(
  options: SaveCriminalRecordProofRecordOptions,
): CriminalRecordStoredProofRecord {
  const profile = documentProfiles['criminal-record'];
  return {
    version: profile.recordVersion,
    documentType: profile.documentType,
    profile: profile.tlsProfile,
    createdAt: new Date().toISOString(),
    mode: 'ultrahonk',
    publicInputs: {
      contentStreamCommitmentHex: options.contentStreamCommitmentHex,
      compressedLength: options.compressedLength,
      identityNumber: options.identityNumber,
    },
    tlsNotary: {
      notaryPublicKeyHex: options.notaryPublicKeyHex,
      privateRanges: options.privateRanges,
      presentationBase64: options.presentation.toString('base64'),
    },
    noir: {
      programIdentity: options.programIdentity,
      publicInputsBase64: options.publicInputs.toString('base64'),
      proofBase64: options.proof.toString('base64'),
    },
  };
}

export async function saveCriminalRecordProofRecord(
  options: SaveCriminalRecordProofRecordOptions,
): Promise<ProofRecordSummary> {
  return saveStoredProofRecord(createCriminalRecordProofRecord(options));
}

export interface SaveDriverLicenseProofRecordOptions {
  contentStreamCommitmentHex: string;
  compressedLength: number;
  maximumTrafficTickets: number;
  maximumTotalPenaltyPoints: number;
  maximumActivePenaltyPoints: number;
  notaryPublicKeyHex: string;
  privateRanges: AuthenticatedPrivateRange[];
  presentation: Buffer;
  programIdentity: NoirProgramIdentity;
  publicInputs: Buffer;
  proof: Buffer;
}

export function createDriverLicenseProofRecord(
  options: SaveDriverLicenseProofRecordOptions,
): DriverLicenseStoredProofRecord {
  const profile = documentProfiles['driver-license'];
  return {
    version: profile.recordVersion,
    documentType: profile.documentType,
    profile: profile.tlsProfile,
    createdAt: new Date().toISOString(),
    mode: 'ultrahonk',
    publicInputs: {
      contentStreamCommitmentHex: options.contentStreamCommitmentHex,
      compressedLength: options.compressedLength,
      maximumTrafficTickets: options.maximumTrafficTickets,
      maximumTotalPenaltyPoints: options.maximumTotalPenaltyPoints,
      maximumActivePenaltyPoints: options.maximumActivePenaltyPoints,
    },
    tlsNotary: {
      notaryPublicKeyHex: options.notaryPublicKeyHex,
      privateRanges: options.privateRanges,
      presentationBase64: options.presentation.toString('base64'),
    },
    noir: {
      programIdentity: options.programIdentity,
      publicInputsBase64: options.publicInputs.toString('base64'),
      proofBase64: options.proof.toString('base64'),
    },
  };
}

export async function saveDriverLicenseProofRecord(
  options: SaveDriverLicenseProofRecordOptions,
): Promise<ProofRecordSummary> {
  return saveStoredProofRecord(createDriverLicenseProofRecord(options));
}

export interface SaveTaxDebtProofRecordOptions {
  contentStreamCommitmentHex: string;
  compressedLength: number;
  identityNumber: string;
  issuanceDateYyyymmdd: number;
  issuanceDate: string;
  notaryPublicKeyHex: string;
  privateRanges: AuthenticatedPrivateRange[];
  presentation: Buffer;
  programIdentity: NoirProgramIdentity;
  publicInputs: Buffer;
  proof: Buffer;
}

export function createTaxDebtProofRecord(
  options: SaveTaxDebtProofRecordOptions,
): TaxDebtStoredProofRecord {
  const profile = documentProfiles['tax-debt'];
  return {
    version: profile.recordVersion,
    documentType: profile.documentType,
    profile: profile.tlsProfile,
    createdAt: new Date().toISOString(),
    mode: 'ultrahonk',
    publicInputs: {
      contentStreamCommitmentHex: options.contentStreamCommitmentHex,
      compressedLength: options.compressedLength,
      identityNumber: options.identityNumber,
      issuanceDateYyyymmdd: options.issuanceDateYyyymmdd,
      issuanceDate: options.issuanceDate,
    },
    tlsNotary: {
      notaryPublicKeyHex: options.notaryPublicKeyHex,
      privateRanges: options.privateRanges,
      presentationBase64: options.presentation.toString('base64'),
    },
    noir: {
      programIdentity: options.programIdentity,
      publicInputsBase64: options.publicInputs.toString('base64'),
      proofBase64: options.proof.toString('base64'),
    },
  };
}
