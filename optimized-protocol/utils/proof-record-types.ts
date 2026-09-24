import type { AuthenticatedPrivateRange } from './perform-zktls-verification';
import { getResidenceCity } from './residence-cities';
import {
  documentProfiles,
  getDocumentProfile,
  type DocumentType,
  type NoirProgram,
  type PrivateRangeKind,
} from './document-profiles';
import { isTurkishIdentityNumber } from './turkish-identity-number';

export interface NoirProgramIdentity {
  version: 'zk-devlet-noir-program-identity-v1';
  program: NoirProgram;
  verifierTarget: 'evm';
  bytecodeSha256: string;
  verificationKeySha256: string;
  solidityVerifierSha256: string;
  toolchain: {
    noir: string;
    barretenberg: string;
    proofSystem: string;
    oracleHash: string;
  };
}

interface StoredProofBase {
  createdAt: string;
  mode: 'ultrahonk';
  tlsNotary: {
    notaryPublicKeyHex: string;
    privateRanges: AuthenticatedPrivateRange[];
    presentationBase64: string;
  };
  noir: {
    programIdentity: NoirProgramIdentity;
    publicInputsBase64: string;
    proofBase64: string;
  };
}

export interface MilitaryStoredProofRecord extends StoredProofBase {
  version: typeof documentProfiles['military-service']['recordVersion'];
  documentType: typeof documentProfiles['military-service']['documentType'];
  profile: typeof documentProfiles['military-service']['tlsProfile'];
  publicInputs: {
    contentStreamCommitmentHex: string;
    compressedLength: number;
    comparisonDateYyyymmdd: number;
    comparisonDate: string;
    assertionMonths: number;
  };
}

export interface ResidenceStoredProofRecord extends StoredProofBase {
  version: typeof documentProfiles.residence.recordVersion;
  documentType: typeof documentProfiles.residence.documentType;
  profile: typeof documentProfiles.residence.tlsProfile;
  publicInputs: {
    contentStreamCommitmentHex: string;
    compressedLength: number;
    cityCode: number;
    city: string;
    cityEncodingHex: string;
  };
}

export interface CriminalRecordStoredProofRecord extends StoredProofBase {
  version: typeof documentProfiles['criminal-record']['recordVersion'];
  documentType: typeof documentProfiles['criminal-record']['documentType'];
  profile: typeof documentProfiles['criminal-record']['tlsProfile'];
  publicInputs: {
    contentStreamCommitmentHex: string;
    compressedLength: number;
    identityNumber: string;
  };
}

export interface DriverLicenseStoredProofRecord extends StoredProofBase {
  version: typeof documentProfiles['driver-license']['recordVersion'];
  documentType: typeof documentProfiles['driver-license']['documentType'];
  profile: typeof documentProfiles['driver-license']['tlsProfile'];
  publicInputs: {
    contentStreamCommitmentHex: string;
    compressedLength: number;
    maximumTrafficTickets: number;
    maximumTotalPenaltyPoints: number;
    maximumActivePenaltyPoints: number;
  };
}

export interface TaxDebtStoredProofRecord extends StoredProofBase {
  version: typeof documentProfiles['tax-debt']['recordVersion'];
  documentType: typeof documentProfiles['tax-debt']['documentType'];
  profile: typeof documentProfiles['tax-debt']['tlsProfile'];
  publicInputs: {
    contentStreamCommitmentHex: string;
    compressedLength: number;
    identityNumber: string;
    issuanceDateYyyymmdd: number;
    issuanceDate: string;
  };
}

export type StoredProofRecord = MilitaryStoredProofRecord | ResidenceStoredProofRecord |
  CriminalRecordStoredProofRecord | DriverLicenseStoredProofRecord | TaxDebtStoredProofRecord;

export interface ProofRecordSummary {
  hash: string;
  documentType: DocumentType;
  documentLabel: string;
  program: StoredProofRecord['noir']['programIdentity']['program'];
  createdAt: string;
  mode: StoredProofRecord['mode'];
  assertion:
    | { kind: 'military-service'; today: string; months: number }
    | { kind: 'residence'; city: string }
    | { kind: 'criminal-record'; identityNumber: string }
    | { kind: 'tax-debt'; identityNumber: string; issuanceDate: string }
    | {
      kind: 'driver-license';
      maximumTrafficTickets: number;
      maximumTotalPenaltyPoints: number;
      maximumActivePenaltyPoints: number;
    };
  proofBytes: number;
}

function isBase64(value: unknown, maximumLength: number): value is string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > maximumLength ||
    !/^[A-Za-z0-9+/]+={0,2}$/.test(value)
  ) {
    return false;
  }
  return Buffer.from(value, 'base64').toString('base64') === value;
}

function hasExactKeys(value: object, expected: readonly string[]): boolean {
  const keys = Object.keys(value).sort();
  return keys.length === expected.length &&
    [...expected].sort().every((key, index) => key === keys[index]);
}

function isPrivateRanges(
  value: unknown,
  expectedKinds: readonly PrivateRangeKind[],
): value is AuthenticatedPrivateRange[] {
  return Array.isArray(value) &&
    value.length === expectedKinds.length &&
    value.every((candidate, index) => {
      if (!candidate || typeof candidate !== 'object') return false;
      const range = candidate as Partial<AuthenticatedPrivateRange>;
      return hasExactKeys(candidate, [
        'kind', 'offset', 'length', 'commitmentHex',
      ]) && range.kind === expectedKinds[index] &&
        Number.isSafeInteger(range.offset) && range.offset! >= 0 &&
        Number.isSafeInteger(range.length) && range.length! > 0 &&
        /^[0-9a-f]{64}$/.test(range.commitmentHex ?? '');
    });
}

function isIsoTimestamp(value: unknown): value is string {
  if (
    typeof value !== 'string' ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)
  ) {
    return false;
  }
  const timestamp = new Date(value);
  return !Number.isNaN(timestamp.getTime()) && timestamp.toISOString() === value;
}

function isGregorianDate(value: string): boolean {
  const match = value.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!match) return false;
  const [year, month, day] = match.slice(1).map(Number);
  const date = new Date(Date.UTC(year, month - 1, day));
  return date.getUTCFullYear() === year &&
    date.getUTCMonth() === month - 1 &&
    date.getUTCDate() === day;
}

export function isNoirProgramIdentity(
  value: unknown,
  program: NoirProgramIdentity['program'],
): value is NoirProgramIdentity {
  if (!value || typeof value !== 'object') return false;
  const identity = value as Partial<NoirProgramIdentity>;
  const toolchain = identity.toolchain as Partial<NoirProgramIdentity['toolchain']> | undefined;
  return hasExactKeys(value, [
    'version', 'program', 'verifierTarget', 'bytecodeSha256',
    'verificationKeySha256', 'solidityVerifierSha256', 'toolchain',
  ]) && !!toolchain && hasExactKeys(toolchain, [
    'noir', 'barretenberg', 'proofSystem', 'oracleHash',
  ]) && identity.version === 'zk-devlet-noir-program-identity-v1' && identity.program === program &&
    identity.verifierTarget === 'evm' && /^[0-9a-f]{64}$/.test(identity.bytecodeSha256 ?? '') &&
    /^[0-9a-f]{64}$/.test(identity.verificationKeySha256 ?? '') &&
    /^[0-9a-f]{64}$/.test(identity.solidityVerifierSha256 ?? '') &&
    toolchain?.noir === '1.0.0-beta.22' &&
    toolchain.barretenberg === '5.0.0-nightly.20260522' &&
    toolchain.proofSystem === 'ultrahonk' && toolchain.oracleHash === 'keccak';
}

function fieldsEqual(fields: Buffer, values: bigint[]): boolean {
  return fields.length === values.length * 32 && values.every((expected, index) =>
    fields.subarray(index * 32, index * 32 + 24).every((byte) => byte === 0) &&
    fields.readBigUInt64BE(index * 32 + 24) === expected);
}

function commitmentU64s(commitmentHex: string): bigint[] {
  return Array.from({ length: 4 }, (_, index) =>
    BigInt(`0x${commitmentHex.slice(index * 16, index * 16 + 16)}`),
  );
}

export function isStoredProofRecord(value: unknown): value is StoredProofRecord {
  if (!value || typeof value !== 'object') return false;
  const record = value as Partial<StoredProofRecord> & { publicInputs?: Record<string, unknown> };
  if (!hasExactKeys(value, [
    'version', 'documentType', 'profile', 'createdAt', 'mode',
    'publicInputs', 'tlsNotary', 'noir',
  ]) || record.mode !== 'ultrahonk' || !isIsoTimestamp(record.createdAt) ||
      !record.tlsNotary || !/^[0-9a-f]{66}$/.test(record.tlsNotary.notaryPublicKeyHex) ||
      !hasExactKeys(record.tlsNotary, [
        'notaryPublicKeyHex', 'privateRanges', 'presentationBase64',
      ]) ||
      !isBase64(record.tlsNotary.presentationBase64, 8 * 1024 * 1024) || !record.noir ||
      !hasExactKeys(record.noir, [
        'programIdentity', 'publicInputsBase64', 'proofBase64',
      ]) ||
      !isBase64(record.noir.publicInputsBase64, 2048) || !isBase64(record.noir.proofBase64, 64 * 1024) || !record.publicInputs) return false;

  const publicInputs = record.publicInputs;
  if (!/^[0-9a-f]{64}$/.test(String(publicInputs.contentStreamCommitmentHex ?? '')) ||
      !Number.isSafeInteger(publicInputs.compressedLength)) return false;
  const fields = Buffer.from(record.noir.publicInputsBase64, 'base64');

  const military = documentProfiles['military-service'];
  if (record.version === military.recordVersion && record.documentType === military.documentType && record.profile === military.tlsProfile) {
    if (!hasExactKeys(publicInputs, [
      'contentStreamCommitmentHex', 'compressedLength', 'comparisonDateYyyymmdd',
      'comparisonDate', 'assertionMonths',
    ]) || !isPrivateRanges(record.tlsNotary.privateRanges, military.privateRangeKinds) ||
        !isNoirProgramIdentity(record.noir.programIdentity, military.noirProgram) ||
        !Number.isSafeInteger(publicInputs.compressedLength) || Number(publicInputs.compressedLength) < 1 || Number(publicInputs.compressedLength) > military.maximumCompressedLength ||
        !isGregorianDate(String(publicInputs.comparisonDate ?? '')) || !Number.isSafeInteger(publicInputs.comparisonDateYyyymmdd) ||
        !Number.isSafeInteger(publicInputs.assertionMonths) || Number(publicInputs.assertionMonths) < 1 || Number(publicInputs.assertionMonths) > 1200) return false;
    const content = record.tlsNotary.privateRanges.find(({ kind }) => kind === 'content-stream');
    if (!content) return false;
    const date = String(publicInputs.comparisonDate);
    return content.commitmentHex === publicInputs.contentStreamCommitmentHex && content.length === publicInputs.compressedLength &&
      Number(date.replaceAll('-', '')) === publicInputs.comparisonDateYyyymmdd && fieldsEqual(fields, [
        ...commitmentU64s(String(publicInputs.contentStreamCommitmentHex)),
        BigInt(Number(publicInputs.compressedLength)), BigInt(Number(publicInputs.comparisonDateYyyymmdd)), BigInt(Number(publicInputs.assertionMonths)),
      ]);
  }

  const residence = documentProfiles.residence;
  if (record.version === residence.recordVersion && record.documentType === residence.documentType && record.profile === residence.tlsProfile) {
    if (!hasExactKeys(publicInputs, [
      'contentStreamCommitmentHex', 'compressedLength', 'cityCode', 'city',
      'cityEncodingHex',
    ]) || !isPrivateRanges(record.tlsNotary.privateRanges, residence.privateRangeKinds) ||
        !isNoirProgramIdentity(record.noir.programIdentity, residence.noirProgram) ||
        !Number.isSafeInteger(publicInputs.compressedLength) || Number(publicInputs.compressedLength) < 1 || Number(publicInputs.compressedLength) > residence.maximumCompressedLength ||
        !Number.isSafeInteger(publicInputs.cityCode) ||
        typeof publicInputs.city !== 'string' || !/^[A-ZÇĞİÖŞÜ]+$/.test(publicInputs.city) ||
        typeof publicInputs.cityEncodingHex !== 'string' || !/^(?:[0-9a-f]{4}){1,16}$/.test(publicInputs.cityEncodingHex)) return false;
    if (getResidenceCity(Number(publicInputs.cityCode))?.name !== publicInputs.city) return false;
    const content = record.tlsNotary.privateRanges.find(({ kind }) => kind === 'content-stream');
    if (!content) return false;
    const encoding = Buffer.from(publicInputs.cityEncodingHex, 'hex');
    return content.commitmentHex === publicInputs.contentStreamCommitmentHex && content.length === publicInputs.compressedLength && fieldsEqual(fields, [
      ...commitmentU64s(String(publicInputs.contentStreamCommitmentHex)),
      BigInt(Number(publicInputs.compressedLength)), BigInt(Number(publicInputs.cityCode)), BigInt(encoding.length),
      ...[...encoding, ...Buffer.alloc(32 - encoding.length)].map((byte) => BigInt(byte)),
    ]);
  }
  const criminal = documentProfiles['criminal-record'];
  if (record.version === criminal.recordVersion &&
      record.documentType === criminal.documentType && record.profile === criminal.tlsProfile) {
    if (!hasExactKeys(publicInputs, [
      'contentStreamCommitmentHex', 'compressedLength', 'identityNumber',
    ]) || !isPrivateRanges(record.tlsNotary.privateRanges, criminal.privateRangeKinds) ||
        !isNoirProgramIdentity(record.noir.programIdentity, criminal.noirProgram) ||
        !Number.isSafeInteger(publicInputs.compressedLength) ||
        Number(publicInputs.compressedLength) < 1 ||
        Number(publicInputs.compressedLength) > criminal.maximumCompressedLength ||
        !isTurkishIdentityNumber(publicInputs.identityNumber)) return false;
    const content = record.tlsNotary.privateRanges.find(({ kind }) => kind === 'content-stream');
    if (!content) return false;
    return content.commitmentHex === publicInputs.contentStreamCommitmentHex &&
      content.length === publicInputs.compressedLength && fieldsEqual(fields, [
        ...commitmentU64s(String(publicInputs.contentStreamCommitmentHex)),
        BigInt(Number(publicInputs.compressedLength)), BigInt(publicInputs.identityNumber),
      ]);
  }
  const driverLicense = documentProfiles['driver-license'];
  if (record.version === driverLicense.recordVersion &&
      record.documentType === driverLicense.documentType &&
      record.profile === driverLicense.tlsProfile) {
    if (!hasExactKeys(publicInputs, [
      'contentStreamCommitmentHex', 'compressedLength', 'maximumTrafficTickets',
      'maximumTotalPenaltyPoints', 'maximumActivePenaltyPoints',
    ]) || !isPrivateRanges(record.tlsNotary.privateRanges, driverLicense.privateRangeKinds) ||
        !isNoirProgramIdentity(record.noir.programIdentity, driverLicense.noirProgram) ||
        !Number.isSafeInteger(publicInputs.compressedLength) ||
        Number(publicInputs.compressedLength) < 1 ||
        Number(publicInputs.compressedLength) > driverLicense.maximumCompressedLength ||
        !isPositiveU32(publicInputs.maximumTrafficTickets) ||
        !isPositiveU32(publicInputs.maximumTotalPenaltyPoints) ||
        !isPositiveU32(publicInputs.maximumActivePenaltyPoints)) return false;
    const content = record.tlsNotary.privateRanges.find(({ kind }) => kind === 'content-stream');
    if (!content) return false;
    return content.commitmentHex === publicInputs.contentStreamCommitmentHex &&
      content.length === publicInputs.compressedLength && fieldsEqual(fields, [
        ...commitmentU64s(String(publicInputs.contentStreamCommitmentHex)),
        BigInt(Number(publicInputs.compressedLength)),
        BigInt(Number(publicInputs.maximumTrafficTickets)),
        BigInt(Number(publicInputs.maximumTotalPenaltyPoints)),
        BigInt(Number(publicInputs.maximumActivePenaltyPoints)),
      ]);
  }
  const taxDebt = documentProfiles['tax-debt'];
  if (record.version === taxDebt.recordVersion &&
      record.documentType === taxDebt.documentType && record.profile === taxDebt.tlsProfile) {
    if (!hasExactKeys(publicInputs, [
      'contentStreamCommitmentHex', 'compressedLength', 'identityNumber',
      'issuanceDateYyyymmdd', 'issuanceDate',
    ]) || !isPrivateRanges(record.tlsNotary.privateRanges, taxDebt.privateRangeKinds) ||
        !isNoirProgramIdentity(record.noir.programIdentity, taxDebt.noirProgram) ||
        !Number.isSafeInteger(publicInputs.compressedLength) ||
        Number(publicInputs.compressedLength) < 1 ||
        Number(publicInputs.compressedLength) > taxDebt.maximumCompressedLength ||
        !isTurkishIdentityNumber(publicInputs.identityNumber) ||
        !isGregorianDate(String(publicInputs.issuanceDate ?? '')) ||
        !Number.isSafeInteger(publicInputs.issuanceDateYyyymmdd) ||
        Number(publicInputs.issuanceDateYyyymmdd) < 20_000_101 ||
        Number(publicInputs.issuanceDateYyyymmdd) > 99_991_231) return false;
    const content = record.tlsNotary.privateRanges.find(({ kind }) => kind === 'content-stream');
    if (!content) return false;
    const issuanceDate = String(publicInputs.issuanceDate);
    return content.commitmentHex === publicInputs.contentStreamCommitmentHex &&
      content.length === publicInputs.compressedLength &&
      Number(issuanceDate.replaceAll('-', '')) === publicInputs.issuanceDateYyyymmdd &&
      fieldsEqual(fields, [
        ...commitmentU64s(String(publicInputs.contentStreamCommitmentHex)),
        BigInt(Number(publicInputs.compressedLength)),
        BigInt(String(publicInputs.identityNumber)),
        BigInt(Number(publicInputs.issuanceDateYyyymmdd)),
      ]);
  }
  return false;
}

function isPositiveU32(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) >= 1 && Number(value) <= 0xffff_ffff;
}

export function summarizeProofRecord(hash: string, record: StoredProofRecord): ProofRecordSummary {
  return {
    hash,
    documentType: record.documentType,
    documentLabel: getDocumentProfile(record.documentType).displayName,
    program: record.noir.programIdentity.program,
    createdAt: record.createdAt,
    mode: record.mode,
    assertion: record.documentType === 'military-service'
      ? { kind: 'military-service', today: record.publicInputs.comparisonDate, months: record.publicInputs.assertionMonths }
      : record.documentType === 'residence'
        ? { kind: 'residence', city: record.publicInputs.city }
        : record.documentType === 'criminal-record'
          ? { kind: 'criminal-record', identityNumber: record.publicInputs.identityNumber }
          : record.documentType === 'driver-license' ? {
            kind: 'driver-license',
            maximumTrafficTickets: record.publicInputs.maximumTrafficTickets,
            maximumTotalPenaltyPoints: record.publicInputs.maximumTotalPenaltyPoints,
            maximumActivePenaltyPoints: record.publicInputs.maximumActivePenaltyPoints,
          } : {
            kind: 'tax-debt',
            identityNumber: record.publicInputs.identityNumber,
            issuanceDate: record.publicInputs.issuanceDate,
          },
    proofBytes: Buffer.from(record.noir.proofBase64, 'base64').length,
  };
}
