import {
  performCriminalRecordProof,
  type CriminalRecordProofResult,
} from './perform-criminal-record-proof';
import {
  performDriverLicenseProof,
  type DriverLicenseProofResult,
} from './perform-driver-license-proof';
import {
  performMilitaryServiceProof,
  type MilitaryServiceProofResult,
} from './perform-military-service-proof';
import {
  performResidenceProof,
  type ResidenceProofResult,
} from './perform-residence-proof';
import {
  performTaxDebtProof,
  type TaxDebtProofResult,
} from './perform-tax-debt-proof';
import type {
  AuthenticatedPrivateRange,
  ZkTlsVerificationResult,
} from './perform-zktls-verification';
import {
  createCriminalRecordProofRecord,
  createDriverLicenseProofRecord,
  createMilitaryServiceProofRecord,
  createResidenceProofRecord,
  createTaxDebtProofRecord,
} from './save-proof-record';
import type { StoredProofRecord } from './proof-record-types';
import type { NoirPerformanceOptions } from './noir-proof-runner';

export type PublicParameters = {
  documentType: 'military-service';
  comparisonDate: string;
  comparisonDateYyyymmdd: number;
  assertionMonths: number;
} | {
  documentType: 'residence';
  cityCode: number;
  city: string;
} | {
  documentType: 'criminal-record';
  identityNumber: string;
} | {
  documentType: 'driver-license';
  maximumTrafficTickets: number;
  maximumTotalPenaltyPoints: number;
  maximumActivePenaltyPoints: number;
} | {
  documentType: 'tax-debt';
  identityNumber: string;
  issuanceDate: string;
  issuanceDateYyyymmdd: number;
};

export type NoirProofResult = MilitaryServiceProofResult | ResidenceProofResult |
  CriminalRecordProofResult | DriverLicenseProofResult | TaxDebtProofResult;

function requireResidenceCityEncoding(result: ZkTlsVerificationResult): string {
  if (!result.cityEncodingHex) {
    throw new Error('TLSNotary did not return the authenticated city encoding.');
  }
  return result.cityEncodingHex;
}

export function contentStreamRange(
  zkTls: ZkTlsVerificationResult,
): AuthenticatedPrivateRange {
  const range = zkTls.privateRanges.find((candidate) => candidate.kind === 'content-stream');
  if (!range) throw new Error('TLSNotary did not return a content-stream range.');
  return range;
}

export function generateNoirProof(
  parameters: PublicParameters,
  zkTls: ZkTlsVerificationResult,
  range: AuthenticatedPrivateRange,
  performance: NoirPerformanceOptions = {},
): Promise<NoirProofResult> {
  const commitment = {
    contentStream: zkTls.contentStream,
    blinderHex: zkTls.contentBlinderHex,
    commitmentHex: range.commitmentHex,
  };
  switch (parameters.documentType) {
    case 'military-service':
      return performMilitaryServiceProof({
        ...commitment,
        comparisonDateYyyymmdd: parameters.comparisonDateYyyymmdd,
        assertionMonths: parameters.assertionMonths,
      }, performance);
    case 'residence':
      return performResidenceProof({
        ...commitment,
        cityCode: parameters.cityCode,
        cityEncodingHex: requireResidenceCityEncoding(zkTls),
      }, performance);
    case 'criminal-record':
      return performCriminalRecordProof({
        ...commitment,
        identityNumber: parameters.identityNumber,
      }, performance);
    case 'driver-license':
      return performDriverLicenseProof({
        ...commitment,
        maximumTrafficTickets: parameters.maximumTrafficTickets,
        maximumTotalPenaltyPoints: parameters.maximumTotalPenaltyPoints,
        maximumActivePenaltyPoints: parameters.maximumActivePenaltyPoints,
      }, performance);
    case 'tax-debt':
      return performTaxDebtProof({
        ...commitment,
        identityNumber: parameters.identityNumber,
        issuanceDateYyyymmdd: parameters.issuanceDateYyyymmdd,
      }, performance);
  }
}

export function createGeneratedProofRecord(
  parameters: PublicParameters,
  zkTls: ZkTlsVerificationResult,
  range: AuthenticatedPrivateRange,
  noir: NoirProofResult,
  notaryPublicKeyHex: string,
): StoredProofRecord {
  const authenticatedProof = {
    contentStreamCommitmentHex: range.commitmentHex,
    compressedLength: range.length,
    notaryPublicKeyHex,
    privateRanges: zkTls.privateRanges,
    presentation: zkTls.presentation,
    programIdentity: noir.programIdentity,
    publicInputs: noir.publicInputs,
    proof: noir.proof,
  };
  switch (parameters.documentType) {
    case 'military-service':
      return createMilitaryServiceProofRecord({
        ...authenticatedProof,
        comparisonDateYyyymmdd: parameters.comparisonDateYyyymmdd,
        comparisonDate: parameters.comparisonDate,
        assertionMonths: parameters.assertionMonths,
      });
    case 'residence':
      return createResidenceProofRecord({
        ...authenticatedProof,
        cityCode: parameters.cityCode,
        city: parameters.city,
        cityEncodingHex: requireResidenceCityEncoding(zkTls),
      });
    case 'criminal-record':
      return createCriminalRecordProofRecord({
        ...authenticatedProof,
        identityNumber: parameters.identityNumber,
      });
    case 'driver-license':
      return createDriverLicenseProofRecord({
        ...authenticatedProof,
        maximumTrafficTickets: parameters.maximumTrafficTickets,
        maximumTotalPenaltyPoints: parameters.maximumTotalPenaltyPoints,
        maximumActivePenaltyPoints: parameters.maximumActivePenaltyPoints,
      });
    case 'tax-debt':
      return createTaxDebtProofRecord({
        ...authenticatedProof,
        identityNumber: parameters.identityNumber,
        issuanceDate: parameters.issuanceDate,
        issuanceDateYyyymmdd: parameters.issuanceDateYyyymmdd,
      });
  }
}
