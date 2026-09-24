import { documentProfiles } from './document-profiles';
import {
  runNoirProof,
  type CommitmentOpening,
  type NoirPerformanceOptions,
  type NoirProofResult,
} from './noir-proof-runner';
import { isTurkishIdentityNumber } from './turkish-identity-number';

const profile = documentProfiles['tax-debt'];

export interface PerformTaxDebtProofOptions extends CommitmentOpening {
  identityNumber: string;
  issuanceDateYyyymmdd: number;
}

export type TaxDebtProofResult = NoirProofResult<typeof profile.noirProgram>;

export function performTaxDebtProof(
  options: PerformTaxDebtProofOptions,
  performance: NoirPerformanceOptions = {},
): Promise<TaxDebtProofResult> {
  if (!isTurkishIdentityNumber(options.identityNumber)) {
    throw new Error('The tax-debt identity number is invalid.');
  }
  const value = String(options.issuanceDateYyyymmdd);
  const year = Number(value.slice(0, 4));
  const month = Number(value.slice(4, 6));
  const day = Number(value.slice(6, 8));
  const date = new Date(Date.UTC(year, month - 1, day));
  if (!Number.isSafeInteger(options.issuanceDateYyyymmdd) || value.length !== 8 ||
      date.getUTCFullYear() !== year || date.getUTCMonth() !== month - 1 ||
      date.getUTCDate() !== day) {
    throw new Error('The tax-debt issuance date is invalid.');
  }
  return runNoirProof(profile, {
    ...options,
    witnessArguments: [
      '--identity', options.identityNumber,
      '--issuance-date', String(options.issuanceDateYyyymmdd),
    ],
    claimPublicU64s: [
      BigInt(options.identityNumber),
      BigInt(options.issuanceDateYyyymmdd),
    ],
  }, performance);
}
