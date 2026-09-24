import { documentProfiles } from './document-profiles';
import {
  runNoirProof,
  type CommitmentOpening,
  type NoirPerformanceOptions,
  type NoirProofResult,
} from './noir-proof-runner';

const profile = documentProfiles['military-service'];

export interface PerformMilitaryServiceProofOptions extends CommitmentOpening {
  comparisonDateYyyymmdd: number;
  assertionMonths: number;
}

export type MilitaryServiceProofResult = NoirProofResult<typeof profile.noirProgram>;

export function performMilitaryServiceProof(
  options: PerformMilitaryServiceProofOptions,
  performance: NoirPerformanceOptions = {},
): Promise<MilitaryServiceProofResult> {
  if (
    !Number.isInteger(options.comparisonDateYyyymmdd) ||
    !Number.isInteger(options.assertionMonths) ||
    options.assertionMonths < 1 ||
    options.assertionMonths > 1200
  ) {
    throw new Error('The Noir public assertion parameters are invalid.');
  }
  return runNoirProof(profile, {
    ...options,
    witnessArguments: [
      '--date',
      String(options.comparisonDateYyyymmdd),
      '--months',
      String(options.assertionMonths),
    ],
    claimPublicU64s: [
      BigInt(options.comparisonDateYyyymmdd),
      BigInt(options.assertionMonths),
    ],
  }, performance);
}
