import { documentProfiles } from './document-profiles';
import {
  runNoirProof,
  type CommitmentOpening,
  type NoirPerformanceOptions,
  type NoirProofResult,
} from './noir-proof-runner';
import { isTurkishIdentityNumber } from './turkish-identity-number';

const profile = documentProfiles['criminal-record'];

export interface PerformCriminalRecordProofOptions extends CommitmentOpening {
  identityNumber: string;
}

export type CriminalRecordProofResult = NoirProofResult<typeof profile.noirProgram>;

export function performCriminalRecordProof(
  options: PerformCriminalRecordProofOptions,
  performance: NoirPerformanceOptions = {},
): Promise<CriminalRecordProofResult> {
  if (!isTurkishIdentityNumber(options.identityNumber)) {
    throw new Error('The public identity number is invalid.');
  }
  return runNoirProof(profile, {
    ...options,
    witnessArguments: ['--identity', options.identityNumber],
    claimPublicU64s: [BigInt(options.identityNumber)],
  }, performance);
}
