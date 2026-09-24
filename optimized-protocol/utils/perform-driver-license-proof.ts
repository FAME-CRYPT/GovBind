import { documentProfiles } from './document-profiles';
import {
  runNoirProof,
  type CommitmentOpening,
  type NoirPerformanceOptions,
  type NoirProofResult,
} from './noir-proof-runner';

const profile = documentProfiles['driver-license'];

export interface PerformDriverLicenseProofOptions extends CommitmentOpening {
  maximumTrafficTickets: number;
  maximumTotalPenaltyPoints: number;
  maximumActivePenaltyPoints: number;
}

export type DriverLicenseProofResult = NoirProofResult<typeof profile.noirProgram>;

function requireThreshold(value: number): void {
  if (!Number.isSafeInteger(value) || value < 1 || value > 0xffff_ffff) {
    throw new Error('Traffic penalty thresholds must be positive 32-bit integers.');
  }
}

export function performDriverLicenseProof(
  options: PerformDriverLicenseProofOptions,
  performance: NoirPerformanceOptions = {},
): Promise<DriverLicenseProofResult> {
  requireThreshold(options.maximumTrafficTickets);
  requireThreshold(options.maximumTotalPenaltyPoints);
  requireThreshold(options.maximumActivePenaltyPoints);
  return runNoirProof(profile, {
    ...options,
    witnessArguments: [
      '--maximum-traffic-tickets', String(options.maximumTrafficTickets),
      '--maximum-total-penalty-points', String(options.maximumTotalPenaltyPoints),
      '--maximum-active-penalty-points', String(options.maximumActivePenaltyPoints),
    ],
    claimPublicU64s: [
      BigInt(options.maximumTrafficTickets),
      BigInt(options.maximumTotalPenaltyPoints),
      BigInt(options.maximumActivePenaltyPoints),
    ],
  }, performance);
}
