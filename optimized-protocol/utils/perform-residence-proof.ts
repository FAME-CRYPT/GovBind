import { documentProfiles } from './document-profiles';
import {
  runNoirProof,
  type CommitmentOpening,
  type NoirPerformanceOptions,
  type NoirProofResult,
} from './noir-proof-runner';
import { getResidenceCity } from './residence-cities';

const profile = documentProfiles.residence;

export interface PerformResidenceProofOptions extends CommitmentOpening {
  cityCode: number;
  cityEncodingHex: string;
}

export type ResidenceProofResult = NoirProofResult<typeof profile.noirProgram>;

export function performResidenceProof(
  options: PerformResidenceProofOptions,
  performance: NoirPerformanceOptions = {},
): Promise<ResidenceProofResult> {
  if (
    !getResidenceCity(options.cityCode) ||
    !/^(?:[0-9a-f]{4}){1,16}$/.test(options.cityEncodingHex)
  ) {
    throw new Error('The Noir public assertion parameters are invalid.');
  }
  const cityEncoding = Buffer.from(options.cityEncodingHex, 'hex');
  return runNoirProof(profile, {
    ...options,
    witnessArguments: [
      '--city-code',
      String(options.cityCode),
      '--city-encoding',
      options.cityEncodingHex,
    ],
    claimPublicU64s: [
      BigInt(options.cityCode),
      BigInt(cityEncoding.length),
      ...[...cityEncoding, ...Buffer.alloc(32 - cityEncoding.length)]
        .map((byte) => BigInt(byte)),
    ],
  }, performance);
}
