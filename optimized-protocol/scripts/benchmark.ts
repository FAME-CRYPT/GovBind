import { randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import {
  chmod,
  readFile,
  rename,
  stat,
  unlink,
  writeFile,
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import dotenv from 'dotenv';

import {
  contentStreamRange,
  createGeneratedProofRecord,
  generateNoirProof,
  type PublicParameters,
} from '../utils/document-proof';
import {
  documentProfiles,
  type DocumentType,
} from '../utils/document-profiles';
import {
  extractVerificationInfo,
  type VerificationInfo,
} from '../utils/extract-verification-info';
import { trustedNotaryPublicKey } from '../utils/notary-trust';
import {
  captureZkTlsBenchmark,
  performZkTlsBenchmark,
} from '../utils/perform-zktls-verification';
import { prepareVerificationSession } from '../utils/prepare-verification-session';
import { prepareTaxDebtVerificationSession } from '../utils/prepare-tax-debt-verification-session';
import {
  isNoirProgramIdentity,
  isStoredProofRecord,
  type NoirProgramIdentity,
} from '../utils/proof-record-types';
import { getResidenceCity } from '../utils/residence-cities';
import { verifyStoredProofRecord } from '../utils/verify-stored-proof-record';

dotenv.config({ quiet: true });

const projectDirectory = path.resolve(__dirname, '..', '..');
const resultsPath = path.join(projectDirectory, 'benchmarks.json');
const DEFAULT_RUNS = 5;
const DEFAULT_VERIFICATION_RUNS = 20;

interface Options {
  profile: DocumentType;
  pdfPath: string;
  runs: number;
  verificationRuns: number;
  comparisonDate?: string;
  comparisonDateYyyymmdd?: number;
  assertionMonths?: number;
  cityCode?: number;
  maximumTrafficTickets?: number;
  maximumTotalPenaltyPoints?: number;
  maximumActivePenaltyPoints?: number;
}

interface Statistics {
  count: number;
  meanMs: number;
  medianMs: number;
  minimumMs: number;
  maximumMs: number;
  standardDeviationMs: number;
}

interface VerificationRun {
  tlsNotaryMs: number;
  noirMs: number;
  totalMs: number;
}

interface BenchmarkRun {
  generation: {
    zkTlsMs: number;
    noirMs: number;
    noirSelfVerificationMs: number;
    noirTotalMs: number;
    totalMs: number;
    zkTlsPeakRssBytes: number;
    noirPeakRssBytes: number;
  };
  verification: VerificationRun[];
  sizes: {
    responseBodyBytes: number;
    compressedStreamBytes: number;
    presentationBytes: number;
    proofBytes: number;
    publicInputsBytes: number;
    privateRanges: Array<{ kind: string; length: number }>;
  };
}

interface BenchmarkRecord {
  version: 'zk-devlet-benchmark-v2';
  id: string;
  createdAt: string;
  status: 'incomplete' | 'complete';
  configuration: {
    command: string;
    profile: DocumentType;
    runs: number;
    verificationRunsPerProof: number;
  };
  environment: {
    platform: NodeJS.Platform;
    operatingSystemRelease: string;
    architecture: string;
    cpu: string;
    logicalCpuCount: number;
    totalMemoryBytes: number;
    node: string;
    programIdentity: NoirProgramIdentity;
  };
  runs: BenchmarkRun[];
  summary?: {
    zkTlsGeneration: Statistics;
    noirGeneration: Statistics;
    noirSelfVerification: Statistics;
    totalGeneration: Statistics;
    zkTlsVerification: Statistics;
    noirVerification: Statistics;
    totalVerification: Statistics;
  };
}

function usage(): string {
  return [
    'Usage:',
    '  npm run benchmark -- --profile military-service --pdf <path> --date <YYYYMMDD> --months <n> [--runs <n>] [--verification-runs <n>]',
    '  npm run benchmark -- --profile residence --pdf <path> --city-code <1..81> [--runs <n>] [--verification-runs <n>]',
    '  npm run benchmark -- --profile criminal-record --pdf <path> [--runs <n>] [--verification-runs <n>]',
    '  npm run benchmark -- --profile driver-license --pdf <path> --maximum-traffic-tickets <n> --maximum-total-penalty-points <n> --maximum-active-penalty-points <n> [--runs <n>] [--verification-runs <n>]',
    '  npm run benchmark -- --profile tax-debt --pdf <path> [--runs <n>] [--verification-runs <n>]',
    '',
    'Run npm run build first and start the local Notary separately.',
    'Preparation is reported for context but excluded from benchmark results.',
  ].join('\n');
}

function benchmarkCommand(argv: string[]): string {
  return [
    'npm',
    'run',
    'benchmark',
    '--',
    ...argv.map((argument) => `'${argument.replaceAll("'", `'"'"'`)}'`),
  ].join(' ');
}

function positiveInteger(value: string | undefined, name: string): number {
  if (!value || !/^\d+$/.test(value)) throw new Error(`${name} must be a positive integer.`);
  const result = Number(value);
  if (!Number.isSafeInteger(result) || result < 1) {
    throw new Error(`${name} must be a positive integer.`);
  }
  return result;
}

function parseDate(value: string | undefined): { text: string; number: number } {
  if (!value || !/^\d{8}$/.test(value)) throw new Error('--date must use YYYYMMDD format.');
  const year = Number(value.slice(0, 4));
  const month = Number(value.slice(4, 6));
  const day = Number(value.slice(6, 8));
  const date = new Date(Date.UTC(year, month - 1, day));
  if (
    date.getUTCFullYear() !== year ||
    date.getUTCMonth() !== month - 1 ||
    date.getUTCDate() !== day
  ) {
    throw new Error('--date must be a real Gregorian date.');
  }
  return {
    text: `${value.slice(0, 4)}-${value.slice(4, 6)}-${value.slice(6, 8)}`,
    number: Number(value),
  };
}

function parseOptions(argv: string[]): Options {
  if (argv.includes('--help')) {
    console.log(usage());
    process.exit(0);
  }
  const values = new Map<string, string>();
  const allowed = new Set([
    '--profile', '--pdf', '--date', '--months', '--city-code', '--runs',
    '--verification-runs',
    '--maximum-traffic-tickets', '--maximum-total-penalty-points',
    '--maximum-active-penalty-points',
  ]);
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (!name?.startsWith('--') || value === undefined) {
      throw new Error(`Arguments must be provided as --name value pairs.\n\n${usage()}`);
    }
    if (!allowed.has(name)) throw new Error(`Unknown argument: ${name}`);
    if (values.has(name)) throw new Error(`Duplicate argument: ${name}`);
    values.set(name, value);
  }

  const profile = values.get('--profile') as DocumentType | undefined;
  if (!profile || !(profile in documentProfiles)) {
    throw new Error(`--profile must be one of: ${Object.keys(documentProfiles).join(', ')}.`);
  }
  const pdf = values.get('--pdf');
  if (!pdf) throw new Error('--pdf is required.');
  const runs = values.has('--runs')
    ? positiveInteger(values.get('--runs'), '--runs')
    : DEFAULT_RUNS;
  const verificationRuns = values.has('--verification-runs')
    ? positiveInteger(values.get('--verification-runs'), '--verification-runs')
    : DEFAULT_VERIFICATION_RUNS;
  if (runs > 100 || verificationRuns > 1_000) {
    throw new Error('--runs must not exceed 100 and --verification-runs must not exceed 1000.');
  }

  const common = {
    profile,
    pdfPath: path.resolve(process.cwd(), pdf),
    runs,
    verificationRuns,
  };
  const driverArguments = [
    '--maximum-traffic-tickets', '--maximum-total-penalty-points',
    '--maximum-active-penalty-points',
  ];
  if (profile === 'military-service') {
    if (values.has('--city-code') || driverArguments.some((name) => values.has(name))) {
      throw new Error('The selected claim arguments do not apply to military-service.');
    }
    const date = parseDate(values.get('--date'));
    const assertionMonths = positiveInteger(values.get('--months'), '--months');
    if (assertionMonths > 1200) throw new Error('--months must not exceed 1200.');
    return {
      ...common,
      comparisonDate: date.text,
      comparisonDateYyyymmdd: date.number,
      assertionMonths,
    };
  }
  if (profile === 'residence') {
    if (values.has('--date') || values.has('--months') ||
        driverArguments.some((name) => values.has(name))) {
      throw new Error('The selected claim arguments do not apply to residence.');
    }
    const city = getResidenceCity(values.get('--city-code'));
    if (!city) throw new Error('--city-code must be a supported city code from 1 to 81.');
    return { ...common, cityCode: city.code };
  }
  if (profile === 'driver-license') {
    if (values.has('--date') || values.has('--months') || values.has('--city-code')) {
      throw new Error('The selected arguments do not apply to driver-license.');
    }
    const maximumTrafficTickets = positiveInteger(
      values.get('--maximum-traffic-tickets'), '--maximum-traffic-tickets',
    );
    const maximumTotalPenaltyPoints = positiveInteger(
      values.get('--maximum-total-penalty-points'), '--maximum-total-penalty-points',
    );
    const maximumActivePenaltyPoints = positiveInteger(
      values.get('--maximum-active-penalty-points'), '--maximum-active-penalty-points',
    );
    if ([maximumTrafficTickets, maximumTotalPenaltyPoints, maximumActivePenaltyPoints]
      .some((value) => value > 0xffff_ffff)) {
      throw new Error('Driver-license thresholds must fit in 32 bits.');
    }
    return {
      ...common,
      maximumTrafficTickets,
      maximumTotalPenaltyPoints,
      maximumActivePenaltyPoints,
    };
  }
  if (values.has('--date') || values.has('--months') || values.has('--city-code') ||
      driverArguments.some((name) => values.has(name))) {
    throw new Error(`${profile} does not accept claim arguments.`);
  }
  return common;
}

function elapsedMilliseconds(startedAt: bigint): number {
  return Number(process.hrtime.bigint() - startedAt) / 1_000_000;
}

function seconds(milliseconds: number): string {
  return `${(milliseconds / 1000).toFixed(2)} s`;
}

function gibibytes(bytes: number): string {
  return `${(bytes / 1024 ** 3).toFixed(2)} GiB`;
}

function statistics(values: number[]): Statistics {
  const sorted = [...values].sort((left, right) => left - right);
  const mean = values.reduce((sum, value) => sum + value, 0) / values.length;
  const middle = Math.floor(sorted.length / 2);
  const median = sorted.length % 2 === 0
    ? (sorted[middle - 1] + sorted[middle]) / 2
    : sorted[middle];
  const variance = values.length < 2
    ? 0
    : values.reduce((sum, value) => sum + (value - mean) ** 2, 0) /
      (values.length - 1);
  return {
    count: values.length,
    meanMs: mean,
    medianMs: median,
    minimumMs: sorted[0],
    maximumMs: sorted[sorted.length - 1],
    standardDeviationMs: Math.sqrt(variance),
  };
}

function summarize(runs: BenchmarkRun[]): BenchmarkRecord['summary'] {
  const verification = runs.flatMap((run) => run.verification);
  return {
    zkTlsGeneration: statistics(runs.map((run) => run.generation.zkTlsMs)),
    noirGeneration: statistics(runs.map((run) => run.generation.noirMs)),
    noirSelfVerification: statistics(
      runs.map((run) => run.generation.noirSelfVerificationMs),
    ),
    totalGeneration: statistics(runs.map((run) => run.generation.totalMs)),
    zkTlsVerification: statistics(verification.map((run) => run.tlsNotaryMs)),
    noirVerification: statistics(verification.map((run) => run.noirMs)),
    totalVerification: statistics(verification.map((run) => run.totalMs)),
  };
}

async function readResults(): Promise<unknown[]> {
  try {
    const existing = JSON.parse(await readFile(resultsPath, 'utf8')) as unknown;
    if (!Array.isArray(existing)) throw new Error('benchmarks.json must contain a JSON array.');
    return existing;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw error;
  }
}

async function writeResults(results: unknown[]): Promise<void> {
  const temporaryPath = `${resultsPath}.${randomUUID()}.tmp`;
  try {
    await writeFile(temporaryPath, `${JSON.stringify(results, null, 2)}\n`, {
      mode: 0o600,
      flag: 'wx',
    });
    await rename(temporaryPath, resultsPath);
    await chmod(resultsPath, 0o600);
  } finally {
    await unlink(temporaryPath).catch(() => undefined);
  }
}

function publicParameters(
  options: Options,
  verificationInfo: VerificationInfo,
): PublicParameters {
  if (options.profile === 'military-service') {
    return {
      documentType: 'military-service',
      comparisonDate: options.comparisonDate!,
      comparisonDateYyyymmdd: options.comparisonDateYyyymmdd!,
      assertionMonths: options.assertionMonths!,
    };
  }
  if (options.profile === 'residence') {
    const city = getResidenceCity(options.cityCode)!;
    return { documentType: 'residence', cityCode: city.code, city: city.name };
  }
  if (options.profile === 'driver-license') {
    return {
      documentType: 'driver-license',
      maximumTrafficTickets: options.maximumTrafficTickets!,
      maximumTotalPenaltyPoints: options.maximumTotalPenaltyPoints!,
      maximumActivePenaltyPoints: options.maximumActivePenaltyPoints!,
    };
  }
  if (options.profile === 'tax-debt') {
    return {
      documentType: 'tax-debt',
      identityNumber: verificationInfo.idNumber,
      issuanceDate: verificationInfo.issuanceDate!,
      issuanceDateYyyymmdd: verificationInfo.issuanceDateYyyymmdd!,
    };
  }
  return { documentType: 'criminal-record', identityNumber: verificationInfo.idNumber };
}

async function preflight(options: Options): Promise<NoirProgramIdentity> {
  if (process.platform !== 'darwin') {
    throw new Error('Peak-memory measurement currently requires macOS /usr/bin/time -l.');
  }
  const pdfStat = await stat(options.pdfPath);
  if (!pdfStat.isFile()) throw new Error('--pdf must refer to a regular file.');
  const profile = documentProfiles[options.profile];
  const circuitTarget = path.join(
    projectDirectory, 'circuits', profile.circuitDirectory, 'target',
  );
  const requiredPaths = [
    path.join(projectDirectory, 'native', 'zktls', 'target', 'release',
      'govbind-optimized-zktls-prover'),
    path.join(projectDirectory, 'native', 'zktls', 'target', 'release',
      'govbind-optimized-zktls-verifier'),
    path.join(circuitTarget, profile.artifactName),
    path.join(circuitTarget, 'evm', 'vk'),
    path.join(circuitTarget, 'evm', 'Verifier.sol'),
    path.join(circuitTarget, 'evm', 'identity.json'),
  ];
  if (requiredPaths.some((requiredPath) => !existsSync(requiredPath))) {
    throw new Error('Required native or circuit artifacts are missing; run npm run build first.');
  }
  const identity = JSON.parse(
    await readFile(path.join(circuitTarget, 'evm', 'identity.json'), 'utf8'),
  ) as unknown;
  if (!isNoirProgramIdentity(identity, profile.noirProgram)) {
    throw new Error('The selected circuit identity is invalid; run npm run build first.');
  }
  return identity;
}

async function main(): Promise<void> {
  const options = parseOptions(process.argv.slice(2));
  const programIdentity = await preflight(options);
  const notaryPublicKeyHex = await trustedNotaryPublicKey();
  process.env.TLSN_NOTARY_PUBLIC_KEY = notaryPublicKeyHex;

  console.log(`Preparing ${documentProfiles[options.profile].displayName} benchmark...`);
  const preparationStartedAt = process.hrtime.bigint();
  const verificationInfo = await extractVerificationInfo(options.pdfPath, options.profile);
  const parameters = publicParameters(options, verificationInfo);
  console.log(
    `Initial preparation completed in ${seconds(elapsedMilliseconds(preparationStartedAt))} ` +
    `(excluded from benchmark).`,
  );

  const cpus = os.cpus();
  const record: BenchmarkRecord = {
    version: 'zk-devlet-benchmark-v2',
    id: randomUUID(),
    createdAt: new Date().toISOString(),
    status: 'incomplete',
    configuration: {
      command: benchmarkCommand(process.argv.slice(2)),
      profile: options.profile,
      runs: options.runs,
      verificationRunsPerProof: options.verificationRuns,
    },
    environment: {
      platform: process.platform,
      operatingSystemRelease: os.release(),
      architecture: process.arch,
      cpu: cpus[0]?.model ?? 'unknown',
      logicalCpuCount: cpus.length,
      totalMemoryBytes: os.totalmem(),
      node: process.version,
      programIdentity,
    },
    runs: [],
  };
  const results = await readResults();
  results.push(record);
  await writeResults(results);

  const zkTlsOptions = {
    profile: documentProfiles[options.profile].tlsProfile,
    ...(parameters.documentType === 'residence' ? { city: parameters.city } : {}),
    ...(parameters.documentType === 'criminal-record'
      ? { identityNumber: parameters.identityNumber }
      : {}),
    ...(parameters.documentType === 'tax-debt'
      ? { identityNumber: parameters.identityNumber }
      : {}),
  };

  console.log('Preparing one verification session for the benchmark capture...');
  const sessionStartedAt = process.hrtime.bigint();
  const session = options.profile === 'tax-debt'
    ? await prepareTaxDebtVerificationSession(
      verificationInfo.petitionNumber ?? '', verificationInfo.idNumber,
    )
    : await prepareVerificationSession({
      barcode: verificationInfo.barcode ?? '', idNumber: verificationInfo.idNumber,
    });
  console.log(
    `Session preparation completed in ${seconds(elapsedMilliseconds(sessionStartedAt))} ` +
    `(excluded from benchmark).`,
  );
  console.log('Capturing one authenticated TLS response for all benchmark runs...');
  const captureStartedAt = process.hrtime.bigint();
  const capture = await captureZkTlsBenchmark(session, zkTlsOptions);
  console.log(
    `Benchmark capture completed in ${seconds(elapsedMilliseconds(captureStartedAt))} ` +
    `(excluded from benchmark).`,
  );

  for (let runIndex = 0; runIndex < options.runs; runIndex += 1) {
    console.log(`Run ${runIndex + 1}/${options.runs}`);
    console.log('  Starting zkTLS generation from the stored capture...');
    const zkTls = await performZkTlsBenchmark(
      session,
      zkTlsOptions,
      capture,
      { measurePeakRss: true },
    );
    const zkTlsMs = zkTls.benchmarkMs;
    console.log(
      `  zkTLS generation completed in ${seconds(zkTlsMs)} ` +
      `(peak ${gibibytes(zkTls.peakRssBytes!)}); the download is excluded.`,
    );

    const range = contentStreamRange(zkTls);
    console.log('  Starting Noir generation and self-check...');
    const noirStartedAt = process.hrtime.bigint();
    const noir = await generateNoirProof(
      parameters,
      zkTls,
      range,
      { measurePeakRss: true },
    );
    const noirWallMs = elapsedMilliseconds(noirStartedAt);
    const noirMs = noir.performance.generationMs;
    console.log(
      `  Noir generation and self-check completed in ${seconds(noirWallMs)}: ` +
      `generation ${seconds(noirMs)}, self-check ` +
      `${seconds(noir.performance.selfVerificationMs)} ` +
      `(peak ${gibibytes(noir.performance.peakRssBytes!)}).`,
    );
    if (noir.programIdentity.program !== documentProfiles[options.profile].noirProgram) {
      throw new Error('The generated proof used the wrong document program.');
    }

    const proofRecord = createGeneratedProofRecord(
      parameters, zkTls, range, noir, notaryPublicKeyHex,
    );
    const verification: VerificationRun[] = [];
    console.log(`  Starting ${options.verificationRuns} independent verification run(s)...`);
    for (let verificationIndex = 0;
      verificationIndex < options.verificationRuns;
      verificationIndex += 1) {
      const verificationStartedAt = process.hrtime.bigint();
      if (!isStoredProofRecord(proofRecord)) {
        throw new Error('The generated benchmark proof record is invalid.');
      }
      const measured = await verifyStoredProofRecord(proofRecord);
      const result = {
        ...measured,
        totalMs: elapsedMilliseconds(verificationStartedAt),
      };
      verification.push(result);
      console.log(
        `    Verification ${verificationIndex + 1}/${options.verificationRuns} completed: ` +
        `zkTLS ${seconds(result.tlsNotaryMs)}, Noir ${seconds(result.noirMs)}, ` +
        `total ${seconds(result.totalMs)}.`,
      );
    }

    const run: BenchmarkRun = {
      generation: {
        zkTlsMs,
        noirMs,
        noirSelfVerificationMs: noir.performance.selfVerificationMs,
        noirTotalMs: noir.performance.totalMs,
        totalMs: zkTlsMs + noirMs,
        zkTlsPeakRssBytes: zkTls.peakRssBytes!,
        noirPeakRssBytes: noir.performance.peakRssBytes!,
      },
      verification,
      sizes: {
        responseBodyBytes: zkTls.responseBodyBytes,
        compressedStreamBytes: zkTls.contentStream.length,
        presentationBytes: zkTls.presentation.length,
        proofBytes: noir.proof.length,
        publicInputsBytes: noir.publicInputs.length,
        privateRanges: zkTls.privateRanges.map(({ kind, length }) => ({ kind, length })),
      },
    };
    record.runs.push(run);
    record.summary = summarize(record.runs);
    await writeResults(results);
    console.log(`  Run ${runIndex + 1} saved to ${resultsPath}.`);
    console.log(`  Total generation time: ${seconds(run.generation.totalMs)}.`);
  }

  record.status = 'complete';
  await writeResults(results);
  console.log(`Benchmark complete. Results saved to ${resultsPath}.`);
  console.log(`Average zkTLS generation: ${seconds(record.summary!.zkTlsGeneration.meanMs)}.`);
  console.log(`Average Noir generation:  ${seconds(record.summary!.noirGeneration.meanMs)}.`);
  console.log(`Average total generation: ${seconds(record.summary!.totalGeneration.meanMs)}.`);
  console.log(`Average total verification: ${seconds(record.summary!.totalVerification.meanMs)}.`);
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
