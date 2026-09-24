import { spawn } from 'node:child_process';
import path from 'node:path';

const projectDirectory = path.resolve(__dirname, '..', '..');
const runnerPath = path.join(
  projectDirectory,
  'native',
  'zkproofs',
  'military-service',
  'target',
  'release',
  'military-service',
);
const PROCESS_TIMEOUT_MS = 10 * 60_000;
const MAX_STDOUT_BYTES = 16 * 1024;
const MAX_STDERR_BYTES = 64 * 1024;

export interface PerformMilitaryServiceProofOptions {
  pdfPath: string;
  commitmentHex: string;
  blinderHex: string;
  documentDate: string;
  today: string;
  assertionMonths: number;
}

export interface MilitaryServiceProofExecutionResult {
  publicValuesHex: string;
  totalInstructionCount: number;
  proverGas: number;
}

interface NativeExecutionResult {
  version: string;
  publicValuesHex: string;
  totalInstructionCount: number;
  proverGas: number;
}

function parseNativeResult(
  stdout: string,
  expectedPublicValuesHex: string,
): MilitaryServiceProofExecutionResult {
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    throw new Error('The military-service SP1 runner returned invalid JSON.');
  }

  if (!parsed || typeof parsed !== 'object') {
    throw new Error('The military-service SP1 runner returned invalid metadata.');
  }
  const value = parsed as NativeExecutionResult;
  if (
    value.version !== 'zk-devlet-military-service-execution-v2' ||
    value.publicValuesHex !== expectedPublicValuesHex ||
    !Number.isSafeInteger(value.totalInstructionCount) ||
    value.totalInstructionCount < 0 ||
    !Number.isSafeInteger(value.proverGas) ||
    value.proverGas < 0
  ) {
    throw new Error('The military-service SP1 runner returned invalid metadata.');
  }

  return {
    publicValuesHex: value.publicValuesHex,
    totalInstructionCount: value.totalInstructionCount,
    proverGas: value.proverGas,
  };
}

function encodePublicValues(
  commitmentHex: string,
  today: string,
  assertionMonths: number,
): string {
  const months = Buffer.allocUnsafe(4);
  months.writeUInt32BE(assertionMonths);
  return `${commitmentHex}${Buffer.from(today, 'ascii').toString('hex')}${months.toString('hex')}`;
}

export async function performMilitaryServiceProof({
  pdfPath,
  commitmentHex,
  blinderHex,
  documentDate,
  today,
  assertionMonths,
}: PerformMilitaryServiceProofOptions): Promise<MilitaryServiceProofExecutionResult> {
  if (!/^[0-9a-f]{64}$/.test(commitmentHex)) {
    throw new Error('The TLSNotary body commitment is invalid.');
  }
  if (!/^[0-9a-f]{32}$/.test(blinderHex)) {
    throw new Error('The TLSNotary body blinder is invalid.');
  }
  if (!/^\d{2}\/\d{2}\/\d{4}$/.test(documentDate)) {
    throw new Error('The private document date must use DD/MM/YYYY format.');
  }
  if (!/^\d{2}\/\d{2}\/\d{4}$/.test(today)) {
    throw new Error('The public generation date must use DD/MM/YYYY format.');
  }
  if (
    !Number.isSafeInteger(assertionMonths) ||
    assertionMonths < 0 ||
    assertionMonths > 0xffff_ffff
  ) {
    throw new Error('The public time assertion must fit in an unsigned 32-bit integer.');
  }

  const expectedPublicValuesHex = encodePublicValues(
    commitmentHex,
    today,
    assertionMonths,
  );

  return new Promise((resolve, reject) => {
    const child = spawn(runnerPath, [], { stdio: ['pipe', 'pipe', 'pipe'] });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let stdoutLength = 0;
    let stderrLength = 0;
    let settled = false;

    const finish = (error?: Error): void => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      if (error) {
        reject(error);
        return;
      }

      try {
        resolve(
          parseNativeResult(
            Buffer.concat(stdout).toString('utf8'),
            expectedPublicValuesHex,
          ),
        );
      } catch (parseError) {
        reject(parseError);
      }
    };

    const timer = setTimeout(() => {
      child.kill('SIGTERM');
      finish(new Error('The military-service SP1 execution timed out.'));
    }, PROCESS_TIMEOUT_MS);

    child.once('error', (error) => {
      finish(new Error(`Could not start the military-service SP1 runner: ${error.message}`));
    });
    child.stdin.once('error', (error) => {
      finish(new Error(`Could not send input to the military-service SP1 runner: ${error.message}`));
    });
    child.stdout.on('data', (chunk: Buffer) => {
      stdoutLength += chunk.length;
      if (stdoutLength > MAX_STDOUT_BYTES) {
        child.kill('SIGTERM');
        finish(new Error('The military-service SP1 runner output exceeded its size limit.'));
        return;
      }
      stdout.push(chunk);
    });
    child.stderr.on('data', (chunk: Buffer) => {
      stderrLength += chunk.length;
      if (stderrLength <= MAX_STDERR_BYTES) {
        stderr.push(chunk);
      }
    });
    child.once('close', (code, signal) => {
      if (code !== 0) {
        const details = Buffer.concat(stderr).toString('utf8').trim();
        finish(
          new Error(
            `The military-service SP1 runner failed${
              signal ? ` with signal ${signal}` : ` with exit code ${code ?? 'unknown'}`
            }${details ? `: ${details}` : ''}`,
          ),
        );
        return;
      }
      finish();
    });

    child.stdin.end(
      JSON.stringify({
        pdfPath,
        commitmentHex,
        blinderHex,
        documentDate,
        today,
        assertionMonths,
      }),
    );
  });
}
