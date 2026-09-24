import { readFile, readdir } from 'node:fs/promises';

import dotenv from 'dotenv';

import {
  computeProofHash,
  getProofPath,
  isProofHash,
  proofsDirectory,
} from '../utils/proof-record-hash';
import {
  isStoredProofRecord,
  type StoredProofRecord,
} from '../utils/proof-record-types';
import { verifyStoredProofRecord } from '../utils/verify-stored-proof-record';

dotenv.config({ quiet: true });

function addMonthsClamped(dateText: string, months: number): Date {
  const [year, month, day] = dateText.split('-').map(Number);
  const monthIndex = month - 1 + months;
  const targetYear = year + Math.floor(monthIndex / 12);
  const targetMonth = ((monthIndex % 12) + 12) % 12;
  const lastDay = new Date(Date.UTC(targetYear, targetMonth + 1, 0)).getUTCDate();
  return new Date(Date.UTC(targetYear, targetMonth, Math.min(day, lastDay)));
}

function formatDate(date: Date): string {
  return new Intl.DateTimeFormat('en-GB', {
    timeZone: 'UTC',
    day: 'numeric',
    month: 'long',
    year: 'numeric',
  }).format(date);
}

async function selectProofHash(argument: string | undefined): Promise<string> {
  if (argument !== undefined) {
    const hash = argument.toLowerCase();
    if (!isProofHash(hash)) {
      throw new Error('Proof hash must be exactly 64 hexadecimal characters.');
    }
    return hash;
  }

  const entries = await readdir(proofsDirectory, { withFileTypes: true });
  const hashes = entries
    .filter((entry) => entry.isFile() && /^[0-9a-f]{64}\.json$/.test(entry.name))
    .map((entry) => entry.name.slice(0, -'.json'.length))
    .sort((left, right) => left.localeCompare(right));
  if (hashes.length === 0) {
    throw new Error(`No proof records were found in ${proofsDirectory}.`);
  }
  return hashes[0];
}

async function loadProofRecord(hash: string): Promise<StoredProofRecord> {
  let contents: Buffer;
  try {
    contents = await readFile(getProofPath(hash));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      throw new Error(`Proof ${hash} was not found.`);
    }
    throw error;
  }
  if (computeProofHash(contents) !== hash) {
    throw new Error(`Proof ${hash} does not match its filename hash.`);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(contents.toString('utf8'));
  } catch {
    throw new Error(`Proof ${hash} does not contain valid JSON.`);
  }
  if (!isStoredProofRecord(parsed)) {
    throw new Error(`Proof ${hash} has an invalid record or public-input format.`);
  }
  return parsed;
}

function verifyTrustedNotary(record: StoredProofRecord): 'pinned' | 'embedded' {
  const configured = process.env.TLSN_NOTARY_PUBLIC_KEY;
  if (!configured) return 'embedded';

  const trustedKey = configured.toLowerCase();
  if (!/^[0-9a-f]{66}$/.test(trustedKey)) {
    throw new Error('TLSN_NOTARY_PUBLIC_KEY is not a compressed public key.');
  }
  if (trustedKey !== record.tlsNotary.notaryPublicKeyHex) {
    throw new Error('Proof was not signed by the configured trusted TLSNotary key.');
  }
  return 'pinned';
}

async function main(): Promise<void> {
  if (process.argv.length > 3) {
    throw new Error('Usage: npm run verify:proof -- [proof-hash]');
  }

  const hash = await selectProofHash(process.argv[2]);
  const record = await loadProofRecord(hash);
  const notaryTrust = verifyTrustedNotary(record);
  await verifyStoredProofRecord(record);

  const keyDescription = notaryTrust === 'pinned'
    ? 'configured trusted key'
    : 'key embedded in the proof record';

  console.log(`Verified proof ${hash}`);
  console.log(`TLSNotary: valid signature, HTTP provenance, and PDF range partition (${keyDescription}).`);
  console.log(`UltraHonk: valid proof for the pinned ${record.documentType} Noir program.`);
  console.log('Public inputs: valid and linked to the signed content-stream commitment.');
  if (record.documentType === 'military-service') {
    const comparison = new Date(`${record.publicInputs.comparisonDate}T00:00:00Z`);
    const cutoff = addMonthsClamped(record.publicInputs.comparisonDate, record.publicInputs.assertionMonths);
    const monthWord = record.publicInputs.assertionMonths === 1 ? 'month' : 'months';
    console.log(
      `Claim: This authenticated military-service document proves that its private ` +
      `valid-until date is later than ${formatDate(cutoff)}, which is ` +
      `${record.publicInputs.assertionMonths} ${monthWord} after ${formatDate(comparison)}.`,
    );
    console.log(`Freshness: not evaluated; the proof comparison date is ${record.publicInputs.comparisonDate}.`);
  } else if (record.documentType === 'residence') {
    console.log(`Claim: This authenticated residence document proves residence in ${record.publicInputs.city} without revealing the complete address.`);
    console.log('Freshness: not evaluated; consumers must apply an issuance-date policy from authenticated PDF metadata.');
  } else if (record.documentType === 'criminal-record') {
    console.log(
      `Claim: This authenticated criminal-record document proves that identity number ` +
      `${record.publicInputs.identityNumber} has no criminal record.`,
    );
    console.log('Freshness: not evaluated; consumers must apply their own document-age policy.');
  } else if (record.documentType === 'driver-license') {
    console.log(
      `Claim: This authenticated driver-license document proves traffic ticket count < ` +
      `${record.publicInputs.maximumTrafficTickets}, total penalty points < ` +
      `${record.publicInputs.maximumTotalPenaltyPoints}, and active penalty points < ` +
      `${record.publicInputs.maximumActivePenaltyPoints}.`,
    );
    console.log('Freshness: not evaluated; consumers must apply their own document-age policy.');
  } else {
    console.log(
      `Claim: This authenticated GİB document proves that identity number ` +
      `${record.publicInputs.identityNumber} had no overdue tax debt on ` +
      `${record.publicInputs.issuanceDate}.`,
    );
    console.log(`Freshness: not evaluated; the authenticated issuance date is ${record.publicInputs.issuanceDate}.`);
  }
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`Proof verification failed: ${message}`);
  process.exitCode = 1;
});
