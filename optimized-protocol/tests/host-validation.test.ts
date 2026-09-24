import assert from 'node:assert/strict';
import { describe, test } from 'node:test';

import {
  documentProfiles,
  getDocumentProfileByTlsProfile,
} from '../utils/document-profiles';
import { parseVerificationInfo } from '../utils/extract-verification-info';
import { getResidenceCity, residenceCities } from '../utils/residence-cities';
import {
  extractPageContentStream as extractMilitaryStream,
  parseArguments as parseMilitaryArguments,
} from '../scripts/prepare-military-service-witness';
import {
  extractPageContentStream as extractResidenceStream,
  findAddressBlock,
  findTextOperations,
  parseArguments as parseResidenceArguments,
} from '../scripts/prepare-residence-witness';
import {
  extractPageContentStream as extractCriminalRecordStream,
  parseArguments as parseCriminalRecordArguments,
} from '../scripts/prepare-criminal-record-witness';
import {
  extractPageContentStream as extractTaxDebtStream,
  parseArguments as parseTaxDebtArguments,
} from '../scripts/prepare-tax-debt-witness';
import { isTurkishIdentityNumber } from '../utils/turkish-identity-number';
import { isStoredProofRecord } from '../utils/proof-record-types';

function minimalPdf(contentObjectNumber = 42): Buffer {
  const stream = 'private content';
  return Buffer.from([
    '%PDF-1.4',
    '9 0 obj',
    `<< /Type /Page /Contents ${contentObjectNumber} 0 R >>`,
    'endobj',
    `${contentObjectNumber} 0 obj`,
    `<< /Length ${Buffer.byteLength(stream)} >>`,
    'stream',
    stream,
    'endstream',
    'endobj',
  ].join('\n'), 'latin1');
}

function minimalCriminalRecordPdf(contentObjectNumber = 42): Buffer {
  const references = [6, 9, contentObjectNumber, 10, 7];
  const objects = references.map((number) => {
    const stream = number === contentObjectNumber ? 'private content' : 'x';
    return [
      `${number} 0 obj`,
      `<< /Length ${Buffer.byteLength(stream)} >>`,
      'stream', stream, 'endstream', 'endobj',
    ].join('\n');
  });
  return Buffer.from([
    '%PDF-1.5',
    '22 0 obj',
    `<< /Type /Page /Contents [${references.map((number) => `${number} 0 R`).join(' ')}] >>`,
    'endobj',
    ...objects,
  ].join('\n'), 'latin1');
}

describe('document profile registry', () => {
  test('keeps protocol identifiers unique and resolves TLS profiles', () => {
    const profiles = Object.values(documentProfiles);
    for (const field of ['tlsProfile', 'recordVersion', 'noirProgram'] as const) {
      assert.equal(new Set(profiles.map((profile) => profile[field])).size, profiles.length);
    }
    for (const profile of profiles) {
      assert.equal(getDocumentProfileByTlsProfile(profile.tlsProfile), profile);
      assert.equal(
        profile.privateRangeKinds.filter((kind) => kind === 'content-stream').length,
        1,
      );
    }
  });
});

describe('residence city table', () => {
  test('contains every unique plate code in order', () => {
    assert.equal(residenceCities.length, 81);
    assert.deepEqual(residenceCities.map(({ code }) => code),
      Array.from({ length: 81 }, (_, index) => index + 1));
    assert.equal(new Set(residenceCities.map(({ name }) => name)).size, 81);
  });

  test('accepts canonical codes and rejects ambiguous values', () => {
    assert.equal(getResidenceCity('34')?.name, 'İSTANBUL');
    assert.equal(getResidenceCity(81)?.name, 'DÜZCE');
    for (const value of [undefined, '01', '0', '82', 1.5, Number.NaN]) {
      assert.equal(getResidenceCity(value), undefined);
    }
  });
});

describe('verification information parsing', () => {
  const identityNumber = '12345678901';

  test('accepts residence barcodes with general alphanumeric groups', () => {
    for (const barcode of [
      'AB12-CD34-EFG5-HIJ6',
      'AB12-CD3E-FGHI-JKLM',
    ]) {
      assert.deepEqual(
        parseVerificationInfo(`${barcode} ${identityNumber}`, 'residence'),
        { barcode, idNumber: identityNumber },
      );
    }
  });

  test('rejects ambiguous and non-alphanumeric residence barcode candidates', () => {
    assert.throws(
      () => parseVerificationInfo(
        `AB12-CD34-EFG5-HIJ6 KL78-MN90-OPQ1-RST2 ${identityNumber}`,
        'residence',
      ),
      /expected document barcode/,
    );
    assert.throws(
      () => parseVerificationInfo(`ABCD-EFGH-IJKL-MNOP ${identityNumber}`, 'residence'),
      /expected document barcode/,
    );
  });

  test('accepts the criminal-record barcode and identity labels', () => {
    assert.deepEqual(
      parseVerificationInfo(
        'ADB02612345678 SAYI : 0000-2026-1234567890 / 12:34 '
          + 'KİMLİK NUMARASI : 10000000146',
        'criminal-record',
      ),
      { barcode: 'ADB02612345678', idNumber: '10000000146' },
    );
  });

  test('extracts GIB tax-debt verification fields', () => {
    assert.deepEqual(
      parseVerificationInfo(
        'SAYI : 9pmttowqy11oly Düzenleme Tarihi: 03/09/2026 '
          + 'T.C. Kimlik Numarası : 10000000146',
        'tax-debt',
      ),
      {
        petitionNumber: '9pmttowqy11oly',
        idNumber: '10000000146',
        issuanceDate: '2026-09-03',
        issuanceDateYyyymmdd: 20260903,
      },
    );
  });

  test('does not treat the criminal-record SAYI as its barcode', () => {
    assert.throws(
      () => parseVerificationInfo(
        'SAYI : 0000-2026-1234567890 / 12:34 KİMLİK NUMARASI : 10000000146',
        'criminal-record',
      ),
      /expected document barcode/,
    );
  });
});

describe('Turkish identity numbers', () => {
  test('checks length, leading digit, and both checksum digits', () => {
    assert.equal(isTurkishIdentityNumber('10000000146'), true);
    for (const value of ['00000000146', '10000000145', '12345678901', 'not-an-id']) {
      assert.equal(isTurkishIdentityNumber(value), false);
    }
  });
});

describe('criminal-record proof records', () => {
  test('binds the public identity number to the exact Noir public-input field', () => {
    const fields = Buffer.alloc(6 * 32);
    fields.writeBigUInt64BE(828n, 4 * 32 + 24);
    fields.writeBigUInt64BE(10000000146n, 5 * 32 + 24);
    const profile = documentProfiles['criminal-record'];
    const record = {
      version: profile.recordVersion,
      documentType: profile.documentType,
      profile: profile.tlsProfile,
      createdAt: '2026-09-03T00:00:00.000Z',
      mode: 'ultrahonk',
      publicInputs: {
        contentStreamCommitmentHex: '00'.repeat(32),
        compressedLength: 828,
        identityNumber: '10000000146',
      },
      tlsNotary: {
        notaryPublicKeyHex: `02${'00'.repeat(32)}`,
        privateRanges: profile.privateRangeKinds.map((kind, index) => ({
          kind, offset: index * 100, length: 1, commitmentHex: '00'.repeat(32),
        })).map((range) => range.kind === 'content-stream'
          ? { ...range, length: 828 }
          : range),
        presentationBase64: 'AA==',
      },
      noir: {
        programIdentity: {
          version: 'zk-devlet-noir-program-identity-v1',
          program: profile.noirProgram,
          verifierTarget: 'evm',
          bytecodeSha256: '00'.repeat(32),
          verificationKeySha256: '00'.repeat(32),
          solidityVerifierSha256: '00'.repeat(32),
          toolchain: {
            noir: '1.0.0-beta.22',
            barretenberg: '5.0.0-nightly.20260522',
            proofSystem: 'ultrahonk',
            oracleHash: 'keccak',
          },
        },
        publicInputsBase64: fields.toString('base64'),
        proofBase64: 'AA==',
      },
    };
    assert.equal(isStoredProofRecord(record), true);
    record.publicInputs.identityNumber = '10000000145';
    assert.equal(isStoredProofRecord(record), false);
  });
});

describe('witness command validation', () => {
  const shared = [
    '--stream', '/private/stream',
    '--blinder', '00'.repeat(16),
    '--output', '/private/Prover.toml',
  ];

  test('parses valid profile-specific arguments', () => {
    const military = parseMilitaryArguments([
      ...shared, '--date', '20260901', '--months', '12',
    ]);
    assert.equal(military.assertionMonths, 12);

    const residence = parseResidenceArguments([
      ...shared, '--city-code', '34', '--city-encoding', '00410042',
    ]);
    assert.equal(residence.cityCode, 34);
    assert.equal(residence.cityEncoding.toString('hex'), '00410042');

    const criminal = parseCriminalRecordArguments([
      ...shared, '--identity', '10000000146',
    ]);
    assert.equal(criminal.identityNumber, '10000000146');

    const taxDebt = parseTaxDebtArguments([
      ...shared, '--identity', '10000000146', '--issuance-date', '20260903',
    ]);
    assert.equal(taxDebt.issuanceDateYyyymmdd, 20260903);
  });

  test('rejects duplicate, unknown, and invalid arguments', () => {
    assert.throws(() => parseMilitaryArguments([
      ...shared, '--date', '20260901', '--months', '0',
    ]), /outside their supported range/);
    assert.throws(() => parseMilitaryArguments([
      ...shared, '--date', '20260901', '--months', '1', '--months', '2',
    ]), /Duplicate argument/);
    assert.throws(() => parseResidenceArguments([
      ...shared, '--city-code', '34', '--city-encoding', '0041', '--extra', 'x',
    ]), /Unknown argument/);
    assert.throws(() => parseCriminalRecordArguments([
      ...shared, '--identity', '10000000145',
    ]), /valid 11-digit/);
    assert.throws(() => parseTaxDebtArguments([
      ...shared, '--identity', '10000000145', '--issuance-date', '20260903',
    ]), /valid 11-digit/);
  });
});

describe('semantic PDF content lookup', () => {
  test('does not depend on a fixed content object number', () => {
    for (const objectNumber of [4, 42, 987]) {
      const pdf = minimalPdf(objectNumber);
      assert.equal(extractMilitaryStream(pdf).toString(), 'private content');
      assert.equal(extractResidenceStream(pdf).toString(), 'private content');
      assert.equal(
        extractCriminalRecordStream(minimalCriminalRecordPdf(objectNumber)).toString(),
        'private content',
      );
      assert.equal(extractTaxDebtStream(pdf).toString(), 'private content');
    }
  });

  test('rejects duplicate referenced objects and incorrect stream lengths', () => {
    const duplicated = Buffer.concat([
      minimalPdf(),
      Buffer.from('\n42 0 obj\n<< /Length 1 >>\nstream\nx\nendstream\nendobj'),
    ]);
    assert.throws(() => extractMilitaryStream(duplicated), /not unique/);
    const wrongLength = Buffer.from(minimalPdf().toString('latin1').replace(
      '/Length 15',
      '/Length 14',
    ), 'latin1');
    assert.throws(() => extractResidenceStream(wrongLength), /does not end at endstream/);
  });
});

describe('residence address layout', () => {
  test('selects the final text operation from variable-length address blocks', () => {
    for (const lineCount of [2, 3]) {
      const addressLines = Array.from(
        { length: lineCount },
        (_, index) => `<00${index + 1}> Tj`,
      ).join('\n1 1 Td\n');
      const content = Buffer.from([
        'BT',
        '/Font_1 -10 Tf',
        '1 1 Td',
        addressLines,
        'ET',
        'BT',
        '/Font_1 -10 Tf',
        '1 1 Td',
        '<0041> Tj',
        'ET',
      ].join('\n'));
      const operations = findTextOperations(content);
      const address = findAddressBlock(content, operations);
      assert.equal(address.operations.length, lineCount);
      assert.equal(address.operations.at(-1)?.valueEnd, operations[lineCount - 1].valueEnd);
    }
  });
});
