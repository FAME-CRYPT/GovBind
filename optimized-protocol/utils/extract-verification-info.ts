import { readFile } from 'node:fs/promises';
import path from 'node:path';
import type { DocumentType } from './document-profiles';

export interface VerificationInfo {
  barcode?: string;
  petitionNumber?: string;
  issuanceDate?: string;
  issuanceDateYyyymmdd?: number;
  idNumber: string;
}

export function parseVerificationInfo(
  text: string,
  documentType: DocumentType,
): VerificationInfo {
  const normalizedText = text.normalize('NFKC').replace(/\s+/g, ' ').trim();
  if (documentType === 'tax-debt') {
    const uppercaseText = normalizedText.toLocaleUpperCase('tr-TR');
    const petitionNumber = normalizedText.match(
      /\b[Ss][Aa][Yy][Iİıi]\s*:\s*([A-Za-z0-9]{14})\b/u,
    )?.[1];
    const idNumber = uppercaseText.match(
      /\bT\.?\s*C\.?\s*KİMLİK NUMARASI\s*:\s*(\d{11})\b/u,
    )?.[1];
    const dateMatch = uppercaseText.match(
      /\bDÜZENLEME TARİHİ\s*:\s*(\d{2})\/(\d{2})\/(\d{4})\b/u,
    );
    if (!petitionNumber || !idNumber || !dateMatch) {
      throw new Error('Could not find the expected GIB petition, identity number, and issuance date.');
    }
    const issuanceDate = `${dateMatch[3]}-${dateMatch[2]}-${dateMatch[1]}`;
    const year = Number(dateMatch[3]);
    const month = Number(dateMatch[2]);
    const day = Number(dateMatch[1]);
    const parsedDate = new Date(Date.UTC(year, month - 1, day));
    if (parsedDate.getUTCFullYear() !== year || parsedDate.getUTCMonth() !== month - 1 ||
        parsedDate.getUTCDate() !== day) {
      throw new Error('The GIB issuance date is not a real Gregorian date.');
    }
    return {
      petitionNumber,
      idNumber,
      issuanceDate,
      issuanceDateYyyymmdd: Number(issuanceDate.replaceAll('-', '')),
    };
  }
  let barcode: string | undefined;
  if (documentType === 'military-service') {
    barcode = normalizedText
      .match(/\bSAYI\s*:\s*([A-Z0-9]{12,})\b/i)?.[1]
      ?.toUpperCase();
  } else if (documentType === 'residence') {
    const residenceBarcodes = [
      ...new Set(
        normalizedText.match(/\b[A-Z0-9]{4}(?:-[A-Z0-9]{4}){3}\b/g) ?? [],
      ),
    ].filter((candidate) => /[A-Z]/.test(candidate) && /\d/.test(candidate));
    barcode = residenceBarcodes.length === 1 ? residenceBarcodes[0] : undefined;
  } else if (documentType === 'criminal-record') {
    const criminalRecordBarcodes = [
      ...new Set(
        (normalizedText.match(/\bADB\d{11}\b/gi) ?? [])
          .map((candidate) => candidate.toUpperCase()),
      ),
    ];
    barcode = criminalRecordBarcodes.length === 1
      ? criminalRecordBarcodes[0]
      : undefined;
  } else {
    const driverLicenseBarcodes = [
      ...new Set(
        (normalizedText.match(/\bEGM\d{21}\b/gi) ?? [])
          .map((candidate) => candidate.toUpperCase()),
      ),
    ];
    barcode = driverLicenseBarcodes.length === 1
      ? driverLicenseBarcodes[0]
      : undefined;
  }
  const standardLabelledId = normalizedText
    .match(/\bT\.?\s*C\.?\s*KİMLİK\s*(?:NO|NUMARASI)\s*:?\s*(\d{11})\b/iu)?.[1];
  const criminalRecordId = documentType === 'criminal-record'
    ? normalizedText.match(/\bKİMLİK\s+NUMARASI\s*:\s*(\d{11})\b/iu)?.[1]
    : undefined;
  const labelledId = standardLabelledId ?? criminalRecordId;
  const residenceIds = documentType === 'residence' || documentType === 'driver-license'
    ? [...normalizedText.matchAll(/\b\d{11}\b/g)].map((match) => match[0])
    : [];
  const uniqueResidenceIds = [...new Set(residenceIds)];
  const idNumber = labelledId ?? (
    (documentType === 'residence' || documentType === 'driver-license') &&
      uniqueResidenceIds.length === 1
      ? uniqueResidenceIds[0]
      : undefined
  );
  if (!barcode) {
    throw new Error('Could not find the expected document barcode.');
  }

  if (!idNumber) {
    throw new Error(
      'Could not find an 11-digit identity number after the expected identity label.',
    );
  }

  return { barcode, idNumber };
}

export async function extractVerificationInfo(
  inputPath: string,
  documentType: DocumentType = 'military-service',
): Promise<VerificationInfo> {
  const [{ getDocument }, data] = await Promise.all([
    import('pdfjs-dist/legacy/build/pdf.mjs'),
    readFile(path.resolve(inputPath)),
  ]);
  const pdfJsPackagePath = require.resolve('pdfjs-dist/package.json');
  const standardFontDataUrl = `${path.join(
    path.dirname(pdfJsPackagePath),
    'standard_fonts',
  )}${path.sep}`;
  const loadingTask = getDocument({
    data: new Uint8Array(data),
    standardFontDataUrl,
  });
  const pdf = await loadingTask.promise;

  try {
    const pages: string[] = [];

    for (let pageNumber = 1; pageNumber <= pdf.numPages; pageNumber += 1) {
      const page = await pdf.getPage(pageNumber);
      const content = await page.getTextContent();
      pages.push(
        content.items
          .map((item) => ('str' in item ? item.str : ''))
          .join(' '),
      );
      page.cleanup();
    }

    return parseVerificationInfo(pages.join('\n'), documentType);
  } finally {
    await loadingTask.destroy();
  }
}
