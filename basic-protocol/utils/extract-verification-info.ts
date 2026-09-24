import { readFile } from 'node:fs/promises';
import path from 'node:path';

export interface VerificationInfo {
  barcode: string;
  documentDate: string;
  idNumber: string;
}

function parseVerificationInfo(text: string): VerificationInfo {
  const normalizedText = text.normalize('NFKC').replace(/\s+/g, ' ').trim();
  const barcode = normalizedText
    .match(/\bSAYI\s*:\s*([A-Z0-9]{12,})\b/i)?.[1]
    ?.toUpperCase();
  const idNumber = normalizedText
    .match(/\bT\.?\s*C\.?\s*KİMLİK\s*NO\s*:\s*(\d{11})\b/iu)?.[1];
  const documentDate = normalizedText.match(
    /\b(\d{2}\/\d{2}\/\d{4})(?=\s+TARİHİNE\s+KADAR\s+ASKERLİK\s+İLE\s+İLİŞİĞİ\s+YOKTUR\b)/u,
  )?.[1];

  if (!barcode) {
    throw new Error('Could not find the document barcode after the "SAYI" label.');
  }

  if (!idNumber) {
    throw new Error(
      'Could not find an 11-digit identity number after the "T.C. KİMLİK NO" label.',
    );
  }

  if (!documentDate) {
    throw new Error('Could not find the military-service validity date.');
  }

  return { barcode, documentDate, idNumber };
}

export async function extractVerificationInfo(
  inputPath: string,
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

    return parseVerificationInfo(pages.join('\n'));
  } finally {
    await loadingTask.destroy();
  }
}
