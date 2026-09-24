import { createHash } from 'node:crypto';
import { chmod, readFile, writeFile } from 'node:fs/promises';
import { inflateSync } from 'node:zlib';
import { isTurkishIdentityNumber } from '../utils/turkish-identity-number';

const MAX_COMMITMENT_PREIMAGE = 1040;
const MAX_COMPRESSED = 1024;
const MAX_COMPRESSED_BITS = MAX_COMPRESSED * 8;
const MAX_OUTPUT = 4096;
const MAX_HEADER_TOKENS = 160;
const MAX_DATA_TOKENS = 800;
const EXPECTED_STATIC_HASHES = new Map([
  [39, '54d1dbfe23d6ef99d50e95e8b798aee065814f8b1311bb0ab148b2a34edf72d6'],
  [42, '00cad7c10e2b838f15e3ffbf27ab64114778dd52a12f144c942bcc7c81c09e1a'],
]);
const FIELD_OPERATIONS = new Map([
  [39, [22, 24, 26, 28, 32, 34, 36, 38]],
  [42, [25, 27, 29, 31, 35, 37, 39, 41]],
]);
const CODE_LENGTH_ORDER = [
  16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];
const LENGTH_BASE = [
  3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51,
  59, 67, 83, 99, 115, 131, 163, 195, 227, 258,
];
const LENGTH_EXTRA_BITS = [
  0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4,
  4, 4, 5, 5, 5, 5, 0,
];
const DISTANCE_BASE = [
  1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385,
  513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385,
  24577,
];
const DISTANCE_EXTRA_BITS = [
  0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9,
  10, 10, 11, 11, 12, 12, 13, 13,
];

interface WitnessOptions {
  pdfPath?: string;
  streamPath?: string;
  blinder: Buffer;
  outputPath: string;
  identityNumber: string;
}

interface TextOperation {
  valueStart: number;
  valueEnd: number;
}

interface PrivateSpan {
  start: number;
  length: number;
}

interface DeflateTrace {
  bits: number[];
  codeLengths: number[];
  headerSymbols: number[];
  headerSymbolCount: number;
  headerTokenIndex: number[];
  dataSymbols: number[];
  distanceSymbols: number[];
  dataSymbolCount: number;
  output: number[];
  outputTokenIndex: number[];
}

function fail(message: string): never {
  throw new Error(message);
}

export function parseArguments(argv: string[]): WitnessOptions {
  const options: Record<string, string> = {};
  const allowedOptions = new Set([
    'pdf', 'stream', 'blinder', 'output', 'identity',
  ]);
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (!name?.startsWith('--') || value === undefined) {
      fail('Arguments must be provided as --name value pairs.');
    }
    const key = name.slice(2);
    if (!allowedOptions.has(key)) fail(`Unknown argument: ${name}`);
    if (options[key] !== undefined) fail(`Duplicate argument: ${name}`);
    options[key] = value;
  }

  if ((!options.pdf && !options.stream) || (options.pdf && options.stream)) {
    fail('Exactly one of --pdf or --stream is required.');
  }
  if (!options.blinder || !options.output) {
    fail('--blinder and --output are required.');
  }
  if (!/^[0-9a-fA-F]{32}$/.test(options.blinder)) {
    fail('--blinder must be exactly 16 bytes of hexadecimal.');
  }
  if (!isTurkishIdentityNumber(options.identity ?? '')) {
    fail('--identity must be a valid 11-digit Turkish identity number.');
  }

  return {
    pdfPath: options.pdf,
    streamPath: options.stream,
    blinder: Buffer.from(options.blinder, 'hex'),
    outputPath: options.output,
    identityNumber: options.identity,
  };
}

function findAscii(buffer: Buffer, value: string, start = 0): number {
  return buffer.indexOf(Buffer.from(value, 'ascii'), start);
}

export function extractPageContentStream(pdf: Buffer): Buffer {
  const serialized = pdf.toString('latin1');
  const objects = [...serialized.matchAll(/(?:^|[\r\n])(\d+)\s+0\s+obj\b/g)]
    .map((match) => {
      const objectStart = match.index + match[0].search(/\d/);
      const objectEnd = serialized.indexOf('endobj', objectStart);
      if (objectEnd < 0) {
        fail('A PDF indirect object has no endobj marker.');
      }
      return {
        number: Number(match[1]),
        start: objectStart,
        end: objectEnd,
        dictionary: serialized.slice(objectStart, objectEnd),
      };
    });
  const pageObjects = objects.filter(
    ({ dictionary }) => /\/Type\s*\/Page(?![A-Za-z0-9])/u.test(dictionary),
  );
  if (pageObjects.length !== 1) {
    fail(`Expected exactly one PDF page, found ${pageObjects.length}.`);
  }
  const contentArrays = [
    ...pageObjects[0].dictionary.matchAll(/\/Contents\s*\[([^\]]*)\]/g),
  ];
  if (contentArrays.length !== 1) {
    fail('The criminal-record PDF page must have one /Contents array.');
  }
  const contentReferences = [
    ...contentArrays[0][1].matchAll(/(\d+)\s+0\s+R\b/g),
  ];
  const residue = contentArrays[0][1].replace(/\d+\s+0\s+R\b/g, '').trim();
  if (contentReferences.length !== 5 || residue !== '') {
    fail('The criminal-record PDF page must reference exactly five content streams.');
  }
  const objectNumber = Number(contentReferences[2][1]);
  const contentObjects = objects.filter(({ number }) => number === objectNumber);
  if (contentObjects.length !== 1) {
    fail('The referenced PDF page-content object is not unique.');
  }
  const objectStart = contentObjects[0].start;
  const objectEnd = contentObjects[0].end;
  const dictionaryEnd = findAscii(pdf, 'stream', objectStart);
  if (objectEnd < 0 || dictionaryEnd < 0 || dictionaryEnd > objectEnd) {
    fail('The referenced PDF page-content object has no stream.');
  }

  const dictionary = pdf.subarray(objectStart, dictionaryEnd).toString('ascii');
  const lengthMatches = [...dictionary.matchAll(/\/Length\s+(\d+)/g)];
  if (lengthMatches.length !== 1) {
    fail('The PDF page-content object must have one direct stream length.');
  }
  const streamLength = Number(lengthMatches[0][1]);
  if (!Number.isSafeInteger(streamLength) || streamLength <= 0) {
    fail('The PDF page-content object has an invalid stream length.');
  }

  let dataStart = dictionaryEnd + Buffer.byteLength('stream');
  if (pdf[dataStart] === 0x0d && pdf[dataStart + 1] === 0x0a) {
    dataStart += 2;
  } else if (pdf[dataStart] === 0x0a) {
    dataStart += 1;
  } else {
    fail('The PDF page-content stream marker has invalid line termination.');
  }
  const dataEnd = dataStart + streamLength;
  if (dataEnd > pdf.length) {
    fail('The PDF page-content stream exceeds the document.');
  }
  let markerStart = dataEnd;
  if (pdf[markerStart] === 0x0d && pdf[markerStart + 1] === 0x0a) {
    markerStart += 2;
  } else if (pdf[markerStart] === 0x0a) {
    markerStart += 1;
  }
  if (!pdf.subarray(markerStart, markerStart + 9).equals(Buffer.from('endstream'))) {
    fail('The PDF page-content stream length does not end at endstream.');
  }
  return pdf.subarray(dataStart, dataEnd);
}

export function findTextOperations(content: Buffer): TextOperation[] {
  const operations: TextOperation[] = [];
  for (let start = 0; start < content.length; start += 1) {
    if (content[start] !== 0x28) {
      continue;
    }
    let depth = 1;
    let cursor = start + 1;
    while (cursor < content.length && depth > 0) {
      if (content[cursor] === 0x5c) {
        cursor += 2;
        continue;
      }
      if (content[cursor] === 0x28) {
        depth += 1;
      } else if (content[cursor] === 0x29) {
        depth -= 1;
      }
      cursor += 1;
    }
    if (depth !== 0) {
      fail('Page content contains an unterminated PDF literal string.');
    }

    let operator = cursor;
    while (
      operator < content.length &&
      [0x00, 0x09, 0x0a, 0x0c, 0x0d, 0x20].includes(content[operator])
    ) {
      operator += 1;
    }
    if (content[operator] === 0x54 && content[operator + 1] === 0x6a) {
      operations.push({ valueStart: start + 1, valueEnd: cursor - 1 });
      start = operator + 1;
    }
  }
  if (operations.length !== 39 && operations.length !== 42) {
    fail('The page content does not match a reviewed criminal-record layout.');
  }
  return operations;
}

export function derivePrivateSpans(
  _content: Buffer,
  operations: TextOperation[],
): PrivateSpan[] {
  const fieldOperations = FIELD_OPERATIONS.get(operations.length);
  if (!fieldOperations) fail('Unsupported criminal-record layout.');
  return fieldOperations.map((operationIndex, fieldIndex) => {
    const operation = operations[operationIndex];
    const prefixLength = fieldIndex === 4 ? 6 : 0;
    const length = operation.valueEnd - operation.valueStart - prefixLength;
    if (length <= 0) fail('A criminal-record private field is empty.');
    return { start: operation.valueStart + prefixLength, length };
  });
}

export function verifyStaticProfile(content: Buffer, spans: PrivateSpan[]): void {
  const staticSegments: Buffer[] = [];
  let cursor = 0;
  for (const span of spans) {
    if (span.start < cursor) {
      fail('Private criminal-record fields overlap.');
    }
    staticSegments.push(content.subarray(cursor, span.start));
    cursor = span.start + span.length;
  }
  staticSegments.push(content.subarray(cursor));
  const digest = createHash('sha256')
    .update(Buffer.concat(staticSegments))
    .digest('hex');
  const expected = EXPECTED_STATIC_HASHES.get(findTextOperations(content).length);
  if (digest !== expected) {
    fail('The PDF page content does not match criminal-record profile v1.');
  }
}

export function verifyPublicIdentity(
  content: Buffer,
  operations: TextOperation[],
  identityNumber: string,
): void {
  const fieldOperations = FIELD_OPERATIONS.get(operations.length);
  if (!fieldOperations) fail('Unsupported criminal-record layout.');
  const operation = operations[fieldOperations[4]];
  const value = content.subarray(operation.valueStart, operation.valueEnd);
  if (value.length !== 28 || !value.subarray(0, 6).equals(
    Buffer.from([0, 3, 0, 29, 0, 3]),
  )) {
    fail('The criminal-record identity value has the wrong PDF encoding.');
  }
  for (let index = 0; index < 11; index += 1) {
    const digit = Number(identityNumber[index]);
    if (value[index * 2 + 6] !== 0 || value[index * 2 + 7] !== 0x13 + digit) {
      fail('The public identity number does not match the authenticated document.');
    }
  }
}

function isEncodedDigit(content: Buffer, offset: number): boolean {
  return content[offset] === 0 && content[offset + 1] >= 0x13 &&
    content[offset + 1] <= 0x1c;
}

function verifyEncodedDateSuffix(content: Buffer, span: PrivateSpan): void {
  if (span.length < 20) fail('A private date field is too short.');
  const start = span.start + span.length - 20;
  for (let glyph = 0; glyph < 10; glyph += 1) {
    const offset = start + glyph * 2;
    if (glyph === 2 || glyph === 5) {
      if (content[offset] !== 0 || content[offset + 1] !== 0x11) {
        fail('A private date field has the wrong PDF encoding.');
      }
    } else if (!isEncodedDigit(content, offset)) {
      fail('A private date field has the wrong PDF encoding.');
    }
  }
}

export function verifyPrivateFieldShapes(
  content: Buffer,
  spans: PrivateSpan[],
): void {
  const lengths = spans.map(({ length }) => length);
  if (
    lengths.length !== 8 || lengths[0] !== 62 || lengths[1] !== 94 ||
    lengths[2] < 8 || lengths[2] > 64 ||
    lengths[3] < 8 || lengths[3] > 128 || lengths[4] !== 22 ||
    lengths[5] < 2 || lengths[5] > 160 ||
    lengths[6] < 2 || lengths[6] > 160 ||
    lengths[7] < 20 || lengths[7] > 160
  ) {
    fail('A criminal-record private field is outside its reviewed bound.');
  }

  const documentNumber = content.subarray(spans[0].start, spans[0].start + 62);
  const fixedGlyphs = new Map([
    [0, 0x03], [1, 0x1d], [2, 0x03], [7, 0x10], [12, 0x10],
    [23, 0x03], [24, 0x12], [25, 0x03], [28, 0x1d],
  ]);
  for (let glyph = 0; glyph < 31; glyph += 1) {
    const expected = fixedGlyphs.get(glyph);
    const offset = glyph * 2;
    if (expected !== undefined) {
      if (documentNumber[offset] !== 0 || documentNumber[offset + 1] !== expected) {
        fail('The private document number has the wrong PDF encoding.');
      }
    } else if (!isEncodedDigit(documentNumber, offset)) {
      fail('The private document number has the wrong PDF encoding.');
    }
  }
  verifyEncodedDateSuffix(content, spans[1]);
  verifyEncodedDateSuffix(content, spans[7]);
}

class BitReader {
  private position = 0;

  constructor(private readonly bytes: Buffer) {
  }

  read(length: number): number {
    if (this.position + length > this.bytes.length * 8) {
      fail('The DEFLATE bitstream ended unexpectedly.');
    }
    let value = 0;
    for (let offset = 0; offset < length; offset += 1) {
      value |=
        ((this.bytes[Math.floor(this.position / 8)] >>
          (this.position % 8)) &
          1) <<
        offset;
      this.position += 1;
    }
    return value;
  }
}

function reverseBits(value: number, length: number): number {
  let reversed = 0;
  for (let offset = 0; offset < length; offset += 1) {
    reversed = (reversed << 1) | ((value >> offset) & 1);
  }
  return reversed;
}

function buildHuffmanTable(lengths: number[]): Map<string, number> {
  const counts = Array(16).fill(0);
  for (const length of lengths) {
    if (length > 0) {
      counts[length] += 1;
    }
  }
  const next = Array(16).fill(0);
  let code = 0;
  for (let length = 1; length < 16; length += 1) {
    code = (code + counts[length - 1]) << 1;
    next[length] = code;
  }
  const table = new Map<string, number>();
  lengths.forEach((length, symbol) => {
    if (length > 0) {
      table.set(`${reverseBits(next[length], length)}:${length}`, symbol);
      next[length] += 1;
    }
  });
  return table;
}

function decodeHuffman(reader: BitReader, table: Map<string, number>): number {
  let code = 0;
  for (let length = 1; length <= 15; length += 1) {
    code |= reader.read(1) << (length - 1);
    const symbol = table.get(`${code}:${length}`);
    if (symbol !== undefined) {
      return symbol;
    }
  }
  fail('The DEFLATE stream contains an invalid Huffman code.');
}

function pad(values: number[], length: number): number[] {
  if (values.length > length) {
    fail('The DEFLATE trace exceeds a circuit bound.');
  }
  return [...values, ...Array(length - values.length).fill(0)];
}

export function buildDeflateTrace(
  compressed: Buffer,
  expectedOutput: Buffer,
): DeflateTrace {
  if (compressed.length > MAX_COMPRESSED) {
    fail('The compressed content stream exceeds the circuit bound.');
  }
  if (compressed[0] !== 0x78 || compressed[1] !== 0x9c) {
    fail('The criminal-record profile requires the expected zlib header.');
  }

  const deflateBytes = compressed.subarray(2, compressed.length - 4);
  const reader = new BitReader(deflateBytes);
  if (reader.read(1) !== 1 || reader.read(2) !== 2) {
    fail('The criminal-record profile requires one final dynamic-Huffman block.');
  }
  const literalCount = reader.read(5) + 257;
  const distanceCount = reader.read(5) + 1;
  const codeLengthCount = reader.read(4) + 4;
  if (
    literalCount !== 279 ||
    distanceCount !== 23 ||
    codeLengthCount !== 14
  ) {
    fail('The dynamic-Huffman header is outside criminal-record profile v1.');
  }

  const headerLengths = Array(19).fill(0);
  for (let index = 0; index < codeLengthCount; index += 1) {
    headerLengths[CODE_LENGTH_ORDER[index]] = reader.read(3);
  }
  const headerTable = buildHuffmanTable(headerLengths);
  const headerSymbols: number[] = [];
  const codeLengths: number[] = [];
  const headerTokenIndex: number[] = [];
  while (codeLengths.length < literalCount + distanceCount) {
    const tokenIndex = headerSymbols.length;
    const symbol = decodeHuffman(reader, headerTable);
    headerSymbols.push(symbol);
    if (symbol <= 15) {
      codeLengths.push(symbol);
      headerTokenIndex.push(tokenIndex);
    } else if (symbol === 16) {
      if (codeLengths.length === 0) {
        fail('The DEFLATE header repeats a missing code length.');
      }
      const repeat = reader.read(2) + 3;
      codeLengths.push(...Array<number>(repeat).fill(codeLengths[codeLengths.length - 1]));
      headerTokenIndex.push(...Array(repeat).fill(tokenIndex));
    } else if (symbol === 17) {
      const repeat = reader.read(3) + 3;
      codeLengths.push(...Array(repeat).fill(0));
      headerTokenIndex.push(...Array(repeat).fill(tokenIndex));
    } else if (symbol === 18) {
      const repeat = reader.read(7) + 11;
      codeLengths.push(...Array(repeat).fill(0));
      headerTokenIndex.push(...Array(repeat).fill(tokenIndex));
    } else {
      fail('The DEFLATE header contains an invalid symbol.');
    }
  }
  if (codeLengths.length !== 302) {
    fail('The DEFLATE header expands beyond its declared code lengths.');
  }

  const literalTable = buildHuffmanTable(codeLengths.slice(0, literalCount));
  const distanceTable = buildHuffmanTable(
    codeLengths.slice(literalCount, literalCount + distanceCount),
  );
  const dataSymbols: number[] = [];
  const distanceSymbols: number[] = [];
  const output: number[] = [];
  const outputTokenIndex: number[] = [];

  while (true) {
    const tokenIndex = dataSymbols.length;
    const symbol = decodeHuffman(reader, literalTable);
    dataSymbols.push(symbol);
    distanceSymbols.push(0);
    if (symbol < 256) {
      output.push(symbol);
      outputTokenIndex.push(tokenIndex);
    } else if (symbol === 256) {
      break;
    } else {
      if (symbol > 285) {
        fail('The DEFLATE stream uses a reserved length symbol.');
      }
      const lengthIndex = symbol - 257;
      const length =
        LENGTH_BASE[lengthIndex] + reader.read(LENGTH_EXTRA_BITS[lengthIndex]);
      const distanceSymbol = decodeHuffman(reader, distanceTable);
      if (distanceSymbol > 29) {
        fail('The DEFLATE stream uses a reserved distance symbol.');
      }
      distanceSymbols[tokenIndex] = distanceSymbol;
      const distance =
        DISTANCE_BASE[distanceSymbol] +
        reader.read(DISTANCE_EXTRA_BITS[distanceSymbol]);
      if (distance <= 0 || distance > output.length) {
        fail('The DEFLATE stream has an invalid back-reference.');
      }
      for (let offset = 0; offset < length; offset += 1) {
        output.push(output[output.length - distance]);
        outputTokenIndex.push(tokenIndex);
      }
    }
    if (dataSymbols.length >= MAX_DATA_TOKENS || output.length > MAX_OUTPUT) {
      fail('The DEFLATE data exceeds a circuit bound.');
    }
  }

  const reconstructed = Buffer.from(output);
  if (!reconstructed.equals(expectedOutput)) {
    fail('The DEFLATE trace does not reconstruct the host-decoded stream.');
  }
  return {
    bits: pad(
      [...compressed].flatMap((byte) =>
        Array.from({ length: 8 }, (_, bit) => (byte >> bit) & 1),
      ),
      MAX_COMPRESSED_BITS,
    ),
    codeLengths,
    headerSymbols: pad(headerSymbols, MAX_HEADER_TOKENS),
    headerSymbolCount: headerSymbols.length,
    headerTokenIndex,
    dataSymbols: pad(dataSymbols, MAX_DATA_TOKENS),
    distanceSymbols: pad(distanceSymbols, MAX_DATA_TOKENS),
    dataSymbolCount: dataSymbols.length,
    output: pad(output, MAX_OUTPUT),
    outputTokenIndex: pad(outputTokenIndex, MAX_OUTPUT),
  };
}

function formatTomlArray(values: readonly (string | number | bigint)[]): string {
  const lines: string[] = [];
  for (let start = 0; start < values.length; start += 32) {
    lines.push(`  ${values.slice(start, start + 32).join(', ')}`);
  }
  return `[\n${lines.join(',\n')}\n]`;
}

function commitmentLimbs(digest: Buffer): bigint[] {
  const limbs: bigint[] = [];
  for (let offset = 0; offset < digest.length; offset += 8) {
    limbs.push(BigInt(`0x${digest.subarray(offset, offset + 8).toString('hex')}`));
  }
  return limbs;
}

async function main(): Promise<void> {
  const options = parseArguments(process.argv.slice(2));
  let compressed: Buffer;
  if (options.streamPath) {
    compressed = await readFile(options.streamPath);
  } else if (options.pdfPath) {
    compressed = extractPageContentStream(await readFile(options.pdfPath));
  } else {
    fail('Exactly one of --pdf or --stream is required.');
  }
  if (compressed.length > MAX_COMMITMENT_PREIMAGE - options.blinder.length) {
    fail('The compressed content stream exceeds the circuit bound.');
  }

  let content: Buffer;
  try {
    content = inflateSync(compressed);
  } catch {
    fail('PDF page content is not a valid zlib stream.');
  }
  const operations = findTextOperations(content);
  const spans = derivePrivateSpans(content, operations);
  verifyStaticProfile(content, spans);
  verifyPrivateFieldShapes(content, spans);
  verifyPublicIdentity(content, operations, options.identityNumber);
  const deflateTrace = buildDeflateTrace(compressed, content);

  const preimage = Buffer.alloc(MAX_COMMITMENT_PREIMAGE);
  compressed.copy(preimage);
  options.blinder.copy(preimage, compressed.length);
  const commitment = createHash('sha256')
    .update(compressed)
    .update(options.blinder)
    .digest();

  const toml = [
    `commitment = ${formatTomlArray(
      commitmentLimbs(commitment).map((value) => `"${value}"`),
    )}`,
    `compressed_length = "${compressed.length}"`,
    `identity_number = "${options.identityNumber}"`,
    `commitment_preimage = ${formatTomlArray([...preimage])}`,
    `layout_variant = "${operations.length === 39 ? 0 : 1}"`,
    `private_field_lengths = ${formatTomlArray(spans.map(({ length }) => length))}`,
    '',
    '[deflate_trace]',
    `bits = ${formatTomlArray(deflateTrace.bits)}`,
    `code_lengths = ${formatTomlArray(deflateTrace.codeLengths)}`,
    `header_symbols = ${formatTomlArray(deflateTrace.headerSymbols)}`,
    `header_symbol_count = "${deflateTrace.headerSymbolCount}"`,
    `header_token_index = ${formatTomlArray(deflateTrace.headerTokenIndex)}`,
    `data_symbols = ${formatTomlArray(deflateTrace.dataSymbols)}`,
    `distance_symbols = ${formatTomlArray(deflateTrace.distanceSymbols)}`,
    `data_symbol_count = "${deflateTrace.dataSymbolCount}"`,
    `output = ${formatTomlArray(deflateTrace.output)}`,
    `output_token_index = ${formatTomlArray(deflateTrace.outputTokenIndex)}`,
    '',
  ].join('\n');

  await writeFile(options.outputPath, toml, { mode: 0o600 });
  await chmod(options.outputPath, 0o600);
  process.stderr.write(
    `Prepared criminal-record profile v1 witness (${compressed.length} committed bytes).\n`,
  );
}

if (require.main === module) {
  main().catch((error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
