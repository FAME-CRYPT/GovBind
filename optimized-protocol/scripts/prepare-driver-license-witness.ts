import { createHash } from 'node:crypto';
import { chmod, readFile, writeFile } from 'node:fs/promises';
import { inflateSync } from 'node:zlib';

const MAX_COMMITMENT_PREIMAGE = 4112;
const MAX_COMPRESSED = 4096;
const MAX_COMPRESSED_BITS = MAX_COMPRESSED * 8;
const MAX_OUTPUT = 16384;
const MAX_HEADER_TOKENS = 160;
const MAX_DATA_TOKENS = 2304;
const EXPECTED_STATIC_PROFILES = new Map([
  [13150, '79d29db854ce24c043f5953338b841a4ad90cbfceeefb68e8e6247a1926f836d'],
  [13144, 'a2c84165196e7ab53f34def3c84de8f2277dcf11069eab2f36ec28174f903631'],
]);
const PRIVATE_TEXT_OPERATIONS = [
  1, 3, 5, 7, 9, 15, 17, 19, 21, 23, 25, 27, 28, 43, 44,
];
const TARGET_PRIVATE_FIELDS = [6, 8, 10] as const;
const TARGET_PREFIXES = [
  'BT /F4 10 Tf 0 0 0 rg 452.718 TL 448.517 549.219 Td (',
  'BT /F4 10 Tf 0 0 0 rg 452.718 TL 448.517 531.364 Td (',
  'BT /F4 10 Tf 0 0 0 rg 452.718 TL 448.517 513.579 Td (',
] as const;
const TARGET_SUFFIX = ') Tj T* ET';
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
  maximumTrafficTickets: number;
  maximumTotalPenaltyPoints: number;
  maximumActivePenaltyPoints: number;
}

interface TextOperation {
  start: number;
  end: number;
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
    'pdf', 'stream', 'blinder', 'output', 'maximum-traffic-tickets',
    'maximum-total-penalty-points', 'maximum-active-penalty-points',
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
  const threshold = (name: string): number => {
    if (!/^\d+$/.test(options[name] ?? '')) fail(`--${name} is required.`);
    const value = Number(options[name]);
    if (!Number.isSafeInteger(value) || value < 1 || value > 0xffff_ffff) {
      fail(`--${name} must be a positive 32-bit integer.`);
    }
    return value;
  };

  return {
    pdfPath: options.pdf,
    streamPath: options.stream,
    blinder: Buffer.from(options.blinder, 'hex'),
    outputPath: options.output,
    maximumTrafficTickets: threshold('maximum-traffic-tickets'),
    maximumTotalPenaltyPoints: threshold('maximum-total-penalty-points'),
    maximumActivePenaltyPoints: threshold('maximum-active-penalty-points'),
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
  const contentReferences = [
    ...pageObjects[0].dictionary.matchAll(/\/Contents\s+(\d+)\s+0\s+R\b/g),
  ];
  if (contentReferences.length !== 1) {
    fail('The PDF page must have one direct /Contents reference.');
  }
  const objectNumber = Number(contentReferences[0][1]);
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

  const markerEnd = dictionaryEnd + Buffer.byteLength('stream');
  if (!pdf.subarray(markerEnd, markerEnd + 3).equals(Buffer.from(' \r\n'))) {
    fail('The PDF page-content stream marker has invalid line termination.');
  }
  const dataStart = markerEnd + 3;
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
  const serialized = content.toString('latin1');
  for (const match of serialized.matchAll(/BT[^\r\n]*?\sTj\s+T\*\s+ET/g)) {
    const literal = match[0].match(/\(((?:\\.|[^\\)])*)\)\s*Tj\b/);
    const hexadecimal = match[0].match(/<([0-9A-Fa-f\s]*)>\s*Tj\b/);
    if (!literal && !hexadecimal) fail('Driver-license text operation has an invalid value.');
    const value = literal?.[1] ?? hexadecimal![1];
    const relative = match[0].indexOf(value);
    operations.push({
      start: match.index,
      end: match.index + match[0].length,
      valueStart: match.index + relative,
      valueEnd: match.index + relative + value.length,
    });
  }
  if (operations.length !== 46) fail('The page content does not match driver-license profile v1.');
  return operations;
}

export function derivePrivateSpans(
  _content: Buffer,
  operations: TextOperation[],
): PrivateSpan[] {
  return PRIVATE_TEXT_OPERATIONS.map((operationIndex) => {
    const operation = operations[operationIndex];
    if (!operation) fail('A private driver-license field is missing.');
    return { start: operation.start, length: operation.end - operation.start };
  });
}

export function verifyStaticProfile(content: Buffer, spans: PrivateSpan[]): number {
  const staticSegments: Buffer[] = [];
  let cursor = 0;
  for (const span of spans) {
    if (span.start < cursor) {
      fail('Private driver-license fields overlap.');
    }
    staticSegments.push(content.subarray(cursor, span.start));
    cursor = span.start + span.length;
  }
  staticSegments.push(content.subarray(cursor));
  const normalized = Buffer.concat(staticSegments);
  const digest = createHash('sha256').update(normalized).digest('hex');
  const entries = [...EXPECTED_STATIC_PROFILES.entries()];
  const layoutVariant = entries.findIndex(
    ([length, expectedDigest]) => normalized.length === length && digest === expectedDigest,
  );
  if (layoutVariant < 0) {
    fail('The PDF page content does not match driver-license profile v1.');
  }
  return layoutVariant;
}

function parseTargetValue(
  content: Buffer,
  span: PrivateSpan,
  target: number,
  layoutVariant: number,
): number {
  const operation = content.subarray(span.start, span.start + span.length).toString('ascii');
  const prefix = layoutVariant === 1 && target === 1
    ? TARGET_PREFIXES[target].replace('531.364', '531.363')
    : TARGET_PREFIXES[target];
  if (!operation.startsWith(prefix) || !operation.endsWith(TARGET_SUFFIX)) {
    fail('A driver-license traffic value is not in its reviewed table position.');
  }
  const digits = operation.slice(prefix.length, -TARGET_SUFFIX.length);
  if (!/^\d{1,10}$/.test(digits) || (digits.length > 1 && digits.startsWith('0'))) {
    fail('A driver-license traffic value is not a canonical integer.');
  }
  const value = Number(digits);
  if (!Number.isSafeInteger(value) || value > 0xffff_ffff) {
    fail('A driver-license traffic value exceeds its supported range.');
  }
  return value;
}

function verifyPrivateFields(
  content: Buffer,
  spans: PrivateSpan[],
  options: WitnessOptions,
  layoutVariant: number,
): void {
  if (spans.length !== 15) fail('The driver-license profile has the wrong private-field count.');
  const exact = new Map([[0, 73], [4, 72], [9, 73], [13, 87], [14, 79]]);
  spans.forEach((span, index) => {
    const expected = exact.get(index);
    if (expected !== undefined && span.length !== expected) fail('A fixed driver-license field has the wrong length.');
    if (expected === undefined && (span.length < 64 || span.length > 512)) fail('A driver-license field exceeds its reviewed bound.');
  });
  const values = TARGET_PRIVATE_FIELDS.map(
    (field, target) => parseTargetValue(content, spans[field], target, layoutVariant),
  );
  if (values[0] >= options.maximumTrafficTickets ||
      values[1] >= options.maximumTotalPenaltyPoints ||
      values[2] >= options.maximumActivePenaltyPoints) {
    fail('The driver-license traffic values do not satisfy the selected thresholds.');
  }
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
  if (compressed[0] !== 0x58 || compressed[1] !== 0x09) {
    fail('The driver-license profile requires the expected zlib header.');
  }

  const deflateBytes = compressed.subarray(2, compressed.length - 4);
  const reader = new BitReader(deflateBytes);
  if (reader.read(1) !== 1 || reader.read(2) !== 2) {
    fail('The driver-license profile requires one final dynamic-Huffman block.');
  }
  const literalCount = reader.read(5) + 257;
  const distanceCount = reader.read(5) + 1;
  const codeLengthCount = reader.read(4) + 4;
  if (
    literalCount !== 280 ||
    distanceCount !== 28 ||
    codeLengthCount !== 14
  ) {
    fail('The dynamic-Huffman header is outside driver-license profile v1.');
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
  if (codeLengths.length !== 308) {
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
  const layoutVariant = verifyStaticProfile(content, spans);
  verifyPrivateFields(content, spans, options, layoutVariant);
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
    `maximum_traffic_tickets = "${options.maximumTrafficTickets}"`,
    `maximum_total_penalty_points = "${options.maximumTotalPenaltyPoints}"`,
    `maximum_active_penalty_points = "${options.maximumActivePenaltyPoints}"`,
    `commitment_preimage = ${formatTomlArray([...preimage])}`,
    `layout_variant = "${layoutVariant}"`,
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
    `Prepared driver-license profile v1 witness (${compressed.length} committed bytes).\n`,
  );
}

if (require.main === module) {
  main().catch((error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
