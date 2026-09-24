import type { PreparedVerificationSession } from './prepare-verification-session';
import { isTurkishIdentityNumber } from './turkish-identity-number';

const ORIGIN = 'https://dijital.gib.gov.tr';
const PAGE_PATH = '/dogrulamalar/mukellefiyetDogrulama';
const API_PATH = '/apigateway/verification/mukellefiyetborc/dilekcedogrula';
const REPORT_PREFIX = '/apigateway/verification/report/download?uuid=';
const RETRYABLE_CODES = new Set([
  'EPIPE', 'ECONNRESET', 'ETIMEDOUT', 'EAI_AGAIN', 'ENETDOWN', 'ENETUNREACH',
  'EHOSTUNREACH', 'UND_ERR_SOCKET', 'UND_ERR_CONNECT_TIMEOUT',
  'UND_ERR_HEADERS_TIMEOUT',
]);

class CookieJar {
  readonly #cookies = new Map<string, string>();

  absorb(response: Response): void {
    const headers = response.headers as Headers & { getSetCookie?: () => string[] };
    for (const value of headers.getSetCookie?.() ?? []) {
      const pair = value.split(';', 1)[0] ?? '';
      const separator = pair.indexOf('=');
      if (separator > 0) {
        const name = pair.slice(0, separator);
        if (/Max-Age=0/i.test(value)) this.#cookies.delete(name);
        else this.#cookies.set(name, pair.slice(separator + 1));
      }
    }
  }

  header(): string {
    return [...this.#cookies].map(([name, value]) => `${name}=${value}`).join('; ');
  }
}

function networkCode(error: unknown): string | undefined {
  if (!error || typeof error !== 'object') return undefined;
  const direct = (error as { code?: unknown }).code;
  if (typeof direct === 'string') return direct;
  const cause = (error as { cause?: unknown }).cause;
  return cause && typeof cause === 'object' && typeof (cause as { code?: unknown }).code === 'string'
    ? (cause as { code: string }).code
    : undefined;
}

async function requestWithRetry(url: string, options: RequestInit): Promise<Response> {
  let lastError: unknown;
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    try {
      return await fetch(url, { ...options, signal: AbortSignal.timeout(30_000) });
    } catch (error) {
      lastError = error;
      if (!RETRYABLE_CODES.has(networkCode(error) ?? '') || attempt === 3) throw error;
      await new Promise((resolve) => setTimeout(resolve, 1_000));
    }
  }
  throw lastError;
}

export async function prepareTaxDebtVerificationSession(
  petitionNumber: string,
  identityNumber: string,
): Promise<PreparedVerificationSession> {
  if (!/^[A-Za-z0-9]{14}$/.test(petitionNumber) || !isTurkishIdentityNumber(identityNumber)) {
    throw new Error('The GIB navigation fields are invalid.');
  }
  const jar = new CookieJar();
  const pageUrl = `${ORIGIN}${PAGE_PATH}`;
  const page = await requestWithRetry(pageUrl, {
    redirect: 'error',
    headers: {
      accept: 'text/html,application/xhtml+xml',
      'accept-language': 'tr-TR,tr;q=0.9',
      'user-agent': 'Mozilla/5.0 (compatible; GovBind/1.0)',
    },
  });
  jar.absorb(page);
  await page.body?.cancel();
  if (!page.ok) throw new Error(`GIB verification page returned HTTP ${page.status}.`);

  await new Promise((resolve) => setTimeout(resolve, 1_000));
  const response = await requestWithRetry(`${ORIGIN}${API_PATH}`, {
    method: 'POST',
    redirect: 'error',
    headers: {
      accept: 'application/json',
      'accept-language': 'tr-TR',
      'content-type': 'application/json',
      cookie: jar.header(),
      origin: ORIGIN,
      referer: pageUrl,
      'user-agent': 'Mozilla/5.0 (compatible; GovBind/1.0)',
    },
    body: JSON.stringify({
      data: { dilekceOid: petitionNumber, vknTckn: identityNumber },
      toBeLink: true,
    }),
  });
  jar.absorb(response);
  if (!response.ok) {
    await response.body?.cancel();
    throw new Error(`GIB verification request returned HTTP ${response.status}.`);
  }
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length === 0 || bytes.length > 64 * 1024) {
    throw new Error('GIB verification metadata has an invalid size.');
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytes.toString('utf8'));
  } catch {
    throw new Error('GIB verification metadata is not valid JSON.');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('GIB did not return a verification report link.');
  }
  const value = parsed as { reportLink?: unknown; messages?: unknown };
  const hasNoMessages = value.messages === null ||
    (Array.isArray(value.messages) && value.messages.length === 0);
  if (typeof value.reportLink !== 'string' || !hasNoMessages) {
    throw new Error('GIB did not return a verification report link.');
  }
  const report = new URL(value.reportLink, ORIGIN);
  if (report.origin !== ORIGIN || !report.pathname.concat(report.search).startsWith(REPORT_PREFIX) ||
      report.searchParams.size !== 1 ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
        .test(report.searchParams.get('uuid') ?? '')) {
    throw new Error('GIB returned an invalid report link.');
  }
  return {
    cookie: jar.header(),
    referer: pageUrl,
    requestTarget: `${report.pathname}${report.search}`,
  };
}
