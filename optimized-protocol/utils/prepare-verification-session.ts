const DEFAULT_ORIGIN = 'https://www.turkiye.gov.tr';
const VERIFICATION_PATH = '/belge-dogrulama';
const NAVIGATION_ATTEMPTS = 3;
const NAVIGATION_REQUEST_DELAY_MS = 1_000;
const RETRYABLE_NETWORK_CODES = new Set([
  'EPIPE',
  'ECONNRESET',
  'ETIMEDOUT',
  'EAI_AGAIN',
  'ENETDOWN',
  'ENETUNREACH',
  'EHOSTUNREACH',
  'UND_ERR_SOCKET',
  'UND_ERR_CONNECT_TIMEOUT',
  'UND_ERR_HEADERS_TIMEOUT',
]);

class CookieJar {
  readonly #cookies = new Map<string, string>();

  absorb(response: Response): void {
    const headers = response.headers as Headers & {
      getSetCookie?: () => string[];
    };

    for (const value of headers.getSetCookie?.() ?? []) {
      const pair = value.split(';', 1)[0] ?? '';
      const separator = pair.indexOf('=');

      if (separator < 1) {
        continue;
      }

      const name = pair.slice(0, separator);
      const cookieValue = pair.slice(separator + 1);

      if (/Max-Age=0/i.test(value)) {
        this.#cookies.delete(name);
      } else {
        this.#cookies.set(name, cookieValue);
      }
    }
  }

  header(): string {
    return [...this.#cookies]
      .map(([name, value]) => `${name}=${value}`)
      .join('; ');
  }
}

function createRequestPacer(): () => Promise<void> {
  let firstRequest = true;
  return async () => {
    if (firstRequest) {
      firstRequest = false;
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, NAVIGATION_REQUEST_DELAY_MS));
  };
}

export interface PrepareVerificationSessionOptions {
  barcode: string;
  idNumber: string;
  origin?: string;
}

export interface PreparedVerificationSession {
  cookie: string;
  referer: string;
  requestTarget?: string;
}

async function request(
  target: string,
  origin: string,
  cookieJar: CookieJar,
  waitBeforeRequest: () => Promise<void>,
  options: RequestInit = {},
): Promise<Response> {
  await waitBeforeRequest();
  const headers = new Headers(options.headers);
  const cookie = cookieJar.header();

  if (cookie) {
    headers.set('cookie', cookie);
  }

  headers.set('user-agent', 'Mozilla/5.0 (compatible; GovBind/1.0)');
  headers.set('accept-language', 'tr-TR,tr;q=0.9');

  const response = await fetch(new URL(target, origin), {
    ...options,
    headers,
    redirect: 'manual',
    signal: AbortSignal.timeout(30_000),
  });
  cookieJar.absorb(response);

  return response;
}

function extractHiddenToken(html: string): string {
  const input = html.match(
    /<input\b(?=[^>]*\bname=["']token["'])[^>]*>/i,
  )?.[0];
  const token = input?.match(/\bvalue=["']([^"']+)["']/i)?.[1];

  if (!token) {
    throw new Error('The page did not contain the expected one-time token.');
  }

  return token.replaceAll('&amp;', '&');
}

async function getPage(
  target: string,
  origin: string,
  cookieJar: CookieJar,
  waitBeforeRequest: () => Promise<void>,
  referer?: string,
): Promise<string> {
  const response = await request(target, origin, cookieJar, waitBeforeRequest, {
    headers: {
      accept: 'text/html,application/xhtml+xml',
      ...(referer ? { referer: new URL(referer, origin).href } : {}),
    },
  });

  if (!response.ok) {
    throw new Error(`GET ${target}: HTTP ${response.status}`);
  }

  return response.text();
}

async function postForm(
  target: string,
  fields: Record<string, string>,
  referer: string,
  origin: string,
  cookieJar: CookieJar,
  waitBeforeRequest: () => Promise<void>,
): Promise<string> {
  const response = await request(target, origin, cookieJar, waitBeforeRequest, {
    method: 'POST',
    headers: {
      accept: 'text/html,application/xhtml+xml',
      'content-type': 'application/x-www-form-urlencoded',
      referer: new URL(referer, origin).href,
    },
    body: new URLSearchParams(fields),
  });

  if (response.status !== 302 && response.status !== 303) {
    await response.body?.cancel();
    throw new Error(
      `POST ${target}: expected redirect, got HTTP ${response.status}`,
    );
  }

  const location = response.headers.get('location');

  if (!location) {
    throw new Error(`POST ${target}: redirect has no Location header`);
  }

  const resolvedLocation = new URL(location, origin);

  if (resolvedLocation.origin !== new URL(origin).origin) {
    throw new Error('e-Devlet redirected outside its expected origin.');
  }

  return `${resolvedLocation.pathname}${resolvedLocation.search}`;
}

async function prepareVerificationSessionOnce(
  {
    barcode,
    idNumber,
    origin = process.env.VERIFICATION_ORIGIN ?? DEFAULT_ORIGIN,
  }: PrepareVerificationSessionOptions,
  waitBeforeRequest: () => Promise<void>,
): Promise<PreparedVerificationSession> {
  const cookieJar = new CookieJar();

  let page = await getPage(
    VERIFICATION_PATH,
    origin,
    cookieJar,
    waitBeforeRequest,
  );
  let location = await postForm(
    `${VERIFICATION_PATH}?submit`,
    {
      sorgulananBarkod: barcode,
      token: extractHiddenToken(page),
      btn: 'Devam Et',
    },
    VERIFICATION_PATH,
    origin,
    cookieJar,
    waitBeforeRequest,
  );

  page = await getPage(
    location,
    origin,
    cookieJar,
    waitBeforeRequest,
    VERIFICATION_PATH,
  );
  location = await postForm(
    `${VERIFICATION_PATH}?islem=dogrulama&submit`,
    {
      ikinciAlan: idNumber,
      token: extractHiddenToken(page),
      btn: 'Devam Et',
    },
    location,
    origin,
    cookieJar,
    waitBeforeRequest,
  );

  page = await getPage(
    location,
    origin,
    cookieJar,
    waitBeforeRequest,
    `${VERIFICATION_PATH}?islem=dogrulama`,
  );
  location = await postForm(
    `${VERIFICATION_PATH}?islem=onay&submit`,
    {
      chkOnay: '1',
      token: extractHiddenToken(page),
      btn: 'Devam Et',
    },
    location,
    origin,
    cookieJar,
    waitBeforeRequest,
  );

  await getPage(
    location,
    origin,
    cookieJar,
    waitBeforeRequest,
    `${VERIFICATION_PATH}?islem=onay`,
  );

  const cookie = cookieJar.header();

  if (!cookie) {
    throw new Error('The prepared e-Devlet session has no cookies.');
  }

  return {
    cookie,
    referer: new URL(location, origin).href,
  };
}

function networkErrorCode(error: unknown): string | undefined {
  if (!error || typeof error !== 'object') return undefined;
  const direct = (error as { code?: unknown }).code;
  if (typeof direct === 'string') return direct;
  return networkErrorCode((error as { cause?: unknown }).cause);
}

function isRetryableNavigationFailure(error: unknown): boolean {
  const code = networkErrorCode(error);
  return code !== undefined && RETRYABLE_NETWORK_CODES.has(code);
}

export async function prepareVerificationSession(
  options: PrepareVerificationSessionOptions,
): Promise<PreparedVerificationSession> {
  let lastError: unknown;
  const waitBeforeRequest = createRequestPacer();
  for (let attempt = 1; attempt <= NAVIGATION_ATTEMPTS; attempt += 1) {
    try {
      return await prepareVerificationSessionOnce(options, waitBeforeRequest);
    } catch (error) {
      lastError = error;
      if (!isRetryableNavigationFailure(error) || attempt === NAVIGATION_ATTEMPTS) {
        throw error;
      }
      await new Promise((resolve) => setTimeout(resolve, attempt * 100));
    }
  }
  throw lastError;
}
