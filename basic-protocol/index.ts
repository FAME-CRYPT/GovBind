import net from 'node:net';
import path from 'node:path';

import dotenv from 'dotenv';
import express, { type ErrorRequestHandler } from 'express';
import multer from 'multer';

import indexRouter from './routers';
import proofRouter from './routers/proof';
import verifyRouter from './routers/verify';
import { getProofRecords } from './utils/get-proof-records';
import { withProcessLogging } from './utils/process-logger';

dotenv.config({ quiet: true });

const app = express();
const port = Number.parseInt(process.env.PORT ?? '3000', 10);
const projectDirectory = path.resolve(__dirname, '..');
const notaryAddress = process.env.TLSN_NOTARY_ADDR ?? '127.0.0.1:8000';
const NOTARY_KEY_REQUEST = 'ZKDEVLET_NOTARY_KEY_V1\n';

function parseNotaryAddress(address: string): { host: string; port: number } {
  const match = address.match(/^(127\.0\.0\.1|\[::1\]):(\d{1,5})$/);
  const notaryPort = Number.parseInt(match?.[2] ?? '', 10);

  if (!match || notaryPort < 1 || notaryPort > 65_535) {
    throw new Error(
      'TLSN_NOTARY_ADDR must be a loopback address such as 127.0.0.1:8000.',
    );
  }

  return {
    host: match[1] === '[::1]' ? '::1' : match[1],
    port: notaryPort,
  };
}

async function initializeNotary(): Promise<void> {
  const address = parseNotaryAddress(notaryAddress);
  const publicKey = await new Promise<string>((resolve, reject) => {
    const socket = net.createConnection(address);
    let response = '';
    let settled = false;

    const finish = (error?: Error): void => {
      if (settled) {
        return;
      }
      settled = true;
      socket.destroy();
      if (error) {
        reject(error);
      }
    };

    socket.setEncoding('ascii');
    socket.setTimeout(5_000);
    socket.once('connect', () => socket.write(NOTARY_KEY_REQUEST));
    socket.on('data', (chunk: string) => {
      response += chunk;
      if (response.length > 68) {
        finish(new Error('Notary public-key response is too large.'));
        return;
      }

      const newline = response.indexOf('\n');
      if (newline >= 0) {
        const key = response.slice(0, newline).toLowerCase();
        if (!/^[0-9a-f]{66}$/.test(key)) {
          finish(new Error('Notary returned an invalid public key.'));
          return;
        }
        settled = true;
        socket.destroy();
        resolve(key);
      }
    });
    socket.once('timeout', () => finish(new Error('Notary connection timed out.')));
    socket.once('error', (error) =>
      finish(new Error(`Notary is unavailable at ${notaryAddress}: ${error.message}`)),
    );
    socket.once('close', () => {
      if (!settled) {
        finish(new Error('Notary closed the public-key connection unexpectedly.'));
      }
    });
  });

  const configuredKey = process.env.TLSN_NOTARY_PUBLIC_KEY?.toLowerCase();
  if (configuredKey && configuredKey !== publicKey) {
    throw new Error('Notary public key does not match TLSN_NOTARY_PUBLIC_KEY.');
  }
  process.env.TLSN_NOTARY_PUBLIC_KEY = publicKey;
}

app.set('view engine', 'pug');
app.set('views', path.join(projectDirectory, 'views'));
app.use(express.static(path.join(projectDirectory, 'public')));
app.use(indexRouter);
app.use('/proof', proofRouter);
app.use('/verify', verifyRouter);

const handleError: ErrorRequestHandler = (error, _request, response, _next) => {
  if (error instanceof multer.MulterError) {
    response.status(400).json({ error: error.message });
    return;
  }
  if (error instanceof SyntaxError && (error as { status?: number }).status === 400) {
    response.status(400).json({ error: 'Request body must contain valid JSON.' });
    return;
  }

  console.error(error);
  response.status(500).json({ error: 'Unexpected server error.' });
};

app.use(handleError);

async function start(): Promise<void> {
  await withProcessLogging('startup', 'load proof records', getProofRecords);
  await withProcessLogging('startup', 'connect to notary', initializeNotary);
  app.listen(port, '127.0.0.1', (error?: Error) => {
    if (error) {
      console.error(`Unable to start GovBind: ${error.message}`);
      process.exitCode = 1;
      return;
    }

    console.log(`GovBind is available at http://localhost:${port}`);
  });
}

void start().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`Unable to initialize GovBind: ${message}`);
  process.exitCode = 1;
});
