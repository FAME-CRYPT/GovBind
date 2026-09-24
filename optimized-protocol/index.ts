import path from 'node:path';

import dotenv from 'dotenv';
import express, { type ErrorRequestHandler } from 'express';
import multer from 'multer';

import indexRouter from './routers';
import proofRouter from './routers/proof';
import verifyRouter from './routers/verify';
import { getProofRecords } from './utils/get-proof-records';
import { withProcessLogging } from './utils/process-logger';
import {
  DEFAULT_NOTARY_ADDRESS,
  trustedNotaryPublicKey,
} from './utils/notary-trust';

dotenv.config({ quiet: true });

const app = express();
const port = Number.parseInt(process.env.PORT ?? '3000', 10);
const projectDirectory = path.resolve(__dirname, '..');
const notaryAddress = process.env.TLSN_NOTARY_ADDR ?? DEFAULT_NOTARY_ADDRESS;

async function initializeNotary(): Promise<void> {
  process.env.TLSN_NOTARY_PUBLIC_KEY = await trustedNotaryPublicKey(notaryAddress);
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
