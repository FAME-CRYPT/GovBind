import type { RequestHandler } from 'express';

import { getProofRecordFile } from '../../../utils/get-proof-record-file';
import { isProofHash } from '../../../utils/proof-record-hash';
import { withProcessLogging } from '../../../utils/process-logger';

const handler: RequestHandler = async (request, response) => {
  const hash = request.query.hash;
  if (!isProofHash(hash)) {
    response.status(400).json({ error: 'A valid proof hash is required.' });
    return;
  }

  const contents = await withProcessLogging(
    'proofs',
    'read proof download',
    () => getProofRecordFile(hash),
  );
  if (!contents) {
    response.status(404).json({ error: 'Proof not found.' });
    return;
  }

  response
    .status(200)
    .attachment(`${hash}.json`)
    .type('application/json')
    .send(contents);
};

export = handler;
