import type { RequestHandler } from 'express';

import { deleteProofRecord } from '../../../utils/delete-proof-record';
import { isProofHash } from '../../../utils/proof-record-hash';
import { withProcessLogging } from '../../../utils/process-logger';

interface DeleteProofBody {
  hash?: unknown;
}

const handler: RequestHandler = async (request, response) => {
  const { hash } = (request.body ?? {}) as DeleteProofBody;
  if (!isProofHash(hash)) {
    response.status(400).json({ error: 'A valid proof hash is required.' });
    return;
  }

  const deleted = await withProcessLogging(
    'proofs',
    'delete proof record',
    () => deleteProofRecord(hash),
  );
  if (!deleted) {
    response.status(404).json({ error: 'Proof not found.' });
    return;
  }

  response.status(200).json({ deleted: true, hash });
};

export = handler;
