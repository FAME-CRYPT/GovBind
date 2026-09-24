import type { RequestHandler } from 'express';

import { getProofRecords } from '../../../utils/get-proof-records';
import { withProcessLogging } from '../../../utils/process-logger';

const handler: RequestHandler = async (_request, response) => {
  const proofs = await withProcessLogging(
    'proofs',
    'load proof summaries',
    getProofRecords,
  );
  response.status(200).render('proof', {
    activePage: 'proof',
    proofs,
  });
};

export = handler;
