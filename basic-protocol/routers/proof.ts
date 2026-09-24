import express from 'express';

import deleteProof = require('../controllers/proof/delete/post');
import downloadProof = require('../controllers/proof/download/get');
import listProofs = require('../controllers/proof/index/get');

const proofRouter = express.Router();

proofRouter.get('/', listProofs);
proofRouter.get('/download', downloadProof);
proofRouter.post('/delete', express.json({ limit: '1kb' }), deleteProof);

export default proofRouter;
