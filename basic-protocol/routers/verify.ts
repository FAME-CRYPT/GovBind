import path from 'node:path';

import express from 'express';
import multer from 'multer';

import showVerification = require('../controllers/verify/get');
import verifyDocument = require('../controllers/verify/post');

const verifyRouter = express.Router();
const upload = multer({
  dest: path.resolve(__dirname, '..', '..', 'uploads', 'original'),
  limits: { fileSize: 4 * 1024 * 1024 },
  fileFilter: (_request, file, done) => {
    done(null, file.mimetype === 'application/pdf');
  },
});

verifyRouter.get('/', showVerification);
verifyRouter.post('/', upload.single('document'), verifyDocument);

export default verifyRouter;
