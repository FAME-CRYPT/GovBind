import express from 'express';

import showHome = require('../controllers/index/get');

const indexRouter = express.Router();

indexRouter.get('/', showHome);

export default indexRouter;
