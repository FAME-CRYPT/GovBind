import type { RequestHandler } from 'express';

const handler: RequestHandler = (_request, response) => {
  response.redirect('/verify');
};

export = handler;
