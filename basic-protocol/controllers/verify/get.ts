import type { RequestHandler } from 'express';

const handler: RequestHandler = (_request, response) => {
  const now = new Date();
  const today = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Europe/Istanbul',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  }).format(now);
  const generationDateLabel = new Intl.DateTimeFormat('en', {
    timeZone: 'Europe/Istanbul',
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  }).format(now);

  response.render('index', {
    activePage: 'verify',
    today,
    generationDateLabel,
  });
};

export = handler;
