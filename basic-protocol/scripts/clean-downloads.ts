import { readdir, unlink } from 'node:fs/promises';
import path from 'node:path';

import { withProcessLogging } from '../utils/process-logger';

const projectDirectory = path.resolve(__dirname, '..', '..');
const uploadDirectories = [
  path.join(projectDirectory, 'uploads', 'original'),
  path.join(projectDirectory, 'uploads', 'verification'),
];

async function cleanDirectory(directory: string): Promise<number> {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = entries.filter(
    (entry) => entry.isFile() && entry.name !== '.gitignore',
  );
  await Promise.all(
    files.map((entry) => unlink(path.join(directory, entry.name))),
  );
  return files.length;
}

async function main(): Promise<void> {
  const removedCounts = await withProcessLogging(
    'cleanup',
    'remove uploaded and downloaded documents',
    () => Promise.all(uploadDirectories.map(cleanDirectory)),
  );
  const removedTotal = removedCounts.reduce((total, count) => total + count, 0);
  console.info(`Removed ${removedTotal} document file${removedTotal === 1 ? '' : 's'}.`);
}

void main().catch(() => {
  process.exitCode = 1;
});
