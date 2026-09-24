import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { documentProfiles } from '../utils/document-profiles';

const projectDirectory = path.resolve(__dirname, '..', '..');
const defaultNargo = path.join(os.homedir(), '.nargo', 'bin', 'nargo');
const nargo = process.env.NARGO_BIN ??
  (existsSync(defaultNargo) ? defaultNargo : 'nargo');

for (const profile of Object.values(documentProfiles)) {
  execFileSync(nargo, ['test'], {
    cwd: path.join(projectDirectory, 'circuits', profile.circuitDirectory),
    stdio: 'inherit',
    timeout: 15 * 60_000,
  });
}
