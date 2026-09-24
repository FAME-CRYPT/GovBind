import net from 'node:net';

export const DEFAULT_NOTARY_ADDRESS = '127.0.0.1:8000';
const NOTARY_KEY_REQUEST = 'ZKDEVLET_NOTARY_KEY_V1\n';

function parseNotaryAddress(address: string): { host: string; port: number } {
  const match = address.match(/^(127\.0\.0\.1|\[::1\]):(\d{1,5})$/);
  const port = Number.parseInt(match?.[2] ?? '', 10);
  if (!match || port < 1 || port > 65_535) {
    throw new Error('TLSN_NOTARY_ADDR must be a loopback address such as 127.0.0.1:8000.');
  }
  return { host: match[1] === '[::1]' ? '::1' : match[1], port };
}

export async function trustedNotaryPublicKey(
  notaryAddress = process.env.TLSN_NOTARY_ADDR ?? DEFAULT_NOTARY_ADDRESS,
): Promise<string> {
  const address = parseNotaryAddress(notaryAddress);
  const discoveredKey = await new Promise<string>((resolve, reject) => {
    const socket = net.createConnection(address);
    let response = '';
    let settled = false;
    const finish = (error: Error): void => {
      if (settled) return;
      settled = true;
      socket.destroy();
      reject(error);
    };

    socket.setEncoding('ascii');
    socket.setTimeout(5_000);
    socket.once('connect', () => socket.write(NOTARY_KEY_REQUEST));
    socket.on('data', (chunk: string) => {
      response += chunk;
      if (response.length > 68) {
        finish(new Error('Notary public-key response is too large.'));
        return;
      }
      const newline = response.indexOf('\n');
      if (newline < 0) return;
      const key = response.slice(0, newline).toLowerCase();
      if (!/^[0-9a-f]{66}$/.test(key)) {
        finish(new Error('Notary returned an invalid public key.'));
        return;
      }
      settled = true;
      socket.destroy();
      resolve(key);
    });
    socket.once('timeout', () => finish(new Error('Notary connection timed out.')));
    socket.once('error', (error) => finish(
      new Error(`Notary is unavailable at ${notaryAddress}: ${error.message}`),
    ));
    socket.once('close', () => {
      if (!settled) finish(new Error('Notary closed the public-key connection unexpectedly.'));
    });
  });

  const configuredKey = process.env.TLSN_NOTARY_PUBLIC_KEY?.toLowerCase();
  if (configuredKey && configuredKey !== discoveredKey) {
    throw new Error('Notary public key does not match TLSN_NOTARY_PUBLIC_KEY.');
  }
  return discoveredKey;
}
