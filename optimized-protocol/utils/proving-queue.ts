let provingQueue: Promise<void> = Promise.resolve();

export function serializeProving<T>(operation: () => Promise<T>): Promise<T> {
  const result = provingQueue.then(operation);
  provingQueue = result.then(() => undefined, () => undefined);
  return result;
}
