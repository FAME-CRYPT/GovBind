function elapsedMilliseconds(startedAt: bigint): string {
  return (Number(process.hrtime.bigint() - startedAt) / 1_000_000).toFixed(0);
}

export async function withProcessLogging<T>(
  service: string,
  operation: string,
  run: () => Promise<T>,
): Promise<T> {
  const startedAt = process.hrtime.bigint();
  console.info(`[${new Date().toISOString()}] [${service}] ${operation} started.`);

  try {
    const result = await run();
    console.info(
      `[${new Date().toISOString()}] [${service}] ${operation} completed in ${elapsedMilliseconds(startedAt)} ms.`,
    );
    return result;
  } catch (error) {
    console.error(
      `[${new Date().toISOString()}] [${service}] ${operation} failed after ${elapsedMilliseconds(startedAt)} ms.`,
    );
    throw error;
  }
}
