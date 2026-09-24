export function isTurkishIdentityNumber(value: unknown): value is string {
  if (typeof value !== 'string' || !/^[1-9]\d{10}$/.test(value)) return false;
  const digits = [...value].map(Number);
  const odd = digits[0] + digits[2] + digits[4] + digits[6] + digits[8];
  const even = digits[1] + digits[3] + digits[5] + digits[7];
  return ((odd * 7 - even) % 10 + 10) % 10 === digits[9] &&
    digits.slice(0, 10).reduce((sum, digit) => sum + digit, 0) % 10 === digits[10];
}
