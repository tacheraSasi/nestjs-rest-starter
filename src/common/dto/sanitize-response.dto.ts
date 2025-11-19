export function ExcludeFromObject<T extends object>(
  obj: T,
  fields: (keyof T)[],
): Partial<T> {
  const clone = { ...obj };
  for (const field of fields) {
    delete clone[field];
  }
  return clone;
}
