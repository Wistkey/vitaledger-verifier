/**
 * RFC 8785 JSON Canonicalization Scheme (JCS).
 *
 * Object keys are sorted by UTF-16 code units (the default JS string order),
 * numbers use the ECMAScript shortest round-trip form (what JSON.stringify
 * emits), and no insignificant whitespace is written.
 */
export class CanonicalisationError extends Error {
  constructor(message: string, readonly path: string) {
    super(`${message} at ${path}`);
    this.name = "CanonicalisationError";
  }
}

export function canonicalise(value: unknown): string {
  return write(value, "$");
}

function write(value: unknown, path: string): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "string":
      return JSON.stringify(value);
    case "number":
      if (!Number.isFinite(value)) throw new CanonicalisationError("non-finite number", path);
      return JSON.stringify(value);
    case "object": {
      if (Array.isArray(value)) {
        return `[${value.map((v, i) => write(v, `${path}[${i}]`)).join(",")}]`;
      }
      const proto = Object.getPrototypeOf(value);
      if (proto !== Object.prototype && proto !== null) {
        throw new CanonicalisationError("only plain objects are allowed", path);
      }
      const entries = Object.entries(value as Record<string, unknown>)
        .filter(([, v]) => v !== undefined)
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
      return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${write(v, `${path}.${k}`)}`).join(",")}}`;
    }
    default:
      throw new CanonicalisationError(`unsupported type ${typeof value}`, path);
  }
}
