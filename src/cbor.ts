/**
 * Minimal CBOR (RFC 8949) reader for Cardano transactions. It decodes the
 * subset Cardano uses and reports the byte range of each item, so hashes can
 * be taken over the exact bytes that were signed.
 */
export class CborError extends Error {
  constructor(message: string, readonly offset: number) {
    super(`${message} at byte ${offset}`);
    this.name = "CborError";
  }
}

export class Tagged {
  constructor(readonly tag: number, readonly value: CborValue) {}
}

export type CborValue =
  | number
  | bigint
  | string
  | boolean
  | null
  | undefined
  | Uint8Array
  | CborValue[]
  | Map<CborValue, CborValue>
  | Tagged;

export interface Item {
  value: CborValue;
  start: number;
  end: number;
}

const BREAK = Symbol("break");

export function decode(bytes: Uint8Array): CborValue {
  const { value, end } = readItem(bytes, 0);
  if (end !== bytes.length) throw new CborError("trailing bytes", end);
  return value;
}

export function readItem(bytes: Uint8Array, offset: number): Item {
  const r = read(bytes, offset);
  if (r.value === BREAK) throw new CborError("unexpected break", offset);
  return { value: r.value, start: offset, end: r.end };
}

/** Items of a top-level array, each with its byte range. */
export function readArrayItems(bytes: Uint8Array, offset = 0): Item[] {
  const { major, arg, end: headEnd, indefinite } = head(bytes, offset);
  if (major !== 4) throw new CborError("expected an array", offset);
  const items: Item[] = [];
  let o = headEnd;
  if (indefinite) {
    while (bytes[o] !== 0xff) {
      const item = readItem(bytes, o);
      items.push(item);
      o = item.end;
    }
  } else {
    for (let i = 0; i < Number(arg); i++) {
      const item = readItem(bytes, o);
      items.push(item);
      o = item.end;
    }
  }
  return items;
}

interface Head {
  major: number;
  arg: bigint;
  info: number;
  end: number;
  indefinite: boolean;
}

function head(bytes: Uint8Array, offset: number): Head {
  if (offset >= bytes.length) throw new CborError("unexpected end of input", offset);
  const initial = bytes[offset];
  const major = initial >> 5;
  const info = initial & 0x1f;
  let o = offset + 1;
  let arg: bigint;
  if (info < 24) arg = BigInt(info);
  else if (info <= 27) {
    const n = 1 << (info - 24);
    if (o + n > bytes.length) throw new CborError("unexpected end of input", o);
    arg = 0n;
    for (let i = 0; i < n; i++) arg = (arg << 8n) | BigInt(bytes[o + i]);
    o += n;
  } else if (info === 31) {
    return { major, arg: 0n, info, end: o, indefinite: true };
  } else {
    throw new CborError(`reserved additional info ${info}`, offset);
  }
  return { major, arg, info, end: o, indefinite: false };
}

function toNumber(n: bigint): number | bigint {
  return n <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(n) : n;
}

function read(bytes: Uint8Array, offset: number): { value: CborValue | typeof BREAK; end: number } {
  const h = head(bytes, offset);
  let o = h.end;
  switch (h.major) {
    case 0:
      return { value: toNumber(h.arg), end: o };
    case 1: {
      const n = -1n - h.arg;
      return { value: n >= BigInt(Number.MIN_SAFE_INTEGER) ? Number(n) : n, end: o };
    }
    case 2:
    case 3: {
      let data: Uint8Array;
      if (h.indefinite) {
        const chunks: Uint8Array[] = [];
        while (bytes[o] !== 0xff) {
          const c = head(bytes, o);
          if (c.major !== h.major || c.indefinite) throw new CborError("bad indefinite-length chunk", o);
          chunks.push(slice(bytes, c.end, Number(c.arg)));
          o = c.end + Number(c.arg);
        }
        o += 1;
        data = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
        let p = 0;
        for (const c of chunks) {
          data.set(c, p);
          p += c.length;
        }
      } else {
        data = slice(bytes, o, Number(h.arg));
        o += Number(h.arg);
      }
      return { value: h.major === 2 ? data : new TextDecoder("utf-8", { fatal: true }).decode(data), end: o };
    }
    case 4: {
      const arr: CborValue[] = [];
      for (let i = 0; h.indefinite || i < Number(h.arg); i++) {
        const r = read(bytes, o);
        o = r.end;
        if (r.value === BREAK) {
          if (!h.indefinite) throw new CborError("unexpected break", o - 1);
          break;
        }
        arr.push(r.value);
      }
      return { value: arr, end: o };
    }
    case 5: {
      const map = new Map<CborValue, CborValue>();
      for (let i = 0; h.indefinite || i < Number(h.arg); i++) {
        const k = read(bytes, o);
        o = k.end;
        if (k.value === BREAK) {
          if (!h.indefinite) throw new CborError("unexpected break", o - 1);
          break;
        }
        const v = read(bytes, o);
        if (v.value === BREAK) throw new CborError("map missing a value", o);
        o = v.end;
        map.set(k.value, v.value);
      }
      return { value: map, end: o };
    }
    case 6: {
      const inner = read(bytes, o);
      if (inner.value === BREAK) throw new CborError("tag without content", o);
      return { value: new Tagged(Number(h.arg), inner.value), end: inner.end };
    }
    default: {
      if (h.indefinite) return { value: BREAK, end: o };
      if (h.info === 20) return { value: false, end: o };
      if (h.info === 21) return { value: true, end: o };
      if (h.info === 22) return { value: null, end: o };
      if (h.info === 23) return { value: undefined, end: o };
      if (h.info === 25 || h.info === 26 || h.info === 27) {
        const n = 1 << (h.info - 24);
        const view = new DataView(bytes.buffer, bytes.byteOffset + offset + 1, n);
        const f = h.info === 25 ? halfToFloat(view.getUint16(0)) : h.info === 26 ? view.getFloat32(0) : view.getFloat64(0);
        return { value: f, end: o };
      }
      throw new CborError(`unsupported simple value ${h.info}`, offset);
    }
  }
}

function slice(bytes: Uint8Array, start: number, length: number): Uint8Array {
  if (start + length > bytes.length) throw new CborError("unexpected end of input", start);
  return bytes.subarray(start, start + length);
}

function halfToFloat(h: number): number {
  const exp = (h >> 10) & 0x1f;
  const mant = h & 0x3ff;
  const sign = h & 0x8000 ? -1 : 1;
  if (exp === 0) return sign * 2 ** -14 * (mant / 1024);
  if (exp === 31) return mant ? NaN : sign * Infinity;
  return sign * 2 ** (exp - 15) * (1 + mant / 1024);
}
