/** Worker-safe datagram validators. No flow state, port assumptions or inferred fields. */
const u16 = (b: Uint8Array, o: number) => b[o] * 256 + b[o + 1];

export function isDhcpMessage(b: Uint8Array): boolean {
  if (b.length < 240 || ![1, 2].includes(b[0]) || b[2] < 1 || b[2] > 16 ||
      b[236] !== 99 || b[237] !== 130 || b[238] !== 83 || b[239] !== 99) return false;
  let cur = 240;
  let messageType = false;
  while (cur < b.length) {
    const code = b[cur++];
    if (code === 0) continue;
    if (code === 255) return messageType;
    if (cur >= b.length) return false;
    const length = b[cur++];
    if (cur + length > b.length) return false;
    if (code === 53) {
      if (messageType || length !== 1 || b[cur] < 1 || b[cur] > 8) return false;
      messageType = true;
    }
    cur += length;
  }
  return false;
}

/** Validate ordinary options and recursively bounded relay-message options. */
export function isDhcpv6Message(b: Uint8Array, depth = 0): boolean {
  if (depth > 8 || b.length < 4 || b[0] < 1 || b[0] > 13) return false;
  const relay = b[0] === 12 || b[0] === 13;
  let cur = relay ? 34 : 4;
  if (cur > b.length || (relay && b[1] > 32)) return false;
  let relayMessage = false;
  while (cur < b.length) {
    if (cur + 4 > b.length) return false;
    const code = u16(b, cur), length = u16(b, cur + 2);
    cur += 4;
    if (!code || cur + length > b.length) return false;
    if (relay && code === 9) {
      if (relayMessage || !isDhcpv6Message(b.subarray(cur, cur + length), depth + 1)) return false;
      relayMessage = true;
    }
    cur += length;
  }
  return !relay || relayMessage;
}

export function isPfcpMessage(b: Uint8Array, servicePort: boolean): boolean {
  if (b.length < 8 || b[0] >> 5 !== 1 || (b[0] & 0x1c) || u16(b, 2) + 4 !== b.length ||
      ![1, 2, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 50, 51, 52, 53, 54, 55, 56, 57].includes(b[1])) return false;
  const session = Boolean(b[0] & 1);
  const header = session ? 16 : 8;
  if (b.length < header || (b[1] < 50 && session) || ((b[0] & 2) && !session)) return false;
  // Last header octet is spare, or priority in its high nibble when MP is set.
  if (b[header - 1] & (b[0] & 2 ? 15 : 255)) return false;
  let cur = header, corroborated = false;
  while (cur < b.length) {
    if (cur + 4 > b.length) return false;
    const type = u16(b, cur), length = u16(b, cur + 2);
    cur += 4;
    if (!type || cur + length > b.length) return false;
    if (type === 96) {
      if (length !== 4) return false;
      corroborated = true;
    }
    if (type === 60) {
      if (!length || b[cur] > 2 || (b[cur] === 0 && length !== 5) || (b[cur] === 1 && length !== 17)) return false;
      if (b[cur] < 2) corroborated = true;
    }
    cur += length;
  }
  return servicePort || corroborated;
}

/** Validate every RTCP block, including type-specific minimum sizes and final-only padding. */
export function isRtcpMessage(b: Uint8Array): boolean {
  let cur = 0;
  if (b.length < 8 || b.length % 4) return false;
  while (cur < b.length) {
    if (cur + 4 > b.length || b[cur] >> 6 !== 2) return false;
    const type = b[cur + 1], count = b[cur] & 31;
    const size = (u16(b, cur + 2) + 1) * 4;
    if (size < 8 || cur + size > b.length || type < 200 || type > 207) return false;
    let content = size;
    if (b[cur] & 32) {
      const padding = b[cur + size - 1];
      if (cur + size !== b.length || !padding || padding > size - 4) return false;
      content -= padding;
    }
    const minimum = type === 200 ? 28 + count * 24 : type === 201 ? 8 + count * 24 :
      type === 203 ? 4 + count * 4 : [204, 205, 206].includes(type) ? 12 : 8;
    if (content < minimum) return false;
    cur += size;
  }
  return cur === b.length;
}