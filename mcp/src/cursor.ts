import { createHmac, timingSafeEqual } from "node:crypto";
import { HangarError, type ResourceName } from "./types.js";

const PREFIX = "hmc1.";
const MAX_CURSOR_LENGTH = 2048;

export interface CursorState {
  readonly version: 1;
  readonly resource: ResourceName;
  readonly scope: string;
  readonly projectIndex: number;
  readonly upstreamCursor: string | null;
  readonly offset: number;
}

function sign(payload: string, secret: string): string {
  return createHmac("sha256", secret).update(payload).digest("base64url");
}

export function encodeCursor(state: CursorState, secret: string): string {
  const payload = Buffer.from(JSON.stringify(state), "utf8").toString("base64url");
  return `${PREFIX}${payload}.${sign(payload, secret)}`;
}

export function decodeCursor(value: string, secret: string, resource: ResourceName, scope: string): CursorState {
  if (!value.startsWith(PREFIX) || value.length > MAX_CURSOR_LENGTH) {
    throw new HangarError("INVALID_CURSOR", "The pagination cursor is invalid");
  }
  const parts = value.slice(PREFIX.length).split(".");
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    throw new HangarError("INVALID_CURSOR", "The pagination cursor is invalid");
  }
  const expected = sign(parts[0], secret);
  const actual = parts[1];
  const expectedBytes = Buffer.from(expected);
  const actualBytes = Buffer.from(actual);
  if (expectedBytes.length !== actualBytes.length || !timingSafeEqual(expectedBytes, actualBytes)) {
    throw new HangarError("INVALID_CURSOR", "The pagination cursor is invalid");
  }
  try {
    const decoded = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8")) as Partial<CursorState>;
    if (
      decoded.version !== 1 ||
      decoded.resource !== resource ||
      decoded.scope !== scope ||
      !Number.isInteger(decoded.projectIndex) ||
      (decoded.projectIndex as number) < 0 ||
      !Number.isInteger(decoded.offset) ||
      (decoded.offset as number) < 0 ||
      (decoded.upstreamCursor !== null && typeof decoded.upstreamCursor !== "string")
    ) {
      throw new Error("invalid cursor state");
    }
    return decoded as CursorState;
  } catch {
    throw new HangarError("INVALID_CURSOR", "The pagination cursor is invalid");
  }
}
