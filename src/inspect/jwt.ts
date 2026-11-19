/** JWT decoder: decodes header and payload, never verifies the signature. */

export interface JwtInfo {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signaturePresent: boolean;
  signatureVerified: false;
  issuedAt: string | null;
  notBefore: string | null;
  expiresAt: string | null;
  expired: boolean | null;
  secondsUntilExpiry: number | null;
  algorithm: string | null;
  warnings: string[];
}

const SENSITIVE_CLAIMS = ["password", "passwd", "secret", "credentials", "private_key", "api_key", "apikey"];

/** Decodes a JWT. Throws on malformed input. Never validates the signature. */
export function decodeJwt(token: string): JwtInfo {
  const trimmed = token.trim();
  const parts = trimmed.split(".");
  if (parts.length < 2 || parts.length > 3) {
    throw new Error("Not a JWT: expected 2 or 3 dot-separated segments");
  }

  const header = decodeJsonSegment(parts[0]!, "header");
  const payload = decodeJsonSegment(parts[1]!, "payload");
  const signature = parts.length === 3 ? parts[2]! : "";

  const warnings: string[] = [];
  const algorithm = typeof header["alg"] === "string" ? header["alg"] : null;
  if (algorithm === "none") warnings.push("algorithm is 'none': the token is unsecured by design");
  if (algorithm && /^HS(128|256|384|512)$/.test(algorithm)) {
    warnings.push(`HMAC algorithm (${algorithm}): validity depends entirely on the signing key`);
  }
  for (const claim of Object.keys(payload)) {
    if (SENSITIVE_CLAIMS.includes(claim.toLowerCase())) {
      warnings.push(`payload contains a sensitive-looking claim: ${claim}`);
    }
  }

  const issuedAt = secondsToIso(payload["iat"]);
  const notBefore = secondsToIso(payload["nbf"]);
  const expiresAt = secondsToIso(payload["exp"]);
  let expired: boolean | null = null;
  let secondsUntilExpiry: number | null = null;
  if (typeof payload["exp"] === "number") {
    const now = Math.floor(Date.now() / 1000);
    secondsUntilExpiry = payload["exp"] - now;
    expired = secondsUntilExpiry < 0;
    if (expired) {
      warnings.push(`token expired ${-secondsUntilExpiry} seconds ago`);
    } else {
      warnings.push(`token expires in ${secondsUntilExpiry} seconds`);
    }
  } else {
    warnings.push("token has no exp claim: it does not expire");
  }

  if (!signature) {
    warnings.push("no signature segment present: this is an unsigned token");
  }

  return {
    header,
    payload,
    signaturePresent: signature.length > 0,
    signatureVerified: false,
    issuedAt,
    notBefore,
    expiresAt,
    expired,
    secondsUntilExpiry,
    algorithm,
    warnings,
  };
}

function decodeJsonSegment(segment: string, label: string): Record<string, unknown> {
  const bytes = base64UrlDecode(segment);
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8").decode(bytes));
  } catch {
    throw new Error(`Not a JWT: ${label} segment is not valid JSON`);
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error(`Not a JWT: ${label} segment must be a JSON object`);
  }
  return parsed as Record<string, unknown>;
}

function base64UrlDecode(segment: string): Uint8Array {
  let normalized = segment.replace(/-/g, "+").replace(/_/g, "/");
  const padding = normalized.length % 4;
  if (padding === 1) throw new Error("Not a JWT: invalid base64url length");
  if (padding > 0) normalized += "=".repeat(4 - padding);
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(normalized)) {
    throw new Error("Not a JWT: invalid base64url characters");
  }
  try {
    return new Uint8Array(Buffer.from(normalized, "base64"));
  } catch {
    throw new Error("Not a JWT: invalid base64url segment");
  }
}

function secondsToIso(value: unknown): string | null {
  if (typeof value !== "number" || !Number.isFinite(value)) return null;
  const date = new Date(value * 1000);
  if (Number.isNaN(date.getTime())) return null;
  return date.toISOString();
}
