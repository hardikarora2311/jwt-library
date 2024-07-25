interface Payload {
  [key: string]: any;
}

async function importKey(secret: string) {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: { name: "SHA-256" } },
    false,
    ["sign", "verify"]
  );
}

async function signData(secret: string, data: string): Promise<string> {
  const key = await importKey(secret);
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(data)
  );
  return Buffer.from(signature).toString("base64url");
}

export async function encode_jwt(
  secret: string,
  id: string | number,
  payload: Payload,
  ttl?: number,
  aud?: string,
  iss?: string
): Promise<string> {
  const header = { alg: "HS256", typ: "JWT" };
  const issuedAt = Math.floor(Date.now() / 1000);
  const expiresAt = ttl ? issuedAt + ttl : undefined;

  const jwtPayload: any = { id, iat: issuedAt, ...payload };
  if (expiresAt) jwtPayload.exp = expiresAt;
  if (aud) jwtPayload.aud = aud;
  if (iss) jwtPayload.iss = iss;

  const base64UrlEncode = (obj: any) =>
    Buffer.from(JSON.stringify(obj)).toString("base64url");

  const headerEncoded = base64UrlEncode(header);
  const payloadEncoded = base64UrlEncode(jwtPayload);
  const signature = await signData(
    secret,
    `${headerEncoded}.${payloadEncoded}`
  );

  return `${headerEncoded}.${payloadEncoded}.${signature}`;
}

async function verifySignature(
  secret: string,
  data: string,
  signature: string
): Promise<boolean> {
  const key = await importKey(secret);
  const sig = Uint8Array.from(
    atob(signature.replace(/-/g, "+").replace(/_/g, "/")),
    (c) => c.charCodeAt(0)
  );
  return crypto.subtle.verify("HMAC", key, sig, new TextEncoder().encode(data));
}

export async function decode_jwt(
  secret: string,
  token: string
): Promise<{
  id: string;
  payload: Payload;
  expires_at: Date;
  issued_at: Date;
}> {
  const [headerEncoded, payloadEncoded, signature] = token.split(".");
  if (!headerEncoded || !payloadEncoded || !signature) {
    throw new Error("Invalid JWT format");
  }

  const base64UrlDecode = (str: string) =>
    Buffer.from(str, "base64url").toString("utf-8");

  const payload = JSON.parse(base64UrlDecode(payloadEncoded));
  const isValid = await verifySignature(
    secret,
    `${headerEncoded}.${payloadEncoded}`,
    signature
  );

  if (!isValid) {
    throw new Error("Invalid JWT");
  }

  const { id, exp, iat, ...restPayload } = payload;

  if (exp && Date.now() >= exp * 1000) {
    throw new Error("JWT has expired");
  }

  return {
    id: id as string,
    payload: restPayload as Payload,
    expires_at: exp ? new Date(exp * 1000) : new Date(),
    issued_at: iat ? new Date(iat * 1000) : new Date(),
  };
}

export async function validate_jwt(
  secret: string,
  token: string
): Promise<boolean> {
  try {
    await decode_jwt(secret, token);
    return true;
  } catch (error) {
    console.error("Validation failed:", error);
    return false;
  }
}
