import { encode_jwt, decode_jwt, validate_jwt } from "../index.js";

// const secret = "your-secret-key";
// const userId = "123";
// const payload = { username: "example_user" };
// const ttl = 3600;
// const audience = "your-audience";
// const issuer = "your-issuer";

// let validToken: string;

// describe("JWT Library", () => {
//   beforeAll(async () => {
//     validToken = await encode_jwt(
//       secret,
//       userId,
//       payload,
//       ttl,
//       audience,
//       issuer
//     );
//   });

//   test("should encode a JWT", async () => {
//     const token = await encode_jwt(
//       secret,
//       userId,
//       payload,
//       ttl,
//       audience,
//       issuer
//     );
//     expect(token).toBeDefined();
//   });

//   test("should decode a JWT", async () => {
//     const decoded = await decode_jwt(secret, validToken, audience, issuer);
//     expect(decoded).toBeDefined();
//     expect(decoded.id).toBe(userId);
//     expect(decoded.payload.username).toBe(payload.username);
//   });

//   test("should validate a valid JWT", async () => {
//     const isValid = await validate_jwt(secret, validToken, audience, issuer);
//     expect(isValid).toBe(true);
//   });

//   test("should invalidate an invalid JWT", async () => {
//     const invalidToken = "invalid-token";
//     const isValid = await validate_jwt(secret, invalidToken, audience, issuer);
//     expect(isValid).toBe(false);
//   });

//   test("should invalidate an expired JWT", async () => {
//     const expiredToken = await encode_jwt(
//       secret,
//       userId,
//       payload,
//       -10,
//       audience,
//       issuer
//     ); // expired by 10 seconds
//     const isValid = await validate_jwt(secret, expiredToken, audience, issuer);
//     expect(isValid).toBe(false);
//   });

//   test("should invalidate a JWT with wrong audience", async () => {
//     const isValid = await validate_jwt(
//       secret,
//       validToken,
//       "wrong-audience",
//       issuer
//     );
//     expect(isValid).toBe(false);
//   });

//   test("should invalidate a JWT with wrong issuer", async () => {
//     const isValid = await validate_jwt(
//       secret,
//       validToken,
//       audience,
//       "wrong-issuer"
//     );
//     expect(isValid).toBe(false);
//   });
// });

const secret = "your-secret-key";
const userId = "123";
const payload = { username: "example_user", aud: "your-audience", iss: "your-issuer" };
const ttl = 3600;

let validToken: string;

describe("JWT Library", () => {
  beforeAll(async () => {
    validToken = await encode_jwt(secret, userId, payload, ttl);
  });

  test("should encode a JWT", async () => {
    const token = await encode_jwt(secret, userId, payload, ttl);
    expect(token).toBeDefined();
  });

  test("should decode a JWT", async () => {
    const decoded = await decode_jwt(secret, validToken);
    expect(decoded).toBeDefined();
    expect(decoded.id).toBe(userId);
    expect(decoded.payload.username).toBe(payload.username);
    expect(decoded.payload.aud).toBe(payload.aud);
    expect(decoded.payload.iss).toBe(payload.iss);
  });

  test("should validate a valid JWT", async () => {
    const isValid = await validate_jwt(secret, validToken);
    expect(isValid).toBe(true);
  });

  test("should invalidate an invalid JWT", async () => {
    const invalidToken = "invalid-token";
    const isValid = await validate_jwt(secret, invalidToken);
    expect(isValid).toBe(false);
  });

  test("should invalidate an expired JWT", async () => {
    const expiredToken = await encode_jwt(secret, userId, payload, -10); // expired by 10 seconds
    const isValid = await validate_jwt(secret, expiredToken);
    expect(isValid).toBe(false);
  });
});
