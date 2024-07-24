import { encode_jwt, decode_jwt, validate_jwt } from '../index.js';
const secret = 'test-secret';
describe('JWT Library', () => {
    test('encode_jwt and decode_jwt', () => {
        const id = '123';
        const payload = { username: 'testuser' };
        const token = encode_jwt(secret, id, payload);
        const decoded = decode_jwt(secret, token);
        expect(decoded.id).toBe(id);
        expect(decoded.payload).toEqual(payload);
        expect(decoded.expires_at).toBeInstanceOf(Date);
    });
    test('validate_jwt', () => {
        const token = encode_jwt(secret, '123', { username: 'testuser' });
        expect(validate_jwt(secret, token)).toBe(true);
        expect(validate_jwt(secret, 'invalid-token')).toBe(false);
    });
});
