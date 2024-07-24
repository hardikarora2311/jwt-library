interface Payload {
    [key: string]: any;
}
export declare function encode_jwt(secret: string, id: string | number, payload: Payload, ttl?: number, aud?: string, iss?: string): Promise<string>;
export declare function decode_jwt(secret: string, token: string): Promise<{
    id: string;
    payload: Payload;
    expires_at: Date;
    issued_at: Date;
}>;
export declare function validate_jwt(secret: string, token: string): Promise<boolean>;
export {};
