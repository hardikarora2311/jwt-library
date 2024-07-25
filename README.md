# JWT Library

A custom JSON Web Token (JWT) library implemented using the Web Crypto API, designed for secure encoding and decoding of JWTs without relying on third-party packages.

## Features

- Encode JWTs with custom payloads.
- Decode JWTs to retrieve payload data.
- Validate JWTs to ensure authenticity and validity.
- Support for standard JWT claims such as `iat` (issued at), `exp` (expiration), `aud` (audience), and `iss` (issuer).

## Installation

You can install this library using npm:

```bash
npm install jwt-library
