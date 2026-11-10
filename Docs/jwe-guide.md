# JSON Web Encryption (JWE) — Practical Guide

How to encrypt and decrypt tokens with `JOSE.Core.JWE` and the JWE support in `TJOSE` and
`TJOSEConsumer`: shared-secret (`dir`) and RSA-OAEP encryption, nested JWTs (signed, then
encrypted), and validating encrypted tokens that come from outside.

Every snippet in this document is compiled and executed by the companion sample
**`Samples\JWEGuide\JWEGuide.dproj`**, a console app that runs the whole guide top to bottom
(Delphi 13, default OpenSSL provider stack, keys from `Tests\Keys`).

- [What is supported](#what-is-supported)
- [Signed, encrypted, or both?](#signed-encrypted-or-both)
- [Encrypting with a shared secret (`dir`)](#encrypting-with-a-shared-secret-dir)
- [Encrypting to an RSA key (RSA-OAEP)](#encrypting-to-an-rsa-key-rsa-oaep)
- [Nested JWT: sign, then encrypt](#nested-jwt-sign-then-encrypt)
- [Validating encrypted tokens with the consumer](#validating-encrypted-tokens-with-the-consumer)
- [Tokens from Keycloak and other IdPs (AES-CBC-HMAC)](#tokens-from-keycloak-and-other-idps-aes-cbc-hmac)
- [Compression](#compression)
- [Reading the header without decrypting](#reading-the-header-without-decrypting)
- [Error handling](#error-handling)
- [Security notes](#security-notes)
- [Memory ownership rules](#memory-ownership-rules)
- [Provider requirements](#provider-requirements)
- [Running the sample](#running-the-sample)

---

## What is supported

JWE compact serialization ([RFC 7516](https://tools.ietf.org/html/rfc7516)), single recipient:

| Header | Values | Notes |
|---|---|---|
| `alg` (key management) | `dir` | The shared key *is* the content encryption key (CEK) |
| | `RSA-OAEP`, `RSA-OAEP-256` | A random CEK, encrypted to the recipient's RSA public key (2048 bits or more) |
| `enc` (content encryption) | `A128GCM`, `A192GCM`, `A256GCM` | AES-GCM with a fresh random 96-bit IV per token |
| | `A128CBC-HS256`, `A192CBC-HS384`, `A256CBC-HS512` | AES-CBC plus an HMAC-SHA2 tag, fresh random 128-bit IV per token. `A128CBC-HS256` is Keycloak's default |
| `zip` (compression) | `DEF` | Raw DEFLATE. Always accepted on decryption, used on encryption only [when asked](#compression) |

Not supported (yet): AES key wrap (`A*KW`), ECDH-ES, AES-GCM key wrap, password-based encryption,
and the JSON serializations. A token that uses any of them is rejected with an error that names
it. `RSA1_5` is left out on purpose: it is vulnerable to padding-oracle attacks and
[RFC 8725](https://tools.ietf.org/html/rfc8725) advises against it.

Units you will normally need:

```delphi
uses
  JOSE.Types.Bytes,      // TJOSEBytes
  JOSE.Core.Base,        // EJOSEException
  JOSE.Core.JWA,         // TJOSEAlgorithmId, TJOSEEncryptionAlgorithmId
  JOSE.Core.JWK,         // TJWK, TJSONWebKey
  JOSE.Core.JWT,         // TJWT, TJWTClaims
  JOSE.Core.JWE,         // TJWE (only for the lower-level API)
  JOSE.Core.Builder,     // TJOSE
  JOSE.Consumer;         // TJOSEConsumerBuilder, IJOSEConsumer
```

---

## Signed, encrypted, or both?

| You want | Use | Who can read the claims | Who can have produced the token |
|---|---|---|---|
| Integrity only | JWS (`TJOSE.SerializeCompact`) | anyone | the holder of the signing key |
| Confidentiality, shared secret | JWE `dir` (`TJOSE.Encrypt`) | the holders of the secret | the holders of the secret |
| Confidentiality to one recipient | JWE RSA-OAEP (`TJOSE.Encrypt`) | the holder of the private key | **anyone** with the public key |
| Both | Nested JWT (`TJOSE.SignAndEncrypt`) | the decryption key holder | the signing key holder |

The third row is the one to think about: RSA-OAEP encryption needs only the recipient's
**public** key, so an encrypted token on its own proves nothing about who made it. That is why
encrypted JWTs are almost always nested (signed by the issuer, then encrypted to the recipient),
and why the consumer requires a signature by default.

---

## Encrypting with a shared secret (`dir`)

```delphi
function Snippet_EncryptDir(const AKey: TJOSEBytes): TJOSEBytes;
var
  LToken: TJWT;
begin
  LToken := TJWT.Create;
  try
    LToken.Claims.Subject := 'paolo.rossi';
    LToken.Claims.Expiration := IncHour(Now, 1);

    // "dir": AKey is the content encryption key itself, 32 bytes for A256GCM
    Result := TJOSE.Encrypt(AKey, LToken, TJOSEAlgorithmId.Dir, TJOSEEncryptionAlgorithmId.A256GCM);
  finally
    LToken.Free;
  end;
end;
```

With `dir` the key length is fixed by `enc`: **16 bytes for `A128GCM`, 24 for `A192GCM`, 32 for
`A256GCM`; 32, 48 and 64 for `A128CBC-HS256`, `A192CBC-HS384` and `A256CBC-HS512`** (half HMAC
key, half AES key). A key of any other length is refused (`A "dir" key must be exactly as long as the
content encryption key`), never truncated or padded. Generate one with
`TJOSEBytes.RandomBytes(32)`, which uses the operating system's cryptographic generator.

The token's header (`typ`, `kid`, custom members) becomes the JWE header, with `alg` and `enc`
added.

Decrypting:

```delphi
procedure Snippet_DecryptDir(const AKey, ACompactToken: TJOSEBytes);
var
  LToken: TJWT;
begin
  LToken := TJOSE.Decrypt(AKey, ACompactToken);
  try
    Writeln('alg/enc: ', LToken.Header.Algorithm, ' / ', LToken.Header.JSON.GetValue<string>('enc'));
    Writeln('sub    : ', LToken.Claims.Subject);
  finally
    LToken.Free;
  end;
end;
```

```
alg/enc: dir / A256GCM
sub    : paolo.rossi
```

`TJOSE.Decrypt` raises `EJOSEException` when the token cannot be read or decrypted (unlike
`TJOSE.Verify`, it never returns `nil`). Like `TJOSE.Verify`, it has **no algorithm allowlist**:
any supported `alg`/`enc` is accepted. It does not check the claims (`exp`, `aud`, ...) either.
For tokens that come from outside, use the [consumer](#validating-encrypted-tokens-with-the-consumer).

---

## Encrypting to an RSA key (RSA-OAEP)

The sender needs the recipient's public key, a PEM public key or an X.509 certificate. The
recipient decrypts with the private key.

```delphi
function Snippet_EncryptRSA: TJOSEBytes;
var
  LToken: TJWT;
begin
  LToken := TJWT.Create;
  try
    LToken.Header.KeyID := 'enc-2026-11';
    LToken.Claims.Subject := 'paolo.rossi';

    // The recipient's public key: a PEM public key or an X.509 certificate
    Result := TJOSE.Encrypt(TFile.ReadAllBytes('rsa-public.pem'), LToken,
      TJOSEAlgorithmId.RSA_OAEP_256, TJOSEEncryptionAlgorithmId.A256GCM);
  finally
    LToken.Free;
  end;
end;

procedure Snippet_DecryptRSA(const ACompactToken: TJOSEBytes);
var
  LToken: TJWT;
begin
  LToken := TJOSE.Decrypt(TFile.ReadAllBytes('rsa-private.pem'), ACompactToken);
  try
    Writeln('kid: ', LToken.Header.KeyID, ', sub: ', LToken.Claims.Subject);
  finally
    LToken.Free;
  end;
end;
```

```
kid: enc-2026-11, sub: paolo.rossi
```

`RSA-OAEP-256` (OAEP with SHA-256) is the one to choose for new systems. `RSA-OAEP` (SHA-1) is
there for interoperability: it is what Azure AD/Entra and Keycloak issue by default, and it is not
broken the way `RSA1_5` is. Keys below 2048 bits are refused, as RFC 7518 requires.

An X.509 certificate is accepted as a container for the public key, exactly as for RS*/PS*
verification. **The certificate is not validated** (chain, dates, revocation, key usage): check
it yourself before encrypting to it if that matters.

### With a JSON Web Key

A `TJSONWebKey` (see the [JWK guide](jwk-guide.md)) gives you the PEM that `TJOSE` takes:

```delphi
procedure Snippet_RSAWithJWK;
var
  LKey: TJSONWebKey;
  LPublicPEM, LPrivatePEM, LCompact: TJOSEBytes;
  LToken: TJWT;
begin
  LKey := TJSONWebKey.FromPEM(TFile.ReadAllBytes('rsa-private.pem'));
  try
    LPublicPEM := LKey.ToPEM(False);
    LPrivatePEM := LKey.ToPEM(True);
  finally
    LKey.Free;
  end;

  LToken := TJWT.Create;
  try
    LToken.Claims.Subject := 'paolo.rossi';
    LCompact := TJOSE.Encrypt(LPublicPEM, LToken, TJOSEAlgorithmId.RSA_OAEP_256,
      TJOSEEncryptionAlgorithmId.A128GCM);
  finally
    LToken.Free;
  end;

  LToken := TJOSE.Decrypt(LPrivatePEM, LCompact);
  try
    Writeln('decrypted with the JWK: sub=', LToken.Claims.Subject);
  finally
    LToken.Free;
  end;
end;
```

For `dir`, the secret of an `oct` key is `TJSONWebKey.K`.

---

## Nested JWT: sign, then encrypt

`TJOSE.SignAndEncrypt` signs the token (a JWS, exactly what `TJOSE.SerializeCompact` produces),
then encrypts that JWS into a JWE whose header says `"cty":"JWT"`
([RFC 7519 §5.2](https://tools.ietf.org/html/rfc7519#section-5.2)):

```delphi
function Snippet_SignAndEncrypt: TJOSEBytes;
var
  LSignKey, LEncryptKey: TJWK;
  LToken: TJWT;
begin
  LSignKey := TJWK.Create(HMAC_SECRET);
  LEncryptKey := TJWK.Create(TFile.ReadAllBytes('rsa-public.pem'));
  LToken := TJWT.Create;
  try
    LToken.Claims.Issuer := 'https://auth.example.com';
    LToken.Claims.Audience := 'my-api';
    LToken.Claims.Subject := 'paolo.rossi';
    LToken.Claims.Expiration := IncHour(Now, 1);

    // Signed with HS256, then encrypted with RSA-OAEP-256 + A256GCM ("cty":"JWT")
    Result := TJOSE.SignAndEncrypt(LSignKey, TJOSEAlgorithmId.HS256,
      LEncryptKey, TJOSEAlgorithmId.RSA_OAEP_256, TJOSEEncryptionAlgorithmId.A256GCM, LToken);
  finally
    LToken.Free;
    LEncryptKey.Free;
    LSignKey.Free;
  end;
end;
```

Any signing algorithm works for the inner token (HS*, RS*, PS*, ES*), with any of the encryption
algorithms for the outer one.

`SignAndEncrypt` takes an optional outer header: pass a `TJWTHeader` (or `TJWEHeader`) to put the
encryption key's `kid`, a `"zip":"DEF"` or any custom JWE parameter on the outer token. The header is
copied, never modified, and its `cty` is always forced to `JWT`; with no header the outer token
carries only `typ` and `cty`.

The counterpart is `TJOSE.DecryptAndVerify`, which decrypts with one key and verifies the inner
signature with the other:

```delphi
procedure Snippet_DecryptAndVerify(const ACompactToken: TJOSEBytes);
var
  LDecryptKey, LVerifyKey: TJWK;
  LToken: TJWT;
begin
  LDecryptKey := TJWK.Create(TFile.ReadAllBytes('rsa-private.pem'));
  LVerifyKey := TJWK.Create(HMAC_SECRET);
  try
    // Raises if the JWE does not decrypt or the inner signature does not verify
    LToken := TJOSE.DecryptAndVerify(LDecryptKey, LVerifyKey, ACompactToken);
    try
      Writeln('inner alg: ', LToken.Header.Algorithm, ', sub: ', LToken.Claims.Subject);
    finally
      LToken.Free;
    end;
  finally
    LVerifyKey.Free;
    LDecryptKey.Free;
  end;
end;
```

```
inner alg: HS256, sub: paolo.rossi
```

The token that comes back is the **inner** one: its header is the JWS header, its claims are the
signed claims.

`Encrypt`, `Decrypt`, `SignAndEncrypt` and `DecryptAndVerify` also have `TJSONWebKey` overloads: the
public half is used to encrypt and to verify (the secret for `oct` keys), the private half to sign
and to decrypt. A key that carries no private half (a public-only RSA JWK, for instance) is refused
with a clear error rather than failing inside the provider.

`TJOSE.Decrypt` refuses a nested JWT (`use DecryptAndVerify, which also verifies the inner
signature`), so the signature cannot be skipped by accident. `DecryptAndVerify` in turn refuses a
JWE that is not nested.

---

## Validating encrypted tokens with the consumer

For a token that comes from outside, use `TJOSEConsumerBuilder`, as for JWS. It adds what
`TJOSE` leaves out: algorithm allowlists and claim validation.

```delphi
function Snippet_NestedConsumer: IJOSEConsumer;
begin
  Result := TJOSEConsumerBuilder.NewConsumer
    // The two keys: one per layer
    .SetDecryptionKey(TFile.ReadAllBytes('rsa-private.pem'))
    .SetVerificationKey(HMAC_SECRET)
    // Outer layer (JWE): empty by default, so nothing gets in unless listed
    .SetExpectedKeyManagementAlgorithms([TJOSEAlgorithmId.RSA_OAEP_256])
    .SetExpectedEncryptionAlgorithms([TJOSEEncryptionAlgorithmId.A256GCM])
    // Inner layer (JWS)
    .SetExpectedAlgorithms([TJOSEAlgorithmId.HS256])
    // Claims of the inner token
    .SetExpectedIssuer(True, 'https://auth.example.com')
    .SetExpectedAudience(True, ['my-api'])
    .SetRequireSubject
    .SetRequireExpirationTime
    .Build;
end;
```

What the consumer does with a JWE:

1. Checks `alg` against `SetExpectedKeyManagementAlgorithms` and `enc` against
   `SetExpectedEncryptionAlgorithms`, **before any cryptography**. Both lists are **empty by
   default**: a consumer that was never told about JWE rejects every encrypted token, so existing
   code does not start accepting them by surprise. A signing `alg` such as `HS256` never passes,
   even if it is listed there by mistake.
2. Decrypts with the **decryption key**. It is separate from the verification key: a nested JWT
   needs both.
3. For a nested JWT, puts the inner JWS through the same checks as a plain JWS
   (`SetExpectedAlgorithms`, the verification key), and validates **its** claims. Only one level
   of nesting is accepted: an inner token that is itself a JWE is rejected.
4. Validates the claims, as for any token.

`SetDecryptionKey` does not also set the verification key, so a JWS (or the inner JWS of a nested
JWT) needs `SetVerificationKey` explicitly, even if a previous version accepted only the decryption
key. A JWS verified without a verification key raises `A verification key is required to verify the
token`.

After `ProcessContext` (or `Process`), the context's `GetHeader` and `GetClaims` describe the same
layer: for a nested JWT that is the inner JWS, so `GetHeader.Algorithm` is the signing algorithm
that was verified. The outer JWE header stays available through `GetJWEHeader` (`alg`, `enc`,
`zip`, ...).

The signature requirement (on by default) is met by a JWS, or by the inner JWS of a nested JWT. A
JWE that carries the claims directly has no signature, so accepting one is an explicit choice:

```delphi
procedure Snippet_PlainJWEConsumer(const AKey, ACompactToken: TJOSEBytes);
begin
  TJOSEConsumerBuilder.NewConsumer
    .SetDecryptionKey(AKey)
    .SetExpectedKeyManagementAlgorithms([TJOSEAlgorithmId.Dir])
    .SetExpectedEncryptionAlgorithms([TJOSEEncryptionAlgorithmId.A256GCM])
    // The claims are encrypted but not signed: say that this is acceptable
    .SetDisableRequireSignature
    .SetRequireSubject
    .Build
    .Process(ACompactToken);

  Writeln('plain JWE accepted by the consumer');
end;
```

That is reasonable with `dir`, where only the holders of the shared secret can produce a token. It
is rarely what you want with RSA-OAEP, where anyone with your public key can (see
[Signed, encrypted, or both?](#signed-encrypted-or-both)).

`SetEnableRequireEncryption` does the opposite: it rejects anything that is not a JWE, plain JWS
included.

---

## Tokens from Keycloak and other IdPs (AES-CBC-HMAC)

Identity providers that encrypt their tokens mostly use RSA-OAEP for the key, and often the
AES-CBC-HMAC family for the content: Keycloak's defaults are `RSA-OAEP` and `A128CBC-HS256`.
Nothing changes in the code, only the algorithm values:

```delphi
function Snippet_KeycloakStyle: TJOSEBytes;
var
  LSignKey, LEncryptKey: TJWK;
  LToken: TJWT;
begin
  // RS256 inside RSA-OAEP + A128CBC-HS256: the shape of Keycloak's encrypted tokens
  LSignKey := TJWK.Create(TFile.ReadAllBytes('rsa-private.pem'));
  LEncryptKey := TJWK.Create(TFile.ReadAllBytes('rsa-public.pem'));
  LToken := TJWT.Create;
  try
    LToken.Claims.Subject := 'paolo.rossi';
    Result := TJOSE.SignAndEncrypt(LSignKey, TJOSEAlgorithmId.RS256,
      LEncryptKey, TJOSEAlgorithmId.RSA_OAEP, TJOSEEncryptionAlgorithmId.A128CBC_HS256, LToken);
  finally
    LToken.Free;
    LEncryptKey.Free;
    LSignKey.Free;
  end;
end;

procedure Snippet_KeycloakStyleConsumer(const ACompactToken: TJOSEBytes);
begin
  TJOSEConsumerBuilder.NewConsumer
    .SetDecryptionKey(TFile.ReadAllBytes('rsa-private.pem'))
    .SetVerificationKey(TFile.ReadAllBytes('rsa-public.pem'))
    .SetExpectedKeyManagementAlgorithms([TJOSEAlgorithmId.RSA_OAEP, TJOSEAlgorithmId.RSA_OAEP_256])
    .SetExpectedEncryptionAlgorithms([TJOSEEncryptionAlgorithmId.A128CBC_HS256,
      TJOSEEncryptionAlgorithmId.A256GCM])
    .SetExpectedAlgorithms([TJOSEAlgorithmId.RS256])
    .SetRequireSubject
    .Build
    .Process(ACompactToken);

  Writeln('RSA-OAEP + A128CBC-HS256 nested token accepted');
end;
```

In a real deployment the decryption key is **your** private key (the IdP encrypts to the public
key you registered with it), and the verification key is the **IdP's** public signing key.

With AES-CBC-HMAC the key splits in two: the first half is the HMAC key, the second the AES key,
so a `dir` key is twice as long as for GCM (32, 48 and 64 bytes). The tag covers the protected
header, the IV and the ciphertext, and it is checked **before** anything is decrypted: a tampered
token never reaches the CBC padding, which is what keeps CBC safe from padding-oracle attacks.

---

## Compression

`"zip":"DEF"` compresses the payload (raw DEFLATE) before it is encrypted. On the receiving side
it is always supported: a compressed token decrypts like any other. On the sending side it is
**never automatic**. You ask for it by putting `zip` in the token header:

```delphi
function Snippet_Compressed(const AKey: TJOSEBytes): TJOSEBytes;
var
  LToken: TJWT;
begin
  LToken := TJWT.Create;
  try
    LToken.Claims.Subject := 'paolo.rossi';
    LToken.Claims.SetClaim('permissions', DupeString('documents:read ', 100));

    // Compression is never automatic: ask for it in the header
    LToken.Header.SetHeaderParam('zip', 'DEF');
    Result := TJOSE.Encrypt(AKey, LToken, TJOSEAlgorithmId.Dir, TJOSEEncryptionAlgorithmId.A256GCM);
  finally
    LToken.Free;
  end;
end;
```

The 1 500-character claim above makes a 199-character token. Why it is opt-in: the size of the
compressed data depends on how much of it repeats, so when part of the payload is controlled by
an attacker and the rest is secret, the ciphertext length can leak the secret one guess at a time
(the CRIME/BREACH family of attacks, [RFC 8725 §3.6](https://tools.ietf.org/html/rfc8725#section-3.6)).
Compress only payloads that contain no attacker-chosen data next to secrets.

**Decompression is capped.** A few kilobytes of DEFLATE can expand to gigabytes, so a payload that
decompresses to more than `TJWE.MaxDecompressedSize` bytes (250 000 by default) is rejected while
it is being inflated:

```delphi
procedure Snippet_DecompressionCap(const AKey, ACompactToken: TJOSEBytes);
var
  LToken: TJWT;
begin
  // Process-wide, 250 000 bytes unless changed: set it at startup
  TJWE.MaxDecompressedSize := 1024;
  try
    try
      TJOSE.Decrypt(AKey, ACompactToken).Free;
    except
      on E: EJOSEException do
        Writeln('JOSE error: ', E.Message);
    end;
  finally
    TJWE.MaxDecompressedSize := 250000;
  end;

  LToken := TJOSE.Decrypt(AKey, ACompactToken);
  try
    Writeln('decompressed permissions: ', Length(LToken.Claims.JSON.GetValue<string>('permissions')), ' chars');
  finally
    LToken.Free;
  end;
end;
```

```
JOSE error: The JWE payload decompresses to more than 1024 bytes (TJWE.MaxDecompressedSize)
decompressed permissions: 1500 chars
```

Decompression runs after the tag check, so a tampered compressed token fails like any other
(`JWE decryption failed`) and never reaches the decompressor. Any `zip` value other than `DEF` is
rejected, on encryption and decryption alike.

---

## Reading the header without decrypting

To choose a key by `kid` before decrypting, parse the token with `TJWE`. Setting `CompactToken`
reads the header and the parts; nothing is decrypted:

```delphi
procedure Snippet_InspectHeader(const ACompactToken: TJOSEBytes);
var
  LToken: TJWT;
  LJWE: TJWE;
begin
  LToken := TJWT.Create;
  LJWE := TJWE.Create(LToken);
  try
    // Parses, does not decrypt: the header is readable (and unverified) as it is
    LJWE.CompactToken := ACompactToken;
    Writeln('kid=', LJWE.Header.KeyID, ' alg=', LJWE.Header.Algorithm,
      ' enc=', LJWE.Header.Encryption, ' nested=', BoolToStr(LJWE.Header.IsNestedJWT, True));
  finally
    LJWE.Free;
    LToken.Free;
  end;
end;
```

```
kid=enc-2026-11 alg=RSA-OAEP-256 enc=A256GCM nested=False
kid= alg=RSA-OAEP-256 enc=A256GCM nested=True
```

The header is authenticated by the decryption that follows, not before: treat `kid` as a hint
for choosing a key, never as a reason to trust the token.

`TJWE` is also the lower-level API: `Encrypt`/`Decrypt` work on the token's claims,
`EncryptPayload`/`DecryptPayload` on any plaintext (`Payload` holds the result), and
`ProtectedHeader`, `EncryptedKey`, `IV`, `Ciphertext`, `AuthenticationTag` give the five parts as
they appear in the token.

To tell the shapes apart before parsing, `TJOSE.CheckJWECompactToken` answers for a JWE what
`TJOSE.CheckCompactToken` answers for a JWS.

---

## Error handling

| Failure | Exception | Message |
|---|---|---|
| Malformed token (part count, base64url, header not JSON) | `EJOSEException` | names the problem |
| `alg`/`enc` unsupported, `zip` other than `DEF`, `crit` present | `EJOSEException` | names the value or the member |
| `alg`/`enc` not in the consumer's allowlists | `EJOSEException` | names the value |
| **Anything that goes wrong with the token while decrypting** (wrong key, tampered part, bad tag, wrong `dir` key length) | `EJOSEException` | always `JWE decryption failed` |
| Compressed payload that does not inflate, or inflates past `TJWE.MaxDecompressedSize` | `EJOSEException` | names the problem (the token is authentic by then) |
| Inner JWS of a nested JWT: unexpected `alg`, invalid signature | `EJOSEException` | as for a JWS |
| Claim validation failures | `EInvalidJWTException` | lists every failed validator |
| A fault inside a provider while decrypting (out of memory, an access violation, a programming error) | the original exception | not masked as `JWE decryption failed` |
| No provider for AES-GCM/AES-CBC/RSA-OAEP registered | `EJOSEProvidersNotRegistered` | |
| The OpenSSL library has no JWE functions (default stack, before 1.0.2) | `EJOSEProvidersNotRegistered` | says which version is needed |

The last three are configuration or fault problems, not properties of the token, so they keep their
own exception and message even while decrypting. A fault is not disguised as a bad token: that would
leave a broken deployment looking like an attack.

The single `JWE decryption failed` message is deliberate. The header is public, so errors about
it name the problem. Past that point, saying *which* step failed (the key unwrapping, the tag, ...)
would help an attacker who can send tokens and read your errors. The same applies to timing: when
the RSA-OAEP key does not decrypt, processing carries on with a random key and fails on the tag,
like any tampered token
([RFC 7516 §11.5](https://tools.ietf.org/html/rfc7516#section-11.5)).

```delphi
procedure Snippet_ErrorHandling(AConsumer: IJOSEConsumer; const ACompactToken: TJOSEBytes);
begin
  try
    AConsumer.Process(ACompactToken);
    Writeln('Valid token');
  except
    on E: EInvalidJWTException do
      Writeln('Token rejected: ', E.Message);
    on E: EJOSEException do
      Writeln('JOSE error: ', E.Message);
  end;
end;
```

The sample runs it on the nested token, on a copy with one ciphertext character changed, and with
a consumer that was never told about JWE:

```
Valid token
JOSE error: JWE decryption failed
JOSE error: JWE key management algorithm [RSA-OAEP-256] is not listed among those expected
```

---

## Security notes

- **Authenticated header.** The protected header is authenticated exactly as it appears in the
  token. Changing it, even only reordering its members, makes decryption fail.
- **Fresh IV.** Every encryption uses a new random IV (96 bits for GCM, 128 for CBC) from the
  operating system's generator: never encrypt with a fixed IV, and there is no API to pass one.
- **MAC before CBC.** With AES-CBC-HMAC the tag is checked, in constant time, before anything is
  decrypted, so the CBC padding is never examined for a ciphertext that is not authentic: no
  padding oracle.
- **Compression is opt-in and capped.** Never automatic on encryption (it can leak secrets
  through the length, RFC 8725 §3.6), and decompression stops at `TJWE.MaxDecompressedSize`.
- **No unauthenticated plaintext.** If the tag check fails, the partly decrypted plaintext is
  wiped and never returned.
- **One nesting level.** Only one level is followed, so a token cannot make the consumer decrypt
  an unbounded chain.
- **Algorithm namespaces.** JWS and JWE `alg` values are kept apart: a JWE can never be
  "verified" with a signing algorithm, and `TJOSE.Verify` rejects a JWE.
- **`RSA1_5` is not implemented**, and will not be.

---

## Memory ownership rules

| Call | Who frees the result |
|---|---|
| `TJOSE.Decrypt` / `DecryptAndVerify` | **you** (never `nil`: failures raise) |
| `TJOSE.Encrypt` / `SignAndEncrypt` | nothing to free: they return a `TJOSEBytes`; the `TJWT` you pass stays yours |
| `TJWE.Create(AToken)` | **you**, and `AToken` stays yours: free the `TJWE` first |
| `TJWE.Header` | the **TJWE**, borrowed reference |
| `TJOSEContext.GetClaims` on a JWE | the **context**, and empty until `ProcessContext` has decrypted it |

`TJOSE.Encrypt` writes the final header (with `alg` and `enc`) back into the `TJWT` you pass.

---

## Provider requirements

JWE goes through three optional provider capabilities, `TJOSEProviders.AESGCM`,
`TJOSEProviders.AESCBC` and `TJOSEProviders.RSAEncryption` (the CBC-HMAC tag uses the HMAC
provider every stack already has; compression is pure RTL):

| Provider stack | Unit | JWE |
|---|---|---|
| `TJOSEDefaultProviders` (registered automatically) | `JOSE.Providers.Default` | yes: OpenSSL **1.0.2** or later (AES-GCM, AES-CBC and both RSA-OAEP variants) |
| `TJOSETaurusTLSProviders` | `JOSE.Providers.TaurusTLS` | yes: OpenSSL 1.1.x/3.x/4.x |
| `TJOSECryptoLibProviders` | `JOSE.Providers.CryptoLib` | yes: pure Pascal, no DLLs |

On the default stack the JWE functions are loaded the first time JWE is used, and only then: an
OpenSSL library without them does not affect JWS at all, and JWE raises an
`EJOSEProvidersNotRegistered` that says OpenSSL 1.0.2 is required. The check covers the version
number as well as the symbols: the RSA-OAEP digest controls arrived in 1.0.2 and are macros, so a
1.0.1 library that exports everything else is refused up front rather than failing later (on
decryption, with the generic message). The test suite runs the default stack on OpenSSL 1.0.2.

`dir`, AES-GCM, AES-CBC-HMAC and compression do not depend on RSA. RSA-OAEP is compiled out together with RS*/PS* where
`RSA_SIGNING` is switched off in `Source\JOSE.inc`.

---

## Running the sample

```
msbuild Samples\JWEGuide\JWEGuide.dproj /p:Config=Debug /p:Platform=Win32
Samples\Exe\JWEGuide.exe
```

The executable defaults to the keys in `Tests\Keys`; pass another directory as the first parameter
to use your own `rsa-public.pem`/`rsa-private.pem`. Being built on the default provider stack, it
needs `libeay32.dll`/`ssleay32.dll` (OpenSSL 1.0.2) next to the executable, the same pair used by
`Tests\Exe`. Alternatively, register `TJOSECryptoLibProviders` and drop the DLL requirement.

The whole run:

```
--- dir + A256GCM
parts: 5
alg/enc: dir / A256GCM
sub    : paolo.rossi
plain JWE accepted by the consumer
--- RSA-OAEP-256 + A256GCM
kid=enc-2026-11 alg=RSA-OAEP-256 enc=A256GCM nested=False
kid: enc-2026-11, sub: paolo.rossi
decrypted with the JWK: sub=paolo.rossi
--- nested JWT
kid= alg=RSA-OAEP-256 enc=A256GCM nested=True
inner alg: HS256, sub: paolo.rossi
Valid token
JOSE error: JWE decryption failed
JOSE error: JWE key management algorithm [RSA-OAEP-256] is not listed among those expected
--- RSA-OAEP + A128CBC-HS256 (Keycloak style)
kid= alg=RSA-OAEP enc=A128CBC-HS256 nested=True
RSA-OAEP + A128CBC-HS256 nested token accepted
--- compression
kid= alg=dir enc=A256GCM nested=False
token length: 199 chars
JOSE error: The JWE payload decompresses to more than 1024 bytes (TJWE.MaxDecompressedSize)
decompressed permissions: 1500 chars
```
