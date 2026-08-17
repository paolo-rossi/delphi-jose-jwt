# JSON Web Key (JWK) — Practical Guide

How to use the `TJSONWebKey` / `TJSONWebKeySet` classes in `JOSE.Core.JWK`: creating keys,
importing/exporting PEM, reading a JWKS document, and signing/validating tokens with the keys
you get out of it.

Every snippet in this document is compiled and executed by the companion sample
**`Samples\JWKGuide\JWKGuide.dproj`** — a console app that runs the whole guide top to bottom
(Delphi 12, default OpenSSL provider stack, keys from `Tests\Keys`).

- [Two key models: `TJWK` vs `TJSONWebKey`](#two-key-models-tjwk-vs-tjsonwebkey)
- [Creating keys](#creating-keys)
- [Inspecting a key](#inspecting-a-key)
- [Reading a key set (JWKS)](#reading-a-key-set-jwks)
- [Publishing your own JWKS](#publishing-your-own-jwks)
- [Signing a token with a JWK](#signing-a-token-with-a-jwk)
- [Verifying a token — the quick way](#verifying-a-token--the-quick-way)
- [Validating a token against a key set](#validating-a-token-against-a-key-set)
- [Error handling](#error-handling)
- [Memory ownership rules](#memory-ownership-rules)
- [Provider requirements](#provider-requirements)
- [Running the sample](#running-the-sample)

---

## Two key models: `TJWK` vs `TJSONWebKey`

`JOSE.Core.JWK` contains **two** unrelated things, and the names are close enough to be confusing:

| Type | What it is |
|---|---|
| `TJWK` / `TKeyPair` | The *legacy* key model: a thin wrapper over raw bytes (an HMAC secret or a PEM blob). This is what `TJOSE.Sign`/`TJOSE.Verify`, `TJWS` and `TJOSEProducer` consume internally. |
| `TJSONWebKey` / `TJSONWebKeySet` | The full [RFC 7517](https://tools.ietf.org/html/rfc7517) implementation: a JSON object with `kty`, `kid`, `alg`, `use`, and the type-specific key material (`k`, `n`/`e`/`d`/…, `crv`/`x`/`y`/`d`). |

They are bridged by **`TJSONWebKey.ToKeyPair`** (and `TJSONWebKey.FromKeyPair`). The typical pipeline is:

```
JWKS JSON / PEM  ->  TJSONWebKey  ->  ToKeyPair  ->  TJOSE.Sign / TJOSE.Verify / TJOSEConsumer
```

Units you will normally need:

```delphi
uses
  JOSE.Types.Bytes,      // TJOSEBytes
  JOSE.Core.Base,        // TJOSETimeUnit, EJOSEException
  JOSE.Core.JWA,         // TJOSEAlgorithmId
  JOSE.Core.JWK,         // TJSONWebKey, TJSONWebKeySet, TKeyPair
  JOSE.Core.JWT,         // TJWT, TJWTClaims
  JOSE.Core.JWS,         // TJWS (only if you inspect the JOSE header)
  JOSE.Core.Builder,     // TJOSE
  JOSE.Context,          // TJOSEContext
  JOSE.Consumer,         // TJOSEConsumerBuilder, IJOSEConsumer
  JOSE.Encoding.Base64;  // TBase64
```

---

## Creating keys

### From a PEM file (RSA or EC, public or private)

`FromPEM` sniffs the key type for you — PKCS#1, PKCS#8, SPKI and traditional EC PEMs are all accepted:

```delphi
var
  LKey: TJSONWebKey;
begin
  LKey := TJSONWebKey.FromPEM(TFile.ReadAllBytes('rsa-private.pem'));
  try
    Writeln('kty       : ', LKey.Kty.AsString);
    Writeln('private?  : ', BoolToStr(LKey.IsPrivate, True));
    Writeln('thumbprint: ', LKey.Thumbprint.AsString);
    Writeln(LKey.ToJSON);
  finally
    LKey.Free;
  end;
end;
```

Output (with `Tests\Keys\rsa-private.pem`):

```
kty       : RSA
private?  : True
thumbprint: QkmVSGf0ngVOZXj1EyLfAYHJ_I44aOCaMnq47Jy3Hbc
{"kty":"RSA","n":"3-fRbSnigY-ibVisHjAc_3nyv23y4kC4pCoyDWcX9jWqb3m0...","e":"AQAB","d":"Uy8w4zmYaUIPukgjSePeIhwQT4Ztohkhf_wdNFWE1Xg...","p":"...","q":"...","dp":"...","dq":"...","qi":"..."}
```

### From components

```delphi
var
  LOct, LRSA, LEC: TJSONWebKey;
begin
  // Symmetric (HMAC) key
  LOct := TJSONWebKey.CreateOct('my_very_long_and_safe_secret_key');
  LOct.Kid := 'hmac-2026-01';
  LOct.Use := TJOSEKeyUse.Signature;
  LOct.Alg := TJOSEAlgorithmId.HS256;
  LOct.KeyOps := [TJOSEKeyOperation.Sign, TJOSEKeyOperation.Verify];

  // RSA public key — components are raw bytes, not base64url strings
  LRSA := TJSONWebKey.CreateRSAPublic(TBase64.URLDecode('0vx7ago...'), TBase64.URLDecode('AQAB'));

  // EC public key
  LEC := TJSONWebKey.CreateECPublic(TJOSEEllipticCurve.P256,
    TBase64.URLDecode('f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU'),
    TBase64.URLDecode('x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0'));
  ...
```

The other constructors are `CreateRSAPrivate(N, E, D, P, Q, DP, DQ, QI)` and
`CreateECPrivate(Crv, X, Y, D)`.

> **Note:** the `TJOSEBytes` properties (`K`, `N`, `E`, `D`, `X`, `Y`, …) hold the **decoded** key
> material. Base64url encoding/decoding to and from the JSON representation is automatic — so when
> you feed a value taken from a JWK document, decode it first with `TBase64.URLDecode`.

### From JSON

```delphi
var
  LKey, LParsed: TJSONWebKey;
  LJSON: string;
begin
  LKey := TJSONWebKey.CreateOct('my_very_long_and_safe_secret_key');
  try
    LJSON := LKey.ToJSON;
  finally
    LKey.Free;
  end;

  LParsed := TJSONWebKey.FromJSON(LJSON);
  try
    Writeln(LParsed.K.AsString);   // my_very_long_and_safe_secret_key
  finally
    LParsed.Free;
  end;
end;
```

`FromJSON` validates that `kty` is present and recognized; anything else raises `EJOSEJWKException`.

---

## Inspecting a key

| Member | Notes |
|---|---|
| `Kty` | `TJOSEKeyType` — `Oct`, `RSA`, `EC`. **Raises** `EJOSEJWKException` if `kty` is missing. |
| `Kid`, `X5u`, `X5t`, `X5tS256` | plain strings, empty when absent |
| `X5c` | `TArray<string>` |
| `Use` | `TJOSEKeyUse` — `Unspecified` when absent |
| `Alg` | `TJOSEAlgorithmId` — `Unknown` when absent |
| `KeyOps` | set of `TJOSEKeyOperation` |
| `Crv` | `TJOSEEllipticCurve` — **raises** if `crv` is missing, so only read it on `EC` keys |
| `IsPrivate` | `k` for oct, `d` for RSA/EC |
| `Thumbprint` | RFC 7638 SHA-256 thumbprint, already base64url-encoded — makes an excellent `kid` |

```delphi
LKey.Kid := LKey.Thumbprint;   // TJOSEBytes converts implicitly to string
```

---

## Reading a key set (JWKS)

This is the typical *consumer* side: you fetched `https://issuer.example.com/.well-known/jwks.json`
into a string and now want to look at what's inside.

```delphi
procedure ReadKeySet(const AJWKS, AKid: string);
var
  LSet: TJSONWebKeySet;
  LKey: TJSONWebKey;
  LPublicPEM: TJOSEBytes;
begin
  LSet := TJSONWebKeySet.FromJSON(AJWKS);
  try
    for LKey in LSet.Keys do
    begin
      Writeln(Format('kid=%s kty=%s alg=%s use=%s private=%s',
        [LKey.Kid, LKey.Kty.AsString, LKey.Alg.AsString, LKey.Use.AsString,
         BoolToStr(LKey.IsPrivate, True)]));

      case LKey.Kty of
        TJOSEKeyType.Oct:
          Writeln('  secret length: ', LKey.K.Size);
        TJOSEKeyType.RSA:
          Writeln('  modulus bits : ', LKey.N.Size * 8);
        TJOSEKeyType.EC:
          Writeln('  curve        : ', LKey.Crv.AsString);
      end;
    end;

    // Pick one key by its [kid] — returns nil when not found
    LKey := LSet.FindByKid(AKid);
    if not Assigned(LKey) then
      raise EJOSEJWKException.CreateFmt('Key [%s] not found in the key set', [AKid]);

    // Extract the key material in PEM form (False = public half only)
    LPublicPEM := LKey.ToPEM(False);
    Writeln(LPublicPEM.AsString);
  finally
    LSet.Free;    // owns and frees every key in Keys
  end;
end;
```

Output for one RSA entry:

```
kid=QkmVSGf0ngVOZXj1EyLfAYHJ_I44aOCaMnq47Jy3Hbc kty=RSA alg=RS256 use=sig private=False
  modulus bits : 2048
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA3+fRbSnigY+ibVisHjAc/3nyv23y4kC4pCoyDWcX9jWqb3m04L9S
...
-----END RSA PUBLIC KEY-----
```

> :information_source: That `RSA PUBLIC KEY` header is what the OpenSSL-backed stacks emit. The
> CryptoLib stack writes the same key as a `PUBLIC KEY` (SPKI) block instead — see
> [`ToPEM` output format is provider-dependent](#topem-output-format-is-provider-dependent).

`LSet.Keys` is a `TObjectList<TJSONWebKey>` — index it, enumerate it, `Count` it. The keys belong
to the set: **do not free** what `FindByKid` or the enumeration hands you, and do not use them after
the set is freed.

---

## Publishing your own JWKS

Load your private signing key, strip it down to its public half with `ToPublicJWK`, and publish
that:

```delphi
var
  LSet: TJSONWebKeySet;
  LPrivate, LPublic: TJSONWebKey;
begin
  LSet := TJSONWebKeySet.Create;
  try
    LPrivate := TJSONWebKey.FromPEM(TFile.ReadAllBytes('rsa-private.pem'));
    try
      LPrivate.SetKidFromThumbprint;     // RFC 7638: the key names itself
      LPrivate.Use := TJOSEKeyUse.Signature;
      LPrivate.Alg := TJOSEAlgorithmId.RS256;

      LPublic := LPrivate.ToPublicJWK;   // kid/use/alg come across; d, p, q, dp, dq, qi do not
      LSet.AddKey(LPublic);              // the set now owns LPublic
    finally
      LPrivate.Free;
    end;

    Writeln(LSet.ToJSON);
  finally
    LSet.Free;
  end;
end;
```

Produces:

```json
{"keys":[{"kty":"RSA","n":"3-fRbSnigY-ibVisHjAc_3ny...","e":"AQAB","kid":"QkmVSGf0ngVOZXj1EyLfAYHJ_I44aOCaMnq47Jy3Hbc","use":"sig","alg":"RS256"}]}
```

`SetKidFromThumbprint` applies the RFC 7638 convention of naming a key after itself, so whoever
holds the private key and whoever fetches the published one arrive at the same `kid` without
agreeing on it in advance. Because the thumbprint covers only the public members, the `kid`
survives `ToPublicJWK` unchanged.

> :warning: Avoid it on `oct` keys. A symmetric key's thumbprint is a hash of the secret, and a
> `kid` travels in cleartext in every JWS header — against a guessable secret that hands an
> attacker an offline oracle.

`ToPublicJWK` copies members by allowlist rather than by deleting the private ones from a clone,
so a member it does not recognise is dropped instead of published. `kid`, `use`, `alg`,
`key_ops` and the `x5*` members carry across; unknown extension members do not. An `oct` key has
no public half at all — `k` *is* the secret — so `ToPublicJWK` raises for one.

If you already hold a whole set, `ToPublicJWKSet` does the same across it, skipping any `oct`
keys rather than refusing the lot:

```delphi
LPublicSet := LSet.ToPublicJWKSet;
try
  Writeln(LPublicSet.ToJSON);
finally
  LPublicSet.Free;
end;
```

> :bulb: The key set reads `Keys` afresh every time you serialise it, so you can keep configuring
> a key after `AddKey` and `ToJSON` will reflect it.

---

## Signing a token with a JWK

`ToKeyPair` gives you the legacy `TKeyPair` that `TJOSE` expects. Put the key's `kid` in the JOSE
header so the other side knows which key to pick from your JWKS:

```delphi
function SignWithJWK(AKey: TJSONWebKey): TJOSEBytes;
var
  LKeyPair: TKeyPair;
  LToken: TJWT;
begin
  LKeyPair := AKey.ToKeyPair;
  try
    LToken := TJWT.Create;
    try
      LToken.Header.KeyID := AKey.Kid;                  // -> "kid" in the JOSE header
      LToken.Claims.Issuer := 'https://auth.example.com';
      LToken.Claims.Audience := 'my-api';
      LToken.Claims.Subject := 'paolo.rossi';
      LToken.Claims.IssuedAt := Now;
      LToken.Claims.Expiration := IncHour(Now, 1);

      Result := TJOSE.SerializeCompact(LKeyPair.PrivateKey, TJOSEAlgorithmId.RS256, LToken);
    finally
      LToken.Free;
    end;
  finally
    LKeyPair.Free;   // ToKeyPair returns a new object: you own it
  end;
end;
```

The resulting header is `{"typ":"JWT","kid":"QkmVSGf0ngVOZXj1EyLfAYHJ_I44aOCaMnq47Jy3Hbc","alg":"RS256"}`.

The same works for `oct` keys (`ToKeyPair` returns a symmetric pair holding the raw secret) with
`TJOSEAlgorithmId.HS256`, and for EC keys with `ES256`/`ES384`/`ES512`.

> **Careful:** the header is serialized at signing time, so `LToken.Header.KeyID` must be assigned
> *before* `SerializeCompact`.

---

## Verifying a token — the quick way

When you already know which key to use, `TJOSE.Verify` is enough. It checks the signature only —
no claim validation:

```delphi
function QuickVerify(AKey: TJSONWebKey; const ACompactToken: TJOSEBytes): Boolean;
var
  LKeyPair: TKeyPair;
  LToken: TJWT;
begin
  LKeyPair := AKey.ToKeyPair;
  try
    LToken := TJOSE.Verify(LKeyPair.PublicKey, ACompactToken);
    try
      Result := Assigned(LToken) and LToken.Verified;
      if Result then
        Writeln('sub: ', LToken.Claims.Subject);
    finally
      LToken.Free;
    end;
  finally
    LKeyPair.Free;
  end;
end;
```

`TJOSE.Verify` returns `nil` for a malformed token and a `TJWT` with `Verified = False` for a bad
signature — always test both, and always free the returned token.

---

## Validating a token against a key set

This is the real-world flow: an incoming token, a JWKS you fetched from the issuer, and a full
claim validation. The `kid` from the token header selects the key, then the consumer verifies the
signature *and* the claims.

```delphi
function ValidateWithKeySet(const ACompactToken: TJOSEBytes; AKeySet: TJSONWebKeySet): string;
var
  LContext: TJOSEContext;
  LJWS: TJWS;
  LKid: string;
  LKey: TJSONWebKey;
  LKeyPair: TKeyPair;
  LConsumer: IJOSEConsumer;
begin
  LContext := TJOSEContext.Create(ACompactToken, TJWTClaims);
  try
    // 1. Read the [kid] from the (still unverified) JOSE header
    LKid := LContext.GetHeader.KeyID;
    if LKid.IsEmpty then
      raise EInvalidJWTException.Create('The token has no [kid] header');

    // 2. Look the key up in the key set
    LKey := AKeySet.FindByKid(LKid);
    if not Assigned(LKey) then
      raise EInvalidJWTException.CreateFmt('No key with kid [%s] in the key set', [LKid]);

    // 3. Cross-check the [alg] of the token with the one declared by the key
    LJWS := LContext.GetJOSEObject<TJWS>;
    if (LKey.Alg <> TJOSEAlgorithmId.Unknown) and (LKey.Alg <> LJWS.HeaderAlgorithmId) then
      raise EInvalidJWTException.CreateFmt(
        'Token algorithm [%s] does not match the algorithm of key [%s]',
        [LJWS.HeaderAlgorithm, LKid]);

    // 4. Verify the signature and validate the claims
    LKeyPair := LKey.ToKeyPair;
    try
      LConsumer := TJOSEConsumerBuilder.NewConsumer
        .SetVerificationKey(LKeyPair.PublicKey.Key)
        .SetExpectedAlgorithms([TJOSEAlgorithmId.RS256, TJOSEAlgorithmId.ES256])
        .SetExpectedIssuer(True, 'https://auth.example.com')
        .SetExpectedAudience(True, ['my-api'])
        .SetRequireSubject
        .SetRequireExpirationTime
        .SetAllowedClockSkew(60, TJOSETimeUnit.Seconds)
        .Build;

      LConsumer.ProcessContext(LContext);
    finally
      LKeyPair.Free;
    end;

    Result := LContext.GetClaims.Subject;
  finally
    LContext.Free;
  end;
end;
```

Notes on the flow:

- **`TJOSEContext` parses without verifying**, which is exactly what you need to read `kid` before
  you know the key. Everything read at that point is *untrusted*: use it only to select a key,
  never as data.
- Reusing the same context for `ProcessContext` avoids parsing the token twice.
- `SetVerificationKey` takes `TJOSEBytes`, so you pass `LKeyPair.PublicKey.Key` (the raw PEM /
  secret bytes), not the `TJWK` object.
- **Always constrain `SetExpectedAlgorithms`.** The builder's default list includes `None` and
  every supported algorithm; narrowing it to what your issuer actually signs with is what stops
  algorithm-substitution attacks.
- Step 3 is optional but cheap: it rejects a token that claims `HS256` while the JWKS entry says
  `RS256`.
- `LContext.GetClaims` is valid only inside the `try` block — the claims are owned by the context.
  Copy out what you need (as above) or do your work before freeing it.

---

## Error handling

Two exception families reach the caller, and the signature check is *not* the one you might expect:

| Failure | Exception |
|---|---|
| Malformed token, unsupported/unexpected `alg`, **invalid signature** | `EJOSEException` |
| Claim validation failures (`iss`, `aud`, `sub`, `exp`, `nbf`, `jti`, …) | `EInvalidJWTException` |
| Bad JWK/JWKS JSON, missing `kty`/`crv`, unsupported key type | `EJOSEJWKException` (a descendant of `EJOSEException`) |

```delphi
try
  Writeln('Valid token, subject: ', ValidateWithKeySet(ACompactToken, AKeySet));
except
  on E: EInvalidJWTException do
    Writeln('Token rejected: ', E.Message);
  on E: EJOSEException do
    Writeln('JOSE error: ', E.Message);
end;
```

`EInvalidJWTException.Message` contains the claims JSON followed by a `Validation errors:` section
listing every failed validator, so logging the message alone tells you exactly what was wrong.

A tampered token produces, for example:

```
JOSE error: JWS signature is invalid
```

---

## Memory ownership rules

| Call | Who frees the result |
|---|---|
| `TJSONWebKey.FromPEM` / `FromJSON` / `Create*` | **you** |
| `TJSONWebKeySet.FromJSON` / `Create` | **you** (freeing the set frees all its keys) |
| `TJSONWebKeySet.AddKey(AKey)` | the **set** takes ownership of `AKey` |
| `TJSONWebKeySet.FindByKid`, `Keys[i]` | the **set** — borrowed reference, don't free |
| `TJSONWebKey.ToKeyPair` | **you** (it's a fresh `TKeyPair`) |
| `TJOSE.Verify` / `DeserializeCompact` | **you** (may return `nil`) |
| `TJOSEContext.GetClaims` / `GetHeader` / `GetJOSEObject` | the **context** — borrowed references |

One more trap: `ToKeyPair` on a **public-only** RSA/EC key puts the public PEM in *both* halves of
the `TKeyPair` (and reports `KeyType = Symmetric`, because the two blobs are equal). That pair
verifies fine but cannot sign — check `IsPrivate` before trying to sign with a key that came out of
someone else's JWKS.

---

## Provider requirements

`FromPEM` / `ToPEM` (and therefore `ToKeyPair` for RSA/EC keys) go through the registered crypto
provider's optional `RSAKeyMaterial` / `ECKeyMaterial` capabilities:

| Provider stack | Unit | PEM import/export |
|---|---|---|
| `TJOSEDefaultProviders` (registered automatically) | `JOSE.Providers.Default` | yes — needs the OpenSSL 1.x DLLs |
| `TJOSETaurusTLSProviders` | `JOSE.Providers.TaurusTLS` | yes — OpenSSL 1.1.x/3.x/4.x |
| `TJOSECryptoLibProviders` | `JOSE.Providers.CryptoLib` | yes — pure Pascal, no DLLs |

```delphi
uses JOSE.Providers.CryptoLib;
...
TJOSECryptoLibProviders.Register;   // no OpenSSL DLL needed from here on
```

Everything that does **not** touch PEM — `CreateOct`, `CreateRSAPublic`, `FromJSON`, `ToJSON`,
`Thumbprint`, `TJSONWebKeySet` — is pure RTL and works on any platform, including the ones where
`RSA_SIGNING` is switched off in `Source\JOSE.inc` (there, the `FromPEM`/`ToPEM`/`ToKeyPair`/
`FromKeyPair` methods are compiled out entirely).

If a provider is registered without key-material support, `FromPEM`/`ToPEM` raise
`EJOSEProvidersNotRegistered`; ordinary signing and verification are unaffected.

### `ToPEM` output format is provider-dependent

All three stacks write a PEM that all three can read back, but they do not agree on *which*
encoding to write. If you hand the output to something outside this library — an external tool, a
config file, a remote system — it is worth knowing which you will get:

| `ToPEM` call | Default / TaurusTLS (OpenSSL) | CryptoLib |
|---|---|---|
| RSA, `ToPEM(True)` | `RSA PRIVATE KEY` (PKCS#1) | `RSA PRIVATE KEY` (PKCS#1) |
| RSA, `ToPEM(False)` | `RSA PUBLIC KEY` (PKCS#1) | **`PUBLIC KEY` (SPKI)** |
| EC, `ToPEM(True)` | `PRIVATE KEY` (PKCS#8) | **`EC PRIVATE KEY` (SEC1)** |
| EC, `ToPEM(False)` | `PUBLIC KEY` (SPKI) | `PUBLIC KEY` (SPKI) |

So the two that differ are the RSA public key and the EC private key. The difference is purely in
the container: the key material is identical either way, and `FromPEM` on any stack accepts every
one of these forms, so round trips and cross-provider exchange both work. The RSA public example
further up this page shows the OpenSSL stacks' `RSA PUBLIC KEY` output; under CryptoLib the same
call produces a `PUBLIC KEY` block.

If you need one specific encoding regardless of the registered provider, convert the PEM yourself
rather than relying on `ToPEM` — for instance `openssl rsa -RSAPublicKey_in -pubout` to go from
PKCS#1 to SPKI.

---

## Running the sample

```
msbuild Samples\JWKGuide\JWKGuide.dproj /p:Config=Debug /p:Platform=Win32
Samples\Exe\JWKGuide.exe
```

The executable defaults to the keys in `Tests\Keys`; pass another directory as the first parameter
to use your own `rsa-private.pem`. Being built on the default provider stack, it needs
`libeay32.dll`/`ssleay32.dll` next to the executable (the same pair used by `Tests\Exe`) — or
register `TJOSECryptoLibProviders` instead and drop the DLL requirement entirely.

The run ends with two deliberate outcomes, a valid token and a tampered one:

```
Valid token, subject: paolo.rossi
JOSE error: JWS signature is invalid
```
