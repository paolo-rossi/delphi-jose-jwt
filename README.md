# Delphi JOSE and JWT Library

<br />

<p align="center">
  <a href="http://jwt.io/">
    <img src="https://user-images.githubusercontent.com/4686497/59972946-554a2180-9598-11e9-9842-8ab83cf3a97d.png" alt="Delphi JWT Library" width="250" />
  </a>
</p>

## What is Delphi JOSE and JWT Library

![Top language](https://img.shields.io/github/languages/top/paolo-rossi/delphi-jose-jwt)
[![GitHub license](https://img.shields.io/github/license/paolo-rossi/delphi-jose-jwt)](https://github.com/paolo-rossi/delphi-jose-jwt/blob/master/LICENSE)
[![GitHub issues](https://img.shields.io/github/issues/paolo-rossi/delphi-jose-jwt)](https://github.com/paolo-rossi/delphi-jose-jwt/issues)
[![GitHub PR](https://img.shields.io/github/issues-pr/paolo-rossi/delphi-jose-jwt)](https://github.com/paolo-rossi/delphi-jose-jwt/pulls)
[![GitHub release](https://img.shields.io/github/release/paolo-rossi/delphi-jose-jwt)](https://github.com/paolo-rossi/delphi-jose-jwt/release)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/paolo-rossi/delphi-jose-jwt)
![GitHub last commit](https://img.shields.io/github/last-commit/paolo-rossi/delphi-jose-jwt)
![GitHub contributors](https://img.shields.io/github/contributors-anon/paolo-rossi/delphi-jose-jwt)

[Delphi](https://www.embarcadero.com/products/delphi) implementation of JWT (JSON Web Token) and the JOSE (JSON Object Signing and Encryption) specification suite. This library supports the JWS (JWE support is planned) compact serializations with several JOSE algorithms, plus full [JWK (JSON Web Key)](#json-web-key-jwk-support) support and a [swappable crypto provider](#custom-crypto-providers-bring-your-own-crypto) backend (OpenSSL 1.x via Indy, OpenSSL 1.1.x/3.x/4.x via TaurusTLS, or pure-Pascal CryptoLib4Pascal).

![Image of Delphi-JOSE Demo](https://user-images.githubusercontent.com/4686497/103456073-1485a980-4cf3-11eb-8bac-295198ba508b.png)


## :books: Articles about using Delphi-JOSE

- [JWT authentication with Delphi. Part 1](https://blog.paolorossi.net/post/jwt-authentication-with-delphi-part-1/) - JWT and authentication technologies introduction (using Delphi)
- [JWT authentication with Delphi. Part 2](https://blog.paolorossi.net/post/jwt-authentication-with-delphi-part-2/) - Understanding the JSON Web Token
- [JWT authentication with Delphi. Part 3](https://blog.paolorossi.net/post/jwt-authentication-with-delphi-part-3/) - Using Delphi-JOSE-JWT to generate and verify JWT tokens
- [JWT authentication with Delphi. Part 4](https://blog.paolorossi.net/post/jwt-authentication-with-delphi-part-4/) - Using JWT consumer to validate JWT's claims

## :warning: Important: OpenSSL requirements

#### HMAC using SHA algorithm
Prior to Delphi 10 Seattle the the HMAC-SHA algorithm uses OpenSSL through the Indy library, so in order to generate the token you should have the OpenSSL DLLs in your server system.

In Delphi 10 Seattle or newer Delphi versions the HMAC algorithm is also in the System.Hash unit so OpenSSL is not needed.

#### HMAC using RSA or ECDSA algorithm
The HMAC-RSA(ECDSA) algorithm uses necessarily OpenSSL so if you plan to use these algorithms to sign your token you have to download and deploy OpenSSL (on the server).

#### Client-side considerations
Please keep in mind that the client doesn't have to generate or verify the token (using SHA or RSA) so on the client-side there's no need for the OpenSSL DLLs.

#### OpenSSL download
If you need the OpenSSL library on the server, you can download the package directly to the [Indy's GitHub project page](https://github.com/IndySockets/OpenSSL-Binaries) (keep in mind to always update to the latest version and to match you application's bitness)

## :satellite: Custom crypto providers (bring your own crypto)

Since [PR #95](https://github.com/paolo-rossi/delphi-jose-jwt/pull/95), every crypto and Base64 operation goes through a swappable provider registry, `TJOSEProviders` (`JOSE.Providers`), instead of calling OpenSSL directly. Three provider stacks ship with the library:

| Provider stack | Unit | Backing library | Notes |
| --------------- | ---- | ---------------- | ----- |
| `TJOSEDefaultProviders` (default) | `JOSE.Providers.Default` | OpenSSL 1.0.x/1.1.x (via Indy) | Registered automatically at startup. Needs the OpenSSL DLLs for RSA/ECDSA (see [OpenSSL requirements](#important-openssl-requirements) above). Pokes a few raw OpenSSL struct fields internally, so it does **not** work against OpenSSL 3.x/4.x (those structs are opaque) — use `TJOSETaurusTLSProviders` for that. Implements [JWK](#json-web-key-jwk-support) PEM import/export |
| `TJOSETaurusTLSProviders` | `JOSE.Providers.TaurusTLS` | OpenSSL 1.1.x/3.x/4.x, via the [TaurusTLS](https://github.com/JPeterMugaas/TaurusTLS) binding for Indy (vendored under `Libs\TaurusTLS`) | Only touches OpenSSL through accessor functions (`RSA_get0_key`/`RSA_set0_key`, `EC_KEY_get0_public_key`, `EC_POINT_get/set_affine_coordinates`, ...), so it's forward-compatible as OpenSSL's structs get more opaque. TaurusTLS itself already probes for `-4` (OpenSSL 4.x) DLLs before falling back to `-3`/`-1_1`/`-1`. Implements [JWK](#json-web-key-jwk-support) PEM import/export. Not part of the `.dpk` package `contains` list — add `Libs\TaurusTLS`'s runtime package and `JOSE.Providers.TaurusTLS.pas` to your project manually, plus OpenSSL 3.x/4.x binaries (see `Libs\TaurusTLS\OpenSSL\binaries\README.md` for where to get them). Exercised by its own test project, `Tests\JOSE.Tests.TaurusTLS.dproj` |
| `TJOSECryptoLibProviders` | `JOSE.Providers.CryptoLib` | pure-Pascal [CryptoLib4Pascal](https://github.com/Xor-el/CryptoLib4Pascal) | No native OpenSSL DLLs needed at all. Implements [JWK](#json-web-key-jwk-support) PEM import/export. Not part of the `.dpk` package `contains` list — add `JOSE.Providers.CryptoLib.pas` and a CryptoLib4Pascal dependency to your project manually if you want it. Exercised by its own test project, `Tests\JOSE.Tests.CryptoLib.dproj` (also needs `HashLib4Pascal` and `SimpleBaseLib4Pascal`, both vendored under `Libs\`) |

> :warning: **Unlike the default (OpenSSL/Indy) stack, `TJOSETaurusTLSProviders` and `TJOSECryptoLibProviders` are *not* built into the JOSE `.dpk` packages.** Using either one in your own project means adding its unit(s) and backing library to your project manually (see the table above). Same story for the test suite: `Tests\JOSE.Tests.TaurusTLS.dproj` and `Tests\JOSE.Tests.CryptoLib.dproj` are separate projects from `Tests\JOSE.Tests.dproj` precisely because each pulls in its own extra, non-`.dpk` dependencies — see [Running the tests](#test_tube-running-the-tests) below before trying to build them.

Switching to the TaurusTLS-backed stack (OpenSSL 3.x/4.x) or the CryptoLib4Pascal-backed stack (and back):

```delphi
uses
  JOSE.Providers,
  JOSE.Providers.TaurusTLS,
  JOSE.Providers.CryptoLib;

begin
  TJOSETaurusTLSProviders.Register; // OpenSSL 3.x/4.x capable, via TaurusTLS
  ...

  TJOSECryptoLibProviders.Register; // from here on, no OpenSSL DLL is needed for HS/RS/ES signing
  ...

  TJOSECryptoLibProviders.Unregister;
  TJOSEProviders.RegisterProvider;  // back to the OpenSSL 1.x-backed default
end;
```

To bring your own backend (a hardware security module, another crypto library, ...), implement whichever of the interfaces in `JOSE.Providers.Interfaces` you need and assign them directly — you don't have to replace the whole stack:

```delphi
TJOSEProviders.RSA := TMyHSMBackedRSAProvider.Create;
TJOSEProviders.ECDSA := TMyHSMBackedECDSAProvider.Create;
```

| Interface | Capability |
| --------- | ---------- |
| `IJOSEBase64Provider` | Base64 / Base64Url encode/decode |
| `IJOSEHmacProvider` | HMAC signing (HS256/384/512) |
| `IJOSESignerRSA` | RSA signing/verification (RS256/384/512) |
| `IJOSESignerECDSA` | ECDSA signing/verification (ES256/384/512/256K) |
| `IJOSECertificateProvider` | Public key extraction/verification from an X.509 certificate |
| `IJOSERSAKeyMaterialProvider` | Raw RSA key import/export to/from PEM ([JWK](#json-web-key-jwk-support) support) |
| `IJOSEECKeyMaterialProvider` | Raw EC key import/export to/from PEM ([JWK](#json-web-key-jwk-support) support) |

`RSAKeyMaterial`/`ECKeyMaterial` are optional — a provider stack doesn't need to implement them unless you call `TJSONWebKey.FromPEM`/`ToPEM`. Every stack that ships with the library implements both, but if you assign providers individually and leave these two unset, ordinary RSA/ECDSA signing is unaffected; it just means `FromPEM`/`ToPEM` will raise until you supply an implementation.

## :question: What is JOSE

[JOSE](https://tools.ietf.org/html/rfc7520) is a standard that provides a general approach to the signing and encryption of any content. JOSE consists of several RFC:

- [JWT (JSON Web Token)](https://tools.ietf.org/html/rfc7519) - describes representation of claims encoded in JSON
- [JWS (JSON Web Signature)](https://tools.ietf.org/html/rfc7515) - describes producing and handling signed messages
- [JWE (JSON Web Encryption)](https://tools.ietf.org/html/rfc7516) - describes producing and handling encrypted messages
- [JWA (JSON Web Algorithms)](https://tools.ietf.org/html/rfc7518) - describes cryptographic algorithms used in JOSE
- [JWK (JSON Web Key)](https://tools.ietf.org/html/rfc7517) - describes format and handling of cryptographic keys in JOSE

## :zap: General Features

#### Token serialization
- One method call to serialize a token

#### Token deserialization
- One method call to validate and deserialize a compact token

#### Token & Claims validation (Consumer)

| _Algorithms_ | _Supported_      | 
| -------------| -----------      |
|  `exp`       | ✔️               |
|  `iat`       | ✔️               |
|  `nbf`       | ✔️               |
|  `aud`       | ✔️               |
|  `iss`       | ✔️               |
|  `jti`       | ✔️               |
|  `typ`       | ✔️               |

#### Easy to use classes for compact token productiom
- Easy to use `TJOSEProducer` and `TJOSEProducerBuilder` (alias `TJOSEProcess`) classes to build a new compact token with many options

#### Easy to use classes for custom validation

- Easy to use `TJOSEConsumer` and `TJOSEConsumerBuilder` classes to validate token with a fine granularity
- Easy to write custom validators!

#### Signing algorithms

| _Algorithms_ | _Supported_      | 
| -------------| -----------      |
|  `None`      | ✔️ don't use it! 💀 |
|  `HS256`     | ✔️               |
|  `HS384`     | ✔️               |
|  `HS512`     | ✔️               |
|  `RS256`     | ✔️ updated! 🔥   |
|  `RS384`     | ✔️ updated! 🔥   |
|  `RS512`     | ✔️ updated! 🔥   |
|  `ES256`     | ✔️ new! 🌟      |
|  `ES384`     | ✔️ new! 🌟      |
|  `ES512`     | ✔️ new! 🌟      |
|  `ES256K`    | ✔️ new! 🌟      |

#### Security notes
- This library is not affected by the `None` algorithm vulnerability
- This library is not susceptible to the [recently discussed encryption vulnerability](https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/).

## :key: JSON Web Key (JWK) support

Full [RFC 7517](https://tools.ietf.org/html/rfc7517) JSON Web Key support, via `TJSONWebKey`/`TJSONWebKeySet` in `JOSE.Core.JWK`:

- `oct` (symmetric), `RSA` and `EC` (P-256 / P-384 / P-521 / secp256k1) key types
- JSON (de)serialization of the standard members (`kty`, `use`, `key_ops`, `alg`, `kid`, `x5u`/`x5c`/`x5t`/`x5t#S256`) plus the type-specific key material
- PEM import/export (`FromPEM`/`ToPEM`), for both public and private keys
- [RFC 7638](https://tools.ietf.org/html/rfc7638) JWK Thumbprint (`Thumbprint`)
- `TJSONWebKeySet` for JWKS documents (`AddKey`, `FindByKid`, JSON round-trip)
- A bridge (`ToKeyPair`/`FromKeyPair`) to the legacy `TJWK`/`TKeyPair` types, so a `TJSONWebKey` can be handed straight to `TJOSE.Sign`/`TJOSE.Verify`/`TJOSEProducer`

PEM import/export is backed by the [crypto provider](#custom-crypto-providers-bring-your-own-crypto) currently registered — every stack in the table above supports it, so `FromPEM`/`ToPEM` works with or without OpenSSL.

> :book: **[JWK Practical Guide](Docs/jwk-guide.md)** — reading a JWKS, extracting keys, signing with a JWK and validating an incoming token against a key set, memory ownership rules. Its snippets are the runnable `Samples\JWKGuide` console project.

#### Import a PEM key and sign a token with it

```delphi
uses
  System.IOUtils,
  JOSE.Core.JWK,
  JOSE.Core.JWT,
  JOSE.Core.JWA,
  JOSE.Core.Builder;

var
  LKey: TJSONWebKey;
  LKeyPair: TKeyPair;
  LToken: TJWT;
  LCompact: TJOSEBytes;
begin
  LKey := TJSONWebKey.FromPEM(TFile.ReadAllBytes('rsa-private.pem'));
  try
    // Use the JWK Thumbprint as a stable key id
    LKey.Kid := LKey.Thumbprint;

    // Bridge to the legacy key model and sign a token with it
    LKeyPair := LKey.ToKeyPair;
    try
      LToken := TJWT.Create;
      try
        LToken.Claims.Subject := 'Paolo Rossi';
        LCompact := TJOSE.SerializeCompact(LKeyPair.PrivateKey, TJOSEAlgorithmId.RS256, LToken);
        memoCompact.Lines.Add(LCompact);
      finally
        LToken.Free;
      end;
    finally
      LKeyPair.Free;
    end;
  finally
    LKey.Free;
  end;
end;
```

#### Build a symmetric key and a JWKS document

```delphi
var
  LKey: TJSONWebKey;
  LSet: TJSONWebKeySet;
begin
  LKey := TJSONWebKey.CreateOct('my_very_long_and_safe_secret_key');
  LKey.Kid := 'hmac-key-1'; // set members you need before AddKey - see note below

  LSet := TJSONWebKeySet.Create;
  try
    LSet.AddKey(LKey); // the set now owns LKey
    memoJWKS.Lines.Add(LSet.ToJSON);
  finally
    LSet.Free; // also frees LKey
  end;
end;
```

> **Note:** `TJSONWebKeySet.AddKey` snapshots the key's JSON representation at the moment it's added. Set properties like `Kid` on the `TJSONWebKey` *before* calling `AddKey`, not after.

## Projects using Delphi JOSE and JWT

- The [**WiRL RESTful Library**](https://github.com/delphi-blocks/WiRL) for Delphi
- [**TMS XData**](https://www.tmssoftware.com/site/xdata.asp) and [**TMS Sparkle**](https://www.tmssoftware.com/site/sparkle.asp). Read the [blog post](https://www.tmssoftware.com/site/blog.asp?post=342) by Wagner R. Landgraf (he is also a contributor of this project)

## :wrench: Todo

##### Features
- JWE support (there is partial implementation in [this PR](https://github.com/paolo-rossi/delphi-jose-jwt/pull/84))
- More crypto providers on top of the [provider abstraction](#custom-crypto-providers-bring-your-own-crypto) (e.g. TMS Cryptography Pack) — OpenSSL and [CryptoLib4Pascal](https://github.com/Xor-el/CryptoLib4Pascal) are supported today

##### Code
- More unit tests
- More examples

## :cookie: Prerequisite
This library has been tested with **Delphi 13 Florence**, **Delphi 12 Athens**, **Delphi 11 Alexandria**, but with some work it should compile with **DXE6 and higher** but I have not tried or tested this, if you succeed in this task I will be happy to create a branch of your work!

#### Libraries/Units dependencies
This library has no required external dependencies when using the default (OpenSSL-backed) provider stack.

Delphi units used:
- System.JSON (DXE6+) (available on earlier Delphi versions as Data.DBXJSON)
- System.Rtti (D2010+)
- System.Generics.Collections (D2009+)
- System.NetEncoding (DXE7+)
- Indy units: IdHMAC, IdHMACSHA1, IdSSLOpenSSL, IdHash

Optional, only if you [switch to the CryptoLib4Pascal provider stack](#custom-crypto-providers-bring-your-own-crypto):
- [CryptoLib4Pascal](https://github.com/Xor-el/CryptoLib4Pascal) — not included in the `.dpk` package, add it (and `JOSE.Providers.CryptoLib.pas`) to your project yourself if you want it

#### Indy notes
- Please use always the latest version [from GitHub](https://github.com/IndySockets/Indy)

## :test_tube: Running the tests

The DUnitX-based test suite is split across three projects, one per crypto stack:

| Project | Covers | Extra setup |
| ------- | ------ | ------------ |
| `Tests\JOSE.Tests.dproj` | Core JOSE/JWT/JWK/JWS + the default OpenSSL 1.x provider stack | None |
| `Tests\JOSE.Tests.TaurusTLS.dproj` | `TJOSETaurusTLSProviders` (OpenSSL 1.1.x/3.x/4.x) | Needs `Libs\TaurusTLS` (vendored) and OpenSSL 3.x/4.x DLLs discoverable at runtime |
| `Tests\JOSE.Tests.CryptoLib.dproj` | `TJOSECryptoLibProviders` (pure-Pascal) | Needs `Libs\CryptoLib4Pascal`, `Libs\HashLib4Pascal` and `Libs\SimpleBaseLib4Pascal` (vendored); run `Libs\build-cryptolib-deps.ps1` once beforehand to precompile them into `Libs\_build` (their combined source tree is too deep for a single Delphi unit search path) |

Each builds to its own console exe under `Tests\Exe`. From a Delphi command prompt (`rsvars.bat` run, or `msbuild` on `PATH`):

```
msbuild "Tests\JOSE.Tests.dproj" /p:Config=Debug /p:Platform=Win32
Tests\Exe\JOSE.Tests.exe
```

...and likewise for the other two `.dproj` files.

## :floppy_disk: Installation

### Manual installation
Simply add the source path "Source/Common" and Source/JOSE" to your Delphi project path and.. you are good to go!

### Boss package manager

Using the [`boss install`](https://github.com/HashLoad/boss) command:

``` sh
$ boss install github.com/paolo-rossi/delphi-jose-jwt
```

## :scroll: Quick Code Examples

### Creating a token
To create a token, simply create an instance of the `TJWT` class and set the properties (claims).

#### Using TJOSE utility class
The easiest way to build a JWT token (compact representation) is to use the `IJOSEProducer` interface:

```delphi
uses
  JOSE.Producer;

var
  LResult: string;
begin
  LResult := TJOSEProcess.New
    .SetIssuer('Delphi JOSE Library')
    .SetIssuedAt(Now)
    .SetExpiration(Now + 1)
    .SetAlgorithm(LAlg)
    .SetKey(TJOSEAlgorithmId.HS256)
    .Build
    .GetCompactToken
  ;

  memoCompact.Lines.Add(LResult);
end;
```

#### Using TJOSE utility class
Another way to serialize, deserialize, verify a token is to use the `TJOSE`utility class:

```delphi
uses
  JOSE.Core.JWT,
  JOSE.Core.Builder;

var
  LToken: TJWT;
  LCompactToken: string;
begin
  LToken := TJWT.Create;
  try
    // Token claims
    LToken.Claims.Issuer := 'WiRL REST Library';
    LToken.Claims.Subject := 'Paolo Rossi';
    LToken.Claims.Expiration := Now + 1;

    // Signing and Compact format creation
    LCompactToken := TJOSE.SHA256CompactToken('my_very_long_and_safe_secret_key', LToken);
    mmoCompact.Lines.Add(LCompactToken);
  finally
    LToken.Free;
  end;
```

#### Using TJWT, TJWS and TJWK classes
Using the `TJWT`, `TJWS` and `TJWK` classes you have more control over the creation of the final compact token.

```delphi
var
  LToken: TJWT;
  LSigner: TJWS;
  LKey: TJWK;
  LAlg: TJOSEAlgorithmId;
begin
  LToken := TJWT.Create;
  try
    // Set your claims
    LToken.Claims.Subject := 'Paolo Rossi';
    LToken.Claims.Issuer := 'Delphi JOSE Library';
    LToken.Claims.IssuedAt := Now;
    LToken.Claims.Expiration := Now + 1;

    // Choose the signing algorithm
    case cbbAlgorithm.ItemIndex of
      0: LAlg := TJOSEAlgorithmId.HS256;
      1: LAlg := TJOSEAlgorithmId.HS384;
      2: LAlg := TJOSEAlgorithmId.HS512;
    else LAlg := TJOSEAlgorithmId.HS256;
    end;

    // Create your key from any text or TBytes
    LKey := TJWK.Create(edtSecret.Text);

    try
      // Create the signer
      LSigner := TJWS.Create(LToken);
      try
        // With this option you can have keys < algorithm length
        LSigner.SkipKeyValidation := True;

        // Sign the token!
        LSigner.Sign(LKey, LAlg);

        memoCompact.Lines.Add('Header: ' + LSigner.Header);
        memoCompact.Lines.Add('Payload: ' + LSigner.Payload);
        memoCompact.Lines.Add('Signature: ' + LSigner.Signature);
        memoCompact.Lines.Add('Compact Token: ' + LSigner.CompactToken);
      finally
        LSigner.Free;
      end;
    finally
      LKey.Free;
    end;  
  finally
    LToken.Free;
  end;

```
## Unpack and verify a token's signature

Unpacking and verifying tokens is simple.

#### Using TJOSE utility class

You have to pass the key and the token compact format to the `TJOSE.Verify` class function

```delphi
var
  LKey: TJWK;
  LToken: TJWT;
begin
  // Create the key from a text or TBytes
  LKey := TJWK.Create('my_very_long_and_safe_secret_key');

  // Unpack and verify the token!
  LToken := TJOSE.Verify(LKey, FCompactToken);

  if Assigned(LToken) then
  begin
    try
      if LToken.Verified then
        mmoJSON.Lines.Add('Token signature is verified')
      else
        mmoJSON.Lines.Add('Token signature is not verified')
    finally
      LToken.Free;
    end;
  end;

end;
```

### Unpacking and token validation

Using the new class `TJOSEConsumer` it's very easy to validate the token's claims. The `TJOSEConsumer` object is built with the `TJOSEConsumerBuilder` utility class using the fluent interface.

```delphi
var
  LConsumer: IJOSEConsumer;
begin
  LConsumer := TJOSEConsumerBuilder.NewConsumer
    .SetClaimsClass(TJWTClaims)

    // JWS-related validation
    .SetVerificationKey(edtConsumerSecret.Text)
    .SetSkipVerificationKeyValidation
    .SetDisableRequireSignature

    // string-based claims validation
    .SetExpectedSubject('paolo-rossi')
    .SetExpectedAudience(True, ['Paolo'])

    // Time-related claims validation
    .SetRequireIssuedAt
    .SetRequireExpirationTime
    .SetEvaluationTime(IncSecond(FNow, 26))
    .SetAllowedClockSkew(20, TJOSETimeUnit.Seconds)
    .SetMaxFutureValidity(20, TJOSETimeUnit.Minutes)

    // Build the consumer object
    .Build();

  try
    // Process the token with your rules!
    LConsumer.Process(Compact);
  except
    // (optionally) log the errors
    on E: Exception do
      memoLog.Lines.Add(E.Message);
  end;
```

<hr />
<div style="text-align:right">Paolo Rossi</div>
