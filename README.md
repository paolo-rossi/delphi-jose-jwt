# Delphi JOSE and JWT Library

<br />

<p align="center">
  <a href="http://jwt.io/">
    <img src="https://user-images.githubusercontent.com/4686497/59972946-554a2180-9598-11e9-9842-8ab83cf3a97d.png" alt="Delphi JWT Library" width="250" />
  </a>
</p>

[Delphi](https://www.embarcadero.com/products/delphi) implementation of JWT (JSON Web Token) and the JOSE (JSON Object Signing and Encryption) specification suite. This library supports the JWS (JWE support is planned) compact serializations with several JOSE algorithms.

![Image of Delphi-JOSE Demo](https://user-images.githubusercontent.com/4686497/103456073-1485a980-4cf3-11eb-8bac-295198ba508b.png)


## :books: Articles about using Delphi-JOSE

- [JWT authentication with Delphi. Part 1](http://blog.paolorossi.net/2017/04/27/jwt-authentication-with-delphi) - JWT and authentication technologies introduction (using Delphi)
- [JWT authentication with Delphi. Part 2](http://blog.paolorossi.net/2017/05/17/jwt-authentication-with-delphi-part-2) - Understanding the JSON Web Token
- [JWT authentication with Delphi. Part 3](http://blog.paolorossi.net/2018/08/27/jwt-authentication-with-delphi-part-3) - Using Delphi-JOSE-JWT to generate and verify JWT tokens
- [JWT authentication with Delphi. Part 4](http://blog.paolorossi.net/2019/07/15/jwt-authentication-with-delphi-part-4) - Using JWT consumer to validate JWT's claims

## :warning: Important: OpenSSL requirements

#### HMAC using SHA algorithm
Prior to Delphi 10 Seattle the the HMAC-SHA algorithm uses OpenSSL through the Indy library, so in order to generate the token you should have the OpenSSL DLLs in your server system.

In Delphi 10 Seattle or newer Delphi versions the HMAC algorithm is also is the System.Hash unit so OpenSSL is not needed.

#### HMAC using RSA or ECDSA algorithm
The HMAC-RSA(ECDSA) algorithm uses necessarily OpenSSL so if you plan to use these algorithms to sign your token you have to download and deploy OpenSSL (on the server).

#### Client-side considerations
Please keep in mind that the client doesn't have to generate or verify the token (using SHA or RSA) so on the client-side there's no need for the OpenSSL DLLs.

#### OpenSSL download
If you need the OpenSSL library on the server, you can download the package directly to the [Indy's GitHub project page](https://github.com/IndySockets/OpenSSL-Binaries) (keep in mind to always update to the latest version and to match you application's bitness)

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

#### Easy to use classes for custom validation

- Easy to use `TJOSEConsumer` and `TJOSEConsumerBuilder` classes to validate token with a fine granularity
- Easy to write custom validators!

#### Signing algorithms

| _Algorithms_ | _Supported_      | 
| -------------| -----------      |
|  `None`      | ✔️ don't use! 💀 |
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

## Projects using Delphi JOSE and JWT

- The [**WiRL RESTful Library**](https://github.com/delphi-blocks/WiRL) for Delphi
- [**TMS XData**](https://www.tmssoftware.com/site/xdata.asp) and [**TMS Sparkle**](https://www.tmssoftware.com/site/sparkle.asp). Read the [blog post](https://www.tmssoftware.com/site/blog.asp?post=342) by Wagner R. Landgraf (he is also a contributor of this project)

## :wrench: Todo

##### Features
- JWE support
- Support of other crypto libraries (TMS Cryptography Pack, etc...)

##### Code
- More unit tests
- More examples

## :cookie: Prerequisite
This library has been tested with **Delphi 10.4 Sydney**, **Delphi 10.3 Rio**, **Delphi 10.2 Tokyo**, **Delphi 10.1 Berlin**, and **Delphi 10.0 Seattle** but with some work it should compile with **DXE6 and higher** but I have not tried or tested this, if you succeed in this task I will be happy to create a branch of your work!

#### Libraries/Units dependencies
This library has no dependencies on external libraries/units.

Delphi units used:
- System.JSON (DXE6+) (available on earlier Delphi versions as Data.DBXJSON)
- System.Rtti (D2010+)
- System.Generics.Collections (D2009+)
- System.NetEncoding (DXE7+)
- Indy units: IdHMAC, IdHMACSHA1, IdSSLOpenSSL, IdHash

#### Indy notes
- Please use always the latest version [from GitHub](https://github.com/IndySockets/Indy)

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
The easiest way to serialize, deserialize, verify a token is to use the `TJOSE`utility class:

```delphi
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
