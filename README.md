# Delphi JOSE and JWT Library

<br />

<a href="http://jwt.io/">![Browse on jwt.io](http://paolo-rossi.github.io/delphi-jose-jwt/images/jwt-badge.svg "Browse on jwt.io")</a>

<hr />

[Delphi](http://www.embarcadero.com/products/delphi) implementation of JWT (JSON Web Token) and the JOSE (JSON Object Signing and Encryption) specification suite. This library supports the JWS (JWE is support planned) compact serializations with several JOSE algorithms.

![Image of Delphi-JOSE Demo](http://paolo-rossi.github.io/delphi-jose-jwt/images/jose-delphi.png)

## Important: OpenSSL requirements

#### HMAC using SHA algorithm
Prior to Delphi 10 Seattle the the HMAC-SHA algorithm uses OpenSSL through the Indy library, so in order to generate the token you should have the OpenSSL DLLs in your server system.

In Delphi 10 Seattle or newer Delphi versions the HMAC algorithm is also is the System.Hash unit so OpenSSL is not needed.

#### HMAC using RSA algorithm
The HMAC-RSA algorithm uses necessarily OpenSSL so if you plan to use this algorithm to sign your token you have to download and deploy OpenSSL (on the server).

#### Client-side considerations
Please keep in mind that the client doesn't have to generate or verify the token (using SHA or RSA) so on the client-side there's no need for the OpenSSL DLLs.

#### OpenSSL download
If you need the OpenSSL library on the server, you can download the package at the [fulgan website](https://indy.fulgan.com/SSL/) (keep in mind to always update to the latest version and to match you application's bitness)

## What is JOSE

[JOSE](https://tools.ietf.org/html/rfc7520) is a standard that provides a general approach to signing and encryption of any content. JOSE consists of several RFC:

- [JWT (JSON Web Token)](https://tools.ietf.org/html/rfc7519) - describes representation of claims encoded in JSON
- [JWS (JSON Web Signature)](https://tools.ietf.org/html/rfc7515) - describes producing and handling signed messages
- [JWE (JSON Web Encryption)](https://tools.ietf.org/html/rfc7516) - describes producing and handling encrypted messages
- [JWA (JSON Web Algorithms)](https://tools.ietf.org/html/rfc7518) - describes cryptographic algorithms used in JOSE
- [JWK (JSON Web Key)](https://tools.ietf.org/html/rfc7517) - describes format and handling of cryptographic keys in JOSE

## General Features

#### Token serialization
- One method call to serialize a token

#### Token deserialization
- One method call to validate and deserialize a compact token

#### Claims validation
- `exp`, `iat`, `nbf`, `aud`, `iss`, `sub` claims validatation: supported
- Easy to use `TJOSEConsumer` and `TJOSEConsumerBuilder` classes to validate token with a fine granularity
- Easy to write custom validators!

#### Signing algorithms
- `NONE algorithm`: supported (but discouraged)
- `HS256`, `HS384`, `HS512 algorithms`: supported
- `RS256`, `RS384`, `RS512 algorithms`: supported (thanks to [SirAlex](https://github.com/SirAlex))
- `ES256`, `ES384`, `ES512` algorithms - not (yet) supported

#### Security notes
- This library is not affected by the `None` algorithm vulnerability
- This library is not susceptible to the [recently discussed encryption vulnerability](https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/).

## Projects using Delphi JOSE and JWT

- The [**WiRL RESTful Library**](https://github.com/delphi-blocks/WiRL) for Delphi
- [**TMS XData**](https://www.tmssoftware.com/site/xdata.asp) and [**TMS Sparkle**](https://www.tmssoftware.com/site/sparkle.asp). Read the [blog post](https://www.tmssoftware.com/site/blog.asp?post=342) by Wagner R. Landgraf (he is also a contributor of this project)

## Todo

##### Features
- JWE support
- Support of other crypto libraries (TMS Cryptography Pack, etc...)

##### Code
- Unit Tests
- More examples


## Prerequisite
This library has been tested with **Delphi 10.2 Tokyo**, **Delphi 10.1 Berlin** and **Delphi XE6** but with a minimum amount of work it should compile with **D2010 and higher**

#### Libraries/Units dependencies
This library has no dependencies on external libraries/units.

Delphi units used:
- System.JSON (DXE6+) (available on earlier Delphi versions as Data.DBXJSON)
- System.Rtti (D2010+)
- System.Generics.Collections (D2009+)
- System.NetEncoding (DXE7+)
- Indy units: IdHMAC, IdHMACSHA1, IdSSLOpenSSL, IdHash

#### Indy notes
- Please use always the latest version [from svn](http://www.indyproject.org/Sockets/Download/svn.EN.aspx)

## Installation
Simply add the source path "Source/Common" and Source/JOSE" to your Delphi project path and.. you are good to go!

## Code Examples

### Creating a token
To create a token, simply create an instance of the `TJWT` class and set the properties (claims).

#### Using TJOSE utility class
The easiest way to serialize, deserialize, verify a token is to use the `TJOSE`utility class:

```delphi
var
  LToken: TJWT;
begin
  LToken := TJWT.Create;
  try
    // Token claims
    LToken.Claims.IssuedAt := Now;
    LToken.Claims.Expiration := Now + 1;
    LToken.Claims.Issuer := 'WiRL REST Library';

    // Signing and Compact format creation
    mmoCompact.Lines.Add(
      TJOSE.SHA256CompactToken('my_very_long_and_safe_secret_key', LToken)
    );

    // Header and Claims JSON representation
    mmoJSON.Lines.Add(LToken.Header.JSON.ToJSON);
    mmoJSON.Lines.Add(LToken.Claims.JSON.ToJSON);
  finally
    LToken.Free;
  end;
```

#### Using TJWT, TJWS and TJWK classes
Using the `TJWT`, `TJWS` and `TJWK` classes you can control more setting in the creation of the final compact token.

```delphi
var
  LToken: TJWT;
  LSigner: TJWS;
  LKey: TJWK;
  LAlg: TJOSEAlgorithmId;
begin
  LToken := TJWT.Create;
  try
    LToken.Claims.Issuer := 'Delphi JOSE Library';
    LToken.Claims.IssuedAt := Now;
    LToken.Claims.Expiration := Now + 1;

    // Signing algorithm
    case cbbAlgorithm.ItemIndex of
      0: LAlg := TJOSEAlgorithmId.HS256;
      1: LAlg := TJOSEAlgorithmId.HS384;
      2: LAlg := TJOSEAlgorithmId.HS512;
    else LAlg := TJOSEAlgorithmId.HS256;
    end;

    LSigner := TJWS.Create(LToken);
    LKey := TJWK.Create(edtSecret.Text);
    try
      // With this option you can have keys < algorithm length
      LSigner.SkipKeyValidation := True;
      LSigner.Sign(LKey, LAlg);

      memoJSON.Lines.Add('Header: ' + TJSONUtils.ToJSON(LToken.Header.JSON));
      memoJSON.Lines.Add('Claims: ' + TJSONUtils.ToJSON(LToken.Claims.JSON));

      memoCompact.Lines.Add('Header: ' + LSigner.Header);
      memoCompact.Lines.Add('Payload: ' + LSigner.Payload);
      memoCompact.Lines.Add('Signature: ' + LSigner.Signature);
      memoCompact.Lines.Add('Compact Token: ' + LSigner.CompactToken);
    finally
      LKey.Free;
      LSigner.Free;
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
  LKey := TJWK.Create('my_very_long_and_safe_secret_key');
  // Unpack and verify the token
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

Using the new class `TJOSEConsumer` it's very easy to validate the token's claims. The `TJOSEConsumer` object id built using the `TJOSEConsumerBuilder` utility class using the fluent interface.

```delphi
var
  LConsumer: TJOSEConsumer;
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
    LConsumer.Process(Compact);
  except
    on E: Exception do
      memoLog.Lines.Add(E.Message);
  end;
  LConsumer.Free;
```

<hr />
<div style="text-align:right">Paolo Rossi</div>
