# Delphi JOSE and JWT Library
[Delphi](http://www.embarcadero.com/products/delphi) implementation of JWT (JSON Web Token) and the JOSE (JSON Object Signing and Encryption) specification suite. This library supports the JWS (JWE is support planned) compact serializations with several JOSE algorithms.

## What is JOSE

[JOSE](https://tools.ietf.org/html/rfc7520) is a standard that provides a general approach to signing and encryption of any content. JOSE consists of several RFC:

- [JWT (JSON Web Token)](https://tools.ietf.org/html/rfc7519) - describes representation of claims encoded in JSON
- [JWS (JSON Web Signature)](https://tools.ietf.org/html/rfc7515) - describes producing and handling signed messages
- [JWE (JSON Web Encryption)](https://tools.ietf.org/html/rfc7516) - describes producing and handling encrypted messages
- [JWA (JSON Web Algorithms)](https://tools.ietf.org/html/rfc7518) - describes cryptographic algorithms used in JOSE
- [JWK (JSON Web Key)](https://tools.ietf.org/html/rfc7517) - describes format and handling of cryptographic keys in JOSE

## Features

- Token serialization
- Token deserialization
- Claims validation
    - `exp`, `iat`, `nbf` claims validatation - supported
    - `aud`, `iss`, `sub` claims validatation - planned
- Sign algorithms
    - `NONE`, `HS256`, `HS384`, `HS512` algorithms - supported
- Encryption algorithms
    - `RS256`, `RS384`, `RS512` algorithms - planned
    - `ES256`, `ES384`, `ES512`, `PS256`, `PS384`, `PS512` algorithms - not (yet) planned
	- Not affected by the`None`algorithm vulnerability

This library is not susceptible to the [recently discussed encryption vulnerability](https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/).

## Todo

##### Features
- Token validation: `aud`, `iss`, `sub`
- RSA algorithms implementation
- Creation of `TJWTClaims` derived classes

##### Code
- D2010+ porting
- Unit Tests 
- More examples


## Prerequisite
This library is built with **Delphi XE8**, but with a minumum amount of work it will compile with **D2010 and higher**
#### Libraries/Units dependencies
This library has no dependencies on external libraries/units.

Delphi units used:
- System.JSON (DXE6+) (available on earlier Delphi versions as Data.DBXJSON)
- System.Rtti (D2010+)
- System.Generics.Collections (D2009+)
- System.NetEncoding (DXE7+)
- Indy units: IdHMAC, IdHMACSHA1, IdSSLOpenSSL, IdHash (use last versions from svn)

## Installation
Simply add the source path "Source/Common" and Source/JOSE" to your Delphi project path and.. you are done!

## Code Examples

### Creating a token
To create a token simple create an instance of the `TJWT` class and set the properties (claims).
The easiest way to serialize, deserialize, verify a token is to use the `TJOSE`utility class.

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
    mmoCompact.Lines.Add(TJOSE.SHA256CompactToken('secret', LToken));

    // Header and Claims JSON representation
    mmoJSON.Lines.Add(LToken.Header.JSON.ToJSON);
    mmoJSON.Lines.Add(LToken.Claims.JSON.ToJSON);
  finally
    LToken.Free;
  end;
```	


### Unpack and Verify a token

Unpacking and verifying tokens is simple.  You have to pass the key (secret) and the token compact format to the `TJOSE.Verify` class function

```delphi
var
  LKey: TJWK;
  LToken: TJWT;
begin
  LKey := TJWK.Create('secret');
  // Unpack and verify the token
  LToken := TJOSE.Verify(LKey, 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJXaVJMIn0.w3BAZ_GwfQYY6dkS8xKUNZ_sOnkDUMELxBN0mKKNhJ4');

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