{******************************************************************************}
{                                                                              }
{  Delphi JOSE-JWT Library                                                     }
{  Copyright (c) 2015 Paolo Rossi                                              }
{  https://github.com/paolo-rossi/delphi-jose-jwt                              }
{                                                                              }
{  Licensed under the MIT license                                              }
{                                                                              }
{******************************************************************************}
unit JOSE.Core.Builder;

{$I ..\JOSE.inc}

interface

uses
  System.SysUtils,
  JOSE.Types.Bytes,
  JOSE.Core.Base,
  JOSE.Core.Parts,
  JOSE.Core.JWA,
  JOSE.Core.JWK,
  JOSE.Core.JWT,
  JOSE.Core.JWS,
  JOSE.Core.JWE;

type
  /// <summary>
  ///   Utility class to encode and decode a JWT
  /// </summary>
  TJOSE = class
  private
    class function DeserializeVerify(AKey: TJWK; const ACompactToken: TJOSEBytes;
      AVerify, ARaiseOnInvalidSignature: Boolean; AClaimsClass: TJWTClaimsClass): TJWT;
    /// <summary>A string member of the token's header, '' when it is absent or cannot be read</summary>
    class function HeaderMember(const ACompactToken: TJOSEBytes; const AName: string): string;
    /// <summary>Decrypts a nested JWT and returns the inner JWS, unverified</summary>
    class function DecryptNested(ADecryptKey: TJWK; const ACompactToken: TJOSEBytes): TJOSEBytes;
  public
    /// <summary>True when AValue has the shape of a JWS compact serialization:
    ///   three parts, strict base64url, a JSON header and a JSON payload</summary>
    class function CheckCompactToken(const AValue: TJOSEBytes): Boolean;
    /// <summary>True when AValue has the shape of a JWE compact serialization:
    ///   five parts, strict base64url, a JSON header. Says nothing about
    ///   whether it decrypts</summary>
    class function CheckJWECompactToken(const AValue: TJOSEBytes): Boolean;

    /// <summary>
    ///   Signs AToken and returns the *signature*. To get the compact token use
    ///   SerializeCompact, which is the real counterpart of Verify
    /// </summary>
    class function Sign(AKey: TJWK; AAlg: TJOSEAlgorithmId; AToken: TJWT): TJOSEBytes;

    /// <summary>
    ///   Parses and verifies a compact token. Returns nil when the token cannot
    ///   be read, and a TJWT whose Verified property tells whether the signature
    ///   checked out - a token with a *broken* signature still comes back, so
    ///   the Verified property must be tested. Use VerifyOrRaise to have an
    ///   invalid signature raise instead.
    /// </summary>
    /// <remarks>
    ///   The signing algorithm is taken from the token's own header: this class
    ///   has no algorithm allowlist. Use TJOSEConsumer.SetExpectedAlgorithms
    ///   when the token comes from outside.
    /// </remarks>
    class function Verify(AKey: TJWK; const ACompactToken: TJOSEBytes; AClaimsClass: TJWTClaimsClass = nil): TJWT; overload;
    class function Verify(AKey: TJOSEBytes; const ACompactToken: TJOSEBytes; AClaimsClass: TJWTClaimsClass = nil): TJWT; overload;
    /// <summary>
    ///   Verifies with a JSON Web Key, using its public half. Raises
    ///   EJOSEJWKException when the key's own [use], [key_ops] or [alg] rule
    ///   out verifying this token (see TJSONWebKey.CheckPermits): that is a
    ///   wrong key, not an unreadable token
    /// </summary>
    class function Verify(AKey: TJSONWebKey; const ACompactToken: TJOSEBytes; AClaimsClass: TJWTClaimsClass = nil): TJWT; overload;
    /// <summary>
    ///   Verifies with the key of AKeySet that the token's header points at.
    ///   See SelectKey for how that key is chosen
    /// </summary>
    class function Verify(AKeySet: TJSONWebKeySet; const ACompactToken: TJOSEBytes; AClaimsClass: TJWTClaimsClass = nil): TJWT; overload;

    /// <summary>
    ///   Same as Verify, but raises EJOSEException when the signature does not
    ///   verify (and lets the parsing errors through instead of returning nil),
    ///   so a token that comes back is always a token that checked out
    /// </summary>
    class function VerifyOrRaise(AKey: TJWK; const ACompactToken: TJOSEBytes; AClaimsClass: TJWTClaimsClass = nil): TJWT; overload;
    class function VerifyOrRaise(AKey: TJOSEBytes; const ACompactToken: TJOSEBytes; AClaimsClass: TJWTClaimsClass = nil): TJWT; overload;
    class function VerifyOrRaise(AKey: TJSONWebKey; const ACompactToken: TJOSEBytes; AClaimsClass: TJWTClaimsClass = nil): TJWT; overload;
    class function VerifyOrRaise(AKeySet: TJSONWebKeySet; const ACompactToken: TJOSEBytes; AClaimsClass: TJWTClaimsClass = nil): TJWT; overload;

    /// <summary>
    ///   The key of AKeySet that ACompactToken's header points at: the one
    ///   whose [kid] matches, provided its [alg] does not contradict the
    ///   header's. A token with no [kid] resolves only when the set holds
    ///   exactly one key. Raises EJOSEException when no single key can be
    ///   chosen - a token that names no usable key is a configuration problem,
    ///   not an unreadable token, so it is reported rather than returned as nil
    /// </summary>
    /// <remarks>
    ///   The header is read without verifying anything: [kid] and [alg] are
    ///   hints for choosing a key, never a reason to trust the token. The
    ///   signature check that follows is what decides.
    /// </remarks>
    class function SelectKey(AKeySet: TJSONWebKeySet; const ACompactToken: TJOSEBytes): TJSONWebKey;

    /// <summary>
    ///   Serializes and signs AToken. The key is validated for the chosen
    ///   algorithm unless ASkipValidation is passed as True
    /// </summary>
    class function SerializeCompact(AKey: TJWK; AAlg: TJOSEAlgorithmId; AToken: TJWT; ASkipValidation: Boolean): TJOSEBytes; overload;
    class function SerializeCompact(AKey: TJWK; AAlg: TJOSEAlgorithmId; AToken: TJWT): TJOSEBytes; overload;
    class function SerializeCompact(AKey: TJOSEBytes; AAlg: TJOSEAlgorithmId; AToken: TJWT): TJOSEBytes; overload;

    class function DeserializeCompact(AKey: TJWK; const ACompactToken: TJOSEBytes; AClaimsClass: TJWTClaimsClass = nil): TJWT; overload;
    class function DeserializeCompact(AKey: TJOSEBytes; const ACompactToken: TJOSEBytes; AClaimsClass: TJWTClaimsClass = nil): TJWT; overload;

    class function DeserializeOnly(const ACompactToken: TJOSEBytes; AClaimsClass: TJWTClaimsClass = nil): TJWT; overload;

    /// <summary>
    ///   Encrypts AToken's claims into a JWE compact serialization (RFC 7516).
    ///   AKey is the shared secret for "dir" (exactly as long as the content
    ///   encryption key AEnc needs), the RSA public key PEM (or an X.509
    ///   certificate) for RSA-OAEP/RSA-OAEP-256. AToken's header (typ, kid,
    ///   ...) becomes the JWE header, plus "alg" and "enc"
    /// </summary>
    /// <remarks>
    ///   The claims are encrypted, not signed. To have them signed as well,
    ///   which is the usual way to encrypt a JWT, use SignAndEncrypt
    /// </remarks>
    class function Encrypt(AKey: TJWK; AToken: TJWT; AAlg: TJOSEAlgorithmId;
      AEnc: TJOSEEncryptionAlgorithmId): TJOSEBytes; overload;
    class function Encrypt(const AKey: TJOSEBytes; AToken: TJWT; AAlg: TJOSEAlgorithmId;
      AEnc: TJOSEEncryptionAlgorithmId): TJOSEBytes; overload;
    /// <summary>
    ///   Same as Encrypt, with a JSON Web Key. Its public half is used: the
    ///   secret for "oct", the public key for RSA. The key's [use], [key_ops]
    ///   and [alg] must allow it (TJSONWebKey.CheckPermits)
    /// </summary>
    class function Encrypt(AKey: TJSONWebKey; AToken: TJWT; AAlg: TJOSEAlgorithmId;
      AEnc: TJOSEEncryptionAlgorithmId): TJOSEBytes; overload;

    /// <summary>
    ///   Decrypts a JWE compact serialization whose payload is a claims set,
    ///   and returns the token. Raises EJOSEException when the token cannot be
    ///   read or decrypted, and for a nested JWT (use DecryptAndVerify, which
    ///   also checks the inner signature)
    /// </summary>
    /// <remarks>
    ///   Like Verify, there is no algorithm allowlist: any registered "alg"
    ///   and "enc" is accepted. For tokens that come from outside, use
    ///   TJOSEConsumer with SetExpectedKeyManagementAlgorithms and
    ///   SetExpectedEncryptionAlgorithms
    /// </remarks>
    class function Decrypt(AKey: TJWK; const ACompactToken: TJOSEBytes;
      AClaimsClass: TJWTClaimsClass = nil): TJWT; overload;
    class function Decrypt(const AKey: TJOSEBytes; const ACompactToken: TJOSEBytes;
      AClaimsClass: TJWTClaimsClass = nil): TJWT; overload;
    /// <summary>
    ///   Same as Decrypt, with a JSON Web Key. Its private half is used: the
    ///   secret for "oct", the private key for RSA. A public-only key raises,
    ///   and so does one whose [use], [key_ops] or [alg] rule out decrypting
    ///   this token (TJSONWebKey.CheckPermits)
    /// </summary>
    class function Decrypt(AKey: TJSONWebKey; const ACompactToken: TJOSEBytes;
      AClaimsClass: TJWTClaimsClass = nil): TJWT; overload;

    /// <summary>
    ///   Signs AToken (a JWS, as SerializeCompact does), then encrypts the JWS
    ///   into a JWE with "cty":"JWT": a nested JWT (RFC 7519 par. 5.2)
    /// </summary>
    /// <remarks>
    ///   AOuterHeader, when given, supplies the JWE header members of the outer
    ///   token (the encryption key's kid, "zip":"DEF", custom ones); it is
    ///   copied, never modified, and its "cty" is overridden to "JWT". With a
    ///   nil header the outer token carries only "typ" and "cty"
    /// </remarks>
    class function SignAndEncrypt(ASignKey: TJWK; ASignAlg: TJOSEAlgorithmId;
      AEncryptKey: TJWK; AAlg: TJOSEAlgorithmId; AEnc: TJOSEEncryptionAlgorithmId;
      AToken: TJWT; AOuterHeader: TJWTHeader = nil): TJOSEBytes; overload;
    /// <summary>
    ///   Same as SignAndEncrypt, with both keys as raw material
    /// </summary>
    class function SignAndEncrypt(const ASignKey: TJOSEBytes; ASignAlg: TJOSEAlgorithmId;
      const AEncryptKey: TJOSEBytes; AAlg: TJOSEAlgorithmId; AEnc: TJOSEEncryptionAlgorithmId;
      AToken: TJWT; AOuterHeader: TJWTHeader = nil): TJOSEBytes; overload;
    /// <summary>
    ///   Same as SignAndEncrypt, with JSON Web Keys: the signing key's private
    ///   half and the encryption key's public half are used. Each key's [use],
    ///   [key_ops] and [alg] must allow its part (TJSONWebKey.CheckPermits)
    /// </summary>
    class function SignAndEncrypt(ASignKey: TJSONWebKey; ASignAlg: TJOSEAlgorithmId;
      AEncryptKey: TJSONWebKey; AAlg: TJOSEAlgorithmId; AEnc: TJOSEEncryptionAlgorithmId;
      AToken: TJWT; AOuterHeader: TJWTHeader = nil): TJOSEBytes; overload;

    /// <summary>
    ///   Decrypts a nested JWT with ADecryptKey and verifies the inner JWS
    ///   with AVerifyKey. Returns the inner token; raises EJOSEException when
    ///   either step fails, or when the JWE payload is not a JWS
    /// </summary>
    /// <remarks>
    ///   No allowlists here either: see Decrypt
    /// </remarks>
    class function DecryptAndVerify(ADecryptKey, AVerifyKey: TJWK; const ACompactToken: TJOSEBytes;
      AClaimsClass: TJWTClaimsClass = nil): TJWT; overload;
    /// <summary>
    ///   Same as DecryptAndVerify, with both keys as raw material
    /// </summary>
    class function DecryptAndVerify(const ADecryptKey, AVerifyKey: TJOSEBytes;
      const ACompactToken: TJOSEBytes; AClaimsClass: TJWTClaimsClass = nil): TJWT; overload;
    /// <summary>
    ///   Same as DecryptAndVerify, with JSON Web Keys: the decryption key's
    ///   private half and the verification key's public half are used. Each
    ///   key's [use], [key_ops] and [alg] must allow its part, the verification
    ///   key's checked against the inner token (TJSONWebKey.CheckPermits)
    /// </summary>
    class function DecryptAndVerify(ADecryptKey, AVerifyKey: TJSONWebKey;
      const ACompactToken: TJOSEBytes; AClaimsClass: TJWTClaimsClass = nil): TJWT; overload;

    class function SHA256CompactToken(AKey: TJOSEBytes; AToken: TJWT): TJOSEBytes;
    class function SHA384CompactToken(AKey: TJOSEBytes; AToken: TJWT): TJOSEBytes;
    class function SHA284CompactToken(AKey: TJOSEBytes; AToken: TJWT): TJOSEBytes; deprecated 'Misspelled, use SHA384CompactToken';
    class function SHA512CompactToken(AKey: TJOSEBytes; AToken: TJWT): TJOSEBytes;
  end;

implementation

uses
  System.Types,
  System.StrUtils,
  JOSE.Types.JSON;

resourcestring
  // The compact-serialization messages now live in JOSE.Core.Base, next to the
  // record that decides when to use them
  SJOSEInvalidSignature = 'The JWS signature is invalid';
  SJOSEVerificationKeyRequired = 'A verification key is required to verify the token';
  SJOSEJWKSNoMatchingKey = 'No key in the key set matches the token header [kid=%s]';
  SJOSEJWKSCannotChooseKey = 'The token header carries no [kid] and the key set holds %d keys: cannot choose one';
  SJOSENotAJWE = 'The token is not a JWE: a JWE Compact Serialization has 5 parts';
  SJOSEDecryptionKeyRequired = 'A decryption key is required to decrypt the token';
  SJOSEEncryptionKeyRequired = 'An encryption key is required to encrypt the token';
  SJOSESigningKeyRequired = 'A signing key is required to sign the token';
  SJOSENestedUseDecryptAndVerify = 'The JWE carries a nested JWT ("cty":"JWT"): use DecryptAndVerify, ' +
    'which also verifies the inner signature';
  SJOSENotNested = 'The JWE does not carry a nested JWT ("cty":"JWT")';
  SJOSENestedNotJWS = 'The payload of a nested JWT ("cty":"JWT") must be a JWS: nested encryption is not supported';

const
  NESTED_JWT_CONTENT_TYPE = 'JWT';

// Parses ACompactToken into a TJWE bound to AToken and decrypts it with AKey.
// The caller owns both; the TJWE is returned so that the caller can read the
// header and the payload
function DecryptJWE(AKey: TJWK; const ACompactToken: TJOSEBytes; AToken: TJWT): TJWE;
begin
  if not Assigned(AKey) then
    raise EJOSEException.Create(SJOSEDecryptionKeyRequired);

  if TJOSECompactSerialization.Split(ACompactToken).Kind <> TJOSECompactKind.JWE then
    raise EJOSEException.Create(SJOSENotAJWE);

  Result := TJWE.Create(AToken);
  try
    Result.CompactToken := ACompactToken;
    Result.DecryptPayload(AKey);
  except
    Result.Free;
    raise;
  end;
end;

{ TJOSE }

class function TJOSE.Encrypt(AKey: TJWK; AToken: TJWT; AAlg: TJOSEAlgorithmId;
  AEnc: TJOSEEncryptionAlgorithmId): TJOSEBytes;
var
  LJWE: TJWE;
begin
  if not Assigned(AKey) then
    raise EJOSEException.Create(SJOSEEncryptionKeyRequired);

  LJWE := TJWE.Create(AToken);
  try
    Result := LJWE.Encrypt(AKey, AAlg, AEnc);
  finally
    LJWE.Free;
  end;
end;

class function TJOSE.Encrypt(const AKey: TJOSEBytes; AToken: TJWT; AAlg: TJOSEAlgorithmId;
  AEnc: TJOSEEncryptionAlgorithmId): TJOSEBytes;
var
  LKey: TJWK;
begin
  LKey := TJWK.Create(AKey);
  try
    Result := Encrypt(LKey, AToken, AAlg, AEnc);
  finally
    LKey.Free;
  end;
end;

class function TJOSE.Encrypt(AKey: TJSONWebKey; AToken: TJWT; AAlg: TJOSEAlgorithmId; AEnc: TJOSEEncryptionAlgorithmId): TJOSEBytes;
var
  LKeyPair: TKeyPair;
begin
  if not Assigned(AKey) then
    raise EJOSEException.Create(SJOSEEncryptionKeyRequired);

  AKey.CheckPermits([TJOSEKeyOperation.Encrypt, TJOSEKeyOperation.WrapKey], AAlg.AsString, AEnc.AsString);

  // PublicKey carries the encryption material for every key type: the secret
  // for oct, the public PEM for RSA and EC
  LKeyPair := AKey.ToKeyPair;
  try
    Result := Encrypt(LKeyPair.PublicKey, AToken, AAlg, AEnc);
  finally
    LKeyPair.Free;
  end;
end;

class function TJOSE.Decrypt(AKey: TJWK; const ACompactToken: TJOSEBytes;
  AClaimsClass: TJWTClaimsClass): TJWT;
var
  LJWE: TJWE;
begin
  Result := TJWT.Create(AClaimsClass);
  try
    LJWE := DecryptJWE(AKey, ACompactToken, Result);
    try
      // A nested JWT is a signed token: handing back its claims unverified
      // would make the signature optional by accident
      if LJWE.Header.IsNestedJWT then
        raise EJOSEException.Create(SJOSENestedUseDecryptAndVerify);

      // The payload is the claims object: parse it in place, no base64 round
      // trip through the URLEncoded property
      Result.Claims.SetJSONFromBytes(LJWE.Payload);
    finally
      LJWE.Free;
    end;
  except
    Result.Free;
    raise;
  end;
end;

class function TJOSE.Decrypt(const AKey: TJOSEBytes; const ACompactToken: TJOSEBytes;
  AClaimsClass: TJWTClaimsClass): TJWT;
var
  LKey: TJWK;
begin
  LKey := TJWK.Create(AKey);
  try
    Result := Decrypt(LKey, ACompactToken, AClaimsClass);
  finally
    LKey.Free;
  end;
end;

class function TJOSE.Decrypt(AKey: TJSONWebKey; const ACompactToken: TJOSEBytes; AClaimsClass: TJWTClaimsClass): TJWT;
var
  LKeyPair: TKeyPair;
begin
  if not Assigned(AKey) then
    raise EJOSEException.Create(SJOSEDecryptionKeyRequired);

  AKey.CheckPermits([TJOSEKeyOperation.Decrypt, TJOSEKeyOperation.UnwrapKey],
    HeaderMember(ACompactToken, 'alg'), HeaderMember(ACompactToken, 'enc'));

  // PrivateKey carries the decryption material: the secret for oct, the
  // private PEM for RSA. A public-only key leaves it empty.
  LKeyPair := AKey.ToKeyPair;
  try
    if LKeyPair.PrivateKey.Key.IsEmpty then
      raise EJOSEException.Create(SJOSEDecryptionKeyRequired);

    Result := Decrypt(LKeyPair.PrivateKey, ACompactToken, AClaimsClass);
  finally
    LKeyPair.Free;
  end;
end;

class function TJOSE.SignAndEncrypt(ASignKey: TJWK; ASignAlg: TJOSEAlgorithmId;
  AEncryptKey: TJWK; AAlg: TJOSEAlgorithmId; AEnc: TJOSEEncryptionAlgorithmId;
  AToken: TJWT; AOuterHeader: TJWTHeader): TJOSEBytes;
var
  LInner: TJOSEBytes;
  LOuter: TJWT;
  LJWE: TJWE;
begin
  if not Assigned(ASignKey) then
    raise EJOSEException.Create(SJOSESigningKeyRequired);

  if not Assigned(AEncryptKey) then
    raise EJOSEException.Create(SJOSEEncryptionKeyRequired);

  LInner := SerializeCompact(ASignKey, ASignAlg, AToken);

  // The outer token contributes its header: the caller's members when given
  // (the encryption key's kid, "zip", custom ones), plus the "cty" that marks
  // the payload as a nested JWT (RFC 7519 par. 5.2)
  LOuter := TJWT.Create;
  try
    if Assigned(AOuterHeader) then
      LOuter.Header.Assign(AOuterHeader);

    LOuter.Header.SetHeaderParam(THeaderNames.CONTENT_TYPE, NESTED_JWT_CONTENT_TYPE);
    LJWE := TJWE.Create(LOuter);
    try
      Result := LJWE.EncryptPayload(AEncryptKey, AAlg, AEnc, LInner);
    finally
      LJWE.Free;
    end;
  finally
    LOuter.Free;
  end;
end;

class function TJOSE.SignAndEncrypt(const ASignKey: TJOSEBytes; ASignAlg: TJOSEAlgorithmId;
  const AEncryptKey: TJOSEBytes; AAlg: TJOSEAlgorithmId; AEnc: TJOSEEncryptionAlgorithmId;
  AToken: TJWT; AOuterHeader: TJWTHeader): TJOSEBytes;
var
  LSignKey, LEncryptKey: TJWK;
begin
  LSignKey := TJWK.Create(ASignKey);
  LEncryptKey := TJWK.Create(AEncryptKey);
  try
    Result := SignAndEncrypt(LSignKey, ASignAlg, LEncryptKey, AAlg, AEnc, AToken, AOuterHeader);
  finally
    LEncryptKey.Free;
    LSignKey.Free;
  end;
end;

class function TJOSE.SignAndEncrypt(ASignKey: TJSONWebKey; ASignAlg: TJOSEAlgorithmId;
  AEncryptKey: TJSONWebKey; AAlg: TJOSEAlgorithmId; AEnc: TJOSEEncryptionAlgorithmId;
  AToken: TJWT; AOuterHeader: TJWTHeader): TJOSEBytes;
var
  LSignPair, LEncryptPair: TKeyPair;
begin
  if not Assigned(ASignKey) then
    raise EJOSEException.Create(SJOSESigningKeyRequired);
  if not Assigned(AEncryptKey) then
    raise EJOSEException.Create(SJOSEEncryptionKeyRequired);

  ASignKey.CheckPermits([TJOSEKeyOperation.Sign], ASignAlg.AsString);
  AEncryptKey.CheckPermits([TJOSEKeyOperation.Encrypt, TJOSEKeyOperation.WrapKey], AAlg.AsString, AEnc.AsString);

  LSignPair := ASignKey.ToKeyPair;
  try
    // PrivateKey is the signing material: the secret for oct, the private PEM
    // for RSA and EC. A public-only key leaves it empty.
    if LSignPair.PrivateKey.Key.IsEmpty then
      raise EJOSEException.Create(SJOSESigningKeyRequired);

    LEncryptPair := AEncryptKey.ToKeyPair;
    try
      Result := SignAndEncrypt(LSignPair.PrivateKey, ASignAlg,
        LEncryptPair.PublicKey, AAlg, AEnc, AToken, AOuterHeader);
    finally
      LEncryptPair.Free;
    end;
  finally
    LSignPair.Free;
  end;
end;

class function TJOSE.DecryptAndVerify(ADecryptKey, AVerifyKey: TJWK; const ACompactToken: TJOSEBytes;
  AClaimsClass: TJWTClaimsClass): TJWT;
begin
  Result := VerifyOrRaise(AVerifyKey, DecryptNested(ADecryptKey, ACompactToken), AClaimsClass);
end;

class function TJOSE.HeaderMember(const ACompactToken: TJOSEBytes; const AName: string): string;
var
  LCompact: TJOSECompactSerialization;
  LHeader: TJWTHeader;
begin
  Result := '';
  LCompact := TJOSECompactSerialization.Split(ACompactToken);
  if LCompact.Count = 0 then
    Exit;

  // Only the header: a JWS payload need not be read for this, and a JWE one
  // cannot be. An unreadable header is left for the parser to report
  LHeader := TJWTHeader.Create;
  try
    try
      LHeader.URLEncoded := LCompact[0];
      Result := TJSONUtils.GetJSONValueAsString(AName, LHeader.JSON);
    except
      on EJOSEException do
        Result := '';
    end;
  finally
    LHeader.Free;
  end;
end;

class function TJOSE.DecryptNested(ADecryptKey: TJWK; const ACompactToken: TJOSEBytes): TJOSEBytes;
var
  LOuter: TJWT;
  LJWE: TJWE;
  LInner: TJOSEBytes;
begin
  LOuter := TJWT.Create;
  try
    LJWE := DecryptJWE(ADecryptKey, ACompactToken, LOuter);
    try
      if not LJWE.Header.IsNestedJWT then
        raise EJOSEException.Create(SJOSENotNested);
      LInner := LJWE.Payload;
    finally
      LJWE.Free;
    end;
  finally
    LOuter.Free;
  end;

  // One level only: an inner JWE is refused rather than decrypted in turn
  if TJOSECompactSerialization.Split(LInner).Kind <> TJOSECompactKind.JWS then
    raise EJOSEException.Create(SJOSENestedNotJWS);

  Result := LInner;
end;

class function TJOSE.DecryptAndVerify(const ADecryptKey, AVerifyKey: TJOSEBytes;
  const ACompactToken: TJOSEBytes; AClaimsClass: TJWTClaimsClass): TJWT;
var
  LDecryptKey, LVerifyKey: TJWK;
begin
  LDecryptKey := TJWK.Create(ADecryptKey);
  LVerifyKey := TJWK.Create(AVerifyKey);
  try
    Result := DecryptAndVerify(LDecryptKey, LVerifyKey, ACompactToken, AClaimsClass);
  finally
    LVerifyKey.Free;
    LDecryptKey.Free;
  end;
end;

class function TJOSE.DecryptAndVerify(ADecryptKey, AVerifyKey: TJSONWebKey;
  const ACompactToken: TJOSEBytes; AClaimsClass: TJWTClaimsClass): TJWT;
var
  LDecryptPair: TKeyPair;
  LInner: TJOSEBytes;
begin
  if not Assigned(ADecryptKey) then
    raise EJOSEException.Create(SJOSEDecryptionKeyRequired);
  if not Assigned(AVerifyKey) then
    raise EJOSEException.Create(SJOSEVerificationKeyRequired);

  ADecryptKey.CheckPermits([TJOSEKeyOperation.Decrypt, TJOSEKeyOperation.UnwrapKey],
    HeaderMember(ACompactToken, 'alg'), HeaderMember(ACompactToken, 'enc'));

  LDecryptPair := ADecryptKey.ToKeyPair;
  try
    if LDecryptPair.PrivateKey.Key.IsEmpty then
      raise EJOSEException.Create(SJOSEDecryptionKeyRequired);

    LInner := DecryptNested(LDecryptPair.PrivateKey, ACompactToken);
  finally
    LDecryptPair.Free;
  end;

  // The JWK overload, so the verification key is checked against the inner
  // token's own "alg"
  Result := VerifyOrRaise(AVerifyKey, LInner, AClaimsClass);
end;

class function TJOSE.CheckCompactToken(const AValue: TJOSEBytes): Boolean;
begin
  Result := TJWS.CheckCompactToken(AValue);
end;

class function TJOSE.CheckJWECompactToken(const AValue: TJOSEBytes): Boolean;
begin
  Result := TJWE.CheckCompactToken(AValue);
end;

class function TJOSE.DeserializeCompact(AKey: TJOSEBytes; const ACompactToken: TJOSEBytes;
  AClaimsClass: TJWTClaimsClass): TJWT;
var
  LKey: TJWK;
begin
  LKey := TJWK.Create(AKey);
  try
    Result := DeserializeVerify(LKey, ACompactToken, True, False, AClaimsClass);
  finally
    LKey.Free;
  end;
end;

class function TJOSE.DeserializeOnly(const ACompactToken: TJOSEBytes; AClaimsClass: TJWTClaimsClass): TJWT;
begin
  Result := DeserializeVerify(nil, ACompactToken, False, False, AClaimsClass);
end;

class function TJOSE.DeserializeCompact(AKey: TJWK; const ACompactToken: TJOSEBytes;
  AClaimsClass: TJWTClaimsClass): TJWT;
begin
  Result := DeserializeVerify(AKey, ACompactToken, True, False, AClaimsClass);
end;

class function TJOSE.DeserializeVerify(AKey: TJWK; const ACompactToken: TJOSEBytes;
    AVerify, ARaiseOnInvalidSignature: Boolean; AClaimsClass: TJWTClaimsClass): TJWT;
var
  LSigner: TJWS;
  LVerified: Boolean;
begin
  Result := nil;

  // Raises for a JWE, for a wrong part count and for a part that is not
  // base64url: the same rules TJOSEContext and TJWS apply
  TJOSECompactSerialization.Split(ACompactToken).CheckIsJWS;

  // Without this, SetKey below would dereference nil and the failure would
  // be reported as an unreadable token
  if AVerify and not Assigned(AKey) then
    raise EJOSEException.Create(SJOSEVerificationKeyRequired);

  LVerified := False;
  Result := TJWT.Create(AClaimsClass);
  try
    LSigner := TJWS.Create(Result);
    try
      LSigner.CompactToken := ACompactToken;
      if AVerify then
      begin
        LSigner.SetKey(AKey);
        LVerified := LSigner.VerifySignature;
      end;
    finally
      LSigner.Free;
    end;
  except
    on E: Exception do
    begin
      FreeAndNil(Result);
      // "nil means the token could not be read" is the documented contract
      // of Verify/DeserializeCompact, but only for JOSE-level errors: any
      // other exception is a fault and must not be turned into a nil
      if (E is EJOSEException) and not ARaiseOnInvalidSignature then
        Exit(nil);
      raise;
    end;
  end;

  if AVerify and not LVerified and ARaiseOnInvalidSignature then
  begin
    FreeAndNil(Result);
    raise EJOSEException.Create(SJOSEInvalidSignature);
  end;
end;

class function TJOSE.SerializeCompact(AKey: TJWK; AAlg: TJOSEAlgorithmId; AToken: TJWT): TJOSEBytes;
begin
  // The key IS validated here: skipping it would silently allow an under-length
  // HMAC secret (RFC 7518 par. 3.2) or a PEM used as a shared secret. Callers
  // that really want to opt out have the 4-argument overload
  Result := SerializeCompact(AKey, AAlg, AToken, False);
end;

class function TJOSE.Sign(AKey: TJWK; AAlg: TJOSEAlgorithmId; AToken: TJWT): TJOSEBytes;
var
  LSigner: TJWS;
begin
  if not Assigned(AKey) then
    raise EJOSEException.Create(SJOSESigningKeyRequired);

  LSigner := TJWS.Create(AToken);
  try
    Result := LSigner.Sign(AKey, AAlg);
  finally
    LSigner.Free;
  end;
end;

class function TJOSE.SerializeCompact(AKey: TJOSEBytes; AAlg: TJOSEAlgorithmId; AToken: TJWT): TJOSEBytes;
var
  LKey: TJWK;
begin
  LKey := TJWK.Create(AKey);
  try
    Result := SerializeCompact(LKey, AAlg, AToken, False);
  finally
    LKey.Free;
  end;
end;

class function TJOSE.SerializeCompact(AKey: TJWK; AAlg: TJOSEAlgorithmId; AToken: TJWT;
  ASkipValidation: Boolean): TJOSEBytes;
var
  LSigner: TJWS;
begin
  LSigner := TJWS.Create(AToken);
  try
    LSigner.SkipKeyValidation := ASkipValidation;
    LSigner.Sign(AKey, AAlg);
    Result := LSigner.CompactToken;
  finally
    LSigner.Free;
  end;
end;

class function TJOSE.SHA256CompactToken(AKey: TJOSEBytes; AToken: TJWT): TJOSEBytes;
begin
  Result := SerializeCompact(AKey, TJOSEAlgorithmId.HS256, AToken);
end;

class function TJOSE.SHA384CompactToken(AKey: TJOSEBytes; AToken: TJWT): TJOSEBytes;
begin
  Result := SerializeCompact(AKey, TJOSEAlgorithmId.HS384, AToken);
end;

class function TJOSE.SHA284CompactToken(AKey: TJOSEBytes; AToken: TJWT): TJOSEBytes;
begin
  Result := SHA384CompactToken(AKey, AToken);
end;

class function TJOSE.SHA512CompactToken(AKey: TJOSEBytes; AToken: TJWT): TJOSEBytes;
begin
  Result := SerializeCompact(AKey, TJOSEAlgorithmId.HS512, AToken);
end;

class function TJOSE.Verify(AKey: TJWK; const ACompactToken: TJOSEBytes; AClaimsClass: TJWTClaimsClass): TJWT;
begin
  Result := DeserializeVerify(AKey, ACompactToken, True, False, AClaimsClass);
end;

class function TJOSE.Verify(AKey: TJOSEBytes; const ACompactToken: TJOSEBytes;
  AClaimsClass: TJWTClaimsClass): TJWT;
var
  LKey: TJWK;
begin
  LKey := TJWK.Create(AKey);
  try
    Result := Verify(LKey, ACompactToken, AClaimsClass);
  finally
    LKey.Free;
  end;
end;

class function TJOSE.VerifyOrRaise(AKey: TJWK; const ACompactToken: TJOSEBytes;
  AClaimsClass: TJWTClaimsClass): TJWT;
begin
  Result := DeserializeVerify(AKey, ACompactToken, True, True, AClaimsClass);
end;

class function TJOSE.SelectKey(AKeySet: TJSONWebKeySet; const ACompactToken: TJOSEBytes): TJSONWebKey;
var
  LToken: TJWT;
  LKid: string;
  LAlg: TJOSEAlgorithmId;
begin
  if not Assigned(AKeySet) then
    raise EJOSEException.Create(SJOSEVerificationKeyRequired);

  LToken := DeserializeOnly(ACompactToken);
  if not Assigned(LToken) then
    raise EJOSEException.Create(SJOSEMalformedCompactSerialization);
  try
    LKid := LToken.Header.KeyID;
    LAlg.AsString := LToken.Header.Algorithm;
  finally
    LToken.Free;
  end;

  if LKid <> '' then
    // Rejects a key whose own [alg] contradicts the header's; Unknown on
    // either side means unconstrained
    Result := AKeySet.FindByKidAndAlg(LKid, LAlg)
  else if AKeySet.Keys.Count = 1 then
    Result := AKeySet.Keys[0]
  else
    raise EJOSEException.CreateFmt(SJOSEJWKSCannotChooseKey, [AKeySet.Keys.Count]);

  if not Assigned(Result) then
    raise EJOSEException.CreateFmt(SJOSEJWKSNoMatchingKey, [LKid]);
end;

class function TJOSE.Verify(AKey: TJSONWebKey; const ACompactToken: TJOSEBytes;
  AClaimsClass: TJWTClaimsClass): TJWT;
var
  LKeyPair: TKeyPair;
begin
  if not Assigned(AKey) then
    raise EJOSEException.Create(SJOSEVerificationKeyRequired);

  AKey.CheckPermits([TJOSEKeyOperation.Verify], HeaderMember(ACompactToken, 'alg'));

  // PublicKey carries the verification material for every key type: the secret
  // for oct, the public PEM for RSA and EC
  LKeyPair := AKey.ToKeyPair;
  try
    Result := Verify(LKeyPair.PublicKey, ACompactToken, AClaimsClass);
  finally
    LKeyPair.Free;
  end;
end;

class function TJOSE.VerifyOrRaise(AKey: TJSONWebKey; const ACompactToken: TJOSEBytes;
  AClaimsClass: TJWTClaimsClass): TJWT;
var
  LKeyPair: TKeyPair;
begin
  if not Assigned(AKey) then
    raise EJOSEException.Create(SJOSEVerificationKeyRequired);

  AKey.CheckPermits([TJOSEKeyOperation.Verify], HeaderMember(ACompactToken, 'alg'));

  LKeyPair := AKey.ToKeyPair;
  try
    Result := VerifyOrRaise(LKeyPair.PublicKey, ACompactToken, AClaimsClass);
  finally
    LKeyPair.Free;
  end;
end;

class function TJOSE.Verify(AKeySet: TJSONWebKeySet; const ACompactToken: TJOSEBytes;
  AClaimsClass: TJWTClaimsClass): TJWT;
begin
  Result := Verify(SelectKey(AKeySet, ACompactToken), ACompactToken, AClaimsClass);
end;

class function TJOSE.VerifyOrRaise(AKeySet: TJSONWebKeySet; const ACompactToken: TJOSEBytes;
  AClaimsClass: TJWTClaimsClass): TJWT;
begin
  Result := VerifyOrRaise(SelectKey(AKeySet, ACompactToken), ACompactToken, AClaimsClass);
end;

class function TJOSE.VerifyOrRaise(AKey: TJOSEBytes; const ACompactToken: TJOSEBytes;
  AClaimsClass: TJWTClaimsClass): TJWT;
var
  LKey: TJWK;
begin
  LKey := TJWK.Create(AKey);
  try
    Result := VerifyOrRaise(LKey, ACompactToken, AClaimsClass);
  finally
    LKey.Free;
  end;
end;

end.
