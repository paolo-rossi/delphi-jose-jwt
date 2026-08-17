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
  public
    class function CheckCompactToken(const AValue: TJOSEBytes): Boolean;

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
    /// <summary>Verifies with a JSON Web Key, using its public half</summary>
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

    class function SHA256CompactToken(AKey: TJOSEBytes; AToken: TJWT): TJOSEBytes;
    class function SHA384CompactToken(AKey: TJOSEBytes; AToken: TJWT): TJOSEBytes;
    class function SHA284CompactToken(AKey: TJOSEBytes; AToken: TJWT): TJOSEBytes; deprecated 'Misspelled, use SHA384CompactToken';
    class function SHA512CompactToken(AKey: TJOSEBytes; AToken: TJWT): TJOSEBytes;
  end;

implementation

uses
  System.Types,
  System.StrUtils;

resourcestring
  // The compact-serialization messages now live in JOSE.Core.Base, next to the
  // record that decides when to use them
  SJOSEInvalidSignature = 'The JWS signature is invalid';
  SJOSEVerificationKeyRequired = 'A verification key is required to verify the token';
  SJOSEJWKSNoMatchingKey = 'No key in the key set matches the token header [kid=%s]';
  SJOSEJWKSCannotChooseKey = 'The token header carries no [kid] and the key set holds %d keys: cannot choose one';

{ TJOSE }

class function TJOSE.CheckCompactToken(const AValue: TJOSEBytes): Boolean;
begin
  Result := TJWS.CheckCompactToken(AValue);
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
