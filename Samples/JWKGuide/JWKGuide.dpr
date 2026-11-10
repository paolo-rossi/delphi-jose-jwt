{******************************************************************************}
{                                                                              }
{  Delphi JOSE-JWT Library                                                     }
{  Copyright (c) 2015 Paolo Rossi                                              }
{  https://github.com/paolo-rossi/delphi-jose-jwt                              }
{                                                                              }
{  Licensed under the MIT license                                              }
{                                                                              }
{******************************************************************************}

/// <summary>
///   Runnable companion to Docs\JWK-Guide.md: every snippet of the guide, in the
///   order it appears there, plus an end-to-end run that signs a token with a JWK
///   and validates it on the other side using only a published JWKS document.
/// </summary>
/// <remarks>
///   Uses the test keys in Tests\Keys (pass a different directory as the first
///   command line parameter). The default provider stack needs the OpenSSL 1.x
///   DLLs next to the executable - see Tests\Exe.
/// </remarks>
program JWKGuide;

{$APPTYPE CONSOLE}

uses
  System.SysUtils,
  System.DateUtils,
  System.IOUtils,
  JOSE.Types.Bytes,
  JOSE.Core.Base,
  JOSE.Core.JWA,
  JOSE.Core.JWK,
  JOSE.Core.JWT,
  JOSE.Core.JWS,
  JOSE.Core.Builder,
  JOSE.Context,
  JOSE.Consumer,
  JOSE.Consumer.Validators,
  JOSE.Encoding.Base64;

// ---------------------------------------------------------------- snippet 1
procedure Snippet_LoadPEM;
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

// ---------------------------------------------------------------- snippet 2
procedure Snippet_CreateKeys;
var
  LOct, LRSA, LEC: TJSONWebKey;
begin
  LOct := TJSONWebKey.CreateOct('my_very_long_and_safe_secret_key');
  LOct.Kid := 'hmac-2026-01';
  LOct.Use := TJOSEKeyUse.Signature;
  LOct.Alg := TJOSEAlgorithmId.HS256;
  LOct.KeyOps := [TJOSEKeyOperation.Sign, TJOSEKeyOperation.Verify];
  LOct.Free;

  LRSA := TJSONWebKey.CreateRSAPublic(TBase64.URLDecode('0vx7ago'), TBase64.URLDecode('AQAB'));
  LRSA.Free;

  LEC := TJSONWebKey.CreateECPublic(TJOSEEllipticCurve.P256,
    TBase64.URLDecode('f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU'),
    TBase64.URLDecode('x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0'));
  LEC.Free;
end;

// ---------------------------------------------------------------- snippet 3
function ExtractPublicKey(AKey: TJSONWebKey): TJSONWebKey;
begin
  case AKey.Kty of
    TJOSEKeyType.RSA:
      Result := TJSONWebKey.CreateRSAPublic(AKey.N, AKey.E);
    TJOSEKeyType.EC:
      Result := TJSONWebKey.CreateECPublic(AKey.Crv, AKey.X, AKey.Y);
  else
    raise EJOSEJWKException.Create('Only RSA and EC keys have a public half');
  end;

  Result.Kid := AKey.Kid;
  Result.Use := AKey.Use;
  Result.Alg := AKey.Alg;
end;

// ---------------------------------------------------------------- snippet 4
procedure Snippet_ReadKeySet(const AJWKS, AKid: string);
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

    LKey := LSet.FindByKid(AKid);
    if not Assigned(LKey) then
      raise EJOSEJWKException.CreateFmt('Key [%s] not found in the key set', [AKid]);

    LPublicPEM := LKey.ToPEM(False);
    Writeln(LPublicPEM.AsString);
  finally
    LSet.Free;
  end;
end;

// ---------------------------------------------------------------- snippet 5
procedure Snippet_BuildKeySet;
var
  LSet: TJSONWebKeySet;
  LPrivate, LPublic: TJSONWebKey;
begin
  LSet := TJSONWebKeySet.Create;
  try
    LPrivate := TJSONWebKey.FromPEM(TFile.ReadAllBytes('rsa-private.pem'));
    try
      LPublic := ExtractPublicKey(LPrivate);
      LPublic.Kid := LPrivate.Thumbprint;
      LPublic.Use := TJOSEKeyUse.Signature;
      LPublic.Alg := TJOSEAlgorithmId.RS256;
      LSet.AddKey(LPublic);
    finally
      LPrivate.Free;
    end;

    Writeln(LSet.ToJSON);
  finally
    LSet.Free;
  end;
end;

// ---------------------------------------------------------------- snippet 6
function Snippet_SignWithJWK(AKey: TJSONWebKey): TJOSEBytes;
var
  LKeyPair: TKeyPair;
  LToken: TJWT;
begin
  LKeyPair := AKey.ToKeyPair;
  try
    LToken := TJWT.Create;
    try
      LToken.Header.KeyID := AKey.Kid;
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
    LKeyPair.Free;
  end;
end;

// ---------------------------------------------------------------- snippet 7
function Snippet_QuickVerify(AKey: TJSONWebKey; const ACompactToken: TJOSEBytes): Boolean;
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

// ---------------------------------------------------------------- snippet 8
function Snippet_ValidateWithKeySet(const ACompactToken: TJOSEBytes; AKeySet: TJSONWebKeySet): string;
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

// ---------------------------------------------------------------- snippet 9
procedure Snippet_ErrorHandling(const ACompactToken: TJOSEBytes; AKeySet: TJSONWebKeySet);
begin
  try
    Writeln('Valid token, subject: ', Snippet_ValidateWithKeySet(ACompactToken, AKeySet));
  except
    on E: EInvalidJWTException do
      Writeln('Token rejected: ', E.Message);
    on E: EJOSEException do
      Writeln('JOSE error: ', E.Message);
  end;
end;

// ---------------------------------------------------------------- snippet 10
procedure Snippet_OctRoundTrip;
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
    Writeln(LParsed.K.AsString);
  finally
    LParsed.Free;
  end;
end;

// ------------------------------------------------------- end-to-end run
procedure RunAll;
var
  LPrivate, LPublic: TJSONWebKey;
  LSet: TJSONWebKeySet;
  LCompact: TJOSEBytes;
  LJSON: string;
begin
  Snippet_LoadPEM;
  Snippet_CreateKeys;
  Snippet_OctRoundTrip;
  Snippet_BuildKeySet;

  LPrivate := TJSONWebKey.FromPEM(TFile.ReadAllBytes('rsa-private.pem'));
  try
    LPrivate.Kid := LPrivate.Thumbprint;
    LPrivate.Alg := TJOSEAlgorithmId.RS256;
    LPrivate.Use := TJOSEKeyUse.Signature;

    LSet := TJSONWebKeySet.Create;
    try
      LPublic := ExtractPublicKey(LPrivate);
      LSet.AddKey(LPublic);
      LJSON := LSet.ToJSON;
    finally
      LSet.Free;
    end;

    Snippet_ReadKeySet(LJSON, LPrivate.Kid);

    LCompact := Snippet_SignWithJWK(LPrivate);
    Writeln('token: ', LCompact.AsString);
    Snippet_QuickVerify(LPrivate, LCompact);
  finally
    LPrivate.Free;
  end;

  // Consumer-side: only the published JWKS JSON is available here
  LSet := TJSONWebKeySet.FromJSON(LJSON);
  try
    Snippet_ErrorHandling(LCompact, LSet);
    Snippet_ErrorHandling(LCompact + 'tampered', LSet);
  finally
    LSet.Free;
  end;
end;

const
  // The sample builds into Samples\Exe (see the project's DCC_ExeOutput)
  DEFAULT_KEYS_PATH = '..\..\Tests\Keys';

var
  LKeysPath: string;

begin
  try
    LKeysPath := ParamStr(1);
    if LKeysPath.IsEmpty then
      LKeysPath := TPath.Combine(TPath.GetDirectoryName(ParamStr(0)), DEFAULT_KEYS_PATH);

    if not SetCurrentDir(LKeysPath) then
      raise Exception.CreateFmt('Keys directory not found: %s', [LKeysPath]);

    RunAll;
  except
    on E: Exception do
      Writeln('FAILED -> ', E.ClassName, ': ', E.Message);
  end;

  Write('Press ENTER to exit...');
  Readln;
end.
