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
///   Runnable companion to Docs\jwe-guide.md: every snippet of the guide, in the
///   order it appears there, ending with a nested JWT validated by a consumer and
///   the two failures the guide shows (a tampered token, a consumer that was
///   never told about JWE).
/// </summary>
/// <remarks>
///   Uses the test keys in Tests\Keys (pass a different directory as the first
///   command line parameter). The default provider stack needs the OpenSSL 1.0.2
///   DLLs next to the executable - see Tests\Exe.
/// </remarks>
program JWEGuide;

{$APPTYPE CONSOLE}

uses
  System.SysUtils,
  System.StrUtils,
  System.DateUtils,
  System.IOUtils,
  JOSE.Types.Bytes,
  JOSE.Core.Base,
  JOSE.Core.JWA,
  JOSE.Core.JWK,
  JOSE.Core.JWT,
  JOSE.Core.JWE,
  JOSE.Core.Builder,
  JOSE.Consumer;

const
  HMAC_SECRET = 'my_very_long_and_safe_secret_key';

// ---------------------------------------------------------------- snippet 1
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

// ---------------------------------------------------------------- snippet 2
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

// ---------------------------------------------------------------- snippet 3
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

// ---------------------------------------------------------------- snippet 4
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

// ---------------------------------------------------------------- snippet 5
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

// ---------------------------------------------------------------- snippet 6
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

// ---------------------------------------------------------------- snippet 7
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

// ---------------------------------------------------------------- snippet 8
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

// ---------------------------------------------------------------- snippet 10
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

// ---------------------------------------------------------------- snippet 11
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

// ---------------------------------------------------------------- snippet 9
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

// ------------------------------------------------------- end-to-end run
function Tamper(const ACompactToken: TJOSEBytes): TJOSEBytes;
var
  LParts: TArray<string>;
begin
  // Changes the last character of the ciphertext (part 4) for another valid one
  LParts := ACompactToken.AsString.Split(['.']);
  if LParts[3].EndsWith('A') then
    LParts[3] := LParts[3].Remove(LParts[3].Length - 1) + 'Q'
  else
    LParts[3] := LParts[3].Remove(LParts[3].Length - 1) + 'A';
  Result := string.Join('.', LParts);
end;

procedure RunAll;
var
  LDirKey, LCompact, LNested: TJOSEBytes;
begin
  Writeln('--- dir + A256GCM');
  LDirKey := TJOSEBytes.RandomBytes(32);
  LCompact := Snippet_EncryptDir(LDirKey);
  Writeln('parts: ', Length(LCompact.AsString.Split(['.'])));
  Snippet_DecryptDir(LDirKey, LCompact);
  Snippet_PlainJWEConsumer(LDirKey, LCompact);

  Writeln('--- RSA-OAEP-256 + A256GCM');
  LCompact := Snippet_EncryptRSA;
  Snippet_InspectHeader(LCompact);
  Snippet_DecryptRSA(LCompact);
  Snippet_RSAWithJWK;

  Writeln('--- nested JWT');
  LNested := Snippet_SignAndEncrypt;
  Snippet_InspectHeader(LNested);
  Snippet_DecryptAndVerify(LNested);

  Snippet_ErrorHandling(Snippet_NestedConsumer, LNested);
  Snippet_ErrorHandling(Snippet_NestedConsumer, Tamper(LNested));
  // A consumer that was never told about JWE
  Snippet_ErrorHandling(TJOSEConsumerBuilder.NewConsumer.SetVerificationKey(HMAC_SECRET).Build, LNested);

  Writeln('--- RSA-OAEP + A128CBC-HS256 (Keycloak style)');
  LNested := Snippet_KeycloakStyle;
  Snippet_InspectHeader(LNested);
  Snippet_KeycloakStyleConsumer(LNested);

  Writeln('--- compression');
  LCompact := Snippet_Compressed(LDirKey);
  Snippet_InspectHeader(LCompact);
  Writeln('token length: ', LCompact.Size, ' chars');
  Snippet_DecompressionCap(LDirKey, LCompact);
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
