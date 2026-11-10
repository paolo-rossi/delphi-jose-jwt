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
///   Project Wycheproof JOSE test vectors (Tests/Data/Wycheproof, see the
///   README there): JWS and JWE tokens produced by other implementations,
///   each marked valid or invalid, many of them crafted to catch a known
///   class of bug (malleable signatures, padding oracles, alg confusion,
///   lenient base64)
/// </summary>
/// <remarks>
///   <para>
///     Every vector is run and compared with its expected result. The ones
///     this library knowingly answers differently are listed in
///     KNOWN_DEVIATIONS with the reason; a test fails both when a new vector
///     disagrees and when a listed one stops disagreeing, so the list cannot
///     go stale.
///   </para>
///   <para>
///     A vector whose algorithm the library does not implement (AES key
///     wrap, ECDH-ES, RSA1_5) is skipped, not counted as a rejection: that
///     would pass every invalid vector for the wrong reason.
///   </para>
///   <para>
///     JWS payloads here are opaque bytes ("foo", zeros, binary), while
///     TJWS always parses the payload as JWT claims. VerifyJWS therefore
///     repeats TJWS.SetCompactToken/VerifySignature and TJOSE.SelectKey with
///     the library's own primitives, leaving out only the claims parse. JWE
///     goes through TJWE.DecryptPayload as is.
///   </para>
/// </remarks>
unit JOSE.Tests.Wycheproof;

interface

uses
  System.SysUtils,
  System.Classes,
  System.JSON,
  System.Generics.Collections,
  DUnitX.TestFramework,

  JOSE.Tests.Classes;

type
  TWycheproofOutcome = (Accepted, Rejected, Skipped);

  [TestFixture]
  TTestWycheproof = class(TTestBase)
  private
    FPath: string;
    function LoadFile(const AFileName: string): TJSONObject;
    function VerifyJWS(AGroup: TJSONObject; const AToken: string): Boolean;
    function DecryptJWE(AGroup: TJSONObject; const AToken: string): TBytes;
    function RunVector(AGroup, ATest: TJSONObject; out ADetail: string): TWycheproofOutcome;
    procedure RunFile(const AFileName: string);
  public
    constructor Create;

    [Test]
    procedure JsonWebSignature;
    [Test]
    procedure JsonWebEncryption;
    [Test]
    procedure JsonWebKey;
    [Test]
    procedure JsonWebCrypto;
  end;

implementation

uses
  System.IOUtils,
  System.StrUtils,

  JOSE.Types.Bytes,
  JOSE.Encoding.Base64,
  JOSE.Providers.Interfaces,
  JOSE.Signing.Base,
  JOSE.Types.JSON,
  JOSE.Core.Base,
  JOSE.Core.JWA,
  JOSE.Core.JWA.Signing,
  JOSE.Core.JWA.Factory,
  JOSE.Core.JWK,
  JOSE.Core.JWT,
  JOSE.Core.JWE;

const
  // '<file>:<tcId> <reason>', for every vector this library answers
  // differently. Keep it in sync with what the tests report: a deviation
  // that goes away fails the test as well, so the list must shrink with it.
  //   VECTOR   the vector itself is wrong
  //   STRICTER the library rejects what Wycheproof accepts, on purpose
  //   POLICY   flagged "Ambiguous" by Wycheproof, or beyond what a JOSE
  //            library is expected to check
  KNOWN_DEVIATIONS: array of string = [
    'json_web_signature_test:346 STRICTER: key alg PS256, token PS384; a key whose alg contradicts the header is never selected',
    'json_web_signature_test:350 STRICTER: same as 346, with key_ops',
    'json_web_signature_test:347 VECTOR: key alg "ES521" (no such algorithm, RFC 7520 has none) and token ES512; json_web_key_test:19 expects the same label refused',
    'json_web_signature_test:351 VECTOR: same as 347, with key_ops',
    'json_web_signature_test:367 VECTOR: byte-identical to the valid vector 357, there is no padding in it',
    'json_web_signature_test:370 VECTOR: byte-identical to the valid vector 357, there is no padding in it',
    'json_web_signature_test:372 STRICTER: a "?" inside a part fails the strict base64url check instead of being skipped',
    'json_web_signature_test:373 STRICTER: same as 372, in the payload',
    'json_web_key_test:1 POLICY: a set mixing public and private keys is not refused (Ambiguous)',
    'json_web_key_test:4 POLICY: duplicate kid, the first matching key is used (Ambiguous)',
    'json_web_key_test:7 POLICY: ROCA-vulnerable moduli are not detected',
    'json_web_crypto_test:46 POLICY: ROCA-vulnerable moduli are not detected',
    'json_web_crypto_test:47 POLICY: a set mixing public and private keys is not refused'
  ];

  // JWE key management algorithms this library implements; the rest of the
  // vectors are skipped (see the unit remarks)
  SUPPORTED_JWE_ALGS: array[0..2] of string = ('dir', 'RSA-OAEP', 'RSA-OAEP-256');

function HexToBytes(const AHex: string): TBytes;
var
  LIndex: Integer;
begin
  SetLength(Result, Length(AHex) div 2);
  for LIndex := 0 to High(Result) do
    Result[LIndex] := StrToInt('$' + Copy(AHex, LIndex * 2 + 1, 2));
end;

function SameBytes(const A, B: TBytes): Boolean;
begin
  Result := (Length(A) = Length(B)) and
    ((Length(A) = 0) or CompareMem(@A[0], @B[0], Length(A)));
end;

/// <summary>
///   The exceptions a rejection is expected to come as. Anything else (an
///   access violation, a range or encoding error) means the input reached
///   code that did not expect it, even when the token ends up rejected
/// </summary>
function IsLibraryException(E: Exception): Boolean;
begin
  Result := (E is EJOSEException) or (E is EJOSEBase64Exception) or
    (E is EJOSECryptoException) or (E is ESignException) or
    (E is EJSONConversionException);
end;

function IsKnownDeviation(const AId: string): Boolean;
var
  LEntry: string;
begin
  for LEntry in KNOWN_DEVIATIONS do
    if StartsText(AId + ' ', LEntry) then
      Exit(True);
  Result := False;
end;

/// <summary>The token's header as JSON, nil when it does not decode</summary>
function TryReadHeader(const AToken: string): TJSONObject;
var
  LPart: string;
  LBytes: TJOSEBytes;
  LValue: TJSONValue;
begin
  Result := nil;
  LPart := Copy(AToken, 1, Pos('.', AToken) - 1);
  if LPart = '' then
    Exit;
  LBytes := TBase64.TryURLDecode(LPart);
  if LBytes.IsEmpty then
    Exit;
  LValue := TJSONObject.ParseJSONValue(LBytes.AsBytes, 0, False);
  if LValue is TJSONObject then
    Result := TJSONObject(LValue)
  else
    LValue.Free;
end;

{ TTestWycheproof }

constructor TTestWycheproof.Create;
begin
  inherited;
  FPath := TPath.Combine(FDataPath, 'Wycheproof');
end;

function TTestWycheproof.LoadFile(const AFileName: string): TJSONObject;
var
  LValue: TJSONValue;
begin
  LValue := TJSONObject.ParseJSONValue(
    TFile.ReadAllBytes(TPath.Combine(FPath, AFileName)), 0, True);
  if not (LValue is TJSONObject) then
  begin
    LValue.Free;
    raise Exception.CreateFmt('%s is not a JSON object', [AFileName]);
  end;
  Result := TJSONObject(LValue);
end;

function TTestWycheproof.VerifyJWS(AGroup: TJSONObject; const AToken: string): Boolean;
var
  LKeyValue: TJSONValue;
  LKeySet: TJSONWebKeySet;
  LCompact: TJOSECompactSerialization;
  LHeader: TJWTHeader;
  LAlg: IJOSESigningAlgorithm;
  LAlgId: TJOSEAlgorithmId;
  LKey: TJSONWebKey;
  LPair: TKeyPair;
  LMaterial: TJOSEBytes;
begin
  // The verifier's key: a single JWK, or a JWKS in the key-set vectors
  LKeyValue := AGroup.GetValue('public');
  if not Assigned(LKeyValue) then
    LKeyValue := AGroup.GetValue('private');

  if (LKeyValue as TJSONObject).GetValue('keys') <> nil then
    LKeySet := TJSONWebKeySet.FromJSON(LKeyValue.ToJSON)
  else
  begin
    LKeySet := TJSONWebKeySet.Create;
    LKeySet.AddKey(TJSONWebKey.FromJSON(LKeyValue.ToJSON));
  end;

  LHeader := TJWTHeader.Create;
  try
    // TJWS.SetCompactToken: three parts, each strict base64url, JSON header
    LCompact := TJOSECompactSerialization.Split(AToken);
    LCompact.CheckIsJWS;
    if not LCompact.PartsAreBase64URL then
      raise EJOSEException.Create('A part is not base64url');
    LHeader.URLEncoded := LCompact[0];

    // TJWS.GetAlgorithm
    if LHeader.Algorithm = '' then
      raise EJOSEException.Create('No alg');
    LAlg := TJOSEAlgorithmRegistryFactory.Instance.SigningAlgorithmRegistry
      .GetAlgorithm(LHeader.Algorithm);
    if not Assigned(LAlg) then
      raise EJOSEException.CreateFmt('alg %s not supported', [LHeader.Algorithm]);

    // TJOSE.SelectKey
    LAlgId.AsString := LHeader.Algorithm;
    if LHeader.KeyID <> '' then
      LKey := LKeySet.FindByKidAndAlg(LHeader.KeyID, LAlgId)
    else if LKeySet.Keys.Count = 1 then
      LKey := LKeySet.Keys[0]
    else
      raise EJOSEException.Create('Cannot choose a key');
    if not Assigned(LKey) then
      raise EJOSEException.CreateFmt('No key for kid %s', [LHeader.KeyID]);

    // TJOSE.Verify(TJSONWebKey) + TJWS.VerifySignature
    LKey.CheckPermits([TJOSEKeyOperation.Verify], LHeader.Algorithm);
    LPair := LKey.ToKeyPair;
    try
      LMaterial := LPair.PublicKey.Key;
    finally
      LPair.Free;
    end;
    LAlg.ValidateVerificationKey(LMaterial);
    Result := LAlg.VerifySignature(LMaterial, LCompact[0] + '.' + LCompact[1], LCompact[2]);
  finally
    LHeader.Free;
    LKeySet.Free;
  end;
end;

function TTestWycheproof.DecryptJWE(AGroup: TJSONObject; const AToken: string): TBytes;
var
  LJWK: TJSONWebKey;
  LPair: TKeyPair;
  LKey: TJWK;
  LToken: TJWT;
  LJWE: TJWE;
  LHeader: TJSONObject;
  LAlg, LEnc: string;
begin
  LJWK :=TJSONWebKey.FromJSON(AGroup.GetValue('private').ToJSON);
  try
    // As TJOSE.Decrypt(TJSONWebKey): the key must allow it, then its private half
    LHeader := TryReadHeader(AToken);
    try
      LAlg := '';
      LEnc := '';
      if Assigned(LHeader) then
      begin
        LAlg := LHeader.GetValue<string>('alg', '');
        LEnc := LHeader.GetValue<string>('enc', '');
      end;
    finally
      LHeader.Free;
    end;
    LJWK.CheckPermits([TJOSEKeyOperation.Decrypt, TJOSEKeyOperation.UnwrapKey], LAlg, LEnc);
    LPair := LJWK.ToKeyPair;
    try
      LKey := TJWK.Create(LPair.PrivateKey.Key);
    finally
      LPair.Free;
    end;
  finally
    LJWK.Free;
  end;

  LToken := TJWT.Create;
  LJWE := TJWE.Create(LToken);
  try
    LJWE.CompactToken := AToken;
    Result := LJWE.DecryptPayload(LKey).AsBytes;
  finally
    LJWE.Free;
    LToken.Free;
    LKey.Free;
  end;
end;

function TTestWycheproof.RunVector(AGroup, ATest: TJSONObject; out ADetail: string): TWycheproofOutcome;
var
  LTokenValue: TJSONValue;
  LToken: string;
  LIsJWE: Boolean;
  LHeader: TJSONObject;
  LAlg: string;
  LPlain: TBytes;
  LExpected: string;
begin
  ADetail := '';
  LIsJWE := Assigned(ATest.GetValue('jwe'));
  if LIsJWE then
    LTokenValue := ATest.GetValue('jwe')
  else
    LTokenValue := ATest.GetValue('jws');

  // A JSON serialization comes as an object: hand its text to the compact
  // parser, which must turn it down
  if LTokenValue is TJSONString then
    LToken := TJSONString(LTokenValue).Value
  else
    LToken := LTokenValue.ToJSON;

  if LIsJWE then
  begin
    LHeader := TryReadHeader(LToken);
    try
      if Assigned(LHeader) then
      begin
        LAlg := LHeader.GetValue<string>('alg', '');
        if (LAlg <> '') and (IndexStr(LAlg, SUPPORTED_JWE_ALGS) < 0) then
        begin
          ADetail := 'alg ' + LAlg + ' not implemented';
          Exit(TWycheproofOutcome.Skipped);
        end;
      end;
    finally
      LHeader.Free;
    end;
  end;

  try
    if LIsJWE then
    begin
      LPlain := DecryptJWE(AGroup, LToken);
      Result := TWycheproofOutcome.Accepted;
      if ATest.TryGetValue<string>('pt', LExpected) and not SameBytes(LPlain, HexToBytes(LExpected)) then
        ADetail := 'decrypted to the wrong plaintext';
    end
    else if VerifyJWS(AGroup, LToken) then
      Result := TWycheproofOutcome.Accepted
    else
    begin
      Result := TWycheproofOutcome.Rejected;
      ADetail := 'signature does not verify';
    end;
  except
    on E: Exception do
    begin
      Result := TWycheproofOutcome.Rejected;
      ADetail := E.ClassName + ': ' + E.Message;
      if not IsLibraryException(E) then
        ADetail := 'UNEXPECTED ' + ADetail;
    end;
  end;
end;

procedure TTestWycheproof.RunFile(const AFileName: string);
var
  LRoot, LGroup, LTest: TJSONObject;
  LGroupValue, LTestValue: TJSONValue;
  LFile, LId, LDetail, LExpected: string;
  LOutcome: TWycheproofOutcome;
  LAgrees, LKnown: Boolean;
  LFailures: TStringList;
  LRun, LSkipped, LDeviations: Integer;
begin
  LFile := ChangeFileExt(AFileName, '');
  LRoot := LoadFile(AFileName);
  LFailures := TStringList.Create;
  try
    LRun := 0;
    LSkipped := 0;
    LDeviations := 0;
    for LGroupValue in LRoot.GetValue<TJSONArray>('testGroups') do
    begin
      LGroup := LGroupValue as TJSONObject;
      for LTestValue in LGroup.GetValue<TJSONArray>('tests') do
      begin
        LTest := LTestValue as TJSONObject;
        LId := LFile + ':' + LTest.GetValue<string>('tcId');
        LExpected := LTest.GetValue<string>('result');

        LOutcome := RunVector(LGroup, LTest, LDetail);
        if LOutcome = TWycheproofOutcome.Skipped then
        begin
          Inc(LSkipped);
          Continue;
        end;
        Inc(LRun);

        if SameText(LExpected, 'valid') then
          LAgrees := (LOutcome = TWycheproofOutcome.Accepted) and (LDetail = '')
        else
          // 'invalid' (no vector here is 'acceptable'), and a rejection that
          // took an unexpected exception is still a defect
          LAgrees := (LOutcome = TWycheproofOutcome.Rejected) and not StartsStr('UNEXPECTED', LDetail);

        LKnown := IsKnownDeviation(LId);
        if LKnown then
          Inc(LDeviations);

        if not LAgrees and not LKnown then
          LFailures.Add(Format('%s (%s, expected %s): %s',
            [LId, LTest.GetValue<string>('comment'), LExpected, LDetail]))
        else if LAgrees and LKnown then
          LFailures.Add(Format('%s is listed in KNOWN_DEVIATIONS but now agrees (%s): remove it',
            [LId, LExpected]));
      end;
    end;

    TDUnitX.CurrentRunner.Log(TLogLevel.Information, Format('%s: %d run, %d skipped (not implemented), %d known deviations',
      [LFile, LRun, LSkipped, LDeviations]));

    if LFailures.Count > 0 then
      Assert.Fail(Format('%d vector(s) of %s disagree:'#13#10'%s',
        [LFailures.Count, AFileName, LFailures.Text]));
  finally
    LRoot.Free;
    LFailures.Free;
  end;
end;

procedure TTestWycheproof.JsonWebSignature;
begin
  RunFile('json_web_signature_test.json');
end;

procedure TTestWycheproof.JsonWebEncryption;
begin
  RunFile('json_web_encryption_test.json');
end;

procedure TTestWycheproof.JsonWebKey;
begin
  RunFile('json_web_key_test.json');
end;

procedure TTestWycheproof.JsonWebCrypto;
begin
  RunFile('json_web_crypto_test.json');
end;

initialization
  TDUnitX.RegisterTestFixture(TTestWycheproof);

end.
