{******************************************************************************}
{                                                                              }
{  Delphi JOSE-JWT Library                                                     }
{  Copyright (c) 2015 Paolo Rossi                                              }
{  https://github.com/paolo-rossi/delphi-jose-jwt                              }
{                                                                              }
{  Licensed under the MIT license                                              }
{                                                                              }
{******************************************************************************}
unit JOSE.Tests.JWA.ECDSA;

interface

uses
  System.Rtti, System.SysUtils, DUnitX.TestFramework,

  JOSE.Types.Bytes,
  JOSE.Core.Base,
  JOSE.Core.JWT,
  JOSE.Core.JWS,
  JOSE.Core.JWK,
  JOSE.Core.JWA,
  JOSE.Signing.Base,
  JOSE.Signing.ECDSA,
  JOSE.Encoding.Base64,

  JOSE.Tests.Classes;

type
  [TestFixture]
  TTestJWA = class(TTestBase)
  private const
    TOKEN_ES256 =
      'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.' +
      'eyJpYXQiOjE1MTYyMzkwMjIsImV4cCI6MTUxNjI0OTAyMiwiaXNzIjoiRGVscGhpIEpPU0UgYW5kIEpXVCBMaWJyYXJ5In0.' +
      '4QDMKAvHwb6pA5fN0oQjlzuKmPIlNpmIQ8vPH7zy4fjZdtcPVJMtfiVhztwQldQL9A5yzBKI8q2puVygm-2Adw';
    TOKEN_ES384 =
      'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCJ9.' +
      'eyJpYXQiOjE1MTYyMzkwMjIsImV4cCI6MTUxNjI0OTAyMiwiaXNzIjoiRGVscGhpIEpPU0UgYW5kIEpXVCBMaWJyYXJ5In0.' +
      'aZ1qDq43VbGj_xI1uO7r8oX7PmPSGfKPdY0sP2KgPuDNlvr7O2JDZ_Nt8guzcl5wHszvCGswE5B85Q2f6TADpyu6eXMjEJHJ9h6PjJkQDMPndOg8H90muDCI69cWVZAQ';
    TOKEN_ES512 =
      'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzUxMiJ9.' +
      'eyJpYXQiOjE1MTYyMzkwMjIsImV4cCI6MTUxNjI0OTAyMiwiaXNzIjoiRGVscGhpIEpPU0UgYW5kIEpXVCBMaWJyYXJ5In0.' +
      'ABozcDdHtfGvpwgtjaZ_tcGPls5BBJDUs9lTFiF1adiZJuBKdRRgeO6mINopLvHY5bc5EjQPqb9NTIPss7eJdbZ2AJnrcomRl6_9g26CMWVAoqFxeAlYV6XIP_gP7tdYNx2DdtogdbGOmbj_2yYOAjdDeCblojkUilFs5vYnN59KvMoZ';

    TOKEN_ES256K =
      'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.' +
      'eyJpYXQiOjE1MTYyMzkwMjIsImV4cCI6MTUxNjI0OTAyMiwiaXNzIjoiRGVscGhpIEpPU0UgYW5kIEpXVCBMaWJyYXJ5In0.' +
      'Vw5OtIPlWbA8szsuYH8LpUnTRvo1kJiqmGOGV9-kZbDGcaBpkz2uajpp_5XdLtUN8PKVm0Wl1EAMyOKoKTAfGQ';
  private
    FKeys: TKeyPair;
    procedure LoadKeys(AAlg: TJOSEAlgorithmId);
  public
    [Setup]
    procedure Setup;
    [TearDown]
    procedure TearDown;

    [Test]
    [TestCase('TestECDSAVerify256', 'ES256,' + TOKEN_ES256)]
    [TestCase('TestECDSAVerify384', 'ES384,' + TOKEN_ES384)]
    [TestCase('TestECDSAVerify512', 'ES512,' + TOKEN_ES512)]
    [TestCase('TestECDSAVerify256K', 'ES256K,' + TOKEN_ES256K)]
    procedure TestECDSAVerify(AAlg: TJOSEAlgorithmId; const AToken: string);

    // SkipKeyValidation is the caller's policy: the ES* implementation must not
    // validate the key on its own account, as HMAC and RSA already don't
    [Test]
    procedure TestECDSAVerifyHonoursSkipKeyValidation;
    [Test]
    procedure TestECDSAVerifyValidatesTheKeyWhenNotSkipped;

    // RFC 7518 par. 3.4: R||S, each half the curve's field size
    [Test]
    [TestCase('ES256 truncated', 'ES256,1')]
    [TestCase('ES256 padded',    'ES256,-1')]
    [TestCase('ES384 truncated', 'ES384,1')]
    [TestCase('ES512 truncated', 'ES512,1')]
    procedure TestSignatureOfTheWrongWidthIsRejected(AAlg: TJOSEAlgorithmId; ABytesRemoved: Integer);
    [Test]
    [TestCase('ES256', 'ES256,64')]
    [TestCase('ES256K','ES256K,64')]
    [TestCase('ES384', 'ES384,96')]
    [TestCase('ES512', 'ES512,132')]
    procedure TestSignatureWidthIsTheCurveFieldSize(AAlg: TJOSEAlgorithmId; AExpectedBytes: Integer);
  end;

implementation

uses
  System.DateUtils, System.IOUtils,
  JOSE.Tests.Utils;

procedure TTestJWA.LoadKeys(AAlg: TJOSEAlgorithmId);
var
  LPrefix, LFileName: string;
begin
  case AAlg of
    TJOSEAlgorithmId.ES256:  LPrefix := 'es256';
    TJOSEAlgorithmId.ES256K: LPrefix := 'es256k';
    TJOSEAlgorithmId.ES384:  LPrefix := 'es384';
    TJOSEAlgorithmId.ES512:  LPrefix := 'es512';
  end;
  FKeys := TKeyPair.Create;

  LFileName := TPath.Combine(FKeysPath, LPrefix + '-private.pem');
  FKeys.PrivateKey.Key :=  TFile.ReadAllBytes(LFileName);

  LFileName := TPath.Combine(FKeysPath, LPrefix + '-public.pem');
  FKeys.PublicKey.Key :=  TFile.ReadAllBytes(LFileName);
end;

procedure TTestJWA.Setup;
begin
end;

procedure TTestJWA.TearDown;
begin
  FreeAndNil(FKeys);
end;

procedure TTestJWA.TestECDSAVerify(AAlg: TJOSEAlgorithmId; const AToken: string);
var
  LToken: TJWT;
  LSigner: TJWS;
begin
  LoadKeys(AAlg);

  LToken := TJWT.Create;
  try
    LSigner := TJWS.Create(LToken);
    try
      LSigner.SetKey(FKeys.PublicKey);
      LSigner.SkipKeyValidation := True;
      LSigner.CompactToken := AToken;

      Assert.IsTrue(LSigner.VerifySignature, 'Signature (RSA) should validate');
    finally
      LSigner.Free;
    end;
  finally
    LToken.Free;
  end;
end;

procedure TTestJWA.TestECDSAVerifyHonoursSkipKeyValidation;
var
  LToken: TJWT;
  LSigner: TJWS;
  LKey: TJOSEBytes;
  LJOSEError: string;
begin
  // An empty key is refused by ValidateVerificationKey itself, before any
  // provider call, so an EJOSEException here can only mean the check ran
  LKey := TJOSEBytes.Empty;

  LToken := TJWT.Create;
  try
    LSigner := TJWS.Create(LToken);
    try
      LSigner.SetKey(LKey);
      LSigner.SkipKeyValidation := True;
      LSigner.CompactToken := TOKEN_ES256;

      LJOSEError := '';
      try
        // Failing inside the provider is fine - what must not happen is the
        // library-level key check firing despite the flag
        LSigner.VerifySignature;
      except
        on E: EJOSEException do
          LJOSEError := E.Message;
        on E: Exception do
          ;
      end;

      Assert.AreEqual('', LJOSEError,
        'SkipKeyValidation must suppress the ECDSA key check');
    finally
      LSigner.Free;
    end;
  finally
    LToken.Free;
  end;
end;

procedure TTestJWA.TestECDSAVerifyValidatesTheKeyWhenNotSkipped;
var
  LToken: TJWT;
  LSigner: TJWS;
  LKey: TJOSEBytes;
begin
  LKey := TJOSEBytes.Empty;

  LToken := TJWT.Create;
  try
    LSigner := TJWS.Create(LToken);
    try
      LSigner.SetKey(LKey);
      LSigner.CompactToken := TOKEN_ES256;

      Assert.WillRaise(
        procedure begin LSigner.VerifySignature end,
        EJOSEException, 'Without the flag the key must still be validated');
    finally
      LSigner.Free;
    end;
  finally
    LToken.Free;
  end;
end;

procedure TTestJWA.TestSignatureWidthIsTheCurveFieldSize(AAlg: TJOSEAlgorithmId; AExpectedBytes: Integer);
var
  LToken: TJWT;
  LSigner: TJWS;
begin
  LoadKeys(AAlg);

  LToken := TJWT.Create;
  try
    LSigner := TJWS.Create(LToken);
    try
      LSigner.SetKey(FKeys.PrivateKey);
      LSigner.SetHeaderAlgorithm(AAlg);
      LSigner.Sign;

      Assert.AreEqual(AExpectedBytes, TBase64.URLDecode(LSigner.Signature).Size,
        'The signer must emit R||S at the curve width');
    finally
      LSigner.Free;
    end;
  finally
    LToken.Free;
  end;
end;

procedure TTestJWA.TestSignatureOfTheWrongWidthIsRejected(AAlg: TJOSEAlgorithmId; ABytesRemoved: Integer);
var
  LToken: TJWT;
  LSigner: TJWS;
  LSignature: TBytes;
  LTampered: TJOSEBytes;
begin
  LoadKeys(AAlg);

  LToken := TJWT.Create;
  try
    LSigner := TJWS.Create(LToken);
    try
      LSigner.SetKey(FKeys.PrivateKey);
      LSigner.SetHeaderAlgorithm(AAlg);
      LSigner.Sign;

      // Take a byte off the decoded signature (or add one), then re-encode:
      // still valid base64url, but no longer a pair of field-sized components
      LSignature := TBase64.URLDecode(LSigner.Signature).AsBytes;
      SetLength(LSignature, Length(LSignature) - ABytesRemoved);
      LTampered := TBase64.URLEncode(LSignature);

      LSigner.SetKey(FKeys.PublicKey);
      LSigner.Signature := LTampered;

      Assert.WillRaise(
        procedure begin LSigner.VerifySignature end,
        EJOSEException, 'A signature of the wrong width must be reported as such');
    finally
      LSigner.Free;
    end;
  finally
    LToken.Free;
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TTestJWA);

end.

