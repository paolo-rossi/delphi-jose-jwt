{******************************************************************************}
{                                                                              }
{  Delphi JOSE Library                                                         }
{  Copyright (c) 2015 Paolo Rossi                                              }
{  https://github.com/paolo-rossi/delphi-jose-jwt                              }
{                                                                              }
{******************************************************************************}
{                                                                              }
{  Licensed under the Apache License, Version 2.0 (the "License");             }
{  you may not use this file except in compliance with the License.            }
{  You may obtain a copy of the License at                                     }
{                                                                              }
{      http://www.apache.org/licenses/LICENSE-2.0                              }
{                                                                              }
{  Unless required by applicable law or agreed to in writing, software         }
{  distributed under the License is distributed on an "AS IS" BASIS,           }
{  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.    }
{  See the License for the specific language governing permissions and         }
{  limitations under the License.                                              }
{                                                                              }
{******************************************************************************}

unit JOSE.Tests.Providers.CryptoLib;

interface

uses
  DUnitX.TestFramework,

  JOSE.Tests.Classes,
  JOSE.Core.JWT,
  JOSE.Core.JWS,
  JOSE.Core.JWA,
  JOSE.Core.JWK,
  JOSE.Signing.RSA,
  JOSE.Signing.ECDSA,
  JOSE.Signing.Base,
  JOSE.Providers,
  JOSE.Providers.CryptoLib,
  JOSE.Hashing.HMAC,
  JOSE.Crypto.Algorithms,
  JOSE.Encoding.Base64;

type
  /// <summary>
  ///   Tests for the CryptoLib4Pascal-backed provider stack: signing/HMAC through
  ///   TJOSECryptoLibProviders, the TCryptoLibRSAKeyMaterialProvider/TCryptoLibECKeyMaterialProvider
  ///   raw key import/export, the JWK PEM support those two enable, and their interoperability with
  ///   the OpenSSL-backed default stack.
  /// </summary>
  [TestFixture]
  [Category('CryptoLib')]
  TTestCryptoLibProviders = class(TTestBase)
  public
    [Setup]
    procedure Setup;
    [TearDown]
    procedure TearDown;

    [Test]
    procedure TestHMAC_SHA256_Vector;
    [Test]
    procedure TestRSA_RS256_SignVerifyRoundTrip;

    [Test]
    [TestCase('PS256', 'PS256')]
    [TestCase('PS384', 'PS384')]
    [TestCase('PS512', 'PS512')]
    procedure TestRSA_PSS_SignVerifyRoundTrip(AAlg: TRSAAlgorithm);

    [Test]
    [TestCase('PS256', 'PS256')]
    [TestCase('PS384', 'PS384')]
    [TestCase('PS512', 'PS512')]
    procedure TestRSA_PSS_SignaturesAreNonDeterministic(AAlg: TRSAAlgorithm);

    [Test]
    [TestCase('PS256', 'PS256')]
    [TestCase('PS384', 'PS384')]
    [TestCase('PS512', 'PS512')]
    procedure TestInterop_PSS_CryptoLibSignature_VerifiedByDefaultStack(AAlg: TRSAAlgorithm);

    [Test]
    [TestCase('PS256', 'PS256')]
    [TestCase('PS384', 'PS384')]
    [TestCase('PS512', 'PS512')]
    procedure TestInterop_PSS_DefaultSignature_VerifiedByCryptoLib(AAlg: TRSAAlgorithm);
    [Test]
    procedure TestECDSA_Verify_ES256_Token;

    [Test]
    procedure TestCryptoLib_RSAKeyMaterial_Registered;
    [Test]
    procedure TestCryptoLib_ECKeyMaterial_Registered;

    [Test]
    procedure TestRSAKeyMaterial_ImportPEM_ExtractsComponents;
    [Test]
    procedure TestRSAKeyMaterial_ExportPEM_RoundTrips;
    [Test]
    procedure TestRSAKeyMaterial_ExportPEM_PublicOnly;
    [Test]
    procedure TestRSAKeyMaterial_RejectsECPem;
    [Test]
    procedure TestRSAKeyMaterial_RejectsCertificatePem;

    [Test]
    [TestCase('P256', 'es256,P256,32')]
    [TestCase('secp256k1', 'es256k,secp256k1,32')]
    [TestCase('P384', 'es384,P384,48')]
    [TestCase('P521', 'es512,P521,66')]
    procedure TestECKeyMaterial_ImportPEM_ExtractsComponents(const AKeyFilePrefix: string; ACurve: TECCurve;
      AComponentLen: Integer);

    [Test]
    [TestCase('P256', 'es256,P256')]
    [TestCase('secp256k1', 'es256k,secp256k1')]
    [TestCase('P384', 'es384,P384')]
    [TestCase('P521', 'es512,P521')]
    procedure TestECKeyMaterial_ExportPEM_RoundTrips(const AKeyFilePrefix: string; ACurve: TECCurve);

    [Test]
    [TestCase('P256', 'es256,P256')]
    [TestCase('secp256k1', 'es256k,secp256k1')]
    [TestCase('P384', 'es384,P384')]
    [TestCase('P521', 'es512,P521')]
    procedure TestECKeyMaterial_ExportPEM_PublicOnly(const AKeyFilePrefix: string; ACurve: TECCurve);

    [Test]
    procedure TestECKeyMaterial_RejectsRSAPem;

    // JWK-level round-trips: the whole point of registering the two key-material slots.
    [Test]
    procedure TestJWK_RSA_FromPEM_ToPEM_SignVerify;

    [Test]
    [TestCase('ES256', 'ES256,es256,P256')]
    [TestCase('ES256K', 'ES256K,es256k,secp256k1')]
    [TestCase('ES384', 'ES384,es384,P384')]
    [TestCase('ES512', 'ES512,es512,P521')]
    procedure TestJWK_EC_FromPEM_ToPEM_SignVerify(AAlg: TJOSEAlgorithmId; const AKeyFilePrefix: string;
      ACurve: TJOSEEllipticCurve);

    // Cross-stack: the two stacks must agree on the components a PEM decodes to, and each must be
    // able to read what the other writes.
    [Test]
    procedure TestInterop_RSA_ImportAgreesWithDefaultStack;
    [Test]
    [TestCase('P256', 'es256')]
    [TestCase('secp256k1', 'es256k')]
    [TestCase('P384', 'es384')]
    [TestCase('P521', 'es512')]
    procedure TestInterop_EC_ImportAgreesWithDefaultStack(const AKeyFilePrefix: string);

    [Test]
    procedure TestInterop_RSA_CryptoLibExport_ReadByDefaultStack;
    [Test]
    [TestCase('P256', 'es256')]
    [TestCase('secp256k1', 'es256k')]
    [TestCase('P384', 'es384')]
    [TestCase('P521', 'es512')]
    procedure TestInterop_EC_CryptoLibExport_ReadByDefaultStack(const AKeyFilePrefix: string);

    [Test]
    procedure TestInterop_RSA_DefaultExport_ReadByCryptoLib;
    [Test]
    [TestCase('P256', 'es256')]
    [TestCase('secp256k1', 'es256k')]
    [TestCase('P384', 'es384')]
    [TestCase('P521', 'es512')]
    procedure TestInterop_EC_DefaultExport_ReadByCryptoLib(const AKeyFilePrefix: string);
  end;

implementation

uses
  System.SysUtils,
  System.IOUtils,
  JOSE.Types.Bytes,
  JOSE.Core.Builder,
  JOSE.Providers.Interfaces,
  JOSE.Providers.Default;

procedure TTestCryptoLibProviders.Setup;
begin
  inherited;
  TJOSECryptoLibProviders.Register;
end;

procedure TTestCryptoLibProviders.TearDown;
begin
  TJOSECryptoLibProviders.Unregister;
  TJOSEProviders.RegisterProvider;
  inherited;
end;

procedure TTestCryptoLibProviders.TestHMAC_SHA256_Vector;
var
  LSig, LExpected: TBytes;
begin
  LSig := THMAC.Sign(TEncoding.ANSI.GetBytes('plaintext'), TEncoding.ANSI.GetBytes('secret'), THMACAlgorithm.SHA256);
  LExpected := TBase64.Decode('XXv4q83DfQItSR7PCiZwWFlG10ah668c1cRsrKh6Ylg=').AsBytes;
  Assert.AreEqualMemory(@LExpected[0], @LSig[0], Length(LExpected));
end;

procedure TTestCryptoLibProviders.TestRSA_PSS_SignVerifyRoundTrip(AAlg: TRSAAlgorithm);
var
  LPriv, LPub, LInput, LSig: TBytes;
begin
  LPriv := TFile.ReadAllBytes(TPath.Combine(FKeysPath, 'rsa-private.pem'));
  LPub := TFile.ReadAllBytes(TPath.Combine(FKeysPath, 'rsa-public.pem'));
  LInput := TEncoding.UTF8.GetBytes('The quick brown fox');

  LSig := TRSA.Sign(LInput, LPriv, AAlg);
  Assert.IsTrue(TRSA.Verify(LInput, LSig, LPub, AAlg));

  // The padding scheme has to be part of the identity of the signature, not just of the header.
  Assert.IsFalse(TRSA.Verify(LInput, LSig, LPub, TRSAAlgorithm.RS256),
    'A PSS signature must not verify as PKCS#1 v1.5');
end;

procedure TTestCryptoLibProviders.TestRSA_PSS_SignaturesAreNonDeterministic(AAlg: TRSAAlgorithm);
var
  LPriv, LPub, LInput, LFirst, LSecond: TBytes;
begin
  LPriv := TFile.ReadAllBytes(TPath.Combine(FKeysPath, 'rsa-private.pem'));
  LPub := TFile.ReadAllBytes(TPath.Combine(FKeysPath, 'rsa-public.pem'));
  LInput := TEncoding.UTF8.GetBytes('The quick brown fox');

  LFirst := TRSA.Sign(LInput, LPriv, AAlg);
  LSecond := TRSA.Sign(LInput, LPriv, AAlg);

  // PSS draws a fresh salt per signature. Identical output would mean CryptoLib had been asked
  // for a deterministic (PKCS#1 v1.5) mechanism by mistake.
  Assert.AreNotEqual<TBytes>(LFirst, LSecond,
    'PSS signatures must differ between signings');
  Assert.IsTrue(TRSA.Verify(LInput, LFirst, LPub, AAlg));
  Assert.IsTrue(TRSA.Verify(LInput, LSecond, LPub, AAlg));
end;

procedure TTestCryptoLibProviders.TestInterop_PSS_CryptoLibSignature_VerifiedByDefaultStack(AAlg: TRSAAlgorithm);
var
  LPriv, LPub, LInput, LSig: TBytes;
begin
  LPriv := TFile.ReadAllBytes(TPath.Combine(FKeysPath, 'rsa-private.pem'));
  LPub := TFile.ReadAllBytes(TPath.Combine(FKeysPath, 'rsa-public.pem'));
  LInput := TEncoding.UTF8.GetBytes('The quick brown fox');

  // Signed by CryptoLib (registered in Setup)...
  LSig := TRSA.Sign(LInput, LPriv, AAlg);

  // ...and verified by the OpenSSL stack. Two independent PSS implementations have to agree on
  // the salt length and MGF1 hash or this fails.
  TJOSEDefaultProviders.Register;
  try
    Assert.IsTrue(TRSA.Verify(LInput, LSig, LPub, AAlg));
  finally
    TJOSECryptoLibProviders.Register;
  end;
end;

procedure TTestCryptoLibProviders.TestInterop_PSS_DefaultSignature_VerifiedByCryptoLib(AAlg: TRSAAlgorithm);
var
  LPriv, LPub, LInput, LSig: TBytes;
begin
  LPriv := TFile.ReadAllBytes(TPath.Combine(FKeysPath, 'rsa-private.pem'));
  LPub := TFile.ReadAllBytes(TPath.Combine(FKeysPath, 'rsa-public.pem'));
  LInput := TEncoding.UTF8.GetBytes('The quick brown fox');

  TJOSEDefaultProviders.Register;
  try
    LSig := TRSA.Sign(LInput, LPriv, AAlg);
  finally
    TJOSECryptoLibProviders.Register;
  end;

  Assert.IsTrue(TRSA.Verify(LInput, LSig, LPub, AAlg),
    'CryptoLib should verify what the OpenSSL stack signed');
end;

procedure TTestCryptoLibProviders.TestRSA_RS256_SignVerifyRoundTrip;
var
  LPriv, LPub, LInput: TBytes;
  LSig: TBytes;
begin
  LPriv := TFile.ReadAllBytes(TPath.Combine(FKeysPath, 'rsa-private.pem'));
  LPub := TFile.ReadAllBytes(TPath.Combine(FKeysPath, 'rsa-public.pem'));
  LInput := TEncoding.UTF8.GetBytes('The quick brown fox');
  LSig := TRSA.Sign(LInput, LPriv, TRSAAlgorithm.RS256);
  Assert.IsTrue(TRSA.Verify(LInput, LSig, LPub, TRSAAlgorithm.RS256));
end;

procedure TTestCryptoLibProviders.TestECDSA_Verify_ES256_Token;
const
  TOKEN_ES256 =
    'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.' +
    'eyJpYXQiOjE1MTYyMzkwMjIsImV4cCI6MTUxNjI0OTAyMiwiaXNzIjoiRGVscGhpIEpPU0UgYW5kIEpXVCBMaWJyYXJ5In0.' +
    '4QDMKAvHwb6pA5fN0oQjlzuKmPIlNpmIQ8vPH7zy4fjZdtcPVJMtfiVhztwQldQL9A5yzBKI8q2puVygm-2Adw';
var
  LToken: TJWT;
  LSigner: TJWS;
begin
  LToken := TJWT.Create;
  try
    LSigner := TJWS.Create(LToken);
    try
      LSigner.SetKey(TFile.ReadAllBytes(TPath.Combine(FKeysPath, 'es256-public.pem')));
      LSigner.SkipKeyValidation := True;
      LSigner.CompactToken := TOKEN_ES256;
      Assert.IsTrue(LSigner.VerifySignature, 'ES256 (CryptoLib) should validate');
    finally
      LSigner.Free;
    end;
  finally
    LToken.Free;
  end;
end;

procedure TTestCryptoLibProviders.TestCryptoLib_RSAKeyMaterial_Registered;
begin
  Assert.IsNotNull(TJOSEProviders.RSAKeyMaterial, 'RSAKeyMaterial should be registered by the CryptoLib provider stack');
end;

procedure TTestCryptoLibProviders.TestCryptoLib_ECKeyMaterial_Registered;
begin
  Assert.IsNotNull(TJOSEProviders.ECKeyMaterial, 'ECKeyMaterial should be registered by the CryptoLib provider stack');
end;

procedure TTestCryptoLibProviders.TestRSAKeyMaterial_ImportPEM_ExtractsComponents;
var
  LPem: TBytes;
  LMaterial: TJOSERSAKeyMaterial;
begin
  LPem := TFile.ReadAllBytes(TPath.Combine(FKeysPath, 'rsa-private.pem'));
  LMaterial := TJOSEProviders.RSAKeyMaterial.ImportPEM(LPem);

  Assert.IsTrue(Length(LMaterial.Modulus) > 0, 'Modulus should not be empty');
  Assert.IsTrue(Length(LMaterial.PublicExponent) > 0, 'PublicExponent should not be empty');
  Assert.IsTrue(LMaterial.IsPrivate, 'Imported key should be reported as private');
  Assert.IsTrue(Length(LMaterial.PrivateExponent) > 0, 'PrivateExponent should not be empty');
  Assert.IsTrue(Length(LMaterial.P) > 0, 'P should not be empty');
  Assert.IsTrue(Length(LMaterial.Q) > 0, 'Q should not be empty');
  Assert.IsTrue(Length(LMaterial.DP) > 0, 'DP should not be empty');
  Assert.IsTrue(Length(LMaterial.DQ) > 0, 'DQ should not be empty');
  Assert.IsTrue(Length(LMaterial.QI) > 0, 'QI should not be empty');
end;

procedure TTestCryptoLibProviders.TestRSAKeyMaterial_ExportPEM_RoundTrips;
var
  LPem, LExportedPem: TBytes;
  LMaterial, LReimported: TJOSERSAKeyMaterial;
begin
  LPem := TFile.ReadAllBytes(TPath.Combine(FKeysPath, 'rsa-private.pem'));
  LMaterial := TJOSEProviders.RSAKeyMaterial.ImportPEM(LPem);

  LExportedPem := TJOSEProviders.RSAKeyMaterial.ExportPEM(LMaterial, True);
  LReimported := TJOSEProviders.RSAKeyMaterial.ImportPEM(LExportedPem);

  Assert.IsTrue(LReimported.IsPrivate, 'Re-imported key should still be private');
  Assert.AreEqual<Byte>(LMaterial.Modulus, LReimported.Modulus, 'Modulus should round-trip exactly');
  Assert.AreEqual<Byte>(LMaterial.PublicExponent, LReimported.PublicExponent, 'PublicExponent should round-trip exactly');
  Assert.AreEqual<Byte>(LMaterial.PrivateExponent, LReimported.PrivateExponent, 'PrivateExponent should round-trip exactly');
  Assert.AreEqual<Byte>(LMaterial.P, LReimported.P, 'P should round-trip exactly');
  Assert.AreEqual<Byte>(LMaterial.Q, LReimported.Q, 'Q should round-trip exactly');
  Assert.AreEqual<Byte>(LMaterial.DP, LReimported.DP, 'DP should round-trip exactly');
  Assert.AreEqual<Byte>(LMaterial.DQ, LReimported.DQ, 'DQ should round-trip exactly');
  Assert.AreEqual<Byte>(LMaterial.QI, LReimported.QI, 'QI should round-trip exactly');
end;

procedure TTestCryptoLibProviders.TestRSAKeyMaterial_ExportPEM_PublicOnly;
var
  LPem, LExportedPem: TBytes;
  LMaterial, LReimported: TJOSERSAKeyMaterial;
begin
  LPem := TFile.ReadAllBytes(TPath.Combine(FKeysPath, 'rsa-private.pem'));
  LMaterial := TJOSEProviders.RSAKeyMaterial.ImportPEM(LPem);

  LExportedPem := TJOSEProviders.RSAKeyMaterial.ExportPEM(LMaterial, False);
  LReimported := TJOSEProviders.RSAKeyMaterial.ImportPEM(LExportedPem);

  Assert.IsFalse(LReimported.IsPrivate, 'Public-only export should re-import as public-only');
  Assert.AreEqual<Byte>(LMaterial.Modulus, LReimported.Modulus, 'Modulus should round-trip exactly');
  Assert.AreEqual<Byte>(LMaterial.PublicExponent, LReimported.PublicExponent, 'PublicExponent should round-trip exactly');
end;

procedure TTestCryptoLibProviders.TestRSAKeyMaterial_RejectsECPem;
var
  LPem: TBytes;
begin
  LPem := TFile.ReadAllBytes(TPath.Combine(FKeysPath, 'es256-private.pem'));

  Assert.WillRaise(
    procedure
    begin
      TJOSEProviders.RSAKeyMaterial.ImportPEM(LPem);
    end,
    ESignException
  );
end;

procedure TTestCryptoLibProviders.TestRSAKeyMaterial_RejectsCertificatePem;
var
  LPem: TBytes;
begin
  // A certificate carries a public key, but the key-material providers take key PEMs only -
  // extracting from a certificate is IJOSECertificateProvider's job.
  LPem := TFile.ReadAllBytes(TPath.Combine(TPath.Combine(FKeysPath, 'cert'), 'rsa-x509.pem'));

  Assert.WillRaise(
    procedure
    begin
      TJOSEProviders.RSAKeyMaterial.ImportPEM(LPem);
    end,
    ESignException
  );
end;

procedure TTestCryptoLibProviders.TestECKeyMaterial_ImportPEM_ExtractsComponents(const AKeyFilePrefix: string;
  ACurve: TECCurve; AComponentLen: Integer);
var
  LPem: TBytes;
  LMaterial: TJOSEECKeyMaterial;
begin
  LPem := TFile.ReadAllBytes(TPath.Combine(FKeysPath, AKeyFilePrefix + '-private.pem'));
  LMaterial := TJOSEProviders.ECKeyMaterial.ImportPEM(LPem);

  Assert.AreEqual(ACurve, LMaterial.Curve);
  Assert.IsTrue(LMaterial.IsPrivate, 'Imported key should be reported as private');

  // RFC 7518 6.2.1.2/6.2.2.1: x, y and d are fixed-width for the curve, not minimally encoded.
  Assert.AreEqual<Integer>(AComponentLen, Length(LMaterial.X), 'X should be the full coordinate width');
  Assert.AreEqual<Integer>(AComponentLen, Length(LMaterial.Y), 'Y should be the full coordinate width');
  Assert.AreEqual<Integer>(AComponentLen, Length(LMaterial.D), 'D should be the full order width');
end;

procedure TTestCryptoLibProviders.TestECKeyMaterial_ExportPEM_RoundTrips(const AKeyFilePrefix: string;
  ACurve: TECCurve);
var
  LPem, LExportedPem: TBytes;
  LMaterial, LReimported: TJOSEECKeyMaterial;
begin
  LPem := TFile.ReadAllBytes(TPath.Combine(FKeysPath, AKeyFilePrefix + '-private.pem'));
  LMaterial := TJOSEProviders.ECKeyMaterial.ImportPEM(LPem);

  LExportedPem := TJOSEProviders.ECKeyMaterial.ExportPEM(LMaterial, True);
  LReimported := TJOSEProviders.ECKeyMaterial.ImportPEM(LExportedPem);

  Assert.AreEqual(ACurve, LReimported.Curve);
  Assert.IsTrue(LReimported.IsPrivate, 'Re-imported key should still be private');
  Assert.AreEqual<Byte>(LMaterial.X, LReimported.X, 'X should round-trip exactly');
  Assert.AreEqual<Byte>(LMaterial.Y, LReimported.Y, 'Y should round-trip exactly');
  Assert.AreEqual<Byte>(LMaterial.D, LReimported.D, 'D should round-trip exactly');
end;

procedure TTestCryptoLibProviders.TestECKeyMaterial_ExportPEM_PublicOnly(const AKeyFilePrefix: string;
  ACurve: TECCurve);
var
  LPem, LExportedPem: TBytes;
  LMaterial, LReimported: TJOSEECKeyMaterial;
begin
  LPem := TFile.ReadAllBytes(TPath.Combine(FKeysPath, AKeyFilePrefix + '-private.pem'));
  LMaterial := TJOSEProviders.ECKeyMaterial.ImportPEM(LPem);

  LExportedPem := TJOSEProviders.ECKeyMaterial.ExportPEM(LMaterial, False);
  LReimported := TJOSEProviders.ECKeyMaterial.ImportPEM(LExportedPem);

  Assert.AreEqual(ACurve, LReimported.Curve);
  Assert.IsFalse(LReimported.IsPrivate, 'Public-only export should re-import as public-only');
  Assert.AreEqual<Byte>(LMaterial.X, LReimported.X, 'X should round-trip exactly');
  Assert.AreEqual<Byte>(LMaterial.Y, LReimported.Y, 'Y should round-trip exactly');
end;

procedure TTestCryptoLibProviders.TestECKeyMaterial_RejectsRSAPem;
var
  LPem: TBytes;
begin
  LPem := TFile.ReadAllBytes(TPath.Combine(FKeysPath, 'rsa-private.pem'));

  Assert.WillRaise(
    procedure
    begin
      TJOSEProviders.ECKeyMaterial.ImportPEM(LPem);
    end,
    ESignException
  );
end;

procedure TTestCryptoLibProviders.TestJWK_RSA_FromPEM_ToPEM_SignVerify;
var
  LPem: TBytes;
  LJWK: TJSONWebKey;
  LKeyPair: TKeyPair;
  LToken, LVerified: TJWT;
  LCompact: TJOSEBytes;
begin
  LPem := TFile.ReadAllBytes(TPath.Combine(FKeysPath, 'rsa-private.pem'));

  LJWK := TJSONWebKey.FromPEM(LPem);
  try
    Assert.AreEqual(TJOSEKeyType.RSA, LJWK.Kty);
    Assert.IsTrue(LJWK.IsPrivate);

    LKeyPair := LJWK.ToKeyPair;
    try
      LToken := TJWT.Create;
      try
        LToken.Claims.Subject := 'cryptolib-jwk-rsa';
        LCompact := TJOSE.SerializeCompact(LKeyPair.PrivateKey, TJOSEAlgorithmId.RS256, LToken);
      finally
        LToken.Free;
      end;

      LVerified := TJOSE.Verify(LKeyPair.PublicKey, LCompact);
      try
        Assert.AreEqual('cryptolib-jwk-rsa', LVerified.Claims.Subject);
      finally
        LVerified.Free;
      end;
    finally
      LKeyPair.Free;
    end;
  finally
    LJWK.Free;
  end;
end;

procedure TTestCryptoLibProviders.TestJWK_EC_FromPEM_ToPEM_SignVerify(AAlg: TJOSEAlgorithmId;
  const AKeyFilePrefix: string; ACurve: TJOSEEllipticCurve);
var
  LPem: TBytes;
  LJWK: TJSONWebKey;
  LKeyPair: TKeyPair;
  LToken, LVerified: TJWT;
  LCompact: TJOSEBytes;
begin
  LPem := TFile.ReadAllBytes(TPath.Combine(FKeysPath, AKeyFilePrefix + '-private.pem'));

  LJWK := TJSONWebKey.FromPEM(LPem);
  try
    Assert.AreEqual(TJOSEKeyType.EC, LJWK.Kty);
    Assert.AreEqual(ACurve, LJWK.Crv);
    Assert.IsTrue(LJWK.IsPrivate);

    LKeyPair := LJWK.ToKeyPair;
    try
      LToken := TJWT.Create;
      try
        LToken.Claims.Subject := 'cryptolib-jwk-ec';
        LCompact := TJOSE.SerializeCompact(LKeyPair.PrivateKey, AAlg, LToken);
      finally
        LToken.Free;
      end;

      LVerified := TJOSE.Verify(LKeyPair.PublicKey, LCompact);
      try
        Assert.AreEqual('cryptolib-jwk-ec', LVerified.Claims.Subject);
      finally
        LVerified.Free;
      end;
    finally
      LKeyPair.Free;
    end;
  finally
    LJWK.Free;
  end;
end;

procedure TTestCryptoLibProviders.TestInterop_RSA_ImportAgreesWithDefaultStack;
var
  LPem: TBytes;
  LDefault: IJOSERSAKeyMaterialProvider;
  LFromCryptoLib, LFromDefault: TJOSERSAKeyMaterial;
begin
  LPem := TFile.ReadAllBytes(TPath.Combine(FKeysPath, 'rsa-private.pem'));
  LDefault := TDefaultRSAKeyMaterialProvider.Create;

  LFromCryptoLib := TJOSEProviders.RSAKeyMaterial.ImportPEM(LPem);
  LFromDefault := LDefault.ImportPEM(LPem);

  Assert.AreEqual<Byte>(LFromDefault.Modulus, LFromCryptoLib.Modulus, 'Modulus should match the default stack');
  Assert.AreEqual<Byte>(LFromDefault.PublicExponent, LFromCryptoLib.PublicExponent, 'PublicExponent should match the default stack');
  Assert.AreEqual<Byte>(LFromDefault.PrivateExponent, LFromCryptoLib.PrivateExponent, 'PrivateExponent should match the default stack');
  Assert.AreEqual<Byte>(LFromDefault.P, LFromCryptoLib.P, 'P should match the default stack');
  Assert.AreEqual<Byte>(LFromDefault.Q, LFromCryptoLib.Q, 'Q should match the default stack');
  Assert.AreEqual<Byte>(LFromDefault.DP, LFromCryptoLib.DP, 'DP should match the default stack');
  Assert.AreEqual<Byte>(LFromDefault.DQ, LFromCryptoLib.DQ, 'DQ should match the default stack');
  Assert.AreEqual<Byte>(LFromDefault.QI, LFromCryptoLib.QI, 'QI should match the default stack');
end;

procedure TTestCryptoLibProviders.TestInterop_EC_ImportAgreesWithDefaultStack(const AKeyFilePrefix: string);
var
  LPem: TBytes;
  LDefault: IJOSEECKeyMaterialProvider;
  LFromCryptoLib, LFromDefault: TJOSEECKeyMaterial;
begin
  LPem := TFile.ReadAllBytes(TPath.Combine(FKeysPath, AKeyFilePrefix + '-private.pem'));
  LDefault := TDefaultECKeyMaterialProvider.Create;

  LFromCryptoLib := TJOSEProviders.ECKeyMaterial.ImportPEM(LPem);
  LFromDefault := LDefault.ImportPEM(LPem);

  Assert.AreEqual(LFromDefault.Curve, LFromCryptoLib.Curve, 'Curve should match the default stack');
  Assert.AreEqual<Byte>(LFromDefault.X, LFromCryptoLib.X, 'X should match the default stack');
  Assert.AreEqual<Byte>(LFromDefault.Y, LFromCryptoLib.Y, 'Y should match the default stack');
  Assert.AreEqual<Byte>(LFromDefault.D, LFromCryptoLib.D, 'D should match the default stack');
end;

procedure TTestCryptoLibProviders.TestInterop_RSA_CryptoLibExport_ReadByDefaultStack;
var
  LPem, LExportedPem: TBytes;
  LDefault: IJOSERSAKeyMaterialProvider;
  LMaterial, LReimported: TJOSERSAKeyMaterial;
begin
  LPem := TFile.ReadAllBytes(TPath.Combine(FKeysPath, 'rsa-private.pem'));
  LDefault := TDefaultRSAKeyMaterialProvider.Create;

  LMaterial := TJOSEProviders.RSAKeyMaterial.ImportPEM(LPem);
  LExportedPem := TJOSEProviders.RSAKeyMaterial.ExportPEM(LMaterial, True);
  LReimported := LDefault.ImportPEM(LExportedPem);

  Assert.IsTrue(LReimported.IsPrivate, 'The default stack should read the CryptoLib private key PEM');
  Assert.AreEqual<Byte>(LMaterial.Modulus, LReimported.Modulus, 'Modulus should survive the crossing');
  Assert.AreEqual<Byte>(LMaterial.PrivateExponent, LReimported.PrivateExponent, 'PrivateExponent should survive the crossing');

  LExportedPem := TJOSEProviders.RSAKeyMaterial.ExportPEM(LMaterial, False);
  LReimported := LDefault.ImportPEM(LExportedPem);

  Assert.IsFalse(LReimported.IsPrivate, 'The default stack should read the CryptoLib public key PEM');
  Assert.AreEqual<Byte>(LMaterial.Modulus, LReimported.Modulus, 'Modulus should survive the crossing');
  Assert.AreEqual<Byte>(LMaterial.PublicExponent, LReimported.PublicExponent, 'PublicExponent should survive the crossing');
end;

procedure TTestCryptoLibProviders.TestInterop_EC_CryptoLibExport_ReadByDefaultStack(const AKeyFilePrefix: string);
var
  LPem, LExportedPem: TBytes;
  LDefault: IJOSEECKeyMaterialProvider;
  LMaterial, LReimported: TJOSEECKeyMaterial;
begin
  LPem := TFile.ReadAllBytes(TPath.Combine(FKeysPath, AKeyFilePrefix + '-private.pem'));
  LDefault := TDefaultECKeyMaterialProvider.Create;

  LMaterial := TJOSEProviders.ECKeyMaterial.ImportPEM(LPem);
  LExportedPem := TJOSEProviders.ECKeyMaterial.ExportPEM(LMaterial, True);
  LReimported := LDefault.ImportPEM(LExportedPem);

  Assert.AreEqual(LMaterial.Curve, LReimported.Curve, 'Curve should survive the crossing');
  Assert.IsTrue(LReimported.IsPrivate, 'The default stack should read the CryptoLib private key PEM');
  Assert.AreEqual<Byte>(LMaterial.X, LReimported.X, 'X should survive the crossing');
  Assert.AreEqual<Byte>(LMaterial.Y, LReimported.Y, 'Y should survive the crossing');
  Assert.AreEqual<Byte>(LMaterial.D, LReimported.D, 'D should survive the crossing');

  LExportedPem := TJOSEProviders.ECKeyMaterial.ExportPEM(LMaterial, False);
  LReimported := LDefault.ImportPEM(LExportedPem);

  Assert.AreEqual(LMaterial.Curve, LReimported.Curve, 'Curve should survive the crossing');
  Assert.IsFalse(LReimported.IsPrivate, 'The default stack should read the CryptoLib public key PEM');
  Assert.AreEqual<Byte>(LMaterial.X, LReimported.X, 'X should survive the crossing');
  Assert.AreEqual<Byte>(LMaterial.Y, LReimported.Y, 'Y should survive the crossing');
end;

procedure TTestCryptoLibProviders.TestInterop_RSA_DefaultExport_ReadByCryptoLib;
var
  LPem, LExportedPem: TBytes;
  LDefault: IJOSERSAKeyMaterialProvider;
  LMaterial, LReimported: TJOSERSAKeyMaterial;
begin
  LPem := TFile.ReadAllBytes(TPath.Combine(FKeysPath, 'rsa-private.pem'));
  LDefault := TDefaultRSAKeyMaterialProvider.Create;

  LMaterial := LDefault.ImportPEM(LPem);
  LExportedPem := LDefault.ExportPEM(LMaterial, True);
  LReimported := TJOSEProviders.RSAKeyMaterial.ImportPEM(LExportedPem);

  Assert.IsTrue(LReimported.IsPrivate, 'CryptoLib should read the default stack private key PEM');
  Assert.AreEqual<Byte>(LMaterial.Modulus, LReimported.Modulus, 'Modulus should survive the crossing');
  Assert.AreEqual<Byte>(LMaterial.PrivateExponent, LReimported.PrivateExponent, 'PrivateExponent should survive the crossing');

  // The default stack writes public RSA keys as PKCS#1 'RSA PUBLIC KEY', CryptoLib as SPKI
  // 'PUBLIC KEY' - each reader has to accept both.
  LExportedPem := LDefault.ExportPEM(LMaterial, False);
  LReimported := TJOSEProviders.RSAKeyMaterial.ImportPEM(LExportedPem);

  Assert.IsFalse(LReimported.IsPrivate, 'CryptoLib should read the default stack public key PEM');
  Assert.AreEqual<Byte>(LMaterial.Modulus, LReimported.Modulus, 'Modulus should survive the crossing');
  Assert.AreEqual<Byte>(LMaterial.PublicExponent, LReimported.PublicExponent, 'PublicExponent should survive the crossing');
end;

procedure TTestCryptoLibProviders.TestInterop_EC_DefaultExport_ReadByCryptoLib(const AKeyFilePrefix: string);
var
  LPem, LExportedPem: TBytes;
  LDefault: IJOSEECKeyMaterialProvider;
  LMaterial, LReimported: TJOSEECKeyMaterial;
begin
  LPem := TFile.ReadAllBytes(TPath.Combine(FKeysPath, AKeyFilePrefix + '-private.pem'));
  LDefault := TDefaultECKeyMaterialProvider.Create;

  LMaterial := LDefault.ImportPEM(LPem);

  // The default stack writes EC private keys as PKCS#8 'PRIVATE KEY', CryptoLib as SEC1
  // 'EC PRIVATE KEY'; a PKCS#8 EC key decodes to a lone private key, so CryptoLib has to recover
  // the public point from the scalar to fill in x/y.
  LExportedPem := LDefault.ExportPEM(LMaterial, True);
  LReimported := TJOSEProviders.ECKeyMaterial.ImportPEM(LExportedPem);

  Assert.AreEqual(LMaterial.Curve, LReimported.Curve, 'Curve should survive the crossing');
  Assert.IsTrue(LReimported.IsPrivate, 'CryptoLib should read the default stack private key PEM');
  Assert.AreEqual<Byte>(LMaterial.X, LReimported.X, 'X should survive the crossing');
  Assert.AreEqual<Byte>(LMaterial.Y, LReimported.Y, 'Y should survive the crossing');
  Assert.AreEqual<Byte>(LMaterial.D, LReimported.D, 'D should survive the crossing');

  LExportedPem := LDefault.ExportPEM(LMaterial, False);
  LReimported := TJOSEProviders.ECKeyMaterial.ImportPEM(LExportedPem);

  Assert.AreEqual(LMaterial.Curve, LReimported.Curve, 'Curve should survive the crossing');
  Assert.IsFalse(LReimported.IsPrivate, 'CryptoLib should read the default stack public key PEM');
  Assert.AreEqual<Byte>(LMaterial.X, LReimported.X, 'X should survive the crossing');
  Assert.AreEqual<Byte>(LMaterial.Y, LReimported.Y, 'Y should survive the crossing');
end;

initialization
  TDUnitX.RegisterTestFixture(TTestCryptoLibProviders);

end.
