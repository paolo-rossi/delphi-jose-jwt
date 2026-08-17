{******************************************************************************}
{                                                                              }
{  Delphi JOSE-JWT Library                                                     }
{  Copyright (c) 2015 Paolo Rossi                                              }
{  https://github.com/paolo-rossi/delphi-jose-jwt                              }
{                                                                              }
{  Licensed under the MIT license                                              }
{                                                                              }
{******************************************************************************}
unit JOSE.Tests.Providers;

interface

uses
  DUnitX.TestFramework,

  JOSE.Providers,
  JOSE.Providers.Interfaces,
  JOSE.Providers.Default,
  JOSE.Crypto.Algorithms,
  JOSE.Signing.Base,

  JOSE.Tests.Classes;

type
  /// <summary>
  ///   Tests for the IJOSERSAKeyMaterialProvider/IJOSEECKeyMaterialProvider provider
  ///   interfaces and their TDefaultRSAKeyMaterialProvider/TDefaultECKeyMaterialProvider
  ///   (OpenSSL-backed) implementation, plus the TJOSEProviders registration wiring.
  /// </summary>
  [TestFixture]
  [Category('Providers')]
  TTestKeyMaterialProviders = class(TTestBase)
  public
    [Setup]
    procedure Setup;
    [TearDown]
    procedure TearDown;

    [Test]
    procedure TestDefault_RSAKeyMaterial_Registered;
    [Test]
    procedure TestDefault_ECKeyMaterial_Registered;

    [Test]
    procedure TestUnregistered_RSAKeyMaterial_Raises;
    [Test]
    procedure TestUnregistered_ECKeyMaterial_Raises;

    [Test]
    procedure TestKeyMaterialSlots_CanBeClearedIndependentlyOfSigningStack;

    [Test]
    procedure TestRSAKeyMaterial_ImportPEM_ExtractsComponents;
    [Test]
    procedure TestRSAKeyMaterial_ExportPEM_RoundTrips;
    [Test]
    procedure TestRSAKeyMaterial_ExportPEM_PublicOnly;
    [Test]
    procedure TestRSAKeyMaterial_RejectsECPem;

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
    procedure TestECKeyMaterial_RejectsRSAPem;
  end;

  /// <summary>
  ///   Tests for IJOSECertificateProvider. A certificate is caller-supplied
  ///   (TJWS.SetKeyFromCert), and malformed input must come back as an
  ///   ESignException rather than as an access violation
  /// </summary>
  [TestFixture]
  [Category('Providers')]
  TTestCertificateProvider = class(TTestBase)
  public
    [Setup]
    procedure Setup;

    [Test]
    procedure TestEmptyCertificateRaises;
    [Test]
    [TestCase('One byte',        '-')]
    [TestCase('Shorter than the PEM header', '-----BEGIN CERT')]
    [TestCase('Right length, wrong text',    'not a certificate at all!!!')]
    procedure TestTooShortCertificateRaises(const ACertificate: string);
    [Test]
    procedure TestNotACertificateRaises;
  end;

implementation

uses
  System.SysUtils, System.IOUtils;

procedure TTestKeyMaterialProviders.Setup;
begin
  inherited;
  // Make sure every test starts from the default (OpenSSL-backed) stack, regardless of
  // what another fixture left registered.
  TJOSEProviders.RegisterProvider;
end;

procedure TTestKeyMaterialProviders.TearDown;
begin
  TJOSEProviders.RegisterProvider;
  inherited;
end;

procedure TTestKeyMaterialProviders.TestDefault_RSAKeyMaterial_Registered;
begin
  Assert.IsNotNull(TJOSEProviders.RSAKeyMaterial, 'RSAKeyMaterial should be registered by the default provider stack');
end;

procedure TTestKeyMaterialProviders.TestDefault_ECKeyMaterial_Registered;
begin
  Assert.IsNotNull(TJOSEProviders.ECKeyMaterial, 'ECKeyMaterial should be registered by the default provider stack');
end;

procedure TTestKeyMaterialProviders.TestUnregistered_RSAKeyMaterial_Raises;
begin
  TJOSEDefaultProviders.Unregister;

  Assert.WillRaise(
    procedure
    begin
      TJOSEProviders.RSAKeyMaterial;
    end,
    EJOSEProvidersNotRegistered
  );
end;

procedure TTestKeyMaterialProviders.TestUnregistered_ECKeyMaterial_Raises;
begin
  TJOSEDefaultProviders.Unregister;

  Assert.WillRaise(
    procedure
    begin
      TJOSEProviders.ECKeyMaterial;
    end,
    EJOSEProvidersNotRegistered
  );
end;

procedure TTestKeyMaterialProviders.TestKeyMaterialSlots_CanBeClearedIndependentlyOfSigningStack;
begin
  // Both stacks that ship with the library implement raw key import/export, but the two slots stay
  // optional: a caller assigning providers individually can leave them unset.
  TJOSEProviders.RSAKeyMaterial := nil;
  TJOSEProviders.ECKeyMaterial := nil;

  Assert.WillRaise(
    procedure
    begin
      TJOSEProviders.RSAKeyMaterial;
    end,
    EJOSEProvidersNotRegistered,
    'RSAKeyMaterial should raise once cleared'
  );

  Assert.WillRaise(
    procedure
    begin
      TJOSEProviders.ECKeyMaterial;
    end,
    EJOSEProvidersNotRegistered,
    'ECKeyMaterial should raise once cleared'
  );

  // The missing key-material providers must not affect ordinary RSA/ECDSA signing:
  // RequireRSAKeyMaterial/RequireECKeyMaterial must stay independent of RequireSigningStack.
  Assert.WillNotRaise(
    procedure
    begin
      TJOSEProviders.RSA;
      TJOSEProviders.ECDSA;
    end,
    nil,
    'Ordinary RSA/ECDSA signing must still work when the key-material providers are not registered'
  );
end;

procedure TTestKeyMaterialProviders.TestRSAKeyMaterial_ImportPEM_ExtractsComponents;
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

procedure TTestKeyMaterialProviders.TestRSAKeyMaterial_ExportPEM_RoundTrips;
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
end;

procedure TTestKeyMaterialProviders.TestRSAKeyMaterial_ExportPEM_PublicOnly;
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

procedure TTestKeyMaterialProviders.TestRSAKeyMaterial_RejectsECPem;
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

procedure TTestKeyMaterialProviders.TestECKeyMaterial_ImportPEM_ExtractsComponents(const AKeyFilePrefix: string;
  ACurve: TECCurve; AComponentLen: Integer);
var
  LPem: TBytes;
  LMaterial: TJOSEECKeyMaterial;
begin
  LPem := TFile.ReadAllBytes(TPath.Combine(FKeysPath, AKeyFilePrefix + '-private.pem'));
  LMaterial := TJOSEProviders.ECKeyMaterial.ImportPEM(LPem);

  Assert.AreEqual(ACurve, LMaterial.Curve);
  Assert.IsTrue(LMaterial.IsPrivate, 'Imported key should be reported as private');

  // RFC 7518 §§6.2.1.2/6.2.2.1: x, y and d are encoded as fixed-length octet
  // strings. If the big-endian value has leading zero bytes, they MUST be
  // retained (or added as left padding) so the encoded value has the curve's
  // required length.
  Assert.AreEqual<Integer>(AComponentLen, Length(LMaterial.X), 'X should be the full coordinate width');
  Assert.AreEqual<Integer>(AComponentLen, Length(LMaterial.Y), 'Y should be the full coordinate width');
  Assert.AreEqual<Integer>(AComponentLen, Length(LMaterial.D), 'D should be the full order width');
end;

procedure TTestKeyMaterialProviders.TestECKeyMaterial_ExportPEM_RoundTrips(const AKeyFilePrefix: string;
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
end;

procedure TTestKeyMaterialProviders.TestECKeyMaterial_RejectsRSAPem;
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

{ TTestCertificateProvider }

procedure TTestCertificateProvider.Setup;
begin
  inherited;
  TJOSEProviders.RegisterProvider;
end;

procedure TTestCertificateProvider.TestEmptyCertificateRaises;
begin
  // The prefix check used to read @ACertificate[0] before testing the length,
  // so an empty certificate dereferenced nil
  Assert.WillRaise(
    procedure
    begin
      TJOSEProviders.Certificate.PublicKeyFromCertificate([]);
    end,
    ESignException, 'An empty certificate must raise, not fault');
end;

procedure TTestCertificateProvider.TestTooShortCertificateRaises(const ACertificate: string);
begin
  Assert.WillRaise(
    procedure
    begin
      TJOSEProviders.Certificate.PublicKeyFromCertificate(TEncoding.ASCII.GetBytes(ACertificate));
    end,
    ESignException);
end;

procedure TTestCertificateProvider.TestNotACertificateRaises;
begin
  // Correct armour, nothing behind it
  Assert.WillRaise(
    procedure
    begin
      TJOSEProviders.Certificate.PublicKeyFromCertificate(
        TEncoding.ASCII.GetBytes('-----BEGIN CERTIFICATE-----'#10'nonsense'#10'-----END CERTIFICATE-----'));
    end,
    ESignException);
end;

initialization
  TDUnitX.RegisterTestFixture(TTestKeyMaterialProviders);
  TDUnitX.RegisterTestFixture(TTestCertificateProvider);

end.
