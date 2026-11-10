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

  JOSE.Tests.Classes,
  JOSE.Tests.Providers.JWE;

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
    procedure TestSettingTheCertificateProviderInvalidatesBothSigners;

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
    [Test]
    [TestCase('RSA', 'rsa-x509.pem')]
    [TestCase('EC',  'es256-x509.pem')]
    procedure TestPublicKeyEndsWithNewline(const ACertFile: string);
  end;

  /// <summary>The JWE primitives (AES-GCM, RSA-OAEP) on the default OpenSSL (Indy) stack</summary>
  [TestFixture]
  TTestDefaultJWEPrimitives = class(TJWEPrimitivesTestBase)
  protected
    procedure RegisterStack; override;
    procedure UnregisterStack; override;
  end;

  /// <summary>TJWE end to end on the default OpenSSL (Indy) stack</summary>
  [TestFixture]
  TTestDefaultJWETokens = class(TJWETokenTestBase)
  protected
    procedure RegisterStack; override;
    procedure UnregisterStack; override;
  end;

  /// <summary>TJOSE and TJOSEConsumer with JWE on the default OpenSSL (Indy) stack</summary>
  [TestFixture]
  TTestDefaultJWEConsumer = class(TJWEConsumerTestBase)
  protected
    procedure RegisterStack; override;
    procedure UnregisterStack; override;
  end;

  /// <summary>
  ///   The default stack with an OpenSSL that lacks the JWE functions (simulated: the
  ///   JoseSSL load flags are set to "loaded, not available")
  /// </summary>
  [TestFixture]
  TTestDefaultJWEWithoutSupport = class
  public
    [TearDown]
    procedure TearDown;

    [Test]
    procedure JWEReportsTheMissingCapability;
    [Test]
    procedure JWEVersionIsChecked;
    [Test]
    procedure JWSIsUnaffected;
  end;

implementation

uses
  System.SysUtils, System.IOUtils,
  JOSE.Types.Bytes,
  JOSE.Core.JWA,
  JOSE.Core.JWT,
  JOSE.Core.Builder,
  JOSE.OpenSSL.Headers;

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

procedure TTestKeyMaterialProviders.TestSettingTheCertificateProviderInvalidatesBothSigners;
begin
  // Both signers hold the certificate provider they were built with, so both
  // have to be re-registered when it changes. ECDSA used to be left alone,
  // quietly keeping the previous one
  TJOSEProviders.Certificate := TDefaultCertificateProvider.Create;
  try
    Assert.WillRaise(
      procedure begin TJOSEProviders.RSA end,
      EJOSEProvidersNotRegistered, 'RSA must be invalidated');
    Assert.WillRaise(
      procedure begin TJOSEProviders.ECDSA end,
      EJOSEProvidersNotRegistered, 'ECDSA must be invalidated too');
  finally
    TJOSEProviders.RegisterProvider;
  end;

  // ... and a normal registration puts the stack back
  Assert.IsNotNull(TJOSEProviders.RSA);
  Assert.IsNotNull(TJOSEProviders.ECDSA);
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

procedure TTestCertificateProvider.TestPublicKeyEndsWithNewline(const ACertFile: string);
var
  LPem: TBytes;
begin
  // The BIO read loop used to pass the -1 an exhausted memory BIO returns on to ArrayPush,
  // which took it for a count and dropped the final newline.
  LPem := TJOSEProviders.Certificate.PublicKeyFromCertificate(
    TFile.ReadAllBytes(TPath.Combine(TPath.Combine(FKeysPath, 'cert'), ACertFile)));

  Assert.IsTrue(Length(LPem) > 0);
  Assert.AreEqual<Byte>(10, LPem[High(LPem)], 'A PEM should end with a newline');
end;

{ TTestDefaultJWEPrimitives }

procedure TTestDefaultJWEPrimitives.RegisterStack;
begin
  TJOSEProviders.RegisterProvider;
end;

procedure TTestDefaultJWEPrimitives.UnregisterStack;
begin
  TJOSEProviders.UnregisterProvider;
end;

{ TTestDefaultJWETokens }

procedure TTestDefaultJWETokens.RegisterStack;
begin
  TJOSEProviders.RegisterProvider;
end;

procedure TTestDefaultJWETokens.UnregisterStack;
begin
  TJOSEProviders.UnregisterProvider;
end;

{ TTestDefaultJWEConsumer }

procedure TTestDefaultJWEConsumer.RegisterStack;
begin
  TJOSEProviders.RegisterProvider;
end;

procedure TTestDefaultJWEConsumer.UnregisterStack;
begin
  TJOSEProviders.UnregisterProvider;
end;

{ TTestDefaultJWEWithoutSupport }

const
  JWE_TEST_HMAC_SECRET = 'my_very_long_and_safe_secret_key';

procedure SimulateOpenSSLWithoutJWE;
begin
  JoseSSL.FJWESupportLoaded := True;
  JoseSSL.FJWESupportAvailable := False;
end;

procedure TTestDefaultJWEWithoutSupport.TearDown;
begin
  // The next use resolves the symbols again, for real
  JoseSSL.FJWESupportLoaded := False;
  JoseSSL.FJWESupportAvailable := False;
end;

procedure TTestDefaultJWEWithoutSupport.JWEReportsTheMissingCapability;
var
  LKey, LCompact: TJOSEBytes;
  LToken: TJWT;
  LMessage: string;
begin
  LKey := TJOSEBytes.RandomBytes(32);
  LToken := TJWT.Create;
  try
    LToken.Claims.Subject := 'alice';
    LCompact := TJOSE.Encrypt(LKey, LToken, TJOSEAlgorithmId.Dir, TJOSEEncryptionAlgorithmId.A256GCM);

    SimulateOpenSSLWithoutJWE;

    // Encryption and decryption alike say what is missing: on decryption it must not
    // turn into the generic "JWE decryption failed"
    LMessage := '';
    try
      TJOSE.Decrypt(LKey, LCompact).Free;
    except
      on E: EJOSEProvidersNotRegistered do
        LMessage := E.Message;
    end;
    Assert.Contains(LMessage, '1.0.2', 'Decrypt');

    LMessage := '';
    try
      TJOSE.Encrypt(LKey, LToken, TJOSEAlgorithmId.Dir, TJOSEEncryptionAlgorithmId.A256GCM);
    except
      on E: EJOSEProvidersNotRegistered do
        LMessage := E.Message;
    end;
    Assert.Contains(LMessage, '1.0.2', 'Encrypt');
  finally
    LToken.Free;
  end;
end;

procedure TTestDefaultJWEWithoutSupport.JWEVersionIsChecked;
var
  LKey: TJOSEBytes;
  LToken: TJWT;
begin
  // A real JWE operation loads the library and resolves the JWE symbols first,
  // so the checks below have something to look at
  LKey := TJOSEBytes.RandomBytes(32);
  LToken := TJWT.Create;
  try
    LToken.Claims.Subject := 'alice';
    TJOSE.Encrypt(LKey, LToken, TJOSEAlgorithmId.Dir, TJOSEEncryptionAlgorithmId.A256GCM);
  finally
    LToken.Free;
  end;

  // 1.0.2 is the first release whose RSA-OAEP digest controls JWE needs:
  // OPENSSL_VERSION_NUMBER is 0xMNNFFPPS, so 1.0.1 sorts below 1.0.2
  Assert.IsFalse(JoseSSL.VersionSupportsJWE(0), 'No version must not pass');
  Assert.IsFalse(JoseSSL.VersionSupportsJWE($1000100F), '1.0.1 final must not pass');
  Assert.IsTrue(JoseSSL.VersionSupportsJWE($10002000), '1.0.2 must pass');
  Assert.IsTrue(JoseSSL.VersionSupportsJWE($1000200F), '1.0.2 final must pass');
  Assert.IsTrue(JoseSSL.VersionSupportsJWE($10100000), '1.1.0 must pass');

  // And the library the suite runs against is one of the accepted ones
  Assert.IsTrue(JoseSSL.EnsureJWESupport, 'The OpenSSL in Tests\Exe must support JWE');
end;

procedure TTestDefaultJWEWithoutSupport.JWSIsUnaffected;
var
  LToken, LRead: TJWT;
  LCompact: TJOSEBytes;
begin
  SimulateOpenSSLWithoutJWE;

  LToken := TJWT.Create;
  try
    LToken.Claims.Subject := 'alice';
    LCompact := TJOSE.SerializeCompact(TJOSEBytes(JWE_TEST_HMAC_SECRET), TJOSEAlgorithmId.HS256, LToken);
  finally
    LToken.Free;
  end;

  LRead := TJOSE.Verify(TJOSEBytes(JWE_TEST_HMAC_SECRET), LCompact);
  try
    Assert.IsTrue(Assigned(LRead) and LRead.Verified);
  finally
    LRead.Free;
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TTestKeyMaterialProviders);
  TDUnitX.RegisterTestFixture(TTestDefaultJWEPrimitives);
  TDUnitX.RegisterTestFixture(TTestDefaultJWETokens);
  TDUnitX.RegisterTestFixture(TTestDefaultJWEConsumer);
  TDUnitX.RegisterTestFixture(TTestDefaultJWEWithoutSupport);
  TDUnitX.RegisterTestFixture(TTestCertificateProvider);

end.
