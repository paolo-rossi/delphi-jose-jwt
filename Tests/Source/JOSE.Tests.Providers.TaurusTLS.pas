{******************************************************************************}
{                                                                              }
{  Delphi JOSE Library                                                        }
{  Copyright (c) 2015 Paolo Rossi                                             }
{  https://github.com/paolo-rossi/delphi-jose-jwt                             }
{                                                                              }
{******************************************************************************}
{                                                                              }
{  Licensed under the Apache License, Version 2.0 (the "License");            }
{  you may not use this file except in compliance with the License.           }
{  You may obtain a copy of the License at                                    }
{                                                                              }
{      http://www.apache.org/licenses/LICENSE-2.0                             }
{                                                                              }
{  Unless required by applicable law or agreed to in writing, software        }
{  distributed under the License is distributed on an "AS IS" BASIS,          }
{  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.   }
{  See the License for the specific language governing permissions and       }
{  limitations under the License.                                            }
{                                                                              }
{******************************************************************************}

/// <summary>
///   Tests for the TaurusTLS-backed provider stack (TJOSETaurusTLSProviders,
///   JOSE.Providers.TaurusTLS). Built by its own project, Tests\JOSE.Tests.TaurusTLS.dproj
///   (kept separate from Tests\JOSE.Tests.dproj since this stack is optional/opt-in),
///   which adds Libs\TaurusTLS\Source to the unit search path so the provider compiles
///   straight from source (no separate package build needed). Requires real OpenSSL
///   1.1.x/3.x/4.x DLLs (libcrypto-3-x64.dll/libssl-3-x64.dll or the "-4" equivalents,
///   see Libs\TaurusTLS\OpenSSL\binaries\README.md) discoverable at runtime - already
///   present alongside the built exe in Tests\Exe.
/// </summary>
unit JOSE.Tests.Providers.TaurusTLS;

interface

uses
  DUnitX.TestFramework,

  JOSE.Providers,
  JOSE.Providers.Interfaces,
  JOSE.Providers.TaurusTLS,
  JOSE.Crypto.Algorithms,
  JOSE.Signing.Base,

  JOSE.Tests.Classes;

type
  /// <summary>
  ///   Verifies TJOSETaurusTLSProviders registers working RSA/ECDSA signing and
  ///   RSA/EC JWK key-material providers, exercised against the same fixed test
  ///   keys under Tests\Keys used by JOSE.Tests.Providers.pas (the OpenSSL 1.x/
  ///   Indy-backed default stack) - so the two stacks are directly comparable.
  /// </summary>
  [TestFixture]
  [Category('Providers')]
  TTestTaurusTLSProviders = class(TTestBase)
  public
    [Setup]
    procedure Setup;
    [TearDown]
    procedure TearDown;

    [Test]
    procedure TestTaurusTLS_AllProvidersRegistered;

    [Test]
    procedure TestRSA_SignVerify_RoundTrips;
    [Test]
    procedure TestRSA_Verify_RejectsTamperedSignature;

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
    procedure TestInterop_PSS_TaurusTLSSignature_VerifiedByDefaultStack(AAlg: TRSAAlgorithm);

    [Test]
    [TestCase('ES256', 'es256')]
    [TestCase('ES256K', 'es256k')]
    [TestCase('ES384', 'es384')]
    [TestCase('ES512', 'es512')]
    procedure TestECDSA_SignVerify_RoundTrips(const AKeyFilePrefix: string);

    [Test]
    procedure TestRSAKeyMaterial_ImportExportPEM_RoundTrips;
    [Test]
    procedure TestRSAKeyMaterial_RejectsECPem;

    [Test]
    [TestCase('P256', 'es256,P256')]
    [TestCase('secp256k1', 'es256k,secp256k1')]
    [TestCase('P384', 'es384,P384')]
    [TestCase('P521', 'es512,P521')]
    procedure TestECKeyMaterial_ImportExportPEM_RoundTrips(const AKeyFilePrefix: string; ACurve: TECCurve);

    [Test]
    procedure TestECKeyMaterial_RejectsRSAPem;
  end;

implementation

uses
  System.SysUtils, System.IOUtils,
  JOSE.Providers.Default;   // for the cross-stack PSS interop test

procedure TTestTaurusTLSProviders.Setup;
begin
  inherited;
  TJOSETaurusTLSProviders.Register;
end;

procedure TTestTaurusTLSProviders.TearDown;
begin
  TJOSETaurusTLSProviders.Unregister;
  // Restore the default (OpenSSL 1.x/Indy-backed) stack for whichever fixture runs next.
  TJOSEProviders.RegisterProvider;
  inherited;
end;

procedure TTestTaurusTLSProviders.TestTaurusTLS_AllProvidersRegistered;
begin
  Assert.IsNotNull(TJOSEProviders.Base64, 'Base64 should be registered');
  Assert.IsNotNull(TJOSEProviders.HMAC, 'HMAC should be registered');
  Assert.IsNotNull(TJOSEProviders.Certificate, 'Certificate should be registered');
  Assert.IsNotNull(TJOSEProviders.RSA, 'RSA should be registered');
  Assert.IsNotNull(TJOSEProviders.ECDSA, 'ECDSA should be registered');
  Assert.IsNotNull(TJOSEProviders.RSAKeyMaterial, 'RSAKeyMaterial should be registered');
  Assert.IsNotNull(TJOSEProviders.ECKeyMaterial, 'ECKeyMaterial should be registered');
end;

procedure TTestTaurusTLSProviders.TestRSA_PSS_SignVerifyRoundTrip(AAlg: TRSAAlgorithm);
var
  LPrivateKey, LPublicKey, LInput, LSignature: TBytes;
begin
  LPrivateKey := TFile.ReadAllBytes(TPath.Combine(FKeysPath, 'rsa-private.pem'));
  LPublicKey := TFile.ReadAllBytes(TPath.Combine(FKeysPath, 'rsa-public.pem'));
  LInput := TEncoding.UTF8.GetBytes('The quick brown fox jumps over the lazy dog');

  LSignature := TJOSEProviders.RSA.Sign(LInput, LPrivateKey, AAlg);
  Assert.IsTrue(TJOSEProviders.RSA.Verify(LInput, LSignature, LPublicKey, AAlg));

  // The padding scheme has to be part of the identity of the signature, not just of the header.
  Assert.IsFalse(TJOSEProviders.RSA.Verify(LInput, LSignature, LPublicKey, TRSAAlgorithm.RS256),
    'A PSS signature must not verify as PKCS#1 v1.5');
end;

procedure TTestTaurusTLSProviders.TestRSA_PSS_SignaturesAreNonDeterministic(AAlg: TRSAAlgorithm);
var
  LPrivateKey, LPublicKey, LInput, LFirst, LSecond: TBytes;
begin
  LPrivateKey := TFile.ReadAllBytes(TPath.Combine(FKeysPath, 'rsa-private.pem'));
  LPublicKey := TFile.ReadAllBytes(TPath.Combine(FKeysPath, 'rsa-public.pem'));
  LInput := TEncoding.UTF8.GetBytes('The quick brown fox jumps over the lazy dog');

  LFirst := TJOSEProviders.RSA.Sign(LInput, LPrivateKey, AAlg);
  LSecond := TJOSEProviders.RSA.Sign(LInput, LPrivateKey, AAlg);

  // PSS draws a fresh salt per signature. Identical output would mean the provider had fallen
  // back to the deterministic PKCS#1 v1.5 path.
  Assert.AreNotEqual<TBytes>(LFirst, LSecond, 'PSS signatures must differ between signings');
  Assert.IsTrue(TJOSEProviders.RSA.Verify(LInput, LFirst, LPublicKey, AAlg));
  Assert.IsTrue(TJOSEProviders.RSA.Verify(LInput, LSecond, LPublicKey, AAlg));
end;

procedure TTestTaurusTLSProviders.TestInterop_PSS_TaurusTLSSignature_VerifiedByDefaultStack(AAlg: TRSAAlgorithm);
var
  LPrivateKey, LPublicKey, LInput, LSignature: TBytes;
begin
  LPrivateKey := TFile.ReadAllBytes(TPath.Combine(FKeysPath, 'rsa-private.pem'));
  LPublicKey := TFile.ReadAllBytes(TPath.Combine(FKeysPath, 'rsa-public.pem'));
  LInput := TEncoding.UTF8.GetBytes('The quick brown fox jumps over the lazy dog');

  // Signed by TaurusTLS (registered in Setup)...
  LSignature := TJOSEProviders.RSA.Sign(LInput, LPrivateKey, AAlg);

  // ...verified by the Default stack, which reaches OpenSSL through entirely separate bindings.
  TJOSEDefaultProviders.Register;
  try
    Assert.IsTrue(TJOSEProviders.RSA.Verify(LInput, LSignature, LPublicKey, AAlg));
  finally
    TJOSETaurusTLSProviders.Register;
  end;
end;

procedure TTestTaurusTLSProviders.TestRSA_SignVerify_RoundTrips;
var
  LPrivateKey, LPublicKey, LInput, LSignature: TBytes;
begin
  LPrivateKey := TFile.ReadAllBytes(TPath.Combine(FKeysPath, 'rsa-private.pem'));
  LPublicKey := TFile.ReadAllBytes(TPath.Combine(FKeysPath, 'rsa-public.pem'));
  LInput := TEncoding.UTF8.GetBytes('The quick brown fox jumps over the lazy dog');

  LSignature := TJOSEProviders.RSA.Sign(LInput, LPrivateKey, TRSAAlgorithm.RS256);
  Assert.IsTrue(Length(LSignature) > 0, 'Signature should not be empty');
  Assert.IsTrue(TJOSEProviders.RSA.Verify(LInput, LSignature, LPublicKey, TRSAAlgorithm.RS256),
    'Signature should verify against the matching public key');
end;

procedure TTestTaurusTLSProviders.TestRSA_Verify_RejectsTamperedSignature;
var
  LPrivateKey, LPublicKey, LInput, LSignature: TBytes;
begin
  LPrivateKey := TFile.ReadAllBytes(TPath.Combine(FKeysPath, 'rsa-private.pem'));
  LPublicKey := TFile.ReadAllBytes(TPath.Combine(FKeysPath, 'rsa-public.pem'));
  LInput := TEncoding.UTF8.GetBytes('The quick brown fox jumps over the lazy dog');

  LSignature := TJOSEProviders.RSA.Sign(LInput, LPrivateKey, TRSAAlgorithm.RS256);
  LSignature[0] := LSignature[0] xor $FF;

  Assert.IsFalse(TJOSEProviders.RSA.Verify(LInput, LSignature, LPublicKey, TRSAAlgorithm.RS256),
    'A tampered signature must not verify');
end;

procedure TTestTaurusTLSProviders.TestECDSA_SignVerify_RoundTrips(const AKeyFilePrefix: string);
var
  LPrivateKey, LPublicKey, LInput, LSignature: TBytes;
  LAlg: TECDSAAlgorithm;
begin
  LAlg.FromString('ES' + UpperCase(AKeyFilePrefix).Substring(2));
  LPrivateKey := TFile.ReadAllBytes(TPath.Combine(FKeysPath, AKeyFilePrefix + '-private.pem'));
  LPublicKey := TFile.ReadAllBytes(TPath.Combine(FKeysPath, AKeyFilePrefix + '-public.pem'));
  LInput := TEncoding.UTF8.GetBytes('The quick brown fox jumps over the lazy dog');

  LSignature := TJOSEProviders.ECDSA.Sign(LInput, LPrivateKey, LAlg);
  Assert.IsTrue(Length(LSignature) > 0, 'Signature should not be empty');
  Assert.IsTrue(TJOSEProviders.ECDSA.Verify(LInput, LSignature, LPublicKey, LAlg),
    'Signature should verify against the matching public key');
end;

procedure TTestTaurusTLSProviders.TestRSAKeyMaterial_ImportExportPEM_RoundTrips;
var
  LPem, LExportedPem: TBytes;
  LMaterial, LReimported: TJOSERSAKeyMaterial;
begin
  LPem := TFile.ReadAllBytes(TPath.Combine(FKeysPath, 'rsa-private.pem'));
  LMaterial := TJOSEProviders.RSAKeyMaterial.ImportPEM(LPem);

  Assert.IsTrue(LMaterial.IsPrivate, 'Imported key should be reported as private');
  Assert.IsTrue(Length(LMaterial.Modulus) > 0, 'Modulus should not be empty');

  LExportedPem := TJOSEProviders.RSAKeyMaterial.ExportPEM(LMaterial, True);
  LReimported := TJOSEProviders.RSAKeyMaterial.ImportPEM(LExportedPem);

  Assert.IsTrue(LReimported.IsPrivate, 'Re-imported key should still be private');
  Assert.AreEqual<Byte>(LMaterial.Modulus, LReimported.Modulus, 'Modulus should round-trip exactly');
  Assert.AreEqual<Byte>(LMaterial.PublicExponent, LReimported.PublicExponent, 'PublicExponent should round-trip exactly');
  Assert.AreEqual<Byte>(LMaterial.PrivateExponent, LReimported.PrivateExponent, 'PrivateExponent should round-trip exactly');
end;

procedure TTestTaurusTLSProviders.TestRSAKeyMaterial_RejectsECPem;
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

procedure TTestTaurusTLSProviders.TestECKeyMaterial_ImportExportPEM_RoundTrips(const AKeyFilePrefix: string;
  ACurve: TECCurve);
var
  LPem, LExportedPem: TBytes;
  LMaterial, LReimported: TJOSEECKeyMaterial;
begin
  LPem := TFile.ReadAllBytes(TPath.Combine(FKeysPath, AKeyFilePrefix + '-private.pem'));
  LMaterial := TJOSEProviders.ECKeyMaterial.ImportPEM(LPem);

  Assert.AreEqual(ACurve, LMaterial.Curve);
  Assert.IsTrue(LMaterial.IsPrivate, 'Imported key should be reported as private');

  LExportedPem := TJOSEProviders.ECKeyMaterial.ExportPEM(LMaterial, True);
  LReimported := TJOSEProviders.ECKeyMaterial.ImportPEM(LExportedPem);

  Assert.AreEqual(ACurve, LReimported.Curve);
  Assert.IsTrue(LReimported.IsPrivate, 'Re-imported key should still be private');
  Assert.AreEqual<Byte>(LMaterial.X, LReimported.X, 'X should round-trip exactly');
  Assert.AreEqual<Byte>(LMaterial.Y, LReimported.Y, 'Y should round-trip exactly');
end;

procedure TTestTaurusTLSProviders.TestECKeyMaterial_RejectsRSAPem;
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

initialization
  TDUnitX.RegisterTestFixture(TTestTaurusTLSProviders);

end.
