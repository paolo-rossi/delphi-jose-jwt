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
{  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.    }
{  See the License for the specific language governing permissions and        }
{  limitations under the License.                                             }
{                                                                              }
{******************************************************************************}
unit JOSE.Tests.JWK;

interface

uses
  System.SysUtils, System.Rtti, DUnitX.TestFramework,

  JOSE.Types.Bytes,
  JOSE.Core.JWT,
  JOSE.Core.JWA,
  JOSE.Core.JWK,
  JOSE.Core.Builder,
  JOSE.Encoding.Base64,

  JOSE.Tests.Classes;

type
  [TestFixture]
  TTestJWK = class(TTestBase)
  public
    [Setup]
    procedure Setup;
    [TearDown]
    procedure TearDown;

    [Test]
    procedure TestOct_CreateAndJSONRoundTrip;

    [Test]
    procedure TestRSA_Thumbprint_RFC7638Vector;

    [Test]
    procedure TestRSA_FromPEM_ToPEM_SignVerify;

    [Test]
    [TestCase('ES256', 'ES256,es256,P256')]
    [TestCase('ES256K', 'ES256K,es256k,secp256k1')]
    [TestCase('ES384', 'ES384,es384,P384')]
    [TestCase('ES512', 'ES512,es512,P521')]
    procedure TestEC_FromPEM_ToPEM_SignVerify(AAlg: TJOSEAlgorithmId; const AKeyFilePrefix: string; ACurve: TJOSEEllipticCurve);

    [Test]
    procedure TestJWKS_RoundTrip;
  end;

implementation

uses
  System.IOUtils;

procedure TTestJWK.Setup;
begin
end;

procedure TTestJWK.TearDown;
begin
end;

procedure TTestJWK.TestOct_CreateAndJSONRoundTrip;
var
  LJWK, LParsed: TJSONWebKey;
  LJson: string;
begin
  LJWK := TJSONWebKey.CreateOct('my-shared-secret-0123456789');
  try
    Assert.AreEqual(TJOSEKeyType.Oct, LJWK.Kty);
    Assert.IsTrue(LJWK.IsPrivate);
    Assert.AreEqual('my-shared-secret-0123456789', LJWK.K.AsString);

    LJson := LJWK.ToJSON;
  finally
    LJWK.Free;
  end;

  LParsed := TJSONWebKey.FromJSON(LJson);
  try
    Assert.AreEqual(TJOSEKeyType.Oct, LParsed.Kty);
    Assert.AreEqual('my-shared-secret-0123456789', LParsed.K.AsString);
  finally
    LParsed.Free;
  end;
end;

procedure TTestJWK.TestRSA_Thumbprint_RFC7638Vector;
const
  // RFC 7638 Appendix A.1 worked example
  N = '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw';
  E = 'AQAB';
  EXPECTED_THUMBPRINT = 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs';
var
  LJWK: TJSONWebKey;
begin
  LJWK := TJSONWebKey.CreateRSAPublic(TBase64.URLDecode(N), TBase64.URLDecode(E));
  try
    Assert.AreEqual(EXPECTED_THUMBPRINT, LJWK.Thumbprint.AsString);
  finally
    LJWK.Free;
  end;
end;

procedure TTestJWK.TestRSA_FromPEM_ToPEM_SignVerify;
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
    Assert.IsFalse(LJWK.N.IsEmpty);
    Assert.IsFalse(LJWK.E.IsEmpty);

    LKeyPair := LJWK.ToKeyPair;
    try
      LToken := TJWT.Create;
      try
        LToken.Claims.Subject := 'jwk-rsa-roundtrip';
        LCompact := TJOSE.SerializeCompact(LKeyPair.PrivateKey, TJOSEAlgorithmId.RS256, LToken);
      finally
        LToken.Free;
      end;

      LVerified := TJOSE.Verify(LKeyPair.PublicKey, LCompact);
      try
        Assert.AreEqual('jwk-rsa-roundtrip', LVerified.Claims.Subject);
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

procedure TTestJWK.TestEC_FromPEM_ToPEM_SignVerify(AAlg: TJOSEAlgorithmId; const AKeyFilePrefix: string;
  ACurve: TJOSEEllipticCurve);
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
    Assert.IsFalse(LJWK.X.IsEmpty);
    Assert.IsFalse(LJWK.Y.IsEmpty);

    LKeyPair := LJWK.ToKeyPair;
    try
      LToken := TJWT.Create;
      try
        LToken.Claims.Subject := 'jwk-ec-roundtrip';
        LCompact := TJOSE.SerializeCompact(LKeyPair.PrivateKey, AAlg, LToken);
      finally
        LToken.Free;
      end;

      LVerified := TJOSE.Verify(LKeyPair.PublicKey, LCompact);
      try
        Assert.AreEqual('jwk-ec-roundtrip', LVerified.Claims.Subject);
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

procedure TTestJWK.TestJWKS_RoundTrip;
var
  LSet, LParsed: TJSONWebKeySet;
  LKey1, LKey2: TJSONWebKey;
  LFound: TJSONWebKey;
  LJson: string;
begin
  LSet := TJSONWebKeySet.Create;
  try
    LKey1 := TJSONWebKey.CreateOct('secret-one');
    LKey1.Kid := 'key-one';
    LSet.AddKey(LKey1);

    LKey2 := TJSONWebKey.CreateRSAPublic(TBase64.URLDecode('0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78L'), TBase64.URLDecode('AQAB'));
    LKey2.Kid := 'key-two';
    LSet.AddKey(LKey2);

    Assert.AreEqual<Integer>(2, LSet.Keys.Count);

    LJson := LSet.ToJSON;
  finally
    LSet.Free;
  end;

  LParsed := TJSONWebKeySet.FromJSON(LJson);
  try
    Assert.AreEqual<Integer>(2, LParsed.Keys.Count);

    LFound := LParsed.FindByKid('key-one');
    Assert.IsNotNull(LFound, 'key-one should be found in the parsed JWKS');
    Assert.AreEqual(TJOSEKeyType.Oct, LFound.Kty);
    Assert.AreEqual('secret-one', LFound.K.AsString);

    LFound := LParsed.FindByKid('key-two');
    Assert.IsNotNull(LFound, 'key-two should be found in the parsed JWKS');
    Assert.AreEqual(TJOSEKeyType.RSA, LFound.Kty);
  finally
    LParsed.Free;
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TTestJWK);

end.
