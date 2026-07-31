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

unit JOSE.Tests.CryptoLib;

interface

uses
  DUnitX.TestFramework,

  JOSE.Tests.Classes,
  JOSE.Core.JWT,
  JOSE.Core.JWS,
  JOSE.Core.JWA,
  JOSE.Signing.RSA,
  JOSE.Signing.ECDSA,
  JOSE.Providers,
  JOSE.Providers.CryptoLib,
  JOSE.Hashing.HMAC,
  JOSE.Crypto.Algorithms,
  JOSE.Encoding.Base64;

type
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
    procedure TestECDSA_Verify_ES256_Token;
  end;

implementation

uses
  System.SysUtils,
  System.IOUtils;

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

initialization
  TDUnitX.RegisterTestFixture(TTestCryptoLibProviders);

end.
