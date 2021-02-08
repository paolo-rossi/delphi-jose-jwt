{******************************************************************************}
{                                                                              }
{  Delphi JOSE Library                                                         }
{  Copyright (c) 2015-2021 Paolo Rossi                                         }
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
unit JOSE.Tests.JWA.HMAC;

interface

uses
  System.Rtti, System.SysUtils, DUnitX.TestFramework,

  JOSE.Core.JWT,
  JOSE.Core.JWS,
  JOSE.Core.JWK,
  JOSE.Core.JWA,
  JOSE.Hashing.HMAC,
  JOSE.Signing.Base,

  JOSE.Tests.Classes;

type
  [TestFixture]
  TTestHMAC = class(TTestBase)
  private const
    SECRET = 'my-super-secret-hmacsha-key-for-test';
    COMPACT_PAYLOAD = 'eyJpYXQiOjE1MTYyMzkwMjIsImV4cCI6MTUxNjI0OTAyMiwiaXNzIjoiRGVscGhpIEpPU0UgYW5kIEpXVCBMaWJyYXJ5In0';
  public
    [Setup]
    procedure Setup;
    [TearDown]
    procedure TearDown;

    [Test]
    [TestCase('TestHMACSign256', 'HS256,jHok3-EqiaoiWxBQ9Gh84Kc6vIrNM1NeoNRiPBHaTAA')]
    [TestCase('TestHMACSign384', 'HS384,WrDaePkHG0cJMuRXHCz0pY5lt_Is4ZEYw139qt7o-zx40Ze90osIZ8ZhOX5VipE-')]
    [TestCase('TestHMACSign512', 'HS512,wSSOeaU_UlEhOiGksvDZaKdcIJBBDD_cEj_pLhTdW5VK-XeZL5L1LxgJyOArMAOZBaPe-iwKW6UFLy3YlTQr_A')]
    procedure TestHMACSign(AAlg: TJOSEAlgorithmId; const ASignature: string);

    [Test]
    [TestCase('TestHMACVerify256', 'HS256,eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9,jHok3-EqiaoiWxBQ9Gh84Kc6vIrNM1NeoNRiPBHaTAA')]
    [TestCase('TestHMACVerify384', 'HS384,eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9,WrDaePkHG0cJMuRXHCz0pY5lt_Is4ZEYw139qt7o-zx40Ze90osIZ8ZhOX5VipE-')]
    [TestCase('TestHMACVerify512', 'HS512,eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9,wSSOeaU_UlEhOiGksvDZaKdcIJBBDD_cEj_pLhTdW5VK-XeZL5L1LxgJyOArMAOZBaPe-iwKW6UFLy3YlTQr_A')]
    procedure TestHMACVerify(AAlg: TJOSEAlgorithmId; const AHeader, ASignature: string);

  end;

implementation

uses
  System.IOUtils, System.DateUtils,
  JOSE.Tests.Utils;

procedure TTestHMAC.Setup;
begin

end;

procedure TTestHMAC.TearDown;
begin
end;

procedure TTestHMAC.TestHMACSign(AAlg: TJOSEAlgorithmId; const ASignature: string);
var
  LToken: TJWT;
  LSigner: TJWS;
  LKey: TJWK;
  LSignature, LCompact: string;
begin
  LToken := TJWT.Create;
  try
    LToken.Claims.IssuedAt := UnixToDateTime(1516239022, False);
    LToken.Claims.Expiration := UnixToDateTime(1516249022, False);
    LToken.Claims.Issuer := 'Delphi JOSE and JWT Library';

    LSigner := TJWS.Create(LToken);
    try
      LKey := TJWK.Create(SECRET);
      try
        // With this option you can have keys < algorithm length
        LSigner.SkipKeyValidation := True;

        LSigner.Sign(LKey, AAlg);
        LCompact := LSigner.CompactToken;
        LSignature := LSigner.Signature;
        Assert.AreEqual(ASignature, LSignature, 'Expected signature doesn''t match calculated signature');
      finally
        LKey.Free;
      end;
    finally
      LSigner.Free;
    end;
  finally
    LToken.Free;
  end;
end;

procedure TTestHMAC.TestHMACVerify(AAlg: TJOSEAlgorithmId; const AHeader, ASignature: string);
var
  LKey: TJWK;
  LToken: TJWT;
  LSigner: TJWS;
  LCompact: string;
begin
  LKey := TJWK.Create(SECRET);
  try
    LToken := TJWT.Create;
    try
      LSigner := TJWS.Create(LToken);
      try
        LSigner.SetKey(LKey);
        LSigner.SkipKeyValidation := True;
        LCompact := AHeader + '.' + COMPACT_PAYLOAD + '.' + ASignature;
        LSigner.CompactToken := LCompact;

        Assert.IsTrue(LSigner.VerifySignature, 'Signature (HMAC) should validate');
      finally
        LSigner.Free;
      end;
    finally
      LToken.Free;
    end;
  finally
    LKey.Free;
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TTestHMAC);

end.

