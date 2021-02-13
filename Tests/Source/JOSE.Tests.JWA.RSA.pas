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
unit JOSE.Tests.JWA.RSA;

interface

uses
  System.Classes, System.Rtti, System.SysUtils, DUnitX.TestFramework,

  JOSE.Core.JWT,
  JOSE.Core.JWS,
  JOSE.Core.JWK,
  JOSE.Core.JWA,
  JOSE.Signing.Base,
  JOSE.Signing.RSA,

  JOSE.Tests.Classes;

type
  [TestFixture]
  [Category('RSA')]
  TTestJWA = class(TTestBase)
  private const
    COMPACT_PAYLOAD = 'eyJpYXQiOjE1MTYyMzkwMjIsImV4cCI6MTUxNjI0OTAyMiwiaXNzIjoiRGVscGhpIEpPU0UgYW5kIEpXVCBMaWJyYXJ5In0';
    SIGN_RS256 =
      'puUywUz6ExPzAX6lDFhQ2kItfxwjVVBQ77gq5uFOkoN3SWSYqgHK02FnyLf4zl57OjTgVZzhSYM2FUPmmuH9UcOikLGpbuv0qd6_bdgFBrWeQbxD_Iup1t4spcADliT9SH-EaEqkQ4UYbVkBj3Xbv7pTF2otKcteU19lcwF8ayKcqCRWK' +
      '8VCXGZKCugle7fVME3FcuECsDa-HnVe4SpXCJ8m8Gt3hWD8S3ui8j5CnxNGMByS4qSLXcmRlg1DqoGjnZp34KRjbI_bnPe8X_VIQ9srJPhMAQ-vBuRSHMaq3Vjo6K1a3RBrN9lK1Z7_so3tq76PgOGYCPGHm7ymnBO2Og';
    SIGN_RS384 =
      'VffJTuXJgSIRjiltPJIAHxYaRipjmi5v7SVwzuTcKlT8GW-r7BdDg4zyMxzVRCFjy9YGmOECIxL1oaj_KV14V-mTHQwTHKDCASVzPPku9NNIEeUJlD-2Klg0--4QsCnBjar6dJQdEewXBJSoumBnE8PXWjV6qX5PuxO7Dv1XSbPDx1qkv' +
      'qO5KZxLkxviMk9WZ8-AYDXVqfxvXIfSUWj9vQx002xPPl66GoTfvzJtB0IuEBLfjPo8ZfcwgDh5ukzwd46bXeAwpCE6LFjle4OXS8FES136MrDWAdmoQAIvys8yOb-SWpaUpaDKeSaKCny1rpLx5QLPzAPZCUdQZ7K-Mw';
    SIGN_RS512 =
      'v5999Qte0ENzgRX1kDLusP8dgTFWX2wcckfYsiDN7SSROAh9Dpx3lNMOd1GnXTTyBoSCn3NzjxsVzqFn2su0oh-eMHa94UBPBZ-6iZrpYLzm1Wy761tideYONq-QoQg492cmp7Jbzu2sZOti3If2xEQYF0dPzGk48weN1d87vG6Sv8UA7' +
      'yWAoAOvKz9UJzURKdRNAVsETVdRBEG6mmPawv1v-N1xljwdJSnLLRmcGYEBZeJLjTWL973asL8I2gEwHzEqmuNp4TE5NBoXg5xAJQ62iwSWNcnPbupmh3SbatwPwVOmHotzDyrCCG_FKwQnmhHC7efRm3L9TizRueBLfA';
  private
    FKeys: TKeyPair;
  public
    [Setup]
    procedure Setup;
    [TearDown]
    procedure TearDown;
    [Test]
    [TestCase('TestRSASign256', 'RS256,' + SIGN_RS256)]
    [TestCase('TestRSASign384', 'RS384,' + SIGN_RS384)]
    [TestCase('TestRSASign512', 'RS512,' + SIGN_RS512)]
    procedure TestRSASign(AAlg: TJOSEAlgorithmId; const ASignature: string);

    [Test]
    [TestCase('TestRSAVerify256', 'RS256,eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9,' + SIGN_RS256)]
    [TestCase('TestRSAVerify384', 'RS384,eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzM4NCJ9,' + SIGN_RS384)]
    [TestCase('TestRSAVerify512', 'RS512,eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiJ9,' + SIGN_RS512)]
    procedure TestRSAVerify(AAlg: TJOSEAlgorithmId; const AHeader, ASignature: string);
  end;

implementation

uses
  System.DateUtils, System.IOUtils,
  JOSE.Tests.Utils;

procedure TTestJWA.Setup;
var
  LFileName: string;
begin
  FKeys := TKeyPair.Create;

  LFileName := TPath.Combine(FKeysPath, 'rsa-private.pem');
  FKeys.PrivateKey.Key :=  TFile.ReadAllBytes(LFileName);

  LFileName := TPath.Combine(FKeysPath, 'rsa-public.pem');
  FKeys.PublicKey.Key :=  TFile.ReadAllBytes(LFileName);
end;

procedure TTestJWA.TearDown;
begin
  FreeAndNil(FKeys);
end;

procedure TTestJWA.TestRSASign(AAlg: TJOSEAlgorithmId; const ASignature: string);
var
  LToken: TJWT;
  LSigner: TJWS;
  LSignature, LCompact: string;
begin
  LToken := TJWT.Create;
  try
    LToken.Header.Algorithm := AAlg.AsString;
    LToken.Claims.IssuedAt := UnixToDateTime(1516239022, False);
    LToken.Claims.Expiration := UnixToDateTime(1516249022, False);
    LToken.Claims.Issuer := 'Delphi JOSE and JWT Library';

    LSigner := TJWS.Create(LToken);
    try
      // With this option you can have keys < algorithm length
      LSigner.SkipKeyValidation := True;

      LSigner.Sign(FKeys.PrivateKey, AAlg);
      LCompact := LSigner.CompactToken;
      LSignature := LSigner.Signature;

      Assert.AreEqual(ASignature, LSignature, 'Expected signature doesn''t match calculated signature');
    finally
      LSigner.Free;
    end;
  finally
    LToken.Free;
  end;
end;

procedure TTestJWA.TestRSAVerify(AAlg: TJOSEAlgorithmId; const AHeader, ASignature: string);
var
  LToken: TJWT;
  LSigner: TJWS;
  LCompact: string;
begin
  LToken := TJWT.Create;
  try
    LSigner := TJWS.Create(LToken);
    try
      LSigner.SetKey(FKeys.PublicKey);
      LSigner.SkipKeyValidation := True;
      LCompact := AHeader + '.' + COMPACT_PAYLOAD + '.' + ASignature;
      LSigner.CompactToken := LCompact;

      Assert.IsTrue(LSigner.VerifySignature, 'Signature (RSA) should validate');
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

