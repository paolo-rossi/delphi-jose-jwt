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
unit JOSE.Tests.JWA.ECDSA;

interface

uses
  System.Rtti, System.SysUtils, DUnitX.TestFramework,

  JOSE.Core.JWT,
  JOSE.Core.JWS,
  JOSE.Core.JWK,
  JOSE.Core.JWA,
  JOSE.Signing.Base,
  JOSE.Signing.ECDSA,

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

initialization
  TDUnitX.RegisterTestFixture(TTestJWA);

end.

