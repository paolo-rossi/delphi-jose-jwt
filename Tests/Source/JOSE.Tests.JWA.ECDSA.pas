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
  public
    [Setup]
    procedure Setup;
    [TearDown]
    procedure TearDown;

    [Test]
    [TestCase('TestECDSASign256', 'EC256,jHok3-EqiaoiWxBQ9Gh84Kc6vIrNM1NeoNRiPBHaTAA')]
    [TestCase('TestECDSASign384', 'EC384,WrDaePkHG0cJMuRXHCz0pY5lt_Is4ZEYw139qt7o-zx40Ze90osIZ8ZhOX5VipE-')]
    [TestCase('TestECDSASign512', 'EC512,wSSOeaU_UlEhOiGksvDZaKdcIJBBDD_cEj_pLhTdW5VK-XeZL5L1LxgJyOArMAOZBaPe-iwKW6UFLy3YlTQr_A')]
    procedure TestECDSASign(AAlg: TJOSEAlgorithmId; const ASignature: string);
  end;

implementation

uses
  System.IOUtils,
  JOSE.Tests.Utils;

procedure TTestJWA.Setup;
begin

end;

procedure TTestJWA.TearDown;
begin
end;

procedure TTestJWA.TestECDSASign(AAlg: TJOSEAlgorithmId; const ASignature: string);
begin

end;

initialization
  TDUnitX.RegisterTestFixture(TTestJWA);

end.

