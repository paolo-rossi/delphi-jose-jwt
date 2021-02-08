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
  System.Rtti, System.SysUtils, DUnitX.TestFramework,

  JOSE.Core.JWT,
  JOSE.Core.JWS,
  JOSE.Core.JWK,
  JOSE.Core.JWA,
  JOSE.Signing.Base,
  JOSE.Signing.RSA,

  JOSE.Tests.Classes;

type
  [TestFixture]
  [Category('jwa')]
  TTestJWA = class(TTestBase)
  public
    [Setup]
    procedure Setup;
    [TearDown]
    procedure TearDown;

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

initialization
  TDUnitX.RegisterTestFixture(TTestJWA);

end.

