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
unit JOSE.Tests.JWS;

interface

uses
  System.Rtti, DUnitX.TestFramework,

  JOSE.Core.JWS,
  JOSE.Tests.Classes;

type
  [TestFixture]
  TTestJWS = class(TObject)
  public
    [Setup]
    procedure Setup;
    [TearDown]
    procedure TearDown;
    [Test]
    //[TestCase('TestBoolTrue', 'True,True')]
    procedure TestSignHSA256(const AValue: Boolean);
  end;

implementation

procedure TTestJWS.Setup;
begin

end;

procedure TTestJWS.TearDown;
begin
end;

procedure TTestJWS.TestSignHSA256(const AValue: Boolean);
begin
  //Assert.AreEqual(_Result, TTestUtils.SerializeValue(AValue));
end;

initialization
  TDUnitX.RegisterTestFixture(TTestJWS);

end.

