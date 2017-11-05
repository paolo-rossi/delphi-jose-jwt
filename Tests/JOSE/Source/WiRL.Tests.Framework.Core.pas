{******************************************************************************}
{                                                                              }
{  Delphi JOSE Library                                                         }
{  Copyright (c) 2015-2017 Paolo Rossi                                         }
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
unit WiRL.Tests.Framework.Core;

interface

uses
  System.SysUtils,
  DUnitX.TestFramework,

  JOSE.Core.Base;

type

  [TestFixture]
  TTestNumericDate = class(TObject)
  private
    FNumDate: TJOSENumericDate;
  public
    [Setup]
    procedure Setup;
    [TearDown]
    procedure TearDown;

    [Test]
    [TestCase('Before', 'text/html;q=0.5;dialect=extjs')]
    procedure TestDialect(AMediaType: string);

  end;

implementation

procedure TTestNumericDate.Setup;
begin

end;

procedure TTestNumericDate.TearDown;
begin

end;

procedure TTestNumericDate.TestDialect(AMediaType: string);
begin
  FNumDate := TJOSENumericDate.FromSeconds(12345);
  Assert.AreEqual(True,  FNumDate.IsBefore(12346));
end;

initialization
  TDUnitX.RegisterTestFixture(TTestNumericDate);
end.
