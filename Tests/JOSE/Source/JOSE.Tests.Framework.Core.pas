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
unit JOSE.Tests.Framework.Core;

interface

uses
  System.SysUtils,
  DUnitX.TestFramework,

  // Common
  JOSE.Types.Bytes,
  JOSE.Types.JSON,
  JOSE.Hashing.HMAC,
  JOSE.Encoding.Base64,

  // JOSE
  JOSE.Core.Base;

type
  [TestFixture]
  TTestJOSEBytes = class
  private
    FBytes1, FBytes2: TJOSEBytes;
  public
    [Setup]
    procedure Setup;
    [TearDown]
    procedure TearDown;

    [Test]
    procedure TestInitializedEmpty;
    [Test]
    procedure TestEquals(A, B: TJOSEBytes);
  end;


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
    [TestCase('Before', '12345,12346')]
    procedure TestBefore(ADate, ABefore: Int64);
  end;

implementation

procedure TTestNumericDate.Setup;
begin

end;

procedure TTestNumericDate.TearDown;
begin

end;

procedure TTestNumericDate.TestBefore(ADate, ABefore: Int64);
begin
  FNumDate := TJOSENumericDate.FromSeconds(ADate);
  Assert.AreEqual(True, FNumDate.IsBefore(TJOSENumericDate.FromSeconds(ABefore)));
end;

{ TTestJOSEBytes }

procedure TTestJOSEBytes.Setup;
begin
  FBytes1 := TJOSEBytes.Empty;
  FBytes2 := TJOSEBytes.Empty;
end;

procedure TTestJOSEBytes.TearDown;
begin

end;

procedure TTestJOSEBytes.TestEquals(A, B: TJOSEBytes);
begin

end;

procedure TTestJOSEBytes.TestInitializedEmpty;
begin
  Assert.AreEqual(FBytes1.Size, 0);
end;

initialization
  TDUnitX.RegisterTestFixture(TTestNumericDate);
end.
