{******************************************************************************}
{                                                                              }
{  Delphi JOSE-JWT Library                                                     }
{  Copyright (c) 2015 Paolo Rossi                                              }
{  https://github.com/paolo-rossi/delphi-jose-jwt                              }
{                                                                              }
{  Licensed under the MIT license                                              }
{                                                                              }
{******************************************************************************}
unit JOSE.Tests.JWT;

interface

uses
  System.Rtti, DUnitX.TestFramework,

  JOSE.Core.JWT,
  JOSE.Tests.Classes;

type
  [TestFixture]
  TTestJWT = class(TTestBase)
  public
    [Setup]
    procedure Setup;
    [TearDown]
    procedure TearDown;
  end;

implementation

procedure TTestJWT.Setup;
begin

end;

procedure TTestJWT.TearDown;
begin
end;

initialization
  TDUnitX.RegisterTestFixture(TTestJWT);

end.

