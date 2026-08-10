{******************************************************************************}
{                                                                              }
{  Delphi JOSE-JWT Library                                                     }
{  Copyright (c) 2015 Paolo Rossi                                              }
{  https://github.com/paolo-rossi/delphi-jose-jwt                              }
{                                                                              }
{  Licensed under the MIT license                                              }
{                                                                              }
{******************************************************************************}
unit JOSE.Tests.Builder;

interface

uses
  System.Rtti, DUnitX.TestFramework,

  JOSE.Core.JWS;

type
  [TestFixture]
  TTestBuilder = class(TObject)
  public
    [Setup]
    procedure Setup;
    [TearDown]
    procedure TearDown;
  end;

implementation

procedure TTestBuilder.Setup;
begin

end;

procedure TTestBuilder.TearDown;
begin
end;

initialization
  TDUnitX.RegisterTestFixture(TTestBuilder);

end.

