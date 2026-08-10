{******************************************************************************}
{                                                                              }
{  Delphi JOSE-JWT Library                                                     }
{  Copyright (c) 2015 Paolo Rossi                                              }
{  https://github.com/paolo-rossi/delphi-jose-jwt                              }
{                                                                              }
{  Licensed under the MIT license                                              }
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

