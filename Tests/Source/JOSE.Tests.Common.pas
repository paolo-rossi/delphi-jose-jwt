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
unit JOSE.Tests.Common;

interface

uses
  System.SysUtils, System.Rtti, DUnitX.TestFramework,
  
  JOSE.Types.Bytes,
  JOSE.Hashing.HMAC,
  JOSE.Signing.RSA,
  JOSE.Types.Arrays,
  JOSE.Types.JSON,
  JOSE.Encoding.Base64,

  JOSE.Tests.Classes;

type
  [TestFixture]
  TTestJOSEBytes = class(TTestBase)
  public
    [Test]
    [TestCase('TestImplicit', 'aBc')]
    [TestCase('TestImplicitEmptyString', '')]
    [TestCase('TestImplicitUnicode', 'Москва')]
    procedure TestImplicit(const AValue: string);

    [Test]
    procedure TestImplicitBytes(const AValue: TBytes);

    [Test]
    [TestCase('TestEqual', 'aBc,aBc,True')]
    [TestCase('TestEqualEmpty', ',,True')]
    [TestCase('TestNotEqual', 'aBc,abc,False')]
    [TestCase('TestNotEqualEmpy', 'aBc,,False')]
    procedure TestEqual(const AValue1, AValue2 : string; _Result: Boolean);

    [Test]
    [TestCase('TestAdd', 'aBc,xYz,aBcxYz')]
    [TestCase('TestAddEmpty', 'aBc,,aBc')]
    procedure TestAdd(const AValue1, AValue2, _Result: string);

    [Test]
    [TestCase('TestContains', 'aBcDeFgH,De,True')]
    [TestCase('TestContainsByte', 'aBcDeFgH,D,True')]
    [TestCase('TestContainsNot', 'aBcDeFgH,abc,False')]
    [TestCase('TestContainsEmpty', 'aBcDeFgH,,False')]
    procedure TestContains(const AValue1, AValue2 : string; _Result: Boolean);

    [Test]
    [TestCase('TestMerge', 'aBcDeFgH,iLmNoPq,aBcDeFgHiLmNoPq')]
    [TestCase('TestMergeByte', 'aBcDeFgH,i,aBcDeFgHi')]
    [TestCase('TestMergeEmpty', 'aBcDeFgH,,aBcDeFgH')]
    procedure TestMerge(const AValue1, AValue2, _Result: string);
  end;

  [TestFixture]
  TTestBase64 = class(TTestBase)
  public
    [Test]
    [TestCase('TestEncodeString', 'paolo,cGFvbG8=')]
    procedure TestEncodeString(const AValue1, _Expected: string);

    [Test]
    [TestCase('TestDecodeString', 'cGFvbG8=,paolo')]
    procedure TestDecodeString(const AValue1, _Expected: string);
  end;

  [TestFixture]
  TTestHMAC = class(TTestBase)
  public
    [Test]
    [TestCase('TestSignSHA256', 'plaintext,secret,XXv4q83DfQItSR7PCiZwWFlG10ah668c1cRsrKh6Ylg=')]
    procedure TestSignSHA256(const AValue1, AValue2, _Expected: string);

    [Test]
    [TestCase('TestSignSHA384', 'plaintext,secret,u0uk1bjmjw3CqOTwcgWrbrvcoCQMGE8LQCuT8SfxJRXedF3PvGw4FWsoZvPtIl3B')]
    procedure TestSignSHA384(const AValue1, AValue2, _Expected: string);

    [Test]
    [TestCase('TestSignSHA512', 'plaintext,secret,3/adkEcz1vmOINXEEOxdtM119BDAnKgvIJyr7IxLpdQsaUWLu9vu1Wz4veWeKz7wrkKTzySUGFj6'#$D#$A'/rDBrJzRuQ==')]
    procedure TestSignSHA512(const AValue1, AValue2, _Expected: string);
  end;

implementation

procedure TTestBase64.TestDecodeString(const AValue1, _Expected: string);
begin
  Assert.AreEqual(_Expected, TBase64.Decode(AValue1).AsString);
end;

procedure TTestBase64.TestEncodeString(const AValue1, _Expected: string);
begin
  Assert.AreEqual(_Expected, TBase64.Encode(AValue1).AsString);
end;

procedure TTestHMAC.TestSignSHA256(const AValue1, AValue2, _Expected: string);
var
  LSignature: TJOSEBytes;
begin
  LSignature := THMAC.Sign(TEncoding.ANSI.GetBytes(AValue1), TEncoding.ANSI.GetBytes(AValue2), THMACAlgorithm.SHA256);
  Assert.AreEqual(_Expected, TBase64.Encode(LSignature).AsString);
end;

procedure TTestHMAC.TestSignSHA384(const AValue1, AValue2, _Expected: string);
var
  LSignature: TJOSEBytes;
begin
  LSignature := THMAC.Sign(TEncoding.ANSI.GetBytes(AValue1), TEncoding.ANSI.GetBytes(AValue2), THMACAlgorithm.SHA384);
  Assert.AreEqual(_Expected, TBase64.Encode(LSignature).AsString);
end;

procedure TTestHMAC.TestSignSHA512(const AValue1, AValue2, _Expected: string);
var
  LSignature: TJOSEBytes;
begin
  LSignature := THMAC.Sign(TEncoding.ANSI.GetBytes(AValue1), TEncoding.ANSI.GetBytes(AValue2), THMACAlgorithm.SHA512);
  Assert.AreEqual(_Expected, TBase64.Encode(LSignature).AsString);
end;

procedure TTestJOSEBytes.TestAdd(const AValue1, AValue2, _Result: string);
var
  LValue1, LValue2: TJOSEBytes;
  LResult: TJOSEBytes;
begin
  LValue1 := AValue1;
  LValue2 := AValue2;
  LResult := AValue1 + AValue2;

  Assert.AreEqual(_Result, LResult.AsString);
end;

procedure TTestJOSEBytes.TestContains(const AValue1, AValue2: string; _Result: Boolean);
var
  LValue1: TJOSEBytes;
  LValue2: TBytes;
begin
  LValue1 := AValue1;
  LValue2 := TEncoding.ANSI.GetBytes(AValue2);
  if Length(LValue2) = 1 then
    Assert.AreEqual(_Result, LValue1.Contains(LValue2[0]))
  else
    Assert.AreEqual(_Result, LValue1.Contains(LValue2));
end;

procedure TTestJOSEBytes.TestEqual(const AValue1, AValue2 : string; _Result: Boolean);
var
  LValue1, LValue2: TJOSEBytes;
begin
  LValue1 := AValue1;
  LValue2 := AValue2;
  Assert.AreEqual(_Result, LValue1 = LValue2);
end;

procedure TTestJOSEBytes.TestImplicit(const AValue: string);
var
  LBytes: TJOSEBytes;
begin
  LBytes := AValue;
  Assert.AreEqual(AValue, LBytes.AsString);
end;

procedure TTestJOSEBytes.TestImplicitBytes(const AValue: TBytes);
var
  LBytes: TBytes;
  LJOSEBytes: TJOSEBytes;
begin
  LBytes := [97,66,99];
  LJOSEBytes := LBytes;
  Assert.AreEqual('aBc', LJOSEBytes.AsString);
end;

procedure TTestJOSEBytes.TestMerge(const AValue1, AValue2, _Result: string);
var
  LResult, LExpected: TBytes;
begin
  LExpected := TEncoding.ANSI.GetBytes(_Result);
  LResult := TBytesUtils.MergeBytes(TEncoding.ANSI.GetBytes(AValue1), TEncoding.ANSI.GetBytes(AValue2));

  Assert.AreEqualMemory(@LExpected[0], @LResult[0], Length(LExpected));
end;

initialization
  TDUnitX.RegisterTestFixture(TTestJOSEBytes);
  TDUnitX.RegisterTestFixture(TTestBase64);

end.

