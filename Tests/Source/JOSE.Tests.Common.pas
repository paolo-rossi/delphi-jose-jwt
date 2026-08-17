{******************************************************************************}
{                                                                              }
{  Delphi JOSE-JWT Library                                                     }
{  Copyright (c) 2015 Paolo Rossi                                              }
{  https://github.com/paolo-rossi/delphi-jose-jwt                              }
{                                                                              }
{  Licensed under the MIT license                                              }
{                                                                              }
{******************************************************************************}
unit JOSE.Tests.Common;

interface

uses
  System.SysUtils, System.Rtti, System.JSON, DUnitX.TestFramework,

  JOSE.Types.Bytes,
  JOSE.Hashing.HMAC,
  JOSE.Types.Arrays,
  JOSE.Types.JSON,
  JOSE.Types.Utils,
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

    // RFC 7515 par. 2: the base64url alphabet, no padding, no whitespace, a
    // length an encoder can produce, canonical trailing bits
    [Test]
    [TestCase('Empty',            '|True', '|')]
    [TestCase('Four chars',       'TWFu|True', '|')]
    [TestCase('Three chars',      'TWE|True', '|')]
    [TestCase('Two chars',        'TQ|True', '|')]
    [TestCase('Alphabet - and _', 'a-b_|True', '|')]
    [TestCase('Padded',           'TWE=|False', '|')]
    [TestCase('Standard +',       'a+bc|False', '|')]
    [TestCase('Standard /',       'ab/c|False', '|')]
    [TestCase('Out of alphabet',  'TW!u|False', '|')]
    [TestCase('Space',            'TW u|False', '|')]
    [TestCase('Length 1 mod 4',   'TWFuA|False', '|')]
    [TestCase('Trailing bits 3',  'TWF|False', '|')]
    [TestCase('Trailing bits 2',  'TW|False', '|')]
    procedure TestIsValidURLEncoded(const AValue: string; AExpected: Boolean);

    [Test]
    procedure TestURLDecodeRejectsInvalidInput;
    [Test]
    procedure TestTryURLDecodeReturnsEmptyForInvalidInput;
    [Test]
    procedure TestURLDecodeRoundTrip;
    [Test]
    procedure TestStrictURLDecodingCanBeTurnedOff;
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
    [TestCase('TestSignSHA512', 'plaintext,secret,3/adkEcz1vmOINXEEOxdtM119BDAnKgvIJyr7IxLpdQsaUWLu9vu1Wz4veWeKz7wrkKTzySUGFj6/rDBrJzRuQ==')]
    procedure TestSignSHA512(const AValue1, AValue2, _Expected: string);
  end;

  [TestFixture]
  TTestJSONUtils = class(TTestBase)
  private
    function Parse(const AJSON: string): TJSONObject;
  public
    // Whole numbers must keep their Int64 precision
    [Test]
    procedure TestGetJSONValueKeepsInt64Precision;
    [Test]
    procedure TestGetJSONValueKeepsFractionalNumbers;

    // Reading a member as text never raises, whatever its JSON type
    [Test]
    [TestCase('String',  '{"m":"text"}|text', '|')]
    [TestCase('Number',  '{"m":42}|42', '|')]
    [TestCase('Int64',   '{"m":9007199254740993}|9007199254740993', '|')]
    [TestCase('Boolean', '{"m":true}|true', '|')]
    [TestCase('Absent',  '{"other":1}|', '|')]
    procedure TestGetJSONValueAsString(const AJSON, AExpected: string);

    // Date claims come from tokens: every shape must yield a value, not an exception
    [Test]
    [TestCase('Valid epoch',     '{"exp":1700000000}|False', '|')]
    [TestCase('Exponent form',   '{"exp":1e308}|True', '|')]
    [TestCase('Fractional',      '{"exp":1.5}|True', '|')]
    [TestCase('String',          '{"exp":"soon"}|True', '|')]
    [TestCase('Boolean',         '{"exp":true}|True', '|')]
    [TestCase('Int64 max',       '{"exp":9223372036854775807}|True', '|')]
    [TestCase('Int64 min',       '{"exp":-9223372036854775808}|True', '|')]
    [TestCase('Absent',          '{"other":1}|True', '|')]
    procedure TestGetJSONValueAsEpochIsTotal(const AJSON: string; AExpectZero: Boolean);

    // Same for an ISO-8601 date claim: no type is allowed to raise
    [Test]
    [TestCase('Valid ISO',  '{"d":"2026-08-17T10:00:00Z"}|False', '|')]
    [TestCase('Not a date', '{"d":"whenever"}|True', '|')]
    [TestCase('Number',     '{"d":42}|True', '|')]
    [TestCase('Boolean',    '{"d":true}|True', '|')]
    [TestCase('Absent',     '{"other":1}|True', '|')]
    procedure TestGetJSONValueAsDateIsTotal(const AJSON: string; AExpectZero: Boolean);

    // ToJSON must not mangle non-ASCII claims
    [Test]
    procedure TestToJSONKeepsNonAscii;
  end;

  [TestFixture]
  TTestJOSEUtils = class(TTestBase)
  public
    [Test]
    [TestCase('Low and high nibbles', '011FA0FF')]
    procedure TestBinToSingleHex(const AExpected: string);
    [Test]
    procedure TestBinToSingleHexEmpty;
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

procedure TTestBase64.TestIsValidURLEncoded(const AValue: string; AExpected: Boolean);
begin
  Assert.AreEqual(AExpected, TBase64.IsValidURLEncoded(AValue), '[' + AValue + ']');
end;

procedure TTestBase64.TestURLDecodeRejectsInvalidInput;
begin
  Assert.WillRaise(
    procedure begin TBase64.URLDecode('TWE=') end,
    EJOSEBase64Exception);
end;

procedure TTestBase64.TestTryURLDecodeReturnsEmptyForInvalidInput;
begin
  Assert.IsTrue(TBase64.TryURLDecode('TW!u').IsEmpty);
  Assert.IsFalse(TBase64.TryURLDecode('TWFu').IsEmpty);
end;

procedure TTestBase64.TestURLDecodeRoundTrip;
var
  LEncoded: TJOSEBytes;
begin
  // Whatever URLEncode produces must survive the strict decoder
  LEncoded := TBase64.URLEncode('Man');
  Assert.IsTrue(TBase64.IsValidURLEncoded(LEncoded), LEncoded.AsString);
  Assert.AreEqual('Man', TBase64.URLDecode(LEncoded).AsString);

  LEncoded := TBase64.URLEncode('Ma');
  Assert.IsTrue(TBase64.IsValidURLEncoded(LEncoded), LEncoded.AsString);
  Assert.AreEqual('Ma', TBase64.URLDecode(LEncoded).AsString);

  LEncoded := TBase64.URLEncode('M');
  Assert.IsTrue(TBase64.IsValidURLEncoded(LEncoded), LEncoded.AsString);
  Assert.AreEqual('M', TBase64.URLDecode(LEncoded).AsString);
end;

procedure TTestBase64.TestStrictURLDecodingCanBeTurnedOff;
begin
  TBase64.StrictURLDecoding := False;
  try
    // The documented escape hatch for a non-conforming issuer
    Assert.AreEqual('Ma', TBase64.URLDecode('TWE=').AsString);
  finally
    TBase64.StrictURLDecoding := True;
  end;

  Assert.WillRaise(
    procedure begin TBase64.URLDecode('TWE=') end,
    EJOSEBase64Exception, 'The flag must be back on');
end;

{ TTestJSONUtils }

function TTestJSONUtils.Parse(const AJSON: string): TJSONObject;
begin
  Result := TJSONObject.ParseJSONValue(AJSON) as TJSONObject;
  Assert.IsNotNull(Result, 'Bad test data: ' + AJSON);
end;

procedure TTestJSONUtils.TestGetJSONValueKeepsInt64Precision;
var
  LJSON: TJSONObject;
  LValue: TValue;
begin
  LJSON := Parse('{"m":9007199254740993}');
  try
    LValue := TJSONUtils.GetJSONValue('m', LJSON);
    Assert.IsTrue(LValue.IsOrdinal or (LValue.Kind = tkInt64),
      'A whole number must not go through Double');
    Assert.AreEqual<Int64>(9007199254740993, LValue.AsInt64);
  finally
    LJSON.Free;
  end;
end;

procedure TTestJSONUtils.TestGetJSONValueKeepsFractionalNumbers;
var
  LJSON: TJSONObject;
  LValue: TValue;
begin
  LJSON := Parse('{"m":1.5}');
  try
    LValue := TJSONUtils.GetJSONValue('m', LJSON);
    Assert.AreEqual<Double>(1.5, LValue.AsExtended);
  finally
    LJSON.Free;
  end;
end;

procedure TTestJSONUtils.TestGetJSONValueAsString(const AJSON, AExpected: string);
var
  LJSON: TJSONObject;
begin
  LJSON := Parse(AJSON);
  try
    Assert.AreEqual(AExpected, TJSONUtils.GetJSONValueAsString('m', LJSON));
  finally
    LJSON.Free;
  end;
end;

procedure TTestJSONUtils.TestGetJSONValueAsEpochIsTotal(const AJSON: string; AExpectZero: Boolean);
var
  LJSON: TJSONObject;
  LDate: TDateTime;
begin
  LJSON := Parse(AJSON);
  try
    // The call itself must not raise: that is the whole point
    LDate := TJSONUtils.GetJSONValueAsEpoch('exp', LJSON);
    if AExpectZero then
      Assert.AreEqual<TDateTime>(0, LDate, 'An unusable date claim must read as 0')
    else
      Assert.AreNotEqual<TDateTime>(0, LDate);
  finally
    LJSON.Free;
  end;
end;

procedure TTestJSONUtils.TestGetJSONValueAsDateIsTotal(const AJSON: string; AExpectZero: Boolean);
var
  LJSON: TJSONObject;
  LDate: TDateTime;
begin
  LJSON := Parse(AJSON);
  try
    LDate := TJSONUtils.GetJSONValueAsDate('d', LJSON);
    if AExpectZero then
      Assert.AreEqual<TDateTime>(0, LDate)
    else
      Assert.AreNotEqual<TDateTime>(0, LDate);
  finally
    LJSON.Free;
  end;
end;

procedure TTestJSONUtils.TestToJSONKeepsNonAscii;
var
  LJSON, LRoundTrip: TJSONObject;
  LText: string;
begin
  // Whether the RTL escapes the characters or emits them literally is its own
  // business; what must hold is that the text survives the trip
  LText := 'Ren' + Char($00E9) + ' ' + Char($00DC) + 'ber ' + Char($20AC);
  LJSON := Parse('{"sub":"' + LText + '"}');
  try
    LRoundTrip := Parse(TJSONUtils.ToJSON(LJSON));
    try
      Assert.AreEqual(LText, LRoundTrip.GetValue('sub').Value);
    finally
      LRoundTrip.Free;
    end;
  finally
    LJSON.Free;
  end;
end;

{ TTestJOSEUtils }

procedure TTestJOSEUtils.TestBinToSingleHex(const AExpected: string);
begin
  // Both nibbles of every byte, not just the low one
  Assert.AreEqual(AExpected, TJOSEUtils.BinToSingleHex([$01, $1F, $A0, $FF]));
end;

procedure TTestJOSEUtils.TestBinToSingleHexEmpty;
begin
  Assert.AreEqual('', TJOSEUtils.BinToSingleHex([]));
end;

initialization
  TDUnitX.RegisterTestFixture(TTestJOSEBytes);
  TDUnitX.RegisterTestFixture(TTestBase64);
  TDUnitX.RegisterTestFixture(TTestJSONUtils);
  TDUnitX.RegisterTestFixture(TTestJOSEUtils);

end.

