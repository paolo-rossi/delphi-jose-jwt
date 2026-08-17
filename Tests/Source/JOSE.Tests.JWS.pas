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
  System.SysUtils, System.DateUtils, System.Rtti, DUnitX.TestFramework,

  JOSE.Types.Bytes,
  JOSE.Core.Base,
  JOSE.Core.JWA,
  JOSE.Core.JWK,
  JOSE.Core.JWT,
  JOSE.Core.JWS,
  JOSE.Encoding.Base64,

  JOSE.Tests.Classes;

type
  /// <summary>
  ///   TJWS itself: compact serialization in and out, the signing input it
  ///   builds, and the guards around signing and verifying
  /// </summary>
  [TestFixture]
  TTestJWS = class(TTestBase)
  private
    const SECRET = 'a-test-secret-of-at-least-32-bytes-long!';
    const SHORT_SECRET = 'too-short';
  private
    FJWT: TJWT;
    FJWS: TJWS;
    function Segment(const AJSON: string): string;
    function SignedToken: string;
  public
    [Setup]
    procedure Setup;
    [TearDown]
    procedure TearDown;

    // Compact serialization
    [Test]
    procedure TestCompactTokenIsHeaderPayloadSignature;
    [Test]
    procedure TestSigningInputIsHeaderDotPayload;
    [Test]
    procedure TestSetCompactTokenPopulatesHeaderAndClaims;
    [Test]
    procedure TestSetCompactTokenRejectsEmpty;
    [Test]
    [TestCase('One part',   'aaa')]
    [TestCase('Two parts',  'aaa.bbb')]
    [TestCase('Four parts', 'aaa.bbb.ccc.ddd')]
    procedure TestSetCompactTokenRejectsWrongPartCount(const AToken: string);
    [Test]
    procedure TestEmptyClearsThePartsButKeepsTheirNumber;

    // CheckCompactToken
    [Test]
    procedure TestCheckCompactTokenAcceptsASignedToken;
    [Test]
    [TestCase('Empty',            '')]
    [TestCase('One part',         'aaa')]
    [TestCase('Two parts',        'aaa.bbb')]
    [TestCase('Four parts',       'aaa.bbb.ccc.ddd')]
    [TestCase('Empty header',     '.eyJzdWIiOiJhIn0.c2ln')]
    [TestCase('Empty payload',    'eyJhbGciOiJIUzI1NiJ9..c2ln')]
    [TestCase('Empty signature',  'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.')]
    [TestCase('Not base64url',    '@@@.@@@.@@@')]
    [TestCase('Header not JSON',  'bm90LWpzb24.eyJzdWIiOiJhIn0.c2ln')]
    [TestCase('Header is array',  'WzFd.eyJzdWIiOiJhIn0.c2ln')]
    [TestCase('Payload is string','eyJhbGciOiJIUzI1NiJ9.InB3bmVkIg.c2ln')]
    procedure TestCheckCompactTokenRejects(const AToken: string);

    // Signing and verifying
    [Test]
    procedure TestSignThenVerify;
    [Test]
    procedure TestVerifySignatureMarksTheToken;
    [Test]
    procedure TestTamperedPayloadDoesNotVerify;
    [Test]
    procedure TestVerifyWithTheWrongKeyFails;
    [Test]
    procedure TestKeyOverloadsAreEquivalent;
    [Test]
    procedure TestSignWithoutAlgorithmHeaderRaises;
    [Test]
    procedure TestSignWithUnregisteredAlgorithmRaises;
    [Test]
    procedure TestSignValidatesTheKey;
    [Test]
    procedure TestSkipKeyValidationBypassesTheKeyCheck;
    [Test]
    procedure TestUnknownHeaderAlgorithmIsUnknown;

    // One logical token, one wire form: a segment that is not strict base64url
    // is refused at the boundary, so no algorithm ever sees a signature that
    // several different texts could stand for
    [Test]
    [TestCase('Padding',        '=')]
    [TestCase('Out of alphabet','!')]
    [TestCase('Space',          ' ')]
    procedure TestSignatureSegmentIsNotMalleable(const ASuffix: string);
    [Test]
    procedure TestSegmentWithLineBreakIsRejected;
    [Test]
    procedure TestNonCanonicalTrailingBitsAreRejected;
  end;

implementation

function TTestJWS.Segment(const AJSON: string): string;
begin
  Result := TBase64.URLEncode(AJSON).AsString;
end;

function TTestJWS.SignedToken: string;
begin
  FJWT.Claims.Subject := 'alice';
  FJWS.SetKey(SECRET);
  FJWS.SetHeaderAlgorithm(TJOSEAlgorithmId.HS256);
  FJWS.Sign;
  Result := FJWS.CompactToken;
end;

procedure TTestJWS.Setup;
begin
  inherited;
  FJWT := TJWT.Create;
  FJWS := TJWS.Create(FJWT);
end;

procedure TTestJWS.TearDown;
begin
  FJWS.Free;
  FJWT.Free;
  inherited;
end;

procedure TTestJWS.TestCompactTokenIsHeaderPayloadSignature;
var
  LToken: string;
begin
  LToken := SignedToken;
  Assert.AreEqual(
    FJWS.Header.AsString + '.' + FJWS.Payload.AsString + '.' + FJWS.Signature.AsString,
    LToken);
end;

procedure TTestJWS.TestSigningInputIsHeaderDotPayload;
begin
  SignedToken;
  Assert.AreEqual(FJWS.Header.AsString + '.' + FJWS.Payload.AsString,
    FJWS.SigningInput.AsString);
end;

procedure TTestJWS.TestSetCompactTokenPopulatesHeaderAndClaims;
begin
  FJWS.CompactToken := Segment('{"alg":"HS256","typ":"JWT"}') + '.' +
    Segment('{"sub":"alice","iss":"me"}') + '.' + Segment('sig');

  Assert.AreEqual('HS256', FJWT.Header.Algorithm);
  Assert.AreEqual('JWT', FJWT.Header.HeaderType);
  Assert.AreEqual('alice', FJWT.Claims.Subject);
  Assert.AreEqual('me', FJWT.Claims.Issuer);
end;

procedure TTestJWS.TestSetCompactTokenRejectsEmpty;
begin
  Assert.WillRaise(
    procedure begin FJWS.CompactToken := TJOSEBytes.Empty end,
    EJOSEException);
end;

procedure TTestJWS.TestSetCompactTokenRejectsWrongPartCount(const AToken: string);
begin
  Assert.WillRaise(
    procedure begin FJWS.CompactToken := AToken end,
    EJOSEException);
end;

procedure TTestJWS.TestEmptyClearsThePartsButKeepsTheirNumber;
begin
  SignedToken;
  FJWS.Empty;
  Assert.AreEqual('..', FJWS.CompactToken.AsString);
end;

procedure TTestJWS.TestCheckCompactTokenAcceptsASignedToken;
begin
  Assert.IsTrue(TJWS.CheckCompactToken(SignedToken));
end;

procedure TTestJWS.TestCheckCompactTokenRejects(const AToken: string);
begin
  Assert.IsFalse(TJWS.CheckCompactToken(AToken));
end;

procedure TTestJWS.TestSignThenVerify;
var
  LToken: string;
begin
  LToken := SignedToken;

  // A second TJWS, as a verifier would use
  Assert.IsTrue(TJWS.CheckCompactToken(LToken));
  FJWS.CompactToken := LToken;
  Assert.IsTrue(FJWS.VerifySignature);
end;

procedure TTestJWS.TestVerifySignatureMarksTheToken;
begin
  SignedToken;
  Assert.IsFalse(FJWT.Verified, 'Signing must not mark the token as verified');

  FJWS.VerifySignature;
  Assert.IsTrue(FJWT.Verified);
end;

procedure TTestJWS.TestTamperedPayloadDoesNotVerify;
var
  LToken: string;
begin
  LToken := SignedToken;

  // Same signature, different payload
  FJWS.CompactToken :=
    FJWS.Header.AsString + '.' + Segment('{"sub":"mallory"}') + '.' + FJWS.Signature.AsString;

  Assert.IsFalse(FJWS.VerifySignature);
  Assert.IsFalse(FJWT.Verified);
end;

procedure TTestJWS.TestVerifyWithTheWrongKeyFails;
var
  LToken: string;
begin
  LToken := SignedToken;

  FJWS.SetKey('another-secret-of-at-least-32-bytes!!!!!');
  FJWS.CompactToken := LToken;

  Assert.IsFalse(FJWS.VerifySignature);
end;

procedure TTestJWS.TestKeyOverloadsAreEquivalent;
var
  LToken: string;
  LKey: TJWK;
  LBytes: TJOSEBytes;
begin
  LToken := SignedToken;
  LBytes := SECRET;

  LKey := TJWK.Create(LBytes);
  try
    FJWS.SetKey(LKey);
    FJWS.CompactToken := LToken;
    Assert.IsTrue(FJWS.VerifySignature, 'TJWK and TJOSEBytes keys must behave alike');

    FJWS.SetKey(LBytes.AsBytes);
    Assert.IsTrue(FJWS.VerifySignature, 'TBytes and TJOSEBytes keys must behave alike');
  finally
    LKey.Free;
  end;
end;

procedure TTestJWS.TestSignWithoutAlgorithmHeaderRaises;
begin
  FJWS.SetKey(SECRET);
  // No SetHeaderAlgorithm
  Assert.WillRaise(procedure begin FJWS.Sign end, EJOSEException);
end;

procedure TTestJWS.TestSignWithUnregisteredAlgorithmRaises;
begin
  FJWS.SetKey(SECRET);
  FJWS.SetHeaderAlgorithm(TJOSEAlgorithmId.None);

  // alg=none is deliberately not registered
  Assert.WillRaise(procedure begin FJWS.Sign end, EJOSEException);
end;

procedure TTestJWS.TestSignValidatesTheKey;
begin
  FJWS.SetKey(SHORT_SECRET);
  FJWS.SetHeaderAlgorithm(TJOSEAlgorithmId.HS256);

  Assert.WillRaise(procedure begin FJWS.Sign end, EJOSEException,
    'HS256 requires 256 bits of key material');
end;

procedure TTestJWS.TestSkipKeyValidationBypassesTheKeyCheck;
begin
  FJWS.SetKey(SHORT_SECRET);
  FJWS.SetHeaderAlgorithm(TJOSEAlgorithmId.HS256);
  FJWS.SkipKeyValidation := True;

  FJWS.Sign;
  Assert.IsTrue(TJWS.CheckCompactToken(FJWS.CompactToken));
end;

procedure TTestJWS.TestUnknownHeaderAlgorithmIsUnknown;
begin
  FJWS.SetHeaderAlgorithm('NOPE256');
  Assert.IsTrue(FJWS.HeaderAlgorithmId = TJOSEAlgorithmId.Unknown);
end;

procedure TTestJWS.TestSignatureSegmentIsNotMalleable(const ASuffix: string);
var
  LToken: string;
begin
  LToken := SignedToken;

  // The signature is the one segment nothing else covers, so a lenient decoder
  // would make every one of these a second valid form of the same token
  Assert.WillRaise(
    procedure begin FJWS.CompactToken := LToken + ASuffix end,
    EJOSEException, 'Signature + "' + ASuffix + '" must not be a second wire form');
end;

procedure TTestJWS.TestSegmentWithLineBreakIsRejected;
var
  LToken: string;
begin
  LToken := SignedToken;

  Assert.WillRaise(
    procedure
    begin
      FJWS.CompactToken := Copy(LToken, 1, Length(LToken) - 4) + #13#10 +
        Copy(LToken, Length(LToken) - 3, 4);
    end,
    EJOSEException);
end;

procedure TTestJWS.TestNonCanonicalTrailingBitsAreRejected;
const
  ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
var
  LToken: string;
  LValue: Integer;
begin
  LToken := SignedToken;

  // An HS256 signature is 43 characters, so its last one carries 4 significant
  // bits and 2 unused ones. Setting those two leaves the decoded signature
  // byte-identical while changing the token text: the subtlest wire-form
  // variant there is, and the reason the check covers trailing bits at all
  LValue := Pos(LToken[Length(LToken)], ALPHABET) - 1;
  Assert.AreEqual(0, LValue and $03, 'The encoder must emit canonical trailing bits');

  LToken[Length(LToken)] := ALPHABET[(LValue or $03) + 1];

  Assert.WillRaise(
    procedure begin FJWS.CompactToken := LToken end,
    EJOSEException);
end;

initialization
  TDUnitX.RegisterTestFixture(TTestJWS);

end.
