{******************************************************************************}
{                                                                              }
{  Delphi JOSE-JWT Library                                                     }
{  Copyright (c) 2015 Paolo Rossi                                              }
{  https://github.com/paolo-rossi/delphi-jose-jwt                              }
{                                                                              }
{  Licensed under the MIT license                                              }
{                                                                              }
{******************************************************************************}
unit JOSE.Tests.Context;

interface

uses
  System.SysUtils, DUnitX.TestFramework,

  JOSE.Types.Bytes,
  JOSE.Core.Base,
  JOSE.Core.Parts,
  JOSE.Core.Builder,
  JOSE.Core.JWA,
  JOSE.Core.JWT,
  JOSE.Core.JWS,
  JOSE.Consumer,
  JOSE.Context,

  JOSE.Tests.Classes;

type
  /// <summary>
  ///   Malformed compact serializations must never reach the claims
  ///   validation: TJOSEContext has to fail loudly, and the consumer must
  ///   refuse a context it could not parse
  /// </summary>
  [TestFixture]
  TTestContext = class(TTestBase)
  private
    const SECRET = 'a-secret-of-at-least-32-bytes-for-hs256!';
    function Forge(const AHeader, APayload: string): TJOSEBytes;
    function BuildConsumer: IJOSEConsumer;
    function SignedToken: TJOSEBytes;
  public
    // A segment that decodes to a valid but non-object JSON value used to raise
    // EInvalidCast inside TJOSEBase.SetURLEncoded *after* FJSON had been freed;
    // TJOSEContext swallowed it and the consumer then skipped the algorithm
    // check, the signature verification and the require-signature check
    [Test]
    [TestCase('String payload',  '{"alg":"HS256"}|"pwned"', '|')]
    [TestCase('Array payload',   '{"alg":"HS256"}|[1]', '|')]
    [TestCase('Number payload',  '{"alg":"HS256"}|123', '|')]
    [TestCase('Boolean payload', '{"alg":"HS256"}|true', '|')]
    [TestCase('Null payload',    '{"alg":"HS256"}|null', '|')]
    [TestCase('Array header',    '[1]|{"sub":"alice"}', '|')]
    [TestCase('String header',   '"HS256"|{"sub":"alice"}', '|')]
    procedure TestNonObjectSegmentRejectedByContext(const AHeader, APayload: string);

    [Test]
    [TestCase('String payload',  '{"alg":"HS256"}|"pwned"', '|')]
    [TestCase('Array payload',   '{"alg":"HS256"}|[1]', '|')]
    [TestCase('Number payload',  '{"alg":"HS256"}|123', '|')]
    [TestCase('Boolean payload', '{"alg":"HS256"}|true', '|')]
    [TestCase('Null payload',    '{"alg":"HS256"}|null', '|')]
    [TestCase('Array header',    '[1]|{"sub":"alice"}', '|')]
    [TestCase('String header',   '"HS256"|{"sub":"alice"}', '|')]
    procedure TestNonObjectSegmentRejectedByConsumer(const AHeader, APayload: string);

    [Test]
    [TestCase('String payload',  '{"alg":"HS256"}|"pwned"', '|')]
    [TestCase('Array payload',   '{"alg":"HS256"}|[1]', '|')]
    [TestCase('Array header',    '[1]|{"sub":"alice"}', '|')]
    procedure TestNonObjectSegmentRejectedByCheckCompactToken(const AHeader, APayload: string);

    [Test]
    [TestCase('All empty',     '..', '|')]
    [TestCase('Empty header',  '.eyJzdWIiOiJhbGljZSJ9.c2ln', '|')]
    [TestCase('Empty payload', 'eyJhbGciOiJIUzI1NiJ9..c2ln', '|')]
    [TestCase('Not base64',    '@@@.@@@.@@@', '|')]
    procedure TestUnparsableTokenRejected(const AToken: string);

    [Test]
    [TestCase('One part',   'eyJhbGciOiJIUzI1NiJ9', '|')]
    [TestCase('Two parts',  'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9', '|')]
    [TestCase('Four parts', 'a.b.c.d', '|')]
    procedure TestWrongPartCountRejected(const AToken: string);

    [Test]
    procedure TestJWERejected;

    // Guards against over-tightening the checks above
    [Test]
    procedure TestValidTokenIsParsed;
    [Test]
    procedure TestValidTokenIsAccepted;
    [Test]
    procedure TestTamperedSignatureIsRejected;
    [Test]
    procedure TestVerifyReturnsNilOnMalformedToken;
  end;

implementation

uses
  System.DateUtils,
  JOSE.Encoding.Base64;

function TTestContext.BuildConsumer: IJOSEConsumer;
begin
  Result := TJOSEConsumerBuilder.NewConsumer
    .SetVerificationKey(SECRET)
    .SetExpectedAlgorithms([TJOSEAlgorithmId.HS256])
    .Build;
end;

function TTestContext.Forge(const AHeader, APayload: string): TJOSEBytes;
begin
  // Unsigned on purpose: none of these tokens must ever get past the parsing
  Result :=
    TBase64.URLEncode(AHeader).AsString + '.' +
    TBase64.URLEncode(APayload).AsString + '.' +
    TBase64.URLEncode('not-a-signature').AsString;
end;

function TTestContext.SignedToken: TJOSEBytes;
var
  LJWT: TJWT;
begin
  LJWT := TJWT.Create;
  try
    LJWT.Claims.Subject := 'alice';
    LJWT.Claims.IssuedAt := Now;
    LJWT.Claims.Expiration := IncMinute(Now, 30);

    Result := TJOSE.SerializeCompact(SECRET, TJOSEAlgorithmId.HS256, LJWT);
  finally
    LJWT.Free;
  end;
end;

procedure TTestContext.TestNonObjectSegmentRejectedByContext(const AHeader, APayload: string);
var
  LToken: TJOSEBytes;
begin
  LToken := Forge(AHeader, APayload);

  Assert.WillRaise(
    procedure
    var
      LContext: TJOSEContext;
    begin
      LContext := TJOSEContext.Create(LToken, TJWTClaims);
      LContext.Free;
    end,
    EJOSEException
  );
end;

procedure TTestContext.TestNonObjectSegmentRejectedByConsumer(const AHeader, APayload: string);
var
  LToken: TJOSEBytes;
  LConsumer: IJOSEConsumer;
begin
  LToken := Forge(AHeader, APayload);
  LConsumer := BuildConsumer;

  Assert.WillRaise(
    procedure begin LConsumer.Process(LToken) end,
    EJOSEException
  );
end;

procedure TTestContext.TestNonObjectSegmentRejectedByCheckCompactToken(const AHeader, APayload: string);
begin
  Assert.IsFalse(TJOSE.CheckCompactToken(Forge(AHeader, APayload)));
end;

procedure TTestContext.TestUnparsableTokenRejected(const AToken: string);
var
  LConsumer: IJOSEConsumer;
begin
  LConsumer := BuildConsumer;

  Assert.WillRaise(
    procedure begin LConsumer.Process(AToken) end,
    EJOSEException
  );
  Assert.IsFalse(TJOSE.CheckCompactToken(AToken));
end;

procedure TTestContext.TestWrongPartCountRejected(const AToken: string);
var
  LConsumer: IJOSEConsumer;
begin
  LConsumer := BuildConsumer;

  Assert.WillRaise(
    procedure begin LConsumer.Process(AToken) end,
    EJOSEException
  );
end;

procedure TTestContext.TestJWERejected;
var
  LConsumer: IJOSEConsumer;
begin
  LConsumer := BuildConsumer;

  Assert.WillRaise(
    procedure begin LConsumer.Process('a.b.c.d.e') end,
    EJOSEException
  );
end;

procedure TTestContext.TestValidTokenIsParsed;
var
  LContext: TJOSEContext;
  LJOSEObject: TJOSEParts;
begin
  LContext := TJOSEContext.Create(SignedToken, TJWTClaims);
  try
    LJOSEObject := LContext.GetJOSEObject;
    Assert.IsNotNull(LJOSEObject, 'GetJOSEObject must not be nil');
    Assert.InheritsFrom(LJOSEObject.ClassType, TJWS);
    Assert.AreEqual('HS256', LContext.GetHeader.Algorithm);
    Assert.AreEqual('alice', LContext.GetClaims.Subject);
  finally
    LContext.Free;
  end;
end;

procedure TTestContext.TestValidTokenIsAccepted;
var
  LContext: TJOSEContext;
begin
  LContext := TJOSEContext.Create(SignedToken, TJWTClaims);
  try
    BuildConsumer.ProcessContext(LContext);
    Assert.AreEqual('alice', LContext.GetClaims.Subject);
  finally
    LContext.Free;
  end;
end;

procedure TTestContext.TestTamperedSignatureIsRejected;
var
  LToken: string;
  LConsumer: IJOSEConsumer;
begin
  LToken := SignedToken;
  // flip the last character of the signature
  if LToken[Length(LToken)] = 'A' then
    LToken[Length(LToken)] := 'B'
  else
    LToken[Length(LToken)] := 'A';

  LConsumer := BuildConsumer;
  Assert.WillRaise(
    procedure begin LConsumer.Process(LToken) end,
    EJOSEException
  );
end;

procedure TTestContext.TestVerifyReturnsNilOnMalformedToken;
var
  LKey: TJOSEBytes;
  LJWT: TJWT;
begin
  // TJOSE.Verify keeps its documented "nil on failure" contract
  LKey := SECRET;
  LJWT := TJOSE.Verify(LKey, Forge('{"alg":"HS256"}', '"pwned"'));
  try
    Assert.IsNull(LJWT);
  finally
    LJWT.Free;
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TTestContext);

end.
