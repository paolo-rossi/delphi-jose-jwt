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
  System.SysUtils, System.DateUtils, DUnitX.TestFramework,

  JOSE.Types.Bytes,
  JOSE.Types.JSON,
  JOSE.Core.Base,
  JOSE.Core.Builder,
  JOSE.Core.JWA,
  JOSE.Core.JWK,
  JOSE.Core.JWT,
  JOSE.Core.JWS,
  JOSE.Producer;

type
  TCustomClaims = class(TJWTClaims)
  private
    function GetAppId: string;
    procedure SetAppId(const AValue: string);
  public
    property AppId: string read GetAppId write SetAppId;
  end;

  [TestFixture]
  TTestBuilder = class(TObject)
  private
    const SECRET = 'a-test-secret-of-at-least-32-bytes-long!';
    const WEAK_SECRET = 'too-short';
    const PEM_SECRET =
      '-----BEGIN PUBLIC KEY-----'#10 +
      'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEexample'#10 +
      '-----END PUBLIC KEY-----'#10;
    function NewToken: TJWT;
    function SignedToken: TJOSEBytes;
    function TamperedToken: TJOSEBytes;
  public
    // The convenience overloads must not opt out of key validation on the
    // caller's behalf: an under-length HMAC secret (RFC 7518 par. 3.2) or PEM
    // armour used as a shared secret has to be refused
    [Test]
    procedure TestSerializeCompactValidatesWeakKey;
    [Test]
    procedure TestSerializeCompactValidatesPEMAsHmacSecret;
    [Test]
    procedure TestShaCompactTokenValidatesWeakKey;
    [Test]
    procedure TestSerializeCompactCanStillSkipValidation;
    [Test]
    procedure TestSerializeCompactAcceptsAProperKey;

    // Verify keeps its documented contract, VerifyOrRaise is the strict one
    [Test]
    procedure TestVerifyReturnsUnverifiedToken;
    [Test]
    procedure TestVerifyOrRaiseRejectsTamperedSignature;
    [Test]
    procedure TestVerifyOrRaiseRejectsWrongKey;
    [Test]
    procedure TestVerifyOrRaiseReturnsVerifiedToken;
    [Test]
    procedure TestVerifyOrRaisePropagatesMalformedToken;
    [Test]
    procedure TestVerifyWithoutKeyRaises;

    // A claims class can now be passed to DeserializeCompact
    [Test]
    procedure TestDeserializeCompactUsesTheClaimsClass;

    [Test]
    procedure TestSHA384CompactTokenMatchesTheMisspelledOne;

    // The producer refuses to build with a key pair that carries no private key
    [Test]
    procedure TestProducerRejectsAKeyPairWithoutPrivateKey;
    [Test]
    procedure TestProducerBuildsWithAKey;
  end;

implementation

{ TCustomClaims }

function TCustomClaims.GetAppId: string;
begin
  Result := TJSONUtils.GetJSONValue('app_id', FJSON).AsString;
end;

procedure TCustomClaims.SetAppId(const AValue: string);
begin
  TJSONUtils.SetJSONValueFrom<string>('app_id', AValue, FJSON);
end;

{ TTestBuilder }

function TTestBuilder.NewToken: TJWT;
begin
  Result := TJWT.Create;
  Result.Claims.Subject := 'alice';
  Result.Claims.Expiration := IncMinute(Now, 30);
end;

function TTestBuilder.SignedToken: TJOSEBytes;
var
  LJWT: TJWT;
begin
  LJWT := NewToken;
  try
    Result := TJOSE.SerializeCompact(SECRET, TJOSEAlgorithmId.HS256, LJWT);
  finally
    LJWT.Free;
  end;
end;

function TTestBuilder.TamperedToken: TJOSEBytes;
var
  LToken: string;
begin
  LToken := SignedToken;
  if LToken[Length(LToken)] = 'A' then
    LToken[Length(LToken)] := 'B'
  else
    LToken[Length(LToken)] := 'A';
  Result := LToken;
end;

procedure TTestBuilder.TestSerializeCompactValidatesWeakKey;
var
  LJWT: TJWT;
begin
  LJWT := NewToken;
  try
    Assert.WillRaise(
      procedure begin TJOSE.SerializeCompact(WEAK_SECRET, TJOSEAlgorithmId.HS256, LJWT) end,
      EJOSEException, 'An under-length HMAC secret must not sign a token');
  finally
    LJWT.Free;
  end;
end;

procedure TTestBuilder.TestSerializeCompactValidatesPEMAsHmacSecret;
var
  LJWT: TJWT;
begin
  LJWT := NewToken;
  try
    Assert.WillRaise(
      procedure begin TJOSE.SerializeCompact(PEM_SECRET, TJOSEAlgorithmId.HS256, LJWT) end,
      EJOSEException, 'PEM armour must not be usable as a shared secret');
  finally
    LJWT.Free;
  end;
end;

procedure TTestBuilder.TestShaCompactTokenValidatesWeakKey;
var
  LJWT: TJWT;
begin
  LJWT := NewToken;
  try
    Assert.WillRaise(
      procedure begin TJOSE.SHA256CompactToken(WEAK_SECRET, LJWT) end,
      EJOSEException);
  finally
    LJWT.Free;
  end;
end;

procedure TTestBuilder.TestSerializeCompactCanStillSkipValidation;
var
  LJWT: TJWT;
  LKey: TJWK;
  LWeak, LCompact: TJOSEBytes;
begin
  LJWT := NewToken;
  LWeak := WEAK_SECRET;
  LKey := TJWK.Create(LWeak);
  try
    LCompact := TJOSE.SerializeCompact(LKey, TJOSEAlgorithmId.HS256, LJWT, True);
    Assert.IsTrue(TJOSE.CheckCompactToken(LCompact),
      'The 4-argument overload is the documented opt-out');
  finally
    LKey.Free;
    LJWT.Free;
  end;
end;

procedure TTestBuilder.TestSerializeCompactAcceptsAProperKey;
begin
  Assert.IsTrue(TJOSE.CheckCompactToken(SignedToken));
end;

procedure TTestBuilder.TestVerifyReturnsUnverifiedToken;
var
  LKey: TJOSEBytes;
  LJWT: TJWT;
begin
  LKey := SECRET;
  LJWT := TJOSE.Verify(LKey, TamperedToken);
  try
    // Documented behaviour: the token comes back, Verified says it is not valid
    Assert.IsNotNull(LJWT);
    Assert.IsFalse(LJWT.Verified);
  finally
    LJWT.Free;
  end;
end;

procedure TTestBuilder.TestVerifyOrRaiseRejectsTamperedSignature;
var
  LKey: TJOSEBytes;
  LToken: TJOSEBytes;
begin
  LKey := SECRET;
  LToken := TamperedToken;

  Assert.WillRaise(
    procedure begin TJOSE.VerifyOrRaise(LKey, LToken).Free end,
    EJOSEException);
end;

procedure TTestBuilder.TestVerifyOrRaiseRejectsWrongKey;
var
  LKey: TJOSEBytes;
  LToken: TJOSEBytes;
begin
  LKey := 'a-completely-different-secret-32bytes!!!!';
  LToken := SignedToken;

  Assert.WillRaise(
    procedure begin TJOSE.VerifyOrRaise(LKey, LToken).Free end,
    EJOSEException);
end;

procedure TTestBuilder.TestVerifyOrRaiseReturnsVerifiedToken;
var
  LKey: TJOSEBytes;
  LJWT: TJWT;
begin
  LKey := SECRET;
  LJWT := TJOSE.VerifyOrRaise(LKey, SignedToken);
  try
    Assert.IsNotNull(LJWT);
    Assert.IsTrue(LJWT.Verified);
    Assert.AreEqual('alice', LJWT.Claims.Subject);
  finally
    LJWT.Free;
  end;
end;

procedure TTestBuilder.TestVerifyOrRaisePropagatesMalformedToken;
var
  LKey: TJOSEBytes;
begin
  LKey := SECRET;

  // Verify returns nil for a token it cannot read, VerifyOrRaise says why
  Assert.IsNull(TJOSE.Verify(LKey, 'eyJhbGciOiJIUzI1NiJ9.InB3bmVkIg.c2ln'));
  Assert.WillRaise(
    procedure begin TJOSE.VerifyOrRaise(LKey, 'eyJhbGciOiJIUzI1NiJ9.InB3bmVkIg.c2ln').Free end,
    EJOSEException);
end;

procedure TTestBuilder.TestVerifyWithoutKeyRaises;
var
  LToken: TJOSEBytes;
begin
  LToken := SignedToken;

  // A nil key used to be dereferenced and reported as an unreadable token
  Assert.WillRaise(
    procedure begin TJOSE.Verify(TJWK(nil), LToken).Free end,
    EJOSEException);
end;

procedure TTestBuilder.TestDeserializeCompactUsesTheClaimsClass;
var
  LKey: TJOSEBytes;
  LJWT: TJWT;
begin
  LKey := SECRET;
  LJWT := TJOSE.DeserializeCompact(LKey, SignedToken, TCustomClaims);
  try
    Assert.IsNotNull(LJWT);
    Assert.InheritsFrom(LJWT.Claims.ClassType, TCustomClaims);
    Assert.AreEqual('alice', LJWT.ClaimsAs<TCustomClaims>.Subject);
  finally
    LJWT.Free;
  end;
end;

procedure TTestBuilder.TestSHA384CompactTokenMatchesTheMisspelledOne;
var
  LKey: TJOSEBytes;
  LJWT, LParsed: TJWT;
  LCompact: TJOSEBytes;
begin
  // HS384 needs 384 bits of key material, more than SECRET carries
  LKey := 'a-test-secret-of-at-least-48-bytes-long-for-hs384';
  LJWT := NewToken;
  try
    LCompact := TJOSE.SHA384CompactToken(LKey, LJWT);
    Assert.IsTrue(TJOSE.CheckCompactToken(LCompact));

    LParsed := TJOSE.DeserializeOnly(LCompact);
    try
      Assert.AreEqual('HS384', LParsed.Header.Algorithm);
    finally
      LParsed.Free;
    end;
  finally
    LJWT.Free;
  end;
end;

procedure TTestBuilder.TestProducerRejectsAKeyPairWithoutPrivateKey;
begin
  // SetKeyPair with an empty private half used to build happily and fail later,
  // inside the provider
  Assert.WillRaise(
    procedure
    begin
      TJOSEProcess.New
        .SetAlgorithm(TJOSEAlgorithmId.RS256)
        .SetKeyPair('-----BEGIN PUBLIC KEY-----'#10'x'#10'-----END PUBLIC KEY-----', '')
        .SetSubject('alice')
        .Build;
    end,
    EJOSEException);
end;

procedure TTestBuilder.TestProducerBuildsWithAKey;
var
  LProducer: IJOSEProducer;
begin
  LProducer := TJOSEProcess.New
    .SetAlgorithm(TJOSEAlgorithmId.HS256)
    .SetKey(SECRET)
    .SetSubject('alice')
    .Build;

  Assert.IsTrue(TJOSE.CheckCompactToken(LProducer.GetCompactToken));
end;

initialization
  TDUnitX.RegisterTestFixture(TTestBuilder);

end.
