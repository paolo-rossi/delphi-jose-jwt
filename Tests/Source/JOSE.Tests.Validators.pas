{******************************************************************************}
{                                                                              }
{  Delphi JOSE-JWT Library                                                     }
{  Copyright (c) 2015 Paolo Rossi                                              }
{  https://github.com/paolo-rossi/delphi-jose-jwt                              }
{                                                                              }
{  Licensed under the MIT license                                              }
{                                                                              }
{******************************************************************************}
unit JOSE.Tests.Validators;

interface

uses
  System.SysUtils, System.DateUtils, DUnitX.TestFramework,

  JOSE.Types.Bytes,
  JOSE.Core.Base,
  JOSE.Core.Builder,
  JOSE.Core.JWA,
  JOSE.Core.JWT,
  JOSE.Consumer,
  JOSE.Consumer.Validators,
  JOSE.Context,

  JOSE.Tests.Classes;

type
  /// <summary>
  ///   Claim validation behaviour: the evaluation time must not be frozen into
  ///   a reused consumer, an optional claim must stay optional, the audience
  ///   must be matched value by value and the exp boundary must be exclusive
  /// </summary>
  [TestFixture]
  TTestValidators = class(TTestBase)
  private
    const SECRET = 'a-secret-of-at-least-32-bytes-for-hs256!';
    function Sign(AJWT: TJWT): TJOSEBytes;
    function TokenExpiringIn(ASeconds: Integer): TJOSEBytes;
    function Accepts(AConsumer: IJOSEConsumer; const AToken: TJOSEBytes): Boolean;
  public
    // The date params record is captured by the validator closure: reading the
    // evaluation time must not write it back, or a long-lived consumer would
    // keep validating against the instant of its very first call
    [Test]
    procedure TestEvaluationTimeIsNotCached;
    [Test]
    procedure TestStaticEvaluationTimeIsHonoured;
    [Test]
    procedure TestReusedConsumerRejectsTokenExpiredMeanwhile;

    // exp is exclusive: at exactly the evaluation time the token is expired
    [Test]
    procedure TestExpirationBoundaryIsExclusive;
    [Test]
    procedure TestExpirationOneSecondAheadIsAccepted;

    // An absent claim is a "required?" question, not a mismatch
    [Test]
    procedure TestOptionalIssuerAcceptsMissingClaim;
    [Test]
    procedure TestOptionalIssuerRejectsWrongClaim;
    [Test]
    procedure TestRequiredIssuerRejectsMissingClaim;
    [Test]
    procedure TestOptionalSubjectAcceptsMissingClaim;
    [Test]
    procedure TestOptionalJwtIdAcceptsMissingClaim;

    // The audience is matched value by value, not through a comma-joined string
    [Test]
    procedure TestAudienceWithCommaIsNotSplit;
    [Test]
    procedure TestAudienceArrayMatchesOneValue;
    [Test]
    procedure TestSingleAudienceMatches;
    [Test]
    procedure TestAudienceRoundTripKeepsTheComma;
    [Test]
    procedure TestAudiencePresentButNoneExpectedIsRejected;
  end;

implementation

function TTestValidators.Sign(AJWT: TJWT): TJOSEBytes;
begin
  Result := TJOSE.SerializeCompact(SECRET, TJOSEAlgorithmId.HS256, AJWT);
end;

function TTestValidators.TokenExpiringIn(ASeconds: Integer): TJOSEBytes;
var
  LJWT: TJWT;
begin
  LJWT := TJWT.Create;
  try
    LJWT.Claims.Subject := 'alice';
    LJWT.Claims.IssuedAt := Now;
    LJWT.Claims.Expiration := IncSecond(Now, ASeconds);
    Result := Sign(LJWT);
  finally
    LJWT.Free;
  end;
end;

function TTestValidators.Accepts(AConsumer: IJOSEConsumer; const AToken: TJOSEBytes): Boolean;
begin
  try
    AConsumer.Process(AToken);
    Result := True;
  except
    on E: EInvalidJWTException do
      Result := False;
  end;
end;

procedure TTestValidators.TestEvaluationTimeIsNotCached;
var
  LParams: TJOSEDateClaimsParams;
  LFirst, LSecond: TJOSENumericDate;
begin
  LParams := TJOSEDateClaimsParams.New;

  LFirst := LParams.EvaluationTime;
  Assert.AreEqual<TDateTime>(0, LParams.StaticEvaluationTime,
    'Reading EvaluationTime must not cache Now into StaticEvaluationTime');

  Sleep(1100);

  LSecond := LParams.EvaluationTime;
  Assert.IsTrue(LSecond.AsSeconds > LFirst.AsSeconds,
    'EvaluationTime must follow the clock, not the first reading');
end;

procedure TTestValidators.TestStaticEvaluationTimeIsHonoured;
var
  LParams: TJOSEDateClaimsParams;
  LStatic: TDateTime;
begin
  LParams := TJOSEDateClaimsParams.New;
  LStatic := EncodeDateTime(2020, 11, 29, 17, 17, 46, 0);
  LParams.StaticEvaluationTime := LStatic;

  Assert.AreEqual<TDateTime>(LStatic, LParams.EvaluationTime.AsDateTime);
  Assert.AreEqual<TDateTime>(LStatic, LParams.EvaluationTime.AsDateTime);
end;

procedure TTestValidators.TestReusedConsumerRejectsTokenExpiredMeanwhile;
var
  LConsumer: IJOSEConsumer;
  LToken: TJOSEBytes;
begin
  // The same consumer instance, used twice, as a service would
  LConsumer := TJOSEConsumerBuilder.NewConsumer
    .SetVerificationKey(SECRET)
    .SetExpectedAlgorithms([TJOSEAlgorithmId.HS256])
    .SetRequireExpirationTime
    .Build;

  LToken := TokenExpiringIn(1);
  Assert.IsTrue(Accepts(LConsumer, LToken), 'The token is still valid here');

  Sleep(2500);

  Assert.IsFalse(Accepts(LConsumer, LToken),
    'The token has expired: a reused consumer must re-read the clock');
end;

procedure TTestValidators.TestExpirationBoundaryIsExclusive;
var
  LConsumer: IJOSEConsumer;
  LJWT: TJWT;
  LNow: TDateTime;
begin
  LNow := Now;
  LConsumer := TJOSEConsumerBuilder.NewConsumer
    .SetVerificationKey(SECRET)
    .SetExpectedAlgorithms([TJOSEAlgorithmId.HS256])
    .SetRequireExpirationTime
    .SetEvaluationTime(LNow)
    .Build;

  LJWT := TJWT.Create;
  try
    LJWT.Claims.Expiration := LNow;
    Assert.IsFalse(Accepts(LConsumer, Sign(LJWT)),
      'RFC 7519 par. 4.1.4: the evaluation time must be before exp');
  finally
    LJWT.Free;
  end;
end;

procedure TTestValidators.TestExpirationOneSecondAheadIsAccepted;
var
  LConsumer: IJOSEConsumer;
  LJWT: TJWT;
  LNow: TDateTime;
begin
  LNow := Now;
  LConsumer := TJOSEConsumerBuilder.NewConsumer
    .SetVerificationKey(SECRET)
    .SetExpectedAlgorithms([TJOSEAlgorithmId.HS256])
    .SetRequireExpirationTime
    .SetEvaluationTime(LNow)
    .Build;

  LJWT := TJWT.Create;
  try
    LJWT.Claims.Expiration := IncSecond(LNow, 1);
    Assert.IsTrue(Accepts(LConsumer, Sign(LJWT)));
  finally
    LJWT.Free;
  end;
end;

procedure TTestValidators.TestOptionalIssuerAcceptsMissingClaim;
var
  LConsumer: IJOSEConsumer;
begin
  LConsumer := TJOSEConsumerBuilder.NewConsumer
    .SetVerificationKey(SECRET)
    .SetExpectedAlgorithms([TJOSEAlgorithmId.HS256])
    .SetExpectedIssuer(False, 'https://my-issuer')
    .Build;

  Assert.IsTrue(Accepts(LConsumer, TokenExpiringIn(600)),
    'ARequireIssuer=False means "must match when present"');
end;

procedure TTestValidators.TestOptionalIssuerRejectsWrongClaim;
var
  LConsumer: IJOSEConsumer;
  LJWT: TJWT;
begin
  LConsumer := TJOSEConsumerBuilder.NewConsumer
    .SetVerificationKey(SECRET)
    .SetExpectedAlgorithms([TJOSEAlgorithmId.HS256])
    .SetExpectedIssuer(False, 'https://my-issuer')
    .Build;

  LJWT := TJWT.Create;
  try
    LJWT.Claims.Issuer := 'https://another-issuer';
    LJWT.Claims.Expiration := IncMinute(Now, 10);
    Assert.IsFalse(Accepts(LConsumer, Sign(LJWT)));
  finally
    LJWT.Free;
  end;
end;

procedure TTestValidators.TestRequiredIssuerRejectsMissingClaim;
var
  LConsumer: IJOSEConsumer;
begin
  LConsumer := TJOSEConsumerBuilder.NewConsumer
    .SetVerificationKey(SECRET)
    .SetExpectedAlgorithms([TJOSEAlgorithmId.HS256])
    .SetExpectedIssuer(True, 'https://my-issuer')
    .Build;

  Assert.IsFalse(Accepts(LConsumer, TokenExpiringIn(600)));
end;

procedure TTestValidators.TestOptionalSubjectAcceptsMissingClaim;
var
  LConsumer: IJOSEConsumer;
  LJWT: TJWT;
begin
  LConsumer := TJOSEConsumerBuilder.NewConsumer
    .SetVerificationKey(SECRET)
    .SetExpectedAlgorithms([TJOSEAlgorithmId.HS256])
    .Build;

  LJWT := TJWT.Create;
  try
    LJWT.Claims.Expiration := IncMinute(Now, 10);
    Assert.IsTrue(Accepts(LConsumer, Sign(LJWT)));
  finally
    LJWT.Free;
  end;
end;

procedure TTestValidators.TestOptionalJwtIdAcceptsMissingClaim;
var
  LConsumer: IJOSEConsumer;
begin
  LConsumer := TJOSEConsumerBuilder.NewConsumer
    .SetVerificationKey(SECRET)
    .SetExpectedAlgorithms([TJOSEAlgorithmId.HS256])
    .Build;

  Assert.IsTrue(Accepts(LConsumer, TokenExpiringIn(600)));
end;

procedure TTestValidators.TestAudienceWithCommaIsNotSplit;
var
  LConsumer: IJOSEConsumer;
  LJWT: TJWT;
begin
  LConsumer := TJOSEConsumerBuilder.NewConsumer
    .SetVerificationKey(SECRET)
    .SetExpectedAlgorithms([TJOSEAlgorithmId.HS256])
    .SetExpectedAudience(True, ['internal-api'])
    .Build;

  LJWT := TJWT.Create;
  try
    // ONE audience value that happens to contain a comma
    LJWT.Claims.SetClaim('aud', 'public,internal-api');
    LJWT.Claims.Expiration := IncMinute(Now, 10);

    Assert.IsFalse(Accepts(LConsumer, Sign(LJWT)),
      'A single aud value must not be split on commas');
  finally
    LJWT.Free;
  end;
end;

procedure TTestValidators.TestAudienceArrayMatchesOneValue;
var
  LConsumer: IJOSEConsumer;
  LJWT: TJWT;
begin
  LConsumer := TJOSEConsumerBuilder.NewConsumer
    .SetVerificationKey(SECRET)
    .SetExpectedAlgorithms([TJOSEAlgorithmId.HS256])
    .SetExpectedAudience(True, ['internal-api'])
    .Build;

  LJWT := TJWT.Create;
  try
    LJWT.Claims.AudienceArray := ['public', 'internal-api'];
    LJWT.Claims.Expiration := IncMinute(Now, 10);

    Assert.IsTrue(Accepts(LConsumer, Sign(LJWT)));
  finally
    LJWT.Free;
  end;
end;

procedure TTestValidators.TestSingleAudienceMatches;
var
  LConsumer: IJOSEConsumer;
  LJWT: TJWT;
begin
  LConsumer := TJOSEConsumerBuilder.NewConsumer
    .SetVerificationKey(SECRET)
    .SetExpectedAlgorithms([TJOSEAlgorithmId.HS256])
    .SetExpectedAudience(True, ['internal-api'])
    .Build;

  LJWT := TJWT.Create;
  try
    LJWT.Claims.Audience := 'internal-api';
    LJWT.Claims.Expiration := IncMinute(Now, 10);

    Assert.IsTrue(Accepts(LConsumer, Sign(LJWT)));
  finally
    LJWT.Free;
  end;
end;

procedure TTestValidators.TestAudienceRoundTripKeepsTheComma;
var
  LJWT: TJWT;
  LAudience: TArray<string>;
begin
  LJWT := TJWT.Create;
  try
    LJWT.Claims.AudienceArray := ['public', 'a,b'];

    LAudience := LJWT.Claims.AudienceArray;
    Assert.AreEqual(2, Length(LAudience));
    Assert.AreEqual('public', LAudience[0]);
    Assert.AreEqual('a,b', LAudience[1]);
  finally
    LJWT.Free;
  end;
end;

procedure TTestValidators.TestAudiencePresentButNoneExpectedIsRejected;
var
  LConsumer: IJOSEConsumer;
  LJWT: TJWT;
begin
  // Default consumer: no expected audience configured
  LConsumer := TJOSEConsumerBuilder.NewConsumer
    .SetVerificationKey(SECRET)
    .SetExpectedAlgorithms([TJOSEAlgorithmId.HS256])
    .Build;

  LJWT := TJWT.Create;
  try
    LJWT.Claims.Audience := 'internal-api';
    LJWT.Claims.Expiration := IncMinute(Now, 10);

    Assert.IsFalse(Accepts(LConsumer, Sign(LJWT)));
  finally
    LJWT.Free;
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TTestValidators);

end.
