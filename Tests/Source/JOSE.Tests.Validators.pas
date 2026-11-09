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
  System.SysUtils, System.DateUtils, System.JSON, DUnitX.TestFramework,

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
    // 2026-10-25T00:30:00Z: 02:30 in Central Europe, in the first pass of the
    // hour repeated when DST ends
    const REPEATED_HOUR = Int64(1792888200);
    function Sign(AJWT: TJWT): TJOSEBytes;
    // The rejection message of a token carrying AClaimsJSON verbatim,
    // evaluated at REPEATED_HOUR; '' when the token is accepted
    function RejectionAtRepeatedHour(const AClaimsJSON: string): string;
    function TokenExpiringIn(ASeconds: Integer): TJOSEBytes;
    function Accepts(AConsumer: IJOSEConsumer; const AToken: TJOSEBytes): Boolean;
    function ExpiredTokenRejection(AConsumer: IJOSEConsumer): string;
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
    // exp is the instant in the token, not its round trip through local time
    [Test]
    procedure TestExpirationInTheRepeatedHourIsReadExactly;

    // A date claim that is present but unreadable is rejected, never read as
    // 0: an nbf read as 0 (1970) would let the token through at any time
    [Test]
    [TestCase('nbf string',       '{"nbf":"soon"}|nbf', '|')]
    [TestCase('nbf boolean',      '{"nbf":true}|nbf', '|')]
    [TestCase('nbf out of range', '{"nbf":1e308}|nbf', '|')]
    [TestCase('iat string',       '{"iat":"soon"}|iat', '|')]
    [TestCase('exp string',       '{"exp":"soon"}|exp', '|')]
    [TestCase('exp out of range', '{"exp":9223372036854775807}|exp', '|')]
    procedure TestUnreadableDateClaimIsRejected(const AClaimsJSON, AName: string);

    // RFC 7519 par. 2: a NumericDate need not be a whole number. The value is
    // rounded down to the second (evaluation at 1792888200)
    [Test]
    [TestCase('exp fractional ahead',   '{"exp":1792888201.5}|True', '|')]
    [TestCase('exp fractional past',    '{"exp":1792888199.5}|False', '|')]
    [TestCase('exp exponent form',      '{"exp":1.8e9}|True', '|')]
    [TestCase('nbf fractional ahead',   '{"nbf":1792888210.5}|False', '|')]
    [TestCase('nbf fractional past',    '{"nbf":1792888189.5}|True', '|')]
    [TestCase('nbf exponent form',      '{"nbf":1.8e9}|False', '|')]
    procedure TestNonIntegerNumericDate(const AClaimsJSON: string; AAccepted: Boolean);

    // SetEvaluationTime(TJOSENumericDate) takes an exact instant, which a
    // local TDateTime cannot give in the hour repeated when DST ends
    [Test]
    procedure TestEvaluationInstantIsExact;
    [Test]
    procedure TestLastEvaluationTimeSetterWins;

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
    // Rejection messages end up in logs: no claims set, no signature bytes
    [Test]
    procedure TestRejectionMessageOmitsTheClaims;
    [Test]
    procedure TestRejectionMessageKeepsTheDetails;
    [Test]
    procedure TestRejectionMessageCanIncludeTheClaims;
    [Test]
    procedure TestInvalidSignatureMessageOmitsTheSignature;

    [Test]
    procedure TestAudiencePresentAndNoneExpectedIsAccepted;
    [Test]
    procedure TestAudienceRequiredButNoneExpectedIsRejected;
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

procedure TTestValidators.TestExpirationInTheRepeatedHourIsReadExactly;
const
  // 2026-10-25T00:30:00Z: 02:30 in Central Europe, in the first pass of the
  // hour repeated when DST ends. Through a local TDateTime it read as 01:30Z
  EXPIRATION = Int64(1792888200);
var
  LConsumer: IJOSEConsumer;
  LJWT: TJWT;
  LMessage: string;
begin
  LConsumer := TJOSEConsumerBuilder.NewConsumer
    .SetVerificationKey(SECRET)
    .SetExpectedAlgorithms([TJOSEAlgorithmId.HS256])
    .SetRequireExpirationTime
    .SetEvaluationTime(EncodeDateTime(2027, 1, 1, 0, 0, 0, 0))
    .Build;

  LMessage := '';
  LJWT := TJWT.Create;
  try
    LJWT.Claims.SetClaimOfType<Int64>('exp', EXPIRATION);
    try
      LConsumer.Process(Sign(LJWT));
    except
      on E: EInvalidJWTException do
        LMessage := E.Message;
    end;
  finally
    LJWT.Free;
  end;

  Assert.IsTrue(LMessage.Contains('[exp=2026-10-25T00:30:00.000Z]'), LMessage);
end;

function TTestValidators.RejectionAtRepeatedHour(const AClaimsJSON: string): string;
var
  LConsumer: IJOSEConsumer;
  LClaims: TJSONObject;
  LPair: TJSONPair;
  LJWT: TJWT;
  LToken: TJOSEBytes;
begin
  LConsumer := TJOSEConsumerBuilder.NewConsumer
    .SetVerificationKey(SECRET)
    .SetExpectedAlgorithms([TJOSEAlgorithmId.HS256])
    .SetEvaluationTime(TJOSENumericDate.FromSeconds(REPEATED_HOUR))
    .Build;

  // The claims are copied verbatim, so that the token carries exactly the
  // JSON text under test ("1e308", "1.8e9", ...)
  LClaims := TJSONObject.ParseJSONValue(AClaimsJSON) as TJSONObject;
  try
    LJWT := TJWT.Create;
    try
      for LPair in LClaims do
        LJWT.Claims.JSON.AddPair(LPair.JsonString.Value, LPair.JsonValue.Clone as TJSONValue);
      LToken := Sign(LJWT);
    finally
      LJWT.Free;
    end;
  finally
    LClaims.Free;
  end;

  Result := '';
  try
    LConsumer.Process(LToken);
  except
    on E: EInvalidJWTException do
      Result := E.Message;
  end;
end;

procedure TTestValidators.TestUnreadableDateClaimIsRejected(const AClaimsJSON, AName: string);
var
  LMessage: string;
begin
  LMessage := RejectionAtRepeatedHour(AClaimsJSON);
  Assert.IsTrue(LMessage.Contains('[' + AName + '] claim is not a valid NumericDate'),
    'Got: ' + LMessage);
end;

procedure TTestValidators.TestNonIntegerNumericDate(const AClaimsJSON: string; AAccepted: Boolean);
var
  LMessage: string;
begin
  LMessage := RejectionAtRepeatedHour(AClaimsJSON);
  if AAccepted then
    Assert.IsEmpty(LMessage, 'The token was supposed to be accepted')
  else
  begin
    Assert.IsNotEmpty(LMessage, 'The token was supposed to be rejected');
    Assert.IsFalse(LMessage.Contains('not a valid NumericDate'),
      'The claim must be read, not refused as malformed. Got: ' + LMessage);
  end;
end;

procedure TTestValidators.TestEvaluationInstantIsExact;
var
  LBefore, LAt: IJOSEConsumer;
  LJWT: TJWT;
  LToken: TJOSEBytes;
begin
  LJWT := TJWT.Create;
  try
    LJWT.Claims.SetClaimOfType<Int64>('exp', REPEATED_HOUR);
    LToken := Sign(LJWT);
  finally
    LJWT.Free;
  end;

  LBefore := TJOSEConsumerBuilder.NewConsumer
    .SetVerificationKey(SECRET)
    .SetExpectedAlgorithms([TJOSEAlgorithmId.HS256])
    .SetEvaluationTime(TJOSENumericDate.FromSeconds(REPEATED_HOUR - 1))
    .Build;
  LAt := TJOSEConsumerBuilder.NewConsumer
    .SetVerificationKey(SECRET)
    .SetExpectedAlgorithms([TJOSEAlgorithmId.HS256])
    .SetEvaluationTime(TJOSENumericDate.FromUTC(EncodeDateTime(2026, 10, 25, 0, 30, 0, 0)))
    .Build;

  Assert.IsTrue(Accepts(LBefore, LToken), 'One second before exp the token is valid');
  Assert.IsFalse(Accepts(LAt, LToken), 'At exp the token is expired');
end;

procedure TTestValidators.TestLastEvaluationTimeSetterWins;
var
  LJWT: TJWT;
  LToken: TJOSEBytes;
  LConsumer: IJOSEConsumer;
begin
  LJWT := TJWT.Create;
  try
    LJWT.Claims.SetClaimOfType<Int64>('exp', REPEATED_HOUR);
    LToken := Sign(LJWT);
  finally
    LJWT.Free;
  end;

  // Instant (valid) then local time (expired): the local time wins
  LConsumer := TJOSEConsumerBuilder.NewConsumer
    .SetVerificationKey(SECRET)
    .SetExpectedAlgorithms([TJOSEAlgorithmId.HS256])
    .SetEvaluationTime(TJOSENumericDate.FromSeconds(REPEATED_HOUR - 1))
    .SetEvaluationTime(EncodeDateTime(2027, 1, 1, 0, 0, 0, 0))
    .Build;
  Assert.IsFalse(Accepts(LConsumer, LToken), 'The later TDateTime must replace the instant');

  // Local time (expired) then instant (valid): the instant wins
  LConsumer := TJOSEConsumerBuilder.NewConsumer
    .SetVerificationKey(SECRET)
    .SetExpectedAlgorithms([TJOSEAlgorithmId.HS256])
    .SetEvaluationTime(EncodeDateTime(2027, 1, 1, 0, 0, 0, 0))
    .SetEvaluationTime(TJOSENumericDate.FromSeconds(REPEATED_HOUR - 1))
    .Build;
  Assert.IsTrue(Accepts(LConsumer, LToken), 'The later instant must replace the TDateTime');
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
    Assert.AreEqual(2, Integer(Length(LAudience)));
    Assert.AreEqual('public', LAudience[0]);
    Assert.AreEqual('a,b', LAudience[1]);
  finally
    LJWT.Free;
  end;
end;

function TTestValidators.ExpiredTokenRejection(AConsumer: IJOSEConsumer): string;
var
  LJWT: TJWT;
  LToken: TJOSEBytes;
begin
  Result := '';
  LJWT := TJWT.Create;
  try
    LJWT.Claims.Subject := 'alice@example.com';
    LJWT.Claims.Expiration := IncMinute(Now, -10);
    LToken := Sign(LJWT);
  finally
    LJWT.Free;
  end;

  try
    AConsumer.Process(LToken);
  except
    on E: Exception do
      Result := E.Message;
  end;
  Assert.IsNotEmpty(Result, 'The token was supposed to be rejected');
end;

procedure TTestValidators.TestRejectionMessageOmitsTheClaims;
var
  LMessage: string;
begin
  LMessage := ExpiredTokenRejection(
    TJOSEConsumerBuilder.NewConsumer
      .SetVerificationKey(SECRET)
      .SetExpectedAlgorithms([TJOSEAlgorithmId.HS256])
      .SetRequireExpirationTime
      .Build);

  Assert.IsFalse(LMessage.Contains('alice@example.com'),
    'Claims carry personal data and must not be dumped into the message');
  Assert.IsFalse(LMessage.Contains('"sub"'));
end;

procedure TTestValidators.TestRejectionMessageKeepsTheDetails;
var
  LMessage: string;
begin
  LMessage := ExpiredTokenRejection(
    TJOSEConsumerBuilder.NewConsumer
      .SetVerificationKey(SECRET)
      .SetExpectedAlgorithms([TJOSEAlgorithmId.HS256])
      .SetRequireExpirationTime
      .Build);

  // Dropping the claims must not cost the reason for the rejection
  Assert.IsTrue(LMessage.Contains('Validation errors:'), LMessage);
  Assert.IsTrue(LMessage.Contains('no longer valid'), LMessage);
end;

procedure TTestValidators.TestRejectionMessageCanIncludeTheClaims;
var
  LMessage: string;
begin
  TJOSEConsumer.IncludeClaimsInExceptions := True;
  try
    LMessage := ExpiredTokenRejection(
      TJOSEConsumerBuilder.NewConsumer
        .SetVerificationKey(SECRET)
        .SetExpectedAlgorithms([TJOSEAlgorithmId.HS256])
        .SetRequireExpirationTime
        .Build);

    Assert.IsTrue(LMessage.Contains('alice@example.com'),
      'The opt-in switch must restore the claims dump');
  finally
    TJOSEConsumer.IncludeClaimsInExceptions := False;
  end;
end;

procedure TTestValidators.TestInvalidSignatureMessageOmitsTheSignature;
var
  LConsumer: IJOSEConsumer;
  LToken: string;
  LSignature, LMessage: string;
begin
  LConsumer := TJOSEConsumerBuilder.NewConsumer
    .SetVerificationKey(SECRET)
    .SetExpectedAlgorithms([TJOSEAlgorithmId.HS256])
    .Build;

  LToken := TokenExpiringIn(600);
  // flip the last character of the signature, keeping it valid base64url
  // ('A' and 'Q' leave the unused low bits at zero) so that the signature
  // check is what rejects the token
  if LToken[Length(LToken)] = 'A' then
    LToken[Length(LToken)] := 'Q'
  else
    LToken[Length(LToken)] := 'A';
  LSignature := LToken.Substring(LToken.LastIndexOf('.') + 1);

  LMessage := '';
  try
    LConsumer.Process(LToken);
  except
    on E: Exception do
      LMessage := E.Message;
  end;

  Assert.IsNotEmpty(LMessage, 'The token was supposed to be rejected');
  Assert.IsFalse(LMessage.Contains(LSignature),
    'Token material must not be echoed into the message');
end;

procedure TTestValidators.TestAudiencePresentAndNoneExpectedIsAccepted;
var
  LConsumer: IJOSEConsumer;
  LJWT: TJWT;
begin
  // Default consumer: no expected audience configured, so the aud claim is
  // simply not validated - carrying one must not be a reason to reject
  LConsumer := TJOSEConsumerBuilder.NewConsumer
    .SetVerificationKey(SECRET)
    .SetExpectedAlgorithms([TJOSEAlgorithmId.HS256])
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

procedure TTestValidators.TestAudienceRequiredButNoneExpectedIsRejected;
var
  LConsumer: IJOSEConsumer;
  LJWT: TJWT;
begin
  // Audience validation was asked for without giving anything to match:
  // that contradiction still has to be reported
  LConsumer := TJOSEConsumerBuilder.NewConsumer
    .SetVerificationKey(SECRET)
    .SetExpectedAlgorithms([TJOSEAlgorithmId.HS256])
    .SetExpectedAudience(True, [])
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
