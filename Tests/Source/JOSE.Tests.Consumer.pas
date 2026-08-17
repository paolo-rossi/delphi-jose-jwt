{******************************************************************************}
{                                                                              }
{  Delphi JOSE-JWT Library                                                     }
{  Copyright (c) 2015 Paolo Rossi                                              }
{  https://github.com/paolo-rossi/delphi-jose-jwt                              }
{                                                                              }
{  Licensed under the MIT license                                              }
{                                                                              }
{******************************************************************************}
unit JOSE.Tests.Consumer;

interface

uses
  System.Rtti, System.SysUtils, DUnitX.TestFramework,

  JOSE.Consumer,
  JOSE.Types.Bytes,
  JOSE.Core.Base,
  JOSE.Core.Builder,
  JOSE.Core.JWA,
  JOSE.Core.JWT,
  JOSE.Core.JWS,
  JOSE.Encoding.Base64,

  JOSE.Tests.Classes;

type
  [TestFixture]
  TTestConsumer = class(TTestBase)
  private
    // HS256 needs at least 256 bits of key material (RFC 7518 par. 3.2)
    const SECRET = 'a-test-secret-of-at-least-32-bytes-long!';
  private
    FJWT: TJWT;
    FCompact: TJOSEBytes;
  public
    constructor Create;
    destructor Destroy; override;

    [Setup]
    procedure Setup;
    [TearDown]
    procedure TearDown;

    [Test]
    [TestCase('TestSameDates', '1606666666,1606666676,1606666666')]
    procedure TestSameDates(IssuedAt, Expiration, NotBefore: Int64; _Result: Boolean);

    [Test]
    [TestCase('TestExpired', '1606666666,1606666676')]
    procedure TestExpired(Expiration, EvaluationTime: Int64; _Result: Boolean);

    [Test]
    procedure TestAlgNoneIsNotInTheDefaultExpectedAlgorithms;
    [Test]
    procedure TestRequireEncryptionRejectsAJWS;
    [Test]
    procedure TestNumericClaimsOfTheWrongTypeAreRejectedCleanly;
  end;

implementation

uses
  System.DateUtils;

constructor TTestConsumer.Create;
begin
  FJWT := TJWT.Create;
end;

destructor TTestConsumer.Destroy;
begin
  FJWT.Free;
  inherited;
end;

procedure TTestConsumer.Setup;
begin
  FJWT.Clear;
  FCompact.Clear;
end;

procedure TTestConsumer.TearDown;
begin
end;

procedure TTestConsumer.TestExpired(Expiration, EvaluationTime: Int64; _Result: Boolean);
var
  LConsumer: IJOSEConsumer;
begin
  FJWT.Claims.Expiration := UnixToDateTime(Expiration, False);

  FCompact := TJOSE.SerializeCompact(SECRET,  TJOSEAlgorithmId.HS256, FJWT);

  LConsumer := TJOSEConsumerBuilder.NewConsumer
    .SetClaimsClass(TJWTClaims)

    // JWS-related validation
    .SetVerificationKey(SECRET)
    .SetSkipVerificationKeyValidation

    // Time-related claims validation
    .SetRequireExpirationTime
    .SetEvaluationTime(UnixToDateTime(EvaluationTime, False))
    .SetAllowedClockSkew(0, TJOSETimeUnit.Seconds)
    .SetMaxFutureValidity(0, TJOSETimeUnit.Minutes)

    // Build the consumer object
    .Build()
  ;

  Assert.WillRaise(
    procedure begin LConsumer.Process(FCompact) end,
    EInvalidJWTException
  );

end;

procedure TTestConsumer.TestSameDates(IssuedAt, Expiration, NotBefore: Int64; _Result: Boolean);
begin
  FJWT.Claims.IssuedAt := UnixToDateTime(IssuedAt, False);
  FJWT.Claims.Expiration := UnixToDateTime(Expiration, False);
  FJWT.Claims.NotBefore := UnixToDateTime(NotBefore, False);

  FCompact := TJOSE.SerializeCompact(SECRET,  TJOSEAlgorithmId.HS256, FJWT);

  TJOSEConsumerBuilder.NewConsumer
    .SetClaimsClass(TJWTClaims)

    // JWS-related validation
    .SetVerificationKey(SECRET)
    .SetSkipVerificationKeyValidation

    // Time-related claims validation
    .SetRequireIssuedAt
    .SetRequireNotBefore
    .SetRequireExpirationTime
    // Inside the validity window: at exactly Expiration the token is already
    // expired (RFC 7519 par. 4.1.4), which TTestValidators covers on its own
    .SetEvaluationTime(IncSecond(FJWT.Claims.IssuedAt, 5))
    .SetAllowedClockSkew(0, TJOSETimeUnit.Seconds)
    .SetMaxFutureValidity(0, TJOSETimeUnit.Minutes)

    // Build the consumer object
    .Build()

      // Start the process of the Consumer Object
      .Process(FCompact)
  ;
end;

procedure TTestConsumer.TestAlgNoneIsNotInTheDefaultExpectedAlgorithms;
var
  LConsumer: IJOSEConsumer;
  LToken: string;
  LMessage: string;
begin
  LConsumer := TJOSEConsumerBuilder.NewConsumer
    .SetVerificationKey(SECRET)   // no SetExpectedAlgorithms: the default set applies
    .Build;

  LToken :=
    TBase64.URLEncode('{"alg":"none"}').AsString + '.' +
    TBase64.URLEncode('{"sub":"attacker"}').AsString + '.';

  LMessage := '';
  try
    LConsumer.Process(LToken);
  except
    on E: Exception do
      LMessage := E.Message;
  end;

  // Rejected by the allow-list, not merely because the algorithm happens to be
  // unregistered today
  Assert.IsTrue(LMessage.Contains('not listed among those expected'),
    'alg=none must not be in the default expected algorithms. Got: ' + LMessage);
end;

procedure TTestConsumer.TestRequireEncryptionRejectsAJWS;
var
  LConsumer: IJOSEConsumer;
begin
  FJWT.Claims.Subject := 'alice';
  FCompact := TJOSE.SerializeCompact(SECRET, TJOSEAlgorithmId.HS256, FJWT);

  LConsumer := TJOSEConsumerBuilder.NewConsumer
    .SetVerificationKey(SECRET)
    .SetExpectedAlgorithms([TJOSEAlgorithmId.HS256])
    .SetEnableRequireEncryption
    .Build;

  // The flag used to be stored and never read
  Assert.WillRaise(
    procedure begin LConsumer.Process(FCompact) end,
    EJOSEException, 'A signed-only token must not satisfy require-encryption');
end;

procedure TTestConsumer.TestNumericClaimsOfTheWrongTypeAreRejectedCleanly;
var
  LConsumer: IJOSEConsumer;
  LToken: string;
begin
  LConsumer := TJOSEConsumerBuilder.NewConsumer
    .SetVerificationKey(SECRET)
    .SetExpectedAlgorithms([TJOSEAlgorithmId.HS256])
    .SetSkipSignatureVerification
    .SetRequireExpirationTime
    .Build;

  // exp is unusable: the consumer must reject it as an invalid claim rather
  // than let EConvertError or EJSONConversionException escape
  LToken :=
    TBase64.URLEncode('{"alg":"HS256"}').AsString + '.' +
    TBase64.URLEncode('{"exp":1e308}').AsString + '.' +
    TBase64.URLEncode('sig').AsString;

  Assert.WillRaise(
    procedure begin LConsumer.Process(LToken) end,
    EInvalidJWTException);
end;

initialization
  TDUnitX.RegisterTestFixture(TTestConsumer);

end.

