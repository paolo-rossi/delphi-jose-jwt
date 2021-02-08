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

  JOSE.Tests.Classes;

type
  [TestFixture]
  TTestConsumer = class(TTestBase)
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

  FCompact := TJOSE.SerializeCompact('SuperSecretSeed',  TJOSEAlgorithmId.HS256, FJWT);

  LConsumer := TJOSEConsumerBuilder.NewConsumer
    .SetClaimsClass(TJWTClaims)

    // JWS-related validation
    .SetVerificationKey('SuperSecretSeed')
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

  FCompact := TJOSE.SerializeCompact('SuperSecretSeed',  TJOSEAlgorithmId.HS256, FJWT);

  TJOSEConsumerBuilder.NewConsumer
    .SetClaimsClass(TJWTClaims)

    // JWS-related validation
    .SetVerificationKey('SuperSecretSeed')
    .SetSkipVerificationKeyValidation

    // Time-related claims validation
    .SetRequireIssuedAt
    .SetRequireNotBefore
    .SetRequireExpirationTime
    .SetEvaluationTime(IncSecond(FJWT.Claims.IssuedAt, 10))
    .SetAllowedClockSkew(0, TJOSETimeUnit.Seconds)
    .SetMaxFutureValidity(0, TJOSETimeUnit.Minutes)

    // Build the consumer object
    .Build()

      // Start the process of the Consumer Object
      .Process(FCompact)
  ;
end;

initialization
  TDUnitX.RegisterTestFixture(TTestConsumer);

end.

