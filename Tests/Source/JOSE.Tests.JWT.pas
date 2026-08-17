{******************************************************************************}
{                                                                              }
{  Delphi JOSE-JWT Library                                                     }
{  Copyright (c) 2015 Paolo Rossi                                              }
{  https://github.com/paolo-rossi/delphi-jose-jwt                              }
{                                                                              }
{  Licensed under the MIT license                                              }
{                                                                              }
{******************************************************************************}
unit JOSE.Tests.JWT;

interface

uses
  System.SysUtils, System.DateUtils, System.Rtti, System.JSON, DUnitX.TestFramework,

  JOSE.Types.JSON,
  JOSE.Core.Base,
  JOSE.Core.JWT,

  JOSE.Tests.Classes;

type
  /// <summary>
  ///   The date convention of the claims layer. Date claims travel as absolute
  ///   epoch seconds but are exposed as *local* TDateTime values, and every
  ///   comparison in the library is done in that same frame - nothing pinned
  ///   that before, so a change of convention would have gone unnoticed
  /// </summary>
  [TestFixture]
  TTestJWTDates = class(TTestBase)
  private
    const FIXED_EPOCH = Int64(1606666666);   // 2020-11-29T16:17:46Z
  private
    FJWT: TJWT;
    function RawClaim(const AName: string): Int64;
  public
    [Setup]
    procedure Setup;
    [TearDown]
    procedure TearDown;

    [Test]
    [TestCase('exp', 'exp')]
    [TestCase('iat', 'iat')]
    [TestCase('nbf', 'nbf')]
    procedure TestDateClaimIsStoredAsLocalEpochSeconds(const AClaim: string);

    [Test]
    [TestCase('exp', 'exp')]
    [TestCase('iat', 'iat')]
    [TestCase('nbf', 'nbf')]
    procedure TestDateClaimRoundTrips(const AClaim: string);

    [Test]
    procedure TestClaimWrittenElsewhereReadsAsTheSameInstant;
    [Test]
    procedure TestNumericDateUsesTheSameFrameAsTheClaims;
    [Test]
    procedure TestNumericDateSecondsRoundTrip;
    [Test]
    procedure TestNumericDateISO8601IsAnAbsoluteInstant;
    [Test]
    procedure TestComparisonsAreOffsetIndependent;
  end;

implementation

function TTestJWTDates.RawClaim(const AName: string): Int64;
begin
  Result := (FJWT.Claims.JSON.GetValue(AName) as TJSONNumber).AsInt64;
end;

procedure TTestJWTDates.Setup;
begin
  inherited;
  FJWT := TJWT.Create;
end;

procedure TTestJWTDates.TearDown;
begin
  FJWT.Free;
  inherited;
end;

procedure TTestJWTDates.TestDateClaimIsStoredAsLocalEpochSeconds(const AClaim: string);
var
  LLocal: TDateTime;
begin
  // The setter takes a local TDateTime and stores DateTimeToUnix(..., False):
  // on a machine at UTC+2 a claim written for 16:00 local goes out as 14:00Z
  LLocal := EncodeDateTime(2020, 11, 29, 16, 17, 46, 0);

  if AClaim = 'exp' then
    FJWT.Claims.Expiration := LLocal
  else if AClaim = 'iat' then
    FJWT.Claims.IssuedAt := LLocal
  else
    FJWT.Claims.NotBefore := LLocal;

  Assert.AreEqual<Int64>(DateTimeToUnix(LLocal, False), RawClaim(AClaim));
end;

procedure TTestJWTDates.TestDateClaimRoundTrips(const AClaim: string);
var
  LLocal, LReadBack: TDateTime;
begin
  LLocal := EncodeDateTime(2020, 11, 29, 16, 17, 46, 0);

  if AClaim = 'exp' then
  begin
    FJWT.Claims.Expiration := LLocal;
    LReadBack := FJWT.Claims.Expiration;
  end
  else if AClaim = 'iat' then
  begin
    FJWT.Claims.IssuedAt := LLocal;
    LReadBack := FJWT.Claims.IssuedAt;
  end
  else
  begin
    FJWT.Claims.NotBefore := LLocal;
    LReadBack := FJWT.Claims.NotBefore;
  end;

  Assert.AreEqual<TDateTime>(LLocal, LReadBack,
    'A date claim must survive the epoch round trip unchanged');
end;

procedure TTestJWTDates.TestClaimWrittenElsewhereReadsAsTheSameInstant;
begin
  // What a token minted by another system, in another timezone, looks like on
  // the wire: a bare epoch. It must read back as the local rendering of that
  // same instant, whatever this machine's offset is
  FJWT.Claims.SetClaimOfType<Int64>('exp', FIXED_EPOCH);

  Assert.AreEqual<TDateTime>(UnixToDateTime(FIXED_EPOCH, False), FJWT.Claims.Expiration);
  Assert.AreEqual<Int64>(FIXED_EPOCH, DateTimeToUnix(FJWT.Claims.Expiration, False));
end;

procedure TTestJWTDates.TestNumericDateUsesTheSameFrameAsTheClaims;
var
  LLocal: TDateTime;
  LDate: TJOSENumericDate;
begin
  // TJOSENumericDate is what the validators compare, so it has to agree with
  // the claims layer or every comparison is off by the UTC offset
  LLocal := EncodeDateTime(2020, 11, 29, 16, 17, 46, 0);
  FJWT.Claims.Expiration := LLocal;

  LDate := TJOSENumericDate.Create(FJWT.Claims.Expiration);
  Assert.AreEqual<Int64>(RawClaim('exp'), LDate.AsSeconds);
end;

procedure TTestJWTDates.TestNumericDateSecondsRoundTrip;
var
  LDate: TJOSENumericDate;
begin
  // AsSeconds and SetAsSeconds must be inverses of each other
  LDate.AsSeconds := FIXED_EPOCH;
  Assert.AreEqual<Int64>(FIXED_EPOCH, LDate.AsSeconds);
  Assert.AreEqual<TDateTime>(UnixToDateTime(FIXED_EPOCH, False), LDate.AsDateTime);

  LDate := TJOSENumericDate.FromSeconds(FIXED_EPOCH);
  Assert.AreEqual<Int64>(FIXED_EPOCH, LDate.AsSeconds);
end;

procedure TTestJWTDates.TestNumericDateISO8601IsAnAbsoluteInstant;
var
  LDate: TJOSENumericDate;
  LText: string;
begin
  // The rendering used in the rejection messages: it must denote the instant
  // the claim really carries, not the local wall clock stamped with a 'Z'
  LDate := TJOSENumericDate.FromSeconds(FIXED_EPOCH);
  LText := LDate.AsISO8601;

  Assert.AreEqual<Int64>(FIXED_EPOCH, DateTimeToUnix(ISO8601ToDate(LText, False), False),
    'AsISO8601 must round trip back to the same instant. Got: ' + LText);
end;

procedure TTestJWTDates.TestComparisonsAreOffsetIndependent;
var
  LEarlier, LLater: TJOSENumericDate;
begin
  // The ordering of two instants cannot depend on the machine's offset: both
  // sides go through the same conversion
  LEarlier := TJOSENumericDate.FromSeconds(FIXED_EPOCH);
  LLater := TJOSENumericDate.FromSeconds(FIXED_EPOCH + 60);

  Assert.IsTrue(LEarlier.IsBefore(LLater, 0));
  Assert.IsFalse(LLater.IsBefore(LEarlier, 0));
  Assert.IsTrue(LLater.IsOnOrAfter(LEarlier, 0));
  Assert.IsTrue(LLater.IsAfter(LEarlier, 0));

  // ... and the clock skew leeway is applied in seconds, symmetrically
  Assert.IsFalse(LEarlier.IsBefore(LLater, 60), 'A 60s leeway must absorb a 60s gap');
end;

initialization
  TDUnitX.RegisterTestFixture(TTestJWTDates);

end.
