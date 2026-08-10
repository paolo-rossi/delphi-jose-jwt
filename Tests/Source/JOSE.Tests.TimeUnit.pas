{******************************************************************************}
{                                                                              }
{  Delphi JOSE-JWT Library                                                     }
{  Copyright (c) 2015 Paolo Rossi                                              }
{  https://github.com/paolo-rossi/delphi-jose-jwt                              }
{                                                                              }
{  Licensed under the MIT license                                              }
{                                                                              }
{******************************************************************************}

unit JOSE.Tests.TimeUnit;

interface

uses
  DUnitX.TestFramework,

  JOSE.Core.Base;

type
  [TestFixture]
  TTestJOSETimeUnitFromDays = class
  public
    [Test]
    procedure Days_ToDays;

    [Test]
    procedure Days_ToHours;

    [Test]
    procedure Days_ToMinutes;

    [Test]
    procedure Days_ToSeconds;

    [Test]
    procedure Days_ToMilliseconds;
  end;

  [TestFixture]
  TTestJOSETimeUnitFromHours = class
  public
    [Test]
    procedure Hours_ToDays_Exact;

    [Test]
    procedure Hours_ToDays_Truncated;

    [Test]
    procedure Hours_ToHours;

    [Test]
    procedure Hours_ToMinutes;

    [Test]
    procedure Hours_ToSeconds;

    [Test]
    procedure Hours_ToMilliseconds;
  end;

  [TestFixture]
  TTestJOSETimeUnitFromMinutes = class
  public
    [Test]
    procedure Minutes_ToDays_Exact;

    [Test]
    procedure Minutes_ToDays_Truncated;

    [Test]
    procedure Minutes_ToHours_Exact;

    [Test]
    procedure Minutes_ToHours_Truncated;

    [Test]
    procedure Minutes_ToMinutes;

    [Test]
    procedure Minutes_ToSeconds;

    [Test]
    procedure Minutes_ToMilliseconds;
  end;

  [TestFixture]
  TTestJOSETimeUnitFromSeconds = class
  public
    [Test]
    procedure Seconds_ToDays_Exact;

    [Test]
    procedure Seconds_ToDays_Truncated;

    [Test]
    procedure Seconds_ToHours_Exact;

    [Test]
    procedure Seconds_ToHours_Truncated;

    [Test]
    procedure Seconds_ToMinutes_Exact;

    [Test]
    procedure Seconds_ToMinutes_Truncated;

    [Test]
    procedure Seconds_ToSeconds;

    [Test]
    procedure Seconds_ToMilliseconds;
  end;

  [TestFixture]
  TTestJOSETimeUnitFromMilliseconds = class
  public
    [Test]
    procedure Milliseconds_ToDays_Exact;

    [Test]
    procedure Milliseconds_ToDays_Truncated;

    [Test]
    procedure Milliseconds_ToHours_Exact;

    [Test]
    procedure Milliseconds_ToHours_Truncated;

    [Test]
    procedure Milliseconds_ToMinutes_Exact;

    [Test]
    procedure Milliseconds_ToMinutes_Truncated;

    [Test]
    procedure Milliseconds_ToSeconds_Exact;

    [Test]
    procedure Milliseconds_ToSeconds_Truncated;

    [Test]
    procedure Milliseconds_ToMilliseconds;
  end;

  [TestFixture]
  TTestJOSETimeUnitZeroAndBoundary = class
  public
    [Test]
    procedure Zero_Days_ToMilliseconds;

    [Test]
    procedure Zero_Milliseconds_ToDays;

    [Test]
    procedure One_Day_ExactChain;
  end;

implementation

{ TTestJOSETimeUnitFromDays }

procedure TTestJOSETimeUnitFromDays.Days_ToDays;
begin
  Assert.AreEqual(UInt64(3), TJOSETimeUnit.Days.ToDays(3));
end;

procedure TTestJOSETimeUnitFromDays.Days_ToHours;
begin
  // 2 days = 48 hours
  Assert.AreEqual(UInt64(48), TJOSETimeUnit.Days.ToHours(2));
end;

procedure TTestJOSETimeUnitFromDays.Days_ToMinutes;
begin
  // 1 day = 1440 minutes
  Assert.AreEqual(UInt64(1440), TJOSETimeUnit.Days.ToMinutes(1));
end;

procedure TTestJOSETimeUnitFromDays.Days_ToSeconds;
begin
  // 1 day = 86400 seconds
  Assert.AreEqual(UInt64(86400), TJOSETimeUnit.Days.ToSeconds(1));
end;

procedure TTestJOSETimeUnitFromDays.Days_ToMilliseconds;
begin
  // 1 day = 86400000 ms
  Assert.AreEqual(UInt64(86400000), TJOSETimeUnit.Days.ToMilliseconds(1));
end;

{ TTestJOSETimeUnitFromHours }

procedure TTestJOSETimeUnitFromHours.Hours_ToDays_Exact;
begin
  // 48 hours = 2 days
  Assert.AreEqual(UInt64(2), TJOSETimeUnit.Hours.ToDays(48));
end;

procedure TTestJOSETimeUnitFromHours.Hours_ToDays_Truncated;
begin
  // 25 hours = 1 day (truncated)
  Assert.AreEqual(UInt64(1), TJOSETimeUnit.Hours.ToDays(25));
end;

procedure TTestJOSETimeUnitFromHours.Hours_ToHours;
begin
  Assert.AreEqual(UInt64(7), TJOSETimeUnit.Hours.ToHours(7));
end;

procedure TTestJOSETimeUnitFromHours.Hours_ToMinutes;
begin
  // 2 hours = 120 minutes
  Assert.AreEqual(UInt64(120), TJOSETimeUnit.Hours.ToMinutes(2));
end;

procedure TTestJOSETimeUnitFromHours.Hours_ToSeconds;
begin
  // 1 hour = 3600 seconds
  Assert.AreEqual(UInt64(3600), TJOSETimeUnit.Hours.ToSeconds(1));
end;

procedure TTestJOSETimeUnitFromHours.Hours_ToMilliseconds;
begin
  // 1 hour = 3600000 ms
  Assert.AreEqual(UInt64(3600000), TJOSETimeUnit.Hours.ToMilliseconds(1));
end;

{ TTestJOSETimeUnitFromMinutes }

procedure TTestJOSETimeUnitFromMinutes.Minutes_ToDays_Exact;
begin
  // 2880 minutes = 2 days
  Assert.AreEqual(UInt64(2), TJOSETimeUnit.Minutes.ToDays(2880));
end;

procedure TTestJOSETimeUnitFromMinutes.Minutes_ToDays_Truncated;
begin
  // 1500 minutes = 1 day (truncated)
  Assert.AreEqual(UInt64(1), TJOSETimeUnit.Minutes.ToDays(1500));
end;

procedure TTestJOSETimeUnitFromMinutes.Minutes_ToHours_Exact;
begin
  // 120 minutes = 2 hours
  Assert.AreEqual(UInt64(2), TJOSETimeUnit.Minutes.ToHours(120));
end;

procedure TTestJOSETimeUnitFromMinutes.Minutes_ToHours_Truncated;
begin
  // 75 minutes = 1 hour (truncated)
  Assert.AreEqual(UInt64(1), TJOSETimeUnit.Minutes.ToHours(75));
end;

procedure TTestJOSETimeUnitFromMinutes.Minutes_ToMinutes;
begin
  Assert.AreEqual(UInt64(45), TJOSETimeUnit.Minutes.ToMinutes(45));
end;

procedure TTestJOSETimeUnitFromMinutes.Minutes_ToSeconds;
begin
  // 3 minutes = 180 seconds
  Assert.AreEqual(UInt64(180), TJOSETimeUnit.Minutes.ToSeconds(3));
end;

procedure TTestJOSETimeUnitFromMinutes.Minutes_ToMilliseconds;
begin
  // 2 minutes = 120000 ms
  Assert.AreEqual(UInt64(120000), TJOSETimeUnit.Minutes.ToMilliseconds(2));
end;

{ TTestJOSETimeUnitFromSeconds }

procedure TTestJOSETimeUnitFromSeconds.Seconds_ToDays_Exact;
begin
  // 172800 seconds = 2 days
  Assert.AreEqual(UInt64(2), TJOSETimeUnit.Seconds.ToDays(172800));
end;

procedure TTestJOSETimeUnitFromSeconds.Seconds_ToDays_Truncated;
begin
  // 90000 seconds = 1 day (truncated)
  Assert.AreEqual(UInt64(1), TJOSETimeUnit.Seconds.ToDays(90000));
end;

procedure TTestJOSETimeUnitFromSeconds.Seconds_ToHours_Exact;
begin
  // 7200 seconds = 2 hours
  Assert.AreEqual(UInt64(2), TJOSETimeUnit.Seconds.ToHours(7200));
end;

procedure TTestJOSETimeUnitFromSeconds.Seconds_ToHours_Truncated;
begin
  // 3700 seconds = 1 hour (truncated)
  Assert.AreEqual(UInt64(1), TJOSETimeUnit.Seconds.ToHours(3700));
end;

procedure TTestJOSETimeUnitFromSeconds.Seconds_ToMinutes_Exact;
begin
  // 180 seconds = 3 minutes
  Assert.AreEqual(UInt64(3), TJOSETimeUnit.Seconds.ToMinutes(180));
end;

procedure TTestJOSETimeUnitFromSeconds.Seconds_ToMinutes_Truncated;
begin
  // 70 seconds = 1 minute (truncated)
  Assert.AreEqual(UInt64(1), TJOSETimeUnit.Seconds.ToMinutes(70));
end;

procedure TTestJOSETimeUnitFromSeconds.Seconds_ToSeconds;
begin
  Assert.AreEqual(UInt64(30), TJOSETimeUnit.Seconds.ToSeconds(30));
end;

procedure TTestJOSETimeUnitFromSeconds.Seconds_ToMilliseconds;
begin
  // 5 seconds = 5000 ms
  Assert.AreEqual(UInt64(5000), TJOSETimeUnit.Seconds.ToMilliseconds(5));
end;

{ TTestJOSETimeUnitFromMilliseconds }

procedure TTestJOSETimeUnitFromMilliseconds.Milliseconds_ToDays_Exact;
begin
  // 172800000 ms = 2 days
  Assert.AreEqual(UInt64(2), TJOSETimeUnit.Milliseconds.ToDays(172800000));
end;

procedure TTestJOSETimeUnitFromMilliseconds.Milliseconds_ToDays_Truncated;
begin
  // 90000000 ms = 1 day (truncated)
  Assert.AreEqual(UInt64(1), TJOSETimeUnit.Milliseconds.ToDays(90000000));
end;

procedure TTestJOSETimeUnitFromMilliseconds.Milliseconds_ToHours_Exact;
begin
  // 7200000 ms = 2 hours
  Assert.AreEqual(UInt64(2), TJOSETimeUnit.Milliseconds.ToHours(7200000));
end;

procedure TTestJOSETimeUnitFromMilliseconds.Milliseconds_ToHours_Truncated;
begin
  // 3700000 ms = 1 hour (truncated)
  Assert.AreEqual(UInt64(1), TJOSETimeUnit.Milliseconds.ToHours(3700000));
end;

procedure TTestJOSETimeUnitFromMilliseconds.Milliseconds_ToMinutes_Exact;
begin
  // 180000 ms = 3 minutes
  Assert.AreEqual(UInt64(3), TJOSETimeUnit.Milliseconds.ToMinutes(180000));
end;

procedure TTestJOSETimeUnitFromMilliseconds.Milliseconds_ToMinutes_Truncated;
begin
  // 70000 ms = 1 minute (truncated)
  Assert.AreEqual(UInt64(1), TJOSETimeUnit.Milliseconds.ToMinutes(70000));
end;

procedure TTestJOSETimeUnitFromMilliseconds.Milliseconds_ToSeconds_Exact;
begin
  // 5000 ms = 5 seconds
  Assert.AreEqual(UInt64(5), TJOSETimeUnit.Milliseconds.ToSeconds(5000));
end;

procedure TTestJOSETimeUnitFromMilliseconds.Milliseconds_ToSeconds_Truncated;
begin
  // 1500 ms = 1 second (truncated)
  Assert.AreEqual(UInt64(1), TJOSETimeUnit.Milliseconds.ToSeconds(1500));
end;

procedure TTestJOSETimeUnitFromMilliseconds.Milliseconds_ToMilliseconds;
begin
  Assert.AreEqual(UInt64(999), TJOSETimeUnit.Milliseconds.ToMilliseconds(999));
end;

{ TTestJOSETimeUnitZeroAndBoundary }

procedure TTestJOSETimeUnitZeroAndBoundary.Zero_Days_ToMilliseconds;
begin
  Assert.AreEqual(UInt64(0), TJOSETimeUnit.Days.ToMilliseconds(0));
end;

procedure TTestJOSETimeUnitZeroAndBoundary.Zero_Milliseconds_ToDays;
begin
  Assert.AreEqual(UInt64(0), TJOSETimeUnit.Milliseconds.ToDays(0));
end;

procedure TTestJOSETimeUnitZeroAndBoundary.One_Day_ExactChain;
var
  LOneDayInMs: UInt64;
  LBackToDays: UInt64;
begin
  // Round-trip: 1 day -> ms -> days
  LOneDayInMs := TJOSETimeUnit.Days.ToMilliseconds(1);
  Assert.AreEqual(UInt64(86400000), LOneDayInMs);

  LBackToDays := TJOSETimeUnit.Milliseconds.ToDays(LOneDayInMs);
  Assert.AreEqual(UInt64(1), LBackToDays);
end;

initialization
  TDUnitX.RegisterTestFixture(TTestJOSETimeUnitFromDays);
  TDUnitX.RegisterTestFixture(TTestJOSETimeUnitFromHours);
  TDUnitX.RegisterTestFixture(TTestJOSETimeUnitFromMinutes);
  TDUnitX.RegisterTestFixture(TTestJOSETimeUnitFromSeconds);
  TDUnitX.RegisterTestFixture(TTestJOSETimeUnitFromMilliseconds);
  TDUnitX.RegisterTestFixture(TTestJOSETimeUnitZeroAndBoundary);

end.
