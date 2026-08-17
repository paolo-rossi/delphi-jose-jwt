{******************************************************************************}
{                                                                              }
{  Delphi JOSE-JWT Library                                                     }
{  Copyright (c) 2015 Paolo Rossi                                              }
{  https://github.com/paolo-rossi/delphi-jose-jwt                              }
{                                                                              }
{  Licensed under the MIT license                                              }
{******************************************************************************}
unit JOSE.Tests.Concurrency;

interface

uses
  System.SysUtils, System.Classes, System.DateUtils, System.IOUtils,
  System.SyncObjs, DUnitX.TestFramework,

  JOSE.Types.Bytes,
  JOSE.OpenSSL.Headers,
  JOSE.Core.Base,
  JOSE.Core.JWA,
  JOSE.Core.JWA.Factory,
  JOSE.Core.JWK,
  JOSE.Core.JWT,
  JOSE.Core.JWS,
  JOSE.Core.Builder,
  JOSE.Consumer,

  JOSE.Tests.Classes;

type
  /// <summary>
  ///   The library's shared state - the algorithm registry, the provider slots
  ///   and the lazily resolved OpenSSL entry points - is touched by every
  ///   verification. These tests hammer it from several threads at once
  /// </summary>
  /// <remarks>
  ///   These are smoke tests, not proof: the races they cover were fixed by
  ///   construction (the registry is built during unit initialization, the
  ///   lazy OpenSSL loads are serialized), and reverting either fix does not
  ///   make them fail reliably - two threads resolving the same entry points
  ///   write the same pointer values, so the damage is a wasted load and a
  ///   narrow window where one thread can see the "loaded" flag before the
  ///   "available" one. What these tests do catch is the coarser kind of
  ///   regression: shared mutable state reintroduced into a verification path.
  /// </remarks>
  [TestFixture]
  [Category('Concurrency')]
  TTestConcurrency = class(TTestBase)
  private
    const SECRET = 'a-test-secret-of-at-least-32-bytes-long!';
    const THREADS = 8;
    const ITERATIONS = 150;
  private
    FErrors: TStringList;
    FErrorLock: TCriticalSection;
    procedure RecordError(const AWhere: string; E: Exception);
    /// <summary>Runs AWork on THREADS threads at once and waits for them all</summary>
    procedure RunConcurrently(AWork: TProc<Integer>);
    procedure AssertNoErrors;
  public
    [Setup]
    procedure Setup;
    [TearDown]
    procedure TearDown;

    [Test]
    procedure TestConcurrentHmacVerification;
    [Test]
    procedure TestConcurrentSigningAndVerification;
    [Test]
    procedure TestRegistryInstanceIsShared;
    [Test]
    procedure TestConcurrentRSAVerification;
    [Test]
    procedure TestConcurrentPSSVerification;
    [Test]
    procedure TestConcurrentECDSAVerification;
  end;

implementation

procedure TTestConcurrency.Setup;
begin
  inherited;
  FErrors := TStringList.Create;
  FErrorLock := TCriticalSection.Create;
end;

procedure TTestConcurrency.TearDown;
begin
  FErrors.Free;
  FErrorLock.Free;
  inherited;
end;

procedure TTestConcurrency.RecordError(const AWhere: string; E: Exception);
begin
  FErrorLock.Enter;
  try
    FErrors.Add(AWhere + ': ' + E.ClassName + ' - ' + E.Message);
  finally
    FErrorLock.Leave;
  end;
end;

procedure TTestConcurrency.RunConcurrently(AWork: TProc<Integer>);
var
  LThreads: array of TThread;
  LIndex: Integer;
begin
  SetLength(LThreads, THREADS);

  for LIndex := 0 to THREADS - 1 do
  begin
    LThreads[LIndex] := TThread.CreateAnonymousThread(
      procedure
      var
        LIteration: Integer;
      begin
        try
          for LIteration := 1 to ITERATIONS do
            AWork(LIteration);
        except
          on E: Exception do
            RecordError('worker', E);
        end;
      end);
    LThreads[LIndex].FreeOnTerminate := False;
  end;

  // Started only once they all exist, so that they pile onto the shared state
  // together instead of the first one warming it up for the others
  for LIndex := 0 to THREADS - 1 do
    LThreads[LIndex].Start;

  try
    for LIndex := 0 to THREADS - 1 do
      LThreads[LIndex].WaitFor;
  finally
    for LIndex := 0 to THREADS - 1 do
      LThreads[LIndex].Free;
  end;
end;

procedure TTestConcurrency.AssertNoErrors;
begin
  Assert.AreEqual(0, FErrors.Count, FErrors.Text);
end;

procedure TTestConcurrency.TestConcurrentHmacVerification;
var
  LToken: TJOSEBytes;
  LJWT: TJWT;
begin
  LJWT := TJWT.Create;
  try
    LJWT.Claims.Subject := 'alice';
    LJWT.Claims.Expiration := IncMinute(Now, 30);
    LToken := TJOSE.SerializeCompact(SECRET, TJOSEAlgorithmId.HS256, LJWT);
  finally
    LJWT.Free;
  end;

  RunConcurrently(
    procedure (AIteration: Integer)
    var
      LConsumer: IJOSEConsumer;
    begin
      LConsumer := TJOSEConsumerBuilder.NewConsumer
        .SetVerificationKey(SECRET)
        .SetExpectedAlgorithms([TJOSEAlgorithmId.HS256])
        .Build;
      LConsumer.Process(LToken);
    end);

  AssertNoErrors;
end;

procedure TTestConcurrency.TestConcurrentSigningAndVerification;
begin
  // Producers and consumers on the same registry at the same time
  RunConcurrently(
    procedure (AIteration: Integer)
    var
      LJWT, LVerified: TJWT;
      LToken: TJOSEBytes;
      LKey: TJOSEBytes;
    begin
      LKey := SECRET;
      LJWT := TJWT.Create;
      try
        LJWT.Claims.Subject := 'alice-' + AIteration.ToString;
        LJWT.Claims.Expiration := IncMinute(Now, 30);
        LToken := TJOSE.SerializeCompact(LKey, TJOSEAlgorithmId.HS256, LJWT);
      finally
        LJWT.Free;
      end;

      LVerified := TJOSE.VerifyOrRaise(LKey, LToken);
      try
        if LVerified.Claims.Subject <> 'alice-' + AIteration.ToString then
          raise EJOSEException.Create('Claims crossed between threads');
      finally
        LVerified.Free;
      end;
    end);

  AssertNoErrors;
end;

procedure TTestConcurrency.TestRegistryInstanceIsShared;
var
  LInstance: TJOSEAlgorithmRegistryFactory;
begin
  // The lazy singleton used to be built without a lock: two threads arriving
  // together each got their own, and one was leaked with anything registered
  // on it. It is now created during unit initialization
  LInstance := TJOSEAlgorithmRegistryFactory.Instance;

  RunConcurrently(
    procedure (AIteration: Integer)
    begin
      if TJOSEAlgorithmRegistryFactory.Instance <> LInstance then
        raise EJOSEException.Create('The registry singleton is not shared');
      if TJOSEAlgorithmRegistryFactory.Instance.SigningAlgorithmRegistry
        .GetAlgorithm('HS256') = nil then
        raise EJOSEException.Create('HS256 missing from the registry');
    end);

  AssertNoErrors;
end;


procedure TTestConcurrency.TestConcurrentRSAVerification;
var
  LPrivate, LPublic: TJOSEBytes;
  LToken: TJOSEBytes;
  LJWT: TJWT;
begin
  LPrivate := TFile.ReadAllBytes(TPath.Combine(FKeysPath, 'rsa-private.pem'));
  LPublic := TFile.ReadAllBytes(TPath.Combine(FKeysPath, 'rsa-public.pem'));

  LJWT := TJWT.Create;
  try
    LJWT.Claims.Subject := 'alice';
    LJWT.Claims.Expiration := IncMinute(Now, 30);
    LToken := TJOSE.SerializeCompact(LPrivate, TJOSEAlgorithmId.RS256, LJWT);
  finally
    LJWT.Free;
  end;

  RunConcurrently(
    procedure (AIteration: Integer)
    begin
      TJOSE.VerifyOrRaise(LPublic, LToken).Free;
    end);

  AssertNoErrors;
end;

procedure TTestConcurrency.TestConcurrentPSSVerification;
var
  LPrivate, LPublic, LToken: TJOSEBytes;
  LJWT: TJWT;
begin
  // PS* resolves its OpenSSL entry points through EnsurePSSSupport on first
  // use: the load has to survive several threads reaching it at once
  LPrivate := TFile.ReadAllBytes(TPath.Combine(FKeysPath, 'rsa-private.pem'));
  LPublic := TFile.ReadAllBytes(TPath.Combine(FKeysPath, 'rsa-public.pem'));

  LJWT := TJWT.Create;
  try
    LJWT.Claims.Subject := 'alice';
    LJWT.Claims.Expiration := IncMinute(Now, 30);
    LToken := TJOSE.SerializeCompact(LPrivate, TJOSEAlgorithmId.PS256, LJWT);
  finally
    LJWT.Free;
  end;

  // Signing above already resolved the PSS entry points, which would leave the
  // threads below with nothing to race over: drop them so that all eight arrive
  // at the lazy load together
  JoseSSL.Unload;
  Assert.IsTrue(JoseSSL.Load, 'OpenSSL must reload for this test');

  RunConcurrently(
    procedure (AIteration: Integer)
    begin
      TJOSE.VerifyOrRaise(LPublic, LToken).Free;
    end);

  AssertNoErrors;
end;

procedure TTestConcurrency.TestConcurrentECDSAVerification;
var
  LPrivate, LPublic, LToken: TJOSEBytes;
  LJWT: TJWT;
begin
  LPrivate := TFile.ReadAllBytes(TPath.Combine(FKeysPath, 'es256-private.pem'));
  LPublic := TFile.ReadAllBytes(TPath.Combine(FKeysPath, 'es256-public.pem'));

  LJWT := TJWT.Create;
  try
    LJWT.Claims.Subject := 'alice';
    LJWT.Claims.Expiration := IncMinute(Now, 30);
    LToken := TJOSE.SerializeCompact(LPrivate, TJOSEAlgorithmId.ES256, LJWT);
  finally
    LJWT.Free;
  end;

  // Same as the PSS case: make the threads meet at EnsureECKeySupport
  JoseSSL.Unload;
  Assert.IsTrue(JoseSSL.Load, 'OpenSSL must reload for this test');

  RunConcurrently(
    procedure (AIteration: Integer)
    begin
      TJOSE.VerifyOrRaise(LPublic, LToken).Free;
    end);

  AssertNoErrors;
end;


initialization
  TDUnitX.RegisterTestFixture(TTestConcurrency);

end.
