{******************************************************************************}
{                                                                              }
{  Delphi JOSE-JWT Library                                                     }
{  Copyright (c) 2015 Paolo Rossi                                              }
{  https://github.com/paolo-rossi/delphi-jose-jwt                              }
{                                                                              }
{  Licensed under the MIT license                                              }
{                                                                              }
{******************************************************************************}
program JOSE.Tests;

{$IFNDEF TESTINSIGHT}
  {$APPTYPE CONSOLE}
{$ENDIF}

{$STRONGLINKTYPES ON}
uses
  System.SysUtils,
  {$IFDEF TESTINSIGHT}
  TestInsight.DUnitX,
  {$ENDIF }
  DUnitX.Loggers.Console,
  DUnitX.Loggers.Xml.NUnit,
  DUnitX.TestFramework,
  JOSE.Tests.Builder in 'Source\JOSE.Tests.Builder.pas',
  JOSE.Tests.Consumer in 'Source\JOSE.Tests.Consumer.pas',
  JOSE.Tests.Context in 'Source\JOSE.Tests.Context.pas',
  JOSE.Tests.Validators in 'Source\JOSE.Tests.Validators.pas',
  JOSE.Tests.Concurrency in 'Source\JOSE.Tests.Concurrency.pas',
  JOSE.Tests.JWK in 'Source\JOSE.Tests.JWK.pas',
  JOSE.Tests.JWS in 'Source\JOSE.Tests.JWS.pas',
  JOSE.Tests.JWT in 'Source\JOSE.Tests.JWT.pas',
  JOSE.Tests.TimeUnit in 'Source\JOSE.Tests.TimeUnit.pas',
  JOSE.Tests.Utils in 'Source\JOSE.Tests.Utils.pas',
  JOSE.Tests.Common in 'Source\JOSE.Tests.Common.pas',
  JOSE.Tests.JWA.HMAC in 'Source\JOSE.Tests.JWA.HMAC.pas',
  JOSE.Tests.JWA.ECDSA in 'Source\JOSE.Tests.JWA.ECDSA.pas',
  JOSE.Tests.JWA.RSA in 'Source\JOSE.Tests.JWA.RSA.pas',
  JOSE.Tests.Providers in 'Source\JOSE.Tests.Providers.pas',
  JOSE.Tests.Classes in 'Source\JOSE.Tests.Classes.pas';

var
  LRunner : ITestRunner;
  LResults : IRunResults;
  LLogger : ITestLogger;
  LNUnitLogger : ITestLogger;
begin
  ReportMemoryLeaksOnShutdown := True;
{$IFDEF TESTINSIGHT}
  TestInsight.DUnitX.RunRegisteredTests;
  Exit;
{$ENDIF}
  try
    //Check command line options, will exit if invalid
    TDUnitX.CheckCommandLine;
    //Create the test runner
    LRunner := TDUnitX.CreateRunner;
    //Tell the runner to use RTTI to find Fixtures
    LRunner.UseRTTI := True;
    //tell the runner how we will log things
    //Log to the console window
    LLogger := TDUnitXConsoleLogger.Create(true);
    LRunner.AddLogger(LLogger);
    //Generate an NUnit compatible XML File
    LNUnitLogger := TDUnitXXMLNUnitFileLogger.Create(TDUnitX.Options.XMLOutputFile);
    LRunner.AddLogger(LNUnitLogger);
    LRunner.FailsOnNoAsserts := False; //When true, Assertions must be made during tests;

    //Run tests
    LResults := LRunner.Execute;
    if not LResults.AllPassed then
      System.ExitCode := EXIT_ERRORS;

    {$IFNDEF CI}
    //We don't want this happening when running under CI.
    if TDUnitX.Options.ExitBehavior = TDUnitXExitBehavior.Pause then
    begin
      System.Write('Done.. press <Enter> key to quit.');
      System.Readln;
    end;
    {$ENDIF}
  except
    on E: Exception do
      System.Writeln(E.ClassName, ': ', E.Message);
  end;
end.
