{******************************************************************************}
{                                                                              }
{  Delphi JOSE-JWT Library                                                     }
{  Copyright (c) 2015 Paolo Rossi                                              }
{  https://github.com/paolo-rossi/delphi-jose-jwt                              }
{                                                                              }
{  Licensed under the MIT license                                              }
{                                                                              }
{******************************************************************************}
unit JOSE.Tests.Classes;

interface

uses
  System.SysUtils, System.Classes;

type
  /// <summary>
  ///   Base class for the Test classes
  /// </summary>
  TTestBase = class
  protected
    FRootPath: string;
    FDataPath: string;
    FKeysPath: string;
  public
    constructor Create;
  end;

  /// <summary>
  ///   The provider stack this runner tests: the one every fixture that does not
  ///   pin a stack of its own runs on. JOSE.Tests uses the default (OpenSSL 1.x/
  ///   Indy) stack; JOSE.Tests.TaurusTLS and JOSE.Tests.CryptoLib call
  ///   <c>Select</c> at startup, so the whole suite runs on their stack.
  /// </summary>
  /// <remarks>
  ///   A fixture that registers another stack (the provider tests, the
  ///   default-stack tests) must give it back with <c>Restore</c>, never with
  ///   <c>TJOSEProviders.RegisterProvider</c>, or every fixture after it would
  ///   silently run on the default stack.
  /// </remarks>
  TTestStack = class
  private
    class var FName: string;
    class var FRegister: TProc;
  public
    /// <summary>Makes ARegister the runner's stack and registers it</summary>
    class procedure Select(const AName: string; const ARegister: TProc); static;
    /// <summary>Registers the runner's stack again</summary>
    class procedure Restore; static;
    /// <summary>True when the runner tests the default stack</summary>
    class function IsDefault: Boolean; static;
    class function Name: string; static;
  end;

implementation

uses
  System.IOUtils,
  JOSE.Types.Utils,
  JOSE.Providers;

{ TTestBase }

constructor TTestBase.Create;
begin
  FRootPath := TDirectory.GetCurrentDirectory;
  FDataPath := TPath.Combine(TJOSEUtils.DirectoryUp(FRootPath, 1), 'Data');
  FKeysPath := TPath.Combine(TJOSEUtils.DirectoryUp(FRootPath, 1), 'Keys');
end;

{ TTestStack }

class procedure TTestStack.Select(const AName: string; const ARegister: TProc);
begin
  FName := AName;
  FRegister := ARegister;
  Restore;
end;

class procedure TTestStack.Restore;
begin
  if Assigned(FRegister) then
    FRegister()
  else
    TJOSEProviders.RegisterProvider;
end;

class function TTestStack.IsDefault: Boolean;
begin
  Result := not Assigned(FRegister);
end;

class function TTestStack.Name: string;
begin
  if IsDefault then
    Result := 'Default (OpenSSL 1.x/Indy)'
  else
    Result := FName;
end;

end.
