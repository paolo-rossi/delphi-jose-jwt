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

implementation

uses
  System.IOUtils,
  JOSE.Types.Utils;

{ TTestBase }

constructor TTestBase.Create;
begin
  FRootPath := TDirectory.GetCurrentDirectory;
  FDataPath := TPath.Combine(TJOSEUtils.DirectoryUp(FRootPath, 1), 'Data');
  FKeysPath := TPath.Combine(TJOSEUtils.DirectoryUp(FRootPath, 1), 'Keys');
end;

end.
