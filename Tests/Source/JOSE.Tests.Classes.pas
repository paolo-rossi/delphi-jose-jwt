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
