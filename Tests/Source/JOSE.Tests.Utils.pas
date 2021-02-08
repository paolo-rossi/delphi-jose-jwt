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
unit JOSE.Tests.Utils;

interface

uses
  System.SysUtils, System.Classes, System.Rtti, System.JSON;

type

  TTestUtils = class
  public
    class function ExpectedFromFile(const AFileName: string): string;
  end;

implementation

uses
  System.IOUtils;

class function TTestUtils.ExpectedFromFile(const AFileName: string): string;
var
  LReader: TStreamReader;
begin
  LReader := TStreamReader.Create(AFileName, TEncoding.UTF8);
  try
    Result := LReader.ReadToEnd;
  finally
    LReader.Free;
  end;
end;

end.
