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

unit JOSE.Types.Utils;

interface

uses
  System.SysUtils;

type
  TJOSEUtils = class
    class procedure ArrayPush(const ASource: TBytes; var ADest: TBytes; ACount: Integer);
    class function DirectoryUp(const ADirectory: string; ALevel: Integer = 1): string;
    class function BinToSingleHex(ABuffer: TBytes): string; overload;
    class function BinToSingleHex(ABuffer: Pointer; ABufferLen: Integer): string; overload;
  end;

implementation

uses
  System.IOUtils;

class procedure TJOSEUtils.ArrayPush(const ASource: TBytes; var ADest: TBytes; ACount: Integer);
var
  LIndex: Integer;
  LLen: Integer;
begin
  if ACount = 0 then
    Exit;

  LLen := Length(ADest);
  SetLength(ADest, LLen + ACount);

  for LIndex := 0 to ACount - 1 do
    ADest[LIndex + LLen] := ASource[LIndex];
end;

class function TJOSEUtils.BinToSingleHex(ABuffer: Pointer; ABufferLen: Integer): string;
const
  Convert: array[0..15] of AnsiChar = '0123456789ABCDEF';
var
  LIndex: Integer;
  LByte: PByte;
begin
  Result := '';
  for LIndex := 0 to ABufferLen - 1 do
  begin
    LByte := Pointer(Integer(ABuffer) + LIndex);
    Result := Result + string(Convert[(LByte^) and $F]);
  end;
end;

class function TJOSEUtils.DirectoryUp(const ADirectory: string; ALevel: Integer): string;
var
  LIndex: Integer;
begin
  Result := ADirectory;
  for LIndex := 1 to ALevel do
    Result := TDirectory.GetParent(Result);
end;

class function TJOSEUtils.BinToSingleHex(ABuffer: TBytes): string;
const
  Convert: array[0..15] of AnsiChar = '0123456789ABCDEF';
var
  LIndex: Integer;
begin
  Result := '';
  for LIndex := 0 to Length(ABuffer) - 1 do
  begin
    Result := Result + string(Convert[Byte(ABuffer[LIndex]) and $F]);
  end;
end;

end.
