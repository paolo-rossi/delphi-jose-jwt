{******************************************************************************}
{                                                                              }
{  Delphi JOSE-JWT Library                                                     }
{  Copyright (c) 2015 Paolo Rossi                                              }
{  https://github.com/paolo-rossi/delphi-jose-jwt                              }
{                                                                              }
{  Licensed under the MIT license                                              }
{                                                                              }
{******************************************************************************}

unit JOSE.Types.Utils;

{$I ..\JOSE.inc}

interface

uses
  System.SysUtils;

type
  TJOSEUtils = class
    class procedure ArrayPush(const ASource: TBytes; var ADest: TBytes; ACount: Integer);
    class function DirectoryUp(const ADirectory: string; ALevel: Integer = 1): string;
    class function BinToSingleHex(ABuffer: TBytes): string;
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
  HEX_DIGITS: array[0..15] of Char = (
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F');
var
  LIndex: Integer;
begin
  // A byte is two hex digits: masking with $F emitted the low nibble only, so
  // every high nibble was dropped ($1F and $2F both came out as "F")
  SetLength(Result, Length(ABuffer) * 2);
  for LIndex := 0 to Length(ABuffer) - 1 do
  begin
    Result[LIndex * 2 + 1] := HEX_DIGITS[ABuffer[LIndex] shr 4];
    Result[LIndex * 2 + 2] := HEX_DIGITS[ABuffer[LIndex] and $F];
  end;
end;

end.
