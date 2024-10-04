{******************************************************************************}
{                                                                              }
{  Delphi JOSE Library                                                         }
{  Copyright (c) 2015 Paolo Rossi                                              }
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

/// <summary>
///   Base64 utility class
/// </summary>
unit JOSE.Encoding.Base64;

{$I ..\JOSE.inc}

interface

uses
  System.SysUtils,
  {$IF CompilerVersion >= 28}
  System.NetEncoding,
  {$IFEND}
  JOSE.Types.Bytes;

type
  TBase64 = class
    class function Encode(const ASource: TJOSEBytes): TJOSEBytes; overload;
    class function Decode(const ASource: TJOSEBytes): TJOSEBytes; overload;
    class function TryDecode(const ASource: TJOSEBytes): TJOSEBytes;

    class function URLEncode(const ASource: TJOSEBytes): TJOSEBytes; overload;
    class function URLDecode(const ASource: TJOSEBytes): TJOSEBytes; overload;
    class function TryURLDecode(const ASource: TJOSEBytes): TJOSEBytes;
  end;

implementation

{$IF CompilerVersion <= 27}
type
  TPacket = packed record
    case Integer of
      0: (b0, b1, b2, b3: Byte);
      1: (i: Integer);
      2: (a: array[0..3] of Byte);
  end;

function DecodeBase64(const AInput: string): TBytes;
const
  DECODE_TABLE: array[#0..#127] of Integer = (
    Byte('='), 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
    64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
    64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64
  );

  function DecodePacket(AInputBuffer: PChar; var ANumChars: Integer): TPacket;
  begin
    Result.a[0] :=
      (DECODE_TABLE[AInputBuffer[0]] shl 2) or (DECODE_TABLE[AInputBuffer[1]] shr 4);
    ANumChars := 1;
    if AInputBuffer[2] <> '=' then
    begin
      Inc(ANumChars);
      Result.a[1] := (DECODE_TABLE[AInputBuffer[1]] shl 4) or (DECODE_TABLE[AInputBuffer[2]] shr 2);
    end;
    if AInputBuffer[3] <> '=' then
    begin
      Inc(ANumChars);
      Result.a[2] := (DECODE_TABLE[AInputBuffer[2]] shl 6) or DECODE_TABLE[AInputBuffer[3]];
    end;
  end;

var
  I, J, K: Integer;
  LPacket: TPacket;
  LLen: Integer;
begin
  SetLength(Result, Length(AInput) div 4 * 3);
  LLen := 0;
  for I := 1 to Length(AInput) div 4 do
  begin
    LPacket := DecodePacket(PChar(@AInput[(I - 1) * 4 + 1]), J);
    K := 0;
    while J > 0 do
    begin
      Result[LLen] := LPacket.a[K];
      Inc(LLen);
      Inc(K);
      Dec(J);
    end;
  end;
  SetLength(Result, LLen);
end;

function EncodeBase64(const AInput: TBytes): string;
const
  ENCODE_TABLE: array[0..63] of Char =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ' +
    'abcdefghijklmnopqrstuvwxyz' +
    '0123456789+/';

  procedure EncodePacket(const APacket: TPacket; ANumChars: Integer; AOutBuffer: PChar);
  begin
    AOutBuffer[0] := ENCODE_TABLE[APacket.a[0] shr 2];
    AOutBuffer[1] := ENCODE_TABLE[((APacket.a[0] shl 4) or (APacket.a[1] shr 4)) and $0000003f];

    if ANumChars < 2 then
      AOutBuffer[2] := '='
    else
      AOutBuffer[2] := ENCODE_TABLE[((APacket.a[1] shl 2) or (APacket.a[2] shr 6)) and $0000003f];

    if ANumChars < 3 then
      AOutBuffer[3] := '='
    else
      AOutBuffer[3] := ENCODE_TABLE[APacket.a[2] and $0000003f];
  end;

var
  I, K, J: Integer;
  LPacket: TPacket;
begin
  Result := '';
  I := (Length(AInput) div 3) * 4;
  if Length(AInput) mod 3 > 0 then
    Inc(I, 4);
  SetLength(Result, I);
  J := 1;
  for I := 1 to Length(AInput) div 3 do
  begin
    LPacket.i := 0;
    LPacket.a[0] := AInput[(I - 1) * 3];
    LPacket.a[1] := AInput[(I - 1) * 3 + 1];
    LPacket.a[2] := AInput[(I - 1) * 3 + 2];
    EncodePacket(LPacket, 3, PChar(@Result[J]));
    Inc(J, 4);
  end;
  K := 0;
  LPacket.i := 0;
  for I := Length(AInput) - (Length(AInput) mod 3) + 1 to Length(AInput) do
  begin
    LPacket.a[K] := Byte(AInput[I - 1]);
    Inc(K);
    if I = Length(AInput) then
      EncodePacket(LPacket, Length(AInput) mod 3, PChar(@Result[J]));
  end;
end;
{$IFEND}

{ TBase64 }

class function TBase64.Decode(const ASource: TJOSEBytes): TJOSEBytes;
begin
  {$IF CompilerVersion >= 28}
  Result := TNetEncoding.Base64.Decode(ASource.AsBytes);
  {$ELSE}
  Result := DecodeBase64(ASource.AsString);
  {$IFEND}
end;

class function TBase64.Encode(const ASource: TJOSEBytes): TJOSEBytes;
begin
  {$IF CompilerVersion >= 28}
  Result := TNetEncoding.Base64.Encode(ASource.AsBytes);
  {$ELSE}
  Result := EncodeBase64(ASource.AsBytes);
  {$IFEND}
end;

class function TBase64.TryDecode(const ASource: TJOSEBytes): TJOSEBytes;
begin
  try
    Result := Decode(ASource);
  except
    Result.Clear;
  end;
end;

class function TBase64.TryURLDecode(const ASource: TJOSEBytes): TJOSEBytes;
begin
  try
    Result := URLDecode(ASource);
  except
    Result.Clear;
  end;
end;

class function TBase64.URLDecode(const ASource: TJOSEBytes): TJOSEBytes;
var
  LBase64Str: string;
begin
  LBase64Str := ASource;

  LBase64Str := LBase64Str + StringOfChar('=', (4 - ASource.Size mod 4) mod 4);
  LBase64Str := StringReplace(LBase64Str, '-', '+', [rfReplaceAll]);
  LBase64Str := StringReplace(LBase64Str, '_', '/', [rfReplaceAll]);
  Result := TBase64.Decode(LBase64Str);
end;

class function TBase64.URLEncode(const ASource: TJOSEBytes): TJOSEBytes;
var
  LBase64Str: string;
begin
  LBase64Str := TBase64.Encode(ASource);

  LBase64Str := StringReplace(LBase64Str, #13#10, '', [rfReplaceAll]);
  LBase64Str := StringReplace(LBase64Str, #13, '', [rfReplaceAll]);
  LBase64Str := StringReplace(LBase64Str, #10, '', [rfReplaceAll]);
  LBase64Str := LBase64Str.TrimRight(['=']);

  LBase64Str := StringReplace(LBase64Str, '+', '-', [rfReplaceAll]);
  LBase64Str := StringReplace(LBase64Str, '/', '_', [rfReplaceAll]);

  Result := LBase64Str;
end;

end.

