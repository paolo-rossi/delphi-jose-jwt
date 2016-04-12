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

interface

uses
  System.SysUtils,
  {$IF CompilerVersion >= 28}
  System.NetEncoding,
  {$ENDIF}
  JOSE.Types.Bytes;

type
  TBase64 = class
    class function Encode(const ASource: TJOSEBytes): TJOSEBytes; overload;
    class function Decode(const ASource: TJOSEBytes): TJOSEBytes; overload;
    class function URLEncode(const ASource: TJOSEBytes): TJOSEBytes; overload;
    class function URLDecode(const ASource: TJOSEBytes): TJOSEBytes; overload;
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

function DecodeBase64(const Input: string): TBytes;
const
  DecodeTable: array[#0..#127] of Integer = (
    Byte('='), 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
    64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
    64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64);

  function DecodePacket(InBuf: PChar; var nChars: Integer): TPacket;
  begin
    Result.a[0] := (DecodeTable[InBuf[0]] shl 2) or
      (DecodeTable[InBuf[1]] shr 4);
    NChars := 1;
    if InBuf[2] <> '=' then
    begin
      Inc(NChars);
      Result.a[1] := (DecodeTable[InBuf[1]] shl 4) or (DecodeTable[InBuf[2]] shr 2);
    end;
    if InBuf[3] <> '=' then
    begin
      Inc(NChars);
      Result.a[2] := (DecodeTable[InBuf[2]] shl 6) or DecodeTable[InBuf[3]];
    end;
  end;

var
  I, J, K: Integer;
  Packet: TPacket;
  Len: integer;
begin
  SetLength(Result, Length(Input) div 4 * 3);
  Len := 0;
  for I := 1 to Length(Input) div 4 do
  begin
    Packet := DecodePacket(PChar(@Input[(I - 1) * 4 + 1]), J);
    K := 0;
    while J > 0 do
    begin
      Result[Len] := Packet.a[K];
      Inc(Len);
      Inc(K);
      Dec(J);
    end;
  end;
  SetLength(Result, Len);
end;

function EncodeBase64(const Input: TBytes): string;
const
  EncodeTable: array[0..63] of Char =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ' +
    'abcdefghijklmnopqrstuvwxyz' +
    '0123456789+/';

  procedure EncodePacket(const Packet: TPacket; NumChars: Integer; OutBuf: PChar);
  begin
    OutBuf[0] := EnCodeTable[Packet.a[0] shr 2];
    OutBuf[1] := EnCodeTable[((Packet.a[0] shl 4) or (Packet.a[1] shr 4)) and $0000003f];

    if NumChars < 2 then
      OutBuf[2] := '='
    else
      OutBuf[2] := EnCodeTable[((Packet.a[1] shl 2) or (Packet.a[2] shr 6)) and $0000003f];

    if NumChars < 3 then
      OutBuf[3] := '='
    else
      OutBuf[3] := EnCodeTable[Packet.a[2] and $0000003f];
  end;

var
  I, K, J: Integer;
  Packet: TPacket;
begin
  Result := '';
  I := (Length(Input) div 3) * 4;
  if Length(Input) mod 3 > 0 then Inc(I, 4);
  SetLength(Result, I);
  J := 1;
  for I := 1 to Length(Input) div 3 do
  begin
    Packet.i := 0;
    Packet.a[0] := Input[(I - 1) * 3];
    Packet.a[1] := Input[(I - 1) * 3 + 1];
    Packet.a[2] := Input[(I - 1) * 3 + 2];
    EncodePacket(Packet, 3, PChar(@Result[J]));
    Inc(J, 4);
  end;
  K := 0;
  Packet.i := 0;
  for I := Length(Input) - (Length(Input) mod 3) + 1 to Length(Input) do
  begin
    Packet.a[K] := Byte(Input[I - 1]);
    Inc(K);
    if I = Length(Input) then
      EncodePacket(Packet, Length(Input) mod 3, PChar(@Result[J]));
  end;
end;
{$ENDIF}

{ TBase64 }

class function TBase64.Decode(const ASource: TJOSEBytes): TJOSEBytes;
begin
  {$IF CompilerVersion >= 28}
  Result := TNetEncoding.Base64.Decode(ASource.AsBytes);
  {$ELSE}
  Result := EncodeBase64(ASource.AsBytes);
  {$ENDIF}
end;

class function TBase64.Encode(const ASource: TJOSEBytes): TJOSEBytes;
begin
  {$IF CompilerVersion >= 28}
  Result := TNetEncoding.Base64.Encode(ASource.AsBytes);
  {$ELSE}
  Result := DecodeBase64(ASource.AsString);
  {$ENDIF}
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
