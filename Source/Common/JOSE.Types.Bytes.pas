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

/// <summary>
///   Handy TBytes replacement
/// </summary>
unit JOSE.Types.Bytes;

interface

uses
  System.SysUtils, System.Classes;

type
  TJOSEBytes = record
  private
    FPayload: TBytes;

    procedure SetAsString(const Value: string);
    function GetAsString: string; inline;
  public
    class operator Implicit(const AValue: TJOSEBytes): string;
    class operator Implicit(const AValue: TJOSEBytes): TBytes;
    class operator Implicit(const AValue: string): TJOSEBytes;
    class operator Implicit(const AValue: TBytes): TJOSEBytes;

    class operator Equal(const A: TJOSEBytes; const B: TJOSEBytes): Boolean;
    class operator Equal(const A: TJOSEBytes; const B: string): Boolean;
    class operator Equal(const A: TJOSEBytes; const B: TBytes): Boolean;

    class operator Add(const A: TJOSEBytes; const B: TJOSEBytes): TJOSEBytes;
    class operator Add(const A: TJOSEBytes; const B: Byte): TJOSEBytes;
    class operator Add(const A: TJOSEBytes; const B: string): TJOSEBytes;
    class operator Add(const A: TJOSEBytes; const B: TBytes): TJOSEBytes;

    class function Empty: TJOSEBytes; static;
    class function RandomBytes(ANumberOfBytes: Integer): TJOSEBytes; static;

    function IsEmpty: Boolean;
    function Size: Integer;
    procedure Clear;

    function Contains(const AByte: Byte): Boolean; overload;
    function Contains(const ABytes: TBytes): Boolean; overload;
    function Contains(const ABytes: TJOSEBytes): Boolean; overload;

    property AsBytes: TBytes read FPayload write FPayload;
    property AsString: string read GetAsString write SetAsString;
  end;

  TBytesUtils = class
    class function MergeBytes(const ABytes1: TBytes; const ABytes2: TBytes): TBytes; overload; static;
    class function MergeBytes(const ABytes1: TBytes; const ABytes2: Byte): TBytes; overload; static;
  end;

implementation

{ CompareBytes }

function CompareBytes(const A, B: TBytes): Boolean;
var
  LLen: Integer;
begin
  LLen := Length(A);
  Result := LLen = Length(B);
  if Result and (LLen > 0) then
    Result := CompareMem(Pointer(A), Pointer(B), LLen);
end;

{ TJOSEBytes }

class operator TJOSEBytes.Add(const A: TJOSEBytes; const B: Byte): TJOSEBytes;
begin
  SetLength(Result.FPayload, A.Size + 1);
  Move(A.FPayload[0], Result.FPayload[0], A.Size);
  Result.FPayload[Result.Size-1] := B;
end;

class operator TJOSEBytes.Add(const A, B: TJOSEBytes): TJOSEBytes;
begin
  SetLength(Result.FPayload, A.Size + B.Size);
  Move(A.FPayload[0], Result.FPayload[0], A.Size);
  Move(B.FPayload[0], Result.FPayload[A.Size], B.Size);
end;

class operator TJOSEBytes.Add(const A: TJOSEBytes; const B: TBytes): TJOSEBytes;
begin
  SetLength(Result.FPayload, A.Size + Length(B));
  Move(A.FPayload[0], Result.FPayload[0], A.Size);
  Move(B[0], Result.FPayload[A.Size], Length(B));
end;

class operator TJOSEBytes.Add(const A: TJOSEBytes; const B: string): TJOSEBytes;
var
  LB: TBytes;
begin
  LB := TEncoding.UTF8.GetBytes(B);

  SetLength(Result.FPayload, A.Size + Length(LB));
  Move(A.FPayload[0], Result.FPayload[0], A.Size);
  Move(LB[0], Result.FPayload[A.Size], Length(LB));
end;

procedure TJOSEBytes.Clear;
begin
  SetLength(FPayload, 0);
end;

function TJOSEBytes.Contains(const AByte: Byte): Boolean;
var
  LIndex: Integer;
begin
  Result := False;
  for LIndex := 0 to Length(FPayload) - 1 do
    if FPayload[LIndex] = AByte then
      Exit(True);
end;

function TJOSEBytes.Contains(const ABytes: TBytes): Boolean;
var
  LIndex: Integer;
begin
  Result := False;
  if (Length(ABytes) > Length(FPayload)) or (Length(ABytes) = 0) then
    Exit;

  for LIndex := 0 to Length(FPayload) - 1 do
    if FPayload[LIndex] = ABytes[0] then
      if CompareMem(@FPayload[LIndex], @ABytes[0], Length(ABytes)) then
        Exit(True);
end;

function TJOSEBytes.Contains(const ABytes: TJOSEBytes): Boolean;
begin
  Result := Contains(ABytes.AsBytes);
end;

class function TJOSEBytes.Empty: TJOSEBytes;
begin
  SetLength(Result.FPayload, 0);
end;

class operator TJOSEBytes.Equal(const A: TJOSEBytes; const B: string): Boolean;
begin
  Result := CompareBytes(A.FPayload, TEncoding.UTF8.GetBytes(B));
end;

class operator TJOSEBytes.Equal(const A: TJOSEBytes; const B: TBytes): Boolean;
begin
  Result := CompareBytes(A.FPayload, B);
end;

class operator TJOSEBytes.Equal(const A: TJOSEBytes; const B: TJOSEBytes): Boolean;
begin
  Result := CompareBytes(A.FPayload, B.FPayload);
end;

function TJOSEBytes.GetAsString: string;
begin
  Result := TEncoding.UTF8.GetString(FPayload);
end;

class operator TJOSEBytes.Implicit(const AValue: TJOSEBytes): TBytes;
begin
  Result := AValue.AsBytes;
end;

class operator TJOSEBytes.Implicit(const AValue: TJOSEBytes): string;
begin
  Result := TEncoding.UTF8.GetString(AValue.FPayload);
end;

class operator TJOSEBytes.Implicit(const AValue: TBytes): TJOSEBytes;
begin
  Result.FPayload := AValue;
end;

function TJOSEBytes.IsEmpty: Boolean;
begin
  Result := Size = 0;
end;

class function TJOSEBytes.RandomBytes(ANumberOfBytes: Integer): TJOSEBytes;
var
  LIndex: Integer;
begin
  SetLength(Result.FPayload, ANumberOfBytes);
  for LIndex := 0 to ANumberOfBytes - 1 do
    Result.FPayload[LIndex] := Random(255);
end;

function TJOSEBytes.Size: Integer;
begin
  Result := Length(FPayload);
end;

class operator TJOSEBytes.Implicit(const AValue: string): TJOSEBytes;
begin
  Result.FPayload := TEncoding.UTF8.GetBytes(AValue);
end;

procedure TJOSEBytes.SetAsString(const Value: string);
begin
  FPayload := TEncoding.UTF8.GetBytes(Value);
end;

{ TBytesUtils }

class function TBytesUtils.MergeBytes(const ABytes1: TBytes; const ABytes2: TBytes): TBytes;
begin
  SetLength(Result, Length(ABytes1) + Length(ABytes2));
  Move(ABytes1[0], Result[0], Length(ABytes1));
  Move(ABytes2[0], Result[Length(ABytes1)], Length(ABytes2));
end;

class function TBytesUtils.MergeBytes(const ABytes1: TBytes; const ABytes2: Byte): TBytes;
begin
  SetLength(Result, Length(ABytes1) + 1);
  Move(ABytes1[0], Result[0], Length(ABytes1));
  Result[Length(Result)-1] := ABytes2;
end;

initialization
  Randomize;

end.
