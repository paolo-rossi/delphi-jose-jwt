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
///   Handy TArray<T> replacement
/// </summary>
unit JOSE.Types.Arrays;

{$I ..\JOSE.inc}

interface

uses
  System.SysUtils,
  System.Classes,
  System.Generics.Defaults;

type
  TJOSEArray<T> = record
  private
    FPayload: TArray<T>;
    function GetSize: NativeInt; inline;
    function GetLast: T;
    procedure SetLast(const Value: T);
    function GetAsArray: TArray<T>;
    procedure SetAsArray(const Value: TArray<T>);
    function GetFirst: T;
    procedure SetFirst(const Value: T);
    procedure SetSize(const Value: NativeInt);
  public
    class function Create: TJOSEArray<T>; static;
  public
    class operator Implicit(const AValue: TArray<T>): TJOSEArray<T>;
    class operator Implicit(const AValue: TJOSEArray<T>): TArray<T>;
    class operator Add(const A: TJOSEArray<T>; const B: T): TJOSEArray<T>;
    class operator Add(const A: T; const B: TJOSEArray<T>): TJOSEArray<T>;
    class operator Add(const A, B: TJOSEArray<T>): TJOSEArray<T>;
  public
    procedure Empty;
    function Push(AItem: T): Integer;
    function Pop: T;
    function Shift: T;
    procedure Join(const AValue: TJOSEArray<T>); overload;
    procedure Join(const AValue: TArray<T>); overload;
    function Contains(const AValue: T): Boolean;
    function IsEmpty: Boolean;
    function ToString: string;
    function ToStringPluralForm(const APluralPrefix: string): string;

    property Size: NativeInt read GetSize write SetSize;
    property First: T read GetFirst write SetFirst;
    property Last: T read GetLast write SetLast;
    property AsArray: TArray<T> read GetAsArray write SetAsArray;
  end;

implementation

uses
  System.Rtti;

{ TJOSEArray<T> }

function TJOSEArray<T>.Contains(const AValue: T): Boolean;
var
  LComparer: IComparer<T>;
  LItem: T;
begin
  LComparer := TComparer<T>.Default;
  Result := False;
  for LItem in FPayload do
    if LComparer.Compare(LItem, AValue) = 0 then
      Exit(True);
end;

class function TJOSEArray<T>.Create: TJOSEArray<T>;
begin
  Result.Empty;
end;

procedure TJOSEArray<T>.Empty;
begin
  SetLength(FPayload, 0);
end;

function TJOSEArray<T>.GetAsArray: TArray<T>;
begin
  Result := FPayload;
end;

function TJOSEArray<T>.GetFirst: T;
begin
  if Size = 0 then
    raise Exception.Create('Error Message');

  Result := FPayload[0];
end;

function TJOSEArray<T>.GetLast: T;
begin
  if Size = 0 then
    raise Exception.Create('Error Message');

  Result := FPayload[Size - 1];
end;

function TJOSEArray<T>.GetSize: NativeInt;
begin
  Result := Length(FPayload);
end;

class operator TJOSEArray<T>.Implicit(const AValue: TArray<T>): TJOSEArray<T>;
begin
  Result.FPayload := AValue;
end;

class operator TJOSEArray<T>.Implicit(const AValue: TJOSEArray<T>): TArray<T>;
begin
  Result := AValue.FPayload;
end;

class operator TJOSEArray<T>.Add(const A: TJOSEArray<T>; const B: T): TJOSEArray<T>;
begin
  Result.FPayload := A;
  Result.Push(B);
end;

class operator TJOSEArray<T>.Add(const A: T; const B: TJOSEArray<T>): TJOSEArray<T>;
begin
  Result.FPayload := B;
  Result.Push(A);
end;

class operator TJOSEArray<T>.Add(const A, B: TJOSEArray<T>): TJOSEArray<T>;
begin
  Result := A;
  if B.Size = 0 then
    Exit;

  Result.Join(B);
end;

function TJOSEArray<T>.IsEmpty: Boolean;
begin
  Result := Length(FPayload) = 0;
end;

procedure TJOSEArray<T>.Join(const AValue: TJOSEArray<T>);
var
  LSizeSource, LSizeDest: NativeInt;
begin
  LSizeSource := AValue.Size;
  if LSizeSource = 0 then
    Exit;

  LSizeDest := Size;
  Size := LSizeDest + LSizeSource;
  Move(AValue.FPayload[0], FPayload[LSizeDest], SizeOf(T) * LSizeSource);
end;

procedure TJOSEArray<T>.Join(const AValue: TArray<T>);
var
  LSizeSource, LSizeDest: NativeInt;
begin
  LSizeSource := Length(AValue);
  if LSizeSource = 0 then
    Exit;

  LSizeDest := Size;
  Size := LSizeDest + LSizeSource;
  Move(AValue[0], FPayload[LSizeDest], SizeOf(T) * LSizeSource);
end;

function TJOSEArray<T>.Pop: T;
begin
  if Size = 0 then
    raise Exception.Create('Error Message');

  Result := FPayload[Size - 1];
  SetLength(FPayload, Size - 1);
end;

function TJOSEArray<T>.Push(AItem: T): Integer;
begin
  Size := Size + 1;
  FPayload[Size - 1] := AItem;
  Result := Size;
end;

procedure TJOSEArray<T>.SetAsArray(const Value: TArray<T>);
begin
  FPayload := Value;
end;

procedure TJOSEArray<T>.SetFirst(const Value: T);
begin
  if Size = 0 then
    raise Exception.Create('Error Message');

  FPayload[0] := Value;
end;

procedure TJOSEArray<T>.SetLast(const Value: T);
begin
  if Size = 0 then
    raise Exception.Create('Error Message');

  FPayload[Size - 1] := Value;
end;

procedure TJOSEArray<T>.SetSize(const Value: NativeInt);
begin
  if Value < 0 then
    raise Exception.Create('Error Message');
  SetLength(FPayload, Value);
end;

function TJOSEArray<T>.Shift: T;
var
  LIndex: Integer;
begin
  if Size = 0 then
    raise Exception.Create('Error Message');

  Result := FPayload[0];
  if Size > 1 then
  for LIndex := 1 to Size - 1 do
    FPayload[LIndex - 1] := FPayload[LIndex];

  SetLength(FPayload, Size - 1);
end;

function TJOSEArray<T>.ToString: string;
var
  LValue: TValue;
  LItem: T;
begin
  Result := '';
  for LItem in FPayload do
  begin
    LValue := TValue.From<T>(LItem);
    Result := Result + LValue.ToString + ',';
  end;
  Result := Result.TrimRight([',']);
end;

function TJOSEArray<T>.ToStringPluralForm(const APluralPrefix: string): string;
begin
  if Self.Size > 1 then
    Result := APluralPrefix + Self.ToString
  else
    Result := Self.ToString;
end;

end.
