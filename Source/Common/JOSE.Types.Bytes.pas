{******************************************************}
{  Copyright (C) 2015                                  }
{  Delphi JOSE Library                                 }
{                                                      }
{  https://github.com/paolo-rossi/delphi-jose-jwt      }
{                                                      }
{  Authors:                                            }
{  Paolo Rossi <paolo(at)paolorossi(dot)net>           }
{                                                      }
{******************************************************}
unit JOSE.Types.Bytes;

interface

uses
  System.SysUtils,
  System.Classes;

type
  TSuperBytes = record
  private
    FPayload: TBytes;

    procedure SetAsString(const Value: string);
    function GetAsString: string; inline;
  public
    class operator Implicit(const AValue: TSuperBytes): string;
    class operator Implicit(const AValue: TSuperBytes): TBytes;
    class operator Implicit(const AValue: string): TSuperBytes;
    class operator Implicit(const AValue: TBytes): TSuperBytes;

    class operator Equal(const A: TSuperBytes; const B: TSuperBytes): Boolean;
    class operator Equal(const A: TSuperBytes; const B: string): Boolean;
    class operator Equal(const A: TSuperBytes; const B: TBytes): Boolean;

    class operator Add(const A: TSuperBytes; const B: TSuperBytes): TSuperBytes;
    class operator Add(const A: TSuperBytes; const B: Byte): TSuperBytes;
    class operator Add(const A: TSuperBytes; const B: string): TSuperBytes;
    class operator Add(const A: TSuperBytes; const B: TBytes): TSuperBytes;

    class function Empty: TSuperBytes; static;

    function Size: Integer;
    procedure Clear;

    function Contains(const AByte: Byte): Boolean; overload;
    function Contains(const ABytes: TBytes): Boolean; overload;
    function Contains(const ABytes: TSuperBytes): Boolean; overload;

    property AsBytes: TBytes read FPayload write FPayload;
    property AsString: string read GetAsString write SetAsString;
  end;

  TBytesUtils = class
    class function MergeBytes(const ABytes1: TBytes; const ABytes2: TBytes): TBytes; overload; static;
    class function MergeBytes(const ABytes1: TBytes; const ABytes2: Byte): TBytes; overload; static;
  end;

implementation


function CompareBytes(const A, B: TBytes): Boolean;
var
  LLen: Integer;
begin
  LLen := Length(A);
  Result := LLen = Length(B);
  if Result and (LLen > 0) then
    Result := CompareMem(Pointer(A), Pointer(A), LLen);
end;


{ TSuperBytes }

class operator TSuperBytes.Add(const A: TSuperBytes; const B: Byte): TSuperBytes;
begin
  SetLength(Result.FPayload, A.Size + 1);
  Move(A.FPayload[0], Result.FPayload[0], A.Size);
  Result.FPayload[Result.Size-1] := B;
end;

class operator TSuperBytes.Add(const A, B: TSuperBytes): TSuperBytes;
begin
  SetLength(Result.FPayload, A.Size + B.Size);
  Move(A.FPayload[0], Result.FPayload[0], A.Size);
  Move(B.FPayload[0], Result.FPayload[A.Size], B.Size);
end;

class operator TSuperBytes.Add(const A: TSuperBytes; const B: TBytes): TSuperBytes;
begin
  SetLength(Result.FPayload, A.Size + Length(B));
  Move(A.FPayload[0], Result.FPayload[0], A.Size);
  Move(B[0], Result.FPayload[A.Size], Length(B));
end;

class operator TSuperBytes.Add(const A: TSuperBytes; const B: string): TSuperBytes;
var
  LB: TBytes;
begin
  LB := TEncoding.UTF8.GetBytes(B);

  SetLength(Result.FPayload, A.Size + Length(LB));
  Move(A.FPayload[0], Result.FPayload[0], A.Size);
  Move(LB[0], Result.FPayload[A.Size], Length(LB));
end;

procedure TSuperBytes.Clear;
begin
  SetLength(FPayload, 0);
end;

function TSuperBytes.Contains(const AByte: Byte): Boolean;
begin
  Result := False;
end;

function TSuperBytes.Contains(const ABytes: TBytes): Boolean;
begin
  Result := False;
end;

function TSuperBytes.Contains(const ABytes: TSuperBytes): Boolean;
begin
  Result := False;
end;

class function TSuperBytes.Empty: TSuperBytes;
begin
  SetLength(Result.FPayload, 0);
end;

class operator TSuperBytes.Equal(const A: TSuperBytes; const B: string): Boolean;
begin
  Result := CompareBytes(A.FPayload, TEncoding.UTF8.GetBytes(B));
end;

class operator TSuperBytes.Equal(const A: TSuperBytes; const B: TBytes): Boolean;
begin
  Result := CompareBytes(A.FPayload, B);
end;

class operator TSuperBytes.Equal(const A: TSuperBytes; const B: TSuperBytes): Boolean;
begin
  Result := CompareBytes(A.FPayload, B.FPayload);
end;

function TSuperBytes.GetAsString: string;
begin
  Result := TEncoding.UTF8.GetString(FPayload);
end;

class operator TSuperBytes.Implicit(const AValue: TSuperBytes): TBytes;
begin
  Result := AValue.AsBytes;
end;

class operator TSuperBytes.Implicit(const AValue: TSuperBytes): string;
begin
  Result := TEncoding.UTF8.GetString(AValue.FPayload);
end;

class operator TSuperBytes.Implicit(const AValue: TBytes): TSuperBytes;
begin
  Result.FPayload := AValue;
end;

function TSuperBytes.Size: Integer;
begin
  Result := Length(FPayload);
end;

class operator TSuperBytes.Implicit(const AValue: string): TSuperBytes;
begin
  Result.FPayload := TEncoding.UTF8.GetBytes(AValue);
end;

procedure TSuperBytes.SetAsString(const Value: string);
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

end.
