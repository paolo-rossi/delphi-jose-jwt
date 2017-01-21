{******************************************************************************}
{                                                                              }
{  Delphi JOSE Library                                                         }
{  Copyright (c) 2015-2017 Paolo Rossi                                              }
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
///   Base class for the JOSE entities
/// </summary>
unit JOSE.Core.Base;

interface

uses
  System.SysUtils,
  System.Generics.Collections,
  JOSE.Types.Bytes,
  JOSE.Types.JSON;

const
  PART_SEPARATOR: Char = '.';

type
  EJOSEException = class(Exception);

  TJOSEStringArray = TArray<string>;
  {$IF CompilerVersion > 28}
  TJOSEStringArrayHelper = record helper for TJOSEStringArray
    function IsEmpty: Boolean;
    function Size: Integer;
    function Contains(const AValue: string): Boolean;
    function ToString: string;
    function ToStringPluralForm(const APluralPrefix: string): string;
  end;
  {$ENDIF}


  TJOSENumericDate = record
  private
    const CONVERSION: Int64 = 1000;
  private
    FValue: TDateTime;
    function GetAsMilliSeconds: Int64;
    function GetAsSeconds: Int64;
    procedure SetAsSeconds(const AValue: Int64);
  public
    constructor Create(AValue: TDateTime);
    class function FromSeconds(ASecondsFromEpoch: Int64): TJOSENumericDate; static;
    class function FromMilliseconds(AMillisecondsFromEpoch: Int64): TJOSENumericDate; static;

    procedure AddSeconds(ASeconds: Int64);
    function IsBefore(const AWhen: TJOSENumericDate): Boolean;
    function IsOnOrAfter(const AWhen: TJOSENumericDate): Boolean;
    function IsAfter(const AWhen: TJOSENumericDate): Boolean;

    property AsSeconds: Int64 read GetAsSeconds write SetAsSeconds;
    property AsMilliSeconds: Int64 read GetAsMilliSeconds;
  end;

  THeaderNames = class
  public const
    HEADER_TYPE = 'typ';
    ALGORITHM = 'alg';
  end;

  TJOSEBase = class
  private
    function GetEncoded: TJOSEBytes;
    function GetURLEncoded: TJOSEBytes;
    procedure SetEncoded(const Value: TJOSEBytes);
    procedure SetURLEncoded(const Value: TJOSEBytes);
  protected
    FJSON: TJSONObject;

    procedure AddPairOfType<T>(const AName: string; const AValue: T);
  public
    constructor Create;
    destructor Destroy; override;

    function Clone: TJSONObject;

    property JSON: TJSONObject read FJSON write FJSON;
    property Encoded: TJOSEBytes read GetEncoded write SetEncoded;
    property URLEncoded: TJOSEBytes read GetURLEncoded write SetURLEncoded;
  end;

function ToJSON(Value: TJSONAncestor): string;
function JSONDate(ADate: TDateTime): Int64;

implementation

uses
  System.DateUtils,
  System.JSON,
  JOSE.Encoding.Base64;

{$IF CompilerVersion >= 28}
function ToJSON(Value: TJSONAncestor): string;
begin
  Result := Value.ToJson;
end;
{$ELSE}
function ToJSON(Value: TJSONAncestor): string;
var
  LBytes: TBytes;
  LLen: Integer;
begin
  SetLength(LBytes, Value.EstimatedByteSize);
  LLen := Value.ToBytes(LBytes, 0);
  Result := TEncoding.UTF8.GetString(LBytes, 0, LLen);
end;
{$ENDIF}

function JSONDate(ADate: TDateTime): Int64;
begin
  Result := DateTimeToUnix(ADate, False);
end;

{ TJOSEBase }

function TJOSEBase.Clone: TJSONObject;
begin
  Result := FJSON.Clone as TJSONObject;
end;

constructor TJOSEBase.Create;
begin
  FJSON := TJSONObject.Create;
end;

destructor TJOSEBase.Destroy;
begin
  FJSON.Free;
  inherited;
end;

function TJOSEBase.GetEncoded: TJOSEBytes;
begin
  Result := TBase64.Encode(ToJSON(FJSON));
end;

function TJOSEBase.GetURLEncoded: TJOSEBytes;
begin
  Result := TBase64.URLEncode(ToJSON(FJSON));
end;

procedure TJOSEBase.SetEncoded(const Value: TJOSEBytes);
var
  LJSONStr: TJOSEBytes;
begin
  LJSONStr := TBase64.Decode(Value);
  FJSON.Parse(LJSONStr, 0)
end;

procedure TJOSEBase.SetURLEncoded(const Value: TJOSEBytes);
var
  LJSONStr: TJOSEBytes;
  LValue: TJSONValue;
begin
  LJSONStr := TBase64.URLDecode(Value);
  LValue := TJSONObject.ParseJSONValue(LJSONStr.AsBytes, 0, True);

  if Assigned(LValue) then
  begin
    FJSON.Free;
    FJSON := LValue as TJSONObject;
  end;
end;

procedure TJOSEBase.AddPairOfType<T>(const AName: string; const AValue: T);
begin
  TJSONUtils.SetJSONValueFrom<T>(AName, AValue, FJSON);
end;

{ TJOSENumericDate }

procedure TJOSENumericDate.AddSeconds(ASeconds: Int64);
begin
  FValue := System.DateUtils.IncSecond(FValue, ASeconds);
end;

constructor TJOSENumericDate.Create(AValue: TDateTime);
begin
  FValue := AValue;
end;

class function TJOSENumericDate.FromMilliseconds(AMillisecondsFromEpoch: Int64): TJOSENumericDate;
begin
  Result := TJOSENumericDate.Create(UnixToDateTime(AMillisecondsFromEpoch div CONVERSION, False));
end;

class function TJOSENumericDate.FromSeconds(ASecondsFromEpoch: Int64): TJOSENumericDate;
begin
  Result := TJOSENumericDate.Create(UnixToDateTime(ASecondsFromEpoch, False));
end;

function TJOSENumericDate.GetAsMilliSeconds: Int64;
begin
  Result := DateTimeToUnix(FValue, False) * CONVERSION;
end;

function TJOSENumericDate.GetAsSeconds: Int64;
begin
  Result := DateTimeToUnix(FValue, False);
end;

function TJOSENumericDate.IsAfter(const AWhen: TJOSENumericDate): Boolean;
begin
  Result := (Self.AsSeconds > AWhen.AsSeconds);
end;

function TJOSENumericDate.IsBefore(const AWhen: TJOSENumericDate): Boolean;
begin
  Result := (Self.AsSeconds < AWhen.AsSeconds);
end;

function TJOSENumericDate.IsOnOrAfter(const AWhen: TJOSENumericDate): Boolean;
begin
  Result := (Self.AsSeconds >= AWhen.AsSeconds);
end;

procedure TJOSENumericDate.SetAsSeconds(const AValue: Int64);
begin
  FValue := UnixToDateTime(AValue);
end;

{$IF CompilerVersion > 28}

{ TJOSEStringArrayHelper }

function TJOSEStringArrayHelper.Contains(const AValue: string): Boolean;
var
  LIndexValue: string;
begin
  Exit(False);
  for LIndexValue in Self do
    if LIndexValue = AValue then
      Exit(True);
end;

function TJOSEStringArrayHelper.IsEmpty: Boolean;
begin
  Result := Length(Self) = 0;
end;

function TJOSEStringArrayHelper.Size: Integer;
begin
  Result := Length(Self);
end;

function TJOSEStringArrayHelper.ToString: string;
begin
  Result := string.Join(',', Self);
end;

function TJOSEStringArrayHelper.ToStringPluralForm(const APluralPrefix: string): string;
begin
  if Self.Size > 1 then
    Result := APluralPrefix + Self.ToString
  else
    Result := Self.ToString;
end;

{$ENDIF}

end.
