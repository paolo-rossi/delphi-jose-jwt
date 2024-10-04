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
///   Base class for the JOSE entities
/// </summary>
unit JOSE.Core.Base;

{$I ..\JOSE.inc}

interface

{$SCOPEDENUMS ON}

uses
  System.SysUtils,
  System.JSON,
  System.Generics.Collections,
  JOSE.Types.Arrays,
  JOSE.Types.Bytes,
  JOSE.Types.JSON;

const
  PART_SEPARATOR: Char = '.';

type
  EJOSEException = class(Exception);

  TJOSEStringArray = TJOSEArray<string>;

  TJOSETimeUnit = (Days, Hours, Minutes, Seconds, Milliseconds);
  TJOSETimeUnitHelper = record helper for TJOSETimeUnit
  private
    function Convert(ADuration: Cardinal; ADestUnit: TJOSETimeUnit): Cardinal;
  public
    function ToDays(ADuration: Cardinal): Cardinal;
    function ToHours(ADuration: Cardinal): Cardinal;
    function ToMinutes(ADuration: Cardinal): Cardinal;
    function ToSeconds(ADuration: Cardinal): Cardinal;
    function ToMilliseconds(ADuration: Cardinal): Cardinal;
  end;

  TJOSENumericDate = record
  private
    const CONVERSION: Int64 = 1000;
  private
    FValue: TDateTime;
    function GetAsMilliSeconds: Int64;
    function GetAsSeconds: Int64;
    procedure SetAsSeconds(const AValue: Int64);
    function GetAsISO8601: string;
  public
    constructor Create(AValue: TDateTime);
    class function FromSeconds(ASecondsFromEpoch: Int64): TJOSENumericDate; static;
    class function FromMilliseconds(AMillisecondsFromEpoch: Int64): TJOSENumericDate; static;

    procedure AddSeconds(ASeconds: Int64);
    function IsBefore(const AWhen: TJOSENumericDate; ASkewSeconds: Integer): Boolean;
    function IsOnOrAfter(const AWhen: TJOSENumericDate; ASkewSeconds: Integer): Boolean;
    function IsAfter(const AWhen: TJOSENumericDate; ASkewSeconds: Integer): Boolean;

    property AsSeconds: Int64 read GetAsSeconds write SetAsSeconds;
    property AsMilliSeconds: Int64 read GetAsMilliSeconds;
    property AsDateTime: TDateTime read FValue write FValue;
    property AsISO8601: string read GetAsISO8601;
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

    procedure Clear;
    procedure Assign(AValue: TJOSEBase);
    procedure SetNewJSON(AJSON: TJSONObject); overload;
    procedure SetNewJSON(const AJSONStr: string); overload;
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
  JOSE.Encoding.Base64;

{$IF CompilerVersion >= 28}  // Delphi XE7
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
{$IFEND}

function JSONDate(ADate: TDateTime): Int64;
begin
  Result := DateTimeToUnix(ADate, False);
end;

{ TJOSEBase }

procedure TJOSEBase.Assign(AValue: TJOSEBase);
begin
  FJSON.Free;
  FJSON := AValue.Clone;
end;

procedure TJOSEBase.Clear;
begin
  FJSON.Free;
  FJSON := TJSONObject.Create;
end;

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

procedure TJOSEBase.SetNewJSON(const AJSONStr: string);
var
  LJSON: TJSONObject;
begin
  LJSON := FJSON.ParseJSONValue(AJSONStr) as TJSONObject;
  SetNewJSON(LJSON);
end;

procedure TJOSEBase.SetNewJSON(AJSON: TJSONObject);
begin
  FJSON.Free;
  FJSON := AJSON;
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

function TJOSENumericDate.GetAsISO8601: string;
begin
  Result := DateToISO8601(FValue);
end;

function TJOSENumericDate.GetAsMilliSeconds: Int64;
begin
  Result := DateTimeToUnix(FValue, False) * CONVERSION;
end;

function TJOSENumericDate.GetAsSeconds: Int64;
begin
  Result := DateTimeToUnix(FValue, False);
end;

function TJOSENumericDate.IsAfter(const AWhen: TJOSENumericDate; ASkewSeconds: Integer): Boolean;
begin
  Result := ((Self.AsSeconds - ASkewSeconds) > AWhen.AsSeconds);
end;

function TJOSENumericDate.IsBefore(const AWhen: TJOSENumericDate; ASkewSeconds: Integer): Boolean;
begin
  Result := ((Self.AsSeconds + ASkewSeconds) < AWhen.AsSeconds);
end;

function TJOSENumericDate.IsOnOrAfter(const AWhen: TJOSENumericDate; ASkewSeconds: Integer): Boolean;
begin
  Result := ((Self.AsSeconds - ASkewSeconds) >= AWhen.AsSeconds);
end;

procedure TJOSENumericDate.SetAsSeconds(const AValue: Int64);
begin
  FValue := UnixToDateTime(AValue);
end;

{ TJOSETimeUnitHelper }

function TJOSETimeUnitHelper.Convert(ADuration: Cardinal; ADestUnit: TJOSETimeUnit): Cardinal;
begin
  Result := 0;
  case Self of
    TJOSETimeUnit.Days:
    begin
      case ADestUnit of
        TJOSETimeUnit.Days:     Result := ADuration;
        TJOSETimeUnit.Hours:    Result := ADuration * 24;
        TJOSETimeUnit.Minutes:  Result := ADuration * 24 * 60;
        TJOSETimeUnit.Seconds:  Result := ADuration * 24 * 60 * 60;
        TJOSETimeUnit.Milliseconds: Result := ADuration * 24 * 60 * 60 * 1000;
      end;
    end;
    TJOSETimeUnit.Hours:
    begin
      case ADestUnit of
        TJOSETimeUnit.Days:     Result := ADuration div 24;
        TJOSETimeUnit.Hours:    Result := ADuration;
        TJOSETimeUnit.Minutes:  Result := ADuration * 60;
        TJOSETimeUnit.Seconds:  Result := ADuration * 60 * 60;
        TJOSETimeUnit.Milliseconds: Result := ADuration * 60 * 60 * 1000;
      end;
    end;
    TJOSETimeUnit.Minutes:
    begin
      case ADestUnit of
        TJOSETimeUnit.Days:     Result := (ADuration div 24) div 60;
        TJOSETimeUnit.Hours:    Result := ADuration div 60;
        TJOSETimeUnit.Minutes:  Result := ADuration;
        TJOSETimeUnit.Seconds:  Result := ADuration * 60;
        TJOSETimeUnit.Milliseconds: Result := ADuration * 60 * 1000;
      end;
    end;
    TJOSETimeUnit.Seconds:
    begin
      case ADestUnit of
        TJOSETimeUnit.Days:     Result := ((ADuration div 24) div 60) div 60;
        TJOSETimeUnit.Hours:    Result := (ADuration div 24) div 60;
        TJOSETimeUnit.Minutes:  Result := ADuration div 24;
        TJOSETimeUnit.Seconds:  Result := ADuration;
        TJOSETimeUnit.Milliseconds: Result := ADuration * 1000;
      end;
    end;
    TJOSETimeUnit.Milliseconds:
    begin
      case ADestUnit of
        TJOSETimeUnit.Days:     Result := (((ADuration div 24) div 60) div 60) div 1000;
        TJOSETimeUnit.Hours:    Result := ((ADuration div 24) div 60) div 60;
        TJOSETimeUnit.Minutes:  Result := (ADuration div 24) div 60;
        TJOSETimeUnit.Seconds:  Result := ADuration div 24;
        TJOSETimeUnit.Milliseconds: Result := ADuration;
      end;
    end;
  end;
end;

function TJOSETimeUnitHelper.ToDays(ADuration: Cardinal): Cardinal;
begin
  Result := Convert(ADuration, TJOSETimeUnit.Days);
end;

function TJOSETimeUnitHelper.ToHours(ADuration: Cardinal): Cardinal;
begin
  Result := Convert(ADuration, TJOSETimeUnit.Hours);
end;

function TJOSETimeUnitHelper.ToMilliseconds(ADuration: Cardinal): Cardinal;
begin
  Result := Convert(ADuration, TJOSETimeUnit.Milliseconds);
end;

function TJOSETimeUnitHelper.ToMinutes(ADuration: Cardinal): Cardinal;
begin
  Result := Convert(ADuration, TJOSETimeUnit.Minutes);
end;

function TJOSETimeUnitHelper.ToSeconds(ADuration: Cardinal): Cardinal;
begin
  Result := Convert(ADuration, TJOSETimeUnit.Seconds);
end;

end.
