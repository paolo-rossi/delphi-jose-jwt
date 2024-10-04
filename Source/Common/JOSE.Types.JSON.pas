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
///   Utility unit to deal with the JSON Delphi classes
/// </summary>
unit JOSE.Types.JSON;

{$I ..\JOSE.inc}

interface

uses
  System.SysUtils,
  System.StrUtils,
  System.DateUtils,
  System.Rtti,
  System.JSON;

type
  EJSONConversionException = class(Exception);

  TJSONAncestor = System.JSON.TJSONAncestor;
  TJSONPair = System.JSON.TJSONPair;
  TJSONValue = System.JSON.TJSONValue;
  TJSONTrue = System.JSON.TJSONTrue;
  TJSONString = System.JSON.TJSONString;
  TJSONNumber = System.JSON.TJSONNumber;
  TJSONObject = System.JSON.TJSONObject;
  TJSONNull = System.JSON.TJSONNull;
  TJSONFalse = System.JSON.TJSONFalse;
  TJSONArray = System.JSON.TJSONArray;

  TJSONUtils = class
  strict private
    class function GetJSONRttiValue(AValue: TValue): TJSONValue;
  public
    class function IsValidJSON(const AValue: string): Boolean;
    class function IsJSONBool(AJSON: TJSONValue): Boolean;
    class function GetJSONBool(AJSON: TJSONValue): Boolean;

    class function ToJSON(AJSONValue: TJSONValue): string; static;
    class function CheckPair(const AName: string; AJSON: TJSONObject): Boolean;
    class function GetJSONValueInt(const AName: string; AJSON: TJSONObject): TValue;
    class function GetJSONValueInt64(const AName: string; AJSON: TJSONObject): TValue;
    class function GetJSONValueDouble(const AName: string; AJSON: TJSONObject): TValue;
    class function GetJSONValue(const AName: string; AJSON: TJSONObject): TValue;
    class function GetJSONValueAsDate(const AName: string; AJSON: TJSONObject): TDateTime;
    class function GetJSONValueAsEpoch(const AName: string; AJSON: TJSONObject): TDateTime;

    class procedure SetJSONValue(const AName: string; AValue: TJSONValue; AJSON: TJSONObject); overload;
    class procedure SetJSONRttiValue(const AName: string; const AValue: TValue; AJSON: TJSONObject); overload;
    class procedure SetJSONValueFrom<T>(const AName: string; const AValue: T; AJSON: TJSONObject);

    class procedure RemoveJSONNode(const AName: string; AJSON: TJSONObject);
  end;

implementation

uses
  System.TypInfo;

{ TJSONUtils }

class function TJSONUtils.GetJSONRttiValue(AValue: TValue): TJSONValue;
var
  LVal: TValue;
  LArray: TArray<TValue>;
begin
  Result := nil;

  case AValue.Kind of
    tkChar,
    tkString,
    tkWChar,
    tkLString,
    tkWString,
    tkUString:
    begin
      Result := TJSONString.Create(AValue.AsType<string>);
    end;

    tkEnumeration:
    begin
      if AValue.TypeInfo^.NameFld.ToString = 'Boolean' then
      begin
        if AValue.AsType<Boolean> then
          Result := TJSONTrue.Create
        else
          Result := TJSONFalse.Create;
      end;
    end;

    tkInteger,
    tkInt64,
    tkFloat:
    begin
      if SameText(AValue.TypeInfo^.NameFld.ToString, 'TDateTime') or
         SameText(AValue.TypeInfo^.NameFld.ToString, 'TDate') or
         SameText(AValue.TypeInfo^.NameFld.ToString, 'TTime') then
        Result := TJSONNumber.Create(DateTimeToUnix(AValue.AsType<TDateTime>, False))
      else
        if AValue.Kind = tkFloat then
          Result := TJSONNumber.Create(AValue.AsType<Double>)
      else
      if AValue.Kind = tkInt64 then
          Result := TJSONNumber.Create(AValue.AsType<Int64>)
      else
        Result := TJSONNumber.Create(AValue.AsType<Integer>)
    end;

    tkDynArray:
    begin
      LArray := AValue.AsType<TArray<TValue>>;
      Result := TJSONArray.Create();
      for LVal in LArray do
        TJSONArray(Result).AddElement(GetJSONRttiValue(LVal));
    end;
  end;
end;

class function TJSONUtils.CheckPair(const AName: string; AJSON: TJSONObject): Boolean;
begin
  Result := Assigned(AJSON.GetValue(AName));
end;

class function TJSONUtils.GetJSONBool(AJSON: TJSONValue): Boolean;
begin
{$IFDEF HAS_JSON_BOOL}
  if AJSON is TJSONBool then
    Result := (AJSON as TJSONBool).AsBoolean
  else
    raise EJSONConversionException.Create('The JSON value is not boolean');
{$ELSE}
  if AJSON is TJSONTrue then
    Result := True
  else if AJSON is TJSONFalse then
    Result := False
  else
    raise EJSONConversionException.Create('The JSON value is not boolean');
{$ENDIF}
end;

class function TJSONUtils.GetJSONValue(const AName: string; AJSON: TJSONObject): TValue;
var
  LJSONValue: TJSONValue;
begin
  LJSONValue := AJSON.GetValue(AName);

  if not Assigned(LJSONValue) then
    Exit(TValue.Empty);

  if IsJSONBool(LJSONValue) then
    Exit(GetJSONBool(LJSONValue));

  if LJSONValue is TJSONNumber then
    Exit(TJSONNumber(LJSONValue).AsDouble);

  Result := LJSONValue.Value;
end;

class function TJSONUtils.GetJSONValueAsDate(const AName: string; AJSON: TJSONObject): TDateTime;
var
  LJSONValue: string;
begin
  LJSONValue := TJSONUtils.GetJSONValue(AName, AJSON).AsString;
  if LJSONValue = '' then
    Result := 0
  else
    Result := ISO8601ToDate(LJSONValue)
end;

class function TJSONUtils.GetJSONValueAsEpoch(const AName: string; AJSON: TJSONObject): TDateTime;
var
  LJSONValue: Int64;
begin
  LJSONValue := TJSONUtils.GetJSONValueInt64(AName, AJSON).AsInt64;
  if LJSONValue = 0 then
    Result := 0
  else
    Result := UnixToDateTime(LJSONValue, False)
end;

class function TJSONUtils.GetJSONValueDouble(const AName: string; AJSON: TJSONObject): TValue;
var
  LJSONValue: TJSONValue;
begin
  LJSONValue := AJSON.GetValue(AName);

  if not Assigned(LJSONValue) then
    Result := TValue.Empty
  else if LJSONValue is TJSONNumber then
    Result := TJSONNumber(LJSONValue).AsDouble
  else
    raise EJSONConversionException.Create('JSON Incompatible type. Expected Double');
end;

class function TJSONUtils.GetJSONValueInt(const AName: string; AJSON: TJSONObject): TValue;
var
  LJSONValue: TJSONValue;
begin
  LJSONValue := AJSON.GetValue(AName);

  if not Assigned(LJSONValue) then
    Result := TValue.Empty
  else if LJSONValue is TJSONNumber then
    Result := TJSONNumber(LJSONValue).AsInt
  else
    raise EJSONConversionException.Create('JSON Incompatible type. Expected Integer');
end;

class function TJSONUtils.GetJSONValueInt64(const AName: string; AJSON: TJSONObject): TValue;
var
  LJSONValue: TJSONValue;
begin
  LJSONValue := AJSON.GetValue(AName);

  if not Assigned(LJSONValue) then
    Result := TValue.Empty
  else if LJSONValue is TJSONNumber then
    Result := TJSONNumber(LJSONValue).AsInt64
  else
    raise EJSONConversionException.Create('JSON Incompatible type. Expected Int64');
end;

class function TJSONUtils.IsJSONBool(AJSON: TJSONValue): Boolean;
begin
{$IFDEF HAS_JSON_BOOL}
  if AJSON is TJSONBool then
    Exit(True);
{$ELSE}
  if (AJSON is TJSONTrue) or (AJSON is TJSONFalse) then
    Exit(True);
{$ENDIF}
  Result := False;
end;

class function TJSONUtils.IsValidJSON(const AValue: string): Boolean;
var
  LValue: TJSONValue;
begin
  try
    LValue := TJSONObject.ParseJSONValue(AValue);
    Result := Assigned(LValue);
    LValue.Free;
  except
    Result := False;
  end;
end;

class procedure TJSONUtils.RemoveJSONNode(const AName: string; AJSON: TJSONObject);
var
  LPair: TJSONPair;
begin
  LPair := AJSON.RemovePair(AName);
  if Assigned(LPair) then
    LPair.Free;
end;

class procedure TJSONUtils.SetJSONValue(const AName: string; AValue: TJSONValue; AJSON: TJSONObject);
var
  LPair: TJSONPair;
begin
  LPair := AJSON.Get(AName);
  if Assigned(LPair) then
  begin
    // Replace the JSON Value (the previous is freed by the TJSONPair object)
    LPair.JsonValue := AValue;
  end
  else
  begin
    LPair := TJSONPair.Create(AName, AValue);
    AJSON.AddPair(LPair);
  end;
end;

class procedure TJSONUtils.SetJSONValueFrom<T>(const AName: string; const AValue: T; AJSON: TJSONObject);
begin
  SetJSONRttiValue(AName, TValue.From<T>(AValue), AJSON);
end;

class function TJSONUtils.ToJSON(AJSONValue: TJSONValue): string;
var
  LBytes: TBytes;
begin
  SetLength(LBytes, AJSONValue.ToString.Length * 6);
  SetLength(LBytes, AJSONValue.ToBytes(LBytes, 0));
  Result := TEncoding.Default.GetString(LBytes);
end;

class procedure TJSONUtils.SetJSONRttiValue(const AName: string; const AValue: TValue; AJSON: TJSONObject);
var
  LValue: TJSONValue;
begin
  LValue := GetJSONRttiValue(AValue);
  if not Assigned(LValue) then
    Exit;

  SetJSONValue(AName, LValue, AJSON);
end;

end.
