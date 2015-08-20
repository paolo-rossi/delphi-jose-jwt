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
  private

    class procedure SetJSONValue(const AName: string; const AValue: TValue; AJSON: TJSONObject); overload;
    class procedure SetJSONValue(const AName: string; const AValue: string; AJSON: TJSONObject); overload;
    class procedure SetJSONValue(const AName: string; const AValue: Integer; AJSON: TJSONObject); overload;
    class procedure SetJSONValue(const AName: string; const AValue: Int64; AJSON: TJSONObject); overload;
    class procedure SetJSONValue(const AName: string; const AValue: Double; AJSON: TJSONObject); overload;
    class procedure SetJSONValue(const AName: string; const AValue: Boolean; AJSON: TJSONObject); overload;
  public
    class function GetJSONValueInt(const AName: string; AJSON: TJSONObject): TValue;
    class function GetJSONValueInt64(const AName: string; AJSON: TJSONObject): TValue;
    class function GetJSONValueDouble(const AName: string; AJSON: TJSONObject): TValue;
    class function GetJSONValue(const AName: string; AJSON: TJSONObject): TValue;
    class function GetJSONValueAsDate(const AName: string; AJSON: TJSONObject): TDateTime;
    class function GetJSONValueAsEpoch(const AName: string; AJSON: TJSONObject): TDateTime;

    class procedure SetJSONValueFrom<T>(const AName: string; const AValue: T; AJSON: TJSONObject);
    class procedure RemoveJSONNode(const AName: string; AJSON: TJSONObject);
  end;

implementation

uses
  System.TypInfo;

{ TJSONUtils }

class function TJSONUtils.GetJSONValue(const AName: string; AJSON: TJSONObject): TValue;
var
  LValue: TJSONValue;
begin
  LValue := AJSON.GetValue(AName);

  if not Assigned(LValue) then
    Result := TValue.Empty
  else if LValue is TJSONTrue then
    Result := True
  else if LValue is TJSONFalse then
    Result := False
  else if LValue is TJSONNumber then
    Result := TJSONNumber(LValue).AsDouble
  else
    Result := LValue.Value;
end;

class function TJSONUtils.GetJSONValueAsDate(const AName: string; AJSON: TJSONObject): TDateTime;
var
  LValue: string;
begin
  LValue := TJSONUtils.GetJSONValue(AName, AJSON).AsString;
  if LValue = '' then
    Result := 0
  else
    Result := ISO8601ToDate(LValue)
end;

class function TJSONUtils.GetJSONValueAsEpoch(const AName: string; AJSON: TJSONObject): TDateTime;
var
  LValue: Int64;
begin
  LValue := TJSONUtils.GetJSONValueInt64(AName, AJSON).AsInt64;
  if LValue = 0 then
    Result := 0
  else
    Result := UnixToDateTime(LValue)
end;

class function TJSONUtils.GetJSONValueDouble(const AName: string; AJSON: TJSONObject): TValue;
var
  LValue: TJSONValue;
begin
  LValue := AJSON.GetValue(AName);

  if not Assigned(LValue) then
    Result := TValue.Empty
  else if LValue is TJSONNumber then
    Result := TJSONNumber(LValue).AsDouble
  else
    raise EJSONConversionException.Create('JSON Incompatible type. Expected Double');
end;

class function TJSONUtils.GetJSONValueInt(const AName: string; AJSON: TJSONObject): TValue;
var
  LValue: TJSONValue;
begin
  LValue := AJSON.GetValue(AName);

  if not Assigned(LValue) then
    Result := TValue.Empty
  else if LValue is TJSONNumber then
    Result := TJSONNumber(LValue).AsInt
  else
    raise EJSONConversionException.Create('JSON Incompatible type. Expected Integer');
end;

class function TJSONUtils.GetJSONValueInt64(const AName: string; AJSON: TJSONObject): TValue;
var
  LValue: TJSONValue;
begin
  LValue := AJSON.GetValue(AName);

  if not Assigned(LValue) then
    Result := TValue.Empty
  else if LValue is TJSONNumber then
    Result := TJSONNumber(LValue).AsInt64
  else
    raise EJSONConversionException.Create('JSON Incompatible type. Expected Int64');
end;

class procedure TJSONUtils.RemoveJSONNode(const AName: string; AJSON: TJSONObject);
var
  LValue: TJSONValue;
begin
  LValue := AJSON.GetValue(AName);
  if Assigned(LValue) then
    AJSON.RemovePair(AName);
end;

class procedure TJSONUtils.SetJSONValue(const AName: string; const AValue: Int64; AJSON: TJSONObject);
var
  LValue: TJSONValue;
begin
  LValue := AJSON.GetValue(AName);
  if Assigned(LValue) then
    AJSON.RemovePair(AName);

  AJSON.AddPair(TJSONPair.Create(AName, TJSONNumber.Create(AValue)));
end;

class procedure TJSONUtils.SetJSONValueFrom<T>(const AName: string; const AValue: T; AJSON: TJSONObject);
begin
  SetJSONValue(AName, TValue.From<T>(AValue), AJSON);
end;

class procedure TJSONUtils.SetJSONValue(const AName: string; const AValue: Double; AJSON: TJSONObject);
var
  LValue: TJSONValue;
begin
  LValue := AJSON.GetValue(AName);
  if Assigned(LValue) then
    AJSON.RemovePair(AName);

  AJSON.AddPair(TJSONPair.Create(AName, TJSONNumber.Create(AValue)));
end;

class procedure TJSONUtils.SetJSONValue(const AName: string; const AValue: string; AJSON: TJSONObject);
var
  LValue: TJSONValue;
begin
  LValue := AJSON.GetValue(AName);
  if Assigned(LValue) then
    AJSON.RemovePair(AName);

  AJSON.AddPair(TJSONPair.Create(AName, AValue));
end;

class procedure TJSONUtils.SetJSONValue(const AName: string; const AValue: Integer; AJSON: TJSONObject);
var
  LValue: TJSONValue;
begin
  LValue := AJSON.GetValue(AName);
  if Assigned(LValue) then
    AJSON.RemovePair(AName);

  AJSON.AddPair(TJSONPair.Create(AName, TJSONNumber.Create(AValue)));
end;

class procedure TJSONUtils.SetJSONValue(const AName: string; const AValue: Boolean; AJSON: TJSONObject);
var
  LValue: TJSONValue;
begin
  LValue := AJSON.GetValue(AName);
  if Assigned(LValue) then
    AJSON.RemovePair(AName);

  if AValue then
    AJSON.AddPair(TJSONPair.Create(AName, TJSONTrue.Create))
  else
    AJSON.AddPair(TJSONPair.Create(AName, TJSONFalse.Create));
end;

class procedure TJSONUtils.SetJSONValue(const AName: string; const AValue: TValue; AJSON: TJSONObject);
begin
  case AValue.Kind of
    tkChar,
    tkString,
    tkWChar,
    tkLString,
    tkWString,
    tkUString:
    begin
      SetJSONValue(AName, AValue.AsType<string>, AJSON);
    end;

    tkEnumeration:
    begin
      if AValue.TypeInfo^.NameFld.ToString = 'Boolean' then
        SetJSONValue(AName, AValue.AsType<Boolean>, AJSON);
    end;

    tkInteger,
    tkInt64,
    tkFloat:
    begin
      if SameText(AValue.TypeInfo^.NameFld.ToString, 'TDateTime') or
         SameText(AValue.TypeInfo^.NameFld.ToString, 'TDate') or
         SameText(AValue.TypeInfo^.NameFld.ToString, 'TTime') then
        SetJSONValue(AName, DateTimeToUnix(AValue.AsType<TDateTime>), AJSON)
      else
        if AValue.Kind = tkFloat then
          SetJSONValue(AName, AValue.AsType<Double>, AJSON)
        else
          SetJSONValue(AName, AValue.AsType<Integer>, AJSON);
    end;
  end;
end;

end.

