{******************************************************************************}
{                                                                              }
{  Delphi JOSE-JWT Library                                                     }
{  Copyright (c) 2015 Paolo Rossi                                              }
{  https://github.com/paolo-rossi/delphi-jose-jwt                              }
{                                                                              }
{  Licensed under the MIT license                                              }
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
    /// <summary>
    ///   Like IsValidJSON, but additionally requires the value to be a JSON
    ///   *object*: a bare string, array, number or literal is rejected
    /// </summary>
    class function IsValidJSONObject(const AValue: string): Boolean;
    class function IsJSONBool(AJSON: TJSONValue): Boolean;
    class function GetJSONBool(AJSON: TJSONValue): Boolean;

    class function ToJSON(AJSONValue: TJSONValue): string; static;
    class function CheckPair(const AName: string; AJSON: TJSONObject): Boolean;
    class function GetJSONValueInt(const AName: string; AJSON: TJSONObject): TValue;
    class function GetJSONValueInt64(const AName: string; AJSON: TJSONObject): TValue;
    class function GetJSONValueDouble(const AName: string; AJSON: TJSONObject): TValue;
    class function GetJSONValue(const AName: string; AJSON: TJSONObject): TValue;
    /// <summary>
    ///   Reads AName as text, whatever its JSON type, and returns '' when it is
    ///   absent. Never raises: unlike GetJSONValue(...).AsString, which raises
    ///   EInvalidCast as soon as the member is a number or a boolean
    /// </summary>
    class function GetJSONValueAsString(const AName: string; AJSON: TJSONObject): string;
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

resourcestring
  SJOSEJSONValueNotBoolean = 'The JSON value is not boolean';
  SJOSEJSONExpectedDouble = 'JSON Incompatible type. Expected Double';
  SJOSEJSONExpectedInteger = 'JSON Incompatible type. Expected Integer';
  SJOSEJSONExpectedInt64 = 'JSON Incompatible type. Expected Int64';

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
    raise EJSONConversionException.Create(SJOSEJSONValueNotBoolean);
{$ELSE}
  if AJSON is TJSONTrue then
    Result := True
  else if AJSON is TJSONFalse then
    Result := False
  else
    raise EJSONConversionException.Create(SJOSEJSONValueNotBoolean);
{$ENDIF}
end;

class function TJSONUtils.GetJSONValue(const AName: string; AJSON: TJSONObject): TValue;
var
  LJSONValue: TJSONValue;
  LInt64: Int64;
begin
  LJSONValue := AJSON.GetValue(AName);

  if not Assigned(LJSONValue) then
    Exit(TValue.Empty);

  if IsJSONBool(LJSONValue) then
    Exit(GetJSONBool(LJSONValue));

  if LJSONValue is TJSONNumber then
  begin
    // A whole number is returned as Int64: routing everything through AsDouble
    // silently loses precision above 2^53, which matters for id-like claims
    if TryStrToInt64(TJSONNumber(LJSONValue).Value, LInt64) then
      Exit(LInt64);
    Exit(TJSONNumber(LJSONValue).AsDouble);
  end;

  Result := LJSONValue.Value;
end;

class function TJSONUtils.GetJSONValueAsString(const AName: string; AJSON: TJSONObject): string;
var
  LJSONValue: TJSONValue;
begin
  // Total by design: string claims are read from tokens, so a member of an
  // unexpected type must read as text (and fail the comparison downstream)
  // rather than raise EInvalidCast out of the middle of the validation
  LJSONValue := AJSON.GetValue(AName);

  if not Assigned(LJSONValue) then
    Exit('');

  if (LJSONValue is TJSONObject) or (LJSONValue is TJSONArray) then
    Exit(LJSONValue.ToJSON);

  Result := LJSONValue.Value;
end;

class function TJSONUtils.GetJSONValueAsDate(const AName: string; AJSON: TJSONObject): TDateTime;
var
  LJSONValue: string;
begin
  // Total, like GetJSONValueAsEpoch: reading through GetJSONValue(...).AsString
  // raised EInvalidCast as soon as the member was a number or a boolean, and
  // ISO8601ToDate raised EConvertError on any text that is not a date. Both
  // shapes now read as 0, which is what an absent claim reads as
  LJSONValue := TJSONUtils.GetJSONValueAsString(AName, AJSON);

  if (LJSONValue = '') or not TryISO8601ToDate(LJSONValue, Result) then
    Result := 0;
end;

class function TJSONUtils.GetJSONValueAsEpoch(const AName: string; AJSON: TJSONObject): TDateTime;
const
  // Seconds from the Unix epoch to the ends of the TDateTime range (year 1..9999)
  MIN_EPOCH_SECONDS = Int64(-62135596800);
  MAX_EPOCH_SECONDS = Int64(253402300799);
var
  LJSONValue: TJSONValue;
  LSeconds: Int64;
begin
  // Date claims arrive from a token, so every shape has to produce a value
  // instead of an exception: a member of the wrong type ("exp":"soon"), a
  // number that is not a whole number ("exp":1e308, "exp":1.5) and a number
  // outside the TDateTime range all read as 0. That is what an absent claim
  // reads as, which keeps exp fail-closed (0 is long past, so expired)
  Result := 0;

  LJSONValue := AJSON.GetValue(AName);
  if not (LJSONValue is TJSONNumber) then
    Exit;

  if not TryStrToInt64(TJSONNumber(LJSONValue).Value, LSeconds) then
    Exit;

  if (LSeconds < MIN_EPOCH_SECONDS) or (LSeconds > MAX_EPOCH_SECONDS) then
    Exit;

  if LSeconds <> 0 then
    Result := UnixToDateTime(LSeconds, False);
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
    raise EJSONConversionException.Create(SJOSEJSONExpectedDouble);
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
    raise EJSONConversionException.Create(SJOSEJSONExpectedInteger);
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
    raise EJSONConversionException.Create(SJOSEJSONExpectedInt64);
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

class function TJSONUtils.IsValidJSONObject(const AValue: string): Boolean;
var
  LValue: TJSONValue;
begin
  try
    LValue := TJSONObject.ParseJSONValue(AValue);
    try
      Result := LValue is TJSONObject;
    finally
      LValue.Free;
    end;
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

{$IF CompilerVersion >= 28}  // Delphi XE7
class function TJSONUtils.ToJSON(AJSONValue: TJSONValue): string;
begin
  Result := AJSONValue.ToJSON;
end;
{$ELSE}
class function TJSONUtils.ToJSON(AJSONValue: TJSONValue): string;
var
  LBytes: TBytes;
begin
  SetLength(LBytes, AJSONValue.ToString.Length * 6);
  SetLength(LBytes, AJSONValue.ToBytes(LBytes, 0));
  // ToBytes emits UTF-8 here: decoding it with the ANSI codepage mangled every
  // non-ASCII claim. Same shape as the helper in JOSE.Core.Base
  Result := TEncoding.UTF8.GetString(LBytes);
end;
{$IFEND}

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
