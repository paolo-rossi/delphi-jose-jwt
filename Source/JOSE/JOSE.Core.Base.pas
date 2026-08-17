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

resourcestring
  // Shared by every path that parses a compact serialization, so that the same
  // token is refused with the same words wherever it enters the library
  SJOSEJWENotSupported = 'Compact Serialization appears to be a JWE Token which is not (yet) supported';
  SJOSEMalformedCompactSerialization = 'Malformed Compact Serialization';
  SJOSECompactPartNotBase64URL = 'Part %d of the Compact Serialization is not valid base64url';

type
  EJOSEException = class(Exception);

  TJOSEStringArray = TJOSEArray<string>;

  /// <summary>What a compact serialization's part count says it is</summary>
  TJOSECompactKind = (Unknown, JWS, JWE);

  /// <summary>
  ///   A compact serialization split into its parts, with the rules that decide
  ///   whether it is usable
  /// </summary>
  /// <remarks>
  ///   The same "3 parts means JWS, 5 means JWE, anything else is malformed"
  ///   decision used to be written out in TJOSEContext, TJOSE.DeserializeVerify
  ///   and TJWS.CheckCompactToken, each slightly differently - which is how a
  ///   token rejected by one path came to be accepted by another. It lives here
  ///   so the three cannot drift again
  /// </remarks>
  TJOSECompactSerialization = record
  public const
    JWS_PARTS = 3;
    JWE_PARTS = 5;
  private
    FParts: TArray<string>;
    function GetCount: Integer;
    function GetKind: TJOSECompactKind;
    function GetPart(AIndex: Integer): string;
  public
    class function Split(const ACompactToken: TJOSEBytes): TJOSECompactSerialization; static;

    /// <summary>True when every part is strict base64url (RFC 7515 par. 2)</summary>
    function PartsAreBase64URL: Boolean;
    /// <summary>
    ///   Raises EJOSEException unless the part count says JWS, with the message
    ///   that tells a JWE apart from a malformed token
    /// </summary>
    procedure CheckIsJWS;

    property Count: Integer read GetCount;
    property Kind: TJOSECompactKind read GetKind;
    property Parts[AIndex: Integer]: string read GetPart; default;
  end;

  TJOSETimeUnit = (Days, Hours, Minutes, Seconds, Milliseconds);
  TJOSETimeUnitHelper = record helper for TJOSETimeUnit
  private
    function Convert(ADuration: UInt64; ADestUnit: TJOSETimeUnit): UInt64;
  public
    function ToDays(ADuration: UInt64): UInt64;
    function ToHours(ADuration: UInt64): UInt64;
    function ToMinutes(ADuration: UInt64): UInt64;
    function ToSeconds(ADuration: UInt64): UInt64;
    function ToMilliseconds(ADuration: UInt64): UInt64;
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
    /// <summary>
    ///   Replaces FJSON with the object parsed from AJSON. The current FJSON is
    ///   released only after the new object has been built and validated, so a
    ///   malformed segment can never leave FJSON dangling
    /// </summary>
    procedure SetJSONFromBytes(const AJSON: TJOSEBytes);
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
  System.Types,
  System.StrUtils,
  System.DateUtils,
  JOSE.Encoding.Base64;

resourcestring
  SJOSEInvalidJSONSegment = 'The token segment is not a valid JSON object';

{ TJOSECompactSerialization }

class function TJOSECompactSerialization.Split(const ACompactToken: TJOSEBytes): TJOSECompactSerialization;
begin
  Result.FParts := SplitString(ACompactToken, PART_SEPARATOR);
end;

function TJOSECompactSerialization.GetCount: Integer;
begin
  Result := Length(FParts);
end;

function TJOSECompactSerialization.GetKind: TJOSECompactKind;
begin
  case Count of
    JWS_PARTS: Result := TJOSECompactKind.JWS;
    JWE_PARTS: Result := TJOSECompactKind.JWE;
  else
    Result := TJOSECompactKind.Unknown;
  end;
end;

function TJOSECompactSerialization.GetPart(AIndex: Integer): string;
begin
  Result := FParts[AIndex];
end;

function TJOSECompactSerialization.PartsAreBase64URL: Boolean;
var
  LIndex: Integer;
begin
  for LIndex := 0 to Count - 1 do
    if not TBase64.IsValidURLEncoded(FParts[LIndex]) then
      Exit(False);

  Result := True;
end;

procedure TJOSECompactSerialization.CheckIsJWS;
begin
  // Deliberately about the shape only. Whether the parts decode, and what
  // happens when they do not, is the parser's business: TJWS.SetCompactToken
  // reports it, and TJOSE.Verify turns that into its documented nil
  case Kind of
    TJOSECompactKind.JWE:
      raise EJOSEException.Create(SJOSEJWENotSupported);
    TJOSECompactKind.Unknown:
      raise EJOSEException.Create(SJOSEMalformedCompactSerialization);
  end;
end;

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
begin
  SetJSONFromBytes(TBase64.Decode(Value));
end;

procedure TJOSEBase.SetJSONFromBytes(const AJSON: TJOSEBytes);
var
  LValue: TJSONValue;
begin
  LValue := TJSONObject.ParseJSONValue(AJSON.AsBytes, 0, True);

  if not Assigned(LValue) then
    raise EJOSEException.Create(SJOSEInvalidJSONSegment);

  // A JOSE header and a JWT payload are JSON *objects* (RFC 7515 sec. 4,
  // RFC 7519 sec. 7.2): anything else (a string, an array, a number, ...)
  // is a malformed token
  if not (LValue is TJSONObject) then
  begin
    LValue.Free;
    raise EJOSEException.Create(SJOSEInvalidJSONSegment);
  end;

  FJSON.Free;
  FJSON := TJSONObject(LValue);
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
  LDecoded: TJOSEBytes;
begin
  try
    LDecoded := TBase64.URLDecode(Value);
  except
    // Keep the JOSE contract: callers of this layer expect EJOSEException
    on E: EJOSEBase64Exception do
      raise EJOSEException.Create(E.Message);
  end;

  SetJSONFromBytes(LDecoded);
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
  // FValue is a local TDateTime (GetAsSeconds/SetAsSeconds treat it as local),
  // so it must be converted, not stamped with a 'Z' it doesn't deserve
  Result := DateToISO8601(FValue, False);
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
  // Must be the inverse of GetAsSeconds, which uses DateTimeToUnix(..., False)
  FValue := UnixToDateTime(AValue, False);
end;

{ TJOSETimeUnitHelper }

function TJOSETimeUnitHelper.Convert(ADuration: UInt64; ADestUnit: TJOSETimeUnit): UInt64;
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
        TJOSETimeUnit.Days:     Result := (ADuration div 60) div 24;
        TJOSETimeUnit.Hours:    Result := ADuration div 60;
        TJOSETimeUnit.Minutes:  Result := ADuration;
        TJOSETimeUnit.Seconds:  Result := ADuration * 60;
        TJOSETimeUnit.Milliseconds: Result := ADuration * 60 * 1000;
      end;
    end;
    TJOSETimeUnit.Seconds:
    begin
      case ADestUnit of
        TJOSETimeUnit.Days:     Result := ((ADuration div 60) div 60) div 24;
        TJOSETimeUnit.Hours:    Result := (ADuration div 60) div 60;
        TJOSETimeUnit.Minutes:  Result := ADuration div 60;
        TJOSETimeUnit.Seconds:  Result := ADuration;
        TJOSETimeUnit.Milliseconds: Result := ADuration * 1000;
      end;
    end;
    TJOSETimeUnit.Milliseconds:
    begin
      case ADestUnit of
        TJOSETimeUnit.Days:     Result := (((ADuration div 1000) div 60) div 60) div 24;
        TJOSETimeUnit.Hours:    Result := ((ADuration div 1000) div 60) div 60;
        TJOSETimeUnit.Minutes:  Result := (ADuration div 1000) div 60;
        TJOSETimeUnit.Seconds:  Result := ADuration div 1000;
        TJOSETimeUnit.Milliseconds: Result := ADuration;
      end;
    end;
  end;
end;

function TJOSETimeUnitHelper.ToDays(ADuration: UInt64): UInt64;
begin
  Result := Convert(ADuration, TJOSETimeUnit.Days);
end;

function TJOSETimeUnitHelper.ToHours(ADuration: UInt64): UInt64;
begin
  Result := Convert(ADuration, TJOSETimeUnit.Hours);
end;

function TJOSETimeUnitHelper.ToMilliseconds(ADuration: UInt64): UInt64;
begin
  Result := Convert(ADuration, TJOSETimeUnit.Milliseconds);
end;

function TJOSETimeUnitHelper.ToMinutes(ADuration: UInt64): UInt64;
begin
  Result := Convert(ADuration, TJOSETimeUnit.Minutes);
end;

function TJOSETimeUnitHelper.ToSeconds(ADuration: UInt64): UInt64;
begin
  Result := Convert(ADuration, TJOSETimeUnit.Seconds);
end;

end.
