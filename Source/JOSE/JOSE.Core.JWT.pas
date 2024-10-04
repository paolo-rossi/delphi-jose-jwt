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
///   JSON Web Token (JWT) RFC implementation
/// </summary>
/// <seealso href="https://tools.ietf.org/html/rfc7519">
///   JWT RFC Document
/// </seealso>
unit JOSE.Core.JWT;

{$I ..\JOSE.inc}

interface

uses
  System.SysUtils,
  System.StrUtils,
  System.DateUtils,
  System.Rtti,
  System.JSON,
  System.Generics.Collections,

  JOSE.Types.JSON,
  JOSE.Types.Bytes,
  JOSE.Core.Base,
  JOSE.Core.JWA,
  JOSE.Core.JWK;

type
  /// <summary>
  ///   Standard Header Parameters Names
  /// </summary>
  THeaderNames = class
  public const
    HEADER_TYPE = 'typ';
    ALGORITHM = 'alg';
    KEY_ID = 'kid';
  end;

  /// <summary>
  ///   Header part of the JWT
  /// </summary>
  TJWTHeader = class(TJOSEBase)
  private
    function GetAlgorithm: string;
    function GetHeaderType: string;
    procedure SetAlgorithm(const Value: string);
    procedure SetHeaderType(Value: string);
    function GetKeyID: string;
    procedure SetKeyID(const Value: string);
  public
    constructor Create; overload; virtual;
    constructor Create(const AType: string); overload; virtual;

    procedure SetHeaderParam(const AName: string; const AValue: TValue);
    procedure SetHeaderParamOfType<T>(const AName: string; const AValue: T);

    property Algorithm: string read GetAlgorithm write SetAlgorithm;
    property HeaderType: string read GetHeaderType write SetHeaderType;
    property KeyID: string read GetKeyID write SetKeyID;
  end;

  TJWTHeaderClass = class of TJWTHeader;

  /// <summary>
  ///   Reserved (Standard) Claim Names
  /// </summary>
  TReservedClaimNames = class
  public const
    AUDIENCE   = 'aud';
    EXPIRATION = 'exp';
    ISSUED_AT  = 'iat';
    ISSUER     = 'iss';
    JWT_ID     = 'jti';
    NOT_BEFORE = 'nbf';
    SUBJECT    = 'sub';
  end;

  TClaimVerification = (Audience, Expiration, IssuedAt, Issuer, TokenId, NotBefore, Subject);
  TClaimVerifications = set of TClaimVerification;

  /// <summary>
  ///   JSON Web Token (JWT) claims set.
  /// </summary>
  TJWTClaims = class(TJOSEBase)
  private
    const AUDIENCE_SEPARATOR = ',';
  private
    function GetAudience: string;
    function GetExpiration: TDateTime;
    function GetIssuedAt: TDateTime;
    function GetIssuer: string;
    function GetJWTId: string;
    function GetNotBefore: TDateTime;
    function GetSubject: string;
    procedure SetAudience(const AValue: string);
    procedure SetExpiration(AValue: TDateTime);
    procedure SetIssuedAt(AValue: TDateTime);
    procedure SetIssuer(const AValue: string);
    procedure SetJWTId(const AValue: string);
    procedure SetNotBefore(AValue: TDateTime);
    procedure SetSubject(const AValue: string);

    function GetHasAudience: Boolean;
    function GetHasExpiration: Boolean;
    function GetHasIssuedAt: Boolean;
    function GetHasIssuer: Boolean;
    function GetHasJWTId: Boolean;
    function GetHasNotBefore: Boolean;
    function GetHasSubject: Boolean;

    function GetAudienceArray: TArray<string>;
    procedure SetAudienceArray(const AValue: TArray<string>);
  public
    constructor Create; virtual;

    function ClaimExists(const AClaimName: string): Boolean;
    procedure SetClaim(const AName: string; const AValue: TValue);
    procedure SetClaimOfType<T>(const AName: string; const AValue: T);
    function GenerateJWTId(ANumberOfBytes: Integer = 16): string;

    property Audience: string read GetAudience write SetAudience;
    property AudienceArray: TArray<string> read GetAudienceArray write SetAudienceArray;
    property HasAudience: Boolean read GetHasAudience;
    property Expiration: TDateTime read GetExpiration write SetExpiration;
    property HasExpiration: Boolean read GetHasExpiration;
    property IssuedAt: TDateTime read GetIssuedAt write SetIssuedAt;
    property HasIssuedAt: Boolean read GetHasIssuedAt;
    property Issuer: string read GetIssuer write SetIssuer;
    property HasIssuer: Boolean read GetHasIssuer;
    property JWTId: string read GetJWTId write SetJWTId;
    property HasJWTId: Boolean read GetHasJWTId;
    property NotBefore: TDateTime read GetNotBefore write SetNotBefore;
    property HasNotBefore: Boolean read GetHasNotBefore;
    property Subject: string read GetSubject write SetSubject;
    property HasSubject: Boolean read GetHasSubject;
  end;

  TJWTClaimsClass = class of TJWTClaims;

  /// <summary>
  ///   JSON Web Token (JWT) interface.
  /// </summary>
  TJWT = class
  private
    FVerified: Boolean;
  protected
    FClaims: TJWTClaims;
    FHeader: TJWTHeader;
  public
    constructor Create; overload;
    constructor Create(AClaimsClass: TJWTClaimsClass); overload;
    constructor Create(AHeaderClass: TJWTHeaderClass; AClaimsClass: TJWTClaimsClass); overload;
    destructor Destroy; override;

    function Clone: TJWT;
    procedure Clear;

    function HeaderClass: TJWTHeaderClass;
    function ClaimClass: TJWTClaimsClass;

    function GetClaimsAs<T: TJWTClaims>: T; deprecated;
    function ClaimsAs<T: TJWTClaims>: T;
    function HeaderAs<T: TJWTHeader>: T;
  public
    property Header: TJWTHeader read FHeader;
    property Claims: TJWTClaims read FClaims;
    property Verified: Boolean read FVerified write FVerified;
  end;

implementation

uses
  JOSE.Encoding.Base64;

constructor TJWT.Create;
begin
  Create(TJWTHeader, TJWTClaims);
end;

constructor TJWT.Create(AClaimsClass: TJWTClaimsClass);
begin
  Create(TJWTHeader, AClaimsClass);
end;

constructor TJWT.Create(AHeaderClass: TJWTHeaderClass; AClaimsClass: TJWTClaimsClass);
begin
  FHeader := AHeaderClass.Create;
  if AClaimsClass = nil then
    FClaims := TJWTClaims.Create
  else
    FClaims := AClaimsClass.Create;
end;

destructor TJWT.Destroy;
begin
  FClaims.Free;
  FHeader.Free;
  inherited;
end;

function TJWT.ClaimClass: TJWTClaimsClass;
begin
  Result := TJWTClaimsClass(FClaims.ClassType);
end;

function TJWT.GetClaimsAs<T>: T;
begin
  Result := FClaims as T;
end;

function TJWT.HeaderAs<T>: T;
begin
  Result := FHeader as T;
end;

function TJWT.HeaderClass: TJWTHeaderClass;
begin
  Result := TJWTHeaderClass(FHeader.ClassType);
end;

function TJWT.ClaimsAs<T>: T;
begin
  Result := FClaims as T;
end;

procedure TJWT.Clear;
begin
  Header.Clear;
  Claims.Clear;
  Verified := False;
end;

function TJWT.Clone: TJWT;
begin
  Result := TJWT.Create(Self.HeaderClass, Self.ClaimClass);
  try
    Result.Header.Assign(FHeader);
    Result.Claims.Assign(FClaims);
    Result.Verified := FVerified;
  except
    Result.Free;
    raise;
  end;
end;

{ TJWTClaims }

procedure TJWTClaims.SetClaim(const AName: string; const AValue: TValue);
begin
  TJSONUtils.SetJSONRttiValue(AName, AValue, FJSON);
end;

procedure TJWTClaims.SetClaimOfType<T>(const AName: string; const AValue: T);
begin
  AddPairOfType<T>(AName, AValue);
end;

function TJWTClaims.ClaimExists(const AClaimName: string): Boolean;
begin
  Result := TJSONUtils.CheckPair(AClaimName, FJSON);
end;

constructor TJWTClaims.Create;
begin
  inherited Create;
end;

function TJWTClaims.GenerateJWTId(ANumberOfBytes: Integer): string;
var
  LID: TJOSEBytes;
begin
  LID := TJOSEBytes.RandomBytes(ANumberOfBytes);
  Result := TBase64.URLEncode(LID);
end;

function TJWTClaims.GetAudience: string;
var
  LValue, LAudValue: TJSONValue;
  LValueArray: TJSONArray;
begin
  Result := '';
  LAudValue := FJSON.GetValue(TReservedClaimNames.AUDIENCE);
  if Assigned(LAudValue) and (LAudValue is TJSONArray) then
  begin
    LValueArray := LAudValue as TJSONArray;

    for LValue in LValueArray do
      Result := Result + LValue.Value + AUDIENCE_SEPARATOR;

    Result := Result.TrimRight([AUDIENCE_SEPARATOR]);
  end
  else
    Result := TJSONUtils.GetJSONValue(TReservedClaimNames.AUDIENCE, FJSON).AsString;
end;

function TJWTClaims.GetAudienceArray: TArray<string>;
begin
  Result := Audience.Split([AUDIENCE_SEPARATOR]);
end;

function TJWTClaims.GetExpiration: TDateTime;
begin
  Result := TJSONUtils.GetJSONValueAsEpoch(TReservedClaimNames.EXPIRATION, FJSON);
end;

function TJWTClaims.GetHasAudience: Boolean;
begin
  Result := ClaimExists(TReservedClaimNames.AUDIENCE);
end;

function TJWTClaims.GetHasExpiration: Boolean;
begin
  Result := ClaimExists(TReservedClaimNames.EXPIRATION);
end;

function TJWTClaims.GetHasIssuedAt: Boolean;
begin
  Result := ClaimExists(TReservedClaimNames.ISSUED_AT);
end;

function TJWTClaims.GetHasIssuer: Boolean;
begin
  Result := ClaimExists(TReservedClaimNames.ISSUER);
end;

function TJWTClaims.GetHasJWTId: Boolean;
begin
  Result := ClaimExists(TReservedClaimNames.JWT_ID);
end;

function TJWTClaims.GetHasNotBefore: Boolean;
begin
  Result := ClaimExists(TReservedClaimNames.NOT_BEFORE);
end;

function TJWTClaims.GetHasSubject: Boolean;
begin
  Result := ClaimExists(TReservedClaimNames.SUBJECT);
end;

function TJWTClaims.GetIssuedAt: TDateTime;
begin
  Result := TJSONUtils.GetJSONValueAsEpoch(TReservedClaimNames.ISSUED_AT, FJSON);
end;

function TJWTClaims.GetIssuer: string;
begin
  Result := TJSONUtils.GetJSONValue(TReservedClaimNames.ISSUER, FJSON).AsString;
end;

function TJWTClaims.GetJWTId: string;
begin
  Result := TJSONUtils.GetJSONValue(TReservedClaimNames.JWT_ID, FJSON).AsString;
end;

function TJWTClaims.GetNotBefore: TDateTime;
begin
  Result := TJSONUtils.GetJSONValueAsEpoch(TReservedClaimNames.NOT_BEFORE, FJSON);
end;

function TJWTClaims.GetSubject: string;
begin
  Result := TJSONUtils.GetJSONValue(TReservedClaimNames.SUBJECT, FJSON).AsString;
end;

procedure TJWTClaims.SetAudience(const AValue: string);
var
  LAudienceArray: TArray<string>;
  LAudience: string;
  LArray: TJSONArray;
begin
  if AValue.IsEmpty then
  begin
    TJSONUtils.RemoveJSONNode(TReservedClaimNames.AUDIENCE, FJSON);
    Exit;
  end;

  LAudienceArray := AValue.Split([AUDIENCE_SEPARATOR]);

  if Length(LAudienceArray) > 1 then
  begin
    LArray := TJSONArray.Create;
    for LAudience in LAudienceArray do
      LArray.Add(LAudience);

    TJSONUtils.SetJSONValue(TReservedClaimNames.AUDIENCE, LArray, FJSON);
  end;

  if (Length(LAudienceArray) = 1) then
    TJSONUtils.SetJSONValueFrom<string>(TReservedClaimNames.AUDIENCE, AValue, FJSON);
end;

procedure TJWTClaims.SetAudienceArray(const AValue: TArray<string>);
begin
  Audience := string.Join(AUDIENCE_SEPARATOR, AValue);
end;

procedure TJWTClaims.SetExpiration(AValue: TDateTime);
begin
  if AValue = 0 then
    TJSONUtils.RemoveJSONNode(TReservedClaimNames.EXPIRATION, FJSON)
  else
    TJSONUtils.SetJSONValueFrom<TDateTime>(TReservedClaimNames.EXPIRATION, AValue, FJSON);
end;

procedure TJWTClaims.SetIssuedAt(AValue: TDateTime);
begin
  if AValue = 0 then
    TJSONUtils.RemoveJSONNode(TReservedClaimNames.ISSUED_AT, FJSON)
  else
    TJSONUtils.SetJSONValueFrom<TDateTime>(TReservedClaimNames.ISSUED_AT, AValue, FJSON);
end;

procedure TJWTClaims.SetIssuer(const AValue: string);
begin
  if AValue = '' then
    TJSONUtils.RemoveJSONNode(TReservedClaimNames.ISSUER, FJSON)
  else
    TJSONUtils.SetJSONValueFrom<string>(TReservedClaimNames.ISSUER, AValue, FJSON);
end;

procedure TJWTClaims.SetJWTId(const AValue: string);
begin
  if AValue = '' then
    TJSONUtils.RemoveJSONNode(TReservedClaimNames.JWT_ID, FJSON)
  else
    TJSONUtils.SetJSONValueFrom<string>(TReservedClaimNames.JWT_ID, AValue, FJSON);
end;

procedure TJWTClaims.SetNotBefore(AValue: TDateTime);
begin
  if AValue = 0 then
    TJSONUtils.RemoveJSONNode(TReservedClaimNames.NOT_BEFORE, FJSON)
  else
    TJSONUtils.SetJSONValueFrom<TDateTime>(TReservedClaimNames.NOT_BEFORE, AValue, FJSON);
end;

procedure TJWTClaims.SetSubject(const AValue: string);
begin
  if AValue = '' then
    TJSONUtils.RemoveJSONNode(TReservedClaimNames.SUBJECT, FJSON)
  else
    TJSONUtils.SetJSONValueFrom<string>(TReservedClaimNames.SUBJECT, AValue, FJSON);
end;

{ TJWTHeader }

constructor TJWTHeader.Create;
begin
  Create('JWT');
end;

constructor TJWTHeader.Create(const AType: string);
begin
  inherited Create;
  HeaderType := AType;
end;

function TJWTHeader.GetAlgorithm: string;
begin
  Result := TJSONUtils.GetJSONValue(THeaderNames.ALGORITHM, FJSON).AsString;
end;

function TJWTHeader.GetHeaderType: string;
begin
  Result := TJSONUtils.GetJSONValue(THeaderNames.HEADER_TYPE, FJSON).AsString;
end;

function TJWTHeader.GetKeyID: string;
begin
  Result := TJSONUtils.GetJSONValue(THeaderNames.KEY_ID, FJSON).AsString;
end;

procedure TJWTHeader.SetAlgorithm(const Value: string);
begin
  TJSONUtils.SetJSONValueFrom<string>(THeaderNames.ALGORITHM, Value, FJSON);
end;

procedure TJWTHeader.SetHeaderParam(const AName: string; const AValue: TValue);
begin
  TJSONUtils.SetJSONRttiValue(AName, AValue, FJSON);
end;

procedure TJWTHeader.SetHeaderParamOfType<T>(const AName: string; const AValue: T);
begin
  AddPairOfType<T>(AName, AValue);
end;

procedure TJWTHeader.SetHeaderType(Value: string);
begin
  TJSONUtils.SetJSONValueFrom<string>(THeaderNames.HEADER_TYPE, Value, FJSON);
end;

procedure TJWTHeader.SetKeyID(const Value: string);
begin
  TJSONUtils.SetJSONValueFrom<string>(THeaderNames.KEY_ID, Value, FJSON);
end;

end.
