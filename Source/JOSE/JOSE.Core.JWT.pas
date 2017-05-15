{******************************************************************************}
{                                                                              }
{  Delphi JOSE Library                                                         }
{  Copyright (c) 2015-2017 Paolo Rossi                                         }
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
  TJWTHeader = class sealed(TJOSEBase)
  private
    function GetAlgorithm: string;
    function GetHeaderType: string;
    procedure SetAlgorithm(const Value: string);
    procedure SetHeaderType(Value: string);
  public
    property Algorithm: string read GetAlgorithm write SetAlgorithm;
    property HeaderType: string read GetHeaderType write SetHeaderType;
  end;

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
    procedure SetAudience(Value: string);
    procedure SetExpiration(Value: TDateTime);
    procedure SetIssuedAt(Value: TDateTime);
    procedure SetIssuer(Value: string);
    procedure SetJWTId(Value: string);
    procedure SetNotBefore(Value: TDateTime);
    procedure SetSubject(Value: string);

    function GetHasAudience: Boolean;
    function GetHasExpiration: Boolean;
    function GetHasIssuedAt: Boolean;
    function GetHasIssuer: Boolean;
    function GetHasJWTId: Boolean;
    function GetHasNotBefore: Boolean;
    function GetHasSubject: Boolean;

    function ClaimExists(const AClaimName: string): Boolean;
    function GetAudienceArray: TArray<string>;
    procedure SetAudienceArray(const Value: TArray<string>);
  public
    constructor Create; virtual;
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

  TJWT = class
  private
    FVerified: Boolean;
  protected
    FClaims: TJWTClaims;
    FHeader: TJWTHeader;
  public
    constructor Create; overload;
    constructor Create(AClaimsClass: TJWTClaimsClass); overload;
    destructor Destroy; override;

    function GetClaimsAs<T: TJWTClaims>: T;

    property Header: TJWTHeader read FHeader;
    property Claims: TJWTClaims read FClaims;
    property Verified: Boolean read FVerified write FVerified;
  end;

implementation

uses
  JOSE.Encoding.Base64;

function TJWT.GetClaimsAs<T>: T;
begin
  Result := FClaims as T;
end;

constructor TJWT.Create(AClaimsClass: TJWTClaimsClass);
begin
  FHeader := TJWTHeader.Create;
  FHeader.HeaderType := 'JWT';
  FClaims := AClaimsClass.Create;
end;

constructor TJWT.Create;
begin
  Create(TJWTClaims);
end;

destructor TJWT.Destroy;
begin
  FHeader.Free;
  FClaims.Free;
  inherited;
end;

{ TJWTClaims }

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

procedure TJWTClaims.SetAudience(Value: string);
var
  LAudienceArray: TArray<string>;
  LAudience: string;
  LArray: TJSONArray;
begin
  if Value.IsEmpty then
  begin
    TJSONUtils.RemoveJSONNode(TReservedClaimNames.AUDIENCE, FJSON);
    Exit;
  end;

  LAudienceArray := Value.Split([AUDIENCE_SEPARATOR]);

  if Length(LAudienceArray) > 1 then
  begin
    LArray := TJSONArray.Create;
    for LAudience in LAudienceArray do
    begin
      LArray.Add(LAudience);
    end;
    FJSON.AddPair(TJSONPair.Create(TReservedClaimNames.AUDIENCE, LArray));
  end;

  if (Length(LAudienceArray) = 1) then
    TJSONUtils.SetJSONValueFrom<string>(TReservedClaimNames.AUDIENCE, Value, FJSON);
end;

procedure TJWTClaims.SetAudienceArray(const Value: TArray<string>);
begin
  Audience := string.Join(AUDIENCE_SEPARATOR, Value);
end;

procedure TJWTClaims.SetExpiration(Value: TDateTime);
begin
  if Value = 0 then
    TJSONUtils.RemoveJSONNode(TReservedClaimNames.EXPIRATION, FJSON)
  else
    TJSONUtils.SetJSONValueFrom<TDateTime>(TReservedClaimNames.EXPIRATION, Value, FJSON);
end;

procedure TJWTClaims.SetIssuedAt(Value: TDateTime);
begin
  if Value = 0 then
    TJSONUtils.RemoveJSONNode(TReservedClaimNames.ISSUED_AT, FJSON)
  else
    TJSONUtils.SetJSONValueFrom<TDateTime>(TReservedClaimNames.ISSUED_AT, Value, FJSON);
end;

procedure TJWTClaims.SetIssuer(Value: string);
begin
  if Value = '' then
    TJSONUtils.RemoveJSONNode(TReservedClaimNames.ISSUER, FJSON)
  else
    TJSONUtils.SetJSONValueFrom<string>(TReservedClaimNames.ISSUER, Value, FJSON);
end;

procedure TJWTClaims.SetJWTId(Value: string);
begin
  if Value = '' then
    TJSONUtils.RemoveJSONNode(TReservedClaimNames.JWT_ID, FJSON)
  else
    TJSONUtils.SetJSONValueFrom<string>(TReservedClaimNames.JWT_ID, Value, FJSON);
end;

procedure TJWTClaims.SetNotBefore(Value: TDateTime);
begin
  if Value = 0 then
    TJSONUtils.RemoveJSONNode(TReservedClaimNames.NOT_BEFORE, FJSON)
  else
    TJSONUtils.SetJSONValueFrom<TDateTime>(TReservedClaimNames.NOT_BEFORE, Value, FJSON);
end;

procedure TJWTClaims.SetSubject(Value: string);
begin
  if Value = '' then
    TJSONUtils.RemoveJSONNode(TReservedClaimNames.SUBJECT, FJSON)
  else
    TJSONUtils.SetJSONValueFrom<string>(TReservedClaimNames.SUBJECT, Value, FJSON);
end;

{ TJWTHeader }

function TJWTHeader.GetAlgorithm: string;
begin
  Result := TJSONUtils.GetJSONValue(THeaderNames.ALGORITHM, FJSON).AsString;
end;

function TJWTHeader.GetHeaderType: string;
begin
  Result := TJSONUtils.GetJSONValue(THeaderNames.HEADER_TYPE, FJSON).AsString;
end;

procedure TJWTHeader.SetAlgorithm(const Value: string);
begin
  TJSONUtils.SetJSONValueFrom<string>(THeaderNames.ALGORITHM, Value, FJSON);
end;

procedure TJWTHeader.SetHeaderType(Value: string);
begin
  TJSONUtils.SetJSONValueFrom<string>(THeaderNames.HEADER_TYPE, Value, FJSON);
end;

end.
