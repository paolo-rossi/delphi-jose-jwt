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

interface

uses
  System.SysUtils,
  System.StrUtils,
  System.DateUtils,
  System.Rtti,
  System.Generics.Collections,
  JOSE.Types.JSON,
  JOSE.Types.Bytes,
  JOSE.Core.Base,
  JOSE.Core.JWA,
  JOSE.Core.JWK;

type
  THeaderNames = class
  public const
    HEADER_TYPE = 'typ';
    ALGORITHM = 'alg';
  end;

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
  public
    constructor Create; virtual;
    procedure SetClaimOfType<T>(const AName: string; const AValue: T);
    function GenerateJWTId(ANumberOfBytes: Integer = 16): string;
    procedure CheckRegisteredClaims(AOptions: TClaimVerifications = []); virtual;

    property Audience: string read GetAudience write SetAudience;
    property Expiration: TDateTime read GetExpiration write SetExpiration;
    property IssuedAt: TDateTime read GetIssuedAt write SetIssuedAt;
    property Issuer: string read GetIssuer write SetIssuer;
    property JWTId: string read GetJWTId write SetJWTId;
    property NotBefore: TDateTime read GetNotBefore write SetNotBefore;
    property Subject: string read GetSubject write SetSubject;
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

    property Header: TJWTHeader read FHeader;
    property Claims: TJWTClaims read FClaims;
    property Verified: Boolean read FVerified write FVerified;
  end;

implementation

uses
  JOSE.Encoding.Base64;

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

procedure TJWTClaims.CheckRegisteredClaims(AOptions: TClaimVerifications = []);
//var
//  LOption: TClaimVerification;
begin
{
  for LOption in AOptions do
  begin
    case LOption of
      Audience: ;
      Expiration: ;
      IssuedAt: ;
      Issuer: ;
      TokenId: ;
      NotBefore: ;
      Subject: ;
    end;
  end;
}
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
begin
  Result := TJSONUtils.GetJSONValue(TReservedClaimNames.AUDIENCE, FJSON).AsString;
end;

function TJWTClaims.GetExpiration: TDateTime;
begin
  Result := TJSONUtils.GetJSONValueAsEpoch(TReservedClaimNames.EXPIRATION, FJSON);
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
begin
  if Value = '' then
    TJSONUtils.RemoveJSONNode(TReservedClaimNames.AUDIENCE, FJSON)
  else
    TJSONUtils.SetJSONValueFrom<string>(TReservedClaimNames.AUDIENCE, Value, FJSON);
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
