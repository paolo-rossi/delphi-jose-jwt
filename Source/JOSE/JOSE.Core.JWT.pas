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
unit JOSE.Core.JWT;

interface

uses
  System.SysUtils,
  System.StrUtils,
  System.DateUtils,
  System.Rtti,
  System.Generics.Collections,
  IdSSLOpenSSLHeaders,
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
    procedure SetClaimOfType<T>(const AName: string; const AValue: T);

    function CheckRegisteredClaims: Boolean; virtual;
    function CheckPrivateClaims: Boolean; virtual;

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
    constructor Create(AClaimsClass: TJWTClaimsClass);
    destructor Destroy; override;


    property Header: TJWTHeader read FHeader;
    property Claims: TJWTClaims read FClaims;
    property Verified: Boolean read FVerified write FVerified;
  end;

implementation

constructor TJWT.Create(AClaimsClass: TJWTClaimsClass);
begin
  FHeader := TJWTHeader.Create;
  FHeader.HeaderType := 'JWT';
  FClaims := AClaimsClass.Create;
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

function TJWTClaims.CheckPrivateClaims: Boolean;
begin
  Result := True;
end;

function TJWTClaims.CheckRegisteredClaims: Boolean;
begin
  Result := True;
end;

function TJWTClaims.GetAudience: string;
begin
  Result := TJSONUtils.GetJSONValue('aud', FJSON).AsString;
end;

function TJWTClaims.GetExpiration: TDateTime;
begin
  Result := TJSONUtils.GetJSONValueAsDate('exp', FJSON);
end;

function TJWTClaims.GetIssuedAt: TDateTime;
begin
  Result := TJSONUtils.GetJSONValueAsDate('iat', FJSON);
end;

function TJWTClaims.GetIssuer: string;
begin
  Result := TJSONUtils.GetJSONValue('iss', FJSON).AsString;
end;

function TJWTClaims.GetJWTId: string;
begin
  Result := TJSONUtils.GetJSONValue('jti', FJSON).AsString;
end;

function TJWTClaims.GetNotBefore: TDateTime;
begin
  Result := TJSONUtils.GetJSONValueAsDate('nbf', FJSON);
end;

function TJWTClaims.GetSubject: string;
begin
  Result := TJSONUtils.GetJSONValue('sub', FJSON).AsString;
end;

procedure TJWTClaims.SetAudience(Value: string);
begin
  TJSONUtils.SetJSONValueFrom<string>('aud', Value, FJSON);
end;

procedure TJWTClaims.SetExpiration(Value: TDateTime);
begin
  TJSONUtils.SetJSONValueFrom<TDateTime>('exp', Value, FJSON);
end;

procedure TJWTClaims.SetIssuedAt(Value: TDateTime);
begin
  TJSONUtils.SetJSONValueFrom<TDateTime>('iat', Value, FJSON);
end;

procedure TJWTClaims.SetIssuer(Value: string);
begin
  TJSONUtils.SetJSONValueFrom<string>('iss', Value, FJSON);
end;

procedure TJWTClaims.SetJWTId(Value: string);
begin
  TJSONUtils.SetJSONValueFrom<string>('jti', Value, FJSON);
end;

procedure TJWTClaims.SetNotBefore(Value: TDateTime);
begin
  TJSONUtils.SetJSONValueFrom<TDateTime>('nbf', Value, FJSON);
end;

procedure TJWTClaims.SetSubject(Value: string);
begin
  TJSONUtils.SetJSONValueFrom<string>('sub', Value, FJSON);
end;

{ TJWTHeader }

function TJWTHeader.GetAlgorithm: string;
begin
  Result := TJSONUtils.GetJSONValue('alg', FJSON).AsString;
end;

function TJWTHeader.GetHeaderType: string;
begin
  Result := TJSONUtils.GetJSONValue('typ', FJSON).AsString;
end;

procedure TJWTHeader.SetAlgorithm(const Value: string);
begin
  TJSONUtils.SetJSONValueFrom<string>('alg', Value, FJSON);
end;

procedure TJWTHeader.SetHeaderType(Value: string);
begin
  TJSONUtils.SetJSONValueFrom<string>('typ', Value, FJSON);
end;

end.
