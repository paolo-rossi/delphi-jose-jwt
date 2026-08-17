{******************************************************************************}
{                                                                              }
{  Delphi JOSE-JWT Library                                                     }
{  Copyright (c) 2015 Paolo Rossi                                              }
{  https://github.com/paolo-rossi/delphi-jose-jwt                              }
{                                                                              }
{  Licensed under the MIT license                                              }
{                                                                              }
{******************************************************************************}
unit JOSE.Producer;

{$I ..\JOSE.inc}

interface

uses
  System.SysUtils,
  System.Rtti,
  JOSE.Types.Bytes,
  JOSE.Core.Base,
  JOSE.Core.Parts,
  JOSE.Core.JWA,
  JOSE.Core.JWK,
  JOSE.Core.JWT,
  JOSE.Core.JWS,
  JOSE.Core.JWE;

type
  IJOSEProducer = interface
  ['{F1E7C004-134E-453E-B384-162702E2FF65}']
    //procedure Process(const ACompactToken: TJOSEBytes);
    //procedure ProcessContext(AContext: TJOSEContext);
    //procedure Validate(AContext: TJOSEContext);
    function GetCompactToken(): TJOSEBytes;
    function GetCompactString(): string;
  end;

  TJOSEProducer = class(TInterfacedObject, IJOSEProducer)
  private
    FJWT: TJWT;
    FKeys: TKeyPair;
    FAlg: TJOSEAlgorithmId;
    constructor Create(AJWT: TJWT; AKeys: TKeyPair; AAlg: TJOSEAlgorithmId);
  public
    destructor Destroy; override;
    function GetCompactToken(): TJOSEBytes;
    function GetCompactString(): string;
    function GetToken(): TJWT;
  end;

  IJOSEProducerBuilder = interface
  ['{95A11892-71F8-4509-A4E0-EA5EEE446B83}']


    /// <summary>
    ///   Header Claims
    /// </summary>
    function SetAlgorithm(AAlgorithm: TJOSEAlgorithmId): IJOSEProducerBuilder;
    function SetKeyID(const AValue: string): IJOSEProducerBuilder;
    function SetHeaderParam(const AName: string; const AValue: TValue): IJOSEProducerBuilder;

    /// <summary>
    ///   Payload Claims
    /// </summary>
    function SetAudience(const AValue: string): IJOSEProducerBuilder; overload;
    function SetAudience(const AValue: TArray<string>): IJOSEProducerBuilder; overload;
    function SetExpiration(AValue: TDateTime): IJOSEProducerBuilder;
    function SetIssuedAt(AValue: TDateTime): IJOSEProducerBuilder;
    function SetIssuer(const AValue: string): IJOSEProducerBuilder;
    function SetJWTId(const AValue: string): IJOSEProducerBuilder;
    function SetNotBefore(AValue: TDateTime): IJOSEProducerBuilder;
    function SetSubject(const AValue: string): IJOSEProducerBuilder;
    function SetCustomClaim(const AName: string; const AValue: TValue): IJOSEProducerBuilder;

    /// <summary>
    ///   Signing Keys
    /// </summary>
    function SetKey(const AKey: TJOSEBytes): IJOSEProducerBuilder;
    function SetKeyPair(const APublicKey, APrivateKey: TJOSEBytes): IJOSEProducerBuilder;

    function Build(): IJOSEProducer;
  end;

  TJOSEProducerBuilder = class(TInterfacedObject, IJOSEProducerBuilder)
  private
    FJWT: TJWT;
    FKeys: TKeyPair;
    FAlg: TJOSEAlgorithmId;

    function GetJWT: TJWT;
    function GetKeys: TKeyPair;
    procedure CheckPrerequisite;
  public
    class function New(): IJOSEProducerBuilder;
    destructor Destroy; override;

    function SetAlgorithm(AAlgorithm: TJOSEAlgorithmId): IJOSEProducerBuilder;
    function SetKeyID(const AValue: string): IJOSEProducerBuilder;
    function SetHeaderParam(const AName: string; const AValue: TValue): IJOSEProducerBuilder;

    function SetAudience(const AValue: string): IJOSEProducerBuilder; overload;
    function SetAudience(const AValue: TArray<string>): IJOSEProducerBuilder; overload;
    function SetExpiration(AValue: TDateTime): IJOSEProducerBuilder;
    function SetIssuedAt(AValue: TDateTime): IJOSEProducerBuilder;
    function SetIssuer(const AValue: string): IJOSEProducerBuilder;
    function SetJWTId(const AValue: string): IJOSEProducerBuilder;
    function SetNotBefore(AValue: TDateTime): IJOSEProducerBuilder;
    function SetSubject(const AValue: string): IJOSEProducerBuilder;
    function SetCustomClaim(const AName: string; const AValue: TValue): IJOSEProducerBuilder;

    function SetKey(const AKey: TJOSEBytes): IJOSEProducerBuilder;
    function SetKeyPair(const APublicKey, APrivateKey: TJOSEBytes): IJOSEProducerBuilder;

    function Build(): IJOSEProducer;
  end;

  TJOSEProcess = TJOSEProducerBuilder;


implementation

resourcestring
  SJOSEClaimsNotAssigned = 'JWT Claims not assigned';
  SJOSESigningKeysNotAssigned = 'Signing key(s) not assigned';
  SJOSESigningKeyIsEmpty = 'The signing key holds no key material';
  SJOSESigningAlgorithmNotAssigned = 'Signing algorithm not assigned';

{ TJOSEProducer }

constructor TJOSEProducer.Create(AJWT: TJWT; AKeys: TKeyPair; AAlg: TJOSEAlgorithmId);
begin
  FJWT := AJWT.Clone;
  FKeys := AKeys.Clone;
  FAlg := AAlg;
end;

destructor TJOSEProducer.Destroy;
begin
  FJWT.Free;
  FKeys.Free;

  inherited;
end;

function TJOSEProducer.GetCompactString: string;
begin
  Result := GetCompactToken.AsString;
end;

function TJOSEProducer.GetCompactToken: TJOSEBytes;
var
  LSigner: TJWS;
begin
  LSigner := TJWS.Create(FJWT);
  try
    LSigner.Sign(FKeys.PrivateKey, FAlg);
    Result := LSigner.CompactToken;
  finally
    LSigner.Free;
  end;
end;

function TJOSEProducer.GetToken: TJWT;
begin
  Result := FJWT.Clone;
end;

function TJOSEProducerBuilder.Build: IJOSEProducer;
begin
  CheckPrerequisite;
  Result := TJOSEProducer.Create(FJWT, FKeys, FAlg);
end;

procedure TJOSEProducerBuilder.CheckPrerequisite;
begin
  if not Assigned(FJWT) then
    raise EJOSEException.Create(SJOSEClaimsNotAssigned);

  if not Assigned(FKeys) then
    raise EJOSEException.Create(SJOSESigningKeysNotAssigned);

  // A key pair object is not the same thing as key material: SetKeyPair with a
  // public-only key leaves PrivateKey empty, and signing would only fail later,
  // inside the provider. The algorithm-specific checks stay where they belong,
  // in ValidateSigningKey
  if FKeys.PrivateKey.Key.IsEmpty then
    raise EJOSEException.Create(SJOSESigningKeyIsEmpty);

  if FAlg = TJOSEAlgorithmId.Unknown then
    raise EJOSEException.Create(SJOSESigningAlgorithmNotAssigned);
end;

destructor TJOSEProducerBuilder.Destroy;
begin
  FJWT.Free;
  FKeys.Free;

  inherited;
end;

function TJOSEProducerBuilder.GetJWT: TJWT;
begin
  if not Assigned(FJWT) then
    FJWT := TJWT.Create;
  Result := FJWT;
end;

function TJOSEProducerBuilder.GetKeys: TKeyPair;
begin
  if not Assigned(FKeys) then
    FKeys := TKeyPair.Create;
  Result := FKeys;
end;

class function TJOSEProducerBuilder.New: IJOSEProducerBuilder;
begin
  Result := Self.Create;
end;

function TJOSEProducerBuilder.SetAlgorithm(AAlgorithm: TJOSEAlgorithmId): IJOSEProducerBuilder;
begin
  FAlg := AAlgorithm;
  Result := Self;
end;

function TJOSEProducerBuilder.SetAudience(const AValue: string): IJOSEProducerBuilder;
begin
  GetJWT.Claims.Audience := AValue;
  Result := Self;
end;

function TJOSEProducerBuilder.SetAudience(const AValue: TArray<string>): IJOSEProducerBuilder;
begin
  GetJWT.Claims.AudienceArray := AValue;
  Result := Self;
end;

function TJOSEProducerBuilder.SetCustomClaim(const AName: string; const AValue: TValue): IJOSEProducerBuilder;
begin
  GetJWT.Claims.SetClaim(AName, AValue);
  Result := Self;
end;

function TJOSEProducerBuilder.SetExpiration(AValue: TDateTime): IJOSEProducerBuilder;
begin
  GetJWT.Claims.Expiration := AValue;
  Result := Self;
end;

function TJOSEProducerBuilder.SetHeaderParam(const AName: string; const AValue: TValue): IJOSEProducerBuilder;
begin
  GetJWT.Header.SetHeaderParam(AName, AValue);
  Result := Self;
end;

function TJOSEProducerBuilder.SetIssuedAt(AValue: TDateTime): IJOSEProducerBuilder;
begin
  GetJWT.Claims.IssuedAt := AValue;
  Result := Self;
end;

function TJOSEProducerBuilder.SetIssuer(const AValue: string): IJOSEProducerBuilder;
begin
  GetJWT.Claims.Issuer := AValue;
  Result := Self;
end;

function TJOSEProducerBuilder.SetJWTId(const AValue: string): IJOSEProducerBuilder;
begin
  GetJWT.Claims.JWTId := AValue;
  Result := Self;
end;

function TJOSEProducerBuilder.SetKey(const AKey: TJOSEBytes): IJOSEProducerBuilder;
begin
  GetKeys.SetSymmetricKey(AKey);
  Result := Self;
end;

function TJOSEProducerBuilder.SetKeyID(const AValue: string): IJOSEProducerBuilder;
begin
  GetJWT.Header.KeyID := AValue;
  Result := Self;
end;

function TJOSEProducerBuilder.SetKeyPair(const APublicKey, APrivateKey: TJOSEBytes): IJOSEProducerBuilder;
begin
  GetKeys.SetAsymmetricKeys(APublicKey, APrivateKey);
  Result := Self;
end;

function TJOSEProducerBuilder.SetNotBefore(AValue: TDateTime): IJOSEProducerBuilder;
begin
  GetJWT.Claims.NotBefore := AValue;
  Result := Self;
end;

function TJOSEProducerBuilder.SetSubject(const AValue: string): IJOSEProducerBuilder;
begin
  GetJWT.Claims.Subject := AValue;
  Result := Self;
end;

end.
