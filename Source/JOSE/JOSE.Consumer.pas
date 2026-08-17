{******************************************************************************}
{                                                                              }
{  Delphi JOSE-JWT Library                                                     }
{  Copyright (c) 2015 Paolo Rossi                                              }
{  https://github.com/paolo-rossi/delphi-jose-jwt                              }
{                                                                              }
{  Licensed under the MIT license                                              }
{                                                                              }
{******************************************************************************}

unit JOSE.Consumer;

{$I ..\JOSE.inc}

interface

uses
  System.SysUtils, System.Generics.Collections, System.Classes,
  JOSE.Types.Bytes,
  JOSE.Core.Base,
  JOSE.Core.Parts,
  JOSE.Core.JWA,
  JOSE.Core.JWK,
  JOSE.Core.JWT,
  JOSE.Core.JWS,
  JOSE.Core.JWE,
  JOSE.Context,
  JOSE.Consumer.Validators;

type
  /// <summary>
  ///   Base class for the Consumer Exceptions
  /// </summary>
  EInvalidJWTException = class(Exception)
  public
    procedure SetDetails(ADetails: TStrings);
  end;

  /// <summary>
  ///   JOSE Consumer interface to process and validate a JWT
  /// </summary>
  IJOSEConsumer = interface
  ['{A270E909-6D79-4FC1-B4F6-B9911EAB8D36}']
    procedure Process(const ACompactToken: TJOSEBytes);
    procedure ProcessContext(AContext: TJOSEContext);
    procedure Validate(AContext: TJOSEContext);
  end;

  /// <summary>
  ///   Implementation of IJOSEConsumer interface
  /// </summary>
  TJOSEConsumer = class(TInterfacedObject, IJOSEConsumer)
  private
    class var FIncludeClaimsInExceptions: Boolean;
  private
    FKey: TJOSEBytes;
    FValidators: TJOSEValidatorArray;
    FClaimsClass: TJWTClaimsClass;
    FExpectedAlgorithms: TJOSEAlgorithms;

    FRequireSignature: Boolean;
    FRequireEncryption: Boolean;
    FSkipSignatureVerification: Boolean;
    FSkipVerificationKeyValidation: Boolean;
  private
    function SetKey(const AKey: TJOSEBytes): TJOSEConsumer;
    function SetValidators(const AValidators: TJOSEValidatorArray): TJOSEConsumer;
    function SetRequireSignature(ARequireSignature: Boolean): TJOSEConsumer;
    function SetRequireEncryption(ARequireEncryption: Boolean): TJOSEConsumer;
    function SetSkipSignatureVerification(ASkipSignatureVerification: Boolean): TJOSEConsumer;
    function SetSkipVerificationKeyValidation(ASkipVerificationKeyValidation: Boolean): TJOSEConsumer;
    function SetExpectedAlgorithms(AExpectedAlgorithms: TJOSEAlgorithms): TJOSEConsumer;
  public
    constructor Create(AClaimsClass: TJWTClaimsClass);

    procedure Process(const ACompactToken: TJOSEBytes);
    procedure ProcessContext(AContext: TJOSEContext);
    procedure Validate(AContext: TJOSEContext);

    /// <summary>
    ///   When True, the exception raised for a rejected token carries the whole
    ///   claims set in its message. Off by default: claims routinely hold
    ///   personal data (sub, email, roles, ...) and exception messages end up in
    ///   log files and monitoring systems. The per-claim validation details are
    ///   reported either way, so a rejection stays diagnosable without it
    /// </summary>
    class property IncludeClaimsInExceptions: Boolean
      read FIncludeClaimsInExceptions write FIncludeClaimsInExceptions;
  end;

  /// <summary>
  ///   Interface to configure a JOSEConsumer
  /// </summary>
  IJOSEConsumerBuilder = interface
  ['{8EC9CB4B-3233-493B-9366-F06CFFA81D99}']
    // Custom Claim Class
    function SetClaimsClass(AClaimsClass: TJWTClaimsClass): IJOSEConsumerBuilder;
    // Key, Signature & Encryption verification
    function SetEnableRequireEncryption: IJOSEConsumerBuilder;
    function SetDisableRequireSignature: IJOSEConsumerBuilder;
    function SetSkipSignatureVerification: IJOSEConsumerBuilder;
    function SetSkipVerificationKeyValidation: IJOSEConsumerBuilder;
    function SetVerificationKey(const AKey: TJOSEBytes): IJOSEConsumerBuilder;
    function SetDecryptionKey(const AKey: TJOSEBytes): IJOSEConsumerBuilder;
    function SetExpectedAlgorithms(AExpectedAlgorithms: TJOSEAlgorithms): IJOSEConsumerBuilder;
    // String-based claims
    function SetSkipDefaultAudienceValidation(): IJOSEConsumerBuilder;
    function SetExpectedAudience(ARequireAudience: Boolean; const AExpectedAudience: TArray<string>): IJOSEConsumerBuilder;
    function SetExpectedIssuer(ARequireIssuer: Boolean; const AExpectedIssuer: string): IJOSEConsumerBuilder;
    function SetExpectedIssuers(ARequireIssuer: Boolean; const AExpectedIssuers: TArray<string>): IJOSEConsumerBuilder;
    function SetRequireSubject: IJOSEConsumerBuilder;
    function SetExpectedSubject(const ASubject: string): IJOSEConsumerBuilder;
    function SetRequireJwtId: IJOSEConsumerBuilder;
    function SetExpectedJwtId(const AJwtId: string): IJOSEConsumerBuilder;
    // Date-based Claims
    function SetRequireExpirationTime: IJOSEConsumerBuilder;
    function SetRequireIssuedAt: IJOSEConsumerBuilder;
    function SetRequireNotBefore: IJOSEConsumerBuilder;
    function SetEvaluationTime(AEvaluationTime: TDateTime): IJOSEConsumerBuilder;
    function SetAllowedClockSkew(AClockSkew: Integer; ATimeUnit: TJOSETimeUnit): IJOSEConsumerBuilder;
    function SetMaxFutureValidity(AMaxFutureValidity: Integer; ATimeUnit: TJOSETimeUnit): IJOSEConsumerBuilder;
    // External validators
    function RegisterValidator(AValidator: TJOSEValidator): IJOSEConsumerBuilder;
    // Validators skipping
    function SetSkipAllValidators: IJOSEConsumerBuilder;
    function SetSkipAllDefaultValidators: IJOSEConsumerBuilder;

    function Build: IJOSEConsumer;
  end;

  /// <summary>
  ///   Used to create the appropriate TJOSEConsumer for the JWT processing needs.
  ///   Implements IJOSEConsumerBuilder interface
  /// </summary>
  TJOSEConsumerBuilder = class(TInterfacedObject, IJOSEConsumerBuilder)
  private
    FValidators: TJOSEValidatorArray;
    FDateValidatorParams: TJOSEDateClaimsParams;
    FDateValidator: TJOSEValidator;
    FAudValidator: TJOSEValidator;
    FIssValidator: TJOSEValidator;

    FKey: TJOSEBytes;
    FClaimsClass: TJWTClaimsClass;
    FExpectedAlgorithms: TJOSEAlgorithms;
    FDisableRequireSignature: Boolean;
    FEnableRequireEncryption: Boolean;
    FSkipVerificationKeyValidation: Boolean;
    FRequireJwtId: Boolean;
    FRequireSubject: Boolean;
    FSkipAllDefaultValidators: Boolean;
    FSkipAllValidators: Boolean;
    FSkipDefaultAudienceValidation: Boolean;
    FSkipSignatureVerification: Boolean;
    FSubject: string;
    FJwtId: string;
    constructor Create;
    procedure BuildValidators(const ADateParams: TJOSEDateClaimsParams);
  public
    class function NewConsumer: IJOSEConsumerBuilder;
    destructor Destroy; override;

    // Custom Claim Class
    function SetClaimsClass(AClaimsClass: TJWTClaimsClass): IJOSEConsumerBuilder;
    // Key, Signature & Encryption verification
    function SetEnableRequireEncryption: IJOSEConsumerBuilder;
    function SetDisableRequireSignature: IJOSEConsumerBuilder;
    function SetSkipSignatureVerification: IJOSEConsumerBuilder;
    function SetSkipVerificationKeyValidation: IJOSEConsumerBuilder;
    function SetVerificationKey(const AKey: TJOSEBytes): IJOSEConsumerBuilder;
    function SetDecryptionKey(const AKey: TJOSEBytes): IJOSEConsumerBuilder;
    function SetExpectedAlgorithms(AExpectedAlgorithms: TJOSEAlgorithms): IJOSEConsumerBuilder;
    // String-based claims
    function SetSkipDefaultAudienceValidation(): IJOSEConsumerBuilder;
    function SetExpectedAudience(ARequireAudience: Boolean; const AExpectedAudience: TArray<string>): IJOSEConsumerBuilder;
    function SetExpectedIssuer(ARequireIssuer: Boolean; const AExpectedIssuer: string): IJOSEConsumerBuilder;
    function SetExpectedIssuers(ARequireIssuer: Boolean; const AExpectedIssuers: TArray<string>): IJOSEConsumerBuilder;
    function SetRequireSubject: IJOSEConsumerBuilder;
    function SetExpectedSubject(const ASubject: string): IJOSEConsumerBuilder;
    function SetRequireJwtId: IJOSEConsumerBuilder;
    function SetExpectedJwtId(const AJwtId: string): IJOSEConsumerBuilder;
    // Date-based Claims
    function SetRequireExpirationTime: IJOSEConsumerBuilder;
    function SetRequireIssuedAt: IJOSEConsumerBuilder;
    function SetRequireNotBefore: IJOSEConsumerBuilder;
    function SetEvaluationTime(AEvaluationTime: TDateTime): IJOSEConsumerBuilder;
    function SetAllowedClockSkew(AClockSkew: Integer; ATimeUnit: TJOSETimeUnit): IJOSEConsumerBuilder;
    function SetMaxFutureValidity(AMaxFutureValidity: Integer; ATimeUnit: TJOSETimeUnit): IJOSEConsumerBuilder;
    // External validators
    function RegisterValidator(AValidator: TJOSEValidator): IJOSEConsumerBuilder;
    // Validators skipping
    function SetSkipAllValidators: IJOSEConsumerBuilder;
    function SetSkipAllDefaultValidators: IJOSEConsumerBuilder;

    function Build: IJOSEConsumer;
  end;

implementation

uses
  System.Types,
  System.StrUtils,
  JOSE.Types.JSON;

resourcestring
  SJOSEUnexpectedAlgorithm = 'JWS algorithm [%s] is not listed among those expected';
  SJOSEInvalidSignature = 'JWS signature is invalid';
  SJOSESignatureRequired = 'The JWT has no signature but the JWT Consumer is configured to require one';
  SJOSEClaimsRejected = 'JWT rejected due to invalid claims.';
  SJOSEClaimsRejectedWithClaims = 'JWT (claims: %s) rejected due to invalid claims.';
  SJOSEUnparsedToken = 'The JWT has not been parsed into a JOSE object';
  SJOSEUnsupportedJOSEObject = 'Unsupported JOSE object [%s]';

function TJOSEConsumerBuilder.Build: IJOSEConsumer;
begin
  if not Assigned(FClaimsClass) then
    FClaimsClass := TJWTClaims;

  BuildValidators(FDateValidatorParams);

  Result := TJOSEConsumer.Create(FClaimsClass)
    .SetKey(FKey)
    .SetRequireSignature(not FDisableRequireSignature)
    .SetRequireEncryption(FEnableRequireEncryption)
    .SetSkipSignatureVerification(FSkipSignatureVerification)
    .SetSkipVerificationKeyValidation(FSkipVerificationKeyValidation)
    .SetExpectedAlgorithms(FExpectedAlgorithms)
    .SetValidators(FValidators)
  ;
end;

procedure TJOSEConsumerBuilder.BuildValidators(const ADateParams: TJOSEDateClaimsParams);
begin
  if not FSkipAllValidators then
  begin
    if not FSkipAllDefaultValidators then
    begin
      if not FSkipDefaultAudienceValidation then
      begin
        if not Assigned(FAudValidator) then
          FAudValidator := TJOSEClaimsValidators.audValidator(TJOSEStringArray.Create, False);
        FValidators.add(FAudValidator);
      end;

      if not Assigned(FIssValidator) then
        FIssValidator := TJOSEClaimsValidators.issValidator('', False);
      FValidators.Add(FIssValidator);

      if not Assigned(FDateValidator) then
        FDateValidator := TJOSEClaimsValidators.DateClaimsValidator(ADateParams);
      FValidators.Add(FDateValidator);

      if FSubject.IsEmpty then
        FValidators.Add(TJOSEClaimsValidators.subValidator(FRequireSubject))
      else
        FValidators.Add(TJOSEClaimsValidators.subValidator(FSubject, FRequireSubject));

      if FJwtId.IsEmpty then
        FValidators.Add(TJOSEClaimsValidators.jtiValidator(FRequireJwtId))
      else
        FValidators.Add(TJOSEClaimsValidators.jtiValidator(FJwtId, FRequireJwtId));
    end;
  end;
end;

constructor TJOSEConsumerBuilder.Create;
begin
  inherited;
  FDateValidatorParams := TJOSEDateClaimsParams.New;
  FExpectedAlgorithms := [TJOSEAlgorithmId.None,
    TJOSEAlgorithmId.HS256, TJOSEAlgorithmId.HS384, TJOSEAlgorithmId.HS512,
    TJOSEAlgorithmId.RS256, TJOSEAlgorithmId.RS384, TJOSEAlgorithmId.RS512,
    TJOSEAlgorithmId.ES256, TJOSEAlgorithmId.ES256K, TJOSEAlgorithmId.ES384, TJOSEAlgorithmId.ES512,
    TJOSEAlgorithmId.PS256, TJOSEAlgorithmId.PS384, TJOSEAlgorithmId.PS512];
end;

destructor TJOSEConsumerBuilder.Destroy;
begin
  inherited;
end;

class function TJOSEConsumerBuilder.NewConsumer: IJOSEConsumerBuilder;
begin
  Result := Self.Create;
end;

function TJOSEConsumerBuilder.RegisterValidator(AValidator: TJOSEValidator): IJOSEConsumerBuilder;
var
  LLen: Integer;
begin
  LLen := Length(FValidators);
  SetLength(FValidators, LLen + 1);
  FValidators[LLen] := AValidator;
  Result := Self as IJOSEConsumerBuilder;
end;

function TJOSEConsumerBuilder.SetAllowedClockSkew(AClockSkew: Integer;
    ATimeUnit: TJOSETimeUnit): IJOSEConsumerBuilder;
begin
  FDateValidatorParams.AllowedClockSkewSeconds := ATimeUnit.ToSeconds(AClockSkew);
  Result := Self as IJOSEConsumerBuilder;
end;

function TJOSEConsumerBuilder.SetClaimsClass(AClaimsClass: TJWTClaimsClass): IJOSEConsumerBuilder;
begin
  FClaimsClass := AClaimsClass;
  Result := Self as IJOSEConsumerBuilder;
end;

function TJOSEConsumerBuilder.SetDecryptionKey(const AKey: TJOSEBytes): IJOSEConsumerBuilder;
begin
  FKey := AKey;
  Result := Self as IJOSEConsumerBuilder;
end;

function TJOSEConsumerBuilder.SetDisableRequireSignature: IJOSEConsumerBuilder;
begin
  FDisableRequireSignature := True;
  Result := Self as IJOSEConsumerBuilder;
end;

function TJOSEConsumerBuilder.SetEnableRequireEncryption: IJOSEConsumerBuilder;
begin
  FEnableRequireEncryption := True;
  Result := Self as IJOSEConsumerBuilder;
end;

function TJOSEConsumerBuilder.SetEvaluationTime(AEvaluationTime: TDateTime): IJOSEConsumerBuilder;
begin
  FDateValidatorParams.StaticEvaluationTime := AEvaluationTime;
  Result := Self as IJOSEConsumerBuilder;
end;

function TJOSEConsumerBuilder.SetExpectedAlgorithms(
  AExpectedAlgorithms: TJOSEAlgorithms): IJOSEConsumerBuilder;
begin
  FExpectedAlgorithms := AExpectedAlgorithms;
  Result := Self as IJOSEConsumerBuilder;
end;

function TJOSEConsumerBuilder.SetExpectedAudience(ARequireAudience: Boolean;
    const AExpectedAudience: TArray<string>): IJOSEConsumerBuilder;
begin
  FAudValidator := TJOSEClaimsValidators.audValidator(AExpectedAudience, ARequireAudience);
  Result := Self as IJOSEConsumerBuilder;
end;

function TJOSEConsumerBuilder.SetExpectedIssuer(ARequireIssuer: Boolean;
    const AExpectedIssuer: string): IJOSEConsumerBuilder;
begin
  FIssValidator := TJOSEClaimsValidators.issValidator(AExpectedIssuer, ARequireIssuer);
  Result := Self as IJOSEConsumerBuilder;
end;

function TJOSEConsumerBuilder.SetExpectedIssuers(ARequireIssuer: Boolean;
    const AExpectedIssuers: TArray<string>): IJOSEConsumerBuilder;
begin
  FIssValidator := TJOSEClaimsValidators.issValidator(AExpectedIssuers, ARequireIssuer);
  Result := Self as IJOSEConsumerBuilder;
end;

function TJOSEConsumerBuilder.SetExpectedJwtId(const AJwtId: string): IJOSEConsumerBuilder;
begin
  FJwtId := AJwtId;
  SetRequireJwtId;
  Result := Self as IJOSEConsumerBuilder;
end;

function TJOSEConsumerBuilder.SetExpectedSubject(const ASubject: string): IJOSEConsumerBuilder;
begin
  FSubject := ASubject;
  SetRequireSubject;
  Result := Self as IJOSEConsumerBuilder;
end;

function TJOSEConsumerBuilder.SetMaxFutureValidity(AMaxFutureValidity: Integer;
    ATimeUnit: TJOSETimeUnit): IJOSEConsumerBuilder;
begin
  FDateValidatorParams.MaxFutureValidityInMinutes := ATimeUnit.ToMinutes(AMaxFutureValidity);
  Result := Self as IJOSEConsumerBuilder;
end;

function TJOSEConsumerBuilder.SetSkipVerificationKeyValidation: IJOSEConsumerBuilder;
begin
  FSkipVerificationKeyValidation := True;
  Result := Self as IJOSEConsumerBuilder;
end;

function TJOSEConsumerBuilder.SetRequireExpirationTime: IJOSEConsumerBuilder;
begin
  FDateValidatorParams.RequireExp := True;
  Result := Self as IJOSEConsumerBuilder;
end;

function TJOSEConsumerBuilder.SetRequireIssuedAt: IJOSEConsumerBuilder;
begin
  FDateValidatorParams.RequireIat := True;
  Result := Self as IJOSEConsumerBuilder;
end;

function TJOSEConsumerBuilder.SetRequireJwtId: IJOSEConsumerBuilder;
begin
  FRequireJwtId := True;
  Result := Self as IJOSEConsumerBuilder;
end;

function TJOSEConsumerBuilder.SetRequireNotBefore: IJOSEConsumerBuilder;
begin
  FDateValidatorParams.RequireNbf := True;
  Result := Self as IJOSEConsumerBuilder;
end;

function TJOSEConsumerBuilder.SetRequireSubject: IJOSEConsumerBuilder;
begin
  FRequireSubject := True;
  Result := Self as IJOSEConsumerBuilder;
end;

function TJOSEConsumerBuilder.SetSkipAllDefaultValidators: IJOSEConsumerBuilder;
begin
  FSkipAllDefaultValidators := True;
  Result := Self as IJOSEConsumerBuilder;
end;

function TJOSEConsumerBuilder.SetSkipAllValidators: IJOSEConsumerBuilder;
begin
  FSkipAllValidators := True;
  Result := Self as IJOSEConsumerBuilder;
end;

function TJOSEConsumerBuilder.SetSkipDefaultAudienceValidation: IJOSEConsumerBuilder;
begin
  FSkipDefaultAudienceValidation := True;
  Result := Self as IJOSEConsumerBuilder;
end;

function TJOSEConsumerBuilder.SetSkipSignatureVerification: IJOSEConsumerBuilder;
begin
  FSkipSignatureVerification := True;
  Result := Self as IJOSEConsumerBuilder;
end;

function TJOSEConsumerBuilder.SetVerificationKey(const AKey: TJOSEBytes): IJOSEConsumerBuilder;
begin
  FKey := AKey;
  Result := Self as IJOSEConsumerBuilder;
end;

{ TJOSEConsumer }

constructor TJOSEConsumer.Create(AClaimsClass: TJWTClaimsClass);
begin
  FClaimsClass := AClaimsClass;
  FRequireSignature := True;
end;

procedure TJOSEConsumer.Process(const ACompactToken: TJOSEBytes);
var
  LContext: TJOSEContext;
begin
  LContext := TJOSEContext.Create(ACompactToken, FClaimsClass);
  try
    ProcessContext(LContext);
  finally
    LContext.Free;
  end;
end;

procedure TJOSEConsumer.ProcessContext(AContext: TJOSEContext);
var
  LJOSEObject: TJOSEParts;
  LJWS: TJWS;
  LHasSignature: Boolean;
  //LJWE: TJWE;
begin
  LHasSignature := False;

  // Never fall through to the claims validation with an unusable JOSE object:
  // that would silently skip the algorithm check and the signature verification
  LJOSEObject := AContext.GetJOSEObject;
  if not Assigned(LJOSEObject) then
    raise EJOSEException.Create(SJOSEUnparsedToken);

  if LJOSEObject is TJWS then
  begin
    LJWS := AContext.GetJOSEObject<TJWS>;

    // JWS Signature Verification
    if not FSkipSignatureVerification then
    begin
      if not (LJWS.HeaderAlgorithmId in FExpectedAlgorithms) then
        raise EJOSEException.CreateFmt(SJOSEUnexpectedAlgorithm, [LJWS.HeaderAlgorithm]);

      if FSkipVerificationKeyValidation then
        LJWS.SkipKeyValidation := True;

      LJWS.SetKey(Self.FKey);
      // The signature itself is not echoed: it is token material and exception
      // messages end up in logs. The caller already holds the token
      if not LJWS.VerifySignature then
        raise EJOSEException.Create(SJOSEInvalidSignature);
    end;

    if LJWS.HeaderAlgorithm <> TJOSEAlgorithmId.None.AsString then
      LHasSignature := True;

    if FRequireSignature and not LHasSignature then
      raise EJOSEException.Create(SJOSESignatureRequired);

  end
  else if LJOSEObject is TJWE then
  begin

  end
  else
    raise EJOSEException.CreateFmt(SJOSEUnsupportedJOSEObject, [LJOSEObject.ClassName]);

  Validate(AContext);
end;

function TJOSEConsumer.SetExpectedAlgorithms(AExpectedAlgorithms: TJOSEAlgorithms): TJOSEConsumer;
begin
  FExpectedAlgorithms := AExpectedAlgorithms;
  Result := Self;
end;

function TJOSEConsumer.SetKey(const AKey: TJOSEBytes): TJOSEConsumer;
begin
  FKey := AKey;
  Result := Self;
end;

function TJOSEConsumer.SetSkipVerificationKeyValidation(ASkipVerificationKeyValidation: Boolean): TJOSEConsumer;
begin
  FSkipVerificationKeyValidation := ASkipVerificationKeyValidation;
  Result := Self;
end;

function TJOSEConsumer.SetRequireEncryption(ARequireEncryption: Boolean): TJOSEConsumer;
begin
  FRequireEncryption := ARequireEncryption;
  Result := Self;
end;

function TJOSEConsumer.SetRequireSignature(ARequireSignature: Boolean): TJOSEConsumer;
begin
  FRequireSignature := ARequireSignature;
  Result := Self;
end;

function TJOSEConsumer.SetSkipSignatureVerification(ASkipSignatureVerification: Boolean): TJOSEConsumer;
begin
  FSkipSignatureVerification := ASkipSignatureVerification;
  Result := Self;
end;

function TJOSEConsumer.SetValidators(const AValidators: TJOSEValidatorArray): TJOSEConsumer;
begin
  FValidators := AValidators;
  Result := Self;
end;

procedure TJOSEConsumer.Validate(AContext: TJOSEContext);
var
  LValidator: TJOSEValidator;
  LResult: string;
  LIssues: TStringList;
  LException: EInvalidJWTException;
begin
  LIssues := TStringList.Create;
  try
    for LValidator in FValidators do
    begin
      LResult := LValidator(AContext);
      if LResult.IsEmpty then
        Continue;
      LIssues.Add(LResult);
    end;
    if LIssues.Count > 0 then
    begin
      // The details below name every claim that failed, which is what one needs
      // to diagnose a rejection. The claims set itself is only dumped on demand:
      // it routinely carries personal data and this message ends up in logs
      if IncludeClaimsInExceptions then
        LException := EInvalidJWTException.CreateFmt(
          SJOSEClaimsRejectedWithClaims,
          [TJSONUtils.ToJSON(AContext.GetClaims.JSON)])
      else
        LException := EInvalidJWTException.Create(SJOSEClaimsRejected);
      LException.SetDetails(LIssues);

      raise LException;
    end;
  finally
    LIssues.Free;
  end;
end;

{ EInvalidJWTException }

procedure EInvalidJWTException.SetDetails(ADetails: TStrings);
var
  LDetails: TSTringList;
begin
 if ADetails.Count > 0 then
 begin
   LDetails := TStringList.Create;
   try
     LDetails.Add(Message);
     LDetails.Add('Validation errors:');
     LDetails.AddStrings(ADetails);
     Message := LDetails.Text;
   finally
     LDetails.Free;
   end;
 end;
end;

end.

