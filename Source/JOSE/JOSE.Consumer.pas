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
  /// <remarks>
  ///   <para>
  ///     A JWE is accepted only when its "alg" and "enc" are in the expected
  ///     key management and encryption algorithms, which are empty by default.
  ///   </para>
  ///   <para>
  ///     A nested JWT ("cty":"JWT") is decrypted with the decryption key, and
  ///     the inner JWS goes through the same checks as a plain JWS (algorithm
  ///     allowlist, verification key). Only one level is accepted: an inner
  ///     token that is itself a JWE is rejected.
  ///   </para>
  ///   <para>
  ///     The signature requirement (on by default) is met by a JWS or by the
  ///     inner JWS of a nested JWT. A JWE with the claims directly inside
  ///     carries no signature: accept it with SetDisableRequireSignature.
  ///   </para>
  /// </remarks>
  TJOSEConsumer = class(TInterfacedObject, IJOSEConsumer)
  private
    class var FIncludeClaimsInExceptions: Boolean;
  private
    FVerificationKey: TJOSEBytes;
    FDecryptionKey: TJOSEBytes;
    FValidators: TJOSEValidatorArray;
    FClaimsClass: TJWTClaimsClass;
    FExpectedAlgorithms: TJOSEAlgorithms;
    FExpectedKeyManagementAlgorithms: TJOSEAlgorithms;
    FExpectedEncryptionAlgorithms: TJOSEEncryptionAlgorithms;

    FRequireSignature: Boolean;
    FRequireEncryption: Boolean;
    FSkipSignatureVerification: Boolean;
    FSkipVerificationKeyValidation: Boolean;
  private
    function SetVerificationKey(const AKey: TJOSEBytes): TJOSEConsumer;
    function SetDecryptionKey(const AKey: TJOSEBytes): TJOSEConsumer;
    function SetValidators(const AValidators: TJOSEValidatorArray): TJOSEConsumer;
    function SetRequireSignature(ARequireSignature: Boolean): TJOSEConsumer;
    function SetRequireEncryption(ARequireEncryption: Boolean): TJOSEConsumer;
    function SetSkipSignatureVerification(ASkipSignatureVerification: Boolean): TJOSEConsumer;
    function SetSkipVerificationKeyValidation(ASkipVerificationKeyValidation: Boolean): TJOSEConsumer;
    function SetExpectedAlgorithms(AExpectedAlgorithms: TJOSEAlgorithms): TJOSEConsumer;
    function SetExpectedKeyManagementAlgorithms(AAlgorithms: TJOSEAlgorithms): TJOSEConsumer;
    function SetExpectedEncryptionAlgorithms(AAlgorithms: TJOSEEncryptionAlgorithms): TJOSEConsumer;

    /// <summary>
    ///   Checks the algorithm and the signature of AJWS. Returns whether it
    ///   carries a signature at all ("alg" other than "none")
    /// </summary>
    function ProcessJWS(AJWS: TJWS): Boolean;
    /// <summary>
    ///   Checks the algorithms of AJWE, decrypts it into AContext's claims and,
    ///   for a nested JWT, processes the inner JWS. Returns whether a
    ///   signature was found (only a nested JWT has one)
    /// </summary>
    function ProcessJWE(AContext: TJOSEContext; AJWE: TJWE): Boolean;
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
    /// <summary>
    ///   The key that verifies a JWS signature, including the inner JWS of a
    ///   nested JWT
    /// </summary>
    function SetVerificationKey(const AKey: TJOSEBytes): IJOSEConsumerBuilder;
    /// <summary>
    ///   The key that decrypts a JWE: the shared secret for "dir", the RSA
    ///   private key PEM for RSA-OAEP. Separate from the verification key: a
    ///   nested JWT needs both
    /// </summary>
    function SetDecryptionKey(const AKey: TJOSEBytes): IJOSEConsumerBuilder;
    /// <summary>The JWS "alg" values accepted. Defaults to every signing algorithm but "none"</summary>
    function SetExpectedAlgorithms(AExpectedAlgorithms: TJOSEAlgorithms): IJOSEConsumerBuilder;
    /// <summary>
    ///   The JWE "alg" values accepted. Empty by default, so a consumer
    ///   rejects every JWE until it is told which algorithms to accept
    /// </summary>
    function SetExpectedKeyManagementAlgorithms(AAlgorithms: TJOSEAlgorithms): IJOSEConsumerBuilder;
    /// <summary>
    ///   The JWE "enc" values accepted. Empty by default, like the key
    ///   management algorithms
    /// </summary>
    function SetExpectedEncryptionAlgorithms(AAlgorithms: TJOSEEncryptionAlgorithms): IJOSEConsumerBuilder;
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
    /// <summary>
    ///   Fixes the evaluation time to a local TDateTime. In the hour repeated
    ///   when daylight saving time ends a local time is ambiguous: pass a
    ///   TJOSENumericDate (TJOSENumericDate.FromSeconds/FromUTC) instead
    /// </summary>
    function SetEvaluationTime(AEvaluationTime: TDateTime): IJOSEConsumerBuilder; overload;
    /// <summary>
	///   Fixes the evaluation time to an exact instant
	/// </summary>
    function SetEvaluationTime(const AEvaluationTime: TJOSENumericDate): IJOSEConsumerBuilder; overload;
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

    FVerificationKey: TJOSEBytes;
    FDecryptionKey: TJOSEBytes;
    FClaimsClass: TJWTClaimsClass;
    FExpectedAlgorithms: TJOSEAlgorithms;
    FExpectedKeyManagementAlgorithms: TJOSEAlgorithms;
    FExpectedEncryptionAlgorithms: TJOSEEncryptionAlgorithms;
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
    function SetExpectedKeyManagementAlgorithms(AAlgorithms: TJOSEAlgorithms): IJOSEConsumerBuilder;
    function SetExpectedEncryptionAlgorithms(AAlgorithms: TJOSEEncryptionAlgorithms): IJOSEConsumerBuilder;
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
    function SetEvaluationTime(AEvaluationTime: TDateTime): IJOSEConsumerBuilder; overload;
    function SetEvaluationTime(const AEvaluationTime: TJOSENumericDate): IJOSEConsumerBuilder; overload;
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
  SJOSEEncryptionRequired = 'The JWT is not encrypted but the JWT Consumer is configured to require encryption';
  SJOSEClaimsRejected = 'JWT rejected due to invalid claims.';
  SJOSEClaimsRejectedWithClaims = 'JWT (claims: %s) rejected due to invalid claims.';
  SJOSEUnparsedToken = 'The JWT has not been parsed into a JOSE object';
  SJOSEUnsupportedJOSEObject = 'Unsupported JOSE object [%s]';
  SJOSEUnexpectedKeyManagementAlgorithm = 'JWE key management algorithm [%s] is not listed among those expected';
  SJOSEUnexpectedEncryptionAlgorithm = 'JWE content encryption algorithm [%s] is not listed among those expected';
  SJOSENestedNotJWS = 'The payload of a nested JWT ("cty":"JWT") must be a JWS: nested encryption is not supported';

function TJOSEConsumerBuilder.Build: IJOSEConsumer;
begin
  if not Assigned(FClaimsClass) then
    FClaimsClass := TJWTClaims;

  BuildValidators(FDateValidatorParams);

  Result := TJOSEConsumer.Create(FClaimsClass)
    .SetVerificationKey(FVerificationKey)
    .SetDecryptionKey(FDecryptionKey)
    .SetRequireSignature(not FDisableRequireSignature)
    .SetRequireEncryption(FEnableRequireEncryption)
    .SetSkipSignatureVerification(FSkipSignatureVerification)
    .SetSkipVerificationKeyValidation(FSkipVerificationKeyValidation)
    .SetExpectedAlgorithms(FExpectedAlgorithms)
    .SetExpectedKeyManagementAlgorithms(FExpectedKeyManagementAlgorithms)
    .SetExpectedEncryptionAlgorithms(FExpectedEncryptionAlgorithms)
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
  // Deliberately without None: the algorithm is unregistered today, so a "none"
  // token already fails, but listing it here would silently accept unsigned
  // tokens the moment someone registers TUnsecureNoneAlgorithm
  FExpectedAlgorithms := [
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
  // Its own field: it used to overwrite the verification key
  FDecryptionKey := AKey;
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
  FDateValidatorParams.SetStaticEvaluationTime(AEvaluationTime);
  Result := Self as IJOSEConsumerBuilder;
end;

function TJOSEConsumerBuilder.SetEvaluationTime(const AEvaluationTime: TJOSENumericDate): IJOSEConsumerBuilder;
begin
  FDateValidatorParams.SetStaticEvaluationInstant(AEvaluationTime);
  Result := Self as IJOSEConsumerBuilder;
end;

function TJOSEConsumerBuilder.SetExpectedAlgorithms(
  AExpectedAlgorithms: TJOSEAlgorithms): IJOSEConsumerBuilder;
begin
  FExpectedAlgorithms := AExpectedAlgorithms;
  Result := Self as IJOSEConsumerBuilder;
end;

function TJOSEConsumerBuilder.SetExpectedKeyManagementAlgorithms(
  AAlgorithms: TJOSEAlgorithms): IJOSEConsumerBuilder;
begin
  FExpectedKeyManagementAlgorithms := AAlgorithms;
  Result := Self as IJOSEConsumerBuilder;
end;

function TJOSEConsumerBuilder.SetExpectedEncryptionAlgorithms(
  AAlgorithms: TJOSEEncryptionAlgorithms): IJOSEConsumerBuilder;
begin
  FExpectedEncryptionAlgorithms := AAlgorithms;
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
  FVerificationKey := AKey;
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
  LHasSignature: Boolean;
begin
  // Never fall through to the claims validation with an unusable JOSE object:
  // that would silently skip the algorithm check and the signature verification
  LJOSEObject := AContext.GetJOSEObject;
  if not Assigned(LJOSEObject) then
    raise EJOSEException.Create(SJOSEUnparsedToken);

  // Encryption was demanded, so anything that is not a JWE has to be refused
  if FRequireEncryption and not (LJOSEObject is TJWE) then
    raise EJOSEException.Create(SJOSEEncryptionRequired);

  if LJOSEObject is TJWS then
    LHasSignature := ProcessJWS(TJWS(LJOSEObject))
  else if LJOSEObject is TJWE then
    LHasSignature := ProcessJWE(AContext, TJWE(LJOSEObject))
  else
    raise EJOSEException.CreateFmt(SJOSEUnsupportedJOSEObject, [LJOSEObject.ClassName]);

  if FRequireSignature and not LHasSignature then
    raise EJOSEException.Create(SJOSESignatureRequired);

  Validate(AContext);
end;

function TJOSEConsumer.ProcessJWS(AJWS: TJWS): Boolean;
begin
  // JWS Signature Verification
  if not FSkipSignatureVerification then
  begin
    if not (AJWS.HeaderAlgorithmId in FExpectedAlgorithms) then
      raise EJOSEException.CreateFmt(SJOSEUnexpectedAlgorithm, [AJWS.HeaderAlgorithm]);

    if FSkipVerificationKeyValidation then
      AJWS.SkipKeyValidation := True;

    AJWS.SetKey(FVerificationKey);
    // The signature itself is not echoed: it is token material and exception
    // messages end up in logs. The caller already holds the token
    if not AJWS.VerifySignature then
      raise EJOSEException.Create(SJOSEInvalidSignature);
  end;

  Result := AJWS.HeaderAlgorithm <> TJOSEAlgorithmId.None.AsString;
end;

function TJOSEConsumer.ProcessJWE(AContext: TJOSEContext; AJWE: TJWE): Boolean;
var
  LAlgId: TJOSEAlgorithmId;
  LEncId: TJOSEEncryptionAlgorithmId;
  LKey: TJWK;
  LInnerToken: TJWT;
  LInner: TJWS;
begin
  Result := False;

  // Both allowlists before any cryptography. A signing "alg" can never be in
  // here: the set is checked for key management membership too
  LAlgId.AsString := AJWE.Header.Algorithm;
  if not (LAlgId.IsKeyManagement and (LAlgId in FExpectedKeyManagementAlgorithms)) then
    raise EJOSEException.CreateFmt(SJOSEUnexpectedKeyManagementAlgorithm, [AJWE.Header.Algorithm]);

  LEncId.AsString := AJWE.Header.Encryption;
  if (LEncId = TJOSEEncryptionAlgorithmId.Unknown) or not (LEncId in FExpectedEncryptionAlgorithms) then
    raise EJOSEException.CreateFmt(SJOSEUnexpectedEncryptionAlgorithm, [AJWE.Header.Encryption]);

  // Fills the context's claims, unless the payload is a nested JWT
  LKey := TJWK.Create(FDecryptionKey);
  try
    AJWE.Decrypt(LKey);
  finally
    LKey.Free;
  end;

  if not AJWE.Header.IsNestedJWT then
    Exit;

  // One level only: the inner token must be a JWS, so an attacker cannot
  // drive the consumer through an unbounded chain of decryptions
  if TJOSECompactSerialization.Split(AJWE.Payload).Kind <> TJOSECompactKind.JWS then
    raise EJOSEException.Create(SJOSENestedNotJWS);

  LInnerToken := TJWT.Create(FClaimsClass);
  try
    LInner := TJWS.Create(LInnerToken);
    try
      LInner.CompactToken := AJWE.Payload;
      // The same checks as a plain JWS: algorithm allowlist, verification key
      Result := ProcessJWS(LInner);
    finally
      LInner.Free;
    end;

    // The claims to validate are the inner JWS's
    AContext.GetClaims.Assign(LInnerToken.Claims);
  finally
    LInnerToken.Free;
  end;
end;

function TJOSEConsumer.SetExpectedAlgorithms(AExpectedAlgorithms: TJOSEAlgorithms): TJOSEConsumer;
begin
  FExpectedAlgorithms := AExpectedAlgorithms;
  Result := Self;
end;

function TJOSEConsumer.SetExpectedKeyManagementAlgorithms(AAlgorithms: TJOSEAlgorithms): TJOSEConsumer;
begin
  FExpectedKeyManagementAlgorithms := AAlgorithms;
  Result := Self;
end;

function TJOSEConsumer.SetExpectedEncryptionAlgorithms(AAlgorithms: TJOSEEncryptionAlgorithms): TJOSEConsumer;
begin
  FExpectedEncryptionAlgorithms := AAlgorithms;
  Result := Self;
end;

function TJOSEConsumer.SetVerificationKey(const AKey: TJOSEBytes): TJOSEConsumer;
begin
  FVerificationKey := AKey;
  Result := Self;
end;

function TJOSEConsumer.SetDecryptionKey(const AKey: TJOSEBytes): TJOSEConsumer;
begin
  FDecryptionKey := AKey;
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

