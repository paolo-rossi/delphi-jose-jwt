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
///   Claim validators used by the JOSE Consumer pipeline
/// </summary>
unit JOSE.Consumer.Validators;

{$I ..\JOSE.inc}

interface

uses
  System.SysUtils, System.Generics.Collections,
  JOSE.Types.Bytes,
  JOSE.Core.Base,
  JOSE.Core.Parts,
  JOSE.Core.JWT,
  JOSE.Context;

type
  TJOSEDateClaimsParams = record
  private
    function GetEvaluationTime: TJOSENumericDate;
  public
    RequireExp: Boolean;
    RequireIat: Boolean;
    RequireNbf: Boolean;
    StaticEvaluationTime: TDateTime;
    AllowedClockSkewSeconds: Integer;
    MaxFutureValidityInMinutes: Integer;

    class function New: TJOSEDateClaimsParams; static;
    function SkewMessage: string;
    /// <summary>
    ///   The instant the claims are evaluated against: StaticEvaluationTime
    ///   when one was configured, the current time otherwise. Reading it has no
    ///   side effect, so take a snapshot into a local variable to compare
    ///   several claims against one consistent instant
    /// </summary>
    property EvaluationTime: TJOSENumericDate read GetEvaluationTime;
  end;

  TJOSEValidator = reference to function (AJOSEContext: TJOSEContext): string;

  TJOSEValidatorArray = TArray<TJOSEValidator>;
  TJOSEValidatorArrayHelper = record helper for TJOSEValidatorArray
  public
    function Add(AValue: TJOSEValidator): Integer;
  end;

  TJOSEClaimsValidators = class
    class function DateClaimsValidator(ADateParams: TJOSEDateClaimsParams): TJOSEValidator;

    class function audValidator(AAudience: TJOSEStringArray; ARequired: Boolean = True): TJOSEValidator;
    class function issValidator(const AIssuer: string; ARequired: Boolean = True): TJOSEValidator; overload;
    class function issValidator(AIssuers: TJOSEStringArray; ARequired: Boolean = True): TJOSEValidator; overload;
    class function subValidator(const ASubject: string; ARequired: Boolean): TJOSEValidator; overload;
    class function subValidator(ARequired: Boolean): TJOSEValidator; overload;
    class function jtiValidator(const AJwtId: string; ARequired: Boolean): TJOSEValidator; overload;
    class function jtiValidator(ARequired: Boolean): TJOSEValidator; overload;
  end;



implementation

uses
  System.DateUtils,
  System.Types,
  System.StrUtils;

resourcestring
  SJOSEOneOf = 'one of ';
  SJOSEClockSkewSuffix = '(even when providing [%d] seconds of leeway to account for clock skew)';
  SJOSENoAudienceClaim = 'No Audience [aud] claim present';
  SJOSEAudienceNotProvided = 'Audience [aud] claim present in the JWT but no expected audience value(s) were provided to the JWT Consumer.';
  SJOSEAudienceMismatch = 'Audience [aud] claim doesn''t contain an acceptable identifier. Expected %s as aud value.';
  SJOSENoExpirationClaim = 'No Expiration Time [exp] claim present';
  SJOSENoIssuedAtClaim = 'No IssuedAt [iat] claim present';
  SJOSENoNotBeforeClaim = 'No NotBefore [nbf] claim present';
  SJOSEExpiredToken = 'The JWT is no longer valid - the evaluation time [%s] is on or after the Expiration Time [exp=%s] claim value%s.';
  SJOSEExpBeforeIat = 'The Expiration Time (exp=%s) claim value cannot be before the IssuedAt (iat=%s) claim value';
  SJOSEExpBeforeNbf = 'The Expiration Time (exp=%s) claim value cannot be before the NotBefore (nbf=%s) claim value';
  SJOSEExpTooFarInFuture = 'The Expiration Time [exp=%s] claim value cannot be more than [%d] minutes in the future relative to the evaluation time [%s]%s.';
  SJOSENotYetValid = 'The JWT is not yet valid as the evaluation time [%s] is before the NotBefore [nbf=%s] claim time%s.';
  SJOSENoIssuerClaim = 'No Issuer [iss] claim present but was expecting %s';
  SJOSEIssuerMismatch = 'Issuer [iss] claim value [%s] doesn''t match expected value of [%s]';
  SJOSENoJTIClaim = 'No JWT ID [jti] claim present.';
  SJOSEJTIMismatch = 'JWT Id [jti] claim value [%s] doesn''t match expected value of [%s]';
  SJOSENoSubjectClaim = 'No Subject [sub] claim present';
  SJOSESubjectMismatch = 'Subject [sub] claim value [%s] doesn''t match expected value of [%s]';

{ TJOSEDateClaimsParams }

function TJOSEDateClaimsParams.GetEvaluationTime: TJOSENumericDate;
begin
  // Must NOT cache Now into StaticEvaluationTime: the record is captured by the
  // validator closure, so the first evaluation would freeze the clock for every
  // later validation done by the same (long-lived) consumer, and expired tokens
  // would keep being accepted
  if StaticEvaluationTime = 0 then
    Result := TJOSENumericDate.Create(Now)
  else
    Result := TJOSENumericDate.Create(StaticEvaluationTime);
end;

class function TJOSEDateClaimsParams.New: TJOSEDateClaimsParams;
begin
  Result.RequireExp := False;
  Result.RequireIat := False;
  Result.RequireNbf := False;
  Result.StaticEvaluationTime := 0;
  Result.AllowedClockSkewSeconds := 0;
  Result.MaxFutureValidityInMinutes := 0;
end;

function TJOSEDateClaimsParams.SkewMessage: string;
begin
  if AllowedClockSkewSeconds > 0 then
    Result := ' ' + Format(
      SJOSEClockSkewSuffix,
      [AllowedClockSkewSeconds]
    )
  else
    Result := '';
end;

{ TJOSEClaimsValidators }

class function TJOSEClaimsValidators.audValidator(AAudience: TJOSEStringArray; ARequired: Boolean = True): TJOSEValidator;
begin
  Result :=
    function (AJOSEContext: TJOSEContext): string
    var
      LOk: Boolean;
      LSingleAudience: string;
      LClaims: TJWTClaims;
      LExpected: string;
    begin
      Result := '';
      LClaims := AJOSEContext.GetClaims;

      if not LClaims.HasAudience then
        if ARequired then
          Exit(SJOSENoAudienceClaim)
        else
          Exit('');

      // No expected audience was configured, so there is nothing to match the
      // claim against. Only complain when the caller did ask for the audience
      // to be validated: the default consumer must not reject every token that
      // happens to carry an aud claim
      if AAudience.IsEmpty then
        if ARequired then
          Exit(SJOSEAudienceNotProvided)
        else
          Exit('');

      LOk := False;
      for LSingleAudience in LClaims.AudienceArray do
        if AAudience.Contains(LSingleAudience) then
        begin
          LOk := True;
          Break;
        end;

      if not LOk then
      begin
        LExpected := '[' + AAudience.ToStringPluralForm(SJOSEOneOf) + ']';
        Result := Format(SJOSEAudienceMismatch, [LExpected]);
      end;
    end
end;

class function TJOSEClaimsValidators.DateClaimsValidator(ADateParams: TJOSEDateClaimsParams): TJOSEValidator;
begin
  Result :=
    function (AJOSEContext: TJOSEContext): string
    var
      LClaims: TJWTClaims;
      // Every one of these must stay local to this function: the enclosing
      // method's locals live in the closure frame and would be shared by all
      // the validations performed through this validator, including concurrent ones
      LEvaluationTime: TJOSENumericDate;
      LExpiration, LIssuedAt, LNotBefore: TJOSENumericDate;
      LDeltaInSeconds: Int64;
    begin
      Result := '';
      LClaims := AJOSEContext.GetClaims;

      // One snapshot per validation, so all the claims below are compared
      // against the same instant
      LEvaluationTime := ADateParams.EvaluationTime;

      if ADateParams.RequireExp and not LClaims.HasExpiration then
        Exit(SJOSENoExpirationClaim);

      if ADateParams.RequireIat and not LClaims.HasIssuedAt then
        Exit(SJOSENoIssuedAtClaim);

      if ADateParams.RequireNbf and not LClaims.HasNotBefore then
        Exit(SJOSENoNotBeforeClaim);

      LIssuedAt := TJOSENumericDate.Create(LClaims.IssuedAt);
      LNotBefore := TJOSENumericDate.Create(LClaims.NotBefore);

      if LClaims.HasExpiration then
      begin
        LExpiration := TJOSENumericDate.Create(LClaims.Expiration);

        // RFC 7519 par. 4.1.4: the current time must be *before* exp, so an
        // evaluation time equal to exp is already too late
        if LEvaluationTime.IsOnOrAfter(LExpiration, ADateParams.AllowedClockSkewSeconds) then
          Exit(Format(
            SJOSEExpiredToken,
            [LEvaluationTime.AsISO8601, LExpiration.AsISO8601, ADateParams.SkewMessage])
          );

        if LClaims.HasIssuedAt and LExpiration.IsBefore(LIssuedAt, ADateParams.AllowedClockSkewSeconds) then
          Exit(Format(SJOSEExpBeforeIat,
            [LExpiration.AsISO8601, LIssuedAt.AsISO8601])
          );

        if LClaims.HasNotBefore and LExpiration.IsBefore(LNotBefore, ADateParams.AllowedClockSkewSeconds) then
          Exit(Format(SJOSEExpBeforeNbf,
            [LExpiration.AsISO8601, LNotBefore.AsISO8601])
          );

        if ADateParams.MaxFutureValidityInMinutes > 0 then
        begin
          LDeltaInSeconds :=
            LExpiration.AsSeconds -
            ADateParams.AllowedClockSkewSeconds -
            LEvaluationTime.AsSeconds;

          if LDeltaInSeconds > (Int64(ADateParams.MaxFutureValidityInMinutes) * 60) then
            Exit(Format(SJOSEExpTooFarInFuture,
              [LExpiration.AsISO8601, ADateParams.MaxFutureValidityInMinutes, LEvaluationTime.AsISO8601, ADateParams.SkewMessage])
            );
        end;
      end;

      if LClaims.HasNotBefore then
        if LEvaluationTime.IsBefore(LNotBefore, ADateParams.AllowedClockSkewSeconds) then
          Exit(Format(SJOSENotYetValid,
            [LEvaluationTime.AsISO8601, LNotBefore.AsISO8601, ADateParams.SkewMessage])
          );
    end;
end;

class function TJOSEClaimsValidators.issValidator(const AIssuer: string; ARequired: Boolean): TJOSEValidator;
var
  LIssuers: TJOSEStringArray;
begin
  LIssuers := TJOSEStringArray.Create;
  if not AIssuer.IsEmpty then
  begin
    LIssuers.Push(AIssuer);
  end;
  Result := issValidator(LIssuers, ARequired);
end;

class function TJOSEClaimsValidators.issValidator(AIssuers: TJOSEStringArray; ARequired: Boolean): TJOSEValidator;
begin
  Result :=
    function (AJOSEContext: TJOSEContext): string
    var
      LClaims: TJWTClaims;
      LIssuer: string;
    begin
      Result := '';
      LClaims := AJOSEContext.GetClaims;

      // An absent claim is a "required" question, never a mismatch: without
      // this, an optional issuer would still be rejected as [] <> [expected]
      if not LClaims.HasIssuer then
        if ARequired then
          Exit(Format(SJOSENoIssuerClaim,
            [AIssuers.ToStringPluralForm(SJOSEOneOf)]))
        else
          Exit('');

      LIssuer := LClaims.Issuer;
      if (AIssuers.Size > 0) and not AIssuers.Contains(LIssuer) then
        Exit(Format(SJOSEIssuerMismatch,
          [LIssuer, AIssuers.ToStringPluralForm(SJOSEOneOf)]));
    end
  ;
end;

class function TJOSEClaimsValidators.jtiValidator(const AJwtId: string; ARequired: Boolean): TJOSEValidator;
begin
  Result :=
    function (AJOSEContext: TJOSEContext): string
    var
      LClaims: TJWTClaims;
      LJWTId: string;
    begin
      Result := '';
      LClaims := AJOSEContext.GetClaims;

      if not LClaims.HasJWTId then
        if ARequired then
          Exit(SJOSENoJTIClaim)
        else
          Exit('');

      LJWTId := LClaims.JWTId;
      if not AJwtId.IsEmpty and not AJwtId.Equals(LJwtId) then
        Exit(Format(
          SJOSEJTIMismatch,
          [LJwtId, AJwtId]));
    end
  ;
end;

class function TJOSEClaimsValidators.jtiValidator(ARequired: Boolean): TJOSEValidator;
begin
  Result :=  TJOSEClaimsValidators.jtiValidator('', ARequired);
end;

class function TJOSEClaimsValidators.subValidator(const ASubject: string; ARequired: Boolean): TJOSEValidator;
begin
  Result :=
    function (AJOSEContext: TJOSEContext): string
    var
      LClaims: TJWTClaims;
      LSubject: string;
    begin
      Result := '';
      LClaims := AJOSEContext.GetClaims;

      if not LClaims.HasSubject then
        if ARequired then
          Exit(SJOSENoSubjectClaim)
        else
          Exit('');

      LSubject := LClaims.Subject;
      if not ASubject.IsEmpty and not ASubject.Equals(LSubject) then
        Exit(Format(
          SJOSESubjectMismatch,
          [LSubject, ASubject]));
    end
  ;
end;

class function TJOSEClaimsValidators.subValidator(ARequired: Boolean): TJOSEValidator;
begin
  Result := TJOSEClaimsValidators.subValidator('', ARequired);
end;

{ TJOSEValidatorArrayHelper }

function TJOSEValidatorArrayHelper.Add(AValue: TJOSEValidator): Integer;
begin
  Result := Length(Self);

  SetLength(Self, Result + 1);
  Self[Result] := AValue;
end;

end.
