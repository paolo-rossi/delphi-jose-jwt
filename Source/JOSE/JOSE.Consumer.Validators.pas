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
///   Utility class to encode and decode a JWT
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
  IJOSEValidator = interface
    function Validate(AJOSEContext: TJOSEContext): string;
  end;

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
    class function issValidator(AIssuer: string; ARequired: Boolean = True): TJOSEValidator; overload;
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

{ TJOSEDateClaimsParams }

function TJOSEDateClaimsParams.GetEvaluationTime: TJOSENumericDate;
begin
  if StaticEvaluationTime = 0 then
    StaticEvaluationTime := Now;

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
    Result := Format(
      '(even when providing [%d] seconds of leeway to account for clock skew)',
      [AllowedClockSkewSeconds]
    )
  else
    Result := '.';
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
    begin
      Result := '';
      LClaims := AJOSEContext.GetClaims;

      if not LClaims.HasAudience then
        if ARequired then
          Exit('No Audience [aud] claim present')
        else
          Exit('');

      LOk := False;
      for LSingleAudience in LClaims.AudienceArray do
        if AAudience.Contains(LSingleAudience) then
          LOk := True;

      if not LOk then
      begin
        Result := 'Audience [aud] claim ';

        if AAudience.IsEmpty then
          Result := Result + ' present in the JWT but no expected audience value(s) were provided to the JWT Consumer.'
        else
          Result := Result + ' doesn''t contain an acceptable identifier.';

        Result := Result + ' Expected ';

        if AAudience.Size = 1 then
          Result := Result + '[' + AAudience.ToString + ']'
        else
          Result := Result + 'one of [' + AAudience.ToString + ']';

        Result := Result +  ' as aud value.';
      end;
    end
end;

class function TJOSEClaimsValidators.DateClaimsValidator(ADateParams: TJOSEDateClaimsParams): TJOSEValidator;
var
  LDeltaInSeconds: Int64;
begin
  Result :=
    function (AJOSEContext: TJOSEContext): string
    var
      LClaims: TJWTClaims;
      LExpiration, LIssuedAt, LNotBefore: TJOSENumericDate;
    begin
      Result := '';
      LClaims := AJOSEContext.GetClaims;

      LExpiration := TJOSENumericDate.Create(LClaims.Expiration);
      LIssuedAt := TJOSENumericDate.Create(LClaims.IssuedAt);
      LNotBefore := TJOSENumericDate.Create(LClaims.NotBefore);

      if ADateParams.RequireExp and not LClaims.HasExpiration then
        Exit('No Expiration Time [exp] claim present');

      if ADateParams.RequireIat and not LClaims.HasIssuedAt then
        Exit('No IssuedAt [iat] claim present');

      if ADateParams.RequireNbf and not LClaims.HasNotBefore then
        Exit('No NotBefore [nbf] claim present');

      if LClaims.HasExpiration then
      begin
        if ADateParams.EvaluationTime.IsAfter(LExpiration, ADateParams.AllowedClockSkewSeconds) then
          Exit(Format(
            'The JWT is no longer valid - the evaluation time [%s] is on or after the Expiration Time [exp=%s] claim value %s',
            [ADateParams.EvaluationTime.AsISO8601, DateToISO8601(LClaims.Expiration, False), ADateParams.SkewMessage])
          );

        if LClaims.HasIssuedAt and LExpiration.IsBefore(LIssuedAt, ADateParams.AllowedClockSkewSeconds) then
          Exit(Format('The Expiration Time (exp=%s) claim value cannot be before the IssuedAt (iat=%s) claim value',
            [LExpiration.AsISO8601, LIssuedAt.AsISO8601])
          );

        if LClaims.HasNotBefore and LExpiration.IsBefore(LNotBefore, ADateParams.AllowedClockSkewSeconds) then
          Exit(Format('The Expiration Time (exp=%s) claim value cannot be before the NotBefore (nbf=%s) claim value',
            [LExpiration.AsISO8601, LNotBefore.AsISO8601])
          );

        if ADateParams.MaxFutureValidityInMinutes > 0 then
        begin
          LDeltaInSeconds :=
            LExpiration.AsSeconds -
            ADateParams.AllowedClockSkewSeconds -
            ADateParams.EvaluationTime.AsSeconds;

          if LDeltaInSeconds > (ADateParams.MaxFutureValidityInMinutes * 60) then
            Exit(Format('The Expiration Time [exp=%s] claim value cannot be more than [%d] minutes in the future relative to the evaluation time [%s] %s',
              [LExpiration.AsISO8601, ADateParams.MaxFutureValidityInMinutes, ADateParams.EvaluationTime.AsISO8601, ADateParams.SkewMessage])
            );
        end;
      end;

      if LClaims.HasNotBefore then
        if (ADateParams.EvaluationTime.AsSeconds + ADateParams.AllowedClockSkewSeconds) < LNotBefore.AsSeconds then
          Exit(Format('The JWT is not yet valid as the evaluation time [%s] is before the NotBefore [nbf=%s] claim time %s',
            [ADateParams.EvaluationTime.AsISO8601, LNotBefore.AsISO8601, ADateParams.SkewMessage])
          );
    end;
  ;
end;

class function TJOSEClaimsValidators.issValidator(AIssuer: string; ARequired: Boolean): TJOSEValidator;
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
      LIssuer: string;
    begin
      Result := '';
      LIssuer := AJOSEContext.GetClaims.Issuer;

      if not AJOSEContext.GetClaims.HasIssuer and ARequired then
        Exit(Format('No Issuer [iss] claim present but was expecting %s',
          [AIssuers.ToStringPluralForm('one of ')]));

      if (AIssuers.Size > 0) and not AIssuers.Contains(LIssuer) then
          Exit(Format('Issuer [iss] claim value [%s] doesn''t match expected value of [%s]',
            [LIssuer, AIssuers.ToStringPluralForm('one of ')]));
    end
  ;
end;

class function TJOSEClaimsValidators.jtiValidator(const AJwtId: string; ARequired: Boolean): TJOSEValidator;
begin
  Result :=
    function (AJOSEContext: TJOSEContext): string
    var
      LJWTId: string;
    begin
      Result := '';
      LJWTId := AJOSEContext.GetClaims.JWTId;

      if not AJOSEContext.GetClaims.HasJWTId and ARequired then
        Exit('No JWT ID [jti] claim present.')
      else
      if not AJwtId.IsEmpty and not AJwtId.Equals(LJwtId) then
        Exit(Format(
          'JWT Id [jti] claim value [%s] doesn''t match expected value of [%s]',
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
      LSubject: string;
    begin
      Result := '';
      LSubject := AJOSEContext.GetClaims.Subject;

      if not AJOSEContext.GetClaims.HasSubject and ARequired then
        Exit('No Subject [sub] claim present')
      else
      if not ASubject.IsEmpty and not ASubject.Equals(LSubject) then
        Exit(Format(
          'Subject [sub] claim value [%s] doesn''t match expected value of [%s]',
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
