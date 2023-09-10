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
unit JOSE.Core.Builder;

{$I ..\JOSE.inc}

interface

uses
  System.SysUtils,
  JOSE.Types.Bytes,
  JOSE.Core.Base,
  JOSE.Core.Parts,
  JOSE.Core.JWA,
  JOSE.Core.JWK,
  JOSE.Core.JWT,
  JOSE.Core.JWS,
  JOSE.Core.JWE;

type
  /// <summary>
  ///   Utility class to encode and decode a JWT
  /// </summary>
  TJOSE = class
  private
    class function DeserializeVerify(AKey: TJWK; const ACompactToken: TJOSEBytes; AVerify: Boolean; AClaimsClass: TJWTClaimsClass): TJWT;
  public
    class function CheckCompactToken(const AValue: TJOSEBytes): Boolean; static;

    class function Sign(AKey: TJWK; AAlg: TJOSEAlgorithmId; AToken: TJWT): TJOSEBytes;
    class function Verify(AKey: TJWK; const ACompactToken: TJOSEBytes; AClaimsClass: TJWTClaimsClass = nil): TJWT; overload;
    class function Verify(AKey: TJOSEBytes; const ACompactToken: TJOSEBytes; AClaimsClass: TJWTClaimsClass = nil): TJWT; overload;

    class function SerializeCompact(AKey: TJWK; AAlg: TJOSEAlgorithmId; AToken: TJWT; ASkipValidation: Boolean): TJOSEBytes; overload;
    class function SerializeCompact(AKey: TJWK; AAlg: TJOSEAlgorithmId; AToken: TJWT): TJOSEBytes; overload;
    class function SerializeCompact(AKey: TJOSEBytes; AAlg: TJOSEAlgorithmId; AToken: TJWT): TJOSEBytes; overload;

    class function DeserializeCompact(AKey: TJWK; const ACompactToken: TJOSEBytes): TJWT; overload;
    class function DeserializeCompact(AKey: TJOSEBytes; const ACompactToken: TJOSEBytes): TJWT; overload;

    class function DeserializeOnly(const ACompactToken: TJOSEBytes; AClaimsClass: TJWTClaimsClass = nil): TJWT; overload;

    class function SHA256CompactToken(AKey: TJOSEBytes; AToken: TJWT): TJOSEBytes;
    class function SHA284CompactToken(AKey: TJOSEBytes; AToken: TJWT): TJOSEBytes;
    class function SHA512CompactToken(AKey: TJOSEBytes; AToken: TJWT): TJOSEBytes;
  end;

implementation

uses
  System.Types,
  System.StrUtils;

{ TJOSE }

class function TJOSE.CheckCompactToken(const AValue: TJOSEBytes): Boolean;
begin
  Result := TJWS.CheckCompactToken(AValue);
end;

class function TJOSE.DeserializeCompact(AKey: TJOSEBytes; const ACompactToken: TJOSEBytes): TJWT;
var
  LKey: TJWK;
begin
  LKey := TJWK.Create(AKey);
  try
    Result := DeserializeVerify(LKey, ACompactToken, True, TJWTClaims);
  finally
    LKey.Free;
  end;
end;

class function TJOSE.DeserializeOnly(const ACompactToken: TJOSEBytes; AClaimsClass: TJWTClaimsClass): TJWT;
begin
  Result := DeserializeVerify(nil, ACompactToken, False, AClaimsClass);
end;

class function TJOSE.DeserializeCompact(AKey: TJWK; const ACompactToken: TJOSEBytes): TJWT;
begin
  Result := DeserializeVerify(AKey, ACompactToken, True, TJWTClaims);
end;

class function TJOSE.DeserializeVerify(AKey: TJWK; const ACompactToken: TJOSEBytes;
    AVerify: Boolean; AClaimsClass: TJWTClaimsClass): TJWT;
var
  LRes: TStringDynArray;
  LSigner: TJWS;
begin
  Result := nil;
  LRes := SplitString(ACompactToken, PART_SEPARATOR);

  case Length(LRes) of
    3:
    begin
      Result := TJWT.Create(AClaimsClass);
      try
        LSigner := TJWS.Create(Result);
        LSigner.SkipKeyValidation := True;
        try
          LSigner.CompactToken := ACompactToken;
          if AVerify then
          begin
            LSigner.SetKey(AKey);
            LSigner.VerifySignature;
          end;
        finally
          LSigner.Free;
        end;
      except
        FreeAndNil(Result);
      end;
    end;
    5:
    begin
      raise EJOSEException.Create('Compact Serialization appears to be a JWE Token wich is not (yet) supported');
    end;
    else
      raise EJOSEException.Create('Malformed Compact Serialization');
  end
end;

class function TJOSE.SerializeCompact(AKey: TJWK; AAlg: TJOSEAlgorithmId; AToken: TJWT): TJOSEBytes;
begin
  Result := SerializeCompact(AKey, AAlg, AToken, True);
end;

class function TJOSE.Sign(AKey: TJWK; AAlg: TJOSEAlgorithmId; AToken: TJWT): TJOSEBytes;
var
  LSigner: TJWS;
begin
  LSigner := TJWS.Create(AToken);
  try
    Result := LSigner.Sign(AKey, AAlg);
  finally
    LSigner.Free;
  end;
end;

class function TJOSE.SerializeCompact(AKey: TJOSEBytes; AAlg: TJOSEAlgorithmId; AToken: TJWT): TJOSEBytes;
var
  LKey: TJWK;
begin
  LKey := TJWK.Create(AKey);
  try
    Result := SerializeCompact(LKey, AAlg, AToken, True);
  finally
    LKey.Free;
  end;
end;

class function TJOSE.SerializeCompact(AKey: TJWK; AAlg: TJOSEAlgorithmId; AToken: TJWT;
  ASkipValidation: Boolean): TJOSEBytes;
var
  LSigner: TJWS;
begin
  LSigner := TJWS.Create(AToken);
  try
    LSigner.SkipKeyValidation := ASkipValidation;
    LSigner.Sign(AKey, AAlg);
    Result := LSigner.CompactToken;
  finally
    LSigner.Free;
  end;
end;

class function TJOSE.SHA256CompactToken(AKey: TJOSEBytes; AToken: TJWT): TJOSEBytes;
begin
  Result := SerializeCompact(AKey, TJOSEAlgorithmId.HS256, AToken);
end;

class function TJOSE.SHA284CompactToken(AKey: TJOSEBytes; AToken: TJWT): TJOSEBytes;
begin
  Result := SerializeCompact(AKey, TJOSEAlgorithmId.HS384, AToken);
end;

class function TJOSE.SHA512CompactToken(AKey: TJOSEBytes; AToken: TJWT): TJOSEBytes;
begin
  Result := SerializeCompact(AKey, TJOSEAlgorithmId.HS512, AToken);
end;

class function TJOSE.Verify(AKey: TJWK; const ACompactToken: TJOSEBytes; AClaimsClass: TJWTClaimsClass): TJWT;
begin
  if not Assigned(AClaimsClass) then
    AClaimsClass := TJWTClaims;

  Result := DeserializeVerify(AKey, ACompactToken, True, AClaimsClass);
end;

class function TJOSE.Verify(AKey: TJOSEBytes; const ACompactToken: TJOSEBytes;
  AClaimsClass: TJWTClaimsClass): TJWT;
var
  LKey: TJWK;
begin
  LKey := TJWK.Create(AKey);
  try
    Result := Verify(LKey, ACompactToken, AClaimsClass);
  finally
    LKey.Free;
  end;
end;

end.
