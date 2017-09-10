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
///   Utility class to encode and decode a JWT
/// </summary>
unit JOSE.Core.Builder;

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
  TJOSE = class
  private
    class function DeserializeVerify(AKey: TJWK; ACompactToken: TJOSEBytes; AVerify: Boolean; AClaimsClass: TJWTClaimsClass): TJWT;
  public
    class function Sign(AKey: TJWK; AAlg: TJOSEAlgorithmId; AToken: TJWT): TJOSEBytes;
    class function Verify(AKey: TJWK; ACompactToken: TJOSEBytes; AClaimsClass: TJWTClaimsClass = nil): TJWT;

    class function SerializeCompact(AKey: TJWK; AAlg: TJOSEAlgorithmId; AToken: TJWT): TJOSEBytes; overload;
    class function SerializeCompact(AKey: TJOSEBytes; AAlg: TJOSEAlgorithmId; AToken: TJWT): TJOSEBytes; overload;
    class function DeserializeCompact(const ACompactToken: TJOSEBytes): TJWT;

    class function SHA256CompactToken(AKey: TJOSEBytes; AToken: TJWT): TJOSEBytes;
  end;


implementation

uses
  System.Types,
  System.StrUtils;

{ TJOSE }

class function TJOSE.DeserializeCompact(const ACompactToken: TJOSEBytes): TJWT;
begin
  Result := DeserializeVerify(nil, ACompactToken, True, TJWTClaims);
end;

class function TJOSE.DeserializeVerify(AKey: TJWK; ACompactToken: TJOSEBytes;
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
          LSigner.SetKey(AKey);
          LSigner.CompactToken := ACompactToken;
          if AVerify then
            LSigner.VerifySignature
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
var
  LSigner: TJWS;
begin
  LSigner := TJWS.Create(AToken);
  try
    LSigner.Sign(AKey, AAlg);
    Result := LSigner.CompactToken;
  finally
    LSigner.Free;
  end;
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

class function TJOSE.SerializeCompact(AKey: TJOSEBytes; AAlg: TJOSEAlgorithmId;
  AToken: TJWT): TJOSEBytes;
var
  LKey: TJWK;
begin
  LKey := TJWK.Create(AKey);
  try
    Result := SerializeCompact(LKey, AAlg, AToken);
  finally
    LKey.Free;
  end;
end;

class function TJOSE.SHA256CompactToken(AKey: TJOSEBytes; AToken: TJWT): TJOSEBytes;
var
  LSigner: TJWS;
  LKey: TJWK;
begin
  LSigner := TJWS.Create(AToken);
  LSigner.SkipKeyValidation := True;
  LKey := TJWK.Create(AKey);
  try
    LSigner.Sign(LKey, TJOSEAlgorithmId.HS256);
    Result := LSigner.CompactToken;
  finally
    LKey.Free;
    LSigner.Free;
  end;
end;

class function TJOSE.Verify(AKey: TJWK; ACompactToken: TJOSEBytes; AClaimsClass: TJWTClaimsClass): TJWT;
begin
  if not Assigned(AClaimsClass) then
    AClaimsClass := TJWTClaims;

  Result := DeserializeVerify(AKey, ACompactToken, True, AClaimsClass);
end;

end.
