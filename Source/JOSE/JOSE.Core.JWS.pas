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
///   JSON Web Signature (JWS) RFC implementation (partial)
/// </summary>
/// <seealso href="https://tools.ietf.org/html/rfc7515">
///   JWS RFC Document
/// </seealso>
unit JOSE.Core.JWS;

interface

uses
  System.SysUtils,
  JOSE.Types.Bytes,
  JOSE.Core.Base,
  JOSE.Core.Parts,
  JOSE.Core.JWA,
  JOSE.Core.JWK,
  JOSE.Core.JWT;

type
  TJWS = class(TJOSEParts)
  private
    const COMPACT_PARTS = 3;

    function GetSigningInput: TJOSEBytes;
    function GetHeader: TJOSEBytes;
    function GetPayload: TJOSEBytes;
    function GetSignature: TJOSEBytes;
    procedure SetHeader(const Value: TJOSEBytes);
    procedure SetPayload(const Value: TJOSEBytes);
    procedure SetSignature(const Value: TJOSEBytes);
  protected
    function GetCompactToken: TJOSEBytes; override;
    procedure SetCompactToken(const Value: TJOSEBytes); override;
  public
    constructor Create(AToken: TJWT); override;

    function Sign(AKey: TJWK; AAlg: TJWAEnum): TJOSEBytes;
    procedure Verify(AKey: TJWK; const ACompactToken: TJOSEBytes);

    property Header: TJOSEBytes read GetHeader write SetHeader;
    property Payload: TJOSEBytes read GetPayload write SetPayload;
    property Signature: TJOSEBytes read GetSignature write SetSignature;
    property SigningInput: TJOSEBytes read GetSigningInput;
  end;

implementation

uses
  System.Types,
  System.StrUtils,
  JOSE.Encoding.Base64,
  JOSE.Hashing.HMAC;

constructor TJWS.Create(AToken: TJWT);
var
  LIndex: Integer;
begin
  inherited Create(AToken);

  for LIndex := 0 to COMPACT_PARTS - 1 do
    FParts.Add(TJOSEBytes.Empty);
end;

function TJWS.GetCompactToken: TJOSEBytes;
begin
  Result := Header + PART_SEPARATOR + Payload + PART_SEPARATOR + Signature;
end;

function TJWS.GetHeader: TJOSEBytes;
begin
  Result := FParts[0]
end;

function TJWS.GetPayload: TJOSEBytes;
begin
  Result := FParts[1];
end;

function TJWS.GetSignature: TJOSEBytes;
begin
  Result := FParts[2];
end;

function TJWS.GetSigningInput: TJOSEBytes;
begin
  Result := Header + PART_SEPARATOR + Payload;
end;

procedure TJWS.SetCompactToken(const Value: TJOSEBytes);
var
  LRes: TStringDynArray;
begin
  LRes := SplitString(Value, PART_SEPARATOR);
  if Length(LRes) = COMPACT_PARTS then
  begin
    FParts[0] := LRes[0];
    FParts[1] := LRes[1];
    FParts[2] := LRes[2];

    FToken.Header.URLEncoded := LRes[0];
    FToken.Claims.URLEncoded := LRes[1];
  end
  else
    raise EJOSEException.CreateFmt('A JWS Compact Serialization must have %d parts', [COMPACT_PARTS]);
end;

procedure TJWS.SetHeader(const Value: TJOSEBytes);
begin
  FParts[0] := Value;
end;

procedure TJWS.SetPayload(const Value: TJOSEBytes);
begin
  FParts[1] := Value;
end;

procedure TJWS.SetSignature(const Value: TJOSEBytes);
begin
  FParts[2] := Value;
end;

function TJWS.Sign(AKey: TJWK; AAlg: TJWAEnum): TJOSEBytes;
var
  LSign: TJOSEBytes;
begin
  Empty;

  if FToken.Header.Algorithm <> AAlg.AsString then
    FToken.Header.Algorithm := AAlg.AsString;

  Header := TBase64.URLEncode(ToJSON(FToken.Header.JSON));
  Payload := TBase64.URLEncode(ToJSON(FToken.Claims.JSON));

  case AAlg of
    None:  LSign.Clear;
    HS256: LSign := THMAC.Sign(SigningInput, AKey.Key, SHA256);
    HS384: LSign := THMAC.Sign(SigningInput, AKey.Key, SHA384);
    HS512: LSign := THMAC.Sign(SigningInput, AKey.Key, SHA512);
  else
    raise EJOSEException.Create('Signing algorithm not supported');
  end;
  Signature := TBase64.URLEncode(LSign.AsBytes);

  Result := Signature;
end;

procedure TJWS.Verify(AKey: TJWK; const ACompactToken: TJOSEBytes);
var
  LExpectedSign: TJOSEBytes;
  LAlg: TJWAEnum;
begin
  CompactToken := ACompactToken;

  LAlg.AsString := FToken.Header.Algorithm;
  case LAlg of
    None : FToken.Verified := AKey.Key.IsEmpty;
    HS256: LExpectedSign := THMAC.Sign(SigningInput, AKey.Key, SHA256);
    HS384: LExpectedSign := THMAC.Sign(SigningInput, AKey.Key, SHA384);
    HS512: LExpectedSign := THMAC.Sign(SigningInput, AKey.Key, SHA512);
  else
    raise EJOSEException.Create('Signing algorithm not supported');
  end;

  if LAlg <> None then
  begin
    LExpectedSign := TBase64.URLEncode(LExpectedSign);
    if LExpectedSign = Signature then
      FToken.Verified := True;
  end;
end;

end.
