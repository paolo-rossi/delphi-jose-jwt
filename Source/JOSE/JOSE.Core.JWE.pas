{******************************************************************************}
{                                                                              }
{  Delphi JOSE Library                                                         }
{  Copyright (c) 2015-2021 Paolo Rossi                                         }
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

unit JOSE.Core.JWE;

interface

uses
  System.SysUtils,
  JOSE.Types.Bytes,
  JOSE.Core.Base,
  JOSE.Core.Parts,
  JOSE.Core.JWA,
  JOSE.Core.JWA.Factory,
  JOSE.Core.JWK,
  JOSE.Core.JWT,
  JOSE.Encoding.Base64,
  JOSE.Encryption.RSA;

type
  /// <summary>
  ///   JSON Web Encryption (JWE) RFC implementation (initial)
  /// </summary>
  /// <seealso href="https://tools.ietf.org/html/rfc7516">
  ///   JWE RFC Document
  /// </seealso>
  TJWE = class(TJOSEParts)
  private
    const COMPACT_PARTS = 5;
  private
    function GetPart(Index: Integer): TJOSEBytes;
    procedure SetPart(Index: Integer; const Value: TJOSEBytes);
  public
    constructor Create(AToken: TJWT); override;
    function Encrypt(AKey: TJWK; AAlg, AEncryptionAlg: TJOSEAlgorithmId): string;
    //class function Decrypt(AKey: TJWK; AInput: TBytes): Boolean;
    function GetCompactToken: TJOSEBytes; override;

    property Header: TJOSEBytes index 0 read GetPart write SetPart;
    property EncryptedKey: TJOSEBytes index 1 read GetPart write SetPart;
    property IV: TJOSEBytes index 2 read GetPart write SetPart;
    property CipherText: TJOSEBytes index 3 read GetPart write SetPart;
    property AuthenticationTag: TJOSEBytes index 4 read GetPart write SetPart;
  end;
implementation

{ TJWEParts }

constructor TJWE.Create(AToken: TJWT);
var
  LIndex: Integer;
begin
  inherited Create(AToken);

  for LIndex := 0 to COMPACT_PARTS - 1 do
    FParts.Add(TJOSEBytes.Empty);
end;

function TJWE.GetPart(Index: Integer): TJOSEBytes;
begin
  if (Index >= 0) and (Index < COMPACT_PARTS) then
    Result := FParts[Index]
  else
    Result := nil;
end;

procedure TJWE.SetPart(Index: Integer; const Value: TJOSEBytes);
begin
  if (Index >= 0) and (Index < COMPACT_PARTS) then
    FParts[Index] := Value;
end;

function TJWE.Encrypt(AKey: TJWK; AAlg, AEncryptionAlg: TJOSEAlgorithmId): string;
begin

  // Set headers
  SetHeaderAlgorithm(AAlg);
  FToken.Header.SetHeaderParamOfType<string>('enc', AEncryptionAlg.AsString);

  Header := TBase64.URLEncode(ToJSON(FToken.Header.JSON));

  var CEK := TJOSEBytes.RandomBytes(AEncryptionAlg.Length div 8);
  EncryptedKey := TBase64.URLEncode(TRSAEncryption.EncryptWithPublicCertificate(AKey.Key, CEK));

  var Payload : TJOSEBytes := ToJSON(FToken.Claims.JSON);
  var Parts := TJOSEAlgorithmRegistryFactory.Instance.EncryptionAlgorithmRegistry.GetAlgorithm(AEncryptionAlg.AsString).Encrypt(Payload, Header, CEK, nil);
  IV := TBase64.URLEncode(Parts.Iv);
  CipherText := TBase64.URLEncode(Parts.Ciphertext);
  AuthenticationTag := TBase64.URLEncode(Parts.AuthenticationTag);

  Result := GetCompactToken;

end;

function TJWE.GetCompactToken: TJOSEBytes;
begin
  Result := Header + PART_SEPARATOR + EncryptedKey + PART_SEPARATOR + IV + PART_SEPARATOR + CipherText + PART_SEPARATOR + AuthenticationTag;
end;

end.
