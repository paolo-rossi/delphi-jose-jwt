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

/// <summary>
///   JSON Web Key (JWK) RFC implementation (partial)
/// </summary>
/// <seealso href="https://tools.ietf.org/html/rfc7517">
///   JWK RFC Document
/// </seealso>
unit JOSE.Core.JWK;

interface

uses
  System.SysUtils,
  JOSE.Types.Bytes,
  JOSE.Core.Base,
  JOSE.Encoding.Base64;

type
  /// <summary>
  ///   Base class for the Key in a JWS process
  /// </summary>
  TJWK = class(TJOSEBase)
  private
    FKey: TJOSEBytes;
  public
    constructor Create(AKey: TJOSEBytes); overload;
    property Key: TJOSEBytes read FKey write FKey;
  end;

  /// <summary>
  ///   KeyPair utility class (to move in a key management framework)
  /// </summary>
  TKeyPair = class
  private
    FPrivateKey: TJWK;
    FPublicKey: TJWK;
  public
    constructor Create; overload;
    constructor Create(const APublicKey, APrivateKey: TJOSEBytes); overload;
    destructor Destroy; override;

    procedure SetSymmetricKey(const ASecret: TJOSEBytes);
    procedure SetAsymmetricKeys(const APublicKey, APrivateKey: TJOSEBytes);

    property PrivateKey: TJWK read FPrivateKey write FPrivateKey;
    property PublicKey: TJWK read FPublicKey write FPublicKey;
  end;

implementation

{ TJWK }

constructor TJWK.Create(AKey: TJOSEBytes);
begin
  inherited Create;
  FKey := AKey;
end;

{ TKeyPair }

constructor TKeyPair.Create;
begin
  FPrivateKey := TJWK.Create();
  FPublicKey := TJWK.Create();
end;

constructor TKeyPair.Create(const APublicKey, APrivateKey: TJOSEBytes);
begin
  FPublicKey := TJWK.Create(APublicKey);
  FPrivateKey := TJWK.Create(APrivateKey);
end;

destructor TKeyPair.Destroy;
begin
  FPublicKey.Free;
  FPrivateKey.Free;
  inherited;
end;

procedure TKeyPair.SetAsymmetricKeys(const APublicKey, APrivateKey: TJOSEBytes);
begin
  FPublicKey.Key := APublicKey;
  FPrivateKey.Key := APrivateKey;
end;

procedure TKeyPair.SetSymmetricKey(const ASecret: TJOSEBytes);
begin
  FPublicKey.Key := ASecret;
  FPrivateKey.Key := ASecret;
end;

end.
