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
///   JSON Web Algorithms (JWA) RFC implementation (partial) <br />
/// </summary>
/// <seealso href="https://tools.ietf.org/html/rfc7518">
///   JWA RFC Document
/// </seealso>
unit JOSE.Core.JWA.Factory;

{$I ..\JOSE.inc}

interface

uses
  System.SysUtils,
  System.Generics.Defaults,
  System.Generics.Collections,
  JOSE.Types.Bytes,
  JOSE.Core.JWA,
  JOSE.Core.JWA.Signing,
  JOSE.Core.JWA.Compression,
  JOSE.Core.JWA.Encryption;

type
  TJOSEAlgorithmRegistry<T: IJOSEAlgorithm> = class
  private
    FName: string;
    FAlgorithms: TDictionary<string, T>;
  public
    constructor Create(const AName: string);
    destructor Destroy; override;

    function GetAlgorithm(AAlgorithmIdentifier: string): T;

    function RegisterAlgorithm(AAlgorithm: T): TJOSEAlgorithmRegistry<T>;
    procedure UnregisterAlgorithm(AAlgId: string); overload;
    procedure UnregisterAlgorithm(AAlgId: TJOSEAlgorithmId); overload;
  end;

  TJOSEAlgorithmRegistryFactory = class
  private class var
    FInstance: TJOSEAlgorithmRegistryFactory;
  private
    FSigningAlgorithmRegistry: TJOSEAlgorithmRegistry<IJOSESigningAlgorithm>;
    FEncryptionAlgorithmRegistry: TJOSEAlgorithmRegistry<IJOSEEncryptionAlgorithm>;
    FCompressionAlgorithmRegistry: TJOSEAlgorithmRegistry<IJOSECompressionAlgorithm>;

    constructor Create;

    class function GetInstance: TJOSEAlgorithmRegistryFactory; static;
  public
    destructor Destroy; override;

    property SigningAlgorithmRegistry: TJOSEAlgorithmRegistry<IJOSESigningAlgorithm>
      read FSigningAlgorithmRegistry;
    property EncryptionAlgorithmRegistry: TJOSEAlgorithmRegistry<IJOSEEncryptionAlgorithm>
      read FEncryptionAlgorithmRegistry;
    property CompressionAlgorithmRegistry: TJOSEAlgorithmRegistry<IJOSECompressionAlgorithm>
      read FCompressionAlgorithmRegistry;

    class property Instance: TJOSEAlgorithmRegistryFactory read GetInstance;
  end;



implementation

{ TJOSEAlgorithmRegistry<T> }

constructor TJOSEAlgorithmRegistry<T>.Create(const AName: string);
begin
  FAlgorithms := TDictionary<string,T>.Create;
  FName := AName;
end;

destructor TJOSEAlgorithmRegistry<T>.Destroy;
begin
  FAlgorithms.Free;
  inherited;
end;

function TJOSEAlgorithmRegistry<T>.GetAlgorithm(AAlgorithmIdentifier: string): T;
begin
  FAlgorithms.TryGetValue(AAlgorithmIdentifier, Result);
end;

function TJOSEAlgorithmRegistry<T>.RegisterAlgorithm(AAlgorithm: T): TJOSEAlgorithmRegistry<T>;
begin
  FAlgorithms.Add(AAlgorithm.GetAlgorithmIdentifier.AsString, AAlgorithm);
  Result := Self;
end;

procedure TJOSEAlgorithmRegistry<T>.UnregisterAlgorithm(AAlgId: string);
begin
  FAlgorithms.Remove(AAlgId);
end;

procedure TJOSEAlgorithmRegistry<T>.UnregisterAlgorithm(AAlgId: TJOSEAlgorithmId);
begin
  UnregisterAlgorithm(AAlgId.AsString);
end;

{ TJOSEAlgorithmRegistryFactory }

constructor TJOSEAlgorithmRegistryFactory.Create;
begin
  FSigningAlgorithmRegistry := TJOSEAlgorithmRegistry<IJOSESigningAlgorithm>.Create('alg');

  FSigningAlgorithmRegistry
    .RegisterAlgorithm(THmacUsingShaAlgorithm.HmacSha256)
    .RegisterAlgorithm(THmacUsingShaAlgorithm.HmacSha384)
    .RegisterAlgorithm(THmacUsingShaAlgorithm.HmacSha512)

{$IFDEF RSA_SIGNING}
    .RegisterAlgorithm(TRSAUsingShaAlgorithm.RSA256)
    .RegisterAlgorithm(TRSAUsingShaAlgorithm.RSA384)
    .RegisterAlgorithm(TRSAUsingShaAlgorithm.RSA512)

    .RegisterAlgorithm(TECDSAUsingSHAAlgorithm.ECDSA256)
    .RegisterAlgorithm(TECDSAUsingSHAAlgorithm.ECDSA256K)
    .RegisterAlgorithm(TECDSAUsingSHAAlgorithm.ECDSA384)
    .RegisterAlgorithm(TECDSAUsingSHAAlgorithm.ECDSA512)
{$ENDIF}
  ;

  FEncryptionAlgorithmRegistry := TJOSEAlgorithmRegistry<IJOSEEncryptionAlgorithm>.Create('alg');

  FCompressionAlgorithmRegistry := TJOSEAlgorithmRegistry<IJOSECompressionAlgorithm>.Create('alg');
end;

destructor TJOSEAlgorithmRegistryFactory.Destroy;
begin
  FSigningAlgorithmRegistry.Free;
  FEncryptionAlgorithmRegistry.Free;
  FCompressionAlgorithmRegistry.Free;

  inherited;
end;

class function TJOSEAlgorithmRegistryFactory.GetInstance: TJOSEAlgorithmRegistryFactory;
begin
  if not Assigned(FInstance) then
    FInstance := TJOSEAlgorithmRegistryFactory.Create;
  Result := FInstance;
end;

initialization

finalization
  TJOSEAlgorithmRegistryFactory.FInstance.Free;

end.
