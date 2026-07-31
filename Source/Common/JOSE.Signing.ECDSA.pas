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

unit JOSE.Signing.ECDSA;

{$I ..\JOSE.inc}

interface

{$IFDEF RSA_SIGNING}

uses
  System.SysUtils,
  JOSE.Crypto.Algorithms,
  JOSE.Signing.Base;

type
  TECDSAAlgorithm = JOSE.Crypto.Algorithms.TECDSAAlgorithm;
  TECDSAAlgorithmHelper = JOSE.Crypto.Algorithms.TECDSAAlgorithmHelper;

  TECDSA = class(TSigningBase)
  public
    class function Sign(const AInput, APrivateKey: TBytes; AAlg: TECDSAAlgorithm): TBytes;
    class function Verify(const AInput, ASignature, APublicKey: TBytes; AAlg: TECDSAAlgorithm): Boolean;
    class function VerifyWithCertificate(const AInput, ASignature, ACertificate: TBytes; AAlg: TECDSAAlgorithm): Boolean;

    class function VerifyPublicKey(const AKey: TBytes): Boolean;
    class function VerifyPrivateKey(const AKey: TBytes): Boolean;
  end;

{$ENDIF}

implementation

{$IFDEF RSA_SIGNING}

uses
  JOSE.Providers;

{ TECDSA }

class function TECDSA.Sign(const AInput, APrivateKey: TBytes; AAlg: TECDSAAlgorithm): TBytes;
begin
  Result := TJOSEProviders.ECDSA.Sign(AInput, APrivateKey, AAlg);
end;

class function TECDSA.Verify(const AInput, ASignature, APublicKey: TBytes; AAlg: TECDSAAlgorithm): Boolean;
begin
  Result := TJOSEProviders.ECDSA.Verify(AInput, ASignature, APublicKey, AAlg);
end;

class function TECDSA.VerifyPrivateKey(const AKey: TBytes): Boolean;
begin
  Result := TJOSEProviders.ECDSA.VerifyPrivateKey(AKey);
end;

class function TECDSA.VerifyPublicKey(const AKey: TBytes): Boolean;
begin
  Result := TJOSEProviders.ECDSA.VerifyPublicKey(AKey);
end;

class function TECDSA.VerifyWithCertificate(const AInput, ASignature, ACertificate: TBytes; AAlg: TECDSAAlgorithm): Boolean;
begin
  Result := TJOSEProviders.ECDSA.VerifyWithCertificate(AInput, ASignature, ACertificate, AAlg);
end;

{$ENDIF}

end.
