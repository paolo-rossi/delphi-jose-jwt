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

unit JOSE.Signing.Base;

{$I ..\JOSE.inc}

interface

{$IFDEF RSA_SIGNING}

uses
  System.SysUtils,
  JOSE.Crypto.Algorithms;

type
  ESignException = class(Exception);

  TSigningBase = class
  public
    class function PublicKeyFromCertificate(const ACertificate: TBytes): TBytes;
    class function VerifyCertificate(const ACertificate: TBytes; AExpected: TJOSECertificatePublicKey): Boolean;
  end;

{$ENDIF}

implementation

{$IFDEF RSA_SIGNING}

uses
  JOSE.Providers;

class function TSigningBase.PublicKeyFromCertificate(const ACertificate: TBytes): TBytes;
begin
  Result := TJOSEProviders.Certificate.PublicKeyFromCertificate(ACertificate);
end;

class function TSigningBase.VerifyCertificate(const ACertificate: TBytes; AExpected: TJOSECertificatePublicKey): Boolean;
begin
  Result := TJOSEProviders.Certificate.VerifyCertificate(ACertificate, AExpected);
end;

{$ENDIF}

end.
