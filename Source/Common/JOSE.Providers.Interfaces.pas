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

unit JOSE.Providers.Interfaces;

{$I ..\JOSE.inc}

interface

uses
  System.SysUtils,
  JOSE.Types.Bytes,
  JOSE.Crypto.Algorithms;

type
  IJOSEBase64Provider = interface
    ['{8F2E9C1D-4A3B-4E5F-9D8C-7B6A50413210}']
    function Encode(const ASource: TJOSEBytes): TJOSEBytes;
    function Decode(const ASource: TJOSEBytes): TJOSEBytes;
    function TryDecode(const ASource: TJOSEBytes): TJOSEBytes;
    function URLEncode(const ASource: TJOSEBytes): TJOSEBytes;
    function URLDecode(const ASource: TJOSEBytes): TJOSEBytes;
    function TryURLDecode(const ASource: TJOSEBytes): TJOSEBytes;
  end;

  IJOSEHmacProvider = interface
    ['{7D1C8B2E-5F4A-4D3C-8E9F-1029384756AB}']
    function Sign(const AInput, AKey: TBytes; AAlg: THMACAlgorithm): TBytes;
  end;

{$IFDEF RSA_SIGNING}

  IJOSECertificateProvider = interface
    ['{6E0B7A3D-2C1F-4E5D-9A8B-7C6D5E4F3021}']
    function PublicKeyFromCertificate(const ACertificate: TBytes): TBytes;
    function VerifyCertificate(const ACertificate: TBytes; AExpected: TJOSECertificatePublicKey): Boolean;
  end;

  IJOSESignerRSA = interface
    ['{5D9C8B1E-3A2F-4D5C-8B7A-6C5D4E3F2010}']
    function Sign(const AInput, AKey: TBytes; AAlg: TRSAAlgorithm): TBytes;
    function Verify(const AInput, ASignature, AKey: TBytes; AAlg: TRSAAlgorithm): Boolean;
    function VerifyWithCertificate(const AInput, ASignature, ACertificate: TBytes; AAlg: TRSAAlgorithm): Boolean;
    function VerifyPublicKey(const AKey: TBytes): Boolean;
    function VerifyPrivateKey(const AKey: TBytes): Boolean;
  end;

  IJOSESignerECDSA = interface
    ['{4C8B7A2D-1E0F-4C3B-7A6C-5B4D3E2F1098}']
    function Sign(const AInput, APrivateKey: TBytes; AAlg: TECDSAAlgorithm): TBytes;
    function Verify(const AInput, ASignature, APublicKey: TBytes; AAlg: TECDSAAlgorithm): Boolean;
    function VerifyWithCertificate(const AInput, ASignature, ACertificate: TBytes; AAlg: TECDSAAlgorithm): Boolean;
    function VerifyPublicKey(const AKey: TBytes): Boolean;
    function VerifyPrivateKey(const AKey: TBytes): Boolean;
  end;

{$ENDIF}

implementation

end.
