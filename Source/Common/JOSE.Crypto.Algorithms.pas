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

unit JOSE.Crypto.Algorithms;

{$I ..\JOSE.inc}

interface

uses
  System.SysUtils;

type
  THMACAlgorithm = (SHA256, SHA384, SHA512);
  THMACAlgorithmHelper = record helper for THMACAlgorithm
    procedure FromString(const AValue: string);
    function ToString: string;
  end;

{$IFDEF RSA_SIGNING}

  /// <summary>Declared algorithm in an X.509 SubjectPublicKeyInfo (PEM certificate).</summary>
  TJOSECertificatePublicKey = (RSA, EC);

  TRSAAlgorithm = (RS256, RS384, RS512);
  TRSAAlgorithmHelper = record helper for TRSAAlgorithm
    procedure FromString(const AValue: string);
    function ToString: string;
  end;

  TECDSAAlgorithm = (ES256, ES256K, ES384, ES512);
  TECDSAAlgorithmHelper = record helper for TECDSAAlgorithm
    procedure FromString(const AValue: string);
    function ToString: string;
  end;

{$ENDIF}

implementation

{$IFDEF RSA_SIGNING}
uses
  JOSE.Signing.Base;
{$ENDIF}

{ THMACAlgorithmHelper }

procedure THMACAlgorithmHelper.FromString(const AValue: string);
begin
  if AValue = 'SHA256' then
    Self := SHA256
  else if AValue = 'SHA384' then
    Self := SHA384
  else if AValue = 'SHA512' then
    Self := SHA512
  else
    raise Exception.Create('Invalid HMAC algorithm type');
end;

function THMACAlgorithmHelper.ToString: string;
begin
  case Self of
    SHA256: Result := 'SHA256';
    SHA384: Result := 'SHA384';
    SHA512: Result := 'SHA512';
  end;
end;

{$IFDEF RSA_SIGNING}

{ TRSAAlgorithmHelper }

procedure TRSAAlgorithmHelper.FromString(const AValue: string);
begin
  if AValue = 'RS256' then
    Self := RS256
  else if AValue = 'RS384' then
    Self := RS384
  else if AValue = 'RS512' then
    Self := RS512
  else
    raise Exception.Create('Invalid RSA algorithm type');
end;

function TRSAAlgorithmHelper.ToString: string;
begin
  Result := '';
  case Self of
    RS256: Result := 'RS256';
    RS384: Result := 'RS384';
    RS512: Result := 'RS512';
  end;
end;

{ TECDSAAlgorithmHelper }

procedure TECDSAAlgorithmHelper.FromString(const AValue: string);
begin
  if AValue = 'ES256' then
    Self := ES256
  else if AValue = 'ES256K' then
    Self := ES256K
  else if AValue = 'ES384' then
    Self := ES384
  else if AValue = 'ES512' then
    Self := ES512
  else
    raise ESignException.Create('Invalid ECDSA algorithm type');
end;

function TECDSAAlgorithmHelper.ToString: string;
begin
  case Self of
    ES256: Result := 'ES256';
    ES256K: Result := 'ES256K';
    ES384: Result := 'ES384';
    ES512: Result := 'ES512';
  end;
end;

{$ENDIF}

end.
