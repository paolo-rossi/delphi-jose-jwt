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

unit JOSE.Signing.Base;

interface

uses
  System.SysUtils,
  System.StrUtils,
  IdGlobal, IdCTypes,
  IdSSLOpenSSLHeaders,
  JOSE.OpenSSL.Headers,
  JOSE.Encoding.Base64;

type
  ESignException = class(Exception);

  TSigningBase = class
  protected //CERT
    const PEM_X509_CERTIFICATE: RawByteString = '-----BEGIN CERTIFICATE-----';
  protected //RSA
    const PEM_PUBKEY_PKCS1: RawByteString = '-----BEGIN RSA PUBLIC KEY-----';
  protected  //ECDSA
    const PEM_PUBKEY: RawByteString = '-----BEGIN PUBLIC KEY-----';
    const PEM_PRVKEY_PKCS8: RawByteString = '-----BEGIN PRIVATE KEY-----';
    const PEM_PRVKEY_PKCS1: RawByteString = '-----BEGIN EC PRIVATE KEY-----';

    class function LoadCertificate(const ACertificate: TBytes): PX509;
  public
    class procedure LoadOpenSSL;

    class function VerifyCertificate(const ACertificate: TBytes; AObjectID: Integer): Boolean;
  end;


implementation

class function TSigningBase.LoadCertificate(const ACertificate: TBytes): PX509;
var
  LBio: PBIO;
begin
  if not CompareMem(@PEM_X509_CERTIFICATE[1], @ACertificate[0], Length(PEM_X509_CERTIFICATE)) then
    raise ESignException.Create('[SSL] Not a valid X509 certificate');

  LBio := BIO_new(BIO_s_mem);
  try
    BIO_write(LBio, @ACertificate[0], Length(ACertificate));
    Result := PEM_read_bio_X509(LBio, nil, nil, nil);
    if Result = nil then
      raise ESignException.Create('[SSL] Error loading X509 certificate');
  finally
    BIO_free(LBio);
  end;
end;

class procedure TSigningBase.LoadOpenSSL;
begin
  if not IdSSLOpenSSLHeaders.Load then
    raise ESignException.Create('[SSL] Unable to load OpenSSL libraries');

  if not JoseSSL.Load then
    raise ESignException.Create('[SSL] Unable to load OpenSSL libraries');

  if @EVP_DigestVerifyInit = nil then
    raise ESignException.Create('[SSL] Please, use OpenSSL 1.0.0 or newer!');
end;

class function TSigningBase.VerifyCertificate(const ACertificate: TBytes; AObjectID: Integer): Boolean;
var
  LCer: PX509;
  LKey: PEVP_PKEY;
  LAlg: Integer;
begin
  LoadOpenSSL;

  LCer := LoadCertificate(ACertificate);
  try
    LKey := X509_PUBKEY_get(LCer.cert_info.key);
    try
      LAlg := OBJ_obj2nid(LCer.cert_info.key.algor.algorithm);
      Result := Assigned(LCer) and Assigned(LKey) and (LAlg = AObjectID);
    finally
      EVP_PKEY_free(LKey);
    end;
  finally
    X509_free(LCer);
  end;
end;

end.
