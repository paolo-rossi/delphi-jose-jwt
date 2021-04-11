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
    class function LoadPublicKeyFromCert(const ACertificate: TBytes): PEVP_PKEY; overload;
    class function LoadPublicKeyFromCert(const ACertificate: TBytes; AAlgID: Integer): PEVP_PKEY; overload;
  public
    class procedure LoadOpenSSL;

    class function PublicKeyFromCertificate(const ACertificate: TBytes): TBytes;
    class function VerifyCertificate(const ACertificate: TBytes; AObjectID: Integer): Boolean;
  end;


implementation

uses
  JOSE.Types.Utils;

class function TSigningBase.LoadCertificate(const ACertificate: TBytes): PX509;
var
  LBio: PBIO;
begin
  if not CompareMem(@PEM_X509_CERTIFICATE[1], @ACertificate[0], Length(PEM_X509_CERTIFICATE)) then
    raise ESignException.Create('[OpenSSL] Not a valid X509 certificate');

  LBio := BIO_new(BIO_s_mem);
  try
    BIO_write(LBio, @ACertificate[0], Length(ACertificate));
    Result := PEM_read_bio_X509(LBio, nil, nil, nil);
    if Result = nil then
      raise ESignException.Create('[OpenSSL] Error loading X509 certificate');
  finally
    BIO_free(LBio);
  end;
end;

class procedure TSigningBase.LoadOpenSSL;
begin
  if not IdSSLOpenSSLHeaders.Load then
    raise ESignException.Create('[OpenSSL] Unable to load OpenSSL libraries');

  if not JoseSSL.Load then
    raise ESignException.Create('[OpenSSL] Unable to load OpenSSL libraries');

  if @EVP_DigestVerifyInit = nil then
    raise ESignException.Create('[OpenSSL] Please, use OpenSSL 1.0.0 or newer!');
end;

class function TSigningBase.LoadPublicKeyFromCert(const ACertificate: TBytes; AAlgID: Integer): PEVP_PKEY;
var
  LCer: PX509;
  LAlg: Integer;
begin
  LoadOpenSSL;

  LCer := LoadCertificate(ACertificate);
  try
    LAlg := OBJ_obj2nid(LCer.cert_info.key.algor.algorithm);
    if LAlg <> AAlgID then
      raise ESignException.Create('[OpenSSL] Unsupported algorithm type in X509 public key (RSA expected)');

    Result := X509_PUBKEY_get(LCer.cert_info.key);
    if not Assigned(Result) then
      raise ESignException.Create('[OpenSSL] Error extracting public key from X509 certificate');
  finally
    X509_free(LCer);
  end;
end;

class function TSigningBase.LoadPublicKeyFromCert(const ACertificate: TBytes): PEVP_PKEY;
var
  LCer: PX509;
begin
  LoadOpenSSL;

  LCer := LoadCertificate(ACertificate);
  try
    Result := X509_PUBKEY_get(LCer.cert_info.key);
    if not Assigned(Result) then
      raise ESignException.Create('[OpenSSL] Error extracting public key from X509 certificate');
  finally
    X509_free(LCer);
  end;
end;

class function TSigningBase.PublicKeyFromCertificate(const ACertificate: TBytes): TBytes;
var
  LKey: PEVP_PKEY;
  LBio: PBIO;
  LBuffer: TBytes;
  LBytesRead: Integer;
begin
  LKey := LoadPublicKeyFromCert(ACertificate);
  try
    LBio := BIO_new(BIO_s_mem);
    try
      JoseSSL.PEM_write_bio_PUBKEY(LBio, LKey);

      Result := [];
      SetLength(LBuffer, 255);
      repeat
        LBytesRead := BIO_read(LBio, @LBuffer[0], 255);
        TJOSEUtils.ArrayPush(LBuffer, Result, LBytesRead);
      until (LBytesRead <= 0);
    finally
      BIO_free(LBio);
    end;
  finally
    EVP_PKEY_free(LKey);
  end;
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
