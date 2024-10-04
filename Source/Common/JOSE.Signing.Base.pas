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
  System.StrUtils,
  IdGlobal, IdCTypes,
  IdSSLOpenSSLHeaders,
  JOSE.OpenSSL.Headers,
  JOSE.Encoding.Base64;

type
  ESignException = class(Exception);

  TSigningBase = class
  strict private class var
    FPEM_X509_CERTIFICATE: TBytes;
    FPEM_PUBKEY_PKCS1: TBytes;
    FPEM_PUBKEY: TBytes;
    FPEM_PRVKEY_PKCS8: TBytes;
    FPEM_PRVKEY_PKCS1: TBytes;
    class constructor Create;
  protected //CERT
    class property PEM_X509_CERTIFICATE: TBytes read FPEM_X509_CERTIFICATE;
  protected //RSA
    class property PEM_PUBKEY_PKCS1: TBytes read FPEM_PUBKEY_PKCS1;
  protected  //ECDSA
    class property PEM_PUBKEY: TBytes read FPEM_PUBKEY;
    class property PEM_PRVKEY_PKCS8: TBytes read FPEM_PRVKEY_PKCS8;
    class property PEM_PRVKEY_PKCS1: TBytes read FPEM_PRVKEY_PKCS1;

    class function LoadCertificate(const ACertificate: TBytes): PX509;
    class function LoadPublicKeyFromCert(const ACertificate: TBytes): PEVP_PKEY; overload;
    class function LoadPublicKeyFromCert(const ACertificate: TBytes; AAlgID: Integer): PEVP_PKEY; overload;
  public
    class procedure LoadOpenSSL;

    class function PublicKeyFromCertificate(const ACertificate: TBytes): TBytes;
    class function VerifyCertificate(const ACertificate: TBytes; AObjectID: Integer): Boolean;
  end;

{$ENDIF}

implementation

{$IFDEF RSA_SIGNING}

uses
  JOSE.Types.Utils;

class constructor TSigningBase.Create;
begin
  FPEM_X509_CERTIFICATE := TEncoding.ASCII.GetBytes('-----BEGIN CERTIFICATE-----');
  FPEM_PUBKEY_PKCS1 := TEncoding.ASCII.GetBytes('-----BEGIN RSA PUBLIC KEY-----');
  FPEM_PUBKEY := TEncoding.ASCII.GetBytes('-----BEGIN PUBLIC KEY-----');
  FPEM_PRVKEY_PKCS8 := TEncoding.ASCII.GetBytes('-----BEGIN PRIVATE KEY-----');
  FPEM_PRVKEY_PKCS1 := TEncoding.ASCII.GetBytes('-----BEGIN EC PRIVATE KEY-----');
end;

class function TSigningBase.LoadCertificate(const ACertificate: TBytes): PX509;
var
  LBio: PBIO;
begin
  if not CompareMem(@PEM_X509_CERTIFICATE[0], @ACertificate[0], Length(PEM_X509_CERTIFICATE)) then
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
{$IF CompilerVersion < 33 } // Delphi 10.3 Rio or lower
   Result := nil; // prevent compiler warning
{$IFEND}
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

{$ENDIF}

end.
