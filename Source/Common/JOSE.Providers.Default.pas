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

unit JOSE.Providers.Default;

{$I ..\JOSE.inc}

interface

uses
  System.SysUtils,
  JOSE.Types.Bytes,
  JOSE.Crypto.Algorithms,
  JOSE.Providers.Interfaces
{$IFDEF RSA_SIGNING}
  , IdGlobal, IdCTypes, IdSSLOpenSSLHeaders
{$ENDIF};

type
  TDefaultBase64Provider = class(TInterfacedObject, IJOSEBase64Provider)
  private
    function InternalEncode(const ASource: TJOSEBytes): TJOSEBytes;
    function InternalDecode(const ASource: TJOSEBytes): TJOSEBytes;
  public
    function Encode(const ASource: TJOSEBytes): TJOSEBytes;
    function Decode(const ASource: TJOSEBytes): TJOSEBytes;
    function TryDecode(const ASource: TJOSEBytes): TJOSEBytes;
    function URLEncode(const ASource: TJOSEBytes): TJOSEBytes;
    function URLDecode(const ASource: TJOSEBytes): TJOSEBytes;
    function TryURLDecode(const ASource: TJOSEBytes): TJOSEBytes;
  end;

  TDefaultHmacProvider = class(TInterfacedObject, IJOSEHmacProvider)
  public
    function Sign(const AInput, AKey: TBytes; AAlg: THMACAlgorithm): TBytes;
  end;

  /// <summary>Wires default Delphi/OpenSSL-backed implementations into <c>TJOSEProviders</c>.</summary>
  TJOSEDefaultProviders = class
  public
    class procedure Register; static;
    class procedure Unregister; static;
  end;

{$IFDEF RSA_SIGNING}

  TDefaultCertificateProvider = class(TInterfacedObject, IJOSECertificateProvider)
  public
    function PublicKeyFromCertificate(const ACertificate: TBytes): TBytes;
    function VerifyCertificate(const ACertificate: TBytes; AExpected: TJOSECertificatePublicKey): Boolean;
  end;

  TDefaultRSAProvider = class(TInterfacedObject, IJOSESignerRSA)
  private
    FCertificate: IJOSECertificateProvider;
    class function RSAKeyFromEVP(AKey: PEVP_PKEY): PRSA;
    function LoadPublicKey(const AKey: TBytes): PRSA;
    function LoadPrivateKey(const AKey: TBytes): PRSA;
    function LoadRSAPublicKeyFromCert(const ACertificate: TBytes): PRSA;
    function InternalSign(const AInput: TBytes; AKey: PRSA; AAlg: TRSAAlgorithm): TBytes;
    function InternalVerify(const AInput, ASignature: TBytes; AKey: PRSA; AAlg: TRSAAlgorithm): Boolean;
    class function StartsWith(const ABuf, APrefix: TBytes): Boolean; static;
  public
    constructor Create(const ACertificate: IJOSECertificateProvider);
    function Sign(const AInput, AKey: TBytes; AAlg: TRSAAlgorithm): TBytes;
    function Verify(const AInput, ASignature, AKey: TBytes; AAlg: TRSAAlgorithm): Boolean;
    function VerifyWithCertificate(const AInput, ASignature, ACertificate: TBytes; AAlg: TRSAAlgorithm): Boolean;
    function VerifyPublicKey(const AKey: TBytes): Boolean;
    function VerifyPrivateKey(const AKey: TBytes): Boolean;
  end;

  TDefaultECDSAProvider = class(TInterfacedObject, IJOSESignerECDSA)
  private
    FCertificate: IJOSECertificateProvider;
    function LoadPublicKey(const AKey: TBytes): PEVP_PKEY;
    function LoadPrivateKey(const AKey: TBytes): PEVP_PKEY;
    function InternalSign(const AInput: TBytes; AKey: PEVP_PKEY; AAlg: TECDSAAlgorithm): TBytes;
    function InternalVerify(const AInput, ASignature: TBytes; APublicKey: PEVP_PKEY; AAlg: TECDSAAlgorithm): Boolean;
    function HashFromBytes(const AInput: TBytes; AAlg: TECDSAAlgorithm): TBytes;
    function Sig2OctetSequence(ASignature: PECDSA_SIG; AAlg: TECDSAAlgorithm): TBytes;
    function OctetSequence2Sig(const ASignature: TBytes; AAlg: TECDSAAlgorithm): PECDSA_SIG;
  public
    constructor Create(const ACertificate: IJOSECertificateProvider);
    function Sign(const AInput, APrivateKey: TBytes; AAlg: TECDSAAlgorithm): TBytes;
    function Verify(const AInput, ASignature, APublicKey: TBytes; AAlg: TECDSAAlgorithm): Boolean;
    function VerifyWithCertificate(const AInput, ASignature, ACertificate: TBytes; AAlg: TECDSAAlgorithm): Boolean;
    function VerifyPublicKey(const AKey: TBytes): Boolean;
    function VerifyPrivateKey(const AKey: TBytes): Boolean;
  end;

{$ENDIF}

implementation

uses
{$IFDEF RSA_SIGNING}
  System.StrUtils,
  JOSE.Signing.Base,
  JOSE.Types.Utils,
  JOSE.OpenSSL.Headers,
{$ENDIF}
  {$IF CompilerVersion >= 28}
  System.NetEncoding,
  {$IFEND}
  {$IF CompilerVersion < 30 }
  {$IFNDEF RSA_SIGNING}
  IdGlobal,
  {$ENDIF}
  IdHMAC,
  IdHMACSHA1,
  IdSSLOpenSSL,
  IdHash,
  {$IFEND}
  {$IF CompilerVersion >= 30 }
  System.Hash,
  {$IFEND}
  System.Types,
  JOSE.Providers;

{$IFDEF RSA_SIGNING}

function JoseExpectedNidForCertPublicKey(const AExpected: TJOSECertificatePublicKey): Integer;
begin
  case AExpected of
    TJOSECertificatePublicKey.RSA:
      Result := NID_rsaEncryption;
    TJOSECertificatePublicKey.EC:
      Result := JoseSSL.NID_X9_62_id_ecPublicKey;
  else
    raise EArgumentException.Create('Unhandled TJOSECertificatePublicKey value');
  end;
end;

type
  TJOSEDefaultOpenSslPem = class
  strict private
    class var
      FPEM_X509_CERTIFICATE: TBytes;
      FPEM_PUBKEY_PKCS1: TBytes;
      FPEM_PUBKEY: TBytes;
      FPEM_PRVKEY_PKCS8: TBytes;
      FPEM_PRVKEY_PKCS1: TBytes;
    class constructor Create;
  public
    class procedure LoadOpenSSL;
    class function LoadCertificate(const ACertificate: TBytes): PX509;
    class function LoadPublicKeyFromCert(const ACertificate: TBytes): PEVP_PKEY; overload;
    class function LoadPublicKeyFromCert(const ACertificate: TBytes; AExpected: TJOSECertificatePublicKey): PEVP_PKEY; overload;
    /// <summary>SPKI PEM bytes to feed a BIO: certificate PEM yields <c>ACert.PublicKeyFromCertificate</c>, else <c>AKey</c>.</summary>
    class function PublicKeyPemBytesFromKeyOrCert(const AKey: TBytes; const ACert: IJOSECertificateProvider): TBytes;
    class function PublicKeyFromCertificate(const ACertificate: TBytes): TBytes;
    class function VerifyCertificate(const ACertificate: TBytes; AExpected: TJOSECertificatePublicKey): Boolean;
    class property PEM_X509_CERTIFICATE: TBytes read FPEM_X509_CERTIFICATE;
    class property PEM_PUBKEY_PKCS1: TBytes read FPEM_PUBKEY_PKCS1;
  end;

class constructor TJOSEDefaultOpenSslPem.Create;
begin
  FPEM_X509_CERTIFICATE := TEncoding.ASCII.GetBytes('-----BEGIN CERTIFICATE-----');
  FPEM_PUBKEY_PKCS1 := TEncoding.ASCII.GetBytes('-----BEGIN RSA PUBLIC KEY-----');
  FPEM_PUBKEY := TEncoding.ASCII.GetBytes('-----BEGIN PUBLIC KEY-----');
  FPEM_PRVKEY_PKCS8 := TEncoding.ASCII.GetBytes('-----BEGIN PRIVATE KEY-----');
  FPEM_PRVKEY_PKCS1 := TEncoding.ASCII.GetBytes('-----BEGIN EC PRIVATE KEY-----');
end;

class procedure TJOSEDefaultOpenSslPem.LoadOpenSSL;
begin
  if not IdSSLOpenSSLHeaders.Load then
    raise ESignException.Create('[OpenSSL] Unable to load OpenSSL libraries');

  if not JoseSSL.Load then
    raise ESignException.Create('[OpenSSL] Unable to load OpenSSL libraries');

  if @EVP_DigestVerifyInit = nil then
    raise ESignException.Create('[OpenSSL] Please, use OpenSSL 1.0.0 or newer!');
end;

class function TJOSEDefaultOpenSslPem.LoadCertificate(const ACertificate: TBytes): PX509;
var
  LBio: PBIO;
begin
  if not CompareMem(@FPEM_X509_CERTIFICATE[0], @ACertificate[0], Length(FPEM_X509_CERTIFICATE)) then
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

class function TJOSEDefaultOpenSslPem.LoadPublicKeyFromCert(const ACertificate: TBytes; AExpected: TJOSECertificatePublicKey): PEVP_PKEY;
var
  LCer: PX509;
  LAlg: Integer;
  LExpectedNid: Integer;
begin
{$IF CompilerVersion < 33 }
  Result := nil;
{$IFEND}
  LoadOpenSSL;

  LCer := LoadCertificate(ACertificate);
  try
    LAlg := OBJ_obj2nid(LCer.cert_info.key.algor.algorithm);
    LExpectedNid := JoseExpectedNidForCertPublicKey(AExpected);
    if LAlg <> LExpectedNid then
      raise ESignException.Create('[OpenSSL] Certificate public key algorithm does not match expected type');

    Result := X509_PUBKEY_get(LCer.cert_info.key);
    if not Assigned(Result) then
      raise ESignException.Create('[OpenSSL] Error extracting public key from X509 certificate');
  finally
    X509_free(LCer);
  end;
end;

class function TJOSEDefaultOpenSslPem.LoadPublicKeyFromCert(const ACertificate: TBytes): PEVP_PKEY;
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

class function TJOSEDefaultOpenSslPem.PublicKeyPemBytesFromKeyOrCert(const AKey: TBytes; const ACert: IJOSECertificateProvider): TBytes;
begin
  if (Length(AKey) >= Length(FPEM_X509_CERTIFICATE)) and
    CompareMem(@FPEM_X509_CERTIFICATE[0], @AKey[0], Length(FPEM_X509_CERTIFICATE)) then
    Result := ACert.PublicKeyFromCertificate(AKey)
  else
    Result := AKey;
end;

class function TJOSEDefaultOpenSslPem.PublicKeyFromCertificate(const ACertificate: TBytes): TBytes;
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

class function TJOSEDefaultOpenSslPem.VerifyCertificate(const ACertificate: TBytes; AExpected: TJOSECertificatePublicKey): Boolean;
var
  LCer: PX509;
  LKey: PEVP_PKEY;
  LAlg: Integer;
  LExpectedNid: Integer;
begin
  LoadOpenSSL;

  LCer := LoadCertificate(ACertificate);
  try
    LKey := X509_PUBKEY_get(LCer.cert_info.key);
    try
      LAlg := OBJ_obj2nid(LCer.cert_info.key.algor.algorithm);
      LExpectedNid := JoseExpectedNidForCertPublicKey(AExpected);
      Result := Assigned(LCer) and Assigned(LKey) and (LAlg = LExpectedNid);
    finally
      EVP_PKEY_free(LKey);
    end;
  finally
    X509_free(LCer);
  end;
end;

{ TDefaultCertificateProvider }

function TDefaultCertificateProvider.PublicKeyFromCertificate(const ACertificate: TBytes): TBytes;
begin
  Result := TJOSEDefaultOpenSslPem.PublicKeyFromCertificate(ACertificate);
end;

function TDefaultCertificateProvider.VerifyCertificate(const ACertificate: TBytes; AExpected: TJOSECertificatePublicKey): Boolean;
begin
  Result := TJOSEDefaultOpenSslPem.VerifyCertificate(ACertificate, AExpected);
end;

{ TDefaultRSAProvider }

constructor TDefaultRSAProvider.Create(const ACertificate: IJOSECertificateProvider);
begin
  inherited Create;
  FCertificate := ACertificate;
end;

class function TDefaultRSAProvider.StartsWith(const ABuf, APrefix: TBytes): Boolean;
begin
  Result := (Length(ABuf) >= Length(APrefix)) and CompareMem(@APrefix[0], @ABuf[0], Length(APrefix));
end;

class function TDefaultRSAProvider.RSAKeyFromEVP(AKey: PEVP_PKEY): PRSA;
begin
  Result := EVP_PKEY_get1_RSA(AKey);
  if not Assigned(Result) then
    raise ESignException.Create('[RSA] Error extracting RSA key from EVP_PKEY');
end;

function TDefaultRSAProvider.InternalSign(const AInput: TBytes; AKey: PRSA; AAlg: TRSAAlgorithm): TBytes;
var
  LHash: TBytes;
  LNID: Integer;
  LRsaLen: Integer;
  LShaLen: Integer;
begin
  case AAlg of
    RS256:
    begin
      LNID := JoseSSL.NID_sha256;
      LShaLen := SHA256_DIGEST_LENGTH;
      SetLength(LHash, LShaLen);
      JoseSSL.SHA256(@AInput[0], Length(AInput), @LHash[0]);
    end;
    RS384:
    begin
      LNID := JoseSSL.NID_sha384;
      LShaLen := SHA384_DIGEST_LENGTH;
      SetLength(LHash, LShaLen);
      JoseSSL.SHA384(@AInput[0], Length(AInput), @LHash[0]);
    end;
    RS512:
    begin
      LNID := JoseSSL.NID_sha512;
      LShaLen := SHA512_DIGEST_LENGTH;
      SetLength(LHash, LShaLen);
      JoseSSL.SHA512(@AInput[0], Length(AInput), @LHash[0]);
    end;
  else
    raise ESignException.Create('[RSA] Unsupported signing algorithm!');
  end;

  LRsaLen := JoseSSL.RSA_size(AKey);
  SetLength(Result, LRsaLen);
  if JoseSSL.RSA_sign(LNID, @LHash[0], LShaLen, @Result[0], @LRsaLen, AKey) = 0 then
    raise ESignException.Create('[RSA] Unable to sign RSA message digest');
end;

function TDefaultRSAProvider.InternalVerify(const AInput, ASignature: TBytes; AKey: PRSA; AAlg: TRSAAlgorithm): Boolean;
var
  LResult: Integer;
  LHash: TBytes;
  LNID: Integer;
  LShaLen: Integer;
begin
  case AAlg of
    RS256:
    begin
      LNID := JoseSSL.NID_sha256;
      LShaLen := SHA256_DIGEST_LENGTH;
      SetLength(LHash, LShaLen);
      JoseSSL.SHA256(@AInput[0], Length(AInput), @LHash[0]);
    end;
    RS384:
    begin
      LNID := JoseSSL.NID_sha384;
      LShaLen := SHA384_DIGEST_LENGTH;
      SetLength(LHash, LShaLen);
      JoseSSL.SHA384(@AInput[0], Length(AInput), @LHash[0]);
    end;
    RS512:
    begin
      LNID := JoseSSL.NID_sha512;
      LShaLen := SHA512_DIGEST_LENGTH;
      SetLength(LHash, LShaLen);
      JoseSSL.SHA512(@AInput[0], Length(AInput), @LHash[0]);
    end;
  else
    raise ESignException.Create('[RSA] Unsupported signing algorithm!');
  end;
  LResult := JoseSSL.RSA_verify(LNID, @LHash[0], LShaLen, @ASignature[0], Length(ASignature), AKey);

  Result := LResult = 1;
end;

function TDefaultRSAProvider.LoadPrivateKey(const AKey: TBytes): PRSA;
var
  LBio: PBIO;
begin
  LBio := BIO_new(BIO_s_mem);
  try
    BIO_write(LBio, @AKey[0], Length(AKey));
    Result := PEM_read_bio_RSAPrivateKey(LBio, nil, nil, nil);
    if Result = nil then
      raise ESignException.Create('[RSA] Unable to load private key: ' + JoseSSL.GetLastError);
  finally
    BIO_free(LBio);
  end;
end;

function TDefaultRSAProvider.LoadPublicKey(const AKey: TBytes): PRSA;
var
  LBio: PBIO;
  LPem: TBytes;
begin
  LBio := BIO_new(BIO_s_mem);
  try
    LPem := TJOSEDefaultOpenSslPem.PublicKeyPemBytesFromKeyOrCert(AKey, FCertificate);
    BIO_write(LBio, @LPem[0], Length(LPem));
    if StartsWith(LPem, TJOSEDefaultOpenSslPem.PEM_PUBKEY_PKCS1) then
      Result := PEM_read_bio_RSAPublicKey(LBio, nil, nil, nil)
    else
      Result := JoseSSL.PEM_read_bio_RSA_PUBKEY(LBio, nil, nil, nil);

    if Result = nil then
      raise ESignException.Create('[RSA] Unable to load public key: ' + JoseSSL.GetLastError);
  finally
    BIO_free(LBio);
  end;
end;

function TDefaultRSAProvider.LoadRSAPublicKeyFromCert(const ACertificate: TBytes): PRSA;
var
  LKey: PEVP_PKEY;
begin
  LKey := TJOSEDefaultOpenSslPem.LoadPublicKeyFromCert(ACertificate, TJOSECertificatePublicKey.RSA);
  try
    Result := RSAKeyFromEVP(LKey);
  finally
    EVP_PKEY_free(LKey);
  end;
end;

function TDefaultRSAProvider.Sign(const AInput, AKey: TBytes; AAlg: TRSAAlgorithm): TBytes;
var
  LRsa: PRSA;
begin
  TJOSEDefaultOpenSslPem.LoadOpenSSL;

  LRsa := LoadPrivateKey(AKey);
  try
    Result := InternalSign(AInput, LRsa, AAlg);
  finally
    RSA_Free(LRsa);
  end;
end;

function TDefaultRSAProvider.Verify(const AInput, ASignature, AKey: TBytes; AAlg: TRSAAlgorithm): Boolean;
var
  LRsa: PRSA;
begin
  TJOSEDefaultOpenSslPem.LoadOpenSSL;

  LRsa := LoadPublicKey(AKey);
  try
    Result := InternalVerify(AInput, ASignature, LRsa, AAlg);
  finally
    RSA_Free(LRsa);
  end;
end;

function TDefaultRSAProvider.VerifyPrivateKey(const AKey: TBytes): Boolean;
var
  LBio: PBIO;
  LRsa: PRSA;
begin
  TJOSEDefaultOpenSslPem.LoadOpenSSL;

  LBio := BIO_new(BIO_s_mem);
  try
    BIO_write(LBio, @AKey[0], Length(AKey));
    LRsa := PEM_read_bio_RSAPrivateKey(LBio, nil, nil, nil);
    Result := (LRsa <> nil);
    if Result then
      RSA_Free(LRsa);
  finally
    BIO_free(LBio);
  end;
end;

function TDefaultRSAProvider.VerifyPublicKey(const AKey: TBytes): Boolean;
var
  LBio: PBIO;
  LRsa: PRSA;
  LPem: TBytes;
begin
  TJOSEDefaultOpenSslPem.LoadOpenSSL;

  LBio := BIO_new(BIO_s_mem);
  try
    LPem := TJOSEDefaultOpenSslPem.PublicKeyPemBytesFromKeyOrCert(AKey, FCertificate);
    BIO_write(LBio, @LPem[0], Length(LPem));
    if StartsWith(LPem, TJOSEDefaultOpenSslPem.PEM_PUBKEY_PKCS1) then
      LRsa := PEM_read_bio_RSAPublicKey(LBio, nil, nil, nil)
    else
      LRsa := JoseSSL.PEM_read_bio_RSA_PUBKEY(LBio, nil, nil, nil);

    Result := (LRsa <> nil);
    if Result then
      RSA_Free(LRsa);
  finally
    BIO_free(LBio);
  end;
end;

function TDefaultRSAProvider.VerifyWithCertificate(const AInput, ASignature, ACertificate: TBytes; AAlg: TRSAAlgorithm): Boolean;
var
  LRsa: PRSA;
begin
  LRsa := LoadRSAPublicKeyFromCert(ACertificate);
  try
    Result := InternalVerify(AInput, ASignature, LRsa, AAlg);
  finally
    RSA_free(LRsa);
  end;
end;

{ TDefaultECDSAProvider }

constructor TDefaultECDSAProvider.Create(const ACertificate: IJOSECertificateProvider);
begin
  inherited Create;
  FCertificate := ACertificate;
end;

function TDefaultECDSAProvider.HashFromBytes(const AInput: TBytes; AAlg: TECDSAAlgorithm): TBytes;
var
  LShaLen: Integer;
begin
  case AAlg of
    ES256, ES256K:
    begin
      LShaLen := SHA256_DIGEST_LENGTH;
      SetLength(Result, LShaLen);
      JoseSSL.SHA256(@AInput[0], Length(AInput), @Result[0]);
    end;
    ES384:
    begin
      LShaLen := SHA384_DIGEST_LENGTH;
      SetLength(Result, LShaLen);
      JoseSSL.SHA384(@AInput[0], Length(AInput), @Result[0]);
    end;
    ES512:
    begin
      LShaLen := SHA512_DIGEST_LENGTH;
      SetLength(Result, LShaLen);
      JoseSSL.SHA512(@AInput[0], Length(AInput), @Result[0]);
    end;
  else
    raise Exception.Create('[ECDSA] Unsupported signing algorithm!');
  end;
end;

function TDefaultECDSAProvider.InternalVerify(const AInput, ASignature: TBytes; APublicKey: PEVP_PKEY; AAlg: TECDSAAlgorithm): Boolean;
var
  LECKey: PEC_KEY;
  LSig: PECDSA_SIG;
  LShaHash: TBytes;
begin
  LECKey := EVP_PKEY_get1_EC_KEY(APublicKey);
  if LECKey = nil then
    raise Exception.Create('[ECDSA] Error getting memory for ECDSA');
  try
    LSig := OctetSequence2Sig(ASignature, AAlg);
    try
      LShaHash := HashFromBytes(AInput, AAlg);
      Result := JoseSSL.ECDSA_do_verify(@LShaHash[0], Length(LShaHash), LSig, LECKey) = 1;
    finally
      JoseSSL.ECDSA_SIG_free(LSig);
    end;
  finally
    JoseSSL.EC_KEY_free(LECKey);
  end;
end;

function TDefaultECDSAProvider.LoadPrivateKey(const AKey: TBytes): PEVP_PKEY;
var
  LBIO: PBIO;
begin
  TJOSEDefaultOpenSslPem.LoadOpenSSL;

  LBIO := BIO_new(BIO_s_mem);
  try
    BIO_write(LBIO, @AKey[0], Length(AKey));
    Result := PEM_read_bio_PrivateKey(LBIO, nil, nil, nil);
    if Result = nil then
      raise ESignException.Create('[ECDSA] Unable to load private key: ' + JoseSSL.GetLastError);
  finally
    BIO_free(LBIO);
  end;
end;

function TDefaultECDSAProvider.LoadPublicKey(const AKey: TBytes): PEVP_PKEY;
var
  LKeyBuffer: PBIO;
  LPem: TBytes;
begin
  TJOSEDefaultOpenSslPem.LoadOpenSSL;

  LKeyBuffer := BIO_new(BIO_s_mem);
  try
    LPem := TJOSEDefaultOpenSslPem.PublicKeyPemBytesFromKeyOrCert(AKey, FCertificate);
    BIO_write(LKeyBuffer, @LPem[0], Length(LPem));

    Result := JoseSSL.PEM_read_bio_PUBKEY(LKeyBuffer, nil, nil, nil);
    if Result = nil then
      raise Exception.Create('[ECDSA] Unable to load public key: ' + JoseSSL.GetLastError);
  finally
    BIO_free(LKeyBuffer);
  end;
end;

function TDefaultECDSAProvider.Sign(const AInput, APrivateKey: TBytes; AAlg: TECDSAAlgorithm): TBytes;
var
  LKey: PEVP_PKEY;
begin
  Result := [];

  LKey := LoadPrivateKey(APrivateKey);
  try
    Result := InternalSign(AInput, LKey, AAlg);
  finally
    EVP_PKEY_free(LKey);
  end;
end;

function TDefaultECDSAProvider.InternalSign(const AInput: TBytes; AKey: PEVP_PKEY; AAlg: TECDSAAlgorithm): TBytes;
var
  LECKey: PEC_KEY;
  LSig: PECDSA_SIG;
  LShaHash: TBytes;
begin
  Result := [];
  LECKey := EVP_PKEY_get1_EC_KEY(AKey);
  if LECKey = nil then
    raise ESignException.Create('[ECDSA] Error getting EC Key: ' + JoseSSL.GetLastError);
  try
    LShaHash := HashFromBytes(AInput, AAlg);

    LSig := JoseSSL.ECDSA_do_sign(@LShaHash[0], Length(LShaHash), LECKey);
    if LSig = nil then
      raise ESignException.Create('[ECDSA] Digest signing failed: ' + JoseSSL.GetLastError);
    try
      Result := Sig2OctetSequence(LSig, AAlg);
    finally
      JoseSSL.ECDSA_SIG_free(LSig);
    end;
  finally
    JoseSSL.EC_KEY_free(LECKey);
  end;
end;

function TDefaultECDSAProvider.OctetSequence2Sig(const ASignature: TBytes; AAlg: TECDSAAlgorithm): PECDSA_SIG;
var
  LKeyLength: Integer;
begin
  Result := JoseSSL.ECDSA_SIG_new();
  LKeyLength := Length(ASignature) div 2;

  JoseSSL.BN_bin2bn(Pointer(ASignature), LKeyLength, Result.r);
  JoseSSL.BN_bin2bn(Pointer(NativeInt(ASignature) + LKeyLength), LKeyLength, Result.s);
end;

function TDefaultECDSAProvider.Sig2OctetSequence(ASignature: PECDSA_SIG; AAlg: TECDSAAlgorithm): TBytes;
var
  LSigLength, LRLength, LSLength: Integer;
begin
  LSigLength := 0;

  case AAlg of
    ES256:  LSigLength := 32 * 2;
    ES256K: LSigLength := 32 * 2;
    ES384:  LSigLength := 48 * 2;
    ES512:  LSigLength := 66 * 2;
  end;

  LRLength := JoseSSL.BN_num_bytes(ASignature.r);
  LSLength := JoseSSL.BN_num_bytes(ASignature.s);

  SetLength(Result, LSigLength);
  FillChar(Result[0], LSigLength, #0);

  JoseSSL.BN_bn2bin(ASignature.r, Pointer(NativeInt(Result) + (LSigLength div 2) - LRLength));
  JoseSSL.BN_bn2bin(ASignature.s, Pointer(NativeInt(Result) + LSigLength - LSLength));
end;

function TDefaultECDSAProvider.Verify(const AInput, ASignature, APublicKey: TBytes; AAlg: TECDSAAlgorithm): Boolean;
var
  LPubKey: PEVP_PKEY;
begin
  LPubKey := LoadPublicKey(APublicKey);
  try
    Result := InternalVerify(AInput, ASignature, LPubKey, AAlg);
  finally
    EVP_PKEY_free(LPubKey);
  end;
end;

function TDefaultECDSAProvider.VerifyPrivateKey(const AKey: TBytes): Boolean;
var
  LBio: PBIO;
  LPrivKey: PEVP_PKEY;
begin
  TJOSEDefaultOpenSslPem.LoadOpenSSL;

  LBio := BIO_new(BIO_s_mem);
  try
    BIO_write(LBio, @AKey[0], Length(AKey));
    LPrivKey := JoseSSL.PEM_read_bio_ECPrivateKey(LBio, nil, nil, nil);
    Result := (LPrivKey <> nil);
    if Result then
      EVP_PKEY_free(LPrivKey);
  finally
    BIO_free(LBio);
  end;
end;

function TDefaultECDSAProvider.VerifyPublicKey(const AKey: TBytes): Boolean;
var
  LBio: PBIO;
  LKey: PEVP_PKEY;
  LPem: TBytes;
begin
  TJOSEDefaultOpenSslPem.LoadOpenSSL;

  LBio := BIO_new(BIO_s_mem);
  try
    LPem := TJOSEDefaultOpenSslPem.PublicKeyPemBytesFromKeyOrCert(AKey, FCertificate);
    BIO_write(LBio, @LPem[0], Length(LPem));
    LKey := JoseSSL.PEM_read_bio_PUBKEY(LBio, nil, nil, nil);

    Result := (LKey <> nil);
    if Result then
      EVP_PKEY_free(LKey);
  finally
    BIO_free(LBio);
  end;
end;

function TDefaultECDSAProvider.VerifyWithCertificate(const AInput, ASignature, ACertificate: TBytes; AAlg: TECDSAAlgorithm): Boolean;
var
  LKey: PEVP_PKEY;
begin
  LKey := TJOSEDefaultOpenSslPem.LoadPublicKeyFromCert(ACertificate, TJOSECertificatePublicKey.EC);
  try
    Result := InternalVerify(AInput, ASignature, LKey, AAlg);
  finally
    EVP_PKEY_free(LKey);
  end;
end;

{$ENDIF}

{$IF CompilerVersion <= 27}
type
  TPacket = packed record
    case Integer of
      0: (b0, b1, b2, b3: Byte);
      1: (i: Integer);
      2: (a: array[0..3] of Byte);
  end;

function DecodeBase64(const AInput: string): TBytes;
const
  DECODE_TABLE: array[#0..#127] of Integer = (
    Byte('='), 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
    64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
    64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64
  );

  function DecodePacket(AInputBuffer: PChar; var ANumChars: Integer): TPacket;
  begin
    Result.a[0] :=
      (DECODE_TABLE[AInputBuffer[0]] shl 2) or (DECODE_TABLE[AInputBuffer[1]] shr 4);
    ANumChars := 1;
    if AInputBuffer[2] <> '=' then
    begin
      Inc(ANumChars);
      Result.a[1] := (DECODE_TABLE[AInputBuffer[1]] shl 4) or (DECODE_TABLE[AInputBuffer[2]] shr 2);
    end;
    if AInputBuffer[3] <> '=' then
    begin
      Inc(ANumChars);
      Result.a[2] := (DECODE_TABLE[AInputBuffer[2]] shl 6) or DECODE_TABLE[AInputBuffer[3]];
    end;
  end;

var
  I, J, K: Integer;
  LPacket: TPacket;
  LLen: Integer;
begin
  SetLength(Result, Length(AInput) div 4 * 3);
  LLen := 0;
  for I := 1 to Length(AInput) div 4 do
  begin
    LPacket := DecodePacket(PChar(@AInput[(I - 1) * 4 + 1]), J);
    K := 0;
    while J > 0 do
    begin
      Result[LLen] := LPacket.a[K];
      Inc(LLen);
      Inc(K);
      Dec(J);
    end;
  end;
  SetLength(Result, LLen);
end;

function EncodeBase64(const AInput: TBytes): string;
const
  ENCODE_TABLE: array[0..63] of Char =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ' +
    'abcdefghijklmnopqrstuvwxyz' +
    '0123456789+/';

  procedure EncodePacket(const APacket: TPacket; ANumChars: Integer; AOutBuffer: PChar);
  begin
    AOutBuffer[0] := ENCODE_TABLE[APacket.a[0] shr 2];
    AOutBuffer[1] := ENCODE_TABLE[((APacket.a[0] shl 4) or (APacket.a[1] shr 4)) and $0000003f];

    if ANumChars < 2 then
      AOutBuffer[2] := '='
    else
      AOutBuffer[2] := ENCODE_TABLE[((APacket.a[1] shl 2) or (APacket.a[2] shr 6)) and $0000003f];

    if ANumChars < 3 then
      AOutBuffer[3] := '='
    else
      AOutBuffer[3] := ENCODE_TABLE[APacket.a[2] and $0000003f];
  end;

var
  I, K, J: Integer;
  LPacket: TPacket;
begin
  Result := '';
  I := (Length(AInput) div 3) * 4;
  if Length(AInput) mod 3 > 0 then
    Inc(I, 4);
  SetLength(Result, I);
  J := 1;
  for I := 1 to Length(AInput) div 3 do
  begin
    LPacket.i := 0;
    LPacket.a[0] := AInput[(I - 1) * 3];
    LPacket.a[1] := AInput[(I - 1) * 3 + 1];
    LPacket.a[2] := AInput[(I - 1) * 3 + 2];
    EncodePacket(LPacket, 3, PChar(@Result[J]));
    Inc(J, 4);
  end;
  K := 0;
  LPacket.i := 0;
  for I := Length(AInput) - (Length(AInput) mod 3) + 1 to Length(AInput) do
  begin
    LPacket.a[K] := Byte(AInput[I - 1]);
    Inc(K);
    if I = Length(AInput) then
      EncodePacket(LPacket, Length(AInput) mod 3, PChar(@Result[J]));
  end;
end;
{$IFEND}

{ TDefaultBase64Provider }

function TDefaultBase64Provider.InternalDecode(const ASource: TJOSEBytes): TJOSEBytes;
begin
  {$IF CompilerVersion >= 28}
  Result := TNetEncoding.Base64.Decode(ASource.AsBytes);
  {$ELSE}
  Result := DecodeBase64(ASource.AsString);
  {$IFEND}
end;

function TDefaultBase64Provider.InternalEncode(const ASource: TJOSEBytes): TJOSEBytes;
var
  LEnc: TBase64Encoding;
begin
  {$IF CompilerVersion >= 28}
  LEnc := TBase64Encoding.Create(0);
  try
    Result := LEnc.Encode(ASource.AsBytes);
  finally
    LEnc.Free;
  end;
  {$ELSE}
  Result := EncodeBase64(ASource.AsBytes);
  {$IFEND}
end;

function TDefaultBase64Provider.Decode(const ASource: TJOSEBytes): TJOSEBytes;
begin
  Result := InternalDecode(ASource);
end;

function TDefaultBase64Provider.Encode(const ASource: TJOSEBytes): TJOSEBytes;
begin
  Result := InternalEncode(ASource);
end;

function TDefaultBase64Provider.TryDecode(const ASource: TJOSEBytes): TJOSEBytes;
begin
  try
    Result := Decode(ASource);
  except
    Result.Clear;
  end;
end;

function TDefaultBase64Provider.TryURLDecode(const ASource: TJOSEBytes): TJOSEBytes;
begin
  try
    Result := URLDecode(ASource);
  except
    Result.Clear;
  end;
end;

function TDefaultBase64Provider.URLDecode(const ASource: TJOSEBytes): TJOSEBytes;
var
  LBase64Str: string;
begin
  LBase64Str := ASource;

  LBase64Str := LBase64Str + StringOfChar('=', (4 - ASource.Size mod 4) mod 4);
  LBase64Str := StringReplace(LBase64Str, '-', '+', [rfReplaceAll]);
  LBase64Str := StringReplace(LBase64Str, '_', '/', [rfReplaceAll]);
  Result := Decode(LBase64Str);
end;

function TDefaultBase64Provider.URLEncode(const ASource: TJOSEBytes): TJOSEBytes;
var
  LBase64Str: string;
begin
  LBase64Str := Encode(ASource);

  LBase64Str := StringReplace(LBase64Str, #13#10, '', [rfReplaceAll]);
  LBase64Str := StringReplace(LBase64Str, #13, '', [rfReplaceAll]);
  LBase64Str := StringReplace(LBase64Str, #10, '', [rfReplaceAll]);
  LBase64Str := LBase64Str.TrimRight(['=']);

  LBase64Str := StringReplace(LBase64Str, '+', '-', [rfReplaceAll]);
  LBase64Str := StringReplace(LBase64Str, '/', '_', [rfReplaceAll]);

  Result := LBase64Str;
end;

{ TDefaultHmacProvider }

{$IF CompilerVersion >= 30 }
function TDefaultHmacProvider.Sign(const AInput, AKey: TBytes; AAlg: THMACAlgorithm): TBytes;
var
  LHashAlg: THashSHA2.TSHA2Version;
begin
  LHashAlg := THashSHA2.TSHA2Version.SHA256;
  case AAlg of
    THMACAlgorithm.SHA256: LHashAlg := THashSHA2.TSHA2Version.SHA256;
    THMACAlgorithm.SHA384: LHashAlg := THashSHA2.TSHA2Version.SHA384;
    THMACAlgorithm.SHA512: LHashAlg := THashSHA2.TSHA2Version.SHA512;
  end;
  Result := THashSHA2.GetHMACAsBytes(AInput, AKey, LHashAlg);
end;
{$ELSE}
function TDefaultHmacProvider.Sign(const AInput, AKey: TBytes; AAlg: THMACAlgorithm): TBytes;
var
  LSigner: TIdHMAC;
begin
  LSigner := nil;

  if not IdSSLOpenSSL.LoadOpenSSLLibrary then
    raise Exception.Create('Error Loading OpenSSL libraries');

  case AAlg of
    THMACAlgorithm.SHA256: LSigner := TIdHMACSHA256.Create;
    THMACAlgorithm.SHA384: LSigner := TIdHMACSHA384.Create;
    THMACAlgorithm.SHA512: LSigner := TIdHMACSHA512.Create;
  end;

  try
    LSigner.Key := TIdBytes(AKey);
    Result := TBytes(LSigner.HashValue(TIdBytes(AInput)));
  finally
    LSigner.Free;
  end;
end;
{$IFEND}

{ TJOSEDefaultProviders }

class procedure TJOSEDefaultProviders.Register;
{$IFDEF RSA_SIGNING}
var
  LCert: IJOSECertificateProvider;
{$ENDIF}
begin
  TJOSEProviders.Base64 := TDefaultBase64Provider.Create;
  TJOSEProviders.HMAC := TDefaultHmacProvider.Create;
{$IFDEF RSA_SIGNING}
  LCert := TDefaultCertificateProvider.Create;
  TJOSEProviders.Certificate := LCert;
  TJOSEProviders.RSA := TDefaultRSAProvider.Create(LCert);
  TJOSEProviders.ECDSA := TDefaultECDSAProvider.Create(LCert);
{$ENDIF}
end;

class procedure TJOSEDefaultProviders.Unregister;
begin
  TJOSEProviders.Base64 := nil;
  TJOSEProviders.HMAC := nil;
{$IFDEF RSA_SIGNING}
  TJOSEProviders.Certificate := nil;
  TJOSEProviders.RSA := nil;
  TJOSEProviders.ECDSA := nil;
{$ENDIF}
end;

end.
