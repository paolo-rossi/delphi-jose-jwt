{******************************************************************************}
{                                                                              }
{  Delphi JOSE Library                                                         }
{  Copyright (c) 2015-2017 Paolo Rossi                                         }
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

unit JOSE.Signing.RSA;

interface

uses
  System.SysUtils,
  IdGlobal, IdCTypes, IdSSLOpenSSLHeaders,
  JOSE.Encoding.Base64;

type
  TRSAAlgorithm = (RS256, RS384, RS512);
  TRSAAlgorithmHelper = record helper for TRSAAlgorithm
    procedure FromString(const AValue: string);
    function ToString: string;
  end;

  TRSA = class
  private
    const PKCS1_SIGNATURE_PUBKEY: RawByteString = '-----BEGIN RSA PUBLIC KEY-----';
    const PKCS1_X509_CERTIFICATE: RawByteString = '-----BEGIN CERTIFICATE-----';
  private
    class var _PEM_read_bio_RSA_PUBKEY: function(bp: PBIO; x: PPRSA; cb: ppem_password_cb; u: Pointer): PRSA cdecl;
    class var _EVP_MD_CTX_create: function: PEVP_MD_CTX cdecl;
    class var _EVP_MD_CTX_destroy: procedure(ctx: PEVP_MD_CTX); cdecl;
  private
    class procedure LoadOpenSSL;
    class function VerifyWithCertificate(const AInput, ASignature, ACertificate: TBytes; AAlg: TRSAAlgorithm): Boolean;
    class function VerifyCertificate(const ACertificate: TBytes): Boolean;
  public
    class function Sign(const AInput, AKey: TBytes; AAlg: TRSAAlgorithm): TBytes;
    class function Verify(const AInput, ASignature, AKeyOrCertificate: TBytes; AAlg: TRSAAlgorithm): Boolean;
    class function VerifyPublicKey(const AKeyOrCertificate: TBytes): Boolean;
    class function VerifyPrivateKey(const AKey: TBytes): Boolean;
  end;

implementation

{$IFDEF MSWINDOWS}
uses
  WinApi.Windows;
{$ENDIF}

function ArrayToString(const ASource: array of Char): string;
var
  LSourcePointer: PChar;
  LTarget: string;
begin
  LSourcePointer := Addr(ASource);
  SetString(LTarget, LSourcePointer, Length(ASource));
  Result := LTarget;
end;

// Get OpenSSL error and message text
function ERR_GetErrorMessage_OpenSSL: string;
var
  LErrMsg: array[0..160] of Char;
begin
  ERR_error_string(ERR_get_error, @LErrMsg);
  Result := ArrayToString(LErrMsg);
end;

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
  case Self of
    RS256: Result := 'RS256';
    RS384: Result := 'RS384';
    RS512: Result := 'RS512';
  end;
end;

{ TRSA }

class function TRSA.Sign(const AInput, AKey: TBytes; AAlg: TRSAAlgorithm): TBytes;
var
  LPrivKeyBIO: pBIO;
  LPrivKey: pEVP_PKEY;
  LRsa: pRSA;

  LCtx: PEVP_MD_CTX;
  LSha: PEVP_MD;

  LLen: Integer;
  LSig: Pointer;
begin
  LoadOpenSSL;

  // Load Private RSA Key into RSA object
  LPrivKeyBIO := BIO_new(BIO_s_mem);
  try
    BIO_write(LPrivKeyBIO, @AKey[0], Length(AKey));
    LRsa := PEM_read_bio_RSAPrivateKey(LPrivKeyBIO, nil, nil, nil);
    if LRsa = nil then
      raise Exception.Create('[RSA] Unable to load private key: ' + ERR_GetErrorMessage_OpenSSL);
  finally
    BIO_free(LPrivKeyBIO);
  end;

  try
    // Extract Private key from RSA object
    LPrivKey := EVP_PKEY_new();
    if EVP_PKEY_set1_RSA(LPrivKey, LRsa) <> 1 then
      raise Exception.Create('[RSA] Unable to extract private key: ' + ERR_GetErrorMessage_OpenSSL);
    try
      case AAlg of
        RS256: LSha := EVP_sha256();
        RS384: LSha := EVP_sha384();
        RS512: LSha := EVP_sha512();
      else
        raise Exception.Create('[RSA] Unsupported signing algorithm!');
      end;

      LCtx := _EVP_MD_CTX_create;
      try
        if EVP_DigestSignInit(LCtx, NIL, LSha, NIL, LPrivKey ) <> 1 then
          raise Exception.Create('[RSA] Unable to init context: ' + ERR_GetErrorMessage_OpenSSL);
        if EVP_DigestSignUpdate(LCtx, @AInput[0], Length(AInput) ) <> 1 then
          raise Exception.Create('[RSA] Unable to update context with payload: ' + ERR_GetErrorMessage_OpenSSL);

        // Get signature, first read signature len
        EVP_DigestSignFinal(LCtx, nil, @LLen);
        LSig := OPENSSL_malloc(LLen);
        try
          EVP_DigestSignFinal(LCtx, LSig, @LLen);
          SetLength(Result, LLen);
          Move(LSig^, Result[0], LLen);
        finally
          CRYPTO_free(LSig);
        end;
      finally
        _EVP_MD_CTX_destroy(LCtx);
      end;
    finally
      EVP_PKEY_free(LPrivKey);
    end;
  finally
    RSA_Free(LRsa);
  end;
end;

class function TRSA.Verify(const AInput, ASignature, AKeyOrCertificate: TBytes; AAlg: TRSAAlgorithm): Boolean;
var
  LPubKeyBIO: pBIO;
  LPubKey: pEVP_PKEY;
  LRsa: pRSA;
  LCtx: PEVP_MD_CTX;
  LSha: PEVP_MD;
begin
  if CompareMem(@PKCS1_X509_CERTIFICATE[1], @AKeyOrCertificate[0], Length(PKCS1_X509_CERTIFICATE)) then
    Result := VerifyWithCertificate(AInput, ASignature, AKeyOrCertificate, AAlg)
  else
  begin
    LoadOpenSSL;

    // Load Public RSA Key into RSA object
    LPubKeyBIO := BIO_new(BIO_s_mem);
    try
      BIO_write(LPubKeyBIO, @AKeyOrCertificate[0], Length(AKeyOrCertificate));
      if CompareMem(@PKCS1_SIGNATURE_PUBKEY[1], @AKeyOrCertificate[0], Length(PKCS1_SIGNATURE_PUBKEY)) then
        LRsa := PEM_read_bio_RSAPublicKey(LPubKeyBIO, nil, nil, nil)
      else
        LRsa := _PEM_read_bio_RSA_PUBKEY(LPubKeyBIO, nil, nil, nil);
      if LRsa = nil then
        raise Exception.Create('[RSA] Unable to load public key: ' + ERR_GetErrorMessage_OpenSSL);
    finally
      BIO_free(LPubKeyBIO);
    end;

    try
      // Extract Public key from RSA object
      LPubKey := EVP_PKEY_new();
      try
        if EVP_PKEY_set1_RSA(LPubKey, LRsa) <> 1 then
          raise Exception.Create('[RSA] Unable to extract public key: ' + ERR_GetErrorMessage_OpenSSL);

        case AAlg of
          RS256: LSha := EVP_sha256();
          RS384: LSha := EVP_sha384();
          RS512: LSha := EVP_sha512();
        else
          raise Exception.Create('[RSA] Unsupported signing algorithm!');
        end;

        LCtx := _EVP_MD_CTX_create;
        try
          if EVP_DigestVerifyInit(LCtx, NIL, LSha, NIL, LPubKey) <> 1 then
            raise Exception.Create('[RSA] Unable to init context: ' + ERR_GetErrorMessage_OpenSSL);
          if EVP_DigestVerifyUpdate(LCtx, @AInput[0], Length(AInput)) <> 1 then
            raise Exception.Create('[RSA] Unable to update context with payload: ' + ERR_GetErrorMessage_OpenSSL);

          Result := EVP_DigestVerifyFinal(LCtx, @ASignature[0], Length(ASignature)) = 1;
        finally
          _EVP_MD_CTX_destroy(LCtx);
        end;
      finally
        EVP_PKEY_free(LPubKey);
      end;
    finally
      RSA_Free(LRsa);
    end;
  end;
end;

class function TRSA.VerifyPrivateKey(const AKey: TBytes): Boolean;
var
  LPubKeyBIO: pBIO;
  LRsa: pRSA;
begin
  LoadOpenSSL;

  // Load Public RSA Key
  LPubKeyBIO := BIO_new(BIO_s_mem);
  try
    BIO_write(LPubKeyBIO, @AKey[0], Length(AKey));
    LRsa := PEM_read_bio_RSAPrivateKey(LPubKeyBIO, nil, nil, nil);
    Result := (LRsa <> nil);
    if Result then
      RSA_Free(LRsa);
  finally
    BIO_free(LPubKeyBIO);
  end;
end;

class function TRSA.VerifyPublicKey(const AKeyOrCertificate: TBytes): Boolean;
var
  LPubKeyBIO: pBIO;
  LRsa: pRSA;
begin
  if CompareMem(@PKCS1_X509_CERTIFICATE[1], @AKeyOrCertificate[0], Length(PKCS1_X509_CERTIFICATE)) then
    Result := VerifyCertificate(AKeyOrCertificate)
  else
  begin
    LoadOpenSSL;

    // Load Public RSA Key
    LPubKeyBIO := BIO_new(BIO_s_mem);
    try
      BIO_write(LPubKeyBIO, @AKeyOrCertificate[0], Length(AKeyOrCertificate));
      if CompareMem(@PKCS1_SIGNATURE_PUBKEY[1], @AKeyOrCertificate[0], Length(PKCS1_SIGNATURE_PUBKEY)) then
        LRsa := PEM_read_bio_RSAPublicKey(LPubKeyBIO, nil, nil, nil)
      else
        LRsa := _PEM_read_bio_RSA_PUBKEY(LPubKeyBIO, nil, nil, nil);
      Result := (LRsa <> nil);
      if Result then
        RSA_Free(LRsa);
    finally
      BIO_free(LPubKeyBIO);
    end;
  end;
end;

class function TRSA.VerifyWithCertificate(const AInput, ASignature, ACertificate: TBytes; AAlg: TRSAAlgorithm): Boolean;
var
  LCertificateBIO: pBIO;
  LX509: pX509;
  LPubKey: PEVP_PKEY;
  AlgID: integer;
  LCtx: PEVP_MD_CTX;
  LSha: PEVP_MD;
begin
  LoadOpenSSL;
  LCertificateBIO := BIO_new(BIO_s_mem);
  try
    BIO_write(LCertificateBIO, @ACertificate[0], Length(ACertificate));
    if not CompareMem(@PKCS1_X509_CERTIFICATE[1], @ACertificate[0], Length(PKCS1_X509_CERTIFICATE)) then
      raise Exception.Create('[CERT] No X509 certificate received');

    LX509 := PEM_read_bio_X509(LCertificateBIO, nil, nil, nil);
    if not Assigned(LX509) then
      raise Exception.Create('[CERT] Failure by X509 certificate loading');

    LPubKey := X509_PUBKEY_get(LX509.cert_info.key);
    if not Assigned(LPubKey) then
      raise Exception.Create('[CERT] Failure by public key extracting from X509 certificate');

    AlgID := OBJ_obj2nid(LX509.cert_info.key.algor.algorithm);
    if AlgID <> NID_rsaEncryption then
      raise Exception.Create('[CERT] Unsupported algorithm type in X509 public key (RSA expected)');

    case AAlg of
      RS256: LSha := EVP_sha256();
      RS384: LSha := EVP_sha384();
      RS512: LSha := EVP_sha512();
      else
        raise Exception.Create('[RSA] Unsupported signing algorithm!');
    end;

    LCtx := _EVP_MD_CTX_create;
    try
      if EVP_DigestVerifyInit(LCtx, nil, LSha, nil, LPubKey) <> 1 then
        raise Exception.Create('[RSA] Unable to init context: ' + ERR_GetErrorMessage_OpenSSL);
      if EVP_DigestVerifyUpdate(LCtx, @AInput[0], Length(AInput)) <> 1 then
        raise Exception.Create('[RSA] Unable to update context with payload: ' + ERR_GetErrorMessage_OpenSSL);

      Result := EVP_DigestVerifyFinal(LCtx, @ASignature[0], Length(ASignature)) = 1;
    finally
      _EVP_MD_CTX_destroy(LCtx);
    end;
  finally
    BIO_free(LCertificateBIO);
  end;
end;

class function TRSA.VerifyCertificate(const ACertificate: TBytes): Boolean;
var
  LCertificateBIO: pBIO;
  LX509: pX509;
  LPubKey: PEVP_PKEY;
  AlgID: integer;
begin
  LoadOpenSSL;
  LCertificateBIO := BIO_new(BIO_s_mem);
  try
    BIO_write(LCertificateBIO, @ACertificate[0], Length(ACertificate));
    if not CompareMem(@PKCS1_X509_CERTIFICATE[1], @ACertificate[0], Length(PKCS1_X509_CERTIFICATE)) then
      raise Exception.Create('[CERT] No X509 certificate received');

    LX509 := PEM_read_bio_X509(LCertificateBIO, nil, nil, nil);
    LPubKey := X509_PUBKEY_get(LX509.cert_info.key);
    AlgID := OBJ_obj2nid(LX509.cert_info.key.algor.algorithm);
    Result := Assigned(LX509) and Assigned(LPubKey) and (AlgID = NID_rsaEncryption);
  finally
    BIO_free(LCertificateBIO);
  end;
end;

class procedure TRSA.LoadOpenSSL;
begin
  if not IdSSLOpenSSLHeaders.Load then
    raise Exception.Create('[RSA] Unable to load OpenSSL libraries');

  if @EVP_DigestVerifyInit = nil then
    raise Exception.Create('[RSA] Please, use OpenSSL 1.0.0. or newer!');

  if GetCryptLibHandle <> 0 then
  begin
    _PEM_read_bio_RSA_PUBKEY := GetProcAddress(GetCryptLibHandle, 'PEM_read_bio_RSA_PUBKEY');
    if @_PEM_read_bio_RSA_PUBKEY = nil then
      raise Exception.Create('[RSA] Unable to get proc address for "PEM_read_bio_RSA_PUBKEY"');

    _EVP_MD_CTX_create := GetProcAddress(GetCryptLibHandle, 'EVP_MD_CTX_create');
    if @_EVP_MD_CTX_create = nil then
      raise Exception.Create('[RSA] Unable to get proc address for "EVP_MD_CTX_create"');

    _EVP_MD_CTX_destroy := GetProcAddress(GetCryptLibHandle, 'EVP_MD_CTX_destroy');
    if @_EVP_MD_CTX_create = nil then
      raise Exception.Create('[RSA] Unable to get proc address for "EVP_MD_CTX_destroy"');
  end;
end;

initialization
  TRSA._PEM_read_bio_RSA_PUBKEY := nil;
  TRSA._EVP_MD_CTX_create := nil;
  TRSA._EVP_MD_CTX_destroy := nil;

end.
