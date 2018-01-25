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

unit JOSE.Cryptography.RSA;

interface

uses
  System.SysUtils,
  IdGlobal,
  IdCTypes,
  IdSSLOpenSSLHeaders,
  JOSE.Encoding.Base64;


type
  TRSAAlgorithm = (RS256, RS384, RS512);
  TRSAAlgorithmHelper = record helper for TRSAAlgorithm
    procedure FromString(const AValue: string);
    function ToString: string;
  end;

  TRSA = class
  private
    class procedure LoadOpenSSL;
  public
    class function Sign(const AInput, AKey: TBytes; AAlg: TRSAAlgorithm): TBytes;
    class function Verify(const AInput, ASignature, AKey: TBytes; AAlg: TRSAAlgorithm): Boolean;
    class function VerifyPublicKey(const AKey: TBytes): Boolean;
    class function VerifyPrivateKey(const AKey: TBytes): Boolean;
  end;

implementation

uses
  System.AnsiStrings;

// Get OpenSSL error and message text
function ERR_GetErrorMessage_OpenSSL : String;
var locErrMsg: array [0..160] of Char;
begin
  ERR_error_string( ERR_get_error, @locErrMsg );
  result := String( System.AnsiStrings.StrPas( PAnsiChar(@locErrMsg) ) );
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

class function TRSA.Sign(const AInput, AKey: TBytes;
  AAlg: TRSAAlgorithm): TBytes;
var
  PrivKeyBIO: pBIO;
  PrivKey: pEVP_PKEY;
  rsa: pRSA;

  locBIO: pBIO;
  locCtx: PEVP_MD_CTX;
  locSHA: PEVP_MD;

  slen: Integer;
  sig: Pointer;
begin
  LoadOpenSSL;

  // Load Private RSA Key into RSA object
  PrivKeyBIO := BIO_new(BIO_s_mem);
  try
    BIO_write(PrivKeyBIO, @AKey[0], Length(AKey));
    rsa := PEM_read_bio_RSAPrivateKey(PrivKeyBIO, nil, nil, nil);
    if rsa = nil then
      raise Exception.Create('[RSA] Unable to load private key: '+ERR_GetErrorMessage_OpenSSL);
  finally
    BIO_free(PrivKeyBIO);
  end;

  // Extract Private key from RSA object
  PrivKey := EVP_PKEY_new();
  if EVP_PKEY_set1_RSA(PrivKey, rsa) <> 1 then
    raise Exception.Create('[RSA] Unable to extract private key: '+ERR_GetErrorMessage_OpenSSL);

  locBio := BIO_new( BIO_f_md );
  locSHA := nil;
  try
    // Create context. Use this strage hack since Indy library has no EVP_MD_CTX_create
    BIO_get_md_ctx( locBio, @locCtx );

    case AAlg of
      RS256: locSHA := EVP_sha256();
      RS384: locSHA := EVP_sha384();
      RS512: locSHA := EVP_sha512();
    end;

    if EVP_DigestSignInit( locCtx, NIL, locSHA, NIL, PrivKey ) <> 1 then
      raise Exception.Create('[RSA] Unable to init context: '+ERR_GetErrorMessage_OpenSSL);
    if EVP_DigestSignUpdate( locCtx, @AInput[0], Length(AInput) ) <> 1 then
      raise Exception.Create('[RSA] Unable to update context with payload: '+ERR_GetErrorMessage_OpenSSL);
    // Get signature, first read signature len
    EVP_DigestSignFinal( locCtx, nil, @slen );
    sig := OPENSSL_malloc(slen);
    try
      EVP_DigestSignFinal( locCtx, sig, @slen );
      setLength(Result, slen);
      move(sig^, Result[0], slen);
    finally
      CRYPTO_free(sig);
    end;
  finally
    BIO_free( locBio );
  end;
end;

class function TRSA.Verify(const AInput, ASignature, AKey: TBytes;
  AAlg: TRSAAlgorithm): Boolean;
var
  PubKeyBIO: pBIO;
  PubKey: pEVP_PKEY;
  rsa: pRSA;

  locBIO: pBIO;
  locCtx: PEVP_MD_CTX;
  locSHA: PEVP_MD;
begin
  LoadOpenSSL;

  Result := False;

  // Load Public RSA Key into RSA object
  PubKeyBIO := BIO_new(BIO_s_mem);
  try
    BIO_write(PubKeyBIO, @AKey[0], Length(AKey));
    rsa := PEM_read_bio_RSAPublicKey(PubKeyBIO, nil, nil, nil);
    if rsa = nil then
      raise Exception.Create('[RSA] Unable to load public key: '+ERR_GetErrorMessage_OpenSSL);
  finally
    BIO_free(PubKeyBIO);
  end;

  // Extract Public key from RSA object
  PubKey := EVP_PKEY_new();
  if EVP_PKEY_set1_RSA(PubKey,rsa) <> 1 then
    raise Exception.Create('[RSA] Unable to extract public key: '+ERR_GetErrorMessage_OpenSSL);

  locBio := BIO_new( BIO_f_md );
  locSHA := nil;
  try
    // Create context. Use this strage hack since Indy library has no EVP_MD_CTX_create
    BIO_get_md_ctx( locBio, @locCtx );

    case AAlg of
      RS256: locSHA := EVP_sha256();
      RS384: locSHA := EVP_sha384();
      RS512: locSHA := EVP_sha512();
    end;

    if EVP_DigestVerifyInit( locCtx, NIL, locSHA, NIL, PubKey ) <> 1 then
      raise Exception.Create('[RSA] Unable to init context: '+ERR_GetErrorMessage_OpenSSL);
    if EVP_DigestVerifyUpdate( locCtx, @AInput[0], Length(AInput) ) <> 1 then
      raise Exception.Create('[RSA] Unable to update context with payload: '+ERR_GetErrorMessage_OpenSSL);
    result := ( EVP_DigestVerifyFinal( locCtx, PAnsiChar(@ASignature[0]), length(ASignature) ) = 1 );
  finally
    BIO_free( locBio );
  end;
end;

class function TRSA.VerifyPrivateKey(const AKey: TBytes): Boolean;
var
  PubKeyBIO: pBIO;
  rsa: pRSA;
begin
  LoadOpenSSL;

  // Load Public RSA Key
  PubKeyBIO := BIO_new(BIO_s_mem);
  try
    BIO_write(PubKeyBIO, @AKey[0], Length(AKey));
    rsa := PEM_read_bio_RSAPrivateKey(PubKeyBIO, nil, nil, nil);
    Result := (rsa <> nil);
  finally
    BIO_free(PubKeyBIO);
  end;
end;

class function TRSA.VerifyPublicKey(const AKey: TBytes): Boolean;
var
  PubKeyBIO: pBIO;
  rsa: pRSA;
begin
  LoadOpenSSL;

  // Load Public RSA Key
  PubKeyBIO := BIO_new(BIO_s_mem);
  try
    BIO_write(PubKeyBIO, @AKey[0], Length(AKey));
    rsa := PEM_read_bio_RSAPublicKey(PubKeyBIO, nil, nil, nil);
    Result := (rsa <> nil);
  finally
    BIO_free(PubKeyBIO);
  end;
end;

class procedure TRSA.LoadOpenSSL;
begin
  if not IdSSLOpenSSLHeaders.Load then
    raise Exception.Create('[RSA] Unable to load OpenSSL DLLs');

  if @EVP_DigestVerifyInit = nil then
    raise Exception.Create('[RSA] Please, use OpenSSL 1.0.0. or newer!');
end;

end.
