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

unit JOSE.Signing.ECDSA;

interface

uses
  System.SysUtils,
  System.StrUtils,
  IdGlobal, IdCTypes,
  IdSSLOpenSSLHeaders,
  JOSE.OpenSSL.Headers,
  JOSE.Types.Utils,
  JOSE.Signing.Base,
  JOSE.Encoding.Base64;

type
  TECDSAAlgorithm = (ES256, ES256K, ES384, ES512);
  TECDSAAlgorithmHelper = record helper for TECDSAAlgorithm
    procedure FromString(const AValue: string);
    function ToString: string;
  end;

  TECDSA = class(TSigningBase)
  private
    class function LoadPublicKey(const AKey: TBytes): PEVP_PKEY;
    class function LoadPrivateKey(const AKey: TBytes): PEVP_PKEY;
    class function LoadPublicKeyFromCert(const ACertificate: TBytes): PEVP_PKEY;

    class function InternalSign(const AInput: TBytes; AKey: PEVP_PKEY; AAlg: TECDSAAlgorithm): TBytes;
    class function InternalVerify(const AInput, ASignature: TBytes; APublicKey: PEVP_PKEY; AAlg: TECDSAAlgorithm): Boolean;
  public
    class function Sign(const AInput, APrivateKey: TBytes; AAlg: TECDSAAlgorithm): TBytes;
    class function Verify(const AInput, ASignature, APublicKey: TBytes; AAlg: TECDSAAlgorithm): Boolean;
    class function VerifyWithCertificate(const AInput, ASignature, ACertificate: TBytes; AAlg: TECDSAAlgorithm): Boolean;

    class function VerifyPublicKey(const AKey: TBytes): Boolean;
    class function VerifyPrivateKey(const AKey: TBytes): Boolean;
  end;


implementation

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

{ TECDSA }

class function TECDSA.InternalVerify(const AInput, ASignature: TBytes; APublicKey:
    PEVP_PKEY; AAlg: TECDSAAlgorithm): Boolean;
var
  LECKey: PEC_KEY;
  LSig: PECDSA_SIG;
  LPSig: Pointer;
begin
  LoadOpenSSL;
  LSig := nil;

  // Get the actual ec_key
  LECKey := EVP_PKEY_get1_EC_KEY(APublicKey);
  if LECKey = nil then
    raise Exception.Create('[ECDSA] Error getting memory for ECDSA');
  try
    LPSig := @ASignature[0];
    LSig := JoseSSL.d2i_ECDSA_SIG(@LSig, @LPSig, Length(ASignature));
    if LSig = nil then
      raise Exception.Create('[ECDSA] Can''t decode ECDSA signature');
    try
      Result := JoseSSL.ECDSA_do_verify(@AInput[0], Length(AInput), LSig, LECKey) = 1;
    finally
      JoseSSL.ECDSA_SIG_free(LSig);
    end;

  finally
    JoseSSL.EC_KEY_free(LECKey);
  end;
end;

class function TECDSA.LoadPrivateKey(const AKey: TBytes): PEVP_PKEY;
var
  LBIO: PBIO;
begin
  LoadOpenSSL;

  // Load Private Key into ECDSA object
  LBIO := BIO_new(BIO_s_mem);
  try
    BIO_write(LBIO, @AKey[0], Length(AKey));
    Result := PEM_read_bio_PrivateKey(LBIO, nil, nil, nil);
    if Result = nil then
      raise ESignException.Create('[ECDSA] Unable to load private key: ' + JOSESSL.GetLastError);
    //LKeyType := EVP_PKEY_id(LKey);
  finally
    BIO_free(LBIO);
  end;
end;

class function TECDSA.LoadPublicKey(const AKey: TBytes): PEVP_PKEY;
var
  LKeyBuffer: PBIO;
begin
  LoadOpenSSL;

  // Load Public ECDSA Key into ECDSA object
  LKeyBuffer := BIO_new(BIO_s_mem);
  try
    // Check Key prologue
    BIO_write(LKeyBuffer, @AKey[0], Length(AKey));

    Result := JoseSSL.PEM_read_bio_PUBKEY(LKeyBuffer, nil, nil, nil);
    if Result = nil then
      raise Exception.Create('[ECDSA] Unable to load public key: ' + JOSESSL.GetLastError);
  finally
    BIO_free(LKeyBuffer);
  end;
end;

class function TECDSA.LoadPublicKeyFromCert(const ACertificate: TBytes): PEVP_PKEY;
var
  LCer: PX509;
  LAlg: Integer;
begin
  LoadOpenSSL;

  LCer := LoadCertificate(ACertificate);
  try
    LAlg := OBJ_obj2nid(LCer.cert_info.key.algor.algorithm);
    if LAlg <> JoseSSL.NID_X9_62_id_ecPublicKey then
      raise ESignException.Create('[ECDSA] Unsupported algorithm type in X509 public key (RSA expected)');

    Result := X509_PUBKEY_get(LCer.cert_info.key);
    if not Assigned(Result) then
      raise ESignException.Create('[ECDSA] Error extracting public key from X509 certificate');
  finally
    X509_free(LCer);
  end;
end;

class function TECDSA.Sign(const AInput, APrivateKey: TBytes; AAlg: TECDSAAlgorithm): TBytes;
var
  LKey: PEVP_PKEY;
begin
  LoadOpenSSL;
  Result := [];

  LKey := LoadPrivateKey(APrivateKey);
  try
    Result := InternalSign(AInput, LKey, AAlg);
  finally
    EVP_PKEY_free(LKey);
  end;
end;

class function TECDSA.InternalSign(const AInput: TBytes; AKey: PEVP_PKEY; AAlg: TECDSAAlgorithm): TBytes;
var
  LSigPointer: Pointer;
  LECKey: PEC_KEY;
  LSig: PECDSA_SIG;
begin
  LoadOpenSSL;

  Result := [];
  // Convert to a RAW format for the R/S
  LECKey := EVP_PKEY_get1_EC_KEY(AKey);
  if LECKey = nil then
    raise ESignException.Create('[ECDSA] Error getting EC Key: ' + JOSESSL.GetLastError);
  try
    LSig := JoseSSL.ECDSA_do_sign(@AInput[0], Length(AInput), LECKey);
    if LSig = nil then
      raise ESignException.Create('[ECDSA] Digest signing failed: ' + JOSESSL.GetLastError);
    try
      SetLength(Result, JoseSSL.ECDSA_size(LECKey));

      LSigPointer := @Result[0];
      JoseSSL.i2d_ECDSA_SIG(LSig, @LSigPointer);
    finally
      JoseSSL.ECDSA_SIG_free(LSig);
    end;
  finally
    JoseSSL.EC_KEY_free(LECKey);
  end;
end;

class function TECDSA.Verify(const AInput, ASignature, APublicKey: TBytes; AAlg: TECDSAAlgorithm): Boolean;
var
  LPubKey: PEVP_PKEY;
begin
  LoadOpenSSL;

  LPubKey := LoadPublicKey(APublicKey);
  try
    Result := InternalVerify(AInput, ASignature, LPubKey, AAlg);
  finally
    EVP_PKEY_free(LPubKey);
  end;
end;

class function TECDSA.VerifyPrivateKey(const AKey: TBytes): Boolean;
var
  LBio: PBIO;
  LPrivKey: PEVP_PKEY;
begin
  LoadOpenSSL;

  // Load Private Key
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

class function TECDSA.VerifyPublicKey(const AKey: TBytes): Boolean;
var
  LBio: PBIO;
  LKey: PEVP_PKEY;
begin
  LoadOpenSSL;

  // Load Public Key
  LBio := BIO_new(BIO_s_mem);
  try
    BIO_write(LBio, @AKey[0], Length(AKey));
    LKey := JoseSSL.PEM_read_bio_PUBKEY(LBio, nil, nil, nil);

    Result := (LKey <> nil);
    if Result then
      EVP_PKEY_free(LKey);
  finally
    BIO_free(LBio);
  end;
end;

class function TECDSA.VerifyWithCertificate(const AInput, ASignature, ACertificate: TBytes; AAlg: TECDSAAlgorithm): Boolean;
var
  LKey: PEVP_PKEY;
begin
  LoadOpenSSL;

  LKey := LoadPublicKeyFromCert(ACertificate);
  try
    Result := InternalVerify(AInput, ASignature, LKey, AAlg);
  finally
    EVP_PKEY_free(LKey);
  end;
end;

end.
