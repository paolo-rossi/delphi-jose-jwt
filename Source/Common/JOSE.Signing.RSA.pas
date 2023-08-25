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

unit JOSE.Signing.RSA;

{$I JOSE.inc}

interface

{$IFDEF RSA_SIGNING}

uses
  System.SysUtils,
  IdGlobal, IdCTypes,
  IdSSLOpenSSLHeaders,
  JOSE.OpenSSL.Headers,
  JOSE.Signing.Base,
  JOSE.Encoding.Base64;

type
  TRSAAlgorithm = (RS256, RS384, RS512);
  TRSAAlgorithmHelper = record helper for TRSAAlgorithm
    procedure FromString(const AValue: string);
    function ToString: string;
  end;

  TRSA = class(TSigningBase)
  private
    class function RSAKeyFromEVP(AKey: PEVP_PKEY): PRSA;

    class function LoadPublicKey(const AKey: TBytes): PRSA;
    class function LoadPrivateKey(const AKey: TBytes): PRSA;
    class function LoadRSAPublicKeyFromCert(const ACertificate: TBytes): PRSA;

    class function InternalSign(const AInput: TBytes; AKey: PRSA; AAlg: TRSAAlgorithm): TBytes;
    class function InternalVerify(const AInput, ASignature: TBytes; AKey: PRSA; AAlg: TRSAAlgorithm): Boolean;
  public
    class function Sign(const AInput, AKey: TBytes; AAlg: TRSAAlgorithm): TBytes;
    class function Verify(const AInput, ASignature, AKey: TBytes; AAlg: TRSAAlgorithm): Boolean;
    class function VerifyWithCertificate(const AInput, ASignature, ACertificate: TBytes; AAlg: TRSAAlgorithm): Boolean;

    class function VerifyPublicKey(const AKey: TBytes): Boolean;
    class function VerifyPrivateKey(const AKey: TBytes): Boolean;
  end;

{$ENDIF}

implementation

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

{ TRSA }

class function TRSA.InternalSign(const AInput: TBytes; AKey: PRSA; AAlg: TRSAAlgorithm): TBytes;
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
    end
  else
    raise ESignException.Create('[RSA] Unsupported signing algorithm!');
  end;

  LRsaLen := JoseSSL.RSA_size(AKey);
  SetLength(Result, LRsaLen);
  if JoseSSL.RSA_sign(LNID, @LHash[0], LShaLen, @Result[0], @LRsaLen, AKey) = 0 then
    raise ESignException.Create('[RSA] Unable to sign RSA message digest');
end;

class function TRSA.InternalVerify(const AInput, ASignature: TBytes; AKey: PRSA; AAlg: TRSAAlgorithm): Boolean;
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
    end
  else
    raise ESignException.Create('[RSA] Unsupported signing algorithm!');
  end;
  LResult := JoseSSL.RSA_verify(LNID, @LHash[0], LShaLen, @ASignature[0], Length(ASignature), AKey);

  Result := LResult = 1;
end;

class function TRSA.LoadPrivateKey(const AKey: TBytes): PRSA;
var
  LBio: PBIO;
begin
  // Load Private RSA Key into RSA object
  LBio := BIO_new(BIO_s_mem);
  try
    BIO_write(LBio, @AKey[0], Length(AKey));
    Result := PEM_read_bio_RSAPrivateKey(LBio, nil, nil, nil);
    if Result = nil then
      raise ESignException.Create('[RSA] Unable to load private key: ' + JOSESSL.GetLastError);
  finally
    BIO_free(LBio);
  end;
end;

class function TRSA.LoadPublicKey(const AKey: TBytes): PRSA;
var
  LBio: PBIO;
  LPubKey: TBytes;
begin
  // Load Public RSA Key into RSA object
  LBio := BIO_new(BIO_s_mem);
  try
    if CompareMem(@PEM_X509_CERTIFICATE[0], @AKey[0], Length(PEM_X509_CERTIFICATE)) then
    begin
      LPubKey := Self.PublicKeyFromCertificate(AKey);
      BIO_write(LBio, @LPubKey[0], Length(LPubKey));
      Result := JoseSSL.PEM_read_bio_RSA_PUBKEY(LBio, nil, nil, nil);
    end else
    begin
      BIO_write(LBio, @AKey[0], Length(AKey));
      if CompareMem(@PEM_PUBKEY_PKCS1[0], @AKey[0], Length(PEM_PUBKEY_PKCS1)) then
        Result := PEM_read_bio_RSAPublicKey(LBio, nil, nil, nil)
      else
        Result := JoseSSL.PEM_read_bio_RSA_PUBKEY(LBio, nil, nil, nil);
    end;

    if Result = nil then
      raise ESignException.Create('[RSA] Unable to load public key: ' + JOSESSL.GetLastError);
  finally
    BIO_free(LBio);
  end;
end;

class function TRSA.LoadRSAPublicKeyFromCert(const ACertificate: TBytes): PRSA;
var
  LKey: PEVP_PKEY;
begin
  LKey := LoadPublicKeyFromCert(ACertificate, NID_rsaEncryption);
  try
    Result := RSAKeyFromEVP(LKey);
  finally
    EVP_PKEY_free(LKey);
  end;
end;

class function TRSA.RSAKeyFromEVP(AKey: PEVP_PKEY): PRSA;
begin
  Result := EVP_PKEY_get1_RSA(AKey);
  if not Assigned(Result) then
    raise ESignException.Create('[RSA] Error extracting RSA key from EVP_PKEY');
end;

class function TRSA.Sign(const AInput, AKey: TBytes; AAlg: TRSAAlgorithm): TBytes;
var
  LRsa: PRSA;
begin
  LoadOpenSSL;

  LRsa := LoadPrivateKey(AKey);
  try
    Result := InternalSign(AInput, LRsa, AAlg);
  finally
    RSA_Free(LRsa);
  end;
end;

class function TRSA.Verify(const AInput, ASignature, AKey: TBytes; AAlg: TRSAAlgorithm): Boolean;
var
  LRsa: PRSA;
begin
  LoadOpenSSL;

  LRsa := LoadPublicKey(AKey);
  try
    Result := InternalVerify(AInput, ASignature, LRsa, AAlg);
  finally
    RSA_Free(LRsa);
  end;
end;

class function TRSA.VerifyPrivateKey(const AKey: TBytes): Boolean;
var
  LBio: PBIO;
  LRsa: PRSA;
begin
  LoadOpenSSL;

  // Load Private RSA Key
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

class function TRSA.VerifyPublicKey(const AKey: TBytes): Boolean;
var
  LBio: PBIO;
  LRsa: PRSA;
  LPubKey: TBytes;
begin
  LoadOpenSSL;

  // Load Public RSA Key
  LBio := BIO_new(BIO_s_mem);
  try
    if CompareMem(@PEM_X509_CERTIFICATE[0], @AKey[0], Length(PEM_X509_CERTIFICATE)) then
    begin
      LPubKey := Self.PublicKeyFromCertificate(AKey);
      BIO_write(LBio, @LPubKey[0], Length(LPubKey));
      LRsa := JoseSSL.PEM_read_bio_RSA_PUBKEY(LBio, nil, nil, nil);
    end else
    begin
      BIO_write(LBio, @AKey[0], Length(AKey));
      if CompareMem(@PEM_PUBKEY_PKCS1[0], @AKey[0], Length(PEM_PUBKEY_PKCS1)) then
        LRsa := PEM_read_bio_RSAPublicKey(LBio, nil, nil, nil)
      else
        LRsa := JoseSSL.PEM_read_bio_RSA_PUBKEY(LBio, nil, nil, nil);
    end;

    Result := (LRsa <> nil);
    if Result then
      RSA_Free(LRsa);
  finally
    BIO_free(LBio);
  end;
end;

class function TRSA.VerifyWithCertificate(const AInput, ASignature, ACertificate: TBytes; AAlg: TRSAAlgorithm): Boolean;
var
  LRsa: PRSA;
begin
  LoadOpenSSL;

  LRsa := LoadRSAPublicKeyFromCert(ACertificate);
  try
    Result := InternalVerify(AInput, ASignature, LRsa, AAlg);
  finally
    RSA_free(LRsa);
  end;
end;

{$ENDIF}

end.
