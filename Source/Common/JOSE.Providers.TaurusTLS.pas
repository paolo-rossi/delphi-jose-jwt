{******************************************************************************}
{                                                                              }
{  Delphi JOSE Library                                                        }
{  Copyright (c) 2015 Paolo Rossi                                             }
{  https://github.com/paolo-rossi/delphi-jose-jwt                             }
{                                                                              }
{******************************************************************************}
{                                                                              }
{  Licensed under the Apache License, Version 2.0 (the "License");            }
{  you may not use this file except in compliance with the License.           }
{  You may obtain a copy of the License at                                    }
{                                                                              }
{      http://www.apache.org/licenses/LICENSE-2.0                             }
{                                                                              }
{  Unless required by applicable law or agreed to in writing, software        }
{  distributed under the License is distributed on an "AS IS" BASIS,          }
{  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.   }
{  See the License for the specific language governing permissions and        }
{  limitations under the License.                                             }
{                                                                              }
{******************************************************************************}

/// <summary>
///   OpenSSL 3.x/4.x-capable crypto provider stack, backed by the TaurusTLS
///   binding for Indy (vendored under Libs\TaurusTLS). Unlike
///   JOSE.Providers.Default (which pokes raw RSA/EC_KEY struct fields and
///   only reliably targets OpenSSL 1.0.x/1.1.x), every RSA/EC key access here
///   goes through OpenSSL's accessor functions (RSA_get0_key/RSA_set0_key,
///   EC_KEY_get0_public_key, EC_POINT_get/set_affine_coordinates, ...),
///   because OpenSSL 3.0 made those structs opaque. TaurusTLS itself already
///   probes for "-4" (OpenSSL 4.x) libcrypto/libssl DLLs before falling back
///   to "-3"/"-1_1"/"-1" (see TaurusTLSConsts.DefaultLibVersions).
///
///   Optional, opt-in stack: NOT part of the .dpk package `contains` list and
///   NOT auto-registered. Consumers add Libs\TaurusTLS's runtime package (and
///   this unit) to their project manually and call
///   TJOSETaurusTLSProviders.Register, exactly like TJOSECryptoLibProviders.
/// </summary>
unit JOSE.Providers.TaurusTLS;

{$I ..\JOSE.inc}

interface

uses
  System.SysUtils,
  JOSE.Types.Bytes,
  JOSE.Providers.Interfaces,
  JOSE.Crypto.Algorithms;

{$IFDEF RSA_SIGNING}

type
  /// <summary>X.509 public-key extraction/verification via TaurusTLS.</summary>
  TTaurusTLSCertificateProvider = class(TInterfacedObject, IJOSECertificateProvider)
  public
    function PublicKeyFromCertificate(const ACertificate: TBytes): TBytes;
    function VerifyCertificate(const ACertificate: TBytes; AExpected: TJOSECertificatePublicKey): Boolean;
  end;

  /// <summary>RSA signing/verification (RS256/384/512) via TaurusTLS.</summary>
  TTaurusTLSRSAProvider = class(TInterfacedObject, IJOSESignerRSA)
  private
    FCertificate: IJOSECertificateProvider;
    class function StartsWith(const ABuf, APrefix: TBytes): Boolean; static;
    function LoadPrivateKey(const AKey: TBytes): Pointer;
    function LoadPublicKey(const AKey: TBytes): Pointer;
    function LoadRSAPublicKeyFromCert(const ACertificate: TBytes): Pointer;
    function InternalSign(const AInput: TBytes; AKey: Pointer; AAlg: TRSAAlgorithm): TBytes;
    function InternalVerify(const AInput, ASignature: TBytes; AKey: Pointer; AAlg: TRSAAlgorithm): Boolean;
  public
    constructor Create(const ACertificate: IJOSECertificateProvider);
    function Sign(const AInput, AKey: TBytes; AAlg: TRSAAlgorithm): TBytes;
    function Verify(const AInput, ASignature, AKey: TBytes; AAlg: TRSAAlgorithm): Boolean;
    function VerifyWithCertificate(const AInput, ASignature, ACertificate: TBytes; AAlg: TRSAAlgorithm): Boolean;
    function VerifyPublicKey(const AKey: TBytes): Boolean;
    function VerifyPrivateKey(const AKey: TBytes): Boolean;
  end;

  /// <summary>ECDSA signing/verification (ES256/384/512/256K) via TaurusTLS.</summary>
  TTaurusTLSECDSAProvider = class(TInterfacedObject, IJOSESignerECDSA)
  private
    FCertificate: IJOSECertificateProvider;
    function LoadPrivateKey(const AKey: TBytes): Pointer;
    function LoadPublicKey(const AKey: TBytes): Pointer;
    function InternalSign(const AInput: TBytes; AKey: Pointer; AAlg: TECDSAAlgorithm): TBytes;
    function InternalVerify(const AInput, ASignature: TBytes; APublicKey: Pointer; AAlg: TECDSAAlgorithm): Boolean;
    function HashFromBytes(const AInput: TBytes; AAlg: TECDSAAlgorithm): TBytes;
    function Sig2OctetSequence(ASignature: Pointer; AAlg: TECDSAAlgorithm): TBytes;
    function OctetSequence2Sig(const ASignature: TBytes; AAlg: TECDSAAlgorithm): Pointer;
  public
    constructor Create(const ACertificate: IJOSECertificateProvider);
    function Sign(const AInput, APrivateKey: TBytes; AAlg: TECDSAAlgorithm): TBytes;
    function Verify(const AInput, ASignature, APublicKey: TBytes; AAlg: TECDSAAlgorithm): Boolean;
    function VerifyWithCertificate(const AInput, ASignature, ACertificate: TBytes; AAlg: TECDSAAlgorithm): Boolean;
    function VerifyPublicKey(const AKey: TBytes): Boolean;
    function VerifyPrivateKey(const AKey: TBytes): Boolean;
  end;

  /// <summary>Raw RSA key import/export to/from PEM (JWK support), accessor-based (RSA_get0_key/RSA_set0_key/...).</summary>
  TTaurusTLSRSAKeyMaterialProvider = class(TInterfacedObject, IJOSERSAKeyMaterialProvider)
  public
    function ImportPEM(const APEM: TBytes): TJOSERSAKeyMaterial;
    function ExportPEM(const AKeyMaterial: TJOSERSAKeyMaterial; AIncludePrivate: Boolean): TBytes;
  end;

  /// <summary>Raw EC key import/export to/from PEM (JWK support) via TaurusTLS.</summary>
  TTaurusTLSECKeyMaterialProvider = class(TInterfacedObject, IJOSEECKeyMaterialProvider)
  private
    class function CurveToNID(ACurve: TECCurve): Integer; static;
    class function NIDToCurve(ANID: Integer): TECCurve; static;
  public
    function ImportPEM(const APEM: TBytes): TJOSEECKeyMaterial;
    function ExportPEM(const AKeyMaterial: TJOSEECKeyMaterial; AIncludePrivate: Boolean): TBytes;
  end;

{$ENDIF}

  /// <summary>Wires TaurusTLS-backed implementations (OpenSSL 3.x/4.x capable) into TJOSEProviders.</summary>
  TJOSETaurusTLSProviders = class
  public
    class procedure Register; static;
    class procedure Unregister; static;
  end;

implementation

uses
{$IFDEF RSA_SIGNING}
  IdCTypes,
  TaurusTLS,
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_bio,
  TaurusTLSHeaders_bn,
  TaurusTLSHeaders_rsa,
  TaurusTLSHeaders_ec,
  TaurusTLSHeaders_evp,
  TaurusTLSHeaders_pem,
  TaurusTLSHeaders_x509,
  TaurusTLSHeaders_sha,
  TaurusTLSHeaders_obj_mac,
  JOSE.Signing.Base,
{$ENDIF}
  JOSE.Providers,
  JOSE.Providers.Default;

{$IFDEF RSA_SIGNING}

resourcestring
  SJOSETaurusTLSLoadFailed = '[TaurusTLS] Unable to load the OpenSSL libraries';
  SJOSETaurusTLSNotAValidCertificate = '[TaurusTLS] Not a valid X509 certificate';
  SJOSETaurusTLSCertLoadError = '[TaurusTLS] Error loading X509 certificate';
  SJOSETaurusTLSCertKeyAlgMismatch = '[TaurusTLS] Certificate public key algorithm does not match expected type';
  SJOSETaurusTLSCertExtractPublicKeyError = '[TaurusTLS] Error extracting public key from X509 certificate';
  SJOSETaurusTLSRSAUnsupportedAlgorithm = '[RSA] Unsupported signing algorithm!';
  SJOSETaurusTLSRSASignFailed = '[RSA] Unable to sign RSA message digest';
  SJOSETaurusTLSRSALoadPrivateKeyError = '[RSA] Unable to load private key';
  SJOSETaurusTLSRSALoadPublicKeyError = '[RSA] Unable to load public key';
  SJOSETaurusTLSRSAExtractFromEVPError = '[RSA] Error extracting RSA key from EVP_PKEY';
  SJOSETaurusTLSECDSAUnsupportedAlgorithm = '[ECDSA] Unsupported signing algorithm!';
  SJOSETaurusTLSECDSALoadPrivateKeyError = '[ECDSA] Unable to load private key';
  SJOSETaurusTLSECDSALoadPublicKeyError = '[ECDSA] Unable to load public key';
  SJOSETaurusTLSECDSAKeyError = '[ECDSA] Error getting EC Key';
  SJOSETaurusTLSECDSASignFailed = '[ECDSA] Digest signing failed';
  SJOSETaurusTLSJWKMissingKeyComponent = '[JWK] Missing required key component';
  SJOSETaurusTLSJWKBignumConversionError = '[JWK] Unable to convert key component to BIGNUM';
  SJOSETaurusTLSJWKECNoGroup = '[JWK] EC key has no group/curve';
  SJOSETaurusTLSJWKECNoPublicPoint = '[JWK] EC key has no public point';
  SJOSETaurusTLSJWKECReadPublicPointError = '[JWK] Unable to read the EC public point';
  SJOSETaurusTLSJWKECCreateKeyError = '[JWK] Unable to create an EC key for the requested curve';
  SJOSETaurusTLSJWKECInvalidPublicPoint = '[JWK] Invalid EC public point';
  SJOSETaurusTLSJWKECSetPublicKeyError = '[JWK] Unable to set the EC public key';
  SJOSETaurusTLSJWKECSetPrivateKeyError = '[JWK] Unable to set the EC private key';
  SJOSETaurusTLSJWKEmptyPEMData = '[JWK] Empty PEM data';
  SJOSETaurusTLSJWKUnrecognizedPEMFormat = '[JWK] Unable to parse PEM: unrecognized or unsupported key format';
  SJOSETaurusTLSJWKPEMContainsECNotRSA = '[JWK] PEM contains an EC key, not an RSA key';
  SJOSETaurusTLSJWKUnsupportedPEMKeyType = '[JWK] Unsupported PEM key type';
  SJOSETaurusTLSJWKAllocateRSAError = '[JWK] Unable to allocate an RSA key';
  SJOSETaurusTLSJWKWriteRSAPrivateError = '[JWK] Unable to write the RSA private key PEM';
  SJOSETaurusTLSJWKWriteRSAPublicError = '[JWK] Unable to write the RSA public key PEM';
  SJOSETaurusTLSJWKUnsupportedECCurve = '[JWK] Unsupported EC curve';
  SJOSETaurusTLSJWKUnsupportedECCurveNID = '[JWK] Unsupported EC curve (NID %d)';
  SJOSETaurusTLSJWKPEMContainsRSANotEC = '[JWK] PEM contains an RSA key, not an EC key';
  SJOSETaurusTLSJWKPEMNoECKey = '[JWK] PEM does not contain an EC key';
  SJOSETaurusTLSJWKExtractECKeyError = '[JWK] Unable to extract the EC key from the PEM';
  SJOSETaurusTLSJWKAllocateEVPPKeyError = '[JWK] Unable to allocate an EVP_PKEY';
  SJOSETaurusTLSJWKWrapECKeyError = '[JWK] Unable to wrap the EC key';
  SJOSETaurusTLSJWKWriteECPrivateError = '[JWK] Unable to write the EC private key PEM';
  SJOSETaurusTLSJWKWriteECPublicError = '[JWK] Unable to write the EC public key PEM';

{ Shared helpers }

/// <summary>OpenSSL's BN_num_bytes is a macro ((BN_num_bits(a)+7)/8), not an exported symbol.</summary>
function TaurusBNNumBytes(ABN: PBIGNUM): Integer;
begin
  Result := (BN_num_bits(ABN) + 7) div 8;
end;

function BignumToBytes(ABN: PBIGNUM): TBytes;
var
  LLen: Integer;
begin
  Result := nil;
  if not Assigned(ABN) then
    Exit;

  LLen := TaurusBNNumBytes(ABN);
  SetLength(Result, LLen);
  if LLen > 0 then
    BN_bn2bin(ABN, PByte(@Result[0]));
end;

/// <summary>
///   <c>BignumToBytes</c> left-padded to <paramref name="ALength" /> bytes. EC key components are
///   fixed-width octet strings - the coordinate size of the curve for x/y (RFC 7518 6.2.1.2) and
///   the order size for d (RFC 7518 6.2.2.1) - but <c>BN_bn2bin</c> emits the minimal encoding, so
///   a component with a leading zero byte would otherwise come out short. Short components are not
///   just non-conformant on the wire: they also change the canonical JSON that the RFC 7638
///   thumbprint is computed over.
/// </summary>
function BignumToFixedBytes(ABN: PBIGNUM; ALength: Integer): TBytes;
var
  LRaw: TBytes;
begin
  LRaw := BignumToBytes(ABN);
  if Length(LRaw) >= ALength then
    Exit(LRaw);

  SetLength(Result, ALength);
  FillChar(Result[0], ALength, 0);
  if Length(LRaw) > 0 then
    Move(LRaw[0], Result[ALength - Length(LRaw)], Length(LRaw));
end;

function BytesToBignum(const AValue: TBytes): PBIGNUM;
begin
  if Length(AValue) = 0 then
    raise ESignException.Create(SJOSETaurusTLSJWKMissingKeyComponent);

  Result := BN_bin2bn(PByte(@AValue[0]), Length(AValue), nil);
  if not Assigned(Result) then
    raise ESignException.Create(SJOSETaurusTLSJWKBignumConversionError);
end;

function NewBIOFromBytes(const AData: TBytes): PBIO;
begin
  Result := BIO_new(BIO_s_mem);
  if Length(AData) > 0 then
    BIO_write(Result, AData[0], Length(AData));
end;

function ReadBIOToBytes(ABio: PBIO): TBytes;
var
  LBuffer: TBytes;
  LBytesRead, LTotal: Integer;
begin
  Result := [];
  LTotal := 0;
  SetLength(LBuffer, 255);
  repeat
    LBytesRead := BIO_read(ABio, LBuffer[0], 255);
    if LBytesRead > 0 then
    begin
      SetLength(Result, LTotal + LBytesRead);
      Move(LBuffer[0], Result[LTotal], LBytesRead);
      Inc(LTotal, LBytesRead);
    end;
  until LBytesRead <= 0;
end;

/// <summary>Extracts the RSA/EC NID for a certificate's public key without touching the
///   (opaque-in-3.x) X509 struct fields: X509_get0_pubkey + EVP_PKEY_base_id.</summary>
function CertPublicKeyBaseId(ACert: PX509): Integer;
var
  LPKey: PEVP_PKEY;
begin
  LPKey := X509_get0_pubkey(ACert);
  if not Assigned(LPKey) then
    Exit(0);
  Result := EVP_PKEY_base_id(LPKey);
end;

function ExpectedNidForCertPublicKey(const AExpected: TJOSECertificatePublicKey): Integer;
begin
  case AExpected of
    TJOSECertificatePublicKey.RSA: Result := NID_rsaEncryption;
    TJOSECertificatePublicKey.EC:  Result := NID_X9_62_id_ecPublicKey;
  else
    Result := 0;
  end;
end;

type
  TTaurusTLSPem = class
  strict private
    class var
      FPEM_X509_CERTIFICATE: TBytes;
      FPEM_PUBKEY_PKCS1: TBytes;
    class constructor Create;
  public
    class procedure LoadOpenSSL;
    class function LoadCertificate(const ACertificate: TBytes): PX509;
    class function LoadPublicKeyFromCert(const ACertificate: TBytes; AExpected: TJOSECertificatePublicKey): PEVP_PKEY; overload;
    class function LoadPublicKeyFromCert(const ACertificate: TBytes): PEVP_PKEY; overload;
    class function PublicKeyPemBytesFromKeyOrCert(const AKey: TBytes; const ACert: IJOSECertificateProvider): TBytes;
    class function PublicKeyFromCertificate(const ACertificate: TBytes): TBytes;
    class function VerifyCertificate(const ACertificate: TBytes; AExpected: TJOSECertificatePublicKey): Boolean;
    class property PEM_PUBKEY_PKCS1: TBytes read FPEM_PUBKEY_PKCS1;
  end;

class constructor TTaurusTLSPem.Create;
begin
  FPEM_X509_CERTIFICATE := TEncoding.ASCII.GetBytes('-----BEGIN CERTIFICATE-----');
  FPEM_PUBKEY_PKCS1 := TEncoding.ASCII.GetBytes('-----BEGIN RSA PUBLIC KEY-----');
end;

class procedure TTaurusTLSPem.LoadOpenSSL;
begin
  if not TaurusTLS.LoadOpenSSLLibrary then
    raise ESignException.Create(SJOSETaurusTLSLoadFailed);
end;

class function TTaurusTLSPem.LoadCertificate(const ACertificate: TBytes): PX509;
var
  LBio: PBIO;
begin
  if (Length(ACertificate) < Length(FPEM_X509_CERTIFICATE)) or
    not CompareMem(@FPEM_X509_CERTIFICATE[0], @ACertificate[0], Length(FPEM_X509_CERTIFICATE)) then
    raise ESignException.Create(SJOSETaurusTLSNotAValidCertificate);

  LBio := BIO_new(BIO_s_mem);
  try
    BIO_write(LBio, ACertificate[0], Length(ACertificate));
    Result := PEM_read_bio_X509(LBio, nil, nil, nil);
    if Result = nil then
      raise ESignException.Create(SJOSETaurusTLSCertLoadError);
  finally
    BIO_free(LBio);
  end;
end;

class function TTaurusTLSPem.LoadPublicKeyFromCert(const ACertificate: TBytes; AExpected: TJOSECertificatePublicKey): PEVP_PKEY;
var
  LCer: PX509;
  LExpectedNid: Integer;
begin
  LoadOpenSSL;

  LCer := LoadCertificate(ACertificate);
  try
    LExpectedNid := ExpectedNidForCertPublicKey(AExpected);
    if CertPublicKeyBaseId(LCer) <> LExpectedNid then
      raise ESignException.Create(SJOSETaurusTLSCertKeyAlgMismatch);

    Result := X509_get0_pubkey(LCer);
    if not Assigned(Result) then
      raise ESignException.Create(SJOSETaurusTLSCertExtractPublicKeyError)
    else
      EVP_PKEY_up_ref(Result);
  finally
    X509_free(LCer);
  end;
end;

class function TTaurusTLSPem.LoadPublicKeyFromCert(const ACertificate: TBytes): PEVP_PKEY;
var
  LCer: PX509;
begin
  LoadOpenSSL;

  LCer := LoadCertificate(ACertificate);
  try
    Result := X509_get0_pubkey(LCer);
    if not Assigned(Result) then
      raise ESignException.Create(SJOSETaurusTLSCertExtractPublicKeyError)
    else
      EVP_PKEY_up_ref(Result);
  finally
    X509_free(LCer);
  end;
end;

class function TTaurusTLSPem.PublicKeyPemBytesFromKeyOrCert(const AKey: TBytes; const ACert: IJOSECertificateProvider): TBytes;
begin
  if (Length(AKey) >= Length(FPEM_X509_CERTIFICATE)) and
    CompareMem(@FPEM_X509_CERTIFICATE[0], @AKey[0], Length(FPEM_X509_CERTIFICATE)) then
    Result := ACert.PublicKeyFromCertificate(AKey)
  else
    Result := AKey;
end;

class function TTaurusTLSPem.PublicKeyFromCertificate(const ACertificate: TBytes): TBytes;
var
  LKey: PEVP_PKEY;
  LBio: PBIO;
begin
  LKey := LoadPublicKeyFromCert(ACertificate);
  try
    LBio := BIO_new(BIO_s_mem);
    try
      PEM_write_bio_PUBKEY(LBio, LKey);
      Result := ReadBIOToBytes(LBio);
    finally
      BIO_free(LBio);
    end;
  finally
    EVP_PKEY_free(LKey);
  end;
end;

class function TTaurusTLSPem.VerifyCertificate(const ACertificate: TBytes; AExpected: TJOSECertificatePublicKey): Boolean;
var
  LCer: PX509;
  LExpectedNid: Integer;
begin
  LoadOpenSSL;

  LCer := LoadCertificate(ACertificate);
  try
    LExpectedNid := ExpectedNidForCertPublicKey(AExpected);
    Result := Assigned(LCer) and (CertPublicKeyBaseId(LCer) = LExpectedNid);
  finally
    X509_free(LCer);
  end;
end;

{ TTaurusTLSCertificateProvider }

function TTaurusTLSCertificateProvider.PublicKeyFromCertificate(const ACertificate: TBytes): TBytes;
begin
  Result := TTaurusTLSPem.PublicKeyFromCertificate(ACertificate);
end;

function TTaurusTLSCertificateProvider.VerifyCertificate(const ACertificate: TBytes; AExpected: TJOSECertificatePublicKey): Boolean;
begin
  Result := TTaurusTLSPem.VerifyCertificate(ACertificate, AExpected);
end;

{ TTaurusTLSRSAProvider }

constructor TTaurusTLSRSAProvider.Create(const ACertificate: IJOSECertificateProvider);
begin
  inherited Create;
  FCertificate := ACertificate;
end;

class function TTaurusTLSRSAProvider.StartsWith(const ABuf, APrefix: TBytes): Boolean;
begin
  Result := (Length(ABuf) >= Length(APrefix)) and CompareMem(@APrefix[0], @ABuf[0], Length(APrefix));
end;

function TTaurusTLSRSAProvider.InternalSign(const AInput: TBytes; AKey: Pointer; AAlg: TRSAAlgorithm): TBytes;
var
  LHash: TBytes;
  LNID: Integer;
  LRsaLen: TIdC_UINT;
  LShaLen: Integer;
begin
  case AAlg of
    RS256:
    begin
      LNID := NID_sha256;
      LShaLen := SHA256_DIGEST_LENGTH;
      SetLength(LHash, LShaLen);
      SHA256(@AInput[0], Length(AInput), @LHash[0]);
    end;
    RS384:
    begin
      LNID := NID_sha384;
      LShaLen := SHA384_DIGEST_LENGTH;
      SetLength(LHash, LShaLen);
      SHA384(@AInput[0], Length(AInput), @LHash[0]);
    end;
    RS512:
    begin
      LNID := NID_sha512;
      LShaLen := SHA512_DIGEST_LENGTH;
      SetLength(LHash, LShaLen);
      SHA512(@AInput[0], Length(AInput), @LHash[0]);
    end;
  else
    raise ESignException.Create(SJOSETaurusTLSRSAUnsupportedAlgorithm);
  end;

  LRsaLen := RSA_size(AKey);
  SetLength(Result, LRsaLen);
  if RSA_sign(LNID, @LHash[0], LShaLen, @Result[0], @LRsaLen, AKey) = 0 then
    raise ESignException.Create(SJOSETaurusTLSRSASignFailed);
  SetLength(Result, LRsaLen);
end;

function TTaurusTLSRSAProvider.InternalVerify(const AInput, ASignature: TBytes; AKey: Pointer; AAlg: TRSAAlgorithm): Boolean;
var
  LHash: TBytes;
  LNID: Integer;
  LShaLen: Integer;
begin
  case AAlg of
    RS256:
    begin
      LNID := NID_sha256;
      LShaLen := SHA256_DIGEST_LENGTH;
      SetLength(LHash, LShaLen);
      SHA256(@AInput[0], Length(AInput), @LHash[0]);
    end;
    RS384:
    begin
      LNID := NID_sha384;
      LShaLen := SHA384_DIGEST_LENGTH;
      SetLength(LHash, LShaLen);
      SHA384(@AInput[0], Length(AInput), @LHash[0]);
    end;
    RS512:
    begin
      LNID := NID_sha512;
      LShaLen := SHA512_DIGEST_LENGTH;
      SetLength(LHash, LShaLen);
      SHA512(@AInput[0], Length(AInput), @LHash[0]);
    end;
  else
    raise ESignException.Create(SJOSETaurusTLSRSAUnsupportedAlgorithm);
  end;

  Result := RSA_verify(LNID, @LHash[0], LShaLen, @ASignature[0], Length(ASignature), AKey) = 1;
end;

function TTaurusTLSRSAProvider.LoadPrivateKey(const AKey: TBytes): Pointer;
var
  LBio: PBIO;
begin
  LBio := BIO_new(BIO_s_mem);
  try
    BIO_write(LBio, AKey[0], Length(AKey));
    Result := PEM_read_bio_RSAPrivateKey(LBio, nil, nil, nil);
    if Result = nil then
      raise ESignException.Create(SJOSETaurusTLSRSALoadPrivateKeyError);
  finally
    BIO_free(LBio);
  end;
end;

function TTaurusTLSRSAProvider.LoadPublicKey(const AKey: TBytes): Pointer;
var
  LBio: PBIO;
  LPem: TBytes;
begin
  LBio := BIO_new(BIO_s_mem);
  try
    LPem := TTaurusTLSPem.PublicKeyPemBytesFromKeyOrCert(AKey, FCertificate);
    BIO_write(LBio, LPem[0], Length(LPem));
    if StartsWith(LPem, TTaurusTLSPem.PEM_PUBKEY_PKCS1) then
      Result := PEM_read_bio_RSAPublicKey(LBio, nil, nil, nil)
    else
      Result := PEM_read_bio_RSA_PUBKEY(LBio, nil, nil, nil);

    if Result = nil then
      raise ESignException.Create(SJOSETaurusTLSRSALoadPublicKeyError);
  finally
    BIO_free(LBio);
  end;
end;

function TTaurusTLSRSAProvider.LoadRSAPublicKeyFromCert(const ACertificate: TBytes): Pointer;
var
  LKey: PEVP_PKEY;
begin
  LKey := TTaurusTLSPem.LoadPublicKeyFromCert(ACertificate, TJOSECertificatePublicKey.RSA);
  try
    Result := EVP_PKEY_get1_RSA(LKey);
    if not Assigned(Result) then
      raise ESignException.Create(SJOSETaurusTLSRSAExtractFromEVPError);
  finally
    EVP_PKEY_free(LKey);
  end;
end;

function TTaurusTLSRSAProvider.Sign(const AInput, AKey: TBytes; AAlg: TRSAAlgorithm): TBytes;
var
  LRsa: PRSA;
begin
  TTaurusTLSPem.LoadOpenSSL;

  LRsa := LoadPrivateKey(AKey);
  try
    Result := InternalSign(AInput, LRsa, AAlg);
  finally
    RSA_free(LRsa);
  end;
end;

function TTaurusTLSRSAProvider.Verify(const AInput, ASignature, AKey: TBytes; AAlg: TRSAAlgorithm): Boolean;
var
  LRsa: PRSA;
begin
  TTaurusTLSPem.LoadOpenSSL;

  LRsa := LoadPublicKey(AKey);
  try
    Result := InternalVerify(AInput, ASignature, LRsa, AAlg);
  finally
    RSA_free(LRsa);
  end;
end;

function TTaurusTLSRSAProvider.VerifyPrivateKey(const AKey: TBytes): Boolean;
var
  LBio: PBIO;
  LRsa: PRSA;
begin
  TTaurusTLSPem.LoadOpenSSL;

  LBio := BIO_new(BIO_s_mem);
  try
    BIO_write(LBio, AKey[0], Length(AKey));
    LRsa := PEM_read_bio_RSAPrivateKey(LBio, nil, nil, nil);
    Result := (LRsa <> nil);
    if Result then
      RSA_free(LRsa);
  finally
    BIO_free(LBio);
  end;
end;

function TTaurusTLSRSAProvider.VerifyPublicKey(const AKey: TBytes): Boolean;
var
  LBio: PBIO;
  LRsa: PRSA;
  LPem: TBytes;
begin
  TTaurusTLSPem.LoadOpenSSL;

  LBio := BIO_new(BIO_s_mem);
  try
    LPem := TTaurusTLSPem.PublicKeyPemBytesFromKeyOrCert(AKey, FCertificate);
    BIO_write(LBio, LPem[0], Length(LPem));
    if StartsWith(LPem, TTaurusTLSPem.PEM_PUBKEY_PKCS1) then
      LRsa := PEM_read_bio_RSAPublicKey(LBio, nil, nil, nil)
    else
      LRsa := PEM_read_bio_RSA_PUBKEY(LBio, nil, nil, nil);

    Result := (LRsa <> nil);
    if Result then
      RSA_free(LRsa);
  finally
    BIO_free(LBio);
  end;
end;

function TTaurusTLSRSAProvider.VerifyWithCertificate(const AInput, ASignature, ACertificate: TBytes; AAlg: TRSAAlgorithm): Boolean;
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

{ TTaurusTLSECDSAProvider }

constructor TTaurusTLSECDSAProvider.Create(const ACertificate: IJOSECertificateProvider);
begin
  inherited Create;
  FCertificate := ACertificate;
end;

function TTaurusTLSECDSAProvider.HashFromBytes(const AInput: TBytes; AAlg: TECDSAAlgorithm): TBytes;
var
  LShaLen: Integer;
begin
  case AAlg of
    ES256, ES256K:
    begin
      LShaLen := SHA256_DIGEST_LENGTH;
      SetLength(Result, LShaLen);
      SHA256(@AInput[0], Length(AInput), @Result[0]);
    end;
    ES384:
    begin
      LShaLen := SHA384_DIGEST_LENGTH;
      SetLength(Result, LShaLen);
      SHA384(@AInput[0], Length(AInput), @Result[0]);
    end;
    ES512:
    begin
      LShaLen := SHA512_DIGEST_LENGTH;
      SetLength(Result, LShaLen);
      SHA512(@AInput[0], Length(AInput), @Result[0]);
    end;
  else
    raise ESignException.Create(SJOSETaurusTLSECDSAUnsupportedAlgorithm);
  end;
end;

function TTaurusTLSECDSAProvider.OctetSequence2Sig(const ASignature: TBytes; AAlg: TECDSAAlgorithm): Pointer;
var
  LKeyLength: Integer;
  LR, LS: PBIGNUM;
begin
  Result := ECDSA_SIG_new();
  LKeyLength := Length(ASignature) div 2;

  LR := BN_bin2bn(PByte(@ASignature[0]), LKeyLength, nil);
  LS := BN_bin2bn(PByte(@ASignature[LKeyLength]), LKeyLength, nil);
  ECDSA_SIG_set0(Result, LR, LS);
end;

function TTaurusTLSECDSAProvider.Sig2OctetSequence(ASignature: Pointer; AAlg: TECDSAAlgorithm): TBytes;
var
  LSigLength, LRLength, LSLength: Integer;
  LR, LS: PBIGNUM;
begin
  LSigLength := 0;

  case AAlg of
    ES256:  LSigLength := 32 * 2;
    ES256K: LSigLength := 32 * 2;
    ES384:  LSigLength := 48 * 2;
    ES512:  LSigLength := 66 * 2;
  end;

  ECDSA_SIG_get0(ASignature, @LR, @LS);
  LRLength := TaurusBNNumBytes(LR);
  LSLength := TaurusBNNumBytes(LS);

  SetLength(Result, LSigLength);
  FillChar(Result[0], LSigLength, #0);

  BN_bn2bin(LR, PByte(@Result[(LSigLength div 2) - LRLength]));
  BN_bn2bin(LS, PByte(@Result[LSigLength - LSLength]));
end;

function TTaurusTLSECDSAProvider.InternalSign(const AInput: TBytes; AKey: Pointer; AAlg: TECDSAAlgorithm): TBytes;
var
  LECKey: PEC_KEY;
  LSig: PECDSA_SIG;
  LShaHash: TBytes;
begin
  Result := [];
  LECKey := EVP_PKEY_get1_EC_KEY(AKey);
  if LECKey = nil then
    raise ESignException.Create(SJOSETaurusTLSECDSAKeyError);
  try
    LShaHash := HashFromBytes(AInput, AAlg);

    LSig := ECDSA_do_sign(@LShaHash[0], Length(LShaHash), LECKey);
    if LSig = nil then
      raise ESignException.Create(SJOSETaurusTLSECDSASignFailed);
    try
      Result := Sig2OctetSequence(LSig, AAlg);
    finally
      ECDSA_SIG_free(LSig);
    end;
  finally
    EC_KEY_free(LECKey);
  end;
end;

function TTaurusTLSECDSAProvider.InternalVerify(const AInput, ASignature: TBytes; APublicKey: Pointer; AAlg: TECDSAAlgorithm): Boolean;
var
  LECKey: PEC_KEY;
  LSig: PECDSA_SIG;
  LShaHash: TBytes;
begin
  LECKey := EVP_PKEY_get1_EC_KEY(APublicKey);
  if LECKey = nil then
    raise ESignException.Create(SJOSETaurusTLSECDSAKeyError);
  try
    LSig := OctetSequence2Sig(ASignature, AAlg);
    try
      LShaHash := HashFromBytes(AInput, AAlg);
      Result := ECDSA_do_verify(@LShaHash[0], Length(LShaHash), LSig, LECKey) = 1;
    finally
      ECDSA_SIG_free(LSig);
    end;
  finally
    EC_KEY_free(LECKey);
  end;
end;

function TTaurusTLSECDSAProvider.LoadPrivateKey(const AKey: TBytes): Pointer;
var
  LBio: PBIO;
begin
  TTaurusTLSPem.LoadOpenSSL;

  LBio := BIO_new(BIO_s_mem);
  try
    BIO_write(LBio, AKey[0], Length(AKey));
    Result := PEM_read_bio_PrivateKey(LBio, nil, nil, nil);
    if Result = nil then
      raise ESignException.Create(SJOSETaurusTLSECDSALoadPrivateKeyError);
  finally
    BIO_free(LBio);
  end;
end;

function TTaurusTLSECDSAProvider.LoadPublicKey(const AKey: TBytes): Pointer;
var
  LKeyBuffer: PBIO;
  LPem: TBytes;
begin
  TTaurusTLSPem.LoadOpenSSL;

  LKeyBuffer := BIO_new(BIO_s_mem);
  try
    LPem := TTaurusTLSPem.PublicKeyPemBytesFromKeyOrCert(AKey, FCertificate);
    BIO_write(LKeyBuffer, LPem[0], Length(LPem));

    Result := PEM_read_bio_PUBKEY(LKeyBuffer, nil, nil, nil);
    if Result = nil then
      raise ESignException.Create(SJOSETaurusTLSECDSALoadPublicKeyError);
  finally
    BIO_free(LKeyBuffer);
  end;
end;

function TTaurusTLSECDSAProvider.Sign(const AInput, APrivateKey: TBytes; AAlg: TECDSAAlgorithm): TBytes;
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

function TTaurusTLSECDSAProvider.Verify(const AInput, ASignature, APublicKey: TBytes; AAlg: TECDSAAlgorithm): Boolean;
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

function TTaurusTLSECDSAProvider.VerifyPrivateKey(const AKey: TBytes): Boolean;
var
  LBio: PBIO;
  LPrivKey: PEVP_PKEY;
begin
  TTaurusTLSPem.LoadOpenSSL;

  LBio := BIO_new(BIO_s_mem);
  try
    BIO_write(LBio, AKey[0], Length(AKey));
    LPrivKey := PEM_read_bio_PrivateKey(LBio, nil, nil, nil);
    Result := (LPrivKey <> nil);
    if Result then
      EVP_PKEY_free(LPrivKey);
  finally
    BIO_free(LBio);
  end;
end;

function TTaurusTLSECDSAProvider.VerifyPublicKey(const AKey: TBytes): Boolean;
var
  LBio: PBIO;
  LKey: PEVP_PKEY;
  LPem: TBytes;
begin
  TTaurusTLSPem.LoadOpenSSL;

  LBio := BIO_new(BIO_s_mem);
  try
    LPem := TTaurusTLSPem.PublicKeyPemBytesFromKeyOrCert(AKey, FCertificate);
    BIO_write(LBio, LPem[0], Length(LPem));
    LKey := PEM_read_bio_PUBKEY(LBio, nil, nil, nil);

    Result := (LKey <> nil);
    if Result then
      EVP_PKEY_free(LKey);
  finally
    BIO_free(LBio);
  end;
end;

function TTaurusTLSECDSAProvider.VerifyWithCertificate(const AInput, ASignature, ACertificate: TBytes; AAlg: TECDSAAlgorithm): Boolean;
var
  LKey: PEVP_PKEY;
begin
  LKey := TTaurusTLSPem.LoadPublicKeyFromCert(ACertificate, TJOSECertificatePublicKey.EC);
  try
    Result := InternalVerify(AInput, ASignature, LKey, AAlg);
  finally
    EVP_PKEY_free(LKey);
  end;
end;

{ RSA key material (accessor-based: RSA_get0_key/RSA_set0_key/... instead of raw struct fields) }

function RSAKeyToMaterial(ARsa: PRSA): TJOSERSAKeyMaterial;
var
  LN, LE, LD, LP, LQ, LDmp1, LDmq1, LIqmp: PBIGNUM;
begin
  // The result is written straight into the caller's variable, so the private components have to be
  // cleared rather than left over from whatever that variable held before: importing a public key
  // into a reused record would otherwise report IsPrivate and carry the previous key's secrets.
  Result := Default(TJOSERSAKeyMaterial);

  RSA_get0_key(ARsa, @LN, @LE, @LD);
  Result.Modulus := BignumToBytes(LN);
  Result.PublicExponent := BignumToBytes(LE);
  if Assigned(LD) then
  begin
    Result.PrivateExponent := BignumToBytes(LD);
    RSA_get0_factors(ARsa, @LP, @LQ);
    RSA_get0_crt_params(ARsa, @LDmp1, @LDmq1, @LIqmp);
    Result.P := BignumToBytes(LP);
    Result.Q := BignumToBytes(LQ);
    Result.DP := BignumToBytes(LDmp1);
    Result.DQ := BignumToBytes(LDmq1);
    Result.QI := BignumToBytes(LIqmp);
  end;
end;

function TryLoadRSA(const APEM: TBytes): PRSA;
var
  LBio: PBIO;
begin
  LBio := NewBIOFromBytes(APEM);
  try
    Result := PEM_read_bio_RSAPrivateKey(LBio, nil, nil, nil);
  finally
    BIO_free(LBio);
  end;
  if Assigned(Result) then
    Exit;

  LBio := NewBIOFromBytes(APEM);
  try
    Result := PEM_read_bio_RSAPublicKey(LBio, nil, nil, nil);
  finally
    BIO_free(LBio);
  end;
  if Assigned(Result) then
    Exit;

  LBio := NewBIOFromBytes(APEM);
  try
    Result := PEM_read_bio_RSA_PUBKEY(LBio, nil, nil, nil);
  finally
    BIO_free(LBio);
  end;
end;

function TryLoadGenericPKey(const APEM: TBytes): PEVP_PKEY;
var
  LBio: PBIO;
begin
  LBio := NewBIOFromBytes(APEM);
  try
    Result := PEM_read_bio_PrivateKey(LBio, nil, nil, nil);
  finally
    BIO_free(LBio);
  end;
  if Assigned(Result) then
    Exit;

  LBio := NewBIOFromBytes(APEM);
  try
    Result := PEM_read_bio_PUBKEY(LBio, nil, nil, nil);
  finally
    BIO_free(LBio);
  end;
end;

{ TTaurusTLSRSAKeyMaterialProvider }

function TTaurusTLSRSAKeyMaterialProvider.ImportPEM(const APEM: TBytes): TJOSERSAKeyMaterial;
var
  LRsa: PRSA;
  LPKey: PEVP_PKEY;
begin
  TTaurusTLSPem.LoadOpenSSL;

  if Length(APEM) = 0 then
    raise ESignException.Create(SJOSETaurusTLSJWKEmptyPEMData);

  LRsa := TryLoadRSA(APEM);
  if Assigned(LRsa) then
  begin
    try
      Result := RSAKeyToMaterial(LRsa);
    finally
      RSA_free(LRsa);
    end;
    Exit;
  end;

  LPKey := TryLoadGenericPKey(APEM);
  if not Assigned(LPKey) then
    raise ESignException.Create(SJOSETaurusTLSJWKUnrecognizedPEMFormat);
  try
    if EVP_PKEY_base_id(LPKey) = NID_X9_62_id_ecPublicKey then
      raise ESignException.Create(SJOSETaurusTLSJWKPEMContainsECNotRSA);

    LRsa := EVP_PKEY_get1_RSA(LPKey);
    if not Assigned(LRsa) then
      raise ESignException.Create(SJOSETaurusTLSJWKUnsupportedPEMKeyType);
    try
      Result := RSAKeyToMaterial(LRsa);
    finally
      RSA_free(LRsa);
    end;
  finally
    EVP_PKEY_free(LPKey);
  end;
end;

function TTaurusTLSRSAKeyMaterialProvider.ExportPEM(const AKeyMaterial: TJOSERSAKeyMaterial; AIncludePrivate: Boolean): TBytes;
var
  LBio: PBIO;
  LRsa: PRSA;
  LWritePrivate: Boolean;
  LN, LE, LD, LP, LQ, LDmp1, LDmq1, LIqmp: PBIGNUM;
begin
  TTaurusTLSPem.LoadOpenSSL;

  LWritePrivate := AIncludePrivate and AKeyMaterial.IsPrivate;

  LBio := BIO_new(BIO_s_mem);
  try
    LRsa := RSA_new;
    if not Assigned(LRsa) then
      raise ESignException.Create(SJOSETaurusTLSJWKAllocateRSAError);
    try
      LN := BytesToBignum(AKeyMaterial.Modulus);
      LE := BytesToBignum(AKeyMaterial.PublicExponent);
      if LWritePrivate then
      begin
        LD := BytesToBignum(AKeyMaterial.PrivateExponent);
        RSA_set0_key(LRsa, LN, LE, LD);

        LP := BytesToBignum(AKeyMaterial.P);
        LQ := BytesToBignum(AKeyMaterial.Q);
        RSA_set0_factors(LRsa, LP, LQ);

        LDmp1 := BytesToBignum(AKeyMaterial.DP);
        LDmq1 := BytesToBignum(AKeyMaterial.DQ);
        LIqmp := BytesToBignum(AKeyMaterial.QI);
        RSA_set0_crt_params(LRsa, LDmp1, LDmq1, LIqmp);

        if PEM_write_bio_RSAPrivateKey(LBio, LRsa, nil, nil, 0, nil, nil) <> 1 then
          raise ESignException.Create(SJOSETaurusTLSJWKWriteRSAPrivateError);
      end
      else
      begin
        RSA_set0_key(LRsa, LN, LE, nil);
        if PEM_write_bio_RSAPublicKey(LBio, LRsa) <> 1 then
          raise ESignException.Create(SJOSETaurusTLSJWKWriteRSAPublicError);
      end;
    finally
      RSA_free(LRsa);
    end;

    Result := ReadBIOToBytes(LBio);
  finally
    BIO_free(LBio);
  end;
end;

{ EC key material helpers }

function ECKeyToMaterial(ACurve: TECCurve; AEC: PEC_KEY): TJOSEECKeyMaterial;
var
  LGroup: PEC_GROUP;
  LPoint: PEC_POINT;
  LPriv, LX, LY: PBIGNUM;
  LCtx: PBN_CTX;
  LComponentLen: Integer;
begin
  // See RSAKeyToMaterial: clear before filling, so a reused record cannot keep a previous key's D.
  Result := Default(TJOSEECKeyMaterial);

  Result.Curve := ACurve;

  LGroup := EC_KEY_get0_group(AEC);
  if not Assigned(LGroup) then
    raise ESignException.Create(SJOSETaurusTLSJWKECNoGroup);

  LPoint := EC_KEY_get0_public_key(AEC);
  if not Assigned(LPoint) then
    raise ESignException.Create(SJOSETaurusTLSJWKECNoPublicPoint);

  // For every curve JOSE supports (P-256/P-384/P-521/secp256k1) the group order is the same width
  // as a coordinate, so the field degree sizes x, y and d alike.
  LComponentLen := (EC_GROUP_get_degree(LGroup) + 7) div 8;

  LX := BN_new();
  LY := BN_new();
  LCtx := BN_CTX_new();
  try
    if EC_POINT_get_affine_coordinates(LGroup, LPoint, LX, LY, LCtx) <> 1 then
      raise ESignException.Create(SJOSETaurusTLSJWKECReadPublicPointError);
    Result.X := BignumToFixedBytes(LX, LComponentLen);
    Result.Y := BignumToFixedBytes(LY, LComponentLen);
  finally
    BN_free(LX);
    BN_free(LY);
    BN_CTX_free(LCtx);
  end;

  LPriv := EC_KEY_get0_private_key(AEC);
  if Assigned(LPriv) then
    Result.D := BignumToFixedBytes(LPriv, LComponentLen);
end;

function BuildECKey(const AKeyMaterial: TJOSEECKeyMaterial; ANID: Integer; AIncludePrivate: Boolean): PEC_KEY;
var
  LGroup: PEC_GROUP;
  LPoint: PEC_POINT;
  LCtx: PBN_CTX;
  LX, LY, LD: PBIGNUM;
begin
  Result := EC_KEY_new_by_curve_name(ANID);
  if not Assigned(Result) then
    raise ESignException.Create(SJOSETaurusTLSJWKECCreateKeyError);

  // Force named-curve (OID-referenced) encoding rather than explicit domain parameters, so
  // EC_GROUP_get_curve_name can recover the NID after a PEM write/read round-trip.
  EC_KEY_set_asn1_flag(Result, OPENSSL_EC_NAMED_CURVE);

  try
    LGroup := EC_KEY_get0_group(Result);
    LCtx := BN_CTX_new();
    LPoint := EC_POINT_new(LGroup);
    try
      LX := BytesToBignum(AKeyMaterial.X);
      LY := BytesToBignum(AKeyMaterial.Y);
      try
        if EC_POINT_set_affine_coordinates(LGroup, LPoint, LX, LY, LCtx) <> 1 then
          raise ESignException.Create(SJOSETaurusTLSJWKECInvalidPublicPoint);
        if EC_KEY_set_public_key(Result, LPoint) <> 1 then
          raise ESignException.Create(SJOSETaurusTLSJWKECSetPublicKeyError);
      finally
        BN_free(LX);
        BN_free(LY);
      end;

      if AIncludePrivate then
      begin
        LD := BytesToBignum(AKeyMaterial.D);
        try
          if EC_KEY_set_private_key(Result, LD) <> 1 then
            raise ESignException.Create(SJOSETaurusTLSJWKECSetPrivateKeyError);
        finally
          BN_free(LD);
        end;
      end;
    finally
      EC_POINT_free(LPoint);
      BN_CTX_free(LCtx);
    end;
  except
    EC_KEY_free(Result);
    raise;
  end;
end;

{ TTaurusTLSECKeyMaterialProvider }

class function TTaurusTLSECKeyMaterialProvider.CurveToNID(ACurve: TECCurve): Integer;
begin
  case ACurve of
    TECCurve.P256:      Result := NID_X9_62_prime256v1;
    TECCurve.P384:      Result := NID_secp384r1;
    TECCurve.P521:      Result := NID_secp521r1;
    TECCurve.secp256k1: Result := NID_secp256k1;
  else
    raise ESignException.Create(SJOSETaurusTLSJWKUnsupportedECCurve);
  end;
end;

class function TTaurusTLSECKeyMaterialProvider.NIDToCurve(ANID: Integer): TECCurve;
begin
  if ANID = NID_X9_62_prime256v1 then
    Result := TECCurve.P256
  else if ANID = NID_secp384r1 then
    Result := TECCurve.P384
  else if ANID = NID_secp521r1 then
    Result := TECCurve.P521
  else if ANID = NID_secp256k1 then
    Result := TECCurve.secp256k1
  else
    raise ESignException.CreateFmt(SJOSETaurusTLSJWKUnsupportedECCurveNID, [ANID]);
end;

function TTaurusTLSECKeyMaterialProvider.ImportPEM(const APEM: TBytes): TJOSEECKeyMaterial;
var
  LEC: PEC_KEY;
  LPKey: PEVP_PKEY;
  LGroup: PEC_GROUP;
  LRsa: PRSA;
begin
  TTaurusTLSPem.LoadOpenSSL;

  if Length(APEM) = 0 then
    raise ESignException.Create(SJOSETaurusTLSJWKEmptyPEMData);

  LRsa := TryLoadRSA(APEM);
  if Assigned(LRsa) then
  begin
    RSA_free(LRsa);
    raise ESignException.Create(SJOSETaurusTLSJWKPEMContainsRSANotEC);
  end;

  LPKey := TryLoadGenericPKey(APEM);
  if not Assigned(LPKey) then
    raise ESignException.Create(SJOSETaurusTLSJWKUnrecognizedPEMFormat);
  try
    if EVP_PKEY_base_id(LPKey) <> NID_X9_62_id_ecPublicKey then
      raise ESignException.Create(SJOSETaurusTLSJWKPEMNoECKey);

    LEC := EVP_PKEY_get1_EC_KEY(LPKey);
    if not Assigned(LEC) then
      raise ESignException.Create(SJOSETaurusTLSJWKExtractECKeyError);
    try
      LGroup := EC_KEY_get0_group(LEC);
      if not Assigned(LGroup) then
        raise ESignException.Create(SJOSETaurusTLSJWKECNoGroup);

      Result := ECKeyToMaterial(NIDToCurve(EC_GROUP_get_curve_name(LGroup)), LEC);
    finally
      EC_KEY_free(LEC);
    end;
  finally
    EVP_PKEY_free(LPKey);
  end;
end;

function TTaurusTLSECKeyMaterialProvider.ExportPEM(const AKeyMaterial: TJOSEECKeyMaterial; AIncludePrivate: Boolean): TBytes;
var
  LBio: PBIO;
  LEC: PEC_KEY;
  LPKey: PEVP_PKEY;
  LWritePrivate: Boolean;
begin
  TTaurusTLSPem.LoadOpenSSL;

  LWritePrivate := AIncludePrivate and AKeyMaterial.IsPrivate;

  LBio := BIO_new(BIO_s_mem);
  try
    LEC := BuildECKey(AKeyMaterial, CurveToNID(AKeyMaterial.Curve), LWritePrivate);
    try
      LPKey := EVP_PKEY_new;
      if not Assigned(LPKey) then
        raise ESignException.Create(SJOSETaurusTLSJWKAllocateEVPPKeyError);
      try
        if EVP_PKEY_set1_EC_KEY(LPKey, LEC) <> 1 then
          raise ESignException.Create(SJOSETaurusTLSJWKWrapECKeyError);

        if LWritePrivate then
        begin
          if PEM_write_bio_PrivateKey(LBio, LPKey, nil, nil, 0, nil, nil) <> 1 then
            raise ESignException.Create(SJOSETaurusTLSJWKWriteECPrivateError);
        end
        else
        begin
          if PEM_write_bio_PUBKEY(LBio, LPKey) <> 1 then
            raise ESignException.Create(SJOSETaurusTLSJWKWriteECPublicError);
        end;
      finally
        EVP_PKEY_free(LPKey);
      end;
    finally
      EC_KEY_free(LEC);
    end;

    Result := ReadBIOToBytes(LBio);
  finally
    BIO_free(LBio);
  end;
end;

{$ENDIF}

{ TJOSETaurusTLSProviders }

class procedure TJOSETaurusTLSProviders.Register;
{$IFDEF RSA_SIGNING}
var
  LCert: IJOSECertificateProvider;
{$ENDIF}
begin
  TJOSEProviders.Base64 := TDefaultBase64Provider.Create;
  TJOSEProviders.HMAC := TDefaultHmacProvider.Create;
{$IFDEF RSA_SIGNING}
  LCert := TTaurusTLSCertificateProvider.Create;
  TJOSEProviders.Certificate := LCert;
  TJOSEProviders.RSA := TTaurusTLSRSAProvider.Create(LCert);
  TJOSEProviders.ECDSA := TTaurusTLSECDSAProvider.Create(LCert);
  TJOSEProviders.RSAKeyMaterial := TTaurusTLSRSAKeyMaterialProvider.Create;
  TJOSEProviders.ECKeyMaterial := TTaurusTLSECKeyMaterialProvider.Create;
{$ENDIF}
end;

class procedure TJOSETaurusTLSProviders.Unregister;
begin
  TJOSEProviders.Base64 := nil;
  TJOSEProviders.HMAC := nil;
{$IFDEF RSA_SIGNING}
  TJOSEProviders.Certificate := nil;
  TJOSEProviders.RSA := nil;
  TJOSEProviders.ECDSA := nil;
  TJOSEProviders.RSAKeyMaterial := nil;
  TJOSEProviders.ECKeyMaterial := nil;
{$ENDIF}
end;

end.
