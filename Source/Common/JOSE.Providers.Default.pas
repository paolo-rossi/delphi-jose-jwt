{******************************************************************************}
{                                                                              }
{  Delphi JOSE-JWT Library                                                     }
{  Copyright (c) 2015 Paolo Rossi                                              }
{  https://github.com/paolo-rossi/delphi-jose-jwt                              }
{                                                                              }
{  Licensed under the MIT license                                              }
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

  /// <summary>OpenSSL-backed raw RSA key import/export (JWK PEM support).</summary>
  TDefaultRSAKeyMaterialProvider = class(TInterfacedObject, IJOSERSAKeyMaterialProvider)
  public
    function ImportPEM(const APEM: TBytes): TJOSERSAKeyMaterial;
    function ExportPEM(const AKeyMaterial: TJOSERSAKeyMaterial; AIncludePrivate: Boolean): TBytes;
  end;

  /// <summary>OpenSSL-backed raw EC key import/export (JWK PEM support).</summary>
  TDefaultECKeyMaterialProvider = class(TInterfacedObject, IJOSEECKeyMaterialProvider)
  private
    class function CurveToNID(ACurve: TECCurve): Integer; static;
    class function NIDToCurve(ANID: Integer): TECCurve; static;
  public
    function ImportPEM(const APEM: TBytes): TJOSEECKeyMaterial;
    function ExportPEM(const AKeyMaterial: TJOSEECKeyMaterial; AIncludePrivate: Boolean): TBytes;
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

resourcestring
  SJOSEErrorLoadingOpenSSLLibraries = 'Error Loading OpenSSL libraries';

{$IFDEF RSA_SIGNING}

resourcestring
  SJOSEUnhandledCertPublicKeyValue = 'Unhandled TJOSECertificatePublicKey value';
  SJOSEOpenSSLLoadFailed = '[OpenSSL] Unable to load OpenSSL libraries';
  SJOSEOpenSSLTooOld = '[OpenSSL] Please, use OpenSSL 1.0.0 or newer!';
  SJOSEOpenSSLInvalidCertificate = '[OpenSSL] Not a valid X509 certificate';
  SJOSEOpenSSLCertLoadError = '[OpenSSL] Error loading X509 certificate';
  SJOSEOpenSSLCertKeyAlgMismatch = '[OpenSSL] Certificate public key algorithm does not match expected type';
  SJOSEOpenSSLCertExtractPublicKeyError = '[OpenSSL] Error extracting public key from X509 certificate';
  SJOSERSAExtractFromEVPError = '[RSA] Error extracting RSA key from EVP_PKEY';
  SJOSERSAUnsupportedAlgorithm = '[RSA] Unsupported signing algorithm!';
  SJOSERSASignFailed = '[RSA] Unable to sign RSA message digest';
  SJOSERSAPSSUnavailable = '[RSA] The loaded OpenSSL library does not provide the RSASSA-PSS functions';
  SJOSERSAPSSPaddingFailed = '[RSA] Unable to apply RSASSA-PSS padding';
  SJOSERSAPSSKeyTooSmall = '[RSA] %s needs an RSA key of at least %d bytes, this one is %d';
  SJOSERSALoadPrivateKeyError = '[RSA] Unable to load private key: %s';
  SJOSERSALoadPublicKeyError = '[RSA] Unable to load public key: %s';
  SJOSEECDSAUnsupportedAlgorithm = '[ECDSA] Unsupported signing algorithm!';
  SJOSEECDSAMemoryError = '[ECDSA] Error getting memory for ECDSA';
  SJOSEECDSALoadPrivateKeyError = '[ECDSA] Unable to load private key: %s';
  SJOSEECDSALoadPublicKeyError = '[ECDSA] Unable to load public key: %s';
  SJOSEECDSAKeyError = '[ECDSA] Error getting EC Key: %s';
  SJOSEECDSASignFailed = '[ECDSA] Digest signing failed: %s';
  SJOSEJWKMissingKeyComponent = '[JWK] Missing required key component';
  SJOSEJWKBignumConversionError = '[JWK] Unable to convert key component to BIGNUM';
  SJOSEJWKECNoGroup = '[JWK] EC key has no group/curve';
  SJOSEJWKECNoPublicPoint = '[JWK] EC key has no public point';
  SJOSEJWKECReadPublicPointError = '[JWK] Unable to read the EC public point';
  SJOSEJWKECCreateKeyError = '[JWK] Unable to create an EC key for the requested curve';
  SJOSEJWKECInvalidPublicPoint = '[JWK] Invalid EC public point';
  SJOSEJWKECSetPublicKeyError = '[JWK] Unable to set the EC public key';
  SJOSEJWKECSetPrivateKeyError = '[JWK] Unable to set the EC private key';
  SJOSEJWKEmptyPEMData = '[JWK] Empty PEM data';
  SJOSEJWKUnrecognizedPEMFormat = '[JWK] Unable to parse PEM: unrecognized or unsupported key format';
  SJOSEJWKPEMContainsECNotRSA = '[JWK] PEM contains an EC key, not an RSA key';
  SJOSEJWKUnsupportedPEMKeyType = '[JWK] Unsupported PEM key type';
  SJOSEJWKAllocateRSAError = '[JWK] Unable to allocate an RSA key';
  SJOSEJWKWriteRSAPrivateError = '[JWK] Unable to write the RSA private key PEM';
  SJOSEJWKWriteRSAPublicError = '[JWK] Unable to write the RSA public key PEM';
  SJOSEJWKUnsupportedECCurve = '[JWK] Unsupported EC curve';
  SJOSEJWKUnsupportedECCurveNID = '[JWK] Unsupported EC curve (NID %d)';
  SJOSEJWKECSupportUnavailable = '[JWK] EC key support is not available (missing OpenSSL EC symbols)';
  SJOSEJWKPEMContainsRSANotEC = '[JWK] PEM contains an RSA key, not an EC key';
  SJOSEJWKPEMNoECKey = '[JWK] PEM does not contain an EC key';
  SJOSEJWKExtractECKeyError = '[JWK] Unable to extract the EC key from the PEM';
  SJOSEJWKAllocateEVPPKeyError = '[JWK] Unable to allocate an EVP_PKEY';
  SJOSEJWKWrapECKeyError = '[JWK] Unable to wrap the EC key';
  SJOSEJWKWriteECPrivateError = '[JWK] Unable to write the EC private key PEM';
  SJOSEJWKWriteECPublicError = '[JWK] Unable to write the EC public key PEM';

function JoseExpectedNidForCertPublicKey(const AExpected: TJOSECertificatePublicKey): Integer;
begin
  case AExpected of
    TJOSECertificatePublicKey.RSA:
      Result := NID_rsaEncryption;
    TJOSECertificatePublicKey.EC:
      Result := JoseSSL.NID_X9_62_id_ecPublicKey;
  else
    raise EArgumentException.Create(SJOSEUnhandledCertPublicKeyValue);
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
    raise ESignException.Create(SJOSEOpenSSLLoadFailed);

  if not JoseSSL.Load then
    raise ESignException.Create(SJOSEOpenSSLLoadFailed);

  if @EVP_DigestVerifyInit = nil then
    raise ESignException.Create(SJOSEOpenSSLTooOld);
end;

class function TJOSEDefaultOpenSslPem.LoadCertificate(const ACertificate: TBytes): PX509;
var
  LBio: PBIO;
begin
  // The length test must come first: @ACertificate[0] on an empty or too-short
  // array reads past its end (nil dereference when empty), turning a malformed
  // certificate into an access violation instead of an exception
  if (Length(ACertificate) < Length(FPEM_X509_CERTIFICATE)) or
    not CompareMem(@FPEM_X509_CERTIFICATE[0], @ACertificate[0], Length(FPEM_X509_CERTIFICATE)) then
    raise ESignException.Create(SJOSEOpenSSLInvalidCertificate);

  LBio := BIO_new(BIO_s_mem);
  try
    BIO_write(LBio, @ACertificate[0], Length(ACertificate));
    Result := PEM_read_bio_X509(LBio, nil, nil, nil);
    if Result = nil then
      raise ESignException.Create(SJOSEOpenSSLCertLoadError);
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
      raise ESignException.Create(SJOSEOpenSSLCertKeyAlgMismatch);

    Result := X509_PUBKEY_get(LCer.cert_info.key);
    if not Assigned(Result) then
      raise ESignException.Create(SJOSEOpenSSLCertExtractPublicKeyError);
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
      raise ESignException.Create(SJOSEOpenSSLCertExtractPublicKeyError);
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
    raise ESignException.Create(SJOSERSAExtractFromEVPError);
end;

/// <summary>
///   Digests AInput with the hash AAlg names, producing both identifiers the two padding schemes
///   want: PKCS#1 v1.5 signs by NID, PSS by EVP_MD.
/// </summary>
procedure DigestForRSA(const AInput: TBytes; AAlg: TRSAAlgorithm; out AHash: TBytes;
  out ANID: Integer; out AMd: PEVP_MD);
begin
  SetLength(AHash, AAlg.DigestBytes);
  AMd := nil;
  case AAlg of
    RS256, PS256:
    begin
      ANID := JoseSSL.NID_sha256;
      JoseSSL.SHA256(@AInput[0], Length(AInput), @AHash[0]);
    end;
    RS384, PS384:
    begin
      ANID := JoseSSL.NID_sha384;
      JoseSSL.SHA384(@AInput[0], Length(AInput), @AHash[0]);
    end;
    RS512, PS512:
    begin
      ANID := JoseSSL.NID_sha512;
      JoseSSL.SHA512(@AInput[0], Length(AInput), @AHash[0]);
    end;
  else
    raise ESignException.Create(SJOSERSAUnsupportedAlgorithm);
  end;

  // Only resolved for PSS, since EVP_sha* live behind the lazily-loaded capability and an
  // RS*-only caller must never be made to depend on them.
  if AAlg.IsPSS then
  begin
    if not JoseSSL.EnsurePSSSupport then
      raise ESignException.Create(SJOSERSAPSSUnavailable);
    case AAlg of
      PS256: AMd := JoseSSL.EVP_sha256();
      PS384: AMd := JoseSSL.EVP_sha384();
    else
      AMd := JoseSSL.EVP_sha512();
    end;
  end;
end;

function TDefaultRSAProvider.InternalSign(const AInput: TBytes; AKey: PRSA; AAlg: TRSAAlgorithm): TBytes;
var
  LHash, LEM: TBytes;
  LNID: Integer;
  LMd: PEVP_MD;
  LRsaLen: Integer;
  LWritten: Integer;
  LSigLen: Cardinal;
begin
  DigestForRSA(AInput, AAlg, LHash, LNID, LMd);
  LRsaLen := JoseSSL.RSA_size(AKey);

  if AAlg.IsPSS then
  begin
    // OpenSSL's own complaint about an undersized key here is opaque, so say it plainly.
    if LRsaLen < AAlg.MinPSSKeyBytes then
      raise ESignException.CreateFmt(SJOSERSAPSSKeyTooSmall,
        [AAlg.ToString, AAlg.MinPSSKeyBytes, LRsaLen]);

    // PSS has no one-call signing primitive: build the encoded message, then apply the private
    // key to it raw. The salt length is the digest size, per RFC 7518 3.5.
    SetLength(LEM, LRsaLen);
    if JoseSSL.RSA_padding_add_PKCS1_PSS(AKey, @LEM[0], @LHash[0], LMd, AAlg.DigestBytes) <> 1 then
      raise ESignException.Create(SJOSERSAPSSPaddingFailed);

    SetLength(Result, LRsaLen);
    LWritten := JoseSSL.RSA_private_encrypt(LRsaLen, @LEM[0], @Result[0], AKey, RSA_NO_PADDING);
    if LWritten < 0 then
      raise ESignException.Create(SJOSERSASignFailed);
    SetLength(Result, LWritten);
    Exit;
  end;

  // RSA_size is the buffer RSA_sign needs, but it reports the bytes it actually wrote through
  // siglen - which is what the result has to be trimmed to. PKCS#1 v1.5 always fills the modulus,
  // so the two agree today; trusting RSA_size instead would be a latent bug the day they don't.
  LSigLen := LRsaLen;
  SetLength(Result, LRsaLen);
  if JoseSSL.RSA_sign(LNID, @LHash[0], Length(LHash), @Result[0], @LSigLen, AKey) = 0 then
    raise ESignException.Create(SJOSERSASignFailed);
  SetLength(Result, LSigLen);
end;

function TDefaultRSAProvider.InternalVerify(const AInput, ASignature: TBytes; AKey: PRSA; AAlg: TRSAAlgorithm): Boolean;
var
  LHash, LEM: TBytes;
  LNID: Integer;
  LMd: PEVP_MD;
  LRsaLen: Integer;
begin
  DigestForRSA(AInput, AAlg, LHash, LNID, LMd);

  if AAlg.IsPSS then
  begin
    LRsaLen := JoseSSL.RSA_size(AKey);

    // A signature of the wrong width simply is not one this key produced. Checked here because
    // RSA_public_decrypt would report it as an error rather than a mismatch, and because it
    // guards the fixed-size buffer below.
    if Length(ASignature) <> LRsaLen then
      Exit(False);

    SetLength(LEM, LRsaLen);
    if JoseSSL.RSA_public_decrypt(Length(ASignature), @ASignature[0], @LEM[0], AKey, RSA_NO_PADDING) < 0 then
      Exit(False);

    Exit(JoseSSL.RSA_verify_PKCS1_PSS(AKey, @LHash[0], LMd, @LEM[0], AAlg.DigestBytes) = 1);
  end;

  Result := JoseSSL.RSA_verify(LNID, @LHash[0], Length(LHash), @ASignature[0], Length(ASignature), AKey) = 1;
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
      raise ESignException.CreateFmt(SJOSERSALoadPrivateKeyError, [JoseSSL.GetLastError]);
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
      raise ESignException.CreateFmt(SJOSERSALoadPublicKeyError, [JoseSSL.GetLastError]);
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
    raise Exception.Create(SJOSEECDSAUnsupportedAlgorithm);
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
    raise Exception.Create(SJOSEECDSAMemoryError);
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
      raise ESignException.CreateFmt(SJOSEECDSALoadPrivateKeyError, [JoseSSL.GetLastError]);
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
      raise Exception.CreateFmt(SJOSEECDSALoadPublicKeyError, [JoseSSL.GetLastError]);
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
    raise ESignException.CreateFmt(SJOSEECDSAKeyError, [JoseSSL.GetLastError]);
  try
    LShaHash := HashFromBytes(AInput, AAlg);

    LSig := JoseSSL.ECDSA_do_sign(@LShaHash[0], Length(LShaHash), LECKey);
    if LSig = nil then
      raise ESignException.CreateFmt(SJOSEECDSASignFailed, [JoseSSL.GetLastError]);
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
  // One source of truth for the width, shared with the length check the
  // algorithm layer applies when verifying
  LSigLength := AAlg.SignatureLength;

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

{ Key-material (JWK PEM import/export) helpers }

function BignumToBytes(ABN: PBIGNUM): TBytes;
var
  LLen: Integer;
begin
  Result := nil;
  if not Assigned(ABN) then
    Exit;

  LLen := JoseSSL.BN_num_bytes(ABN);
  SetLength(Result, LLen);
  if LLen > 0 then
    JoseSSL.BN_bn2bin(ABN, @Result[0]);
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
    raise ESignException.Create(SJOSEJWKMissingKeyComponent);

  Result := JoseSSL.BN_bin2bn(@AValue[0], Length(AValue), nil);
  if not Assigned(Result) then
    raise ESignException.Create(SJOSEJWKBignumConversionError);
end;

function NewBIOFromBytes(const AData: TBytes): PBIO;
begin
  Result := BIO_new(BIO_s_mem);
  if Length(AData) > 0 then
    BIO_write(Result, @AData[0], Length(AData));
end;

function ReadBIOToBytes(ABio: PBIO): TBytes;
var
  LBuffer: TBytes;
  LBytesRead: Integer;
begin
  Result := [];
  SetLength(LBuffer, 255);
  repeat
    LBytesRead := BIO_read(ABio, @LBuffer[0], 255);
    TJOSEUtils.ArrayPush(LBuffer, Result, LBytesRead);
  until LBytesRead <= 0;
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
    Result := JoseSSL.PEM_read_bio_RSA_PUBKEY(LBio, nil, nil, nil);
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
    Result := JoseSSL.PEM_read_bio_PUBKEY(LBio, nil, nil, nil);
  finally
    BIO_free(LBio);
  end;
end;

function RSAKeyToMaterial(ARsa: PRSA): TJOSERSAKeyMaterial;
begin
  // The result is written straight into the caller's variable, so the private components have to be
  // cleared rather than left over from whatever that variable held before: importing a public key
  // into a reused record would otherwise report IsPrivate and carry the previous key's secrets.
  Result := Default(TJOSERSAKeyMaterial);

  Result.Modulus := BignumToBytes(ARsa.n);
  Result.PublicExponent := BignumToBytes(ARsa.e);
  if Assigned(ARsa.d) then
  begin
    Result.PrivateExponent := BignumToBytes(ARsa.d);
    Result.P := BignumToBytes(ARsa.p);
    Result.Q := BignumToBytes(ARsa.q);
    Result.DP := BignumToBytes(ARsa.dmp1);
    Result.DQ := BignumToBytes(ARsa.dmq1);
    Result.QI := BignumToBytes(ARsa.iqmp);
  end;
end;

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

  LGroup := JoseSSL.EC_KEY_get0_group(AEC);
  if not Assigned(LGroup) then
    raise ESignException.Create(SJOSEJWKECNoGroup);

  LPoint := JoseSSL.EC_KEY_get0_public_key(AEC);
  if not Assigned(LPoint) then
    raise ESignException.Create(SJOSEJWKECNoPublicPoint);

  // For every curve JOSE supports (P-256/P-384/P-521/secp256k1) the group order is the same width
  // as a coordinate, so the field degree sizes x, y and d alike.
  LComponentLen := (JoseSSL.EC_GROUP_get_degree(LGroup) + 7) div 8;

  LX := JoseSSL.BN_new();
  LY := JoseSSL.BN_new();
  LCtx := JoseSSL.BN_CTX_new();
  try
    if JoseSSL.EC_POINT_get_affine_coordinates_GFp(LGroup, LPoint, LX, LY, LCtx) <> 1 then
      raise ESignException.Create(SJOSEJWKECReadPublicPointError);
    Result.X := BignumToFixedBytes(LX, LComponentLen);
    Result.Y := BignumToFixedBytes(LY, LComponentLen);
  finally
    JoseSSL.BN_free(LX);
    JoseSSL.BN_free(LY);
    JoseSSL.BN_CTX_free(LCtx);
  end;

  LPriv := JoseSSL.EC_KEY_get0_private_key(AEC);
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
  Result := JoseSSL.EC_KEY_new_by_curve_name(ANID);
  if not Assigned(Result) then
    raise ESignException.Create(SJOSEJWKECCreateKeyError);

  // Force named-curve (OID-referenced) encoding rather than explicit domain parameters, so
  // EC_GROUP_get_curve_name can recover the NID after a PEM write/read round-trip.
  JoseSSL.EC_KEY_set_asn1_flag(Result, JoseSSL.OPENSSL_EC_NAMED_CURVE);

  try
    LGroup := JoseSSL.EC_KEY_get0_group(Result);
    LCtx := JoseSSL.BN_CTX_new();
    LPoint := JoseSSL.EC_POINT_new(LGroup);
    try
      LX := BytesToBignum(AKeyMaterial.X);
      LY := BytesToBignum(AKeyMaterial.Y);
      try
        if JoseSSL.EC_POINT_set_affine_coordinates_GFp(LGroup, LPoint, LX, LY, LCtx) <> 1 then
          raise ESignException.Create(SJOSEJWKECInvalidPublicPoint);
        if JoseSSL.EC_KEY_set_public_key(Result, LPoint) <> 1 then
          raise ESignException.Create(SJOSEJWKECSetPublicKeyError);
      finally
        JoseSSL.BN_free(LX);
        JoseSSL.BN_free(LY);
      end;

      if AIncludePrivate then
      begin
        LD := BytesToBignum(AKeyMaterial.D);
        try
          if JoseSSL.EC_KEY_set_private_key(Result, LD) <> 1 then
            raise ESignException.Create(SJOSEJWKECSetPrivateKeyError);
        finally
          JoseSSL.BN_free(LD);
        end;
      end;
    finally
      JoseSSL.EC_POINT_free(LPoint);
      JoseSSL.BN_CTX_free(LCtx);
    end;
  except
    JoseSSL.EC_KEY_free(Result);
    raise;
  end;
end;

{ TDefaultRSAKeyMaterialProvider }

function TDefaultRSAKeyMaterialProvider.ImportPEM(const APEM: TBytes): TJOSERSAKeyMaterial;
var
  LRsa: PRSA;
  LPKey: PEVP_PKEY;
begin
  TJOSEDefaultOpenSslPem.LoadOpenSSL;

  if Length(APEM) = 0 then
    raise ESignException.Create(SJOSEJWKEmptyPEMData);

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
    raise ESignException.Create(SJOSEJWKUnrecognizedPEMFormat);
  try
    if EVP_PKEY_id(LPKey) = JoseSSL.NID_X9_62_id_ecPublicKey then
      raise ESignException.Create(SJOSEJWKPEMContainsECNotRSA);

    LRsa := EVP_PKEY_get1_RSA(LPKey);
    if not Assigned(LRsa) then
      raise ESignException.Create(SJOSEJWKUnsupportedPEMKeyType);
    try
      Result := RSAKeyToMaterial(LRsa);
    finally
      RSA_free(LRsa);
    end;
  finally
    EVP_PKEY_free(LPKey);
  end;
end;

function TDefaultRSAKeyMaterialProvider.ExportPEM(const AKeyMaterial: TJOSERSAKeyMaterial; AIncludePrivate: Boolean): TBytes;
var
  LBio: PBIO;
  LRsa: PRSA;
  LWritePrivate: Boolean;
begin
  TJOSEDefaultOpenSslPem.LoadOpenSSL;

  LWritePrivate := AIncludePrivate and AKeyMaterial.IsPrivate;

  LBio := BIO_new(BIO_s_mem);
  try
    LRsa := RSA_new;
    if not Assigned(LRsa) then
      raise ESignException.Create(SJOSEJWKAllocateRSAError);
    try
      LRsa.n := BytesToBignum(AKeyMaterial.Modulus);
      LRsa.e := BytesToBignum(AKeyMaterial.PublicExponent);
      if LWritePrivate then
      begin
        LRsa.d := BytesToBignum(AKeyMaterial.PrivateExponent);
        LRsa.p := BytesToBignum(AKeyMaterial.P);
        LRsa.q := BytesToBignum(AKeyMaterial.Q);
        LRsa.dmp1 := BytesToBignum(AKeyMaterial.DP);
        LRsa.dmq1 := BytesToBignum(AKeyMaterial.DQ);
        LRsa.iqmp := BytesToBignum(AKeyMaterial.QI);
        if PEM_write_bio_RSAPrivateKey(LBio, LRsa, nil, nil, 0, nil, nil) <> 1 then
          raise ESignException.Create(SJOSEJWKWriteRSAPrivateError);
      end
      else
      begin
        if PEM_write_bio_RSAPublicKey(LBio, LRsa) <> 1 then
          raise ESignException.Create(SJOSEJWKWriteRSAPublicError);
      end;
    finally
      RSA_free(LRsa);
    end;

    Result := ReadBIOToBytes(LBio);
  finally
    BIO_free(LBio);
  end;
end;

{ TDefaultECKeyMaterialProvider }

class function TDefaultECKeyMaterialProvider.CurveToNID(ACurve: TECCurve): Integer;
begin
  case ACurve of
    TECCurve.P256:      Result := JoseSSL.NID_X9_62_prime256v1;
    TECCurve.P384:       Result := JoseSSL.NID_secp384r1;
    TECCurve.P521:       Result := JoseSSL.NID_secp521r1;
    TECCurve.secp256k1:  Result := JoseSSL.NID_secp256k1;
  else
    raise ESignException.Create(SJOSEJWKUnsupportedECCurve);
  end;
end;

class function TDefaultECKeyMaterialProvider.NIDToCurve(ANID: Integer): TECCurve;
begin
  if ANID = JoseSSL.NID_X9_62_prime256v1 then
    Result := TECCurve.P256
  else if ANID = JoseSSL.NID_secp384r1 then
    Result := TECCurve.P384
  else if ANID = JoseSSL.NID_secp521r1 then
    Result := TECCurve.P521
  else if ANID = JoseSSL.NID_secp256k1 then
    Result := TECCurve.secp256k1
  else
    raise ESignException.CreateFmt(SJOSEJWKUnsupportedECCurveNID, [ANID]);
end;

function TDefaultECKeyMaterialProvider.ImportPEM(const APEM: TBytes): TJOSEECKeyMaterial;
var
  LEC: PEC_KEY;
  LPKey: PEVP_PKEY;
  LGroup: PEC_GROUP;
  LRsa: PRSA;
begin
  TJOSEDefaultOpenSslPem.LoadOpenSSL;

  if Length(APEM) = 0 then
    raise ESignException.Create(SJOSEJWKEmptyPEMData);

  if not JoseSSL.EnsureECKeySupport then
    raise ESignException.Create(SJOSEJWKECSupportUnavailable);

  LRsa := TryLoadRSA(APEM);
  if Assigned(LRsa) then
  begin
    RSA_free(LRsa);
    raise ESignException.Create(SJOSEJWKPEMContainsRSANotEC);
  end;

  LPKey := TryLoadGenericPKey(APEM);
  if not Assigned(LPKey) then
    raise ESignException.Create(SJOSEJWKUnrecognizedPEMFormat);
  try
    if EVP_PKEY_id(LPKey) <> JoseSSL.NID_X9_62_id_ecPublicKey then
      raise ESignException.Create(SJOSEJWKPEMNoECKey);

    LEC := EVP_PKEY_get1_EC_KEY(LPKey);
    if not Assigned(LEC) then
      raise ESignException.Create(SJOSEJWKExtractECKeyError);
    try
      LGroup := JoseSSL.EC_KEY_get0_group(LEC);
      if not Assigned(LGroup) then
        raise ESignException.Create(SJOSEJWKECNoGroup);

      Result := ECKeyToMaterial(NIDToCurve(JoseSSL.EC_GROUP_get_curve_name(LGroup)), LEC);
    finally
      JoseSSL.EC_KEY_free(LEC);
    end;
  finally
    EVP_PKEY_free(LPKey);
  end;
end;

function TDefaultECKeyMaterialProvider.ExportPEM(const AKeyMaterial: TJOSEECKeyMaterial; AIncludePrivate: Boolean): TBytes;
var
  LBio: PBIO;
  LEC: PEC_KEY;
  LPKey: PEVP_PKEY;
  LWritePrivate: Boolean;
begin
  TJOSEDefaultOpenSslPem.LoadOpenSSL;

  if not JoseSSL.EnsureECKeySupport then
    raise ESignException.Create(SJOSEJWKECSupportUnavailable);

  LWritePrivate := AIncludePrivate and AKeyMaterial.IsPrivate;

  LBio := BIO_new(BIO_s_mem);
  try
    LEC := BuildECKey(AKeyMaterial, CurveToNID(AKeyMaterial.Curve), LWritePrivate);
    try
      LPKey := EVP_PKEY_new;
      if not Assigned(LPKey) then
        raise ESignException.Create(SJOSEJWKAllocateEVPPKeyError);
      try
        if EVP_PKEY_set1_EC_KEY(LPKey, LEC) <> 1 then
          raise ESignException.Create(SJOSEJWKWrapECKeyError);

        if LWritePrivate then
        begin
          if PEM_write_bio_PrivateKey(LBio, LPKey, nil, nil, 0, nil, nil) <> 1 then
            raise ESignException.Create(SJOSEJWKWriteECPrivateError);
        end
        else
        begin
          if JoseSSL.PEM_write_bio_PUBKEY(LBio, LPKey) <> 1 then
            raise ESignException.Create(SJOSEJWKWriteECPublicError);
        end;
      finally
        EVP_PKEY_free(LPKey);
      end;
    finally
      JoseSSL.EC_KEY_free(LEC);
    end;

    Result := ReadBIOToBytes(LBio);
  finally
    BIO_free(LBio);
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
    raise Exception.Create(SJOSEErrorLoadingOpenSSLLibraries);

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
  TJOSEProviders.RSAKeyMaterial := TDefaultRSAKeyMaterialProvider.Create;
  TJOSEProviders.ECKeyMaterial := TDefaultECKeyMaterialProvider.Create;
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
  TJOSEProviders.RSAKeyMaterial := nil;
  TJOSEProviders.ECKeyMaterial := nil;
{$ENDIF}
end;

end.
