{******************************************************************************}
{                                                                              }
{  Delphi JOSE-JWT Library                                                     }
{  Copyright (c) 2015 Paolo Rossi                                              }
{  https://github.com/paolo-rossi/delphi-jose-jwt                              }
{                                                                              }
{  Licensed under the MIT license                                              }
{                                                                              }
{******************************************************************************}

unit JOSE.Providers.CryptoLib;

{$I ..\JOSE.inc}

interface

uses
  System.SysUtils,
  JOSE.Types.Bytes,
  JOSE.Providers.Interfaces,
  JOSE.Crypto.Algorithms,
  ClpIAsymmetricKeyParameter,
  ClpIAsn1Objects;

type
  TCryptoLibBase64Provider = class(TInterfacedObject, IJOSEBase64Provider)
  public
    function Encode(const ASource: TJOSEBytes): TJOSEBytes;
    function Decode(const ASource: TJOSEBytes): TJOSEBytes;
    function TryDecode(const ASource: TJOSEBytes): TJOSEBytes;
    function URLEncode(const ASource: TJOSEBytes): TJOSEBytes;
    function URLDecode(const ASource: TJOSEBytes): TJOSEBytes;
    function TryURLDecode(const ASource: TJOSEBytes): TJOSEBytes;
  end;

  TCryptoLibHmacProvider = class(TInterfacedObject, IJOSEHmacProvider)
  strict private
    function HmacMechanism(AAlg: THMACAlgorithm): string;
  public
    function Sign(const AInput, AKey: TBytes; AAlg: THMACAlgorithm): TBytes;
  end;

  TCryptoLibCertificateProvider = class(TInterfacedObject, IJOSECertificateProvider)
  strict private
    function ExpectedCertPkAlg(AExpected: TJOSECertificatePublicKey): IDerObjectIdentifier;
    function WritePublicKeyPem(const APublicKey: IAsymmetricKeyParameter): TBytes;
  public
    function PublicKeyFromCertificate(const ACertificate: TBytes): TBytes;
    function VerifyCertificate(const ACertificate: TBytes; AExpected: TJOSECertificatePublicKey): Boolean;
  end;

  TCryptoLibRSAProvider = class(TInterfacedObject, IJOSESignerRSA)
  strict private
    FCertificate: IJOSECertificateProvider;
    function PemToPublicKey(const APem: TBytes): IAsymmetricKeyParameter;
    function PemToPrivateKey(const APem: TBytes): IAsymmetricKeyParameter;
    function RsaMechanism(AAlg: TRSAAlgorithm): string;
    function SignWithRsa(const AInput: TBytes; const AKey: IAsymmetricKeyParameter; AAlg: TRSAAlgorithm): TBytes;
    function VerifyWithRsa(const AInput, ASignature: TBytes; const AKey: IAsymmetricKeyParameter; AAlg: TRSAAlgorithm): Boolean;
  public
    constructor Create(const ACertificate: IJOSECertificateProvider);
    function Sign(const AInput, AKey: TBytes; AAlg: TRSAAlgorithm): TBytes;
    function Verify(const AInput, ASignature, AKey: TBytes; AAlg: TRSAAlgorithm): Boolean;
    function VerifyWithCertificate(const AInput, ASignature, ACertificate: TBytes; AAlg: TRSAAlgorithm): Boolean;
    function VerifyPublicKey(const AKey: TBytes): Boolean;
    function VerifyPrivateKey(const AKey: TBytes): Boolean;
  end;

  TCryptoLibECDSAProvider = class(TInterfacedObject, IJOSESignerECDSA)
  strict private
    FCertificate: IJOSECertificateProvider;
    function ExpectedEcCurveOid(AAlg: TECDSAAlgorithm): IDerObjectIdentifier;
    procedure EnsureNamedCurve(const AKey: IAsymmetricKeyParameter; AAlg: TECDSAAlgorithm);
    function EcdsaMechanism(AAlg: TECDSAAlgorithm): string;
    function PemToPublicKey(const APem: TBytes): IAsymmetricKeyParameter;
    function PemToPrivateKey(const APem: TBytes): IAsymmetricKeyParameter;
    function SignWithEc(const AInput: TBytes; const AKey: IAsymmetricKeyParameter; AAlg: TECDSAAlgorithm): TBytes;
    function VerifyWithEc(const AInput, ASignature: TBytes; const AKey: IAsymmetricKeyParameter; AAlg: TECDSAAlgorithm): Boolean;
  public
    constructor Create(const ACertificate: IJOSECertificateProvider);
    function Sign(const AInput, APrivateKey: TBytes; AAlg: TECDSAAlgorithm): TBytes;
    function Verify(const AInput, ASignature, APublicKey: TBytes; AAlg: TECDSAAlgorithm): Boolean;
    function VerifyWithCertificate(const AInput, ASignature, ACertificate: TBytes; AAlg: TECDSAAlgorithm): Boolean;
    function VerifyPublicKey(const AKey: TBytes): Boolean;
    function VerifyPrivateKey(const AKey: TBytes): Boolean;
  end;

  /// <summary>CryptoLib-backed raw RSA key import/export (JWK PEM support).</summary>
  TCryptoLibRSAKeyMaterialProvider = class(TInterfacedObject, IJOSERSAKeyMaterialProvider)
  public
    function ImportPEM(const APEM: TBytes): TJOSERSAKeyMaterial;
    function ExportPEM(const AKeyMaterial: TJOSERSAKeyMaterial; AIncludePrivate: Boolean): TBytes;
  end;

  /// <summary>CryptoLib-backed raw EC key import/export (JWK PEM support).</summary>
  TCryptoLibECKeyMaterialProvider = class(TInterfacedObject, IJOSEECKeyMaterialProvider)
  strict private
    class function CurveToOid(ACurve: TECCurve): IDerObjectIdentifier; static;
    class function OidToCurve(const AOid: IDerObjectIdentifier): TECCurve; static;
  public
    function ImportPEM(const APEM: TBytes): TJOSEECKeyMaterial;
    function ExportPEM(const AKeyMaterial: TJOSEECKeyMaterial; AIncludePrivate: Boolean): TBytes;
  end;

  /// <summary>CryptoLib-backed AES-GCM, for JWE content encryption (A128GCM/A192GCM/A256GCM).</summary>
  TCryptoLibAESGCMProvider = class(TInterfacedObject, IJOSEAESGCMProvider)
  public
    function Encrypt(const APlaintext, AKey, AIV, AAdditionalData: TBytes; out ATag: TBytes): TBytes;
    function Decrypt(const ACiphertext, AKey, AIV, AAdditionalData, ATag: TBytes): TBytes;
  end;

  /// <summary>CryptoLib-backed AES-CBC with PKCS#7 padding, for JWE A128CBC-HS256/A192CBC-HS384/A256CBC-HS512.</summary>
  TCryptoLibAESCBCProvider = class(TInterfacedObject, IJOSEAESCBCProvider)
  public
    function Encrypt(const APlaintext, AKey, AIV: TBytes): TBytes;
    function Decrypt(const ACiphertext, AKey, AIV: TBytes): TBytes;
  end;

  /// <summary>CryptoLib-backed RSAES-OAEP, for JWE key management (RSA-OAEP/RSA-OAEP-256).</summary>
  TCryptoLibRSAEncryptionProvider = class(TInterfacedObject, IJOSERSAEncryptionProvider)
  strict private
    FCertificate: IJOSECertificateProvider;
  public
    constructor Create(const ACertificate: IJOSECertificateProvider);
    function Encrypt(const APlaintext, APublicKey: TBytes; ADigest: TJOSEOAEPDigest): TBytes;
    function Decrypt(const ACiphertext, APrivateKey: TBytes; ADigest: TJOSEOAEPDigest): TBytes;
  end;

  TJOSECryptoLibProviders = class
  public
    /// <summary>Wires CryptoLib implementations into <see cref="JOSE.Providers|TJOSEProviders"/> (Base64, HMAC, cert, RSA, ECDSA, key material, AES-GCM, RSA-OAEP).</summary>
    class procedure Register; static;
    /// <summary>Clears <see cref="JOSE.Providers|TJOSEProviders"/> slots previously set by <see cref="Register"/>.</summary>
    class procedure Unregister; static;
  end;

implementation

uses
  JOSE.Providers,
  System.Classes,
  System.Rtti,
  ClpMacUtilities,
  ClpKeyParameter,
  ClpICipherParameters,
  ClpCryptoLibTypes,
  ClpSignerUtilities,
  ClpISigner,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpOpenSslPemReader,
  ClpOpenSslPemWriter,
  ClpX509CertificateParser,
  ClpIX509CertificateParser,
  ClpIX509Certificate,
  ClpIAsymmetricCipherKeyPair,
  ClpIX509Asn1Objects,
  ClpPkcsObjectIdentifiers,
  ClpX9ObjectIdentifiers,
  ClpSecObjectIdentifiers,
  ClpIRsaParameters,
  ClpRsaParameters,
  ClpIECParameters,
  ClpECParameters,
  ClpECGenerators,
  ClpIECCommon,
  ClpBigInteger,
  ClpBigIntegerUtilities,
  SbpBase64,
  ClpIBlockCipher,
  ClpIAsymmetricBlockCipher,
  ClpIGcmBlockCipher,
  ClpGcmBlockCipher,
  ClpIAeadParameters,
  ClpAeadParameters,
  ClpIKeyParameter,
  ClpAesUtilities,
  ClpRsaBlindedEngine,
  ClpOaepEncoding,
  ClpDigestUtilities,
  ClpCipherUtilities,
  ClpIBufferedCipher,
  ClpParametersWithIV,
  JOSE.Signing.Base;

resourcestring
  SJOSECryptoLibUnsupportedHMACDigest = '[CryptoLib] Unsupported HMAC digest';
  SJOSECryptoLibHMACError = '[CryptoLib] HMAC error: %s';
  SJOSECryptoLibEmptyPEMObject = '[CryptoLib] Empty PEM object';
  SJOSECryptoLibPEMNoPrivateKey = '[CryptoLib] PEM does not contain a private key';
  SJOSECryptoLibPEMNoPublicKey = '[CryptoLib] PEM does not contain a public key';
  SJOSECryptoLibExpectedPublicKeyPEM = '[CryptoLib] Expected a public key PEM (SPKI), not an X.509 certificate PEM';
  SJOSECryptoLibNoCertProvider = '[CryptoLib] Certificate supplied but no IJOSECertificateProvider was configured';
  SJOSECryptoLibCertNotRSA = '[CryptoLib] Certificate does not contain an RSA public key';
  SJOSECryptoLibCertNotEC = '[CryptoLib] Certificate does not contain an EC public key';
  SJOSEUnhandledCertPublicKeyValue = 'Unhandled TJOSECertificatePublicKey value';
  SJOSECryptoLibNoPublicKeyInCert = '[CryptoLib] Unable to read public key from certificate';
  SJOSECryptoLibCertificateError = '[CryptoLib] Certificate error: %s';
  SJOSECryptoLibKeyNotRSA = '[CryptoLib] Key is not an RSA key';
  SJOSECryptoLibKeyNotRSAPrivate = '[CryptoLib] Key is not an RSA private key';
  SJOSECryptoLibRSAPEMNoPrivateKey = '[CryptoLib] RSA PEM did not contain a private key';
  SJOSECryptoLibGCMKeyLength = '[CryptoLib] AES-GCM key must be 16, 24 or 32 bytes, not %d';
  SJOSECryptoLibGCMIVLength = '[CryptoLib] AES-GCM IV must be 12 bytes, not %d';
  SJOSECryptoLibGCMTagLength = '[CryptoLib] AES-GCM authentication tag must be 16 bytes, not %d';
  SJOSECryptoLibGCMEncryptError = '[CryptoLib] AES-GCM encryption error: %s';
  // Deliberately without detail: see IJOSEAESGCMProvider.Decrypt
  SJOSECryptoLibGCMDecryptFailed = '[CryptoLib] AES-GCM decryption failed';
  SJOSECryptoLibCBCKeyLength = '[CryptoLib] AES-CBC key must be 16, 24 or 32 bytes, not %d';
  SJOSECryptoLibCBCIVLength = '[CryptoLib] AES-CBC IV must be 16 bytes, not %d';
  SJOSECryptoLibCBCEncryptError = '[CryptoLib] AES-CBC encryption error: %s';
  // Deliberately without detail: see IJOSEAESCBCProvider.Decrypt
  SJOSECryptoLibCBCDecryptFailed = '[CryptoLib] AES-CBC decryption failed';
  SJOSECryptoLibOAEPEncryptError = '[CryptoLib] RSA-OAEP encryption error: %s';
  // Deliberately without detail: see IJOSERSAEncryptionProvider.Decrypt
  SJOSECryptoLibOAEPDecryptFailed = '[CryptoLib] RSA-OAEP decryption failed';
  SJOSECryptoLibUnsupportedRSAAlg = '[CryptoLib] Unsupported RSA JWS algorithm';
  SJOSECryptoLibRSASignError = '[CryptoLib] RSA sign error: %s';
  SJOSECryptoLibUnsupportedECDSAAlg = '[CryptoLib] Unsupported ECDSA JWS algorithm';
  SJOSECryptoLibKeyNotEC = '[CryptoLib] Key is not an EC key';
  SJOSECryptoLibCurveMismatch = '[CryptoLib] EC key curve does not match the selected JOSE algorithm';
  SJOSECryptoLibKeyNotECPublic = '[CryptoLib] Key is not an EC public key';
  SJOSECryptoLibKeyNotECPrivate = '[CryptoLib] Key is not an EC private key';
  SJOSECryptoLibECDSASignError = '[CryptoLib] ECDSA sign error: %s';
  SJOSECryptoLibJWKEmptyPEMData = '[CryptoLib][JWK] Empty PEM data';
  SJOSECryptoLibJWKExpectedKeyPEM = '[CryptoLib][JWK] Expected a key PEM, not an X.509 certificate PEM';
  SJOSECryptoLibJWKNoKeyInPEM = '[CryptoLib][JWK] PEM does not contain a key';
  SJOSECryptoLibJWKPEMNotRSA = '[CryptoLib][JWK] PEM does not contain an RSA key';
  SJOSECryptoLibJWKPEMNotEC = '[CryptoLib][JWK] PEM does not contain an EC key';
  SJOSECryptoLibJWKRSANoCRT = '[CryptoLib][JWK] RSA private key has no CRT components (public exponent unavailable)';
  SJOSECryptoLibJWKECNoNamedCurve = '[CryptoLib][JWK] EC key does not use a named curve';
  SJOSECryptoLibJWKMissingComponent = '[CryptoLib][JWK] Missing required key component [%s]';
  SJOSECryptoLibJWKUnsupportedECCurve = '[CryptoLib][JWK] Unsupported EC curve';
  SJOSECryptoLibJWKUnsupportedECCurveOID = '[CryptoLib][JWK] Unsupported EC curve (OID %s)';
  SJOSECryptoLibJWKWritePEMError = '[CryptoLib][JWK] Unable to write the key PEM: %s';

{ TJOSECryptoLibPem }

type
  TJOSECryptoLibPem = class
  strict private
    /// <summary>First PEM object must be SPKI / public key (not an X.509 certificate).</summary>
    class function ReadPublicKeyMaterial(const APem: TBytes): IAsymmetricKeyParameter; static;
    class function ParsePublicKeyFromDecodedPem(const LVal: TValue): IAsymmetricKeyParameter; static;
  public
    class function ReadPrivateKey(const APem: TBytes): IAsymmetricKeyParameter; static;
    /// <summary>
    /// Reads a public key from PEM. Dispatches on PEM type (e.g. CERTIFICATE vs PUBLIC KEY).
    /// For certificate PEM, <paramref name="ACertProvider"/> must decode and validate <paramref name="ACertExpected"/>.
    /// </summary>
    class function ReadPublicKey(const APem: TBytes; const ACertProvider: IJOSECertificateProvider;
      ACertExpected: TJOSECertificatePublicKey): IAsymmetricKeyParameter; static;
    /// <summary>
    /// Reads whichever key halves a PEM carries, for the key-material (JWK) providers: a key pair
    /// PEM yields both, a lone private/public key PEM yields that one and leaves the other nil.
    /// Unlike <see cref="ReadPrivateKey"/>/<see cref="ReadPublicKey"/> it accepts either kind, and
    /// never accepts a certificate.
    /// </summary>
    class procedure ReadKeyMaterial(const APem: TBytes; out APrivateKey, APublicKey: IAsymmetricKeyParameter); static;
    /// <summary>Writes any asymmetric key as PEM: RSA private keys as PKCS#1, EC private keys as
    ///   SEC1, public keys as SPKI, which is what <c>TOpenSslPemWriter</c> emits per key type.</summary>
    class function WriteKey(const AKey: IAsymmetricKeyParameter): TBytes; static;
  end;

  /// <summary>Plumbing shared by the two key-material (JWK) providers.</summary>
  TJOSECryptoLibKeyMaterial = class
  public
    /// <summary>The half of a decoded PEM that carries the most key material: a private key
    ///   determines every JWK component, a public key only the public ones.</summary>
    class function SelectKey(const APrivateKey, APublicKey: IAsymmetricKeyParameter): IAsymmetricKeyParameter; static;
    /// <summary>Converts a required JWK key component, naming it in the error when it is absent.</summary>
    class function RequiredComponent(const AValue: TBytes; const AName: string): TBigInteger; static;
  end;

class function TJOSECryptoLibPem.WriteKey(const AKey: IAsymmetricKeyParameter): TBytes;
var
  LStream: TMemoryStream;
  LWriter: TOpenSslPemWriter;
begin
  LStream := TMemoryStream.Create;
  try
    LWriter := TOpenSslPemWriter.Create(LStream);
    try
      LWriter.WriteObject(TValue.From<IAsymmetricKeyParameter>(AKey));
    finally
      LWriter.Free;
    end;
    SetLength(Result, LStream.Size);
    if LStream.Size > 0 then
      Move(LStream.Memory^, Result[0], LStream.Size);
  finally
    LStream.Free;
  end;
end;

{ TJOSECryptoLibKeyMaterial }

class function TJOSECryptoLibKeyMaterial.SelectKey(const APrivateKey, APublicKey: IAsymmetricKeyParameter): IAsymmetricKeyParameter;
begin
  if Assigned(APrivateKey) then
    Result := APrivateKey
  else
    Result := APublicKey;
end;

class function TJOSECryptoLibKeyMaterial.RequiredComponent(const AValue: TBytes; const AName: string): TBigInteger;
begin
  if Length(AValue) = 0 then
    raise ESignException.CreateFmt(SJOSECryptoLibJWKMissingComponent, [AName]);
  Result := TBigIntegerUtilities.FromUnsignedByteArray(AValue);
end;

{ TCryptoLibBase64Provider }

function TCryptoLibBase64Provider.Encode(const ASource: TJOSEBytes): TJOSEBytes;
begin
  Result := SbpBase64.TBase64.Default.Encode(ASource.AsBytes);
end;

function TCryptoLibBase64Provider.Decode(const ASource: TJOSEBytes): TJOSEBytes;
begin
  Result := SbpBase64.TBase64.Default.Decode(Trim(ASource.AsString));
end;

function TCryptoLibBase64Provider.TryDecode(const ASource: TJOSEBytes): TJOSEBytes;
var
  LBuf: TBytes;
  LWritten: Int32;
  LText: string;
begin
  Result.Clear;
  LText := Trim(ASource.AsString);
  if LText = '' then
    Exit;
  SetLength(LBuf, SbpBase64.TBase64.Default.GetSafeByteCountForDecoding(LText));
  if SbpBase64.TBase64.Default.TryDecode(LText, LBuf, LWritten) then
    Result := Copy(LBuf, 0, LWritten);
end;

function TCryptoLibBase64Provider.URLDecode(const ASource: TJOSEBytes): TJOSEBytes;
begin
  Result := SbpBase64.TBase64.Url.Decode(Trim(ASource.AsString));
end;

function TCryptoLibBase64Provider.URLEncode(const ASource: TJOSEBytes): TJOSEBytes;
begin
  Result := SbpBase64.TBase64.Url.Encode(ASource.AsBytes);
end;

function TCryptoLibBase64Provider.TryURLDecode(const ASource: TJOSEBytes): TJOSEBytes;
var
  LBuf: TBytes;
  LWritten: Int32;
  LText: string;
  LBufChars: Integer;
begin
  Result.Clear;
  LText := Trim(ASource.AsString);
  if LText = '' then
    Exit;
  LBufChars := Length(LText);
  SetLength(LBuf, (LBufChars + 3) div 4 * 3);
  if SbpBase64.TBase64.Url.TryDecode(LText, LBuf, LWritten) then
    Result := Copy(LBuf, 0, LWritten);
end;

{ TCryptoLibHmacProvider }

function TCryptoLibHmacProvider.HmacMechanism(AAlg: THMACAlgorithm): string;
begin
  case AAlg of
    THMACAlgorithm.SHA256:
      Result := 'HMAC-SHA256';
    THMACAlgorithm.SHA384:
      Result := 'HMAC-SHA384';
    THMACAlgorithm.SHA512:
      Result := 'HMAC-SHA512';
  else
    raise Exception.Create(SJOSECryptoLibUnsupportedHMACDigest);
  end;
end;

function TCryptoLibHmacProvider.Sign(const AInput, AKey: TBytes; AAlg: THMACAlgorithm): TBytes;
var
  LKeyParam: ICipherParameters;
begin
  try
    LKeyParam := TKeyParameter.Create(AKey);
    Result := TMacUtilities.CalculateMac(HmacMechanism(AAlg), LKeyParam, AInput);
  except
    on E: Exception do
      raise Exception.CreateFmt(SJOSECryptoLibHMACError, [E.Message]);
  end;
end;

class function TJOSECryptoLibPem.ReadPrivateKey(const APem: TBytes): IAsymmetricKeyParameter;
var
  LStream: TStringStream;
  LReader: TOpenSslPemReader;
  LVal: TValue;
  LKp: IAsymmetricCipherKeyPair;
begin
  Result := nil;
  LStream := TStringStream.Create(TEncoding.ASCII.GetString(APem));
  try
    LReader := TOpenSslPemReader.Create(LStream);
    try
      LVal := LReader.ReadObject();
      if LVal.IsEmpty then
        raise ESignException.Create(SJOSECryptoLibEmptyPEMObject);
      if LVal.TryAsType<IAsymmetricKeyParameter>(Result) and (Result <> nil) then
        Exit;
      if LVal.TryAsType<IAsymmetricCipherKeyPair>(LKp) and (LKp <> nil) then
      begin
        Result := LKp.Private;
        Exit;
      end;
      raise ESignException.Create(SJOSECryptoLibPEMNoPrivateKey);
    finally
      LReader.Free;
    end;
  finally
    LStream.Free;
  end;
end;

class function TJOSECryptoLibPem.ParsePublicKeyFromDecodedPem(const LVal: TValue): IAsymmetricKeyParameter;
var
  LKp: IAsymmetricCipherKeyPair;
begin
  if LVal.TryAsType<IAsymmetricKeyParameter>(Result) and (Result <> nil) then
    Exit;
  if LVal.TryAsType<IAsymmetricCipherKeyPair>(LKp) and (LKp <> nil) then
  begin
    Result := LKp.Public;
    Exit;
  end;
  raise ESignException.Create(SJOSECryptoLibPEMNoPublicKey);
end;

class function TJOSECryptoLibPem.ReadPublicKeyMaterial(const APem: TBytes): IAsymmetricKeyParameter;
var
  LStream: TStringStream;
  LReader: TOpenSslPemReader;
  LVal: TValue;
  LCert: IX509Certificate;
begin
  LStream := TStringStream.Create(TEncoding.ASCII.GetString(APem));
  try
    LReader := TOpenSslPemReader.Create(LStream);
    try
      LVal := LReader.ReadObject();
      if LVal.IsEmpty then
        raise ESignException.Create(SJOSECryptoLibEmptyPEMObject);
      if LVal.TryAsType<IX509Certificate>(LCert) and (LCert <> nil) then
        raise ESignException.Create(SJOSECryptoLibExpectedPublicKeyPEM);
      Result := ParsePublicKeyFromDecodedPem(LVal);
    finally
      LReader.Free;
    end;
  finally
    LStream.Free;
  end;
end;

class function TJOSECryptoLibPem.ReadPublicKey(const APem: TBytes; const ACertProvider: IJOSECertificateProvider;
  ACertExpected: TJOSECertificatePublicKey): IAsymmetricKeyParameter;
var
  LStream: TStringStream;
  LReader: TOpenSslPemReader;
  LVal: TValue;
  LCert: IX509Certificate;
  LSpkiPem: TBytes;
begin
  LStream := TStringStream.Create(TEncoding.ASCII.GetString(APem));
  try
    LReader := TOpenSslPemReader.Create(LStream);
    try
      LVal := LReader.ReadObject();
      if LVal.IsEmpty then
        raise ESignException.Create(SJOSECryptoLibEmptyPEMObject);

      if LVal.TryAsType<IX509Certificate>(LCert) and (LCert <> nil) then
      begin
        if ACertProvider = nil then
          raise ESignException.Create(SJOSECryptoLibNoCertProvider);
        if not ACertProvider.VerifyCertificate(APem, ACertExpected) then
        begin
          case ACertExpected of
            TJOSECertificatePublicKey.RSA:
              raise ESignException.Create(SJOSECryptoLibCertNotRSA);
            TJOSECertificatePublicKey.EC:
              raise ESignException.Create(SJOSECryptoLibCertNotEC);
          end;
        end;
        LSpkiPem := ACertProvider.PublicKeyFromCertificate(APem);
        Result := ReadPublicKeyMaterial(LSpkiPem);
        Exit;
      end;

      Result := ParsePublicKeyFromDecodedPem(LVal);
    finally
      LReader.Free;
    end;
  finally
    LStream.Free;
  end;
end;

class procedure TJOSECryptoLibPem.ReadKeyMaterial(const APem: TBytes; out APrivateKey, APublicKey: IAsymmetricKeyParameter);
var
  LStream: TStringStream;
  LReader: TOpenSslPemReader;
  LVal: TValue;
  LKp: IAsymmetricCipherKeyPair;
  LCert: IX509Certificate;
  LKey: IAsymmetricKeyParameter;
begin
  APrivateKey := nil;
  APublicKey := nil;

  LStream := TStringStream.Create(TEncoding.ASCII.GetString(APem));
  try
    LReader := TOpenSslPemReader.Create(LStream);
    try
      LVal := LReader.ReadObject();
      if LVal.IsEmpty then
        raise ESignException.Create(SJOSECryptoLibEmptyPEMObject);
      if LVal.TryAsType<IX509Certificate>(LCert) and (LCert <> nil) then
        raise ESignException.Create(SJOSECryptoLibJWKExpectedKeyPEM);

      // A PKCS#1/SEC1 private key PEM decodes to a key pair, a PKCS#8 or SPKI PEM to a lone key.
      if LVal.TryAsType<IAsymmetricKeyParameter>(LKey) and (LKey <> nil) then
      begin
        if LKey.IsPrivate then
          APrivateKey := LKey
        else
          APublicKey := LKey;
        Exit;
      end;

      if LVal.TryAsType<IAsymmetricCipherKeyPair>(LKp) and (LKp <> nil) then
      begin
        APrivateKey := LKp.Private;
        APublicKey := LKp.Public;
        Exit;
      end;

      raise ESignException.Create(SJOSECryptoLibJWKNoKeyInPEM);
    finally
      LReader.Free;
    end;
  finally
    LStream.Free;
  end;
end;

{ TCryptoLibCertificateProvider }

function TCryptoLibCertificateProvider.ExpectedCertPkAlg(AExpected: TJOSECertificatePublicKey): IDerObjectIdentifier;
begin
  case AExpected of
    TJOSECertificatePublicKey.RSA:
      Result := TPkcsObjectIdentifiers.RsaEncryption;
    TJOSECertificatePublicKey.EC:
      Result := TX9ObjectIdentifiers.IdECPublicKey;
  else
    raise EArgumentException.Create(SJOSEUnhandledCertPublicKeyValue);
  end;
end;

function TCryptoLibCertificateProvider.WritePublicKeyPem(const APublicKey: IAsymmetricKeyParameter): TBytes;
begin
  Result := TJOSECryptoLibPem.WriteKey(APublicKey);
end;

function TCryptoLibCertificateProvider.PublicKeyFromCertificate(const ACertificate: TBytes): TBytes;
var
  LParser: IX509CertificateParser;
  LCert: IX509Certificate;
  LPub: IAsymmetricKeyParameter;
begin
  try
    LParser := TX509CertificateParser.Create;
    LCert := LParser.ReadCertificate(ACertificate);
    LPub := LCert.GetPublicKey;
    if LPub = nil then
      raise ESignException.Create(SJOSECryptoLibNoPublicKeyInCert);
    Result := WritePublicKeyPem(LPub);
  except
    on E: ESignException do
      raise;
    on E: Exception do
      raise ESignException.CreateFmt(SJOSECryptoLibCertificateError, [E.Message]);
  end;
end;

function TCryptoLibCertificateProvider.VerifyCertificate(const ACertificate: TBytes; AExpected: TJOSECertificatePublicKey): Boolean;
var
  LParser: IX509CertificateParser;
  LCert: IX509Certificate;
  LAlg, LExp: IDerObjectIdentifier;
begin
  try
    LParser := TX509CertificateParser.Create;
    LCert := LParser.ReadCertificate(ACertificate);
    LAlg := LCert.SubjectPublicKeyInfo.Algorithm.Algorithm;
    LExp := ExpectedCertPkAlg(AExpected);
    Result := (LAlg <> nil) and (LExp <> nil) and LAlg.Equals(LExp);
  except
    Result := False;
  end;
end;

{ TCryptoLibRSAProvider }

constructor TCryptoLibRSAProvider.Create(const ACertificate: IJOSECertificateProvider);
begin
  inherited Create;
  FCertificate := ACertificate;
end;

function TCryptoLibRSAProvider.PemToPublicKey(const APem: TBytes): IAsymmetricKeyParameter;
begin
  Result := TJOSECryptoLibPem.ReadPublicKey(APem, FCertificate, TJOSECertificatePublicKey.RSA);
  if not Supports(Result, IRsaKeyParameters) then
    raise ESignException.Create(SJOSECryptoLibKeyNotRSA);
end;

function TCryptoLibRSAProvider.PemToPrivateKey(const APem: TBytes): IAsymmetricKeyParameter;
begin
  Result := TJOSECryptoLibPem.ReadPrivateKey(APem);
  if not Supports(Result, IRsaKeyParameters) then
    raise ESignException.Create(SJOSECryptoLibKeyNotRSAPrivate);
  if not Result.IsPrivate then
    raise ESignException.Create(SJOSECryptoLibRSAPEMNoPrivateKey);
end;

function TCryptoLibRSAProvider.RsaMechanism(AAlg: TRSAAlgorithm): string;
begin
  case AAlg of
    TRSAAlgorithm.RS256:
      Result := 'SHA-256withRSA';
    TRSAAlgorithm.RS384:
      Result := 'SHA-384withRSA';
    TRSAAlgorithm.RS512:
      Result := 'SHA-512withRSA';

    // RFC 7518 3.5: RSASSA-PSS, MGF1 with the same hash and a salt the size of the digest.
    // TSignerUtilities maps these to a TPssSigner whose two-argument constructor defaults the
    // salt length to the digest size (ClpPssSigner.pas:183), which is exactly what the RFC wants.
    TRSAAlgorithm.PS256:
      Result := 'SHA-256withRSAandMGF1';
    TRSAAlgorithm.PS384:
      Result := 'SHA-384withRSAandMGF1';
    TRSAAlgorithm.PS512:
      Result := 'SHA-512withRSAandMGF1';
  else
    raise ESignException.Create(SJOSECryptoLibUnsupportedRSAAlg);
  end;
end;

function TCryptoLibRSAProvider.SignWithRsa(const AInput: TBytes; const AKey: IAsymmetricKeyParameter; AAlg: TRSAAlgorithm): TBytes;
var
  LSigner: ISigner;
  LRnd: ISecureRandom;
begin
  try
    LRnd := TSecureRandom.Create();
    LSigner := TSignerUtilities.InitSigner(RsaMechanism(AAlg), True, AKey, LRnd);
    LSigner.BlockUpdate(AInput, 0, Length(AInput));
    Result := LSigner.GenerateSignature();
  except
    on E: ESignException do
      raise;
    on E: Exception do
      raise ESignException.CreateFmt(SJOSECryptoLibRSASignError, [E.Message]);
  end;
end;

function TCryptoLibRSAProvider.VerifyWithRsa(const AInput, ASignature: TBytes; const AKey: IAsymmetricKeyParameter; AAlg: TRSAAlgorithm): Boolean;
var
  LSigner: ISigner;
begin
  try
    LSigner := TSignerUtilities.InitSigner(RsaMechanism(AAlg), False, AKey, nil);
    LSigner.BlockUpdate(AInput, 0, Length(AInput));
    Result := LSigner.VerifySignature(ASignature);
  except
    Result := False;
  end;
end;

function TCryptoLibRSAProvider.Sign(const AInput, AKey: TBytes; AAlg: TRSAAlgorithm): TBytes;
var
  LPriv: IAsymmetricKeyParameter;
begin
  LPriv := PemToPrivateKey(AKey);
  Result := SignWithRsa(AInput, LPriv, AAlg);
end;

function TCryptoLibRSAProvider.Verify(const AInput, ASignature, AKey: TBytes; AAlg: TRSAAlgorithm): Boolean;
var
  LPub: IAsymmetricKeyParameter;
begin
  try
    LPub := PemToPublicKey(AKey);
    Result := VerifyWithRsa(AInput, ASignature, LPub, AAlg);
  except
    Result := False;
  end;
end;

function TCryptoLibRSAProvider.VerifyWithCertificate(const AInput, ASignature, ACertificate: TBytes; AAlg: TRSAAlgorithm): Boolean;
var
  LPub: IAsymmetricKeyParameter;
begin
  try
    LPub := PemToPublicKey(ACertificate);
    Result := VerifyWithRsa(AInput, ASignature, LPub, AAlg);
  except
    Result := False;
  end;
end;

function TCryptoLibRSAProvider.VerifyPublicKey(const AKey: TBytes): Boolean;
begin
  try
    PemToPublicKey(AKey);
    Result := True;
  except
    Result := False;
  end;
end;

function TCryptoLibRSAProvider.VerifyPrivateKey(const AKey: TBytes): Boolean;
begin
  try
    PemToPrivateKey(AKey);
    Result := True;
  except
    Result := False;
  end;
end;

{ TCryptoLibECDSAProvider }

constructor TCryptoLibECDSAProvider.Create(const ACertificate: IJOSECertificateProvider);
begin
  inherited Create;
  FCertificate := ACertificate;
end;

function TCryptoLibECDSAProvider.ExpectedEcCurveOid(AAlg: TECDSAAlgorithm): IDerObjectIdentifier;
begin
  case AAlg of
    TECDSAAlgorithm.ES256:
      Result := TSecObjectIdentifiers.SecP256r1;
    TECDSAAlgorithm.ES256K:
      Result := TSecObjectIdentifiers.SecP256k1;
    TECDSAAlgorithm.ES384:
      Result := TSecObjectIdentifiers.SecP384r1;
    TECDSAAlgorithm.ES512:
      Result := TSecObjectIdentifiers.SecP521r1;
  else
    raise ESignException.Create(SJOSECryptoLibUnsupportedECDSAAlg);
  end;
end;

procedure TCryptoLibECDSAProvider.EnsureNamedCurve(const AKey: IAsymmetricKeyParameter; AAlg: TECDSAAlgorithm);
var
  LEc: IECKeyParameters;
  LExp, LHave: IDerObjectIdentifier;
begin
  if not Supports(AKey, IECKeyParameters, LEc) then
    raise ESignException.Create(SJOSECryptoLibKeyNotEC);
  LExp := ExpectedEcCurveOid(AAlg);
  LHave := LEc.PublicKeyParamSet;
  if (LHave = nil) or (LExp = nil) or (LHave.ID <> LExp.ID) then
    raise ESignException.Create(SJOSECryptoLibCurveMismatch);
end;

function TCryptoLibECDSAProvider.EcdsaMechanism(AAlg: TECDSAAlgorithm): string;
begin
  case AAlg of
    TECDSAAlgorithm.ES256, TECDSAAlgorithm.ES256K:
      Result := 'SHA-256withPLAIN-ECDSA';
    TECDSAAlgorithm.ES384:
      Result := 'SHA-384withPLAIN-ECDSA';
    TECDSAAlgorithm.ES512:
      Result := 'SHA-512withPLAIN-ECDSA';
  else
    raise ESignException.Create(SJOSECryptoLibUnsupportedECDSAAlg);
  end;
end;

function TCryptoLibECDSAProvider.PemToPublicKey(const APem: TBytes): IAsymmetricKeyParameter;
begin
  Result := TJOSECryptoLibPem.ReadPublicKey(APem, FCertificate, TJOSECertificatePublicKey.EC);
  if not Supports(Result, IECPublicKeyParameters) then
    raise ESignException.Create(SJOSECryptoLibKeyNotECPublic);
end;

function TCryptoLibECDSAProvider.PemToPrivateKey(const APem: TBytes): IAsymmetricKeyParameter;
begin
  Result := TJOSECryptoLibPem.ReadPrivateKey(APem);
  if not Supports(Result, IECPrivateKeyParameters) then
    raise ESignException.Create(SJOSECryptoLibKeyNotECPrivate);
end;

function TCryptoLibECDSAProvider.SignWithEc(const AInput: TBytes; const AKey: IAsymmetricKeyParameter; AAlg: TECDSAAlgorithm): TBytes;
var
  LSigner: ISigner;
  LRnd: ISecureRandom;
begin
  EnsureNamedCurve(AKey, AAlg);
  try
    LRnd := TSecureRandom.Create();
    LSigner := TSignerUtilities.InitSigner(EcdsaMechanism(AAlg), True, AKey, LRnd);
    LSigner.BlockUpdate(AInput, 0, Length(AInput));
    Result := TBytes(LSigner.GenerateSignature());
  except
    on E: ESignException do
      raise;
    on E: Exception do
      raise ESignException.CreateFmt(SJOSECryptoLibECDSASignError, [E.Message]);
  end;
end;

function TCryptoLibECDSAProvider.VerifyWithEc(const AInput, ASignature: TBytes; const AKey: IAsymmetricKeyParameter; AAlg: TECDSAAlgorithm): Boolean;
var
  LSigner: ISigner;
begin
  try
    EnsureNamedCurve(AKey, AAlg);
    LSigner := TSignerUtilities.InitSigner(EcdsaMechanism(AAlg), False, AKey, nil);
    LSigner.BlockUpdate(AInput, 0, Length(AInput));
    Result := LSigner.VerifySignature(ASignature);
  except
    Result := False;
  end;
end;

function TCryptoLibECDSAProvider.Sign(const AInput, APrivateKey: TBytes; AAlg: TECDSAAlgorithm): TBytes;
var
  LPriv: IAsymmetricKeyParameter;
begin
  LPriv := PemToPrivateKey(APrivateKey);
  Result := SignWithEc(AInput, LPriv, AAlg);
end;

function TCryptoLibECDSAProvider.Verify(const AInput, ASignature, APublicKey: TBytes; AAlg: TECDSAAlgorithm): Boolean;
var
  LPub: IAsymmetricKeyParameter;
begin
  try
    LPub := PemToPublicKey(APublicKey);
    Result := VerifyWithEc(AInput, ASignature, LPub, AAlg);
  except
    Result := False;
  end;
end;

function TCryptoLibECDSAProvider.VerifyWithCertificate(const AInput, ASignature, ACertificate: TBytes; AAlg: TECDSAAlgorithm): Boolean;
var
  LPub: IAsymmetricKeyParameter;
begin
  try
    LPub := PemToPublicKey(ACertificate);
    Result := VerifyWithEc(AInput, ASignature, LPub, AAlg);
  except
    Result := False;
  end;
end;

function TCryptoLibECDSAProvider.VerifyPublicKey(const AKey: TBytes): Boolean;
begin
  try
    PemToPublicKey(AKey);
    Result := True;
  except
    Result := False;
  end;
end;

function TCryptoLibECDSAProvider.VerifyPrivateKey(const AKey: TBytes): Boolean;
begin
  try
    PemToPrivateKey(AKey);
    Result := True;
  except
    Result := False;
  end;
end;

{ TCryptoLibRSAKeyMaterialProvider }

function TCryptoLibRSAKeyMaterialProvider.ImportPEM(const APEM: TBytes): TJOSERSAKeyMaterial;
var
  LPrivate, LPublic, LKey: IAsymmetricKeyParameter;
  LRsa: IRsaKeyParameters;
  LCrt: IRsaPrivateCrtKeyParameters;
begin
  Result := Default(TJOSERSAKeyMaterial);

  if Length(APEM) = 0 then
    raise ESignException.Create(SJOSECryptoLibJWKEmptyPEMData);

  TJOSECryptoLibPem.ReadKeyMaterial(APEM, LPrivate, LPublic);
  LKey := TJOSECryptoLibKeyMaterial.SelectKey(LPrivate, LPublic);

  if not Supports(LKey, IRsaKeyParameters, LRsa) then
    raise ESignException.Create(SJOSECryptoLibJWKPEMNotRSA);

  Result.Modulus := TBigIntegerUtilities.AsUnsignedByteArray(LRsa.Modulus);

  if not LRsa.IsPrivate then
  begin
    Result.PublicExponent := TBigIntegerUtilities.AsUnsignedByteArray(LRsa.Exponent);
    Exit;
  end;

  // A private RSA key only carries the public exponent in its CRT form, which is what every PEM
  // encoding CryptoLib can read (PKCS#1 and PKCS#8 alike) produces.
  if not Supports(LKey, IRsaPrivateCrtKeyParameters, LCrt) then
    raise ESignException.Create(SJOSECryptoLibJWKRSANoCRT);

  Result.PublicExponent := TBigIntegerUtilities.AsUnsignedByteArray(LCrt.PublicExponent);
  Result.PrivateExponent := TBigIntegerUtilities.AsUnsignedByteArray(LCrt.Exponent);
  Result.P := TBigIntegerUtilities.AsUnsignedByteArray(LCrt.P);
  Result.Q := TBigIntegerUtilities.AsUnsignedByteArray(LCrt.Q);
  Result.DP := TBigIntegerUtilities.AsUnsignedByteArray(LCrt.DP);
  Result.DQ := TBigIntegerUtilities.AsUnsignedByteArray(LCrt.DQ);
  Result.QI := TBigIntegerUtilities.AsUnsignedByteArray(LCrt.QInv);
end;

function TCryptoLibRSAKeyMaterialProvider.ExportPEM(const AKeyMaterial: TJOSERSAKeyMaterial; AIncludePrivate: Boolean): TBytes;
var
  LKey: IAsymmetricKeyParameter;
  LWritePrivate: Boolean;
begin
  LWritePrivate := AIncludePrivate and AKeyMaterial.IsPrivate;

  if LWritePrivate then
    LKey := TRsaPrivateCrtKeyParameters.Create(
      TJOSECryptoLibKeyMaterial.RequiredComponent(AKeyMaterial.Modulus, 'n'),
      TJOSECryptoLibKeyMaterial.RequiredComponent(AKeyMaterial.PublicExponent, 'e'),
      TJOSECryptoLibKeyMaterial.RequiredComponent(AKeyMaterial.PrivateExponent, 'd'),
      TJOSECryptoLibKeyMaterial.RequiredComponent(AKeyMaterial.P, 'p'),
      TJOSECryptoLibKeyMaterial.RequiredComponent(AKeyMaterial.Q, 'q'),
      TJOSECryptoLibKeyMaterial.RequiredComponent(AKeyMaterial.DP, 'dp'),
      TJOSECryptoLibKeyMaterial.RequiredComponent(AKeyMaterial.DQ, 'dq'),
      TJOSECryptoLibKeyMaterial.RequiredComponent(AKeyMaterial.QI, 'qi'))
  else
    LKey := TRsaKeyParameters.Create(False,
      TJOSECryptoLibKeyMaterial.RequiredComponent(AKeyMaterial.Modulus, 'n'),
      TJOSECryptoLibKeyMaterial.RequiredComponent(AKeyMaterial.PublicExponent, 'e'));

  try
    Result := TJOSECryptoLibPem.WriteKey(LKey);
  except
    on E: ESignException do
      raise;
    on E: Exception do
      raise ESignException.CreateFmt(SJOSECryptoLibJWKWritePEMError, [E.Message]);
  end;
end;

{ TCryptoLibECKeyMaterialProvider }

class function TCryptoLibECKeyMaterialProvider.CurveToOid(ACurve: TECCurve): IDerObjectIdentifier;
begin
  case ACurve of
    TECCurve.P256:      Result := TSecObjectIdentifiers.SecP256r1;
    TECCurve.P384:      Result := TSecObjectIdentifiers.SecP384r1;
    TECCurve.P521:      Result := TSecObjectIdentifiers.SecP521r1;
    TECCurve.secp256k1: Result := TSecObjectIdentifiers.SecP256k1;
  else
    raise ESignException.Create(SJOSECryptoLibJWKUnsupportedECCurve);
  end;
end;

class function TCryptoLibECKeyMaterialProvider.OidToCurve(const AOid: IDerObjectIdentifier): TECCurve;
begin
  if AOid = nil then
    raise ESignException.Create(SJOSECryptoLibJWKECNoNamedCurve);

  if AOid.ID = TSecObjectIdentifiers.SecP256r1.ID then
    Result := TECCurve.P256
  else if AOid.ID = TSecObjectIdentifiers.SecP384r1.ID then
    Result := TECCurve.P384
  else if AOid.ID = TSecObjectIdentifiers.SecP521r1.ID then
    Result := TECCurve.P521
  else if AOid.ID = TSecObjectIdentifiers.SecP256k1.ID then
    Result := TECCurve.secp256k1
  else
    raise ESignException.CreateFmt(SJOSECryptoLibJWKUnsupportedECCurveOID, [AOid.ID]);
end;

function TCryptoLibECKeyMaterialProvider.ImportPEM(const APEM: TBytes): TJOSEECKeyMaterial;
var
  LPrivate, LPublic, LKey: IAsymmetricKeyParameter;
  LEc: IECKeyParameters;
  LEcPublic: IECPublicKeyParameters;
  LEcPrivate: IECPrivateKeyParameters;
  LPoint: IECPoint;
begin
  Result := Default(TJOSEECKeyMaterial);

  if Length(APEM) = 0 then
    raise ESignException.Create(SJOSECryptoLibJWKEmptyPEMData);

  TJOSECryptoLibPem.ReadKeyMaterial(APEM, LPrivate, LPublic);
  LKey := TJOSECryptoLibKeyMaterial.SelectKey(LPrivate, LPublic);

  if not Supports(LKey, IECKeyParameters, LEc) then
    raise ESignException.Create(SJOSECryptoLibJWKPEMNotEC);

  Result.Curve := OidToCurve(LEc.PublicKeyParamSet);

  // RFC 7518 6.2.2.1: "d" is the order-sized octet string, not the minimal encoding.
  if Supports(LPrivate, IECPrivateKeyParameters, LEcPrivate) then
    Result.D := TBigIntegerUtilities.AsUnsignedByteArray(
      (LEcPrivate.Parameters.N.BitLength + 7) div 8, LEcPrivate.D);

  // A PKCS#8 EC private key PEM decodes to a lone private key, so the public point has to be
  // recovered from the scalar.
  if Supports(LPublic, IECPublicKeyParameters, LEcPublic) then
    LPoint := LEcPublic.Q
  else if Assigned(LEcPrivate) then
    LPoint := TECKeyPairGenerator.GetCorrespondingPublicKey(LEcPrivate).Q
  else
    raise ESignException.Create(SJOSECryptoLibJWKPEMNotEC);

  LPoint := LPoint.Normalize;
  Result.X := LPoint.AffineXCoord.GetEncoded;
  Result.Y := LPoint.AffineYCoord.GetEncoded;
end;

function TCryptoLibECKeyMaterialProvider.ExportPEM(const AKeyMaterial: TJOSEECKeyMaterial; AIncludePrivate: Boolean): TBytes;
var
  LOid: IDerObjectIdentifier;
  LDomain: IECNamedDomainParameters;
  LPoint: IECPoint;
  LKey: IAsymmetricKeyParameter;
  LWritePrivate: Boolean;
begin
  LWritePrivate := AIncludePrivate and AKeyMaterial.IsPrivate;

  LOid := CurveToOid(AKeyMaterial.Curve);
  LDomain := TECNamedDomainParameters.LookupOid(LOid);

  // Built for both branches: it validates x/y against the curve even when the private scalar is
  // what ends up in the PEM.
  LPoint := LDomain.Curve.CreatePoint(
    TJOSECryptoLibKeyMaterial.RequiredComponent(AKeyMaterial.X, 'x'),
    TJOSECryptoLibKeyMaterial.RequiredComponent(AKeyMaterial.Y, 'y'));

  if LWritePrivate then
    LKey := TECPrivateKeyParameters.Create('EC', TJOSECryptoLibKeyMaterial.RequiredComponent(AKeyMaterial.D, 'd'), LOid)
  else
    LKey := TECPublicKeyParameters.Create('EC', LPoint, LOid);

  try
    Result := TJOSECryptoLibPem.WriteKey(LKey);
  except
    on E: ESignException do
      raise;
    on E: Exception do
      raise ESignException.CreateFmt(SJOSECryptoLibJWKWritePEMError, [E.Message]);
  end;
end;

{ AES-GCM }

const
  // JOSE fixes both (RFC 7518 par. 5.3): a 96-bit IV and a 128-bit tag
  GCM_IV_BYTES = 12;
  GCM_TAG_BYTES = 16;

procedure CheckGCMKeyAndIV(const AKey, AIV: TBytes);
begin
  if (Length(AKey) <> 16) and (Length(AKey) <> 24) and (Length(AKey) <> 32) then
    raise EJOSECryptoException.CreateFmt(SJOSECryptoLibGCMKeyLength, [Length(AKey)]);
  if Length(AIV) <> GCM_IV_BYTES then
    raise EJOSECryptoException.CreateFmt(SJOSECryptoLibGCMIVLength, [Length(AIV)]);
end;

// One pass of AES-GCM. On encryption the output is ciphertext || tag, on
// decryption the input is. The work buffer is a local and is wiped when the
// tag check fails: CryptoLib writes the plaintext out as it goes and checks
// the tag only in DoFinal, and a failed decryption must not leave plaintext
// behind anywhere
function GCMProcess(AForEncryption: Boolean; const AInput, AKey, AIV, AAdditionalData: TBytes): TBytes;
var
  LCipher: IGcmBlockCipher;
  LParams: IAeadParameters;
  LOutput: TBytes;
  LLength: Integer;
begin
  LCipher := TGcmBlockCipher.Create(TAesUtilities.CreateEngine());
  LParams := TAeadParameters.Create(TKeyParameter.Create(AKey) as IKeyParameter,
    GCM_TAG_BYTES * 8, AIV, AAdditionalData);
  LCipher.Init(AForEncryption, LParams);

  SetLength(LOutput, LCipher.GetOutputSize(Length(AInput)));
  try
    LLength := 0;
    if Length(AInput) > 0 then
      LLength := LCipher.ProcessBytes(AInput, 0, Length(AInput), LOutput, 0);
    LLength := LLength + LCipher.DoFinal(LOutput, LLength);
  except
    if Length(LOutput) > 0 then
      FillChar(LOutput[0], Length(LOutput), 0);
    raise;
  end;

  SetLength(LOutput, LLength);
  Result := LOutput;
end;

{ TCryptoLibAESGCMProvider }

function TCryptoLibAESGCMProvider.Encrypt(const APlaintext, AKey, AIV, AAdditionalData: TBytes;
  out ATag: TBytes): TBytes;
var
  LOutput: TBytes;
begin
  CheckGCMKeyAndIV(AKey, AIV);
  try
    LOutput := GCMProcess(True, APlaintext, AKey, AIV, AAdditionalData);
  except
    on E: Exception do
      raise EJOSECryptoException.CreateFmt(SJOSECryptoLibGCMEncryptError, [E.Message]);
  end;

  // CryptoLib appends the tag to the ciphertext
  Result := Copy(LOutput, 0, Length(LOutput) - GCM_TAG_BYTES);
  ATag := Copy(LOutput, Length(LOutput) - GCM_TAG_BYTES, GCM_TAG_BYTES);
end;

function TCryptoLibAESGCMProvider.Decrypt(const ACiphertext, AKey, AIV, AAdditionalData,
  ATag: TBytes): TBytes;
begin
  CheckGCMKeyAndIV(AKey, AIV);
  if Length(ATag) <> GCM_TAG_BYTES then
    raise EJOSECryptoException.CreateFmt(SJOSECryptoLibGCMTagLength, [Length(ATag)]);

  try
    Result := GCMProcess(False, TBytesUtils.MergeBytes(ACiphertext, ATag), AKey, AIV, AAdditionalData);
  except
    // A wrong tag, a wrong key and a tampered ciphertext or header all look
    // the same from here, and must look the same to the caller
    on E: Exception do
      raise EJOSECryptoException.Create(SJOSECryptoLibGCMDecryptFailed);
  end;
end;

{ AES-CBC }

const
  CBC_IV_BYTES = 16;

procedure CheckCBCKeyAndIV(const AKey, AIV: TBytes);
begin
  if (Length(AKey) <> 16) and (Length(AKey) <> 24) and (Length(AKey) <> 32) then
    raise EJOSECryptoException.CreateFmt(SJOSECryptoLibCBCKeyLength, [Length(AKey)]);
  if Length(AIV) <> CBC_IV_BYTES then
    raise EJOSECryptoException.CreateFmt(SJOSECryptoLibCBCIVLength, [Length(AIV)]);
end;

function CBCProcess(AForEncryption: Boolean; const AInput, AKey, AIV: TBytes): TBytes;
var
  LCipher: IBufferedCipher;
begin
  LCipher := TCipherUtilities.GetCipher('AES/CBC/PKCS7PADDING');
  LCipher.Init(AForEncryption, TParametersWithIV.Create(TKeyParameter.Create(AKey) as ICipherParameters, AIV)
    as ICipherParameters);
  // DoFinal(AInput) refuses an empty array, yet an empty plaintext still
  // encrypts to one block of padding
  if Length(AInput) = 0 then
    Result := LCipher.DoFinal()
  else
    Result := LCipher.DoFinal(AInput);
end;

{ TCryptoLibAESCBCProvider }

function TCryptoLibAESCBCProvider.Encrypt(const APlaintext, AKey, AIV: TBytes): TBytes;
begin
  CheckCBCKeyAndIV(AKey, AIV);
  try
    Result := CBCProcess(True, APlaintext, AKey, AIV);
  except
    on E: Exception do
      raise EJOSECryptoException.CreateFmt(SJOSECryptoLibCBCEncryptError, [E.Message]);
  end;
end;

function TCryptoLibAESCBCProvider.Decrypt(const ACiphertext, AKey, AIV: TBytes): TBytes;
begin
  CheckCBCKeyAndIV(AKey, AIV);

  // A CBC ciphertext is always one or more whole blocks. CryptoLib would
  // return an empty plaintext for an empty input, without complaint
  if (Length(ACiphertext) = 0) or (Length(ACiphertext) mod CBC_IV_BYTES <> 0) then
    raise EJOSECryptoException.Create(SJOSECryptoLibCBCDecryptFailed);

  try
    Result := CBCProcess(False, ACiphertext, AKey, AIV);
  except
    // Bad padding, a length that is not a multiple of the block: one message
    on E: Exception do
      raise EJOSECryptoException.Create(SJOSECryptoLibCBCDecryptFailed);
  end;
end;

{ RSAES-OAEP }

// MGF1 gets its own instance of the same digest (RFC 7518 par. 4.3): passing
// only the hash would leave CryptoLib free to choose the MGF1 digest
function CreateOAEPCipher(ADigest: TJOSEOAEPDigest): IAsymmetricBlockCipher;
var
  LName: string;
begin
  case ADigest of
    TJOSEOAEPDigest.SHA1: LName := 'SHA-1';
    TJOSEOAEPDigest.SHA256: LName := 'SHA-256';
  else
    raise EJOSECryptoException.Create(SJOSECryptoLibOAEPDecryptFailed);
  end;

  Result := TOaepEncoding.Create(TRsaBlindedEngine.Create() as IAsymmetricBlockCipher,
    TDigestUtilities.GetDigest(LName), TDigestUtilities.GetDigest(LName), nil);
end;

{ TCryptoLibRSAEncryptionProvider }

constructor TCryptoLibRSAEncryptionProvider.Create(const ACertificate: IJOSECertificateProvider);
begin
  inherited Create;
  FCertificate := ACertificate;
end;

function TCryptoLibRSAEncryptionProvider.Encrypt(const APlaintext, APublicKey: TBytes;
  ADigest: TJOSEOAEPDigest): TBytes;
var
  LKey: IAsymmetricKeyParameter;
  LCipher: IAsymmetricBlockCipher;
begin
  // Key errors keep their message: the key is the caller's configuration,
  // not attacker input
  LKey := TJOSECryptoLibPem.ReadPublicKey(APublicKey, FCertificate, TJOSECertificatePublicKey.RSA);
  if not Supports(LKey, IRsaKeyParameters) then
    raise EJOSECryptoException.Create(SJOSECryptoLibKeyNotRSA);

  try
    LCipher := CreateOAEPCipher(ADigest);
    LCipher.Init(True, LKey);
    Result := LCipher.ProcessBlock(APlaintext, 0, Length(APlaintext));
  except
    on E: Exception do
      raise EJOSECryptoException.CreateFmt(SJOSECryptoLibOAEPEncryptError, [E.Message]);
  end;
end;

function TCryptoLibRSAEncryptionProvider.Decrypt(const ACiphertext, APrivateKey: TBytes;
  ADigest: TJOSEOAEPDigest): TBytes;
var
  LKey: IAsymmetricKeyParameter;
  LCipher: IAsymmetricBlockCipher;
begin
  LKey := TJOSECryptoLibPem.ReadPrivateKey(APrivateKey);
  if not Supports(LKey, IRsaKeyParameters) then
    raise EJOSECryptoException.Create(SJOSECryptoLibKeyNotRSAPrivate);
  if not LKey.IsPrivate then
    raise EJOSECryptoException.Create(SJOSECryptoLibRSAPEMNoPrivateKey);

  try
    LCipher := CreateOAEPCipher(ADigest);
    LCipher.Init(False, LKey);
    Result := LCipher.ProcessBlock(ACiphertext, 0, Length(ACiphertext));
  except
    // One message for every failure (bad padding, wrong length, wrong key)
    on E: Exception do
      raise EJOSECryptoException.Create(SJOSECryptoLibOAEPDecryptFailed);
  end;
end;

{ TJOSECryptoLibProviders }

class procedure TJOSECryptoLibProviders.Register;
var
  LCert: IJOSECertificateProvider;
begin
  TJOSEProviders.Base64 := TCryptoLibBase64Provider.Create;
  TJOSEProviders.HMAC := TCryptoLibHmacProvider.Create;
  LCert := TCryptoLibCertificateProvider.Create;
  TJOSEProviders.Certificate := LCert;
  TJOSEProviders.RSA := TCryptoLibRSAProvider.Create(LCert);
  TJOSEProviders.ECDSA := TCryptoLibECDSAProvider.Create(LCert);
  TJOSEProviders.RSAKeyMaterial := TCryptoLibRSAKeyMaterialProvider.Create;
  TJOSEProviders.ECKeyMaterial := TCryptoLibECKeyMaterialProvider.Create;
  TJOSEProviders.AESGCM := TCryptoLibAESGCMProvider.Create;
  TJOSEProviders.AESCBC := TCryptoLibAESCBCProvider.Create;
  TJOSEProviders.RSAEncryption := TCryptoLibRSAEncryptionProvider.Create(LCert);
end;

class procedure TJOSECryptoLibProviders.Unregister;
begin
  TJOSEProviders.Base64 := nil;
  TJOSEProviders.HMAC := nil;
  TJOSEProviders.Certificate := nil;
  TJOSEProviders.RSA := nil;
  TJOSEProviders.ECDSA := nil;
  TJOSEProviders.RSAKeyMaterial := nil;
  TJOSEProviders.ECKeyMaterial := nil;
  TJOSEProviders.AESGCM := nil;
  TJOSEProviders.AESCBC := nil;
  TJOSEProviders.RSAEncryption := nil;
end;

end.
