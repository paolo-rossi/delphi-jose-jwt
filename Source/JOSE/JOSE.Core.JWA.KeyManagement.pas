{******************************************************************************}
{                                                                              }
{  Delphi JOSE-JWT Library                                                     }
{  Copyright (c) 2015 Paolo Rossi                                              }
{  https://github.com/paolo-rossi/delphi-jose-jwt                              }
{                                                                              }
{  Licensed under the MIT license                                              }
{                                                                              }
{******************************************************************************}

/// <summary>
///   JWE key management algorithms ("alg", RFC 7518 par. 4)
/// </summary>
/// <seealso href="https://tools.ietf.org/html/rfc7518#section-4">
///   JWA RFC Document
/// </seealso>
unit JOSE.Core.JWA.KeyManagement;

{$I ..\JOSE.inc}

interface

uses
  System.SysUtils,
  JOSE.Types.Bytes,
  JOSE.Crypto.Algorithms,
  JOSE.Core.JWA,
  JOSE.Core.JWE.Header;

type
  /// <summary>
  ///   What key management produces on the sending side
  /// </summary>
  TJOSEKeyManagementResult = record
    /// <summary>The Content Encryption Key</summary>
    CEK: TJOSEBytes;
    /// <summary>Part 2 of the compact serialization. Empty for "dir"</summary>
    EncryptedKey: TJOSEBytes;
  end;

  /// <summary>
  ///   A key management algorithm: how the Content Encryption Key is agreed on
  /// </summary>
  /// <remarks>
  ///   AHeader is the JWE header. Some algorithms add members to it on
  ///   encryption (ECDH-ES writes "epk") and read them on decryption, so
  ///   ManageForEncrypt must be called before the protected header is
  ///   serialized. "dir" and RSA-OAEP leave it alone
  /// </remarks>
  IJOSEKeyManagementAlgorithm = interface(IJOSEAlgorithm)
  ['{2A2FBF37-8267-4DA3-AA11-7E1C3ED235DD}']
    /// <summary>
    ///   Gets a CEK of ACEKLength bytes, generated or derived from AKey, and the
    ///   Encrypted Key to send with it
    /// </summary>
    function ManageForEncrypt(const AKey: TJOSEBytes; ACEKLength: Integer;
      AHeader: TJWEHeader): TJOSEKeyManagementResult;
    /// <summary>
    ///   Recovers the CEK from AEncryptedKey. Raises when that fails or when
    ///   the CEK is not ACEKLength bytes long
    /// </summary>
    function ManageForDecrypt(const AKey, AEncryptedKey: TJOSEBytes; ACEKLength: Integer;
      AHeader: TJWEHeader): TJOSEBytes;
  end;

  /// <summary>
  ///   "dir" (RFC 7518 par. 4.5): the shared symmetric key is the CEK itself,
  ///   and the Encrypted Key is empty
  /// </summary>
  TDirAlgorithm = class(TJOSEAlgorithm, IJOSEKeyManagementAlgorithm)
  private
    procedure CheckKeyLength(const AKey: TJOSEBytes; ACEKLength: Integer);
  public
    constructor Create;
    class function Dir: IJOSEKeyManagementAlgorithm;

    function ManageForEncrypt(const AKey: TJOSEBytes; ACEKLength: Integer;
      AHeader: TJWEHeader): TJOSEKeyManagementResult;
    function ManageForDecrypt(const AKey, AEncryptedKey: TJOSEBytes; ACEKLength: Integer;
      AHeader: TJWEHeader): TJOSEBytes;
  end;

{$IFDEF RSA_SIGNING}

  /// <summary>
  ///   "RSA-OAEP" and "RSA-OAEP-256" (RFC 7518 par. 4.3): a random CEK,
  ///   encrypted to the recipient's RSA public key with RSAES-OAEP
  /// </summary>
  /// <remarks>
  ///   Keys are PEM, as for RS*/PS*: the public key (or an X.509 certificate
  ///   carrying it) to encrypt, the private key to decrypt. Keys below 2048
  ///   bits are refused, as RFC 7518 par. 4.3 requires
  /// </remarks>
  TRSAOAEPAlgorithm = class(TJOSEAlgorithm, IJOSEKeyManagementAlgorithm)
  private
    FDigest: TJOSEOAEPDigest;
    class procedure CheckKeySize(const AKey: TJOSEBytes; AIsPrivate: Boolean); static;
  public
    constructor Create(AAlgorithmId: TJOSEAlgorithmId; ADigest: TJOSEOAEPDigest);
    class function RSAOAEP: IJOSEKeyManagementAlgorithm;
    class function RSAOAEP256: IJOSEKeyManagementAlgorithm;

    function ManageForEncrypt(const AKey: TJOSEBytes; ACEKLength: Integer;
      AHeader: TJWEHeader): TJOSEKeyManagementResult;
    function ManageForDecrypt(const AKey, AEncryptedKey: TJOSEBytes; ACEKLength: Integer;
      AHeader: TJWEHeader): TJOSEBytes;
  end;

{$ENDIF}

implementation

uses
  JOSE.Core.Base,
  JOSE.Providers,
  JOSE.Providers.Interfaces;

resourcestring
  SJOSEDirKeyLength = 'A "dir" key must be exactly as long as the content encryption key: ' +
    '%d bytes expected, %d given';
  SJOSEDirEncryptedKeyNotEmpty = 'A "dir" JWE must have an empty Encrypted Key';
  SJOSERSAOAEPKeyTooSmall = 'RSA-OAEP needs an RSA key of at least %d bits, not %d';
  SJOSERSAOAEPNoEncryptedKey = 'An RSA-OAEP JWE must have an Encrypted Key';

{ TDirAlgorithm }

constructor TDirAlgorithm.Create;
begin
  inherited Create;
  FAlgorithmIdentifier := TJOSEAlgorithmId.Dir;
  FKeyCategory := TJOSEKeyCategory.Symmetric;
  FKeyType := 'oct';
end;

class function TDirAlgorithm.Dir: IJOSEKeyManagementAlgorithm;
begin
  Result := TDirAlgorithm.Create;
end;

procedure TDirAlgorithm.CheckKeyLength(const AKey: TJOSEBytes; ACEKLength: Integer);
begin
  // Never truncated or padded: a key of the wrong length is a configuration
  // error, and "fixing" it would silently use a different key
  if AKey.Size <> ACEKLength then
    raise EJOSEException.CreateFmt(SJOSEDirKeyLength, [ACEKLength, AKey.Size]);
end;

function TDirAlgorithm.ManageForEncrypt(const AKey: TJOSEBytes; ACEKLength: Integer;
  AHeader: TJWEHeader): TJOSEKeyManagementResult;
begin
  CheckKeyLength(AKey, ACEKLength);

  Result.CEK := AKey;
  Result.EncryptedKey := TJOSEBytes.Empty;
end;

function TDirAlgorithm.ManageForDecrypt(const AKey, AEncryptedKey: TJOSEBytes; ACEKLength: Integer;
  AHeader: TJWEHeader): TJOSEBytes;
begin
  // RFC 7516 par. 5.2 step 10: a "dir" token with a non-empty Encrypted Key is
  // malformed. The error below is masked by TJWE.DecryptPayload, which replaces
  // every decryption failure with its one generic message on purpose; it is
  // here for the rule's sake (and for a debugger), not for the caller to read.
  // The same applies to CheckKeyLength in this method.
  if not AEncryptedKey.IsEmpty then
    raise EJOSEException.Create(SJOSEDirEncryptedKeyNotEmpty);

  CheckKeyLength(AKey, ACEKLength);

  Result := AKey;
end;

{$IFDEF RSA_SIGNING}

{ TRSAOAEPAlgorithm }

const
  // RFC 7518 par. 4.3
  RSA_OAEP_MIN_KEY_BITS = 2048;
  PEM_CERTIFICATE_MARKER = '-----BEGIN CERTIFICATE-----';

constructor TRSAOAEPAlgorithm.Create(AAlgorithmId: TJOSEAlgorithmId; ADigest: TJOSEOAEPDigest);
begin
  inherited Create;
  FAlgorithmIdentifier := AAlgorithmId;
  FKeyCategory := TJOSEKeyCategory.Asymmetric;
  FKeyType := 'RSA';
  FDigest := ADigest;
end;

class function TRSAOAEPAlgorithm.RSAOAEP: IJOSEKeyManagementAlgorithm;
begin
  Result := TRSAOAEPAlgorithm.Create(TJOSEAlgorithmId.RSA_OAEP, TJOSEOAEPDigest.SHA1);
end;

class function TRSAOAEPAlgorithm.RSAOAEP256: IJOSEKeyManagementAlgorithm;
begin
  Result := TRSAOAEPAlgorithm.Create(TJOSEAlgorithmId.RSA_OAEP_256, TJOSEOAEPDigest.SHA256);
end;

class procedure TRSAOAEPAlgorithm.CheckKeySize(const AKey: TJOSEBytes; AIsPrivate: Boolean);
var
  LBits: Integer;
begin
  // The RSA encryption capability owns the key parsing, so it is asked for the
  // modulus size; the minimum itself is the RFC 7518 par. 4.3 rule and stays
  // here, in one place for every provider stack
  if AIsPrivate then
    LBits := TJOSEProviders.RSAEncryption.PrivateKeyBits(AKey.AsBytes)
  else
    LBits := TJOSEProviders.RSAEncryption.PublicKeyBits(AKey.AsBytes);

  if LBits < RSA_OAEP_MIN_KEY_BITS then
    raise EJOSEException.CreateFmt(SJOSERSAOAEPKeyTooSmall, [RSA_OAEP_MIN_KEY_BITS, LBits]);
end;

function TRSAOAEPAlgorithm.ManageForEncrypt(const AKey: TJOSEBytes; ACEKLength: Integer;
  AHeader: TJWEHeader): TJOSEKeyManagementResult;
var
  LPublicKey: TJOSEBytes;
begin
  // An X.509 certificate is accepted as a container for the public key, as
  // it is for RS*/PS* verification. It is not validated (chain, dates, usage)
  if AKey.Contains(TJOSEBytes(PEM_CERTIFICATE_MARKER)) then
    LPublicKey := TJOSEProviders.Certificate.PublicKeyFromCertificate(AKey.AsBytes)
  else
    LPublicKey := AKey;

  CheckKeySize(LPublicKey, False);

  Result.CEK := TJOSEBytes.RandomBytes(ACEKLength);
  Result.EncryptedKey := TJOSEProviders.RSAEncryption.Encrypt(Result.CEK.AsBytes, LPublicKey.AsBytes, FDigest);
end;

function TRSAOAEPAlgorithm.ManageForDecrypt(const AKey, AEncryptedKey: TJOSEBytes; ACEKLength: Integer;
  AHeader: TJWEHeader): TJOSEBytes;
begin
  if AEncryptedKey.IsEmpty then
    raise EJOSEException.Create(SJOSERSAOAEPNoEncryptedKey);

  CheckKeySize(AKey, True);

  // RFC 7516 par. 11.5: when the CEK does not decrypt, or decrypts to the
  // wrong length, carry on with a random CEK instead of failing here. The
  // content decryption then fails on the tag, so a bad Encrypted Key and a
  // bad ciphertext fail at the same point and cannot be told apart by timing
  try
    Result := TJOSEProviders.RSAEncryption.Decrypt(AEncryptedKey.AsBytes, AKey.AsBytes, FDigest);
  except
    on E: EJOSECryptoException do
      Result := TJOSEBytes.Empty;
  end;

  if Result.Size <> ACEKLength then
    Result := TJOSEBytes.RandomBytes(ACEKLength);
end;

{$ENDIF}

end.
