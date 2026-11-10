{******************************************************************************}
{                                                                              }
{  Delphi JOSE-JWT Library                                                     }
{  Copyright (c) 2015 Paolo Rossi                                              }
{  https://github.com/paolo-rossi/delphi-jose-jwt                              }
{                                                                              }
{  Licensed under the MIT license                                              }
{                                                                              }
{******************************************************************************}

unit JOSE.Providers.Interfaces;

{$I ..\JOSE.inc}

interface

uses
  System.SysUtils,
  JOSE.Types.Bytes,
  JOSE.Crypto.Algorithms;

type
  /// <summary>
  ///   Raised by the JWE crypto providers (AES-GCM, RSAES-OAEP). The message
  ///   may say what went wrong; the JWE layer replaces it with one generic
  ///   decryption error before it reaches the caller
  /// </summary>
  EJOSECryptoException = class(Exception);

  IJOSEBase64Provider = interface
    ['{8F2E9C1D-4A3B-4E5F-9D8C-7B6A50413210}']
    function Encode(const ASource: TJOSEBytes): TJOSEBytes;
    function Decode(const ASource: TJOSEBytes): TJOSEBytes;
    function TryDecode(const ASource: TJOSEBytes): TJOSEBytes;
    function URLEncode(const ASource: TJOSEBytes): TJOSEBytes;
    function URLDecode(const ASource: TJOSEBytes): TJOSEBytes;
    function TryURLDecode(const ASource: TJOSEBytes): TJOSEBytes;
  end;

  IJOSEHmacProvider = interface
    ['{7D1C8B2E-5F4A-4D3C-8E9F-1029384756AB}']
    function Sign(const AInput, AKey: TBytes; AAlg: THMACAlgorithm): TBytes;
  end;

  /// <summary>
  ///   AES in Galois/Counter Mode, for the JWE "A128GCM", "A192GCM" and
  ///   "A256GCM" content encryption (RFC 7518 par. 5.3)
  /// </summary>
  /// <remarks>
  ///   The key length (16, 24 or 32 bytes) selects AES-128/192/256. JOSE always
  ///   uses a 96-bit IV and a 128-bit tag, so implementations raise
  ///   EJOSECryptoException for an IV that is not 12 bytes, a tag that is not
  ///   16 or a key that is not 16, 24 or 32
  /// </remarks>
  IJOSEAESGCMProvider = interface
    ['{363D9C4E-A4A7-4FBF-B12C-30651B83B12D}']
    /// <summary>Encrypts APlaintext; the 16-byte authentication tag is returned in ATag</summary>
    function Encrypt(const APlaintext, AKey, AIV, AAdditionalData: TBytes; out ATag: TBytes): TBytes;
    /// <summary>
    ///   Checks ATag and decrypts. Raises EJOSECryptoException when the tag does not
    ///   match: unauthenticated plaintext is never returned
    /// </summary>
    function Decrypt(const ACiphertext, AKey, AIV, AAdditionalData, ATag: TBytes): TBytes;
  end;

  /// <summary>
  ///   AES in CBC mode with PKCS#7 padding: the encryption half of the JWE
  ///   "A128CBC-HS256", "A192CBC-HS384" and "A256CBC-HS512" content
  ///   encryption (RFC 7518 par. 5.2). The HMAC half is done by the caller
  /// </summary>
  /// <remarks>
  ///   The key length (16, 24 or 32 bytes) selects AES-128/192/256 and the IV
  ///   is always 16 bytes: anything else raises EJOSECryptoException.
  ///   CBC is not authenticated: callers must check a MAC before Decrypt, as
  ///   the JWE layer does, or a padding error becomes an oracle
  /// </remarks>
  IJOSEAESCBCProvider = interface
    ['{3B7DCD4D-10D5-402D-8A9B-FAA3D546C530}']
    function Encrypt(const APlaintext, AKey, AIV: TBytes): TBytes;
    /// <summary>Raises EJOSECryptoException, with no detail, when the padding is wrong</summary>
    function Decrypt(const ACiphertext, AKey, AIV: TBytes): TBytes;
  end;

{$IFDEF RSA_SIGNING}

  /// <summary>
  ///   Reads key material out of a PEM X.509 certificate
  /// </summary>
  /// <remarks>
  ///   Certificates are treated as key containers only. No implementation of
  ///   this interface validates the chain, the validity dates, the revocation
  ///   status, the key usage or the subject - VerifyCertificate only checks
  ///   that the embedded public key is of the expected type. Callers that need
  ///   certificate-path validation must do it themselves before passing the
  ///   certificate in.
  /// </remarks>
  IJOSECertificateProvider = interface
    ['{6E0B7A3D-2C1F-4E5D-9A8B-7C6D5E4F3021}']
    function PublicKeyFromCertificate(const ACertificate: TBytes): TBytes;
    function VerifyCertificate(const ACertificate: TBytes; AExpected: TJOSECertificatePublicKey): Boolean;
  end;

  IJOSESignerRSA = interface
    ['{5D9C8B1E-3A2F-4D5C-8B7A-6C5D4E3F2010}']
    function Sign(const AInput, AKey: TBytes; AAlg: TRSAAlgorithm): TBytes;
    function Verify(const AInput, ASignature, AKey: TBytes; AAlg: TRSAAlgorithm): Boolean;
    /// <summary>Verifies against the public key inside ACertificate. The
    ///   certificate itself is not validated - see IJOSECertificateProvider</summary>
    function VerifyWithCertificate(const AInput, ASignature, ACertificate: TBytes; AAlg: TRSAAlgorithm): Boolean;
    function VerifyPublicKey(const AKey: TBytes): Boolean;
    function VerifyPrivateKey(const AKey: TBytes): Boolean;
  end;

  IJOSESignerECDSA = interface
    ['{4C8B7A2D-1E0F-4C3B-7A6C-5B4D3E2F1098}']
    function Sign(const AInput, APrivateKey: TBytes; AAlg: TECDSAAlgorithm): TBytes;
    function Verify(const AInput, ASignature, APublicKey: TBytes; AAlg: TECDSAAlgorithm): Boolean;
    /// <summary>Verifies against the public key inside ACertificate. The
    ///   certificate itself is not validated - see IJOSECertificateProvider</summary>
    function VerifyWithCertificate(const AInput, ASignature, ACertificate: TBytes; AAlg: TECDSAAlgorithm): Boolean;
    function VerifyPublicKey(const AKey: TBytes): Boolean;
    function VerifyPrivateKey(const AKey: TBytes): Boolean;
  end;

  /// <summary>
  ///   RSAES-OAEP encryption, for the JWE "RSA-OAEP" and "RSA-OAEP-256" key
  ///   management (RFC 7518 par. 4.3). Keys are PEM, like the RSA signer's
  /// </summary>
  IJOSERSAEncryptionProvider = interface
    ['{BBDF3F88-D2C5-4069-984E-C3381CD7285F}']
    function Encrypt(const APlaintext, APublicKey: TBytes; ADigest: TJOSEOAEPDigest): TBytes;
    /// <summary>
    ///   Raises EJOSECryptoException when the ciphertext does not decrypt, with no
    ///   detail about why (the error must not become a padding oracle)
    /// </summary>
    function Decrypt(const ACiphertext, APrivateKey: TBytes; ADigest: TJOSEOAEPDigest): TBytes;
  end;

  /// <summary>Imports/exports raw RSA key material (RFC 7517/7518) to/from PEM, for JWK support.</summary>
  IJOSERSAKeyMaterialProvider = interface
    ['{3A2F1E0D-9C8B-4A7D-9E1F-2B3C4D5E6F70}']
    function ImportPEM(const APEM: TBytes): TJOSERSAKeyMaterial;
    function ExportPEM(const AKeyMaterial: TJOSERSAKeyMaterial; AIncludePrivate: Boolean): TBytes;
  end;

  /// <summary>Imports/exports raw EC key material (RFC 7517/7518) to/from PEM, for JWK support.</summary>
  IJOSEECKeyMaterialProvider = interface
    ['{9B1C2D3E-4F5A-4B6C-8D7E-1F2A3B4C5D6E}']
    function ImportPEM(const APEM: TBytes): TJOSEECKeyMaterial;
    function ExportPEM(const AKeyMaterial: TJOSEECKeyMaterial; AIncludePrivate: Boolean): TBytes;
  end;

{$ENDIF}

implementation

end.
