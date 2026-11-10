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

implementation

end.
