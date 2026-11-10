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
///   JWE content encryption algorithms ("enc", RFC 7518 par. 5)
/// </summary>
/// <seealso href="https://tools.ietf.org/html/rfc7516">
///   JWE RFC Document
/// </seealso>
unit JOSE.Core.JWA.Encryption;

{$I ..\JOSE.inc}

interface

uses
  System.SysUtils,
  JOSE.Types.Bytes,
  JOSE.Core.JWA;

type
  /// <summary>
  ///   The three parts a content encryption produces: they become parts 3, 4
  ///   and 5 of the JWE compact serialization
  /// </summary>
  /// <remarks>
  ///   A record, so that nobody has to own and free it
  /// </remarks>
  TEncryptionParts = record
    IV: TBytes;
    Ciphertext: TBytes;
    AuthenticationTag: TBytes;
    constructor Create(const AIV, ACiphertext, AAuthenticationTag: TBytes);
  end;

  /// <summary>
  ///   A content encryption algorithm ("enc")
  /// </summary>
  /// <remarks>
  ///   "enc" is a namespace of its own, so the identifier is
  ///   GetEncryptionAlgorithmId. GetAlgorithmIdentifier, inherited from
  ///   IJOSEAlgorithm, returns TJOSEAlgorithmId.Unknown. The algorithm is
  ///   registered under GetEncryptionAlgorithmId.AsString.
  ///   There is no way to pass the IV: the algorithm generates a fresh one on
  ///   every call, because reusing an IV with the same key breaks AES-GCM
  /// </remarks>
  IJOSEEncryptionAlgorithm = interface(IJOSEAlgorithm)
  ['{D802ABF3-82E2-494B-B96A-D13C5A782574}']
    function GetEncryptionAlgorithmId: TJOSEEncryptionAlgorithmId;
    /// <summary>Length in bytes of the Content Encryption Key</summary>
    function GetCEKLength: Integer;
    /// <summary>
    ///   Encrypts APlaintext under ACEK, authenticating AAdditionalData too
    ///   (the ASCII of the encoded protected header, RFC 7516 par. 5.1 step 14)
    /// </summary>
    function Encrypt(const APlaintext, AAdditionalData, AContentEncryptionKey: TBytes): TEncryptionParts;
    /// <summary>
    ///   Checks the authentication tag and decrypts. Raises when the tag does
    ///   not match: unauthenticated plaintext is never returned
    /// </summary>
    function Decrypt(const AEncryptionParts: TEncryptionParts; const AAdditionalData, AContentEncryptionKey: TBytes): TBytes;
  end;

implementation

{ TEncryptionParts }

constructor TEncryptionParts.Create(const AIV, ACiphertext, AAuthenticationTag: TBytes);
begin
  IV := AIV;
  Ciphertext := ACiphertext;
  AuthenticationTag := AAuthenticationTag;
end;

end.
