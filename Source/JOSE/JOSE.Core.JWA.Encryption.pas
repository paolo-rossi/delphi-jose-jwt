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

  /// <summary>
  ///   "A128GCM", "A192GCM", "A256GCM" (RFC 7518 par. 5.3), on top of the
  ///   registered IJOSEAESGCMProvider
  /// </summary>
  TAESGCMAlgorithm = class(TJOSEAlgorithm, IJOSEEncryptionAlgorithm)
  private
    FEncryptionAlgorithmId: TJOSEEncryptionAlgorithmId;
    procedure CheckCEK(const AContentEncryptionKey: TBytes);
  public
    constructor Create(AEncryptionAlgorithmId: TJOSEEncryptionAlgorithmId);
    class function A128GCM: IJOSEEncryptionAlgorithm;
    class function A192GCM: IJOSEEncryptionAlgorithm;
    class function A256GCM: IJOSEEncryptionAlgorithm;

    function GetEncryptionAlgorithmId: TJOSEEncryptionAlgorithmId;
    function GetCEKLength: Integer;
    function Encrypt(const APlaintext, AAdditionalData, AContentEncryptionKey: TBytes): TEncryptionParts;
    function Decrypt(const AEncryptionParts: TEncryptionParts; const AAdditionalData, AContentEncryptionKey: TBytes): TBytes;
  end;

implementation

uses
  JOSE.Core.Base,
  JOSE.Providers;

resourcestring
  SJOSECEKLength = 'The content encryption key for %s must be %d bytes, not %d';

const
  // RFC 7518 par. 5.3: a 96-bit IV
  GCM_IV_BYTES = 12;

{ TAESGCMAlgorithm }

constructor TAESGCMAlgorithm.Create(AEncryptionAlgorithmId: TJOSEEncryptionAlgorithmId);
begin
  inherited Create;
  // GetAlgorithmIdentifier stays Unknown: "enc" is not an "alg" value
  FAlgorithmIdentifier := TJOSEAlgorithmId.Unknown;
  FKeyCategory := TJOSEKeyCategory.Symmetric;
  FKeyType := 'oct';
  FEncryptionAlgorithmId := AEncryptionAlgorithmId;
end;

class function TAESGCMAlgorithm.A128GCM: IJOSEEncryptionAlgorithm;
begin
  Result := TAESGCMAlgorithm.Create(TJOSEEncryptionAlgorithmId.A128GCM);
end;

class function TAESGCMAlgorithm.A192GCM: IJOSEEncryptionAlgorithm;
begin
  Result := TAESGCMAlgorithm.Create(TJOSEEncryptionAlgorithmId.A192GCM);
end;

class function TAESGCMAlgorithm.A256GCM: IJOSEEncryptionAlgorithm;
begin
  Result := TAESGCMAlgorithm.Create(TJOSEEncryptionAlgorithmId.A256GCM);
end;

procedure TAESGCMAlgorithm.CheckCEK(const AContentEncryptionKey: TBytes);
begin
  if Length(AContentEncryptionKey) <> GetCEKLength then
    raise EJOSEException.CreateFmt(SJOSECEKLength,
      [FEncryptionAlgorithmId.AsString, GetCEKLength, Length(AContentEncryptionKey)]);
end;

function TAESGCMAlgorithm.GetCEKLength: Integer;
begin
  Result := FEncryptionAlgorithmId.CEKLength;
end;

function TAESGCMAlgorithm.GetEncryptionAlgorithmId: TJOSEEncryptionAlgorithmId;
begin
  Result := FEncryptionAlgorithmId;
end;

function TAESGCMAlgorithm.Encrypt(const APlaintext, AAdditionalData,
  AContentEncryptionKey: TBytes): TEncryptionParts;
var
  LIV, LCiphertext, LTag: TBytes;
begin
  CheckCEK(AContentEncryptionKey);

  // A fresh random IV every time: with GCM, two messages under one key and one
  // IV give away the XOR of the plaintexts and the authentication key
  LIV := TJOSEBytes.RandomBytes(GCM_IV_BYTES);
  LCiphertext := TJOSEProviders.AESGCM.Encrypt(APlaintext, AContentEncryptionKey, LIV, AAdditionalData, LTag);

  Result := TEncryptionParts.Create(LIV, LCiphertext, LTag);
end;

function TAESGCMAlgorithm.Decrypt(const AEncryptionParts: TEncryptionParts; const AAdditionalData,
  AContentEncryptionKey: TBytes): TBytes;
begin
  CheckCEK(AContentEncryptionKey);

  // The provider checks the IV and tag lengths and the tag itself
  Result := TJOSEProviders.AESGCM.Decrypt(AEncryptionParts.Ciphertext, AContentEncryptionKey,
    AEncryptionParts.IV, AAdditionalData, AEncryptionParts.AuthenticationTag);
end;

{ TEncryptionParts }

constructor TEncryptionParts.Create(const AIV, ACiphertext, AAuthenticationTag: TBytes);
begin
  IV := AIV;
  Ciphertext := ACiphertext;
  AuthenticationTag := AAuthenticationTag;
end;

end.
