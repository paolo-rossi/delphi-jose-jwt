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
  JOSE.Crypto.Algorithms,
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

  /// <summary>
  ///   "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512" (RFC 7518 par. 5.2):
  ///   AES-CBC encryption plus an HMAC-SHA2 tag over the AAD, the IV and the
  ///   ciphertext, on top of the registered IJOSEAESCBCProvider and
  ///   IJOSEHmacProvider
  /// </summary>
  /// <remarks>
  ///   The CEK is split in two: the first half is the MAC key, the second the
  ///   AES key. The tag is the first half of the HMAC. On decryption the tag
  ///   is checked, in constant time, before anything is decrypted, so a
  ///   padding error is never reachable with an unauthenticated ciphertext
  /// </remarks>
  TAESCBCHMACAlgorithm = class(TJOSEAlgorithm, IJOSEEncryptionAlgorithm)
  private
    FEncryptionAlgorithmId: TJOSEEncryptionAlgorithmId;
    FHMACAlgorithm: THMACAlgorithm;
    procedure CheckCEK(const AContentEncryptionKey: TBytes);
    function ComputeTag(const AMACKey, AAdditionalData, AIV, ACiphertext: TBytes): TBytes;
  public
    constructor Create(AEncryptionAlgorithmId: TJOSEEncryptionAlgorithmId);
    class function A128CBC_HS256: IJOSEEncryptionAlgorithm;
    class function A192CBC_HS384: IJOSEEncryptionAlgorithm;
    class function A256CBC_HS512: IJOSEEncryptionAlgorithm;

    function GetEncryptionAlgorithmId: TJOSEEncryptionAlgorithmId;
    function GetCEKLength: Integer;
    function Encrypt(const APlaintext, AAdditionalData, AContentEncryptionKey: TBytes): TEncryptionParts;
    function Decrypt(const AEncryptionParts: TEncryptionParts; const AAdditionalData, AContentEncryptionKey: TBytes): TBytes;
  end;

implementation

uses
  JOSE.Core.Base,
  JOSE.Hashing.HMAC,
  JOSE.Providers;

resourcestring
  SJOSECEKLength = 'The content encryption key for %s must be %d bytes, not %d';
  SJOSECBCIVLength = 'The IV for %s must be 16 bytes, not %d';
  SJOSECBCTagLength = 'The authentication tag for %s must be %d bytes, not %d';
  SJOSECBCTagMismatch = 'The authentication tag does not match';

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

{ TAESCBCHMACAlgorithm }

const
  // RFC 7518 par. 5.2.2.1: a 128-bit IV
  CBC_IV_BYTES = 16;

// The AAD length in bits, as a 64-bit big-endian integer ("AL", RFC 7518
// par. 5.2.2.1 step 4)
function AADLengthInBits(const AAdditionalData: TBytes): TBytes;
var
  LBits: UInt64;
  LIndex: Integer;
begin
  LBits := UInt64(Length(AAdditionalData)) * 8;
  SetLength(Result, 8);
  for LIndex := 7 downto 0 do
  begin
    Result[LIndex] := Byte(LBits and $FF);
    LBits := LBits shr 8;
  end;
end;

constructor TAESCBCHMACAlgorithm.Create(AEncryptionAlgorithmId: TJOSEEncryptionAlgorithmId);
begin
  inherited Create;
  FAlgorithmIdentifier := TJOSEAlgorithmId.Unknown;
  FKeyCategory := TJOSEKeyCategory.Symmetric;
  FKeyType := 'oct';
  FEncryptionAlgorithmId := AEncryptionAlgorithmId;

  case AEncryptionAlgorithmId of
    TJOSEEncryptionAlgorithmId.A128CBC_HS256: FHMACAlgorithm := THMACAlgorithm.SHA256;
    TJOSEEncryptionAlgorithmId.A192CBC_HS384: FHMACAlgorithm := THMACAlgorithm.SHA384;
  else
    FHMACAlgorithm := THMACAlgorithm.SHA512;
  end;
end;

class function TAESCBCHMACAlgorithm.A128CBC_HS256: IJOSEEncryptionAlgorithm;
begin
  Result := TAESCBCHMACAlgorithm.Create(TJOSEEncryptionAlgorithmId.A128CBC_HS256);
end;

class function TAESCBCHMACAlgorithm.A192CBC_HS384: IJOSEEncryptionAlgorithm;
begin
  Result := TAESCBCHMACAlgorithm.Create(TJOSEEncryptionAlgorithmId.A192CBC_HS384);
end;

class function TAESCBCHMACAlgorithm.A256CBC_HS512: IJOSEEncryptionAlgorithm;
begin
  Result := TAESCBCHMACAlgorithm.Create(TJOSEEncryptionAlgorithmId.A256CBC_HS512);
end;

procedure TAESCBCHMACAlgorithm.CheckCEK(const AContentEncryptionKey: TBytes);
begin
  if Length(AContentEncryptionKey) <> GetCEKLength then
    raise EJOSEException.CreateFmt(SJOSECEKLength,
      [FEncryptionAlgorithmId.AsString, GetCEKLength, Length(AContentEncryptionKey)]);
end;

function TAESCBCHMACAlgorithm.ComputeTag(const AMACKey, AAdditionalData, AIV, ACiphertext: TBytes): TBytes;
var
  LMacInput: TJOSEBytes;
begin
  // M = HMAC(MAC_KEY, A || IV || E || AL); T = the first half of M, which is
  // as long as the MAC key (16/24/32 bytes)
  LMacInput := TJOSEBytes(AAdditionalData) + AIV + ACiphertext + AADLengthInBits(AAdditionalData);
  Result := Copy(THMAC.Sign(LMacInput.AsBytes, AMACKey, FHMACAlgorithm), 0, Length(AMACKey));
end;

function TAESCBCHMACAlgorithm.GetCEKLength: Integer;
begin
  Result := FEncryptionAlgorithmId.CEKLength;
end;

function TAESCBCHMACAlgorithm.GetEncryptionAlgorithmId: TJOSEEncryptionAlgorithmId;
begin
  Result := FEncryptionAlgorithmId;
end;

function TAESCBCHMACAlgorithm.Encrypt(const APlaintext, AAdditionalData,
  AContentEncryptionKey: TBytes): TEncryptionParts;
var
  LHalf: Integer;
  LMACKey, LEncKey, LIV, LCiphertext: TBytes;
begin
  CheckCEK(AContentEncryptionKey);

  LHalf := Length(AContentEncryptionKey) div 2;
  LMACKey := Copy(AContentEncryptionKey, 0, LHalf);
  LEncKey := Copy(AContentEncryptionKey, LHalf, LHalf);

  // A fresh random IV every time: CBC with a predictable IV leaks plaintext
  LIV := TJOSEBytes.RandomBytes(CBC_IV_BYTES);
  LCiphertext := TJOSEProviders.AESCBC.Encrypt(APlaintext, LEncKey, LIV);

  Result := TEncryptionParts.Create(LIV, LCiphertext,
    ComputeTag(LMACKey, AAdditionalData, LIV, LCiphertext));
end;

function TAESCBCHMACAlgorithm.Decrypt(const AEncryptionParts: TEncryptionParts; const AAdditionalData,
  AContentEncryptionKey: TBytes): TBytes;
var
  LHalf: Integer;
  LMACKey, LEncKey: TBytes;
begin
  CheckCEK(AContentEncryptionKey);

  LHalf := Length(AContentEncryptionKey) div 2;
  if Length(AEncryptionParts.IV) <> CBC_IV_BYTES then
    raise EJOSEException.CreateFmt(SJOSECBCIVLength,
      [FEncryptionAlgorithmId.AsString, Length(AEncryptionParts.IV)]);
  if Length(AEncryptionParts.AuthenticationTag) <> LHalf then
    raise EJOSEException.CreateFmt(SJOSECBCTagLength,
      [FEncryptionAlgorithmId.AsString, LHalf, Length(AEncryptionParts.AuthenticationTag)]);

  LMACKey := Copy(AContentEncryptionKey, 0, LHalf);
  LEncKey := Copy(AContentEncryptionKey, LHalf, LHalf);

  // The tag first, compared in constant time (TJOSEBytes "="): nothing is
  // decrypted, so no padding is examined, until the ciphertext is authentic
  if not (TJOSEBytes(ComputeTag(LMACKey, AAdditionalData, AEncryptionParts.IV, AEncryptionParts.Ciphertext)) =
    AEncryptionParts.AuthenticationTag) then
    raise EJOSEException.Create(SJOSECBCTagMismatch);

  Result := TJOSEProviders.AESCBC.Decrypt(AEncryptionParts.Ciphertext, LEncKey, AEncryptionParts.IV);
end;

{ TEncryptionParts }

constructor TEncryptionParts.Create(const AIV, ACiphertext, AAuthenticationTag: TBytes);
begin
  IV := AIV;
  Ciphertext := ACiphertext;
  AuthenticationTag := AAuthenticationTag;
end;

end.
