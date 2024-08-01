{******************************************************************************}
{                                                                              }
{  Delphi JOSE Library                                                         }
{  Copyright (c) 2015 Paolo Rossi                                              }
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

/// <summary>
///   JSON Web Encryption (JWE) RFC implementation (initial)
/// </summary>
/// <seealso href="https://tools.ietf.org/html/rfc7516">
///   JWE RFC Document
/// </seealso>
unit JOSE.Core.JWA.Encryption;

{$I ..\JOSE.inc}

interface

uses
  System.SysUtils,
  IdSSLOpenSSLHeaders,
  JOSE.Types.Bytes,
  JOSE.Core.JWA;

type

  EEncryptionException = class(Exception);

  TEncryptionParts = class
  private
    FAuthenticationTag: TBytes;
    FCiphertext: TBytes;
    FIv: TBytes;
  public
    constructor Create(const AIv,ACiphertext, AAuthenticationTag: TBytes);

    property Iv: TBytes read FIv;
    property Ciphertext: TBytes read FCiphertext;
    property AuthenticationTag: TBytes read FAuthenticationTag;
  end;

  IJOSEEncryptionAlgorithm = interface(IJOSEAlgorithm)
  ['{D802ABF3-82E2-494B-B96A-D13C5A782574}']
    //function GetContentEncryptionKeyDescriptor: TContentEncryptionKeyDescriptor;
    function Encrypt(const APlaintext, AAdditionalData, AContentEncryptionKey, IvOverride: TBytes{; AHeaders headers}): TEncryptionParts;
    function Decrypt(AEncryptionParts: TEncryptionParts; const AAdditionalData, AContentEncryptionKey: TBytes{; Headers headers}): TBytes;
  end;

  TJOSEEncryptionAlgorithm = class(TJOSEAlgorithm, IJOSEEncryptionAlgorithm)
  protected
    constructor Create(AAlgorithmId: TJOSEAlgorithmId);
  public
    function Encrypt(const APlaintext, AAdditionalData, AContentEncryptionKey, IvOverride: TBytes): TEncryptionParts;
    function Decrypt(AEncryptionParts: TEncryptionParts; const AAdditionalData, AContentEncryptionKey: TBytes): TBytes;
    class function A256CBC_HS512: IJOSEEncryptionAlgorithm;
  end;

implementation

uses
  JOSE.Hashing.HMAC;

{ TEncryptionParts }

constructor TEncryptionParts.Create(const AIv, ACiphertext, AAuthenticationTag: TBytes);
begin
  FIv := AIv;
  FCiphertext := ACiphertext;
  FAuthenticationTag := AAuthenticationTag;
end;

{ TJOSEEncryptionAlgorithm }

constructor TJOSEEncryptionAlgorithm.Create(AAlgorithmId: TJOSEAlgorithmId);
begin
  FAlgorithmIdentifier := AAlgorithmId;
  FKeyCategory := TJOSEKeyCategory.Symmetric;
  FKeyType := 'oct';
end;

function TJOSEEncryptionAlgorithm.Encrypt(const APlaintext, AAdditionalData, AContentEncryptionKey, IvOverride: TBytes): TEncryptionParts;
var
  MacKey, EncKey: TBytes;
  CipherText: TBytes;
  CipherCtx: EVP_CIPHER_CTX;
  IV: TBytes;
begin

  // Check the encryption key size
  if Length(AContentEncryptionKey) * 8 < GetAlgorithmIdentifier.Length then
    raise EEncryptionException.Create('[Encryption] The key size must be ' + GetAlgorithmIdentifier.Length.ToString + '-bit long');

  // Extract MAC key - first half
  SetLength(MacKey, Length(AContentEncryptionKey) div 2);
  Move(AContentEncryptionKey[0], MacKey[0], Length(MacKey));

  // Extract the ENC key - seconds half
  SetLength(EncKey, Length(AContentEncryptionKey) div 2);
  Move(AContentEncryptionKey[Length(AContentEncryptionKey) div 2], EncKey[0], Length(EncKey));

  // Init the cipher
  EVP_CIPHER_CTX_init(@CipherCtx);
  try

    // The initialization vector
    if Assigned(IvOverride) then
      IV := IvOverride
    else
      IV := TJOSEBytes.RandomBytes(EVP_MAX_IV_LENGTH);

    // Initialize cipher
    case GetAlgorithmIdentifier of
      TJOSEAlgorithmId.A256CBC_HS512: EVP_EncryptInit_ex(@CipherCtx, EVP_aes_256_cbc, nil, @EncKey[0], @IV[0]);
      else
        raise EEncryptionException.Create('[Encryption] Invalid encryption algorithm');
    end;

    // Apply PKCS7
    var PaddingSize := CipherCtx.cipher.block_size - Length(APlaintext) mod CipherCtx.cipher.block_size;
    var LPlainText := APlaintext;
    SetLength(LPlainText, Length(LPlainText) + PaddingSize);
    FillChar(LPlainText[Length(APlaintext)], PaddingSize, PaddingSize);

    // Set the cipher text length
    SetLength(CipherText, Length(LPlainText) + CipherCtx.cipher.block_size);

    // Encrypt the plain text
    var OutLen: Integer;
    EVP_EncryptUpdate(@CipherCtx, @CipherText[0], @OutLen, @LPlainText[0], Length(LPlainText));
    EVP_EncryptFinal_ex(@CipherCtx, @CipherText[OutLen], @OutLen);
  finally
    EVP_CIPHER_CTX_cleanup(@cipherCtx);
  end;

  // Additional data len
  var AADSize: UInt64 := Length(AAdditionalData) * 8;
  var AADLen: TBytes;
  SetLength(AADLen, SizeOf(AADSize));
  Move(AADSize, AADLen[0], Length(AADLen));

  // Make HMAC
  var HMACData: TBytes := AAdditionalData + IV + CipherText + TJOSEBytes.Swap(AADLen);
  var HMAC: TBytes := THMAC.Sign(HMACData, MacKey, GetAlgorithmIdentifier.Length);
  var AuthenticationTag: TBytes;
  SetLength(AuthenticationTag, Length(HMAC) div 2);
  Move(HMAC[0], AuthenticationTag[0], Length(AuthenticationTag));

  // Result
  Result := TEncryptionParts.Create(IV, CipherText, AuthenticationTag);

end;

function TJOSEEncryptionAlgorithm.Decrypt(AEncryptionParts: TEncryptionParts; const AAdditionalData, AContentEncryptionKey: TBytes): TBytes;
begin
  // To do
end;

class function TJOSEEncryptionAlgorithm.A256CBC_HS512: IJOSEEncryptionAlgorithm;
begin
  Result := TJOSEEncryptionAlgorithm.Create(TJOSEAlgorithmId.A256CBC_HS512);
end;

end.
