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
  JOSE.Types.Bytes,
  JOSE.Core.JWA;

type
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

implementation

{ TEncryptionParts }

constructor TEncryptionParts.Create(const AIv, ACiphertext, AAuthenticationTag: TBytes);
begin
  FIv := AIv;
  FCiphertext := ACiphertext;
  FAuthenticationTag := AAuthenticationTag;
end;

end.
