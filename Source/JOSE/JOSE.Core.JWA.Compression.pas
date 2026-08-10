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
///   JSON Web Algorithms (JWA) RFC implementation (partial) <br />
/// </summary>
/// <seealso href="https://tools.ietf.org/html/rfc7518">
///   JWA RFC Document
/// </seealso>
unit JOSE.Core.JWA.Compression;

{$I ..\JOSE.inc}

interface

uses
  System.SysUtils,
  JOSE.Types.Bytes,
  JOSE.Core.JWA;

type
  IJOSECompressionAlgorithm = interface(IJOSEAlgorithm)
  ['{B2782386-F5A2-43BF-B86C-B103A0221FC4}']
    function Compress(const Data: TBytes): TBytes;
    function Decompress(const CompressedData: TBytes): TBytes;
  end;

implementation

end.
