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
///   JWE compression ("zip", RFC 7516 par. 4.1.3)
/// </summary>
/// <seealso href="https://tools.ietf.org/html/rfc7516#section-4.1.3">
///   JWE RFC Document
/// </seealso>
unit JOSE.Core.JWA.Compression;

{$I ..\JOSE.inc}

interface

uses
  System.SysUtils,
  JOSE.Types.Bytes,
  JOSE.Core.JWA;

const
  /// <summary>The "zip" value for DEFLATE (RFC 7518 par. 7.3)</summary>
  JWE_COMPRESSION_DEFLATE = 'DEF';

type
  /// <summary>
  ///   A compression algorithm ("zip"). Registered under its "zip" value;
  ///   GetAlgorithmIdentifier returns TJOSEAlgorithmId.Unknown
  /// </summary>
  IJOSECompressionAlgorithm = interface(IJOSEAlgorithm)
  ['{B2782386-F5A2-43BF-B86C-B103A0221FC4}']
    function Compress(const AData: TBytes): TBytes;
    /// <summary>
    ///   Raises EJOSEException when the data does not decompress, or when it
    ///   would decompress to more than AMaxSize bytes (a decompression bomb:
    ///   a few kilobytes can expand to gigabytes)
    /// </summary>
    function Decompress(const ACompressedData: TBytes; AMaxSize: Integer): TBytes;
  end;

  /// <summary>
  ///   "DEF": raw DEFLATE (RFC 1951), with no zlib or gzip header, over
  ///   System.ZLib. Pure RTL: no provider capability involved
  /// </summary>
  TDeflateCompressionAlgorithm = class(TJOSEAlgorithm, IJOSECompressionAlgorithm)
  public
    constructor Create;
    class function Deflate: IJOSECompressionAlgorithm;

    function Compress(const AData: TBytes): TBytes;
    function Decompress(const ACompressedData: TBytes; AMaxSize: Integer): TBytes;
  end;

implementation

uses
  System.Classes,
  System.ZLib,
  JOSE.Core.Base;

resourcestring
  SJOSEDecompressionFailed = 'The JWE payload does not decompress as raw DEFLATE ("zip":"DEF")';
  SJOSEDecompressionTooLarge = 'The JWE payload decompresses to more than %d bytes ' +
    '(TJWE.MaxDecompressedSize)';

const
  // Negative window bits select raw DEFLATE: no zlib header or trailer, which
  // is what "DEF" means. 15 is the largest window, so every stream decodes
  RAW_DEFLATE_WINDOW_BITS = -15;
  DECOMPRESS_CHUNK = 16 * 1024;

{ TDeflateCompressionAlgorithm }

constructor TDeflateCompressionAlgorithm.Create;
begin
  inherited Create;
  FAlgorithmIdentifier := TJOSEAlgorithmId.Unknown;
  FKeyCategory := TJOSEKeyCategory.None;
  FKeyType := '';
end;

class function TDeflateCompressionAlgorithm.Deflate: IJOSECompressionAlgorithm;
begin
  Result := TDeflateCompressionAlgorithm.Create;
end;

function TDeflateCompressionAlgorithm.Compress(const AData: TBytes): TBytes;
var
  LOutput: TBytesStream;
  LDeflate: TZCompressionStream;
begin
  LOutput := TBytesStream.Create;
  try
    LDeflate := TZCompressionStream.Create(LOutput, zcDefault, RAW_DEFLATE_WINDOW_BITS);
    try
      if Length(AData) > 0 then
        LDeflate.WriteBuffer(AData[0], Length(AData));
    finally
      // Freeing the stream flushes the final block
      LDeflate.Free;
    end;
    Result := Copy(LOutput.Bytes, 0, LOutput.Size);
  finally
    LOutput.Free;
  end;
end;

function TDeflateCompressionAlgorithm.Decompress(const ACompressedData: TBytes; AMaxSize: Integer): TBytes;
var
  LSource: TBytesStream;
  LInflate: TZDecompressionStream;
  LOutput: TBytesStream;
  LBuffer: TBytes;
  LRead: Integer;
begin
  LSource := TBytesStream.Create(ACompressedData);
  LOutput := TBytesStream.Create;
  try
    try
      LInflate := TZDecompressionStream.Create(LSource, RAW_DEFLATE_WINDOW_BITS);
      try
        // Chunk by chunk, so that the cap is enforced while inflating rather
        // than after the whole bomb has been expanded in memory
        SetLength(LBuffer, DECOMPRESS_CHUNK);
        repeat
          LRead := LInflate.Read(LBuffer[0], Length(LBuffer));
          if LRead > 0 then
          begin
            if LOutput.Size + LRead > AMaxSize then
              raise EJOSEException.CreateFmt(SJOSEDecompressionTooLarge, [AMaxSize]);
            LOutput.WriteBuffer(LBuffer[0], LRead);
          end;
        until LRead = 0;
      finally
        LInflate.Free;
      end;
    except
      on E: EJOSEException do
        raise;
      // Only ZLib's own errors mean "the payload is not raw DEFLATE": a fault
      // (out of memory, an access violation) must not be disguised as a
      // malformed payload
      on E: EZLibError do
        raise EJOSEException.Create(SJOSEDecompressionFailed);
    end;

    Result := Copy(LOutput.Bytes, 0, LOutput.Size);
  finally
    LOutput.Free;
    LSource.Free;
  end;
end;

end.
