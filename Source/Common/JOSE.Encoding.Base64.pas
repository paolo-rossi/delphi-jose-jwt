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
///   Base64 utility class
/// </summary>
unit JOSE.Encoding.Base64;

{$I ..\JOSE.inc}

interface

uses
  System.SysUtils,
  JOSE.Types.Bytes;

type
  /// <summary>
  ///   Raised when a value is not valid base64url and strict decoding is on
  /// </summary>
  EJOSEBase64Exception = class(Exception);

  TBase64 = class
  private
    class var FStrictURLDecoding: Boolean;
    /// <summary>6-bit value of a base64url character, or -1 when it is not one</summary>
    class function URLCharValue(AChar: Byte): Integer; static;
    class procedure CheckURLEncoded(const ASource: TJOSEBytes); static;
  public
    class constructor Create;

    class function Encode(const ASource: TJOSEBytes): TJOSEBytes; overload;
    class function Decode(const ASource: TJOSEBytes): TJOSEBytes; overload;
    class function TryDecode(const ASource: TJOSEBytes): TJOSEBytes;

    class function URLEncode(const ASource: TJOSEBytes): TJOSEBytes; overload;
    class function URLDecode(const ASource: TJOSEBytes): TJOSEBytes; overload;
    class function TryURLDecode(const ASource: TJOSEBytes): TJOSEBytes;

    /// <summary>
    ///   True when ASource is base64url as RFC 7515 par. 2 requires it: the
    ///   <c>A-Za-z0-9-_</c> alphabet only - no padding, no whitespace, no line
    ///   breaks, none of the standard alphabet's <c>+</c> and <c>/</c> - a
    ///   length that a base64 encoder can actually produce, and canonical
    ///   trailing bits. An empty value is valid and decodes to nothing
    /// </summary>
    class function IsValidURLEncoded(const ASource: TJOSEBytes): Boolean; static;

    /// <summary>
    ///   When True (the default) URLDecode refuses anything IsValidURLEncoded
    ///   rejects, and TryURLDecode returns an empty value for it
    /// </summary>
    /// <remarks>
    ///   The underlying decoders are lenient in ways that differ between the
    ///   provider stacks and between Delphi versions: the Default stack drops
    ///   out-of-alphabet characters and line breaks, tolerates padding and
    ///   ignores non-canonical trailing bits, so many different texts decode to
    ///   the same bytes. For the signature segment of a token that means one
    ///   logical token has many wire forms, all of which verify - which breaks
    ///   any denylist, replay cache or fingerprint keyed on the token text.
    ///   Turn this off only to interoperate with an issuer that emits
    ///   non-conforming tokens.
    /// </remarks>
    class property StrictURLDecoding: Boolean read FStrictURLDecoding write FStrictURLDecoding;
  end;

implementation

uses
  JOSE.Providers;

resourcestring
  SJOSEInvalidBase64URL = 'The value is not valid base64url (RFC 7515 par. 2)';

{ TBase64 }

class constructor TBase64.Create;
begin
  FStrictURLDecoding := True;
end;

class function TBase64.URLCharValue(AChar: Byte): Integer;
begin
  case AChar of
    Ord('A')..Ord('Z'): Result := AChar - Ord('A');
    Ord('a')..Ord('z'): Result := AChar - Ord('a') + 26;
    Ord('0')..Ord('9'): Result := AChar - Ord('0') + 52;
    Ord('-'): Result := 62;
    Ord('_'): Result := 63;
  else
    Result := -1;
  end;
end;

class function TBase64.IsValidURLEncoded(const ASource: TJOSEBytes): Boolean;
var
  LBytes: TBytes;
  LIndex, LLength, LUnusedBits: Integer;
begin
  // Compared as raw bytes: a base64url value is ASCII by definition, and going
  // through a string would first decode it as UTF-8
  LBytes := ASource.AsBytes;
  LLength := Length(LBytes);

  if LLength = 0 then
    Exit(True);

  // 4n+1 characters carry 6 leftover bits: no encoder can produce that
  if LLength mod 4 = 1 then
    Exit(False);

  for LIndex := 0 to LLength - 1 do
    if URLCharValue(LBytes[LIndex]) < 0 then
      Exit(False);

  // The last character of a 4n+2 / 4n+3 value contributes fewer than 6 bits.
  // Its unused low bits must be zero, otherwise two different texts decode to
  // the same bytes ("TWE" and "TWF" both give "Ma")
  case LLength mod 4 of
    2: LUnusedBits := $0F;   // 12 bits carried, 8 used
    3: LUnusedBits := $03;   // 18 bits carried, 16 used
  else
    LUnusedBits := 0;
  end;

  if (LUnusedBits <> 0) and ((URLCharValue(LBytes[LLength - 1]) and LUnusedBits) <> 0) then
    Exit(False);

  Result := True;
end;

class procedure TBase64.CheckURLEncoded(const ASource: TJOSEBytes);
begin
  if FStrictURLDecoding and not IsValidURLEncoded(ASource) then
    raise EJOSEBase64Exception.Create(SJOSEInvalidBase64URL);
end;

class function TBase64.Decode(const ASource: TJOSEBytes): TJOSEBytes;
begin
  Result := TJOSEProviders.Base64.Decode(ASource);
end;

class function TBase64.Encode(const ASource: TJOSEBytes): TJOSEBytes;
begin
  Result := TJOSEProviders.Base64.Encode(ASource);
end;

class function TBase64.TryDecode(const ASource: TJOSEBytes): TJOSEBytes;
begin
  Result := TJOSEProviders.Base64.TryDecode(ASource);
end;

class function TBase64.TryURLDecode(const ASource: TJOSEBytes): TJOSEBytes;
begin
  if FStrictURLDecoding and not IsValidURLEncoded(ASource) then
    Exit(TJOSEBytes.Empty);

  Result := TJOSEProviders.Base64.TryURLDecode(ASource);
end;

class function TBase64.URLDecode(const ASource: TJOSEBytes): TJOSEBytes;
begin
  // Validated here, before the provider: the stacks disagree about what they
  // accept, so the check has to sit above them to make them behave alike
  CheckURLEncoded(ASource);

  Result := TJOSEProviders.Base64.URLDecode(ASource);
end;

class function TBase64.URLEncode(const ASource: TJOSEBytes): TJOSEBytes;
begin
  Result := TJOSEProviders.Base64.URLEncode(ASource);
end;

end.
