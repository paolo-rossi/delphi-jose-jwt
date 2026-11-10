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
///   JOSE Header of a JWE (RFC 7516 par. 4)
/// </summary>
/// <remarks>
///   A unit of its own, rather than part of JOSE.Core.JWE, so that the key
///   management algorithms (JOSE.Core.JWA.KeyManagement) can take the header
///   without a circular unit reference
/// </remarks>
unit JOSE.Core.JWE.Header;

{$I ..\JOSE.inc}

interface

uses
  System.SysUtils,
  System.JSON,
  JOSE.Types.JSON,
  JOSE.Core.JWA,
  JOSE.Core.JWT;

type
  /// <summary>
  ///   Header of a JWE: the JWT header plus the JWE members
  /// </summary>
  TJWEHeader = class(TJWTHeader)
  private
    function GetEncryption: string;
    procedure SetEncryption(const AValue: string);
    function GetEncryptionId: TJOSEEncryptionAlgorithmId;
    procedure SetEncryptionId(AValue: TJOSEEncryptionAlgorithmId);
    function GetContentType: string;
    procedure SetContentType(const AValue: string);
    function GetCompression: string;
    function GetHasCompression: Boolean;
    function GetHasCritical: Boolean;
    function GetIsNestedJWT: Boolean;
  public
    /// <summary>The "enc" member as found in the header</summary>
    property Encryption: string read GetEncryption write SetEncryption;
    /// <summary>The "enc" member, Unknown when it is absent or not supported</summary>
    property EncryptionId: TJOSEEncryptionAlgorithmId read GetEncryptionId write SetEncryptionId;
    /// <summary>The "cty" member</summary>
    property ContentType: string read GetContentType write SetContentType;
    /// <summary>
    ///   The "zip" member. To have a token compressed, set "zip":"DEF" on the
    ///   TJWT's header before encrypting (TJWTHeader.SetHeaderParam): this
    ///   header is rebuilt from that one on every encryption
    /// </summary>
    property Compression: string read GetCompression;
    /// <summary>True when the header has a "zip" member, whatever its value</summary>
    property HasCompression: Boolean read GetHasCompression;
    /// <summary>True when the header has a "crit" member, whatever its value</summary>
    property HasCritical: Boolean read GetHasCritical;
    /// <summary>
    ///   True when "cty" says that the payload is itself a JWT (a nested JWT,
    ///   RFC 7519 par. 5.2). The comparison ignores case and the optional
    ///   "application/" prefix, as RFC 7515 par. 4.1.10 requires
    /// </summary>
    property IsNestedJWT: Boolean read GetIsNestedJWT;
  end;

implementation

{ TJWEHeader }

function TJWEHeader.GetCompression: string;
begin
  Result := TJSONUtils.GetJSONValueAsString(THeaderNames.COMPRESSION, FJSON);
end;

function TJWEHeader.GetContentType: string;
begin
  Result := TJSONUtils.GetJSONValueAsString(THeaderNames.CONTENT_TYPE, FJSON);
end;

function TJWEHeader.GetEncryption: string;
begin
  Result := TJSONUtils.GetJSONValueAsString(THeaderNames.ENCRYPTION, FJSON);
end;

function TJWEHeader.GetEncryptionId: TJOSEEncryptionAlgorithmId;
begin
  Result.AsString := GetEncryption;
end;

function TJWEHeader.GetHasCompression: Boolean;
begin
  // Presence, not value: a "zip" of any type has to be rejected, since
  // ignoring it would hand back the compressed bytes as the payload
  Result := Assigned(FJSON.GetValue(THeaderNames.COMPRESSION));
end;

function TJWEHeader.GetHasCritical: Boolean;
begin
  Result := Assigned(FJSON.GetValue(THeaderNames.CRITICAL));
end;

function TJWEHeader.GetIsNestedJWT: Boolean;
const
  MEDIA_TYPE_PREFIX = 'application/';
var
  LType: string;
begin
  LType := GetContentType;
  if LType.StartsWith(MEDIA_TYPE_PREFIX, True) then
    LType := LType.Substring(Length(MEDIA_TYPE_PREFIX));

  Result := SameText(LType, 'JWT');
end;

procedure TJWEHeader.SetContentType(const AValue: string);
begin
  TJSONUtils.SetJSONValueFrom<string>(THeaderNames.CONTENT_TYPE, AValue, FJSON);
end;

procedure TJWEHeader.SetEncryption(const AValue: string);
begin
  TJSONUtils.SetJSONValueFrom<string>(THeaderNames.ENCRYPTION, AValue, FJSON);
end;

procedure TJWEHeader.SetEncryptionId(AValue: TJOSEEncryptionAlgorithmId);
begin
  SetEncryption(AValue.AsString);
end;

end.
