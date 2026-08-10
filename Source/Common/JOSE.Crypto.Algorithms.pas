{******************************************************************************}
{                                                                              }
{  Delphi JOSE-JWT Library                                                     }
{  Copyright (c) 2015 Paolo Rossi                                              }
{  https://github.com/paolo-rossi/delphi-jose-jwt                              }
{                                                                              }
{  Licensed under the MIT license                                              }
{                                                                              }
{******************************************************************************}

unit JOSE.Crypto.Algorithms;

{$I ..\JOSE.inc}

interface

uses
  System.SysUtils;

type
  THMACAlgorithm = (SHA256, SHA384, SHA512);
  THMACAlgorithmHelper = record helper for THMACAlgorithm
    procedure FromString(const AValue: string);
    function ToString: string;
  end;

{$IFDEF RSA_SIGNING}

  /// <summary>Declared algorithm in an X.509 SubjectPublicKeyInfo (PEM certificate).</summary>
  TJOSECertificatePublicKey = (RSA, EC);

  /// <summary>
  ///   RSA signature algorithms: RS* are RSASSA-PKCS1-v1_5, PS* are RSASSA-PSS (RFC 7518 3.5).
  /// </summary>
  TRSAAlgorithm = (RS256, RS384, RS512, PS256, PS384, PS512);
  TRSAAlgorithmHelper = record helper for TRSAAlgorithm
    procedure FromString(const AValue: string);
    function ToString: string;
    /// <summary>True for the RSASSA-PSS members, which need PSS padding rather than PKCS#1 v1.5.</summary>
    function IsPSS: Boolean;
    /// <summary>
    ///   Size in bytes of this algorithm's digest - which RFC 7518 3.5 also makes the PSS salt
    ///   length, MGF1 using the same hash.
    /// </summary>
    function DigestBytes: Integer;
    /// <summary>
    ///   Smallest RSA modulus, in bytes, that can carry a PSS signature for this algorithm.
    /// </summary>
    /// <remarks>
    ///   RFC 8017 9.1.1 requires emLen >= hLen + sLen + 2, and emLen is a byte short of the
    ///   modulus whenever its top bit is set - hence the extra byte. With salt = digest that
    ///   makes PS512 impossible below ~1040 bits, so a 1024-bit key can do PS256 but not PS512.
    /// </remarks>
    function MinPSSKeyBytes: Integer;
  end;

  TECDSAAlgorithm = (ES256, ES256K, ES384, ES512);
  TECDSAAlgorithmHelper = record helper for TECDSAAlgorithm
    procedure FromString(const AValue: string);
    function ToString: string;
  end;

  /// <summary>Elliptic curve identifier used at the key-material provider boundary (not JSON-facing).</summary>
  TECCurve = (P256, P384, P521, secp256k1);

  /// <summary>Raw RSA key components (RFC 7518 6.3), as used by IJOSERSAKeyMaterialProvider.</summary>
  TJOSERSAKeyMaterial = record
    Modulus: TBytes;          // n
    PublicExponent: TBytes;   // e
    PrivateExponent: TBytes;  // d
    P: TBytes;
    Q: TBytes;
    DP: TBytes;
    DQ: TBytes;
    QI: TBytes;
    function IsPrivate: Boolean;
  end;

  /// <summary>Raw EC key components (RFC 7518 6.2), as used by IJOSEECKeyMaterialProvider.</summary>
  TJOSEECKeyMaterial = record
    Curve: TECCurve;
    X: TBytes;
    Y: TBytes;
    D: TBytes;
    function IsPrivate: Boolean;
  end;

{$ENDIF}

implementation

{$IFDEF RSA_SIGNING}
uses
  JOSE.Signing.Base;
{$ENDIF}

resourcestring
  SJOSEInvalidHMACAlgorithm = 'Invalid HMAC algorithm type';
{$IFDEF RSA_SIGNING}
  SJOSEInvalidRSAAlgorithm = 'Invalid RSA algorithm type';
  SJOSEInvalidECDSAAlgorithm = 'Invalid ECDSA algorithm type';
{$ENDIF}

{ THMACAlgorithmHelper }

procedure THMACAlgorithmHelper.FromString(const AValue: string);
begin
  if AValue = 'SHA256' then
    Self := SHA256
  else if AValue = 'SHA384' then
    Self := SHA384
  else if AValue = 'SHA512' then
    Self := SHA512
  else
    raise Exception.Create(SJOSEInvalidHMACAlgorithm);
end;

function THMACAlgorithmHelper.ToString: string;
begin
  case Self of
    SHA256: Result := 'SHA256';
    SHA384: Result := 'SHA384';
    SHA512: Result := 'SHA512';
  end;
end;

{$IFDEF RSA_SIGNING}

{ TRSAAlgorithmHelper }

procedure TRSAAlgorithmHelper.FromString(const AValue: string);
begin
  if AValue = 'RS256' then
    Self := RS256
  else if AValue = 'RS384' then
    Self := RS384
  else if AValue = 'RS512' then
    Self := RS512
  else if AValue = 'PS256' then
    Self := PS256
  else if AValue = 'PS384' then
    Self := PS384
  else if AValue = 'PS512' then
    Self := PS512
  else
    raise Exception.Create(SJOSEInvalidRSAAlgorithm);
end;

function TRSAAlgorithmHelper.ToString: string;
begin
  Result := '';
  case Self of
    RS256: Result := 'RS256';
    RS384: Result := 'RS384';
    RS512: Result := 'RS512';
    PS256: Result := 'PS256';
    PS384: Result := 'PS384';
    PS512: Result := 'PS512';
  end;
end;

function TRSAAlgorithmHelper.IsPSS: Boolean;
begin
  Result := Self in [PS256, PS384, PS512];
end;

function TRSAAlgorithmHelper.DigestBytes: Integer;
begin
  case Self of
    RS256, PS256: Result := 32;
    RS384, PS384: Result := 48;
    RS512, PS512: Result := 64;
  else
    raise Exception.Create(SJOSEInvalidRSAAlgorithm);
  end;
end;

function TRSAAlgorithmHelper.MinPSSKeyBytes: Integer;
begin
  Result := 2 * DigestBytes + 3;
end;

{ TECDSAAlgorithmHelper }

procedure TECDSAAlgorithmHelper.FromString(const AValue: string);
begin
  if AValue = 'ES256' then
    Self := ES256
  else if AValue = 'ES256K' then
    Self := ES256K
  else if AValue = 'ES384' then
    Self := ES384
  else if AValue = 'ES512' then
    Self := ES512
  else
    raise ESignException.Create(SJOSEInvalidECDSAAlgorithm);
end;

function TECDSAAlgorithmHelper.ToString: string;
begin
  case Self of
    ES256: Result := 'ES256';
    ES256K: Result := 'ES256K';
    ES384: Result := 'ES384';
    ES512: Result := 'ES512';
  end;
end;

{ TJOSERSAKeyMaterial }

function TJOSERSAKeyMaterial.IsPrivate: Boolean;
begin
  Result := Length(PrivateExponent) > 0;
end;

{ TJOSEECKeyMaterial }

function TJOSEECKeyMaterial.IsPrivate: Boolean;
begin
  Result := Length(D) > 0;
end;

{$ENDIF}

end.
