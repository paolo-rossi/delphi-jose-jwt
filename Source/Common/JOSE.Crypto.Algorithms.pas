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

  /// <summary>
  ///   Digest of RSAES-OAEP encryption (RFC 8017 par. 7.1). MGF1 always uses
  ///   the same digest, as RFC 7518 par. 4.3 requires: SHA1 for "RSA-OAEP",
  ///   SHA256 for "RSA-OAEP-256". Scoped (TJOSEOAEPDigest.SHA256), since the
  ///   unscoped THMACAlgorithm already declares SHA256
  /// </summary>
{$SCOPEDENUMS ON}
  TJOSEOAEPDigest = (SHA1, SHA256);
{$SCOPEDENUMS OFF}

  TECDSAAlgorithm = (ES256, ES256K, ES384, ES512);
  TECDSAAlgorithmHelper = record helper for TECDSAAlgorithm
    procedure FromString(const AValue: string);
    function ToString: string;
    /// <summary>
    ///   Size in bytes of each of the two signature components, which RFC 7518
    ///   par. 3.4 fixes to the curve's field size: 32 for P-256 and secp256k1,
    ///   48 for P-384, 66 for P-521
    /// </summary>
    function ComponentLength: Integer;
    /// <summary>Size in bytes of the R||S signature: twice ComponentLength</summary>
    function SignatureLength: Integer;
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
    /// <summary>Size of the modulus in bits, leading zero bytes not counted</summary>
    function ModulusBits: Integer;
    /// <summary>
    ///   True when the public exponent is odd, at least 3 and smaller than
    ///   the modulus (RFC 8017 par. 3.1). With e = 1 a "signature" is the
    ///   encoded message itself, so anyone can forge one
    /// </summary>
    function HasValidPublicExponent: Boolean;
    /// <summary>
    ///   The part of HasValidPublicExponent that needs no modulus: odd and at
    ///   least 3. What a key's description can be checked for on its own
    /// </summary>
    function PublicExponentIsOddAndAboveOne: Boolean;
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

function TECDSAAlgorithmHelper.ComponentLength: Integer;
begin
  Result := 0;
  case Self of
    ES256:  Result := 32;   // P-256
    ES256K: Result := 32;   // secp256k1
    ES384:  Result := 48;   // P-384
    ES512:  Result := 66;   // P-521, 521 bits rounded up
  end;
end;

function TECDSAAlgorithmHelper.SignatureLength: Integer;
begin
  Result := ComponentLength * 2;
end;

{ TJOSERSAKeyMaterial }

function TJOSERSAKeyMaterial.IsPrivate: Boolean;
begin
  Result := Length(PrivateExponent) > 0;
end;

/// <summary>Index of the first non-zero byte of AValue, Length(AValue) when all are zero</summary>
function FirstSignificantByte(const AValue: TBytes): Integer;
begin
  Result := 0;
  while (Result < Length(AValue)) and (AValue[Result] = 0) do
    Inc(Result);
end;

function TJOSERSAKeyMaterial.ModulusBits: Integer;
var
  LFirst: Integer;
  LTop: Byte;
begin
  LFirst := FirstSignificantByte(Modulus);
  if LFirst = Length(Modulus) then
    Exit(0);

  Result := (Length(Modulus) - LFirst - 1) * 8;
  LTop := Modulus[LFirst];
  while LTop <> 0 do
  begin
    Inc(Result);
    LTop := LTop shr 1;
  end;
end;

function TJOSERSAKeyMaterial.PublicExponentIsOddAndAboveOne: Boolean;
var
  LFirst: Integer;
begin
  LFirst := FirstSignificantByte(PublicExponent);

  // Even, or zero (no significant byte at all)
  if (LFirst = Length(PublicExponent)) or not Odd(PublicExponent[High(PublicExponent)]) then
    Exit(False);

  // 1 is the only odd value below 3
  Result := not ((LFirst = High(PublicExponent)) and (PublicExponent[LFirst] = 1));
end;

function TJOSERSAKeyMaterial.HasValidPublicExponent: Boolean;
var
  LFirstE, LFirstN, LLengthE, LLengthN, LIndex: Integer;
begin
  if not PublicExponentIsOddAndAboveOne then
    Exit(False);

  LFirstE := FirstSignificantByte(PublicExponent);
  LLengthE := Length(PublicExponent) - LFirstE;

  // e < n, compared as big-endian unsigned integers
  LFirstN := FirstSignificantByte(Modulus);
  LLengthN := Length(Modulus) - LFirstN;
  if LLengthE <> LLengthN then
    Exit(LLengthE < LLengthN);

  for LIndex := 0 to LLengthE - 1 do
    if PublicExponent[LFirstE + LIndex] <> Modulus[LFirstN + LIndex] then
      Exit(PublicExponent[LFirstE + LIndex] < Modulus[LFirstN + LIndex]);

  Result := False;
end;

{ TJOSEECKeyMaterial }

function TJOSEECKeyMaterial.IsPrivate: Boolean;
begin
  Result := Length(D) > 0;
end;

{$ENDIF}

end.
