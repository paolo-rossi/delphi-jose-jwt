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
unit JOSE.Core.JWA.Signing;

{$I ..\JOSE.inc}

interface

uses
  System.SysUtils,
  JOSE.Types.Bytes,
  JOSE.Hashing.HMAC,
  JOSE.Signing.RSA,
  JOSE.Signing.ECDSA,
  JOSE.Core.Base,
  JOSE.Core.Parts,
  JOSE.Core.JWA,
  JOSE.Core.JWK;

type
  IJOSESigningAlgorithm = interface(IJOSEAlgorithm)
  ['{F999E708-40F5-40E3-81F9-C4D20EB2FA79}']
    function VerifySignature(const AKey, AInput, ASignature: TJOSEBytes): Boolean;
    function Sign(const AKey, AInput: TJOSEBytes): TJOSEBytes;
    procedure ValidateSigningKey(const AKey: TJOSEBytes);
    procedure ValidateVerificationKey(const AKey: TJOSEBytes);
  end;

  TBaseSignatureAlgorithm = class(TJOSEAlgorithm, IJOSESigningAlgorithm)
  public
    function VerifySignature(const AKey, AInput, ASignature: TJOSEBytes): Boolean;
    function Sign(const AKey, AInput: TJOSEBytes): TJOSEBytes;
    procedure ValidateSigningKey(const AKey: TJOSEBytes);
    procedure ValidateVerificationKey(const AKey: TJOSEBytes);
  end;

  TUnsecureNoneAlgorithm = class(TJOSEAlgorithm, IJOSESigningAlgorithm)
  private
    procedure ValidateKey(const AKey: TJOSEBytes);
  public
    constructor Create;
    function VerifySignature(const AKey, AInput, ASignature: TJOSEBytes): Boolean;
    function Sign(const AKey, AInput: TJOSEBytes): TJOSEBytes;
    procedure ValidateSigningKey(const AKey: TJOSEBytes);
    procedure ValidateVerificationKey(const AKey: TJOSEBytes);
  end;

  THmacUsingShaAlgorithm = class(TJOSEAlgorithm, IJOSESigningAlgorithm)
  private
    FKeyMinLength: Integer;
  protected
    FHMACAlgorithm: THMACAlgorithm;
    constructor Create(const AAlgorithmId: TJOSEAlgorithmId; AKeyMinLength: Integer);
    procedure ValidateKey(const AKey: TJOSEBytes);
  public
    class function HmacSha256: IJOSESigningAlgorithm;
    class function HmacSha384: IJOSESigningAlgorithm;
    class function HmacSha512: IJOSESigningAlgorithm;

    function VerifySignature(const AKey, AInput, ASignature: TJOSEBytes): Boolean;
    function Sign(const AKey, AInput: TJOSEBytes): TJOSEBytes;
    procedure ValidateSigningKey(const AKey: TJOSEBytes);
    procedure ValidateVerificationKey(const AKey: TJOSEBytes);
  end;

{$IFDEF RSA_SIGNING}

  TRSAUsingSHAAlgorithm = class(TJOSEAlgorithm, IJOSESigningAlgorithm)
  private
    FKeyMinLength: Integer;
  protected
    FRSAAlgorithm: TRSAAlgorithm;
    constructor Create(const AAlgorithmId: TJOSEAlgorithmId; AKeyMinLength: Integer);
  public
    class function RSA256: IJOSESigningAlgorithm;
    class function RSA384: IJOSESigningAlgorithm;
    class function RSA512: IJOSESigningAlgorithm;

    /// <summary>RSASSA-PSS (RFC 7518 3.5). Same keys as RS*, different padding.</summary>
    class function PSS256: IJOSESigningAlgorithm;
    class function PSS384: IJOSESigningAlgorithm;
    class function PSS512: IJOSESigningAlgorithm;

    function VerifySignature(const AKey, AInput, ASignature: TJOSEBytes): Boolean;
    function Sign(const AKey, AInput: TJOSEBytes): TJOSEBytes;
    procedure ValidateSigningKey(const AKey: TJOSEBytes);
    procedure ValidateVerificationKey(const AKey: TJOSEBytes);
  end;

  TECDSAUsingSHAAlgorithm = class(TJOSEAlgorithm, IJOSESigningAlgorithm)
  private
    FKeyMinLength: Integer;
  protected
    FECDSAAlgorithm: TECDSAAlgorithm;
    constructor Create(const AAlgorithmId: TJOSEAlgorithmId; AKeyMinLength: Integer);
  public
    class function ECDSA256: IJOSESigningAlgorithm;
    class function ECDSA256K: IJOSESigningAlgorithm;
    class function ECDSA384: IJOSESigningAlgorithm;
    class function ECDSA512: IJOSESigningAlgorithm;

    function VerifySignature(const AKey, AInput, ASignature: TJOSEBytes): Boolean;
    function Sign(const AKey, AInput: TJOSEBytes): TJOSEBytes;
    procedure ValidateSigningKey(const AKey: TJOSEBytes);
    procedure ValidateVerificationKey(const AKey: TJOSEBytes);
  end;

{$ENDIF}

implementation

uses
  System.Types,
  System.StrUtils,
  JOSE.Encoding.Base64;

resourcestring
  SJOSEKeyIsNull = 'Key is null';
  SJOSEKeyTooShort = 'Key is too short (%dbit), expected (%dbit)';
  SJOSENotImplemented = 'Not implemented';
  SJOSEUnsecureAlgorithmMustNotUseKey = 'Unsecure JWS (alg=None) must not use a key';
  SJOSEHmacKeyIsPEM = 'HMAC key is PEM-armoured key material, not a shared secret. ' +
    'Refusing it: an attacker holding the matching public key could forge tokens (RS256/HS256 ' +
    'algorithm substitution)';

/// <summary>
///   True when AKey opens - leading whitespace aside - with PEM armour ("-----BEGIN").
/// </summary>
/// <remarks>
///   Compared as raw bytes rather than through a string: an HMAC secret is arbitrary binary and
///   need not survive a text decode.
/// </remarks>
function JOSEKeyLooksLikePEM(const AKey: TJOSEBytes): Boolean;
const
  PEM_ARMOUR: array [0..9] of Byte = (
    Ord('-'), Ord('-'), Ord('-'), Ord('-'), Ord('-'),
    Ord('B'), Ord('E'), Ord('G'), Ord('I'), Ord('N'));
var
  LBytes: TBytes;
  LStart, LIndex: Integer;
begin
  LBytes := AKey.AsBytes;

  LStart := 0;
  while (LStart < Length(LBytes)) and (LBytes[LStart] in [9, 10, 13, 32]) do
    Inc(LStart);

  if Length(LBytes) - LStart < Length(PEM_ARMOUR) then
    Exit(False);

  for LIndex := 0 to High(PEM_ARMOUR) do
    if LBytes[LStart + LIndex] <> PEM_ARMOUR[LIndex] then
      Exit(False);

  Result := True;
end;

constructor THmacUsingShaAlgorithm.Create(const AAlgorithmId: TJOSEAlgorithmId; AKeyMinLength: Integer);
begin
  FAlgorithmIdentifier := AAlgorithmId;

  case AAlgorithmId of
    TJOSEAlgorithmId.HS256: FHMACAlgorithm := THMACAlgorithm.SHA256;
    TJOSEAlgorithmId.HS384: FHMACAlgorithm := THMACAlgorithm.SHA384;
    TJOSEAlgorithmId.HS512: FHMACAlgorithm := THMACAlgorithm.SHA512;
  end;
  FKeyCategory := TJOSEKeyCategory.Symmetric;
  FKeyType := 'oct';
  FKeyMinLength := AKeyMinLength;
end;

class function THmacUsingShaAlgorithm.HmacSha256: IJOSESigningAlgorithm;
begin
  Result := THmacUsingShaAlgorithm.Create(TJOSEAlgorithmId.HS256, 256);
end;

class function THmacUsingShaAlgorithm.HmacSha384: IJOSESigningAlgorithm;
begin
  Result := THmacUsingShaAlgorithm.Create(TJOSEAlgorithmId.HS384, 384);
end;

class function THmacUsingShaAlgorithm.HmacSha512: IJOSESigningAlgorithm;
begin
  Result := THmacUsingShaAlgorithm.Create(TJOSEAlgorithmId.HS512, 512);
end;

function THmacUsingShaAlgorithm.Sign(const AKey, AInput: TJOSEBytes): TJOSEBytes;
var
  LSign: TJOSEBytes;
begin
  LSign := THMAC.Sign(AInput, AKey, FHMACAlgorithm);
  Result := TBase64.URLEncode(LSign.AsBytes);
end;

procedure THmacUsingShaAlgorithm.ValidateKey(const AKey: TJOSEBytes);
begin
  if AKey.IsEmpty then
    raise EJOSEException.Create(SJOSEKeyIsNull);

  // Defence in depth against algorithm substitution. TJWS picks the algorithm from the token's own
  // header, so a verifier holding an RSA/EC *public* key can be handed an HS256 token that was
  // HMACed with that very key - which the attacker also has. Nothing legitimate uses PEM armour as
  // a shared secret, so refusing it costs nothing and closes the classic RS256 -> HS256 swap.
  // The real control is still TJOSEConsumer.SetExpectedAlgorithms; this only narrows the blast
  // radius when that list is left wide, and is bypassed along with every other key check when the
  // caller opts out via SkipKeyValidation.
  if JOSEKeyLooksLikePEM(AKey) then
    raise EJOSEException.Create(SJOSEHmacKeyIsPEM);

  if AKey.Size * 8 < FKeyMinLength then
    raise EJOSEException.CreateFmt(SJOSEKeyTooShort,
      [AKey.Size * 8, FKeyMinLength]);
end;

procedure THmacUsingShaAlgorithm.ValidateSigningKey(const AKey: TJOSEBytes);
begin
  ValidateKey(AKey);
end;

procedure THmacUsingShaAlgorithm.ValidateVerificationKey(const AKey: TJOSEBytes);
begin
  ValidateKey(AKey);
end;

function THmacUsingShaAlgorithm.VerifySignature(const AKey, AInput, ASignature: TJOSEBytes): Boolean;
var
  LComputedSignature: TJOSEBytes;
begin
  LComputedSignature := THMAC.Sign(AInput, AKey, FHMACAlgorithm);
  LComputedSignature := TBase64.URLEncode(LComputedSignature.AsBytes);

  Result := LComputedSignature = ASignature;
end;

{ TBaseSignatureAlgorithm }

function TBaseSignatureAlgorithm.Sign(const AKey, AInput: TJOSEBytes): TJOSEBytes;
begin
  Result := '';
end;

procedure TBaseSignatureAlgorithm.ValidateSigningKey(const AKey: TJOSEBytes);
begin
  raise EJOSEException.Create(SJOSENotImplemented);
end;

procedure TBaseSignatureAlgorithm.ValidateVerificationKey(const AKey: TJOSEBytes);
begin
  raise EJOSEException.Create(SJOSENotImplemented);
end;

function TBaseSignatureAlgorithm.VerifySignature(const AKey, AInput, ASignature: TJOSEBytes): Boolean;
begin
  Result := False;
end;

{ TUnsecureNoneAlgorithm }

constructor TUnsecureNoneAlgorithm.Create;
begin
  FAlgorithmIdentifier := TJOSEAlgorithmId.None;
  FKeyCategory := TJOSEKeyCategory.None;
end;

function TUnsecureNoneAlgorithm.Sign(const AKey, AInput: TJOSEBytes): TJOSEBytes;
begin
  ValidateKey(AKey);
  Result := TJOSEBytes.Empty;
end;

procedure TUnsecureNoneAlgorithm.ValidateKey(const AKey: TJOSEBytes);
begin
  if not AKey.IsEmpty then
    raise EJOSEException.Create(SJOSEUnsecureAlgorithmMustNotUseKey);
end;

procedure TUnsecureNoneAlgorithm.ValidateSigningKey(const AKey: TJOSEBytes);
begin
  ValidateKey(AKey);
end;

procedure TUnsecureNoneAlgorithm.ValidateVerificationKey(const AKey: TJOSEBytes);
begin
  ValidateKey(AKey);
end;

function TUnsecureNoneAlgorithm.VerifySignature(const AKey, AInput, ASignature: TJOSEBytes): Boolean;
begin
  ValidateKey(AKey);
  Result := ASignature.IsEmpty;
end;

{$IFDEF RSA_SIGNING}

resourcestring
  SJOSEKeyNotRSAPem = 'Key is not RSA key in PEM format';
  SJOSEUnsupportedRSAAlgorithmId = 'Not an RSA signing algorithm: %s';
  SJOSEKeyNotECDSAPem = 'Key is not ECDSA key in PEM format';

{ TRSAAlgorithm }

constructor TRSAUsingSHAAlgorithm.Create(const AAlgorithmId: TJOSEAlgorithmId; AKeyMinLength: Integer);
begin
  FAlgorithmIdentifier := AAlgorithmId;

  case AAlgorithmId of
    TJOSEAlgorithmId.RS256: FRSAAlgorithm := TRSAAlgorithm.RS256;
    TJOSEAlgorithmId.RS384: FRSAAlgorithm := TRSAAlgorithm.RS384;
    TJOSEAlgorithmId.RS512: FRSAAlgorithm := TRSAAlgorithm.RS512;
    TJOSEAlgorithmId.PS256: FRSAAlgorithm := TRSAAlgorithm.PS256;
    TJOSEAlgorithmId.PS384: FRSAAlgorithm := TRSAAlgorithm.PS384;
    TJOSEAlgorithmId.PS512: FRSAAlgorithm := TRSAAlgorithm.PS512;
  else
    // Without this the field would keep its zero value (RS256) and the algorithm would sign with
    // PKCS#1 v1.5 while announcing something else in the header.
    raise EJOSEException.CreateFmt(SJOSEUnsupportedRSAAlgorithmId, [AAlgorithmId.AsString]);
  end;
  FKeyCategory := TJOSEKeyCategory.Asymmetric;
  FKeyType := 'pem';
  FKeyMinLength := AKeyMinLength;
end;

class function TRSAUsingSHAAlgorithm.RSA256: IJOSESigningAlgorithm;
begin
  Result := TRSAUsingSHAAlgorithm.Create(TJOSEAlgorithmId.RS256, 256);
end;

class function TRSAUsingSHAAlgorithm.RSA384: IJOSESigningAlgorithm;
begin
  Result := TRSAUsingSHAAlgorithm.Create(TJOSEAlgorithmId.RS384, 384);
end;

class function TRSAUsingSHAAlgorithm.RSA512: IJOSESigningAlgorithm;
begin
  Result := TRSAUsingSHAAlgorithm.Create(TJOSEAlgorithmId.RS512, 512);
end;

class function TRSAUsingSHAAlgorithm.PSS256: IJOSESigningAlgorithm;
begin
  Result := TRSAUsingSHAAlgorithm.Create(TJOSEAlgorithmId.PS256, 256);
end;

class function TRSAUsingSHAAlgorithm.PSS384: IJOSESigningAlgorithm;
begin
  Result := TRSAUsingSHAAlgorithm.Create(TJOSEAlgorithmId.PS384, 384);
end;

class function TRSAUsingSHAAlgorithm.PSS512: IJOSESigningAlgorithm;
begin
  Result := TRSAUsingSHAAlgorithm.Create(TJOSEAlgorithmId.PS512, 512);
end;

function TRSAUsingSHAAlgorithm.Sign(const AKey, AInput: TJOSEBytes): TJOSEBytes;
var
  LSign: TJOSEBytes;
begin
  LSign := TRSA.Sign(AInput, AKey, FRSAAlgorithm);
  Result := TBase64.URLEncode(LSign.AsBytes);
end;

procedure TRSAUsingSHAAlgorithm.ValidateSigningKey(const AKey: TJOSEBytes);
begin
  if AKey.IsEmpty then
    raise EJOSEException.Create(SJOSEKeyIsNull);

  if not TRSA.VerifyPrivateKey(AKey) then
    raise EJOSEException.Create(SJOSEKeyNotRSAPem);
end;

procedure TRSAUsingSHAAlgorithm.ValidateVerificationKey(const AKey: TJOSEBytes);
begin
  if AKey.IsEmpty then
    raise EJOSEException.Create(SJOSEKeyIsNull);

  if not TRSA.VerifyPublicKey(AKey) then
    raise EJOSEException.Create(SJOSEKeyNotRSAPem);
end;

function TRSAUsingSHAAlgorithm.VerifySignature(const AKey, AInput, ASignature: TJOSEBytes): Boolean;
var
  LDecodedSignature: TJOSEBytes;
begin
  // Key validation belongs to the caller (TJWS.VerifySignature), which owns the SkipKeyValidation
  // policy - as it already does for HMAC. Validating here as well ignored that flag and parsed the
  // PEM twice per verification.
  LDecodedSignature := TBase64.URLDecode(ASignature);
  Result := TRSA.Verify(AInput, LDecodedSignature, AKey, FRSAAlgorithm);
end;

{ TECDSAUsingSHAAlgorithm }

constructor TECDSAUsingSHAAlgorithm.Create(const AAlgorithmId: TJOSEAlgorithmId; AKeyMinLength: Integer);
begin
  FAlgorithmIdentifier := AAlgorithmId;

  case AAlgorithmId of
    TJOSEAlgorithmId.ES256: FECDSAAlgorithm := TECDSAAlgorithm.ES256;
    TJOSEAlgorithmId.ES256K: FECDSAAlgorithm := TECDSAAlgorithm.ES256K;
    TJOSEAlgorithmId.ES384: FECDSAAlgorithm := TECDSAAlgorithm.ES384;
    TJOSEAlgorithmId.ES512: FECDSAAlgorithm := TECDSAAlgorithm.ES512;
  end;
  FKeyCategory := TJOSEKeyCategory.Asymmetric;
  FKeyType := 'pem';
  FKeyMinLength := AKeyMinLength;
end;

class function TECDSAUsingSHAAlgorithm.ECDSA256: IJOSESigningAlgorithm;
begin
  Result := TECDSAUsingSHAAlgorithm.Create(TJOSEAlgorithmId.ES256, 256);
end;

class function TECDSAUsingSHAAlgorithm.ECDSA256K: IJOSESigningAlgorithm;
begin
  Result := TECDSAUsingSHAAlgorithm.Create(TJOSEAlgorithmId.ES256K, 256);
end;

class function TECDSAUsingSHAAlgorithm.ECDSA384: IJOSESigningAlgorithm;
begin
  Result := TECDSAUsingSHAAlgorithm.Create(TJOSEAlgorithmId.ES384, 384);
end;

class function TECDSAUsingSHAAlgorithm.ECDSA512: IJOSESigningAlgorithm;
begin
  Result := TECDSAUsingSHAAlgorithm.Create(TJOSEAlgorithmId.ES512, 512);
end;

function TECDSAUsingSHAAlgorithm.Sign(const AKey, AInput: TJOSEBytes): TJOSEBytes;
var
  LSign: TJOSEBytes;
begin
  LSign := TECDSA.Sign(AInput, AKey, FECDSAAlgorithm);
  Result := TBase64.URLEncode(LSign.AsBytes);
end;

procedure TECDSAUsingSHAAlgorithm.ValidateSigningKey(const AKey: TJOSEBytes);
begin
  if AKey.IsEmpty then
    raise EJOSEException.Create(SJOSEKeyIsNull);

  if not TECDSA.VerifyPrivateKey(AKey) then
    raise EJOSEException.Create(SJOSEKeyNotECDSAPem);
end;

procedure TECDSAUsingSHAAlgorithm.ValidateVerificationKey(const AKey: TJOSEBytes);
begin
  if AKey.IsEmpty then
    raise EJOSEException.Create(SJOSEKeyIsNull);

  if not TECDSA.VerifyPublicKey(AKey) then
    raise EJOSEException.Create(SJOSEKeyNotECDSAPem);
end;

function TECDSAUsingSHAAlgorithm.VerifySignature(const AKey, AInput, ASignature: TJOSEBytes): Boolean;
var
  LDecodedSignature: TJOSEBytes;
begin
  ValidateVerificationKey(AKey);
  LDecodedSignature := TBase64.URLDecode(ASignature);
  Result := TECDSA.Verify(AInput, LDecodedSignature, AKey, FECDSAAlgorithm);
end;

{$ENDIF}

end.
