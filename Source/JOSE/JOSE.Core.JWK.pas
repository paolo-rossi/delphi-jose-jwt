{******************************************************************************}
{                                                                              }
{  Delphi JOSE Library                                                        }
{  Copyright (c) 2015 Paolo Rossi                                             }
{  https://github.com/paolo-rossi/delphi-jose-jwt                             }
{                                                                              }
{******************************************************************************}
{                                                                              }
{  Licensed under the Apache License, Version 2.0 (the "License");            }
{  you may not use this file except in compliance with the License.           }
{  You may obtain a copy of the License at                                    }
{                                                                              }
{      http://www.apache.org/licenses/LICENSE-2.0                             }
{                                                                              }
{  Unless required by applicable law or agreed to in writing, software        }
{  distributed under the License is distributed on an "AS IS" BASIS,          }
{  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.   }
{  See the License for the specific language governing permissions and        }
{  limitations under the License.                                             }
{                                                                              }
{******************************************************************************}

/// <summary>
///   JSON Web Key (JWK) RFC implementation
/// </summary>
/// <seealso href="https://tools.ietf.org/html/rfc7517">
///   JWK RFC Document
/// </seealso>
unit JOSE.Core.JWK;

{$I ..\JOSE.inc}

interface

{$SCOPEDENUMS ON}

uses
  System.SysUtils,
  System.Rtti,
  System.JSON,
  System.Hash,
  System.Generics.Collections,
  JOSE.Types.Bytes,
  JOSE.Types.JSON,
  JOSE.Core.Base,
  JOSE.Core.JWA,
  JOSE.Encoding.Base64
  {$IFDEF RSA_SIGNING}
  , JOSE.Crypto.Algorithms, JOSE.Providers, JOSE.Providers.Interfaces
  {$ENDIF};

type
  TKeyType = (Symmetric, Asymmetric);

  /// <summary>
  ///   Base class for the Key in a JWS process
  /// </summary>
  TJWK = class(TJOSEBase)
  private
    FKey: TJOSEBytes;
  public
    constructor Create(AKey: TJOSEBytes); overload;
    property Key: TJOSEBytes read FKey write FKey;
  end;

  /// <summary>
  ///   KeyPair utility class (to move in a key management framework)
  /// </summary>
  TKeyPair = class
  private
    FPrivateKey: TJWK;
    FPublicKey: TJWK;
    FKeyType: TKeyType;
  public
    constructor Create; overload;
    constructor Create(const APublicKey, APrivateKey: TJOSEBytes); overload;
    destructor Destroy; override;

    function Clone: TKeyPair;

    procedure SetSymmetricKey(const ASecret: TJOSEBytes);
    procedure SetAsymmetricKeys(const APublicKey, APrivateKey: TJOSEBytes);

    property KeyType: TKeyType read FKeyType write FKeyType;
    property PrivateKey: TJWK read FPrivateKey write FPrivateKey;
    property PublicKey: TJWK read FPublicKey write FPublicKey;
  end;

  EJOSEJWKException = class(EJOSEException);

  /// <seealso href="https://tools.ietf.org/html/rfc7517#section-4.1">kty</seealso>
  TJOSEKeyType = (Oct, RSA, EC);
  TJOSEKeyTypeHelper = record helper for TJOSEKeyType
  private
    function GetAsString: string;
    procedure SetAsString(const AValue: string);
  public
    property AsString: string read GetAsString write SetAsString;
  end;

  /// <seealso href="https://tools.ietf.org/html/rfc7517#section-4.2">use</seealso>
  TJOSEKeyUse = (Unspecified, Signature, Encryption);
  TJOSEKeyUseHelper = record helper for TJOSEKeyUse
  private
    function GetAsString: string;
    procedure SetAsString(const AValue: string);
  public
    property AsString: string read GetAsString write SetAsString;
  end;

  /// <seealso href="https://tools.ietf.org/html/rfc7517#section-4.3">key_ops</seealso>
  TJOSEKeyOperation = (Sign, Verify, Encrypt, Decrypt, WrapKey, UnwrapKey, DeriveKey, DeriveBits);
  TJOSEKeyOperations = set of TJOSEKeyOperation;

  /// <seealso href="https://tools.ietf.org/html/rfc7518#section-6.2.1.1">crv</seealso>
  TJOSEEllipticCurve = (P256, P384, P521, secp256k1);
  TJOSEEllipticCurveHelper = record helper for TJOSEEllipticCurve
  private
    function GetAsString: string;
    procedure SetAsString(const AValue: string);
  public
    property AsString: string read GetAsString write SetAsString;
    {$IFDEF RSA_SIGNING}
    /// <summary>Maps to the Common-layer curve identifier used at the provider boundary.</summary>
    function ToECCurve: TECCurve;
    class function FromECCurve(ACurve: TECCurve): TJOSEEllipticCurve; static;
    {$ENDIF}
  end;

  /// <summary>
  ///   Full RFC 7517 JSON Web Key implementation: oct (symmetric), RSA and EC key types,
  ///   with (on RSA_SIGNING platforms) PEM import/export and a bridge to the legacy
  ///   <c>TKeyPair</c> consumed internally by <c>TJWS</c>/<c>TJOSE</c>/<c>TJOSEProducer</c>.
  /// </summary>
  TJSONWebKey = class(TJOSEBase)
  private
    function GetStringMember(const AName: string): string;
    procedure SetStringMember(const AName, AValue: string);
    function GetBytesMember(const AName: string): TJOSEBytes;
    procedure SetBytesMember(const AName: string; const AValue: TJOSEBytes);
    function GetStringArrayMember(const AName: string): TArray<string>;
    procedure SetStringArrayMember(const AName: string; const AValue: TArray<string>);

    function GetKty: TJOSEKeyType;
    procedure SetKty(const AValue: TJOSEKeyType);
    function GetUse: TJOSEKeyUse;
    procedure SetUse(const AValue: TJOSEKeyUse);
    function GetKeyOps: TJOSEKeyOperations;
    procedure SetKeyOps(const AValue: TJOSEKeyOperations);
    function GetAlg: TJOSEAlgorithmId;
    procedure SetAlg(const AValue: TJOSEAlgorithmId);
    function GetKid: string;
    procedure SetKid(const AValue: string);
    function GetX5u: string;
    procedure SetX5u(const AValue: string);
    function GetX5c: TArray<string>;
    procedure SetX5c(const AValue: TArray<string>);
    function GetX5t: string;
    procedure SetX5t(const AValue: string);
    function GetX5tS256: string;
    procedure SetX5tS256(const AValue: string);

    function GetK: TJOSEBytes;
    procedure SetK(const AValue: TJOSEBytes);

    function GetN: TJOSEBytes;
    procedure SetN(const AValue: TJOSEBytes);
    function GetE: TJOSEBytes;
    procedure SetE(const AValue: TJOSEBytes);
    function GetD: TJOSEBytes;
    procedure SetD(const AValue: TJOSEBytes);
    function GetP: TJOSEBytes;
    procedure SetP(const AValue: TJOSEBytes);
    function GetQ: TJOSEBytes;
    procedure SetQ(const AValue: TJOSEBytes);
    function GetDP: TJOSEBytes;
    procedure SetDP(const AValue: TJOSEBytes);
    function GetDQ: TJOSEBytes;
    procedure SetDQ(const AValue: TJOSEBytes);
    function GetQI: TJOSEBytes;
    procedure SetQI(const AValue: TJOSEBytes);

    function GetCrv: TJOSEEllipticCurve;
    procedure SetCrv(const AValue: TJOSEEllipticCurve);
    function GetX: TJOSEBytes;
    procedure SetX(const AValue: TJOSEBytes);
    function GetY: TJOSEBytes;
    procedure SetY(const AValue: TJOSEBytes);

    function BuildCanonicalJSON: string;
    procedure CheckMember(const AValue: TJOSEBytes; const AName: string);
    procedure CopyPublicMetadataTo(ATarget: TJSONWebKey);
  public
    constructor CreateOct(const ASecret: TJOSEBytes);
    constructor CreateRSAPublic(const AModulus, AExponent: TJOSEBytes);
    constructor CreateRSAPrivate(const AModulus, AExponent, APrivateExponent, AP, AQ, ADP, ADQ, AQI: TJOSEBytes);
    constructor CreateECPublic(ACurve: TJOSEEllipticCurve; const AX, AY: TJOSEBytes);
    constructor CreateECPrivate(ACurve: TJOSEEllipticCurve; const AX, AY, AD: TJOSEBytes);

    class function FromJSON(const AJSON: string): TJSONWebKey;
    function ToJSON: string;

    /// <summary>True if the type-appropriate private component(s) are present.</summary>
    function IsPrivate: Boolean;

    /// <summary>
    ///   Checks that the members RFC 7517/7518 require for this key's [kty] are present, raising
    ///   <c>EJOSEJWKException</c> naming the first one that is not.
    /// </summary>
    /// <remarks>
    ///   Deliberately not called from <c>FromJSON</c>: JWKS documents in the wild carry keys this
    ///   library has no use for, and refusing to parse a whole set over one of them would be
    ///   worse than letting the caller decide. <c>ToPEM</c> does call it, since it needs a
    ///   complete key anyway and the provider's own complaint arrives with far less context.
    /// </remarks>
    procedure Validate;
    /// <summary><c>Validate</c> as a test rather than an exception.</summary>
    function IsValid: Boolean;

    /// <summary>
    ///   A new key holding only this one's public half - the members that are safe to publish in
    ///   a JWKS. Raises for <c>oct</c>, which has no public half.
    /// </summary>
    /// <remarks>
    ///   Members are copied by allowlist, never by removing the private ones from a clone: an
    ///   unrecognised member is dropped rather than published, so a future addition to the type
    ///   cannot leak by omission. The cost is that unknown extension members do not survive.
    ///   <c>kid</c>, <c>use</c>, <c>alg</c>, <c>key_ops</c> and the <c>x5*</c> members do; note
    ///   that <c>key_ops</c> is carried verbatim, so a value such as <c>sign</c> follows the key
    ///   onto its public twin and may want adjusting.
    /// </remarks>
    function ToPublicJWK: TJSONWebKey;
    /// <seealso href="https://tools.ietf.org/html/rfc7638">RFC 7638 JWK Thumbprint</seealso>
    function Thumbprint: TJOSEBytes;

    {$IFDEF RSA_SIGNING}
    /// <summary>Loads an RSA or EC key (public or private, PKCS1/PKCS8/SPKI/traditional-EC) from PEM.</summary>
    class function FromPEM(const APEM: TJOSEBytes): TJSONWebKey;
    /// <summary>Rebuilds a PEM (RSA or EC) from this key's components.</summary>
    /// <remarks>
    ///   The encoding depends on the registered provider. The OpenSSL-backed stacks write an RSA
    ///   public key as PKCS#1 (<c>RSA PUBLIC KEY</c>) and an EC private key as PKCS#8
    ///   (<c>PRIVATE KEY</c>); CryptoLib writes them as SPKI (<c>PUBLIC KEY</c>) and SEC1
    ///   (<c>EC PRIVATE KEY</c>) respectively. Only the container differs, and <c>FromPEM</c>
    ///   reads every one of these forms on every stack - but do not depend on a particular
    ///   header when handing the result to something outside this library.
    /// </remarks>
    function ToPEM(AIncludePrivate: Boolean = True): TJOSEBytes;

    /// <summary>Bridges to the legacy raw-bytes key model consumed by TJWS/TJOSE/TJOSEProducer.</summary>
    /// <remarks>For a public-only RSA/EC key the returned pair has an empty <c>PrivateKey</c>: it
    ///   can verify, but signing with it raises.</remarks>
    function ToKeyPair: TKeyPair;
    class function FromKeyPair(AKeyPair: TKeyPair; AKty: TJOSEKeyType): TJSONWebKey;
    {$ENDIF}

    property Kty: TJOSEKeyType read GetKty write SetKty;
    property Use: TJOSEKeyUse read GetUse write SetUse;
    property KeyOps: TJOSEKeyOperations read GetKeyOps write SetKeyOps;
    property Alg: TJOSEAlgorithmId read GetAlg write SetAlg;
    property Kid: string read GetKid write SetKid;
    property X5u: string read GetX5u write SetX5u;
    property X5c: TArray<string> read GetX5c write SetX5c;
    property X5t: string read GetX5t write SetX5t;
    property X5tS256: string read GetX5tS256 write SetX5tS256;

    /// <summary>Symmetric key value (oct).</summary>
    property K: TJOSEBytes read GetK write SetK;

    /// <summary>RSA modulus / public exponent.</summary>
    property N: TJOSEBytes read GetN write SetN;
    property E: TJOSEBytes read GetE write SetE;
    /// <summary>RSA private exponent, or EC private key (the JWK "d" member is shared by both).</summary>
    property D: TJOSEBytes read GetD write SetD;
    property P: TJOSEBytes read GetP write SetP;
    property Q: TJOSEBytes read GetQ write SetQ;
    property DP: TJOSEBytes read GetDP write SetDP;
    property DQ: TJOSEBytes read GetDQ write SetDQ;
    property QI: TJOSEBytes read GetQI write SetQI;

    /// <summary>EC curve / public point.</summary>
    property Crv: TJOSEEllipticCurve read GetCrv write SetCrv;
    property X: TJOSEBytes read GetX write SetX;
    property Y: TJOSEBytes read GetY write SetY;
  end;

  /// <seealso href="https://tools.ietf.org/html/rfc7517#section-5">JWK Set</seealso>
  TJSONWebKeySet = class(TJOSEBase)
  private
    FKeys: TObjectList<TJSONWebKey>;
    /// <summary>
    ///   Rebuilds the underlying JSON document from <c>Keys</c>.
    /// </summary>
    /// <remarks>
    ///   Called from every read path rather than from the mutators: <c>Keys</c>
    ///   is a mutable list of mutable keys, so a caller can edit a key, or
    ///   remove one, long after it was added. Nothing about the document can
    ///   safely be cached across that.
    /// </remarks>
    procedure SyncJSON;
    function GetSyncedJSON: TJSONObject;
    function GetSyncedEncoded: TJOSEBytes;
    function GetSyncedURLEncoded: TJOSEBytes;
  public
    constructor Create;
    destructor Destroy; override;

    /// <summary>Appends AKey, taking ownership of it.</summary>
    procedure AddKey(AKey: TJSONWebKey);

    /// <summary>
    ///   The key with this [kid], or nil. An empty AKid never matches,
    ///   including against keys that carry no [kid] of their own.
    /// </summary>
    function FindByKid(const AKid: string): TJSONWebKey;

    class function FromJSON(const AJSON: string): TJSONWebKeySet;
    function ToJSON: string;

    /// <summary>
    ///   A new set holding the public half of every RSA and EC key in this one - the JWKS you can
    ///   publish. <c>oct</c> keys are skipped, not rejected.
    /// </summary>
    /// <remarks>
    ///   Skipping rather than raising is what makes this usable on a mixed set: a symmetric
    ///   secret has no public half and must never be published, but its presence is no reason to
    ///   refuse to publish the asymmetric keys alongside it. See <c>TJSONWebKey.ToPublicJWK</c>
    ///   for what each key carries across.
    /// </remarks>
    function ToPublicJWKSet: TJSONWebKeySet;

    /// <summary>The keys in the set, owned by it. Freely mutable - the JSON output follows.</summary>
    property Keys: TObjectList<TJSONWebKey> read FKeys;

    // Read-only, synchronising overrides of the TJOSEBase members. The inherited setters are
    // deliberately not carried over: assigning a document straight to a key set would leave it
    // disagreeing with Keys, which is the source of truth here.
    property JSON: TJSONObject read GetSyncedJSON;
    property Encoded: TJOSEBytes read GetSyncedEncoded;
    property URLEncoded: TJOSEBytes read GetSyncedURLEncoded;
  end;

implementation

resourcestring
  SJOSEJWKUnknownKeyType = '[JWK] Unknown key type [kty]: %s';
  SJOSEJWKUnknownCurve = '[JWK] Unknown elliptic curve [crv]: %s';
  SJOSEJWKUnsupportedCurve = '[JWK] Unsupported EC curve';
  SJOSEJWKMissingKty = '[JWK] Missing required JWK member [kty]';
  SJOSEJWKMissingMember = '[JWK] Missing required member [%s] for a key of type [%s]';
  SJOSEJWKIncompleteRSACRT = '[JWK] An RSA private key must carry either all of [p, q, dp, dq, qi] or none of them';
  SJOSEJWKNoPublicHalf = '[JWK] Only RSA and EC keys have a public half - an [oct] key is entirely secret';
  SJOSEJWKMissingCrv = '[JWK] Missing required JWK member [crv]';
  SJOSEJWKInvalidJSON = '[JWK] Invalid JSON';
  SJOSEJWKThumbprintUnsupportedKeyType = '[JWK] Unable to compute the thumbprint for this key type';
  SJOSEJWKThumbprintMissingMember = '[JWK] Unable to compute the thumbprint: missing required member [%s]';
  SJOSEJWKToPEMUnsupportedKeyType = '[JWK] ToPEM is only supported for RSA and EC keys';
  SJOSEJWKFromPEMUnrecognized = '[JWK] The PEM data was read neither as an RSA key (%s) nor as an EC key (%s)';
  SJOSEJWKToKeyPairUnsupportedKeyType = '[JWK] Unsupported key type for ToKeyPair';
  SJOSEJWKFromKeyPairUnsupportedKeyType = '[JWK] Unsupported key type for FromKeyPair';
  SJOSEJWKSInvalidJSON = '[JWK] Invalid JWKS JSON';
  SJOSEJWKSInvalidKeyElement = '[JWK] The [keys] array contains a value that is not a JWK object';
  SJOSEJWKSMissingKeys = '[JWK] Missing or malformed required JWKS member [keys]';
  SJOSEJWKSNilKey = '[JWK] Cannot add a nil key to the key set';

{ TJWK }

constructor TJWK.Create(AKey: TJOSEBytes);
begin
  inherited Create;
  FKey := AKey;
end;

{ TKeyPair }

constructor TKeyPair.Create;
begin
  FPrivateKey := TJWK.Create();
  FPublicKey := TJWK.Create();
end;

function TKeyPair.Clone: TKeyPair;
begin
  Result := TKeyPair.Create(FPublicKey.Key, FPrivateKey.Key);
end;

constructor TKeyPair.Create(const APublicKey, APrivateKey: TJOSEBytes);
begin
  if APublicKey = APrivateKey then
    FKeyType := TKeyType.Symmetric
  else
    FKeyType := TKeyType.Asymmetric;

  FPublicKey := TJWK.Create(APublicKey);
  FPrivateKey := TJWK.Create(APrivateKey);
end;

destructor TKeyPair.Destroy;
begin
  FPublicKey.Free;
  FPrivateKey.Free;
  inherited;
end;

procedure TKeyPair.SetAsymmetricKeys(const APublicKey, APrivateKey: TJOSEBytes);
begin
  FKeyType := TKeyType.Asymmetric;
  FPublicKey.Key := APublicKey;
  FPrivateKey.Key := APrivateKey;
end;

procedure TKeyPair.SetSymmetricKey(const ASecret: TJOSEBytes);
begin
  FKeyType := TKeyType.Symmetric;
  FPublicKey.Key := ASecret;
  FPrivateKey.Key := ASecret;
end;

{ TJOSEKeyTypeHelper }

function TJOSEKeyTypeHelper.GetAsString: string;
begin
  case Self of
    TJOSEKeyType.Oct: Result := 'oct';
    TJOSEKeyType.RSA: Result := 'RSA';
    TJOSEKeyType.EC:  Result := 'EC';
  else
    Result := '';
  end;
end;

procedure TJOSEKeyTypeHelper.SetAsString(const AValue: string);
begin
  if AValue = 'oct' then
    Self := TJOSEKeyType.Oct
  else if AValue = 'RSA' then
    Self := TJOSEKeyType.RSA
  else if AValue = 'EC' then
    Self := TJOSEKeyType.EC
  else
    raise EJOSEJWKException.CreateFmt(SJOSEJWKUnknownKeyType, [AValue]);
end;

{ TJOSEKeyUseHelper }

function TJOSEKeyUseHelper.GetAsString: string;
begin
  case Self of
    TJOSEKeyUse.Signature:  Result := 'sig';
    TJOSEKeyUse.Encryption: Result := 'enc';
  else
    Result := '';
  end;
end;

procedure TJOSEKeyUseHelper.SetAsString(const AValue: string);
begin
  if AValue = 'sig' then
    Self := TJOSEKeyUse.Signature
  else if AValue = 'enc' then
    Self := TJOSEKeyUse.Encryption
  else
    Self := TJOSEKeyUse.Unspecified;
end;

{ TJOSEEllipticCurveHelper }

function TJOSEEllipticCurveHelper.GetAsString: string;
begin
  case Self of
    TJOSEEllipticCurve.P256:      Result := 'P-256';
    TJOSEEllipticCurve.P384:      Result := 'P-384';
    TJOSEEllipticCurve.P521:      Result := 'P-521';
    TJOSEEllipticCurve.secp256k1: Result := 'secp256k1';
  else
    Result := '';
  end;
end;

procedure TJOSEEllipticCurveHelper.SetAsString(const AValue: string);
begin
  if AValue = 'P-256' then
    Self := TJOSEEllipticCurve.P256
  else if AValue = 'P-384' then
    Self := TJOSEEllipticCurve.P384
  else if AValue = 'P-521' then
    Self := TJOSEEllipticCurve.P521
  else if AValue = 'secp256k1' then
    Self := TJOSEEllipticCurve.secp256k1
  else
    raise EJOSEJWKException.CreateFmt(SJOSEJWKUnknownCurve, [AValue]);
end;

{$IFDEF RSA_SIGNING}
function TJOSEEllipticCurveHelper.ToECCurve: TECCurve;
begin
  case Self of
    TJOSEEllipticCurve.P256:      Result := TECCurve.P256;
    TJOSEEllipticCurve.P384:      Result := TECCurve.P384;
    TJOSEEllipticCurve.P521:      Result := TECCurve.P521;
    TJOSEEllipticCurve.secp256k1: Result := TECCurve.secp256k1;
  else
    raise EJOSEJWKException.Create(SJOSEJWKUnsupportedCurve);
  end;
end;

class function TJOSEEllipticCurveHelper.FromECCurve(ACurve: TECCurve): TJOSEEllipticCurve;
begin
  case ACurve of
    TECCurve.P256:      Result := TJOSEEllipticCurve.P256;
    TECCurve.P384:      Result := TJOSEEllipticCurve.P384;
    TECCurve.P521:      Result := TJOSEEllipticCurve.P521;
    TECCurve.secp256k1: Result := TJOSEEllipticCurve.secp256k1;
  else
    raise EJOSEJWKException.Create(SJOSEJWKUnsupportedCurve);
  end;
end;
{$ENDIF}

const
  KeyOpNames: array[TJOSEKeyOperation] of string = (
    'sign', 'verify', 'encrypt', 'decrypt', 'wrapKey', 'unwrapKey', 'deriveKey', 'deriveBits'
  );

/// <summary>
///   Parses AJSON and returns it as a JSON object, raising AError if it is not one.
/// </summary>
/// <remarks>
///   ParseJSONValue returns whatever the document happens to be, so a well-formed non-object
///   ("[]", "123", a bare string) has to be freed here: a hard cast to TJSONObject would raise
///   EInvalidCast - the wrong exception class for a malformed JWK - and leak the parsed value.
///   Malformed JSON comes back as nil, which fails the same type test.
/// </remarks>
function ParseJSONObject(const AJSON, AError: string): TJSONObject;
var
  LParsed: TJSONValue;
begin
  LParsed := TJSONObject.ParseJSONValue(AJSON);
  if not (LParsed is TJSONObject) then
  begin
    LParsed.Free;
    raise EJOSEJWKException.Create(AError);
  end;
  Result := TJSONObject(LParsed);
end;

/// <summary>
///   Base64url-encodes a member that RFC 7638 3.2 requires in the thumbprint's canonical JSON,
///   naming it in the error when it is absent.
/// </summary>
/// <remarks>
///   An absent component would otherwise encode as "" and still produce a perfectly stable
///   thumbprint - one that collides with every other incomplete key of the same type.
/// </remarks>
function RequiredThumbprintMember(const AValue: TJOSEBytes; const AName: string): string;
begin
  if AValue.IsEmpty then
    raise EJOSEJWKException.CreateFmt(SJOSEJWKThumbprintMissingMember, [AName]);
  Result := TBase64.URLEncode(AValue).AsString;
end;

{ TJSONWebKey }

function TJSONWebKey.GetStringMember(const AName: string): string;
var
  LValue: TValue;
begin
  LValue := TJSONUtils.GetJSONValue(AName, FJSON);
  if LValue.IsEmpty then
    Result := ''
  else
    Result := LValue.AsString;
end;

procedure TJSONWebKey.SetStringMember(const AName, AValue: string);
begin
  if AValue = '' then
    TJSONUtils.RemoveJSONNode(AName, FJSON)
  else
    AddPairOfType<string>(AName, AValue);
end;

function TJSONWebKey.GetBytesMember(const AName: string): TJOSEBytes;
var
  LStr: string;
begin
  LStr := GetStringMember(AName);
  if LStr = '' then
    Result := TJOSEBytes.Empty
  else
    Result := TBase64.URLDecode(LStr);
end;

procedure TJSONWebKey.SetBytesMember(const AName: string; const AValue: TJOSEBytes);
begin
  if AValue.IsEmpty then
    TJSONUtils.RemoveJSONNode(AName, FJSON)
  else
    SetStringMember(AName, TBase64.URLEncode(AValue).AsString);
end;

function TJSONWebKey.GetStringArrayMember(const AName: string): TArray<string>;
var
  LValue: TJSONValue;
  LArray: TJSONArray;
  I: Integer;
begin
  Result := nil;
  LValue := FJSON.GetValue(AName);
  if Assigned(LValue) and (LValue is TJSONArray) then
  begin
    LArray := LValue as TJSONArray;
    SetLength(Result, LArray.Count);
    for I := 0 to LArray.Count - 1 do
      Result[I] := LArray.Items[I].Value;
  end;
end;

procedure TJSONWebKey.SetStringArrayMember(const AName: string; const AValue: TArray<string>);
var
  LArray: TJSONArray;
  LItem: string;
begin
  TJSONUtils.RemoveJSONNode(AName, FJSON);
  if Length(AValue) = 0 then
    Exit;

  LArray := TJSONArray.Create;
  for LItem in AValue do
    LArray.Add(LItem);
  TJSONUtils.SetJSONValue(AName, LArray, FJSON);
end;

function TJSONWebKey.GetKty: TJOSEKeyType;
var
  LStr: string;
begin
  LStr := GetStringMember('kty');
  if LStr = '' then
    raise EJOSEJWKException.Create(SJOSEJWKMissingKty);
  Result.AsString := LStr;
end;

procedure TJSONWebKey.SetKty(const AValue: TJOSEKeyType);
begin
  SetStringMember('kty', AValue.AsString);
end;

function TJSONWebKey.GetUse: TJOSEKeyUse;
begin
  Result.AsString := GetStringMember('use');
end;

procedure TJSONWebKey.SetUse(const AValue: TJOSEKeyUse);
begin
  if AValue = TJOSEKeyUse.Unspecified then
    TJSONUtils.RemoveJSONNode('use', FJSON)
  else
    SetStringMember('use', AValue.AsString);
end;

function TJSONWebKey.GetKeyOps: TJOSEKeyOperations;
var
  LNames: TArray<string>;
  LName: string;
  LOp: TJOSEKeyOperation;
begin
  Result := [];
  LNames := GetStringArrayMember('key_ops');
  for LName in LNames do
    for LOp := Low(TJOSEKeyOperation) to High(TJOSEKeyOperation) do
      if KeyOpNames[LOp] = LName then
        Include(Result, LOp);
end;

procedure TJSONWebKey.SetKeyOps(const AValue: TJOSEKeyOperations);
var
  LNames: TArray<string>;
  LOp: TJOSEKeyOperation;
  LCount: Integer;
begin
  LCount := 0;
  SetLength(LNames, 0);
  for LOp := Low(TJOSEKeyOperation) to High(TJOSEKeyOperation) do
    if LOp in AValue then
    begin
      SetLength(LNames, LCount + 1);
      LNames[LCount] := KeyOpNames[LOp];
      Inc(LCount);
    end;
  SetStringArrayMember('key_ops', LNames);
end;

function TJSONWebKey.GetAlg: TJOSEAlgorithmId;
begin
  Result.AsString := GetStringMember('alg');
end;

procedure TJSONWebKey.SetAlg(const AValue: TJOSEAlgorithmId);
begin
  if AValue = TJOSEAlgorithmId.Unknown then
    TJSONUtils.RemoveJSONNode('alg', FJSON)
  else
    SetStringMember('alg', AValue.AsString);
end;

function TJSONWebKey.GetKid: string;
begin
  Result := GetStringMember('kid');
end;

procedure TJSONWebKey.SetKid(const AValue: string);
begin
  SetStringMember('kid', AValue);
end;

function TJSONWebKey.GetX5u: string;
begin
  Result := GetStringMember('x5u');
end;

procedure TJSONWebKey.SetX5u(const AValue: string);
begin
  SetStringMember('x5u', AValue);
end;

function TJSONWebKey.GetX5c: TArray<string>;
begin
  Result := GetStringArrayMember('x5c');
end;

procedure TJSONWebKey.SetX5c(const AValue: TArray<string>);
begin
  SetStringArrayMember('x5c', AValue);
end;

function TJSONWebKey.GetX5t: string;
begin
  Result := GetStringMember('x5t');
end;

procedure TJSONWebKey.SetX5t(const AValue: string);
begin
  SetStringMember('x5t', AValue);
end;

function TJSONWebKey.GetX5tS256: string;
begin
  Result := GetStringMember('x5t#S256');
end;

procedure TJSONWebKey.SetX5tS256(const AValue: string);
begin
  SetStringMember('x5t#S256', AValue);
end;

function TJSONWebKey.GetK: TJOSEBytes;
begin
  Result := GetBytesMember('k');
end;

procedure TJSONWebKey.SetK(const AValue: TJOSEBytes);
begin
  SetBytesMember('k', AValue);
end;

function TJSONWebKey.GetN: TJOSEBytes;
begin
  Result := GetBytesMember('n');
end;

procedure TJSONWebKey.SetN(const AValue: TJOSEBytes);
begin
  SetBytesMember('n', AValue);
end;

function TJSONWebKey.GetE: TJOSEBytes;
begin
  Result := GetBytesMember('e');
end;

procedure TJSONWebKey.SetE(const AValue: TJOSEBytes);
begin
  SetBytesMember('e', AValue);
end;

function TJSONWebKey.GetD: TJOSEBytes;
begin
  Result := GetBytesMember('d');
end;

procedure TJSONWebKey.SetD(const AValue: TJOSEBytes);
begin
  SetBytesMember('d', AValue);
end;

function TJSONWebKey.GetP: TJOSEBytes;
begin
  Result := GetBytesMember('p');
end;

procedure TJSONWebKey.SetP(const AValue: TJOSEBytes);
begin
  SetBytesMember('p', AValue);
end;

function TJSONWebKey.GetQ: TJOSEBytes;
begin
  Result := GetBytesMember('q');
end;

procedure TJSONWebKey.SetQ(const AValue: TJOSEBytes);
begin
  SetBytesMember('q', AValue);
end;

function TJSONWebKey.GetDP: TJOSEBytes;
begin
  Result := GetBytesMember('dp');
end;

procedure TJSONWebKey.SetDP(const AValue: TJOSEBytes);
begin
  SetBytesMember('dp', AValue);
end;

function TJSONWebKey.GetDQ: TJOSEBytes;
begin
  Result := GetBytesMember('dq');
end;

procedure TJSONWebKey.SetDQ(const AValue: TJOSEBytes);
begin
  SetBytesMember('dq', AValue);
end;

function TJSONWebKey.GetQI: TJOSEBytes;
begin
  Result := GetBytesMember('qi');
end;

procedure TJSONWebKey.SetQI(const AValue: TJOSEBytes);
begin
  SetBytesMember('qi', AValue);
end;

function TJSONWebKey.GetCrv: TJOSEEllipticCurve;
var
  LStr: string;
begin
  LStr := GetStringMember('crv');
  if LStr = '' then
    raise EJOSEJWKException.Create(SJOSEJWKMissingCrv);
  Result.AsString := LStr;
end;

procedure TJSONWebKey.SetCrv(const AValue: TJOSEEllipticCurve);
begin
  SetStringMember('crv', AValue.AsString);
end;

function TJSONWebKey.GetX: TJOSEBytes;
begin
  Result := GetBytesMember('x');
end;

procedure TJSONWebKey.SetX(const AValue: TJOSEBytes);
begin
  SetBytesMember('x', AValue);
end;

function TJSONWebKey.GetY: TJOSEBytes;
begin
  Result := GetBytesMember('y');
end;

procedure TJSONWebKey.SetY(const AValue: TJOSEBytes);
begin
  SetBytesMember('y', AValue);
end;

constructor TJSONWebKey.CreateOct(const ASecret: TJOSEBytes);
begin
  inherited Create;
  Kty := TJOSEKeyType.Oct;
  K := ASecret;
end;

constructor TJSONWebKey.CreateRSAPublic(const AModulus, AExponent: TJOSEBytes);
begin
  inherited Create;
  Kty := TJOSEKeyType.RSA;
  N := AModulus;
  E := AExponent;
end;

constructor TJSONWebKey.CreateRSAPrivate(const AModulus, AExponent, APrivateExponent, AP, AQ, ADP, ADQ,
  AQI: TJOSEBytes);
begin
  CreateRSAPublic(AModulus, AExponent);
  D := APrivateExponent;
  P := AP;
  Q := AQ;
  DP := ADP;
  DQ := ADQ;
  QI := AQI;
end;

constructor TJSONWebKey.CreateECPublic(ACurve: TJOSEEllipticCurve; const AX, AY: TJOSEBytes);
begin
  inherited Create;
  Kty := TJOSEKeyType.EC;
  Crv := ACurve;
  X := AX;
  Y := AY;
end;

constructor TJSONWebKey.CreateECPrivate(ACurve: TJOSEEllipticCurve; const AX, AY, AD: TJOSEBytes);
begin
  CreateECPublic(ACurve, AX, AY);
  D := AD;
end;

class function TJSONWebKey.FromJSON(const AJSON: string): TJSONWebKey;
begin
  Result := TJSONWebKey.Create;
  try
    Result.SetNewJSON(ParseJSONObject(AJSON, SJOSEJWKInvalidJSON));
    Result.Kty; // Validates that [kty] is present and recognized
  except
    Result.Free;
    raise;
  end;
end;

function TJSONWebKey.ToJSON: string;
begin
  Result := JOSE.Core.Base.ToJSON(FJSON);
end;

function TJSONWebKey.IsPrivate: Boolean;
begin
  case Kty of
    TJOSEKeyType.Oct: Result := not K.IsEmpty;
    TJOSEKeyType.RSA: Result := not D.IsEmpty;
    TJOSEKeyType.EC:  Result := not D.IsEmpty;
  else
    Result := False;
  end;
end;

procedure TJSONWebKey.CheckMember(const AValue: TJOSEBytes; const AName: string);
begin
  if AValue.IsEmpty then
    raise EJOSEJWKException.CreateFmt(SJOSEJWKMissingMember, [AName, Kty.AsString]);
end;

procedure TJSONWebKey.Validate;
var
  LPresentCRT: Integer;
begin
  // Reading Kty validates that [kty] itself is present and recognized.
  case Kty of
    TJOSEKeyType.Oct:
      CheckMember(K, 'k');

    TJOSEKeyType.RSA:
    begin
      CheckMember(N, 'n');
      CheckMember(E, 'e');

      if IsPrivate then
      begin
        // RFC 7518 6.3.2: the CRT parameters are optional as a group, but a producer that
        // includes any of them has to include all of them.
        LPresentCRT := 0;
        if not P.IsEmpty then
          Inc(LPresentCRT);
        if not Q.IsEmpty then
          Inc(LPresentCRT);
        if not DP.IsEmpty then
          Inc(LPresentCRT);
        if not DQ.IsEmpty then
          Inc(LPresentCRT);
        if not QI.IsEmpty then
          Inc(LPresentCRT);

        if not (LPresentCRT in [0, 5]) then
          raise EJOSEJWKException.Create(SJOSEJWKIncompleteRSACRT);
      end;
    end;

    TJOSEKeyType.EC:
    begin
      // Reading Crv raises SJOSEJWKMissingCrv when [crv] is absent, and rejects a curve this
      // library does not know, so the check below can never actually be the one that fires.
      CheckMember(Crv.AsString, 'crv');
      CheckMember(X, 'x');
      CheckMember(Y, 'y');
    end;
  end;
end;

function TJSONWebKey.IsValid: Boolean;
begin
  try
    Validate;
    Result := True;
  except
    on EJOSEJWKException do
      Result := False;
  end;
end;

procedure TJSONWebKey.CopyPublicMetadataTo(ATarget: TJSONWebKey);
begin
  // Every setter here removes its member when handed an empty value, so metadata this key does
  // not carry is simply not written to the target.
  ATarget.Kid := Kid;
  ATarget.Use := Use;
  ATarget.Alg := Alg;
  ATarget.KeyOps := KeyOps;
  ATarget.X5u := X5u;
  ATarget.X5c := X5c;
  ATarget.X5t := X5t;
  ATarget.X5tS256 := X5tS256;
end;

function TJSONWebKey.ToPublicJWK: TJSONWebKey;
begin
  // Refuses to build a public twin out of an incomplete key, rather than publishing a broken one.
  Validate;

  case Kty of
    TJOSEKeyType.RSA:
      Result := TJSONWebKey.CreateRSAPublic(N, E);
    TJOSEKeyType.EC:
      Result := TJSONWebKey.CreateECPublic(Crv, X, Y);
  else
    // [k] is the key itself, so an oct key is secret all the way down: there is nothing here to
    // hand out, and silently returning a copy would be the worst possible answer.
    raise EJOSEJWKException.Create(SJOSEJWKNoPublicHalf);
  end;

  try
    CopyPublicMetadataTo(Result);
  except
    Result.Free;
    raise;
  end;
end;

function TJSONWebKey.BuildCanonicalJSON: string;
begin
  case Kty of
    TJOSEKeyType.Oct:
      Result := Format('{"k":"%s","kty":"oct"}', [RequiredThumbprintMember(K, 'k')]);
    TJOSEKeyType.RSA:
      Result := Format('{"e":"%s","kty":"RSA","n":"%s"}',
        [RequiredThumbprintMember(E, 'e'), RequiredThumbprintMember(N, 'n')]);
    TJOSEKeyType.EC:
      // Crv itself raises SJOSEJWKMissingCrv when [crv] is absent.
      Result := Format('{"crv":"%s","kty":"EC","x":"%s","y":"%s"}',
        [Crv.AsString, RequiredThumbprintMember(X, 'x'), RequiredThumbprintMember(Y, 'y')]);
  else
    raise EJOSEJWKException.Create(SJOSEJWKThumbprintUnsupportedKeyType);
  end;
end;

function TJSONWebKey.Thumbprint: TJOSEBytes;
var
  LHasher: THashSHA2;
begin
  LHasher := THashSHA2.Create(THashSHA2.TSHA2Version.SHA256);
  LHasher.Update(TEncoding.UTF8.GetBytes(BuildCanonicalJSON));
  Result := TBase64.URLEncode(LHasher.HashAsBytes);
end;

{$IFDEF RSA_SIGNING}

class function TJSONWebKey.FromPEM(const APEM: TJOSEBytes): TJSONWebKey;
var
  LData: TBytes;
  LRSAKeys: IJOSERSAKeyMaterialProvider;
  LECKeys: IJOSEECKeyMaterialProvider;
  LRSAMaterial: TJOSERSAKeyMaterial;
  LECMaterial: TJOSEECKeyMaterial;
  LIsRSA: Boolean;
  LRSAError: string;
begin
  LData := APEM.AsBytes;

  // Resolved outside the handler below on purpose. The property getter raises when the slot is
  // empty, and a missing provider registration is a configuration error - it must not be read as
  // "this PEM is not RSA" and quietly retried as EC.
  LRSAKeys := TJOSEProviders.RSAKeyMaterial;

  LIsRSA := True;
  try
    LRSAMaterial := LRSAKeys.ImportPEM(LData);
  except
    on E: Exception do
    begin
      // Any read failure here means "not an RSA key, or not in a format this provider reads".
      // The message is kept so it can still be reported if the EC attempt fails as well.
      LIsRSA := False;
      LRSAError := E.Message;
    end;
  end;

  if LIsRSA then
  begin
    Result := TJSONWebKey.Create;
    try
      Result.Kty := TJOSEKeyType.RSA;
      Result.N := LRSAMaterial.Modulus;
      Result.E := LRSAMaterial.PublicExponent;
      if LRSAMaterial.IsPrivate then
      begin
        Result.D := LRSAMaterial.PrivateExponent;
        Result.P := LRSAMaterial.P;
        Result.Q := LRSAMaterial.Q;
        Result.DP := LRSAMaterial.DP;
        Result.DQ := LRSAMaterial.DQ;
        Result.QI := LRSAMaterial.QI;
      end;
    except
      Result.Free;
      raise;
    end;
    Exit;
  end;

  // Also outside the handler: without an EC reader there is no way to tell whether this is an EC
  // key, so the registration error is the accurate thing to report.
  LECKeys := TJOSEProviders.ECKeyMaterial;

  try
    LECMaterial := LECKeys.ImportPEM(LData);
  except
    on E: Exception do
      // Neither reader recognised the data. Both messages go into the error: whichever attempt
      // happened to run second is not necessarily the one that explains the input.
      raise EJOSEJWKException.CreateFmt(SJOSEJWKFromPEMUnrecognized, [LRSAError, E.Message]);
  end;

  Result := TJSONWebKey.Create;
  try
    Result.Kty := TJOSEKeyType.EC;
    Result.Crv := TJOSEEllipticCurve.FromECCurve(LECMaterial.Curve);
    Result.X := LECMaterial.X;
    Result.Y := LECMaterial.Y;
    if LECMaterial.IsPrivate then
      Result.D := LECMaterial.D;
  except
    Result.Free;
    raise;
  end;
end;

function TJSONWebKey.ToPEM(AIncludePrivate: Boolean): TJOSEBytes;
var
  LRSAMaterial: TJOSERSAKeyMaterial;
  LECMaterial: TJOSEECKeyMaterial;
  LWritePrivate: Boolean;
begin
  // Up front, so a key missing a component is named here rather than reported by the provider as
  // a bare "missing key component" from somewhere inside its PEM writer.
  Validate;

  LWritePrivate := AIncludePrivate and IsPrivate;

  case Kty of
    TJOSEKeyType.RSA:
    begin
      LRSAMaterial.Modulus := N.AsBytes;
      LRSAMaterial.PublicExponent := E.AsBytes;
      if LWritePrivate then
      begin
        LRSAMaterial.PrivateExponent := D.AsBytes;
        LRSAMaterial.P := P.AsBytes;
        LRSAMaterial.Q := Q.AsBytes;
        LRSAMaterial.DP := DP.AsBytes;
        LRSAMaterial.DQ := DQ.AsBytes;
        LRSAMaterial.QI := QI.AsBytes;
      end;
      Result := TJOSEProviders.RSAKeyMaterial.ExportPEM(LRSAMaterial, LWritePrivate);
    end;

    TJOSEKeyType.EC:
    begin
      LECMaterial.Curve := Crv.ToECCurve;
      LECMaterial.X := X.AsBytes;
      LECMaterial.Y := Y.AsBytes;
      if LWritePrivate then
        LECMaterial.D := D.AsBytes;
      Result := TJOSEProviders.ECKeyMaterial.ExportPEM(LECMaterial, LWritePrivate);
    end;
  else
    raise EJOSEJWKException.Create(SJOSEJWKToPEMUnsupportedKeyType);
  end;
end;

function TJSONWebKey.ToKeyPair: TKeyPair;
begin
  case Kty of
    TJOSEKeyType.Oct:
      Result := TKeyPair.Create(K, K);
    TJOSEKeyType.RSA, TJOSEKeyType.EC:
    begin
      Result := TKeyPair.Create;
      try
        // SetAsymmetricKeys rather than the two-argument constructor: that one infers the key type
        // by comparing the halves, so a public-only key - which would otherwise have to carry the
        // same PEM twice - comes back labelled Symmetric.
        if IsPrivate then
          Result.SetAsymmetricKeys(ToPEM(False), ToPEM(True))
        else
          // Left empty on purpose. Repeating the public PEM here would claim a private key this
          // JWK does not have; empty makes PrivateKey.Key.IsEmpty a reliable "cannot sign" test
          // and makes TJWS raise its plain "Key is null" instead of a PEM-parsing error.
          Result.SetAsymmetricKeys(ToPEM(False), TJOSEBytes.Empty);
      except
        Result.Free;
        raise;
      end;
    end;
  else
    raise EJOSEJWKException.Create(SJOSEJWKToKeyPairUnsupportedKeyType);
  end;
end;

class function TJSONWebKey.FromKeyPair(AKeyPair: TKeyPair; AKty: TJOSEKeyType): TJSONWebKey;
begin
  case AKty of
    TJOSEKeyType.Oct:
      Result := TJSONWebKey.CreateOct(AKeyPair.PrivateKey.Key);
    TJOSEKeyType.RSA, TJOSEKeyType.EC:
      Result := TJSONWebKey.FromPEM(AKeyPair.PrivateKey.Key);
  else
    raise EJOSEJWKException.Create(SJOSEJWKFromKeyPairUnsupportedKeyType);
  end;
end;

{$ENDIF}

{ TJSONWebKeySet }

constructor TJSONWebKeySet.Create;
begin
  inherited Create;
  FKeys := TObjectList<TJSONWebKey>.Create(True);
end;

destructor TJSONWebKeySet.Destroy;
begin
  FKeys.Free;
  inherited;
end;

procedure TJSONWebKeySet.AddKey(AKey: TJSONWebKey);
begin
  // Rejected here rather than at the next read, where a nil entry would fault inside SyncJSON
  // with nothing left to point at the call that put it there.
  if not Assigned(AKey) then
    raise EJOSEJWKException.Create(SJOSEJWKSNilKey);
  FKeys.Add(AKey);
end;

function TJSONWebKeySet.FindByKid(const AKid: string): TJSONWebKey;
var
  LKey: TJSONWebKey;
begin
  Result := nil;

  // A key carrying no [kid] reports '', so an empty search term would match the first
  // unidentified key in the set - handing an arbitrary key to a caller that asked for a named
  // one. The usual source of an empty term is a JWS header with no [kid] at all, which is
  // precisely when picking a key by identity must fail rather than guess. Callers that want the
  // lone key of a single-key set should read Keys directly.
  if AKid = '' then
    Exit;

  for LKey in FKeys do
    if LKey.Kid = AKid then
      Exit(LKey);
end;

procedure TJSONWebKeySet.SyncJSON;
var
  LArray: TJSONArray;
  LKey: TJSONWebKey;
begin
  Clear;
  LArray := TJSONArray.Create;
  for LKey in FKeys do
    LArray.AddElement(LKey.Clone);
  TJSONUtils.SetJSONValue('keys', LArray, FJSON);
end;

function TJSONWebKeySet.GetSyncedJSON: TJSONObject;
begin
  SyncJSON;
  Result := FJSON;
end;

function TJSONWebKeySet.GetSyncedEncoded: TJOSEBytes;
begin
  Result := TBase64.Encode(ToJSON);
end;

function TJSONWebKeySet.GetSyncedURLEncoded: TJOSEBytes;
begin
  Result := TBase64.URLEncode(ToJSON);
end;

class function TJSONWebKeySet.FromJSON(const AJSON: string): TJSONWebKeySet;
var
  LParsed: TJSONObject;
  LKeysValue: TJSONValue;
  LKeysArray: TJSONArray;
  LItem: TJSONValue;
  I: Integer;
  LKey: TJSONWebKey;
begin
  Result := TJSONWebKeySet.Create;
  try
    LParsed := ParseJSONObject(AJSON, SJOSEJWKSInvalidJSON);
    try
      // RFC 7517 5 makes [keys] required, so an absent or non-array member is a malformed
      // document, not a set that happens to be empty - the two read very differently when what
      // you are looking at is an errored JWKS endpoint response. An empty array is legal and
      // does yield an empty set. (nil is TJSONArray is False, covering the absent case too.)
      LKeysValue := LParsed.GetValue('keys');
      if not (LKeysValue is TJSONArray) then
        raise EJOSEJWKException.Create(SJOSEJWKSMissingKeys);

      LKeysArray := TJSONArray(LKeysValue);
      for I := 0 to LKeysArray.Count - 1 do
      begin
        // Checked before cloning: a hard cast on a non-object element would raise EInvalidCast
        // and leak the clone.
        LItem := LKeysArray.Items[I];
        if not (LItem is TJSONObject) then
          raise EJOSEJWKException.Create(SJOSEJWKSInvalidKeyElement);

        // The key only belongs to the set once it is added, so anything that fails while it is
        // being filled in has to free it here.
        LKey := TJSONWebKey.Create;
        try
          LKey.SetNewJSON(LItem.Clone as TJSONObject);
          LKey.Kty; // Validates that [kty] is present and recognized
        except
          LKey.Free;
          raise;
        end;
        Result.FKeys.Add(LKey);
      end;
    finally
      LParsed.Free;
    end;
  except
    Result.Free;
    raise;
  end;
end;

function TJSONWebKeySet.ToJSON: string;
begin
  SyncJSON;
  Result := JOSE.Core.Base.ToJSON(FJSON);
end;

function TJSONWebKeySet.ToPublicJWKSet: TJSONWebKeySet;
var
  LKey: TJSONWebKey;
begin
  Result := TJSONWebKeySet.Create;
  try
    for LKey in FKeys do
      if LKey.Kty <> TJOSEKeyType.Oct then
        Result.AddKey(LKey.ToPublicJWK);
  except
    Result.Free;
    raise;
  end;
end;

end.
