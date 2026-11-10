{******************************************************************************}
{                                                                              }
{  Delphi JOSE-JWT Library                                                     }
{  Copyright (c) 2015 Paolo Rossi                                              }
{  https://github.com/paolo-rossi/delphi-jose-jwt                              }
{                                                                              }
{  Licensed under the MIT license                                              }
{                                                                              }
{******************************************************************************}

unit JOSE.Core.JWE;

{$I ..\JOSE.inc}

interface

uses
  System.SysUtils,
  JOSE.Types.Bytes,
  JOSE.Core.Base,
  JOSE.Core.Parts,
  JOSE.Core.JWA,
  JOSE.Core.JWK,
  JOSE.Core.JWT,
  JOSE.Core.JWE.Header,
  JOSE.Core.JWA.KeyManagement,
  JOSE.Core.JWA.Encryption,
  JOSE.Core.JWA.Compression;

type
  /// <summary>
  ///   JSON Web Encryption (JWE, RFC 7516), compact serialization, single
  ///   recipient
  /// </summary>
  /// <remarks>
  ///   <para>
  ///     The five parts are the protected header, the Encrypted Key, the IV,
  ///     the ciphertext and the authentication tag, each base64url-encoded.
  ///   </para>
  ///   <para>
  ///     The header lives in Header, a TJWEHeader owned by the TJWE, so it
  ///     works with any TJWT whatever its header class. On encryption it starts
  ///     from a copy of the token's header; once the token is built, the
  ///     token's header gets the final one (with "alg" and "enc").
  ///   </para>
  ///   <para>
  ///     The additional authenticated data is the protected header exactly as
  ///     it appears in the token (RFC 7516 par. 5.1 step 14), never a
  ///     re-encoding of the parsed header: TJSONObject does not promise the
  ///     same member order or spacing on a round trip.
  ///   </para>
  ///   <para>
  ///     Every failure of the decryption itself (wrong key, tampered part,
  ///     bad tag) raises EJOSEException with one generic message, so that the
  ///     error says nothing about which check failed. A fault inside a provider
  ///     (out of memory, an access violation, a programming error) is not a
  ///     property of the token and keeps its own exception.
  ///   </para>
  ///   <para>
  ///     Compression ("zip":"DEF"): a received token is decompressed after
  ///     decryption, up to MaxDecompressedSize bytes. A token is compressed
  ///     only when its header asks for it ("zip":"DEF" set on the TJWT
  ///     header before encrypting): compressing before encrypting can leak
  ///     plaintext through the ciphertext length when part of the content is
  ///     chosen by an attacker (RFC 8725 par. 3.6). Any other "zip" value is
  ///     rejected.
  ///   </para>
  /// </remarks>
  /// <seealso href="https://tools.ietf.org/html/rfc7516">
  ///   JWE RFC Document
  /// </seealso>
  TJWE = class(TJOSEParts)
  private
    const COMPACT_PARTS = 5;
  private
    class var FMaxDecompressedSize: Integer;
    class constructor Create;
  private
    FHeader: TJWEHeader;
    FPayload: TJOSEBytes;
    function GetPart(AIndex: Integer): TJOSEBytes;
    function GetKeyManagementAlgorithm(const AAlg: string): IJOSEKeyManagementAlgorithm;
    function GetEncryptionAlgorithm(const AEnc: string): IJOSEEncryptionAlgorithm;
    /// <summary>The "zip" algorithm the header names, nil when it names none</summary>
    function GetCompressionAlgorithm: IJOSECompressionAlgorithm;
    procedure CheckHeaderIsSupported;
  protected
    function GetCompactToken: TJOSEBytes; override;
    procedure SetCompactToken(const Value: TJOSEBytes); override;
  public
    /// <summary>
    ///   True when AValue has the shape of a JWE compact serialization: five
    ///   base64url parts and a protected header that is a JSON object. Says
    ///   nothing about whether it decrypts
    /// </summary>
    class function CheckCompactToken(const AValue: TJOSEBytes): Boolean; static;
  public
    constructor Create(AToken: TJWT); override;
    destructor Destroy; override;

    /// <summary>
    ///   Encrypts APayload, whatever it is, and returns the compact
    ///   serialization (also available as CompactToken)
    /// </summary>
    function EncryptPayload(AKey: TJWK; AAlg: TJOSEAlgorithmId; AEnc: TJOSEEncryptionAlgorithmId;
      const APayload: TJOSEBytes): TJOSEBytes;
    /// <summary>
    ///   Encrypts the token's claims and returns the compact serialization
    /// </summary>
    function Encrypt(AKey: TJWK; AAlg: TJOSEAlgorithmId; AEnc: TJOSEEncryptionAlgorithmId): TJOSEBytes;

    /// <summary>
    ///   Decrypts the token set through CompactToken and returns the
    ///   plaintext, whatever it is (also available as Payload). The token's
    ///   claims are left alone
    /// </summary>
    function DecryptPayload(AKey: TJWK): TJOSEBytes;
    /// <summary>
    ///   Decrypts the token set through CompactToken into the token's claims.
    ///   When the header says that the payload is a nested JWT ("cty":"JWT")
    ///   the claims are left empty: the payload is a JWS, read from Payload
    /// </summary>
    procedure Decrypt(AKey: TJWK);

    /// <summary>
    ///   The largest payload a compressed ("zip":"DEF") token may decompress
    ///   to, in bytes; a larger one is rejected. 250 000 by default. Process
    ///   wide: set it at startup, like the provider registration
    /// </summary>
    class property MaxDecompressedSize: Integer read FMaxDecompressedSize write FMaxDecompressedSize;

    /// <summary>The JWE header, protected header included</summary>
    property Header: TJWEHeader read FHeader;
    /// <summary>The plaintext of the last encryption or decryption</summary>
    property Payload: TJOSEBytes read FPayload;

    // The five parts, base64url-encoded, as they appear in the token
    property ProtectedHeader: TJOSEBytes index 0 read GetPart;
    property EncryptedKey: TJOSEBytes index 1 read GetPart;
    property IV: TJOSEBytes index 2 read GetPart;
    property Ciphertext: TJOSEBytes index 3 read GetPart;
    property AuthenticationTag: TJOSEBytes index 4 read GetPart;
  end;

implementation

uses
  JOSE.Types.JSON,
  JOSE.Encoding.Base64,
  JOSE.Providers,
  JOSE.Providers.Interfaces,
  JOSE.Core.JWA.Factory;

resourcestring
  SJOSEJWECompactEmpty = 'The JWE Compact Serialization is empty';
  SJOSEJWEPartCount = 'A JWE Compact Serialization must have %d parts';
  SJOSEJWENoProtectedHeader = 'The JWE has no protected header';
  SJOSEJWENotParsed = 'There is no JWE to decrypt: set CompactToken first';
  SJOSEJWEKeyRequired = 'A key is required';
  SJOSEJWEAlgNotKeyManagement = 'The "alg" value (%s) is not a JWE key management algorithm';
  SJOSEJWEAlgNotSupported = 'JWE key management algorithm (%s) is not supported';
  SJOSEJWEEncNotSupported = 'JWE content encryption algorithm (%s) is not supported';
  SJOSEJWECompressionNotSupported = 'JWE compression ("zip":"%s") is not supported: only "DEF" is';
  SJOSEJWECriticalNotSupported = 'The JWE header has a "crit" member: critical extensions are not supported';
  // Deliberately one message for every decryption failure: see the class remarks
  SJOSEJWEDecryptionFailed = 'JWE decryption failed';

function EncodePart(const AValue: TJOSEBytes): TJOSEBytes;
begin
  // Empty parts are legal ("dir" has an empty Encrypted Key), and are not
  // handed to the provider: the stacks need not agree on empty input
  if AValue.IsEmpty then
    Result := TJOSEBytes.Empty
  else
    Result := TBase64.URLEncode(AValue);
end;

function DecodePart(const AValue: TJOSEBytes): TJOSEBytes;
begin
  if AValue.IsEmpty then
    Result := TJOSEBytes.Empty
  else
    Result := TBase64.URLDecode(AValue);
end;

{ TJWE }

class function TJWE.CheckCompactToken(const AValue: TJOSEBytes): Boolean;
var
  LCompact: TJOSECompactSerialization;
  LHeader: TJOSEBytes;
begin
  if AValue.IsEmpty then
    Exit(False);

  LCompact := TJOSECompactSerialization.Split(AValue);
  if LCompact.Kind <> TJOSECompactKind.JWE then
    Exit(False);

  if not LCompact.PartsAreBase64URL then
    Exit(False);

  LHeader := TBase64.TryURLDecode(LCompact[0]);
  if LHeader.IsEmpty then
    Exit(False);

  Result := TJSONUtils.IsValidJSONObject(LHeader);
end;

constructor TJWE.Create(AToken: TJWT);
var
  LIndex: Integer;
begin
  inherited Create(AToken);
  FHeader := TJWEHeader.Create;

  for LIndex := 0 to COMPACT_PARTS - 1 do
    FParts.Add(TJOSEBytes.Empty);
end;

destructor TJWE.Destroy;
begin
  FHeader.Free;
  inherited;
end;

function TJWE.GetPart(AIndex: Integer): TJOSEBytes;
begin
  Result := FParts[AIndex];
end;

function TJWE.GetCompactToken: TJOSEBytes;
var
  LIndex: Integer;
begin
  Result := FParts[0];
  for LIndex := 1 to COMPACT_PARTS - 1 do
    Result := Result + PART_SEPARATOR + FParts[LIndex];
end;

procedure TJWE.SetCompactToken(const Value: TJOSEBytes);
var
  LCompact: TJOSECompactSerialization;
  LIndex: Integer;
begin
  if Value.IsEmpty then
    raise EJOSEException.Create(SJOSEJWECompactEmpty);

  LCompact := TJOSECompactSerialization.Split(Value);
  if LCompact.Kind <> TJOSECompactKind.JWE then
    raise EJOSEException.CreateFmt(SJOSEJWEPartCount, [COMPACT_PARTS]);

  // Checked at the boundary, like TJWS does: one clean error for a malformed
  // part, and only strict base64url reaches the decoder
  for LIndex := 0 to COMPACT_PARTS - 1 do
    if not TBase64.IsValidURLEncoded(LCompact[LIndex]) then
      raise EJOSEException.CreateFmt(SJOSECompactPartNotBase64URL, [LIndex + 1]);

  if LCompact[0] = '' then
    raise EJOSEException.Create(SJOSEJWENoProtectedHeader);

  // Parsed before anything is stored, so a bad header leaves the object as it was
  FHeader.URLEncoded := LCompact[0];
  FToken.Header.URLEncoded := LCompact[0];

  // Part 0 is kept verbatim: it is the additional authenticated data
  for LIndex := 0 to COMPACT_PARTS - 1 do
    FParts[LIndex] := LCompact[LIndex];

  // A parse starts a new token: the previous token's plaintext and claims must
  // not survive it. Parsing fills neither, and Decrypt leaves the claims empty
  // for a nested JWT, so without this a reused TJWE/TJWT would still report the
  // claims of the token decrypted before it
  FPayload := TJOSEBytes.Empty;
  FToken.Claims.Clear;
end;

function TJWE.GetKeyManagementAlgorithm(const AAlg: string): IJOSEKeyManagementAlgorithm;
var
  LAlgId: TJOSEAlgorithmId;
begin
  // A signing "alg" in a JWE is rejected by name, before the registry is
  // asked: the two namespaces must never cross
  LAlgId.AsString := AAlg;
  if LAlgId.IsSigning then
    raise EJOSEException.CreateFmt(SJOSEJWEAlgNotKeyManagement, [AAlg]);

  Result := TJOSEAlgorithmRegistryFactory.Instance.KeyManagementAlgorithmRegistry.GetAlgorithm(AAlg);
  if Result = nil then
    raise EJOSEException.CreateFmt(SJOSEJWEAlgNotSupported, [AAlg]);
end;

function TJWE.GetEncryptionAlgorithm(const AEnc: string): IJOSEEncryptionAlgorithm;
begin
  Result := TJOSEAlgorithmRegistryFactory.Instance.EncryptionAlgorithmRegistry.GetAlgorithm(AEnc);
  if Result = nil then
    raise EJOSEException.CreateFmt(SJOSEJWEEncNotSupported, [AEnc]);
end;

class constructor TJWE.Create;
begin
  // Nimbus JOSE+JWT's limit: generous for any real token
  FMaxDecompressedSize := 250000;
end;

function TJWE.GetCompressionAlgorithm: IJOSECompressionAlgorithm;
begin
  Result := nil;
  if not FHeader.HasCompression then
    Exit;

  // A "zip" that is not understood is rejected: ignoring it would hand back
  // the compressed bytes as the plaintext (or encrypt uncompressed bytes the
  // recipient will try to inflate). A non-string "zip" reads as '' here
  Result := TJOSEAlgorithmRegistryFactory.Instance.CompressionAlgorithmRegistry.GetAlgorithm(FHeader.Compression);
  if Result = nil then
    raise EJOSEException.CreateFmt(SJOSEJWECompressionNotSupported, [FHeader.Compression]);
end;

procedure TJWE.CheckHeaderIsSupported;
begin
  // Ignoring "crit" is what RFC 7516 par. 4.1.13 forbids
  if FHeader.HasCritical then
    raise EJOSEException.Create(SJOSEJWECriticalNotSupported);
end;

function TJWE.EncryptPayload(AKey: TJWK; AAlg: TJOSEAlgorithmId; AEnc: TJOSEEncryptionAlgorithmId;
  const APayload: TJOSEBytes): TJOSEBytes;
var
  LKeyManagement: IJOSEKeyManagementAlgorithm;
  LEncryption: IJOSEEncryptionAlgorithm;
  LCompression: IJOSECompressionAlgorithm;
  LKeys: TJOSEKeyManagementResult;
  LProtected, LPlaintext: TJOSEBytes;
  LParts: TEncryptionParts;
begin
  if not Assigned(AKey) then
    raise EJOSEException.Create(SJOSEJWEKeyRequired);

  LKeyManagement := GetKeyManagementAlgorithm(AAlg.AsString);
  LEncryption := GetEncryptionAlgorithm(AEnc.AsString);

  // The token's header (typ, kid, custom members, "zip" when the caller asked
  // for compression) plus "alg" and "enc"
  FHeader.Assign(FToken.Header);
  FHeader.Algorithm := AAlg.AsString;
  FHeader.EncryptionId := AEnc;
  CheckHeaderIsSupported;
  LCompression := GetCompressionAlgorithm;

  // Compressed only on request: see the class remarks
  if Assigned(LCompression) then
    LPlaintext := LCompression.Compress(APayload.AsBytes)
  else
    LPlaintext := APayload;

  // Before the header is serialized: some algorithms add header members
  LKeys := LKeyManagement.ManageForEncrypt(AKey.Key, LEncryption.GetCEKLength, FHeader);

  // Serialized once: this string is both part 0 and the AAD
  LProtected := FHeader.URLEncoded;
  LParts := LEncryption.Encrypt(LPlaintext.AsBytes, LProtected.AsBytes, LKeys.CEK);

  FParts[0] := LProtected;
  FParts[1] := EncodePart(LKeys.EncryptedKey);
  FParts[2] := EncodePart(LParts.IV);
  FParts[3] := EncodePart(LParts.Ciphertext);
  FParts[4] := EncodePart(LParts.AuthenticationTag);

  FToken.Header.Assign(FHeader);
  FPayload := APayload;

  Result := GetCompactToken;
end;

function TJWE.Encrypt(AKey: TJWK; AAlg: TJOSEAlgorithmId; AEnc: TJOSEEncryptionAlgorithmId): TJOSEBytes;
begin
  Result := EncryptPayload(AKey, AAlg, AEnc, TJOSEBytes(ToJSON(FToken.Claims.JSON)));
end;

function TJWE.DecryptPayload(AKey: TJWK): TJOSEBytes;
var
  LKeyManagement: IJOSEKeyManagementAlgorithm;
  LEncryption: IJOSEEncryptionAlgorithm;
  LCompression: IJOSECompressionAlgorithm;
  LEncryptedKey, LCEK: TJOSEBytes;
  LParts: TEncryptionParts;
begin
  // Payload describes the last decryption, not the last *successful* one: a
  // failed attempt must not leave the previous plaintext where a caller that
  // catches the exception could read it as this token's
  FPayload := TJOSEBytes.Empty;

  if FParts[0].IsEmpty then
    raise EJOSEException.Create(SJOSEJWENotParsed);
  if not Assigned(AKey) then
    raise EJOSEException.Create(SJOSEJWEKeyRequired);

  // Everything decided from the header comes first and fails with a precise
  // message: the header is public, so naming the problem gives nothing away
  LKeyManagement := GetKeyManagementAlgorithm(FHeader.Algorithm);
  LEncryption := GetEncryptionAlgorithm(FHeader.Encryption);
  CheckHeaderIsSupported;
  LCompression := GetCompressionAlgorithm;

  // SetCompactToken accepted only strict base64url, so these cannot fail
  LEncryptedKey := DecodePart(FParts[1]);
  LParts := TEncryptionParts.Create(DecodePart(FParts[2]).AsBytes, DecodePart(FParts[3]).AsBytes,
    DecodePart(FParts[4]).AsBytes);

  try
    LCEK := LKeyManagement.ManageForDecrypt(AKey.Key, LEncryptedKey, LEncryption.GetCEKLength, FHeader);
    // Part 0 as received, never FHeader re-encoded
    FPayload := LEncryption.Decrypt(LParts, FParts[0].AsBytes, LCEK.AsBytes);
  except
    // A missing provider is a configuration problem, not a property of the
    // token: it keeps its own message
    on E: EJOSEProvidersNotRegistered do
      raise;
    // The generic message is for the JOSE and provider-crypto errors that are
    // properties of the token (bad key, tampered part, bad tag). A fault (out
    // of memory, an access violation, a programming error) is not: masking it
    // as "wrong key or tampered token" would hide a real defect
    on E: EJOSECryptoException do
      raise EJOSEException.Create(SJOSEJWEDecryptionFailed);
    on E: EJOSEException do
      raise EJOSEException.Create(SJOSEJWEDecryptionFailed);
  end;

  // After the decryption, outside the generic error: the payload is
  // authentic by now, so a precise message (corrupt data, over the size cap)
  // tells the sender's mistake apart from an attack without helping one
  if Assigned(LCompression) then
    FPayload := LCompression.Decompress(FPayload.AsBytes, FMaxDecompressedSize);

  Result := FPayload;
end;

procedure TJWE.Decrypt(AKey: TJWK);
begin
  // The claims describe this attempt: a failed one must not leave the claims of
  // a previous successful decryption (even of the same token) where a caller
  // that caught the exception could still read them
  FToken.Claims.Clear;

  DecryptPayload(AKey);

  if not FHeader.IsNestedJWT then
    FToken.Claims.URLEncoded := TBase64.URLEncode(FPayload);
end;

end.
