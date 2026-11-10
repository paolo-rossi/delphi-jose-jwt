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
///   JWE tests. Step 1, phase 0: identifiers, registries, the JWE header and
///   the byte helpers JWE relies on. Nothing is encrypted yet
/// </summary>
unit JOSE.Tests.JWE;

interface

uses
  System.SysUtils,
  System.IOUtils,
  System.Rtti,
  DUnitX.TestFramework,

  JOSE.Tests.Classes,
  JOSE.Types.Bytes,
  JOSE.Core.JWA,
  JOSE.Core.JWA.Factory,
  JOSE.Core.JWT,
  JOSE.Core.JWS,
  JOSE.Core.JWK,
  JOSE.Core.JWE,
  JOSE.Core.JWE.Header,
  JOSE.Core.Base,
  JOSE.Core.Builder,
  JOSE.Context,
  JOSE.Consumer,
  JOSE.Encoding.Base64,
  JOSE.Providers;

type
  [TestFixture]
  TTestJWEIdentifiers = class
  public
    [Test]
    [TestCase('dir',          'dir')]
    [TestCase('RSA-OAEP',     'RSA-OAEP')]
    [TestCase('RSA-OAEP-256', 'RSA-OAEP-256')]
    procedure KeyManagementAlgRoundTrips(const AValue: string);

    [Test]
    procedure EveryAlgorithmIdRoundTrips;

    [Test]
    procedure SigningAndKeyManagementDoNotOverlap;

    [Test]
    [TestCase('Dir',          'Dir')]
    [TestCase('DIR',          'DIR')]
    [TestCase('rsa-oaep',     'rsa-oaep')]
    [TestCase('RSA_OAEP_256', 'RSA_OAEP_256')]
    procedure KeyManagementAlgIsCaseSensitive(const AValue: string);

    [Test]
    [TestCase('A128GCM', 'A128GCM,16')]
    [TestCase('A192GCM', 'A192GCM,24')]
    [TestCase('A256GCM', 'A256GCM,32')]
    procedure EncRoundTripsWithCEKLength(const AValue: string; ACEKLength: Integer);

    [Test]
    [TestCase('Lowercase', 'a256gcm')]
    [TestCase('CBC (not yet)', 'A256CBC-HS512')]
    [TestCase('Empty', '')]
    procedure UnsupportedEncIsUnknown(const AValue: string);

    [Test]
    procedure UnknownIdsHaveNoString;
  end;

  [TestFixture]
  TTestJWARegistries = class
  public
    [Test]
    procedure RegistriesAreNamedAfterTheirHeaderMember;

    [Test]
    [TestCase('dir',          'dir')]
    [TestCase('RSA-OAEP',     'RSA-OAEP')]
    [TestCase('RSA-OAEP-256', 'RSA-OAEP-256')]
    procedure SigningRegistryDoesNotResolveKeyManagement(const AValue: string);

    [Test]
    [TestCase('none',  'none')]
    [TestCase('HS256', 'HS256')]
    [TestCase('RS256', 'RS256')]
    procedure KeyManagementRegistryDoesNotResolveSigning(const AValue: string);
  end;

  [TestFixture]
  TTestJWEHeader = class
  public
    [Test]
    procedure EncryptionRoundTrips;

    [Test]
    [TestCase('JWT',                 'JWT,True')]
    [TestCase('jwt',                 'jwt,True')]
    [TestCase('application/jwt',     'application/jwt,True')]
    [TestCase('Application/JWT',     'Application/JWT,True')]
    [TestCase('Empty',               ',False')]
    [TestCase('JOSE',                'JOSE,False')]
    [TestCase('application/json',    'application/json,False')]
    [TestCase('Prefix only',         'application/,False')]
    [TestCase('JWT with suffix',     'JWTX,False')]
    procedure IsNestedJWT(const AContentType: string; AExpected: Boolean);

    [Test]
    procedure CompressionAndCriticalAreAbsentByDefault;

    [Test]
    procedure CompressionIsDetectedWhateverItsType;

    [Test]
    procedure CriticalIsDetected;
  end;

  [TestFixture]
  TTestJOSEBytesForJWE = class
  public
    [Test]
    procedure SliceMiddle;

    [Test]
    procedure SliceWholeAndEmpty;

    [Test]
    [TestCase('Negative start',  '-1,1')]
    [TestCase('Negative length', '0,-1')]
    [TestCase('Past the end',    '3,2')]
    [TestCase('Start past end',  '5,0')]
    procedure SliceOutOfRangeRaises(AStart, ALength: Integer);

    [Test]
    procedure ConcatenationWithEmptyOperands;

    [Test]
    procedure MergeBytesWithEmptyOperands;

    [Test]
    procedure PartsClearKeepsTheSlots;
  end;

  /// <summary>
  ///   TJWE parsing, and every check that comes before any cryptography. The
  ///   default stack has no AES-GCM provider yet, so the cryptography itself
  ///   is tested per stack in JOSE.Tests.Providers.JWE
  /// </summary>
  [TestFixture]
  TTestJWEParsing = class(TTestBase)
  public
    [Test]
    procedure RegistriesResolveTheStep1Algorithms;

    [Test]
    procedure ParsesTheHeaderAndKeepsThePartsVerbatim;

    [Test]
    [TestCase('JWE',              'RFC,True')]
    [TestCase('JWS',              'a.b.c,False')]
    [TestCase('Four parts',       'a.b.c.d,False')]
    [TestCase('Six parts',        'a.b.c.d.e.f,False')]
    [TestCase('Empty',            ',False')]
    [TestCase('Minimal JWE',      'e30..AA.AA.AA,True')]
    [TestCase('Header not JSON',  'YWJj..AA.AA.AA,False')]
    [TestCase('Not base64url',    'e30..AA.AA.AA!,False')]
    procedure CheckCompactToken(const AToken: string; AExpected: Boolean);

    // Every other part is valid base64url, so each case fails for the
    // reason in its name
    [Test]
    [TestCase('Three parts',      'e30.AA.AA')]
    [TestCase('Six parts',        'e30..AA.AA.AA.AA')]
    [TestCase('Not base64url',    'e30..AA.AA.AA!')]
    [TestCase('No header',        '..AA.AA.AA')]
    [TestCase('Header not JSON',  'YWJj..AA.AA.AA')]
    [TestCase('Header array',     'W10..AA.AA.AA')]
    procedure SetCompactTokenRejectsMalformed(const AToken: string);

    [Test]
    [TestCase('Signing alg',      '{"alg":"HS256","enc":"A128GCM"}|not a JWE key management', '|')]
    [TestCase('none',             '{"alg":"none","enc":"A128GCM"}|not a JWE key management', '|')]
    [TestCase('Unknown alg',      '{"alg":"XYZ","enc":"A128GCM"}|not supported', '|')]
    [TestCase('No alg',           '{"enc":"A128GCM"}|not supported', '|')]
    [TestCase('Unknown enc',      '{"alg":"dir","enc":"A256CBC-HS512"}|not supported', '|')]
    [TestCase('No enc',           '{"alg":"dir"}|not supported', '|')]
    [TestCase('zip',              '{"alg":"dir","enc":"A128GCM","zip":"DEF"}|"zip"', '|')]
    [TestCase('crit',             '{"alg":"dir","enc":"A128GCM","crit":["exp"],"exp":1}|"crit"', '|')]
    procedure DecryptRejectsHeaderBeforeCrypto(const AHeader, AExpectedMessage: string);

    [Test]
    procedure EncryptRejectsSigningAlgorithm;

    [Test]
    procedure MissingProviderIsReportedAsSuch;

    [Test]
    procedure MissingRSAEncryptionProviderIsReportedAsSuch;
  end;

  /// <summary>
  ///   JWE in TJOSEContext, TJOSEConsumer and TJOSE: everything decided before
  ///   any cryptography. The end-to-end cases run per provider stack
  /// </summary>
  [TestFixture]
  TTestJWEWiring = class
  public
    [Test]
    procedure ContextParsesAJWEWithoutDecrypting;

    [Test]
    procedure ContextRejectsFourParts;

    [Test]
    procedure DefaultConsumerRejectsEveryJWE;

    [Test]
    procedure ConsumerRejectsUnexpectedEnc;

    [Test]
    procedure ConsumerRejectsSigningAlgEvenIfListed;

    [Test]
    procedure ConsumerWithAllowlistsGoesOnToDecrypt;

    [Test]
    procedure RequireEncryptionAcceptsAJWEShape;

    [Test]
    procedure VerificationAndDecryptionKeysAreSeparate;

    [Test]
    procedure TJOSEDecryptRejectsAJWS;

    [Test]
    procedure TJOSEDecryptRequiresAKey;

    [Test]
    procedure TJOSEDecryptAndVerifyRejectsAJWS;

    [Test]
    procedure TJOSEVerifyStillRejectsAJWE;
  end;

implementation

{ TTestJWEIdentifiers }

procedure TTestJWEIdentifiers.KeyManagementAlgRoundTrips(const AValue: string);
var
  LId: TJOSEAlgorithmId;
begin
  LId.AsString := AValue;

  Assert.IsTrue(LId.IsKeyManagement, AValue + ' is not a key management algorithm');
  Assert.IsFalse(LId.IsSigning, AValue + ' must not be a signing algorithm');
  Assert.AreEqual(AValue, LId.AsString);
  Assert.AreEqual(0, LId.Length, 'Key management algorithms have no hash length');
end;

procedure TTestJWEIdentifiers.EveryAlgorithmIdRoundTrips;
var
  LId, LBack: TJOSEAlgorithmId;
begin
  // Catches a member added to the enum but forgotten in GetAsString or
  // SetAsString
  for LId := Succ(Low(TJOSEAlgorithmId)) to High(TJOSEAlgorithmId) do
  begin
    Assert.IsNotEmpty(LId.AsString, Format('Ordinal %d has no string', [Ord(LId)]));
    LBack.AsString := LId.AsString;
    Assert.AreEqual(Ord(LId), Ord(LBack), LId.AsString + ' does not round-trip');
  end;
end;

procedure TTestJWEIdentifiers.SigningAndKeyManagementDoNotOverlap;
var
  LId: TJOSEAlgorithmId;
begin
  Assert.IsFalse(TJOSEAlgorithmId.Unknown.IsSigning);
  Assert.IsFalse(TJOSEAlgorithmId.Unknown.IsKeyManagement);

  // Every known member belongs to exactly one namespace
  for LId := Succ(Low(TJOSEAlgorithmId)) to High(TJOSEAlgorithmId) do
    Assert.IsTrue(LId.IsSigning xor LId.IsKeyManagement,
      LId.AsString + ' must be either signing or key management');
end;

procedure TTestJWEIdentifiers.KeyManagementAlgIsCaseSensitive(const AValue: string);
var
  LId: TJOSEAlgorithmId;
begin
  LId.AsString := AValue;
  Assert.AreEqual(Ord(TJOSEAlgorithmId.Unknown), Ord(LId));
end;

procedure TTestJWEIdentifiers.EncRoundTripsWithCEKLength(const AValue: string; ACEKLength: Integer);
var
  LId: TJOSEEncryptionAlgorithmId;
begin
  LId.AsString := AValue;

  Assert.AreNotEqual(Ord(TJOSEEncryptionAlgorithmId.Unknown), Ord(LId));
  Assert.AreEqual(AValue, LId.AsString);
  Assert.AreEqual(ACEKLength, LId.CEKLength);
end;

procedure TTestJWEIdentifiers.UnsupportedEncIsUnknown(const AValue: string);
var
  LId: TJOSEEncryptionAlgorithmId;
begin
  LId.AsString := AValue;

  Assert.AreEqual(Ord(TJOSEEncryptionAlgorithmId.Unknown), Ord(LId));
  Assert.AreEqual(0, LId.CEKLength);
end;

procedure TTestJWEIdentifiers.UnknownIdsHaveNoString;
begin
  Assert.AreEqual('', TJOSEAlgorithmId.Unknown.AsString);
  Assert.AreEqual('', TJOSEEncryptionAlgorithmId.Unknown.AsString);
end;

{ TTestJWARegistries }

procedure TTestJWARegistries.RegistriesAreNamedAfterTheirHeaderMember;
var
  LFactory: TJOSEAlgorithmRegistryFactory;
begin
  LFactory := TJOSEAlgorithmRegistryFactory.Instance;

  Assert.AreEqual('alg', LFactory.SigningAlgorithmRegistry.Name);
  Assert.AreEqual('alg', LFactory.KeyManagementAlgorithmRegistry.Name);
  Assert.AreEqual('enc', LFactory.EncryptionAlgorithmRegistry.Name);
  Assert.AreEqual('zip', LFactory.CompressionAlgorithmRegistry.Name);
end;

procedure TTestJWARegistries.SigningRegistryDoesNotResolveKeyManagement(const AValue: string);
begin
  // A JWS whose header says "alg":"dir" must find no signing algorithm
  Assert.IsNull(TJOSEAlgorithmRegistryFactory.Instance.SigningAlgorithmRegistry.GetAlgorithm(AValue));
end;

procedure TTestJWARegistries.KeyManagementRegistryDoesNotResolveSigning(const AValue: string);
begin
  // And a JWE whose header names a signing algorithm must find nothing either
  Assert.IsNull(TJOSEAlgorithmRegistryFactory.Instance.KeyManagementAlgorithmRegistry.GetAlgorithm(AValue));
end;

{ TTestJWEHeader }

procedure TTestJWEHeader.EncryptionRoundTrips;
var
  LHeader: TJWEHeader;
begin
  LHeader := TJWEHeader.Create;
  try
    Assert.AreEqual(Ord(TJOSEEncryptionAlgorithmId.Unknown), Ord(LHeader.EncryptionId));

    LHeader.EncryptionId := TJOSEEncryptionAlgorithmId.A256GCM;
    Assert.AreEqual('A256GCM', LHeader.Encryption);
    Assert.AreEqual(Ord(TJOSEEncryptionAlgorithmId.A256GCM), Ord(LHeader.EncryptionId));

    LHeader.Encryption := 'A512XYZ';
    Assert.AreEqual(Ord(TJOSEEncryptionAlgorithmId.Unknown), Ord(LHeader.EncryptionId));
    Assert.AreEqual('A512XYZ', LHeader.Encryption);
  finally
    LHeader.Free;
  end;
end;

procedure TTestJWEHeader.IsNestedJWT(const AContentType: string; AExpected: Boolean);
var
  LHeader: TJWEHeader;
begin
  LHeader := TJWEHeader.Create;
  try
    if AContentType <> '' then
      LHeader.ContentType := AContentType;

    Assert.AreEqual(AExpected, LHeader.IsNestedJWT);
  finally
    LHeader.Free;
  end;
end;

procedure TTestJWEHeader.CompressionAndCriticalAreAbsentByDefault;
var
  LHeader: TJWEHeader;
begin
  LHeader := TJWEHeader.Create;
  try
    Assert.IsFalse(LHeader.HasCompression);
    Assert.IsFalse(LHeader.HasCritical);
  finally
    LHeader.Free;
  end;
end;

procedure TTestJWEHeader.CompressionIsDetectedWhateverItsType;
var
  LHeader: TJWEHeader;
begin
  LHeader := TJWEHeader.Create;
  try
    // Not a string: still has to count as present, so that it is rejected
    LHeader.SetHeaderParam(THeaderNames.COMPRESSION, TValue.From<Integer>(1));
    Assert.IsTrue(LHeader.HasCompression);
  finally
    LHeader.Free;
  end;
end;

procedure TTestJWEHeader.CriticalIsDetected;
var
  LHeader: TJWEHeader;
begin
  LHeader := TJWEHeader.Create;
  try
    LHeader.SetHeaderParam(THeaderNames.CRITICAL, TValue.From<string>('exp'));
    Assert.IsTrue(LHeader.HasCritical);
  finally
    LHeader.Free;
  end;
end;

{ TTestJOSEBytesForJWE }

procedure TTestJOSEBytesForJWE.SliceMiddle;
var
  LBytes: TJOSEBytes;
begin
  LBytes := TBytes.Create(1, 2, 3, 4, 5);

  Assert.IsTrue(LBytes.Slice(1, 3) = TBytes.Create(2, 3, 4));
  Assert.IsTrue(LBytes.Slice(3, 2) = TBytes.Create(4, 5));
end;

procedure TTestJOSEBytesForJWE.SliceWholeAndEmpty;
var
  LBytes: TJOSEBytes;
begin
  LBytes := TBytes.Create(1, 2, 3, 4, 5);

  Assert.IsTrue(LBytes.Slice(0, 5) = LBytes);
  Assert.IsTrue(LBytes.Slice(5, 0).IsEmpty, 'A zero-length slice at the end is legal');
  Assert.IsTrue(TJOSEBytes.Empty.Slice(0, 0).IsEmpty);
end;

procedure TTestJOSEBytesForJWE.SliceOutOfRangeRaises(AStart, ALength: Integer);
var
  LBytes: TJOSEBytes;
begin
  LBytes := TBytes.Create(1, 2, 3, 4);

  Assert.WillRaise(
    procedure
    begin
      LBytes.Slice(AStart, ALength);
    end,
    ERangeError);
end;

procedure TTestJOSEBytesForJWE.ConcatenationWithEmptyOperands;
var
  LBytes: TJOSEBytes;
begin
  LBytes := TBytes.Create(1, 2);

  Assert.IsTrue((TJOSEBytes.Empty + TJOSEBytes.Empty).IsEmpty);
  Assert.IsTrue(TJOSEBytes.Empty + LBytes = LBytes);
  Assert.IsTrue(LBytes + TJOSEBytes.Empty = LBytes);
  Assert.IsTrue(LBytes + TBytes(nil) = LBytes);
  Assert.IsTrue(TJOSEBytes.Empty + TBytes.Create(7) = TBytes.Create(7));
  Assert.IsTrue(LBytes + '' = LBytes);
  Assert.IsTrue(TJOSEBytes.Empty + 'AB' = TBytes.Create(65, 66));
  Assert.IsTrue(TJOSEBytes.Empty + Byte(9) = TBytes.Create(9));
  Assert.IsTrue(LBytes + Byte(3) = TBytes.Create(1, 2, 3));
end;

procedure TTestJOSEBytesForJWE.MergeBytesWithEmptyOperands;
begin
  Assert.AreEqual(0, Length(TBytesUtils.MergeBytes(nil, TBytes(nil))));
  Assert.AreEqual(2, Length(TBytesUtils.MergeBytes(nil, TBytes.Create(1, 2))));
  Assert.AreEqual(2, Length(TBytesUtils.MergeBytes(TBytes.Create(1, 2), TBytes(nil))));
  Assert.AreEqual(1, Length(TBytesUtils.MergeBytes(nil, Byte(1))));
end;

procedure TTestJOSEBytesForJWE.PartsClearKeepsTheSlots;
var
  LToken: TJWT;
  LJWS: TJWS;
begin
  LToken := TJWT.Create;
  try
    LJWS := TJWS.Create(LToken);
    try
      LJWS.Signature := TBytes.Create(1, 2, 3);
      LJWS.Clear;

      // Clear used to delete the slots, so this raised a list index error
      Assert.IsTrue(LJWS.Signature.IsEmpty);
      Assert.IsTrue(LJWS.Payload.IsEmpty);
    finally
      LJWS.Free;
    end;
  finally
    LToken.Free;
  end;
end;

{ TTestJWEParsing }

const
  // RFC 7520 par. 5.6 ("dir" + A128GCM). Parsing only here: decryption is
  // tested per provider stack
  RFC7520_56_TOKEN =
    'eyJhbGciOiJkaXIiLCJraWQiOiI3N2M3ZTJiOC02ZTEzLTQ1Y2YtODY3Mi02MTdiNWI0NTI0M2EiLCJlbmMiOiJBMTI4R0NNIn0' +
    '..refa467QzzKx6QAB.' +
    'JW_i_f52hww_ELQPGaYyeAB6HYGcR559l9TYnSovc23XJoBcW29rHP8yZOZG7YhLpT1bjFuvZPjQS-m0IFtVcXkZXdH_lr_FrdYt9H' +
    'RUYkshtrMmIUAyGmUnd9zMDB2n0cRDIHAzFVeJUDxkUwVAE7_YGRPdcqMyiBoCO-FBdE-Nceb4h3-FtBP-c_BIwCPTjb9o0Sbdcd' +
    'REEMJMyZBH8ySWMVi1gPD9yxi-aQpGbSv_F9N4IZAxscj5g-NJsUPbjk29-s7LJAGb15wEBtXphVCgyy53CoIKLHHeJHXex45Uz9a' +
    'KZSRSInZI-wjsY0yu3cT4_aQ3i1o-tiE-F8Ios61EKgyIQ4CWao8PFMj8TTnp' +
    '.vbb32Xvllea2OtmHAdccRQ';

// A well-formed 5-part token around AHeaderJSON. The other parts are dummies:
// every test using it fails before they are looked at
function TokenWithHeader(const AHeaderJSON: string): string;
begin
  Result := TBase64.URLEncode(AHeaderJSON).AsString + '..AAAAAAAAAAAAAAAA.AAAA.AAAAAAAAAAAAAAAAAAAAAA';
end;

// The message of the exception AProc raises, '' when it raises nothing
function ErrorOf(const AProc: TProc): string;
begin
  Result := '';
  try
    AProc();
  except
    on E: Exception do
      Result := E.ClassName + ': ' + E.Message;
  end;
end;

procedure TTestJWEParsing.RegistriesResolveTheStep1Algorithms;
var
  LFactory: TJOSEAlgorithmRegistryFactory;
begin
  LFactory := TJOSEAlgorithmRegistryFactory.Instance;

  Assert.IsNotNull(LFactory.KeyManagementAlgorithmRegistry.GetAlgorithm('dir'));
  Assert.IsNotNull(LFactory.KeyManagementAlgorithmRegistry.GetAlgorithm('RSA-OAEP'));
  Assert.IsNotNull(LFactory.KeyManagementAlgorithmRegistry.GetAlgorithm('RSA-OAEP-256'));
  Assert.IsNull(LFactory.KeyManagementAlgorithmRegistry.GetAlgorithm('RSA1_5'), 'RSA1_5 is never supported');
  Assert.IsNotNull(LFactory.EncryptionAlgorithmRegistry.GetAlgorithm('A128GCM'));
  Assert.IsNotNull(LFactory.EncryptionAlgorithmRegistry.GetAlgorithm('A192GCM'));
  Assert.IsNotNull(LFactory.EncryptionAlgorithmRegistry.GetAlgorithm('A256GCM'));
  Assert.AreEqual(16, LFactory.EncryptionAlgorithmRegistry.GetAlgorithm('A128GCM').GetCEKLength);
  Assert.AreEqual(32, LFactory.EncryptionAlgorithmRegistry.GetAlgorithm('A256GCM').GetCEKLength);
end;

procedure TTestJWEParsing.ParsesTheHeaderAndKeepsThePartsVerbatim;
var
  LToken: TJWT;
  LJWE: TJWE;
begin
  LToken := TJWT.Create;
  LJWE := TJWE.Create(LToken);
  try
    LJWE.CompactToken := RFC7520_56_TOKEN;

    Assert.AreEqual('dir', LJWE.Header.Algorithm);
    Assert.AreEqual('A128GCM', LJWE.Header.Encryption);
    Assert.AreEqual('dir', LToken.Header.Algorithm, 'The token header is filled too');
    Assert.IsTrue(LJWE.EncryptedKey.IsEmpty);
    Assert.AreEqual('refa467QzzKx6QAB', LJWE.IV.AsString);
    Assert.AreEqual('vbb32Xvllea2OtmHAdccRQ', LJWE.AuthenticationTag.AsString);
    Assert.AreEqual(RFC7520_56_TOKEN, LJWE.CompactToken.AsString);
  finally
    LJWE.Free;
    LToken.Free;
  end;
end;

procedure TTestJWEParsing.CheckCompactToken(const AToken: string; AExpected: Boolean);
var
  LToken: string;
begin
  if AToken = 'RFC' then
    LToken := RFC7520_56_TOKEN
  else
    LToken := AToken;

  Assert.AreEqual(AExpected, TJWE.CheckCompactToken(LToken));
end;

procedure TTestJWEParsing.SetCompactTokenRejectsMalformed(const AToken: string);
var
  LToken: TJWT;
  LJWE: TJWE;
begin
  LToken := TJWT.Create;
  LJWE := TJWE.Create(LToken);
  try
    Assert.WillRaise(
      procedure
      begin
        LJWE.CompactToken := AToken;
      end,
      EJOSEException);
  finally
    LJWE.Free;
    LToken.Free;
  end;
end;

procedure TTestJWEParsing.DecryptRejectsHeaderBeforeCrypto(const AHeader, AExpectedMessage: string);
var
  LToken: TJWT;
  LJWE: TJWE;
  LKey: TJWK;
  LError: string;
begin
  LKey := TJWK.Create(TJOSEBytes.RandomBytes(16));
  LToken := TJWT.Create;
  LJWE := TJWE.Create(LToken);
  try
    LJWE.CompactToken := TokenWithHeader(AHeader);
    LError := ErrorOf(
      procedure
      begin
        LJWE.DecryptPayload(LKey);
      end);

    // A precise EJOSEException, raised before the (missing) AES-GCM provider
    // is ever asked for
    Assert.StartsWith('EJOSEException: ', LError);
    Assert.Contains(LError, AExpectedMessage);
  finally
    LJWE.Free;
    LToken.Free;
    LKey.Free;
  end;
end;

procedure TTestJWEParsing.EncryptRejectsSigningAlgorithm;
var
  LToken: TJWT;
  LJWE: TJWE;
  LKey: TJWK;
begin
  LKey := TJWK.Create(TJOSEBytes.RandomBytes(32));
  LToken := TJWT.Create;
  LJWE := TJWE.Create(LToken);
  try
    Assert.WillRaise(
      procedure
      begin
        LJWE.Encrypt(LKey, TJOSEAlgorithmId.HS256, TJOSEEncryptionAlgorithmId.A256GCM);
      end,
      EJOSEException);
  finally
    LJWE.Free;
    LToken.Free;
    LKey.Free;
  end;
end;

procedure TTestJWEParsing.MissingProviderIsReportedAsSuch;
var
  LToken: TJWT;
  LJWE: TJWE;
  LKey: TJWK;
begin
  // The default stack has no AES-GCM yet. That is a configuration problem and
  // must say so, not hide behind the generic "decryption failed"
  if TJOSEProviders.HasAESGCM then
    Exit;

  LKey := TJWK.Create(TJOSEBytes.RandomBytes(16));
  LToken := TJWT.Create;
  LJWE := TJWE.Create(LToken);
  try
    LJWE.CompactToken := RFC7520_56_TOKEN;
    Assert.WillRaise(
      procedure
      begin
        LJWE.DecryptPayload(LKey);
      end,
      EJOSEProvidersNotRegistered);

    Assert.WillRaise(
      procedure
      begin
        LJWE.Encrypt(LKey, TJOSEAlgorithmId.Dir, TJOSEEncryptionAlgorithmId.A128GCM);
      end,
      EJOSEProvidersNotRegistered);
  finally
    LJWE.Free;
    LToken.Free;
    LKey.Free;
  end;
end;

procedure TTestJWEParsing.MissingRSAEncryptionProviderIsReportedAsSuch;
var
  LToken: TJWT;
  LJWE: TJWE;
  LKey: TJWK;
begin
  if TJOSEProviders.HasRSAEncryption then
    Exit;

  LKey := TJWK.Create(TFile.ReadAllBytes(TPath.Combine(FKeysPath, 'rsa-public.pem')));
  LToken := TJWT.Create;
  LJWE := TJWE.Create(LToken);
  try
    Assert.WillRaise(
      procedure
      begin
        LJWE.Encrypt(LKey, TJOSEAlgorithmId.RSA_OAEP_256, TJOSEEncryptionAlgorithmId.A256GCM);
      end,
      EJOSEProvidersNotRegistered);
  finally
    LJWE.Free;
    LToken.Free;
    LKey.Free;
  end;
end;

{ TTestJWEWiring }

const
  HS256_SECRET = 'a-shared-secret-of-at-least-32-bytes!';
  DIR_A128GCM_HEADER = '{"alg":"dir","enc":"A128GCM"}';

function DirConsumer: IJOSEConsumerBuilder;
begin
  Result := TJOSEConsumerBuilder.NewConsumer
    .SetDecryptionKey(TJOSEBytes.RandomBytes(16))
    .SetExpectedKeyManagementAlgorithms([TJOSEAlgorithmId.Dir])
    .SetExpectedEncryptionAlgorithms([TJOSEEncryptionAlgorithmId.A128GCM])
    .SetDisableRequireSignature;
end;

function HS256Token(const ASubject: string): TJOSEBytes;
var
  LToken: TJWT;
begin
  LToken := TJWT.Create;
  try
    LToken.Claims.Subject := ASubject;
    Result := TJOSE.SHA256CompactToken(HS256_SECRET, LToken);
  finally
    LToken.Free;
  end;
end;

procedure TTestJWEWiring.ContextParsesAJWEWithoutDecrypting;
var
  LContext: TJOSEContext;
begin
  LContext := TJOSEContext.Create(TokenWithHeader(DIR_A128GCM_HEADER), TJWTClaims);
  try
    Assert.IsTrue(LContext.GetJOSEObject is TJWE);
    Assert.AreEqual('dir', LContext.GetHeader.Algorithm);
    Assert.IsFalse(LContext.GetClaims.HasSubject, 'Claims stay empty until the consumer decrypts');
  finally
    LContext.Free;
  end;
end;

procedure TTestJWEWiring.ContextRejectsFourParts;
begin
  Assert.WillRaise(
    procedure
    begin
      TJOSEContext.Create('e30.AA.AA.AA', TJWTClaims).Free;
    end,
    EJOSEException);
end;

procedure TTestJWEWiring.DefaultConsumerRejectsEveryJWE;
var
  LError: string;
begin
  // A consumer that was never told about JWE keeps rejecting it, as it did
  // before JWE existed
  LError := ErrorOf(
    procedure
    begin
      TJOSEConsumerBuilder.NewConsumer
        .SetVerificationKey(HS256_SECRET)
        .Build
        .Process(TokenWithHeader(DIR_A128GCM_HEADER));
    end);

  Assert.Contains(LError, 'key management algorithm [dir] is not listed');
end;

procedure TTestJWEWiring.ConsumerRejectsUnexpectedEnc;
var
  LError: string;
begin
  LError := ErrorOf(
    procedure
    begin
      DirConsumer
        .SetExpectedEncryptionAlgorithms([TJOSEEncryptionAlgorithmId.A256GCM])
        .Build
        .Process(TokenWithHeader(DIR_A128GCM_HEADER));
    end);

  Assert.Contains(LError, 'content encryption algorithm [A128GCM] is not listed');
end;

procedure TTestJWEWiring.ConsumerRejectsSigningAlgEvenIfListed;
var
  LError: string;
begin
  // A signing "alg" put in the key management set by mistake still cannot
  // select a key management algorithm
  LError := ErrorOf(
    procedure
    begin
      DirConsumer
        .SetExpectedKeyManagementAlgorithms([TJOSEAlgorithmId.HS256, TJOSEAlgorithmId.Dir])
        .Build
        .Process(TokenWithHeader('{"alg":"HS256","enc":"A128GCM"}'));
    end);

  Assert.Contains(LError, 'key management algorithm [HS256] is not listed');
end;

procedure TTestJWEWiring.ConsumerWithAllowlistsGoesOnToDecrypt;
begin
  // The default stack has no AES-GCM: reaching that error proves the
  // allowlists let the token through to the decryption
  if TJOSEProviders.HasAESGCM then
    Exit;

  Assert.WillRaise(
    procedure
    begin
      DirConsumer.Build.Process(TokenWithHeader(DIR_A128GCM_HEADER));
    end,
    EJOSEProvidersNotRegistered);
end;

procedure TTestJWEWiring.RequireEncryptionAcceptsAJWEShape;
begin
  if TJOSEProviders.HasAESGCM then
    Exit;

  // Not refused as "not encrypted": it gets as far as the decryption
  Assert.WillRaise(
    procedure
    begin
      DirConsumer.SetEnableRequireEncryption.Build.Process(TokenWithHeader(DIR_A128GCM_HEADER));
    end,
    EJOSEProvidersNotRegistered);
end;

procedure TTestJWEWiring.VerificationAndDecryptionKeysAreSeparate;
begin
  // SetDecryptionKey used to overwrite the verification key, so this JWS
  // failed its signature check
  TJOSEConsumerBuilder.NewConsumer
    .SetVerificationKey(HS256_SECRET)
    .SetDecryptionKey(TJOSEBytes.RandomBytes(32))
    .Build
    .Process(HS256Token('alice'));

  Assert.Pass;
end;

procedure TTestJWEWiring.TJOSEDecryptRejectsAJWS;
var
  LError: string;
begin
  LError := ErrorOf(
    procedure
    begin
      TJOSE.Decrypt(TJOSEBytes.RandomBytes(16), HS256Token('alice')).Free;
    end);

  Assert.Contains(LError, 'not a JWE');
end;

procedure TTestJWEWiring.TJOSEDecryptRequiresAKey;
begin
  Assert.WillRaise(
    procedure
    begin
      TJOSE.Decrypt(TJWK(nil), TokenWithHeader(DIR_A128GCM_HEADER)).Free;
    end,
    EJOSEException);
end;

procedure TTestJWEWiring.TJOSEDecryptAndVerifyRejectsAJWS;
var
  LKey: TJWK;
begin
  LKey := TJWK.Create(TJOSEBytes.RandomBytes(16));
  try
    Assert.WillRaise(
      procedure
      begin
        TJOSE.DecryptAndVerify(LKey, LKey, HS256Token('alice')).Free;
      end,
      EJOSEException);
  finally
    LKey.Free;
  end;
end;

procedure TTestJWEWiring.TJOSEVerifyStillRejectsAJWE;
begin
  // Verify is JWS-only: a JWE is not mistaken for a token to verify
  Assert.WillRaise(
    procedure
    begin
      TJOSE.Verify(HS256_SECRET, TokenWithHeader(DIR_A128GCM_HEADER)).Free;
    end,
    EJOSEException);
end;

initialization
  TDUnitX.RegisterTestFixture(TTestJWEWiring);
  TDUnitX.RegisterTestFixture(TTestJWEParsing);
  TDUnitX.RegisterTestFixture(TTestJWEIdentifiers);
  TDUnitX.RegisterTestFixture(TTestJWARegistries);
  TDUnitX.RegisterTestFixture(TTestJWEHeader);
  TDUnitX.RegisterTestFixture(TTestJOSEBytesForJWE);

end.
