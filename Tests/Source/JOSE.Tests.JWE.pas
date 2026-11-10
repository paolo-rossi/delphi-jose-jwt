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
  System.Rtti,
  DUnitX.TestFramework,

  JOSE.Types.Bytes,
  JOSE.Core.JWA,
  JOSE.Core.JWA.Factory,
  JOSE.Core.JWT,
  JOSE.Core.JWS,
  JOSE.Core.JWE.Header;

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

initialization
  TDUnitX.RegisterTestFixture(TTestJWEIdentifiers);
  TDUnitX.RegisterTestFixture(TTestJWARegistries);
  TDUnitX.RegisterTestFixture(TTestJWEHeader);
  TDUnitX.RegisterTestFixture(TTestJOSEBytesForJWE);

end.
