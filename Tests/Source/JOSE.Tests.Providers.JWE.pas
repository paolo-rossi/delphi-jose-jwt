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
///   Stack-independent tests of the JWE crypto providers (AES-GCM, RSA-OAEP).
///   Every provider stack subclasses TJWEPrimitivesTestBase and only says how
///   to register itself, so all stacks are held to the same vectors
/// </summary>
unit JOSE.Tests.Providers.JWE;

interface

uses
  System.SysUtils,
  DUnitX.TestFramework,

  JOSE.Tests.Classes,
  JOSE.Crypto.Algorithms,
  JOSE.Providers.Interfaces,
  JOSE.Core.JWA;

type
  /// <summary>
  ///   Registers a provider stack around every test. Subclasses say which
  /// </summary>
  TJWEStackTestBase = class(TTestBase)
  protected
    procedure RegisterStack; virtual; abstract;
    procedure UnregisterStack; virtual; abstract;
    function ReadKey(const AFileName: string): TBytes;
  public
    [Setup]
    procedure Setup;
    [TearDown]
    procedure TearDown;
  end;

  /// <summary>
  ///   The JWE crypto providers. Not registered itself: register the subclasses
  /// </summary>
  TJWEPrimitivesTestBase = class(TJWEStackTestBase)
  protected
    function GCM: IJOSEAESGCMProvider;
    function OAEP: IJOSERSAEncryptionProvider;
  public
    [Test]
    procedure JWEProvidersAreRegistered;

    // AES-GCM. Test cases 1, 2, 4, 10 and 16 of McGrew & Viega, "The Galois/
    // Counter Mode of Operation (GCM)", the reference vectors NIST SP 800-38D
    // builds on. Checked against .NET's AesGcm (Windows CNG) before they were
    // committed. Fields: key, IV, plaintext, AAD, ciphertext, tag
    [Test]
    [TestCase('TC1 AES-128 empty',  '00000000000000000000000000000000,000000000000000000000000,,,,58e2fccefa7e3061367f1d57a4e7455a')]
    [TestCase('TC2 AES-128 zeros',  '00000000000000000000000000000000,000000000000000000000000,00000000000000000000000000000000,,0388dace60b6a392f328c2b971b2fe78,ab6e47d42cec13bdf53a67b21257bddf')]
    [TestCase('TC4 AES-128 AAD',    'feffe9928665731c6d6a8f9467308308,cafebabefacedbaddecaf888,d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39,feedfacedeadbeeffeedfacedeadbeefabaddad2,42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091,5bc94fbc3221a5db94fae95ae7121a47')]
    [TestCase('TC10 AES-192 AAD',   'feffe9928665731c6d6a8f9467308308feffe9928665731c,cafebabefacedbaddecaf888,d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39,feedfacedeadbeeffeedfacedeadbeefabaddad2,3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710,2519498e80f1478f37ba55bd6d27618c')]
    [TestCase('TC16 AES-256 AAD',   'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308,cafebabefacedbaddecaf888,d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39,feedfacedeadbeeffeedfacedeadbeefabaddad2,522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662,76fc6ece0f4e1768cddf8853bb2d551b')]
    procedure GCM_KnownAnswer(const AKey, AIV, APlaintext, AAAD, ACiphertext, ATag: string);

    [Test]
    [TestCase('16', '16')]
    [TestCase('24', '24')]
    [TestCase('32', '32')]
    procedure GCM_RoundTrip(AKeyLength: Integer);

    [Test]
    procedure GCM_RoundTripEmptyPlaintext;

    [Test]
    [TestCase('Ciphertext', 'Ciphertext')]
    [TestCase('Tag',        'Tag')]
    [TestCase('AAD',        'AAD')]
    [TestCase('IV',         'IV')]
    [TestCase('Key',        'Key')]
    procedure GCM_TamperingIsDetected(const AWhat: string);

    [Test]
    [TestCase('Key 15',   '15,12,16')]
    [TestCase('Key 33',   '33,12,16')]
    [TestCase('IV 16',    '16,16,16')]
    [TestCase('IV 8',     '16,8,16')]
    [TestCase('Tag 12',   '16,12,12')]
    [TestCase('Tag 0',    '16,12,0')]
    procedure GCM_DecryptRejectsBadLengths(AKeyLength, AIVLength, ATagLength: Integer);

    [Test]
    procedure GCM_DecryptFailuresLookTheSame;

    // RSA-OAEP. The fixed ciphertexts below were produced by OpenSSL 3.5:
    //   openssl pkeyutl -encrypt -pubin -inkey Tests/Keys/rsa-public.pem
    //     -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:<md>
    //     -pkeyopt rsa_mgf1_md:<md>
    // over the 32 bytes 00 01 .. 1f. An independent implementation, so they
    // pin the digest and the MGF1 digest, which a same-stack round trip cannot
    [Test]
    [TestCase('RSA-OAEP',     'SHA1')]
    [TestCase('RSA-OAEP-256', 'SHA256')]
    procedure OAEP_RoundTrip(ADigest: TJOSEOAEPDigest);

    [Test]
    [TestCase('RSA-OAEP',     'SHA1')]
    [TestCase('RSA-OAEP-256', 'SHA256')]
    procedure OAEP_DecryptsOpenSSLCiphertext(ADigest: TJOSEOAEPDigest);

    [Test]
    [TestCase('SHA-1 ciphertext, SHA-256 key',   'SHA1,SHA256')]
    [TestCase('SHA-256 ciphertext, SHA-1 key',   'SHA256,SHA1')]
    procedure OAEP_DigestMismatchIsRejected(AEncryptedWith, ADecryptWith: TJOSEOAEPDigest);

    [Test]
    procedure OAEP_TamperingIsDetected;

    [Test]
    procedure OAEP_EncryptionIsRandomized;

    [Test]
    procedure OAEP_DecryptFailuresLookTheSame;
  end;

  /// <summary>
  ///   TJWE end to end ("dir" + AES-GCM) on a provider stack. Not registered
  ///   itself: register the subclasses
  /// </summary>
  TJWETokenTestBase = class(TJWEStackTestBase)
  public
    // RFC 7520 par. 5.6, "Direct Encryption Using AES-GCM" (dir + A128GCM).
    // Checked against .NET's AesGcm before it was committed
    [Test]
    procedure RFC7520_DirA128GCM_Decrypts;

    [Test]
    procedure RFC7520_DirA128GCM_ReserializesUnchanged;

    [Test]
    [TestCase('A128GCM', 'A128GCM')]
    [TestCase('A192GCM', 'A192GCM')]
    [TestCase('A256GCM', 'A256GCM')]
    procedure Dir_ClaimsRoundTrip(AEnc: TJOSEEncryptionAlgorithmId);

    [Test]
    procedure Dir_EmptyPayloadRoundTrips;

    [Test]
    procedure Encrypt_KeepsTheTokenHeader;

    [Test]
    procedure Encrypt_IsRandomized;

    [Test]
    [TestCase('Too short', '16')]
    [TestCase('Too long',  '64')]
    procedure Dir_EncryptRejectsWrongKeyLength(AKeyLength: Integer);

    // The protected header is the AAD exactly as received: the same JSON
    // serialized in another member order is a different AAD
    [Test]
    procedure ReorderedProtectedHeader_IsRejected;

    [Test]
    [TestCase('Encrypted Key', '1')]
    [TestCase('IV',            '2')]
    [TestCase('Ciphertext',    '3')]
    [TestCase('Tag',           '4')]
    procedure TamperedPart_IsRejected(APart: Integer);

    [Test]
    procedure WrongKey_IsRejected;

    [Test]
    procedure DecryptionFailuresLookTheSame;

    [Test]
    procedure NestedJWT_LeavesClaimsAlone;
  end;

implementation

uses
  System.Classes,
  System.IOUtils,
  JOSE.Types.Bytes,
  JOSE.Encoding.Base64,
  JOSE.Providers,
  JOSE.Core.Base,
  JOSE.Core.JWK,
  JOSE.Core.JWT,
  JOSE.Core.JWE;

const
  // See the comment over OAEP_RoundTrip
  OAEP_PLAINTEXT_HEX = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
  OAEP_OPENSSL_SHA1 =
    'q97yHbIW6jPG50+at2Z+qmHly1zc/DqYC/t499iQRIFX6AYICKOfRn8AUjrCC2d3I0snmV0CQtOh79MQj+dpmgsHVIhSP0Kb0ffD' +
    '7ycPpAUZSMA/9A3uPnb77DOsknL+IDn8eHyjpiT9rXuWDK/MWWFVHJnz5c9zNMgc5iFpYFxzQkd2WjMazP0o7XkkVEABREbuci9u' +
    'lkop7WpO2dJqLRQd++Blv7UmmSmOvGUx9oZ4t6+S5+Y7eGXEc69Nv+6K81QWa4nrFp+lXKAESfLMkqwXlZVNzjulHAYzoZxp5VYb' +
    'M0JkXxBHd0PupWBBEQyJVX78XFFC6Q9KRCDK5Zk+og==';
  OAEP_OPENSSL_SHA256 =
    'oS7HZu8WLiHLYAnCkztUr7sjj2dHHipFk447SwBvCQAw4aW/O5km/11biu2O/8QP6+GO89NwYVatqKclTX9+4wG8PorjNrz+yw8x' +
    'row8BhZNbWIYXvu3+o70oMA2IwOs0h8pTZEVNlGHX9qsir1wKCSky3YLS9dRz7E/A8L6XFB+gH/RiHLmxsD/XD1L1uV8m5vU9KLm' +
    'Cqx0td9k2Eb6oCbFEt+S79Kl9EiK5ED7Qe88SyxLacgIG8etxIoLCsKyMKsf6s/iX/rEsh89ugHIptKBdp8EOuenCjsm1q15wxa7' +
    '6lv1696HB9eoKummn2sXe7UjfO4wzWpXT0d3pQ89yg==';

  // TC4 above, reused by the negative tests
  TC4_KEY = 'feffe9928665731c6d6a8f9467308308';
  TC4_IV = 'cafebabefacedbaddecaf888';
  TC4_PT = 'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39';
  TC4_AAD = 'feedfacedeadbeeffeedfacedeadbeefabaddad2';
  TC4_CT = '42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091';
  TC4_TAG = '5bc94fbc3221a5db94fae95ae7121a47';

function HexToBytes(const AHex: string): TBytes;
begin
  SetLength(Result, Length(AHex) div 2);
  if Length(Result) > 0 then
    HexToBin(PChar(AHex), PByte(Result), Length(Result));
end;

function BytesToHex(const ABytes: TBytes): string;
begin
  SetLength(Result, Length(ABytes) * 2);
  if Length(ABytes) > 0 then
    BinToHex(PByte(ABytes), PChar(Result), Length(ABytes));
end;

function FlipBit(const AValue: TBytes; AIndex: Integer = 0): TBytes;
begin
  Result := Copy(AValue);
  Result[AIndex] := Result[AIndex] xor $01;
end;

function OpenSSLCiphertext(ADigest: TJOSEOAEPDigest): TBytes;
begin
  if ADigest = TJOSEOAEPDigest.SHA1 then
    Result := TBase64.Decode(OAEP_OPENSSL_SHA1).AsBytes
  else
    Result := TBase64.Decode(OAEP_OPENSSL_SHA256).AsBytes;
end;

// The message of the exception AProc raises; fails the test when it raises
// nothing or something other than EJOSECryptoException
function CryptoErrorOf(const AProc: TProc): string;
begin
  Result := '';
  try
    AProc();
  except
    on E: EJOSECryptoException do
      Exit(E.Message);
  end;
  Assert.Fail('Expected EJOSECryptoException');
end;

{ TJWEPrimitivesTestBase }

function TJWEPrimitivesTestBase.GCM: IJOSEAESGCMProvider;
begin
  Result := TJOSEProviders.AESGCM;
end;

function TJWEPrimitivesTestBase.OAEP: IJOSERSAEncryptionProvider;
begin
  Result := TJOSEProviders.RSAEncryption;
end;

{ TJWEStackTestBase }

function TJWEStackTestBase.ReadKey(const AFileName: string): TBytes;
begin
  Result := TFile.ReadAllBytes(TPath.Combine(FKeysPath, AFileName));
end;

procedure TJWEStackTestBase.Setup;
begin
  RegisterStack;
end;

procedure TJWEStackTestBase.TearDown;
begin
  UnregisterStack;
  TJOSEProviders.RegisterProvider;
end;

procedure TJWEPrimitivesTestBase.JWEProvidersAreRegistered;
begin
  Assert.IsTrue(TJOSEProviders.HasAESGCM, 'AES-GCM provider missing');
  Assert.IsTrue(TJOSEProviders.HasRSAEncryption, 'RSA-OAEP provider missing');
end;

procedure TJWEPrimitivesTestBase.GCM_KnownAnswer(const AKey, AIV, APlaintext, AAAD, ACiphertext, ATag: string);
var
  LCiphertext, LTag, LPlaintext: TBytes;
begin
  LCiphertext := GCM.Encrypt(HexToBytes(APlaintext), HexToBytes(AKey), HexToBytes(AIV), HexToBytes(AAAD), LTag);
  Assert.AreEqual(ACiphertext, LowerCase(BytesToHex(LCiphertext)), 'Ciphertext');
  Assert.AreEqual(ATag, LowerCase(BytesToHex(LTag)), 'Tag');

  LPlaintext := GCM.Decrypt(HexToBytes(ACiphertext), HexToBytes(AKey), HexToBytes(AIV), HexToBytes(AAAD), HexToBytes(ATag));
  Assert.AreEqual(APlaintext, LowerCase(BytesToHex(LPlaintext)), 'Plaintext');
end;

procedure TJWEPrimitivesTestBase.GCM_RoundTrip(AKeyLength: Integer);
var
  LKey, LIV, LPlaintext, LAAD, LTag, LCiphertext: TBytes;
begin
  LKey := TJOSEBytes.RandomBytes(AKeyLength);
  LIV := TJOSEBytes.RandomBytes(12);
  LPlaintext := TEncoding.UTF8.GetBytes('{"sub":"1234567890","name":"John Doe","admin":true}');
  LAAD := TEncoding.ASCII.GetBytes('eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0');

  LCiphertext := GCM.Encrypt(LPlaintext, LKey, LIV, LAAD, LTag);
  Assert.AreEqual(Length(LPlaintext), Length(LCiphertext), 'GCM does not pad');
  Assert.AreEqual(16, Length(LTag));
  Assert.IsTrue(TJOSEBytes(GCM.Decrypt(LCiphertext, LKey, LIV, LAAD, LTag)) = LPlaintext);
end;

procedure TJWEPrimitivesTestBase.GCM_RoundTripEmptyPlaintext;
var
  LKey, LIV, LTag, LCiphertext: TBytes;
begin
  LKey := TJOSEBytes.RandomBytes(32);
  LIV := TJOSEBytes.RandomBytes(12);

  LCiphertext := GCM.Encrypt(nil, LKey, LIV, nil, LTag);
  Assert.AreEqual(0, Length(LCiphertext));
  Assert.AreEqual(16, Length(LTag));
  Assert.AreEqual(0, Length(GCM.Decrypt(LCiphertext, LKey, LIV, nil, LTag)));
end;

procedure TJWEPrimitivesTestBase.GCM_TamperingIsDetected(const AWhat: string);
var
  LKey, LIV, LAAD, LCiphertext, LTag: TBytes;
begin
  LKey := HexToBytes(TC4_KEY);
  LIV := HexToBytes(TC4_IV);
  LAAD := HexToBytes(TC4_AAD);
  LCiphertext := HexToBytes(TC4_CT);
  LTag := HexToBytes(TC4_TAG);

  if AWhat = 'Ciphertext' then
    LCiphertext := FlipBit(LCiphertext, 30)
  else if AWhat = 'Tag' then
    LTag := FlipBit(LTag, 15)
  else if AWhat = 'AAD' then
    LAAD := FlipBit(LAAD, 3)
  else if AWhat = 'IV' then
    LIV := FlipBit(LIV, 11)
  else if AWhat = 'Key' then
    LKey := FlipBit(LKey, 0);

  CryptoErrorOf(
    procedure
    begin
      GCM.Decrypt(LCiphertext, LKey, LIV, LAAD, LTag);
    end);
end;

procedure TJWEPrimitivesTestBase.GCM_DecryptRejectsBadLengths(AKeyLength, AIVLength, ATagLength: Integer);
var
  LKey, LIV, LTag: TBytes;
begin
  LKey := TJOSEBytes.RandomBytes(AKeyLength);
  LIV := TJOSEBytes.RandomBytes(AIVLength);
  LTag := TJOSEBytes.RandomBytes(ATagLength);

  CryptoErrorOf(
    procedure
    begin
      GCM.Decrypt(TBytes.Create(1, 2, 3), LKey, LIV, nil, LTag);
    end);
end;

procedure TJWEPrimitivesTestBase.GCM_DecryptFailuresLookTheSame;
var
  LKey, LIV, LAAD, LCiphertext, LTag: TBytes;
  LWrongTag, LWrongAAD, LWrongKey: string;
begin
  LKey := HexToBytes(TC4_KEY);
  LIV := HexToBytes(TC4_IV);
  LAAD := HexToBytes(TC4_AAD);
  LCiphertext := HexToBytes(TC4_CT);
  LTag := HexToBytes(TC4_TAG);

  LWrongTag := CryptoErrorOf(procedure begin GCM.Decrypt(LCiphertext, LKey, LIV, LAAD, FlipBit(LTag)); end);
  LWrongAAD := CryptoErrorOf(procedure begin GCM.Decrypt(LCiphertext, LKey, LIV, FlipBit(LAAD), LTag); end);
  LWrongKey := CryptoErrorOf(procedure begin GCM.Decrypt(LCiphertext, FlipBit(LKey), LIV, LAAD, LTag); end);

  Assert.AreEqual(LWrongTag, LWrongAAD);
  Assert.AreEqual(LWrongTag, LWrongKey);
end;

procedure TJWEPrimitivesTestBase.OAEP_RoundTrip(ADigest: TJOSEOAEPDigest);
var
  LCEK, LEncrypted: TBytes;
begin
  LCEK := TJOSEBytes.RandomBytes(32);

  LEncrypted := OAEP.Encrypt(LCEK, ReadKey('rsa-public.pem'), ADigest);
  Assert.AreEqual(256, Length(LEncrypted), 'A 2048-bit key gives a 256-byte ciphertext');
  Assert.IsTrue(TJOSEBytes(OAEP.Decrypt(LEncrypted, ReadKey('rsa-private.pem'), ADigest)) = LCEK);
end;

procedure TJWEPrimitivesTestBase.OAEP_DecryptsOpenSSLCiphertext(ADigest: TJOSEOAEPDigest);
var
  LPlaintext: TBytes;
begin
  LPlaintext := OAEP.Decrypt(OpenSSLCiphertext(ADigest), ReadKey('rsa-private.pem'), ADigest);
  Assert.AreEqual(OAEP_PLAINTEXT_HEX, LowerCase(BytesToHex(LPlaintext)));
end;

procedure TJWEPrimitivesTestBase.OAEP_DigestMismatchIsRejected(AEncryptedWith, ADecryptWith: TJOSEOAEPDigest);
var
  LCiphertext, LKey: TBytes;
begin
  LCiphertext := OpenSSLCiphertext(AEncryptedWith);
  LKey := ReadKey('rsa-private.pem');

  CryptoErrorOf(
    procedure
    begin
      OAEP.Decrypt(LCiphertext, LKey, ADecryptWith);
    end);
end;

procedure TJWEPrimitivesTestBase.OAEP_TamperingIsDetected;
var
  LCiphertext, LKey: TBytes;
begin
  LCiphertext := FlipBit(OpenSSLCiphertext(TJOSEOAEPDigest.SHA256), 100);
  LKey := ReadKey('rsa-private.pem');

  CryptoErrorOf(
    procedure
    begin
      OAEP.Decrypt(LCiphertext, LKey, TJOSEOAEPDigest.SHA256);
    end);
end;

procedure TJWEPrimitivesTestBase.OAEP_EncryptionIsRandomized;
var
  LCEK, LPublic: TBytes;
begin
  LCEK := TJOSEBytes.RandomBytes(32);
  LPublic := ReadKey('rsa-public.pem');

  Assert.IsFalse(TJOSEBytes(OAEP.Encrypt(LCEK, LPublic, TJOSEOAEPDigest.SHA256)) =
    OAEP.Encrypt(LCEK, LPublic, TJOSEOAEPDigest.SHA256), 'OAEP must use a fresh seed every time');
end;

procedure TJWEPrimitivesTestBase.OAEP_DecryptFailuresLookTheSame;
var
  LKey, LCiphertext: TBytes;
  LTampered, LWrongDigest, LTruncated: string;
begin
  LKey := ReadKey('rsa-private.pem');
  LCiphertext := OpenSSLCiphertext(TJOSEOAEPDigest.SHA256);

  LTampered := CryptoErrorOf(procedure begin OAEP.Decrypt(FlipBit(LCiphertext, 7), LKey, TJOSEOAEPDigest.SHA256); end);
  LWrongDigest := CryptoErrorOf(procedure begin OAEP.Decrypt(LCiphertext, LKey, TJOSEOAEPDigest.SHA1); end);
  LTruncated := CryptoErrorOf(procedure begin OAEP.Decrypt(Copy(LCiphertext, 0, 100), LKey, TJOSEOAEPDigest.SHA256); end);

  Assert.AreEqual(LTampered, LWrongDigest);
  Assert.AreEqual(LTampered, LTruncated);
end;

{ RFC 7520 par. 5.6 }

const
  RFC7520_56_KEY = 'XctOhJAkA-pD9Lh7ZgW_2A';
  RFC7520_56_HEADER =
    'eyJhbGciOiJkaXIiLCJraWQiOiI3N2M3ZTJiOC02ZTEzLTQ1Y2YtODY3Mi02MTdiNWI0NTI0M2EiLCJlbmMiOiJBMTI4R0NNIn0';
  RFC7520_56_IV = 'refa467QzzKx6QAB';
  RFC7520_56_CIPHERTEXT =
    'JW_i_f52hww_ELQPGaYyeAB6HYGcR559l9TYnSovc23XJoBcW29rHP8yZOZG7YhLpT1bjFuvZPjQS-m0IFtVcXkZXdH_lr_FrdYt9H' +
    'RUYkshtrMmIUAyGmUnd9zMDB2n0cRDIHAzFVeJUDxkUwVAE7_YGRPdcqMyiBoCO-FBdE-Nceb4h3-FtBP-c_BIwCPTjb9o0Sbdcd' +
    'REEMJMyZBH8ySWMVi1gPD9yxi-aQpGbSv_F9N4IZAxscj5g-NJsUPbjk29-s7LJAGb15wEBtXphVCgyy53CoIKLHHeJHXex45Uz9a' +
    'KZSRSInZI-wjsY0yu3cT4_aQ3i1o-tiE-F8Ios61EKgyIQ4CWao8PFMj8TTnp';
  RFC7520_56_TAG = 'vbb32Xvllea2OtmHAdccRQ';

  // The header of RFC7520_56_HEADER with the members in another order
  RFC7520_56_HEADER_REORDERED = '{"enc":"A128GCM","alg":"dir","kid":"77c7e2b8-6e13-45cf-8672-617b5b45243a"}';

  JWE_DECRYPTION_FAILED = 'JWE decryption failed';

function RFC7520_56_Token: string;
begin
  Result := RFC7520_56_HEADER + '..' + RFC7520_56_IV + '.' + RFC7520_56_CIPHERTEXT + '.' + RFC7520_56_TAG;
end;

// RFC 7520 Figure 72. The two U+2013 EN DASHes are written as character codes
// (CLAUDE.md: no non-ASCII in string literals)
function RFC7520_Plaintext: string;
begin
  Result :=
    'You can trust us to stick with you through thick and ' +
    'thin' + #$2013 + 'to the bitter end. And you can trust us to ' +
    'keep any secret of yours' + #$2013 + 'closer than you keep it ' +
    'yourself. But you cannot trust us to let you face trouble ' +
    'alone, and go off without a word. We are your friends, Frodo.';
end;

function RFC7520Key: TJOSEBytes;
begin
  Result := TBase64.URLDecode(RFC7520_56_KEY);
end;

function ReplacePart(const AToken: string; AIndex: Integer; const AValue: string): string;
var
  LParts: TArray<string>;
begin
  LParts := AToken.Split(['.']);
  LParts[AIndex] := AValue;
  Result := string.Join('.', LParts);
end;

function FlipPartBit(const AToken: string; AIndex: Integer): string;
var
  LBytes: TBytes;
begin
  LBytes := TBase64.URLDecode(AToken.Split(['.'])[AIndex]).AsBytes;
  LBytes[0] := LBytes[0] xor $01;
  Result := ReplacePart(AToken, AIndex, TBase64.URLEncode(LBytes).AsString);
end;

// Parses AToken into a fresh TJWE and decrypts its payload with AKey. Returns
// the message of the EJOSEException raised, or '' when it decrypted
function DecryptError(const AToken: string; const AKey: TJOSEBytes): string;
var
  LToken: TJWT;
  LJWE: TJWE;
  LKey: TJWK;
begin
  Result := '';
  LKey := TJWK.Create(AKey);
  LToken := TJWT.Create;
  LJWE := TJWE.Create(LToken);
  try
    try
      LJWE.CompactToken := AToken;
      LJWE.DecryptPayload(LKey);
    except
      on E: EJOSEException do
        Result := E.Message;
    end;
  finally
    LJWE.Free;
    LToken.Free;
    LKey.Free;
  end;
end;

{ TJWETokenTestBase }

procedure TJWETokenTestBase.RFC7520_DirA128GCM_Decrypts;
var
  LToken: TJWT;
  LJWE: TJWE;
  LKey: TJWK;
begin
  LKey := TJWK.Create(RFC7520Key);
  LToken := TJWT.Create;
  LJWE := TJWE.Create(LToken);
  try
    LJWE.CompactToken := RFC7520_56_Token;

    Assert.AreEqual('dir', LJWE.Header.Algorithm);
    Assert.AreEqual('A128GCM', LJWE.Header.Encryption);
    Assert.AreEqual('77c7e2b8-6e13-45cf-8672-617b5b45243a', LJWE.Header.KeyID);
    Assert.IsTrue(LJWE.EncryptedKey.IsEmpty);

    Assert.AreEqual(RFC7520_Plaintext, LJWE.DecryptPayload(LKey).AsString);
    Assert.AreEqual(RFC7520_Plaintext, LJWE.Payload.AsString);
  finally
    LJWE.Free;
    LToken.Free;
    LKey.Free;
  end;
end;

procedure TJWETokenTestBase.RFC7520_DirA128GCM_ReserializesUnchanged;
var
  LToken: TJWT;
  LJWE: TJWE;
begin
  LToken := TJWT.Create;
  LJWE := TJWE.Create(LToken);
  try
    LJWE.CompactToken := RFC7520_56_Token;
    Assert.AreEqual(RFC7520_56_Token, LJWE.CompactToken.AsString);
    Assert.AreEqual(RFC7520_56_HEADER, LJWE.ProtectedHeader.AsString, 'Part 0 must be kept verbatim');
  finally
    LJWE.Free;
    LToken.Free;
  end;
end;

procedure TJWETokenTestBase.Dir_ClaimsRoundTrip(AEnc: TJOSEEncryptionAlgorithmId);
var
  LKey: TJWK;
  LToken, LReadToken: TJWT;
  LJWE, LReadJWE: TJWE;
  LCompact: TJOSEBytes;
begin
  LKey := TJWK.Create(TJOSEBytes.RandomBytes(AEnc.CEKLength));
  LToken := TJWT.Create;
  LReadToken := TJWT.Create;
  LJWE := TJWE.Create(LToken);
  LReadJWE := TJWE.Create(LReadToken);
  try
    LToken.Claims.Subject := 'alice';
    LToken.Claims.Issuer := 'delphi-jose-jwt';
    LCompact := LJWE.Encrypt(LKey, TJOSEAlgorithmId.Dir, AEnc);

    Assert.AreEqual('dir', LToken.Header.Algorithm, 'The token header gets the final header');
    Assert.IsTrue(LJWE.EncryptedKey.IsEmpty, '"dir" has an empty Encrypted Key');

    LReadJWE.CompactToken := LCompact;
    LReadJWE.Decrypt(LKey);

    Assert.AreEqual(AEnc.AsString, LReadJWE.Header.Encryption);
    Assert.AreEqual('alice', LReadToken.Claims.Subject);
    Assert.AreEqual('delphi-jose-jwt', LReadToken.Claims.Issuer);
  finally
    LReadJWE.Free;
    LJWE.Free;
    LReadToken.Free;
    LToken.Free;
    LKey.Free;
  end;
end;

procedure TJWETokenTestBase.Dir_EmptyPayloadRoundTrips;
var
  LKey: TJWK;
  LToken: TJWT;
  LJWE: TJWE;
  LCompact: TJOSEBytes;
begin
  LKey := TJWK.Create(TJOSEBytes.RandomBytes(32));
  LToken := TJWT.Create;
  LJWE := TJWE.Create(LToken);
  try
    LCompact := LJWE.EncryptPayload(LKey, TJOSEAlgorithmId.Dir, TJOSEEncryptionAlgorithmId.A256GCM, TJOSEBytes.Empty);
    Assert.IsTrue(LJWE.Ciphertext.IsEmpty);
    Assert.AreEqual('', DecryptError(LCompact.AsString, LKey.Key));
  finally
    LJWE.Free;
    LToken.Free;
    LKey.Free;
  end;
end;

procedure TJWETokenTestBase.Encrypt_KeepsTheTokenHeader;
var
  LKey: TJWK;
  LToken, LReadToken: TJWT;
  LJWE, LReadJWE: TJWE;
begin
  LKey := TJWK.Create(TJOSEBytes.RandomBytes(16));
  LToken := TJWT.Create;
  LReadToken := TJWT.Create;
  LJWE := TJWE.Create(LToken);
  LReadJWE := TJWE.Create(LReadToken);
  try
    LToken.Header.KeyID := 'key-1';
    LReadJWE.CompactToken := LJWE.Encrypt(LKey, TJOSEAlgorithmId.Dir, TJOSEEncryptionAlgorithmId.A128GCM);

    Assert.AreEqual('key-1', LReadJWE.Header.KeyID);
    Assert.AreEqual('JWT', LReadJWE.Header.HeaderType);
    Assert.AreEqual('key-1', LReadToken.Header.KeyID, 'The parsed token header is filled too');
  finally
    LReadJWE.Free;
    LJWE.Free;
    LReadToken.Free;
    LToken.Free;
    LKey.Free;
  end;
end;

procedure TJWETokenTestBase.Encrypt_IsRandomized;
var
  LKey: TJWK;
  LToken: TJWT;
  LJWE: TJWE;
  LFirst, LSecond: string;
begin
  LKey := TJWK.Create(TJOSEBytes.RandomBytes(32));
  LToken := TJWT.Create;
  LJWE := TJWE.Create(LToken);
  try
    LToken.Claims.Subject := 'alice';
    LFirst := LJWE.Encrypt(LKey, TJOSEAlgorithmId.Dir, TJOSEEncryptionAlgorithmId.A256GCM).AsString;
    LSecond := LJWE.Encrypt(LKey, TJOSEAlgorithmId.Dir, TJOSEEncryptionAlgorithmId.A256GCM).AsString;

    Assert.AreNotEqual(LFirst.Split(['.'])[2], LSecond.Split(['.'])[2], 'A fresh IV every time');
    Assert.AreNotEqual(LFirst.Split(['.'])[3], LSecond.Split(['.'])[3]);
  finally
    LJWE.Free;
    LToken.Free;
    LKey.Free;
  end;
end;

procedure TJWETokenTestBase.Dir_EncryptRejectsWrongKeyLength(AKeyLength: Integer);
var
  LKey: TJWK;
  LToken: TJWT;
  LJWE: TJWE;
  LMessage: string;
begin
  LKey := TJWK.Create(TJOSEBytes.RandomBytes(AKeyLength));
  LToken := TJWT.Create;
  LJWE := TJWE.Create(LToken);
  try
    // A256GCM needs exactly 32 bytes: never truncated, never padded, and the
    // error names the problem (encryption is not an oracle)
    LMessage := '';
    try
      LJWE.Encrypt(LKey, TJOSEAlgorithmId.Dir, TJOSEEncryptionAlgorithmId.A256GCM);
    except
      on E: EJOSEException do
        LMessage := E.Message;
    end;
    Assert.Contains(LMessage, '"dir" key');
  finally
    LJWE.Free;
    LToken.Free;
    LKey.Free;
  end;
end;

procedure TJWETokenTestBase.ReorderedProtectedHeader_IsRejected;
var
  LToken: string;
begin
  LToken := ReplacePart(RFC7520_56_Token, 0, TBase64.URLEncode(RFC7520_56_HEADER_REORDERED).AsString);

  // The same header members, so the token parses and picks the same
  // algorithms, but the AAD differs and the tag check fails
  Assert.AreEqual(JWE_DECRYPTION_FAILED, DecryptError(LToken, RFC7520Key));
  Assert.AreEqual('', DecryptError(RFC7520_56_Token, RFC7520Key), 'The original still decrypts');
end;

procedure TJWETokenTestBase.TamperedPart_IsRejected(APart: Integer);
var
  LToken: string;
begin
  if APart = 1 then
    // "dir" requires it empty
    LToken := ReplacePart(RFC7520_56_Token, 1, 'AAAA')
  else
    LToken := FlipPartBit(RFC7520_56_Token, APart);

  Assert.AreEqual(JWE_DECRYPTION_FAILED, DecryptError(LToken, RFC7520Key));
end;

procedure TJWETokenTestBase.WrongKey_IsRejected;
var
  LKey: TBytes;
begin
  LKey := RFC7520Key.AsBytes;
  LKey[0] := LKey[0] xor $01;
  Assert.AreEqual(JWE_DECRYPTION_FAILED, DecryptError(RFC7520_56_Token, LKey));
end;

procedure TJWETokenTestBase.DecryptionFailuresLookTheSame;
begin
  // Wrong key length, wrong key, bad tag: one message, nothing to tell apart
  Assert.AreEqual(JWE_DECRYPTION_FAILED, DecryptError(RFC7520_56_Token, TJOSEBytes.RandomBytes(32)));
  Assert.AreEqual(JWE_DECRYPTION_FAILED, DecryptError(RFC7520_56_Token, TJOSEBytes.RandomBytes(16)));
  Assert.AreEqual(JWE_DECRYPTION_FAILED, DecryptError(FlipPartBit(RFC7520_56_Token, 4), RFC7520Key));
end;

procedure TJWETokenTestBase.NestedJWT_LeavesClaimsAlone;
const
  INNER = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2ln';
var
  LKey: TJWK;
  LToken, LReadToken: TJWT;
  LJWE, LReadJWE: TJWE;
begin
  LKey := TJWK.Create(TJOSEBytes.RandomBytes(32));
  LToken := TJWT.Create;
  LReadToken := TJWT.Create;
  LJWE := TJWE.Create(LToken);
  LReadJWE := TJWE.Create(LReadToken);
  try
    LToken.Header.SetHeaderParam('cty', 'JWT');
    LReadJWE.CompactToken := LJWE.EncryptPayload(LKey, TJOSEAlgorithmId.Dir,
      TJOSEEncryptionAlgorithmId.A256GCM, INNER);

    LReadJWE.Decrypt(LKey);

    Assert.IsTrue(LReadJWE.Header.IsNestedJWT);
    Assert.AreEqual(INNER, LReadJWE.Payload.AsString, 'The inner JWS is the payload');
    Assert.IsFalse(LReadToken.Claims.HasSubject, 'The claims belong to the inner JWS, not to the JWE');
  finally
    LReadJWE.Free;
    LJWE.Free;
    LReadToken.Free;
    LToken.Free;
    LKey.Free;
  end;
end;

end.
