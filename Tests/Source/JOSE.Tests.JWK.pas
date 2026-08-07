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
{  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.    }
{  See the License for the specific language governing permissions and        }
{  limitations under the License.                                             }
{                                                                              }
{******************************************************************************}
unit JOSE.Tests.JWK;

interface

uses
  System.SysUtils, System.Rtti, DUnitX.TestFramework,

  JOSE.Types.Bytes,
  JOSE.Core.JWT,
  JOSE.Core.JWA,
  JOSE.Core.JWK,
  JOSE.Core.Builder,
  JOSE.Encoding.Base64,

  JOSE.Tests.Classes;

type
  [TestFixture]
  TTestJWK = class(TTestBase)
  public
    [Setup]
    procedure Setup;
    [TearDown]
    procedure TearDown;

    [Test]
    procedure TestOct_CreateAndJSONRoundTrip;

    [Test]
    procedure TestJWK_FromJSON_RejectsMalformedDocuments;

    [Test]
    procedure TestRSA_Thumbprint_RFC7638Vector;

    [Test]
    procedure TestEC_Thumbprint_Vector;

    [Test]
    procedure TestOct_Thumbprint_Vector;

    [Test]
    procedure TestThumbprint_IncompleteKeyRaises;

    [Test]
    procedure TestFromPEM_RejectsUnreadableData;

    [Test]
    procedure TestFromPEM_UnreadableData_ReportsBothAttempts;

    [Test]
    procedure TestRSA_FromPEM_ToPEM_SignVerify;

    [Test]
    [TestCase('ES256', 'ES256,es256,P256')]
    [TestCase('ES256K', 'ES256K,es256k,secp256k1')]
    [TestCase('ES384', 'ES384,es384,P384')]
    [TestCase('ES512', 'ES512,es512,P521')]
    procedure TestEC_FromPEM_ToPEM_SignVerify(AAlg: TJOSEAlgorithmId; const AKeyFilePrefix: string; ACurve: TJOSEEllipticCurve);

    [Test]
    procedure TestJWKS_RoundTrip;

    [Test]
    procedure TestJWKS_ReflectsEditsAfterAddKey;

    [Test]
    procedure TestJWKS_ReflectsRemovalThroughKeys;

    [Test]
    procedure TestJWKS_FromJSON_RejectsMalformedDocuments;

    [Test]
    procedure TestJWKS_FromJSON_AcceptsEmptyKeysArray;

    [Test]
    procedure TestJWKS_AddKey_RejectsNil;

    [Test]
    procedure TestJWKS_FindByKid_EmptyKidNeverMatches;
  end;

implementation

uses
  System.IOUtils;

procedure TTestJWK.Setup;
begin
end;

procedure TTestJWK.TearDown;
begin
end;

procedure TTestJWK.TestOct_CreateAndJSONRoundTrip;
var
  LJWK, LParsed: TJSONWebKey;
  LJson: string;
begin
  LJWK := TJSONWebKey.CreateOct('my-shared-secret-0123456789');
  try
    Assert.AreEqual(TJOSEKeyType.Oct, LJWK.Kty);
    Assert.IsTrue(LJWK.IsPrivate);
    Assert.AreEqual('my-shared-secret-0123456789', LJWK.K.AsString);

    LJson := LJWK.ToJSON;
  finally
    LJWK.Free;
  end;

  LParsed := TJSONWebKey.FromJSON(LJson);
  try
    Assert.AreEqual(TJOSEKeyType.Oct, LParsed.Kty);
    Assert.AreEqual('my-shared-secret-0123456789', LParsed.K.AsString);
  finally
    LParsed.Free;
  end;
end;

procedure TTestJWK.TestRSA_Thumbprint_RFC7638Vector;
const
  // RFC 7638 Appendix A.1 worked example
  N = '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw';
  E = 'AQAB';
  EXPECTED_THUMBPRINT = 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs';
var
  LJWK: TJSONWebKey;
begin
  LJWK := TJSONWebKey.CreateRSAPublic(TBase64.URLDecode(N), TBase64.URLDecode(E));
  try
    Assert.AreEqual(EXPECTED_THUMBPRINT, LJWK.Thumbprint.AsString);
  finally
    LJWK.Free;
  end;
end;

procedure TTestJWK.TestJWK_FromJSON_RejectsMalformedDocuments;

  procedure CheckRaises(const AJson, AWhy: string);
  begin
    Assert.WillRaise(
      procedure
      begin
        TJSONWebKey.FromJSON(AJson).Free;
      end,
      EJOSEJWKException, AWhy + ': ' + AJson);
  end;

begin
  CheckRaises('not json', 'Malformed JSON');

  // Well-formed JSON that is not an object: these used to escape as EInvalidCast, leaking the
  // parsed value.
  CheckRaises('[]', 'A JSON array is not a JWK');
  CheckRaises('123', 'A JSON number is not a JWK');
  CheckRaises('"a string"', 'A JSON string is not a JWK');

  // RFC 7517 4.1: [kty] is required and has to be one this library knows.
  CheckRaises('{}', 'Missing [kty]');
  CheckRaises('{"use":"sig"}', 'Missing [kty]');
  CheckRaises('{"kty":"XYZ"}', 'Unrecognized [kty]');
end;

procedure TTestJWK.TestEC_Thumbprint_Vector;
const
  // es256-private.pem, whose public point is
  //   x = a938f2836cfae62fb36f25195bc050f8af3b0cdb080916841fb172ed19b732c7
  //   y = 97cbd22d48241455e25bb4eea4614034d26c7b6caa02d6cc79b1bb451319d83d
  // giving the RFC 7638 canonical form
  //   {"crv":"P-256","kty":"EC","x":"qTjyg2z65i-zbyUZW8BQ-K87DNsICRaEH7Fy7Rm3Msc",
  //    "y":"l8vSLUgkFFXiW7TupGFANNJse2yqAtbMebG7RRMZ2D0"}
  EXPECTED_THUMBPRINT = '2f6OViCVGhmX1WmwiXSQ-K66UWtUtCKjvC8YMI9yv5A';
var
  LJWK: TJSONWebKey;
begin
  LJWK := TJSONWebKey.FromPEM(TFile.ReadAllBytes(TPath.Combine(FKeysPath, 'es256-private.pem')));
  try
    // RFC 7638 hashes the public members only, so the private key's thumbprint is its public
    // twin's.
    Assert.AreEqual(EXPECTED_THUMBPRINT, LJWK.Thumbprint.AsString);
  finally
    LJWK.Free;
  end;
end;

procedure TTestJWK.TestOct_Thumbprint_Vector;
const
  // Canonical form {"k":"bXktc2hhcmVkLXNlY3JldC0wMTIzNDU2Nzg5","kty":"oct"}
  EXPECTED_THUMBPRINT = '3sA40wYq1zJmPWHN9axHbLnbvNigRxfiwkBrjjdjWgI';
var
  LJWK: TJSONWebKey;
begin
  LJWK := TJSONWebKey.CreateOct('my-shared-secret-0123456789');
  try
    Assert.AreEqual(EXPECTED_THUMBPRINT, LJWK.Thumbprint.AsString);
  finally
    LJWK.Free;
  end;
end;

procedure TTestJWK.TestThumbprint_IncompleteKeyRaises;

  procedure CheckRaises(const AJson: string);
  var
    LJWK: TJSONWebKey;
  begin
    LJWK := TJSONWebKey.FromJSON(AJson);
    try
      // An absent member used to base64url-encode as "", producing a stable but meaningless
      // thumbprint shared by every other incomplete key of the same type.
      Assert.WillRaise(
        procedure
        begin
          LJWK.Thumbprint;
        end,
        EJOSEJWKException,
        'Thumbprint should reject the incomplete key ' + AJson);
    finally
      LJWK.Free;
    end;
  end;

begin
  CheckRaises('{"kty":"RSA"}');
  CheckRaises('{"kty":"RSA","n":"AQAB"}');
  CheckRaises('{"kty":"RSA","e":"AQAB"}');
  CheckRaises('{"kty":"EC","crv":"P-256"}');
  CheckRaises('{"kty":"EC","crv":"P-256","x":"AQAB"}');
  CheckRaises('{"kty":"EC","x":"AQAB","y":"AQAB"}');
  CheckRaises('{"kty":"oct"}');
end;

procedure TTestJWK.TestFromPEM_RejectsUnreadableData;

  procedure CheckRaises(const APem: TJOSEBytes; const AWhy: string);
  begin
    // EJOSEJWKException, not whatever the second reader happened to raise: input neither reader
    // recognises is a JWK-level failure, not an EC-specific one.
    Assert.WillRaise(
      procedure
      begin
        TJSONWebKey.FromPEM(APem).Free;
      end,
      EJOSEJWKException, AWhy);
  end;

begin
  CheckRaises('', 'Empty data');
  CheckRaises('not a pem at all', 'Data that is not PEM');
  CheckRaises(
    '-----BEGIN PUBLIC KEY-----'#13#10 +
    'bm90IGEga2V5'#13#10 +
    '-----END PUBLIC KEY-----'#13#10,
    'PEM framing around a body that is not a key');
  CheckRaises(
    TFile.ReadAllBytes(TPath.Combine(TPath.Combine(FKeysPath, 'cert'), 'rsa-x509.pem')),
    'An X.509 certificate is not a bare key PEM');
end;

procedure TTestJWK.TestFromPEM_UnreadableData_ReportsBothAttempts;
var
  LMessage: string;
begin
  LMessage := '';
  try
    TJSONWebKey.FromPEM('not a pem at all').Free;
  except
    on E: EJOSEJWKException do
      LMessage := E.Message;
  end;

  // The RSA attempt's reason used to be discarded, leaving only the EC reader's complaint -
  // which for genuinely-RSA-but-malformed input says the opposite of what is wrong.
  Assert.IsTrue(LMessage <> '', 'FromPEM should have raised EJOSEJWKException');
  Assert.IsTrue(Pos('RSA', LMessage) > 0, 'The error should mention the RSA attempt: ' + LMessage);
  Assert.IsTrue(Pos('EC', LMessage) > 0, 'The error should mention the EC attempt: ' + LMessage);
end;

procedure TTestJWK.TestRSA_FromPEM_ToPEM_SignVerify;
var
  LPem: TBytes;
  LJWK: TJSONWebKey;
  LKeyPair: TKeyPair;
  LToken, LVerified: TJWT;
  LCompact: TJOSEBytes;
begin
  LPem := TFile.ReadAllBytes(TPath.Combine(FKeysPath, 'rsa-private.pem'));

  LJWK := TJSONWebKey.FromPEM(LPem);
  try
    Assert.AreEqual(TJOSEKeyType.RSA, LJWK.Kty);
    Assert.IsTrue(LJWK.IsPrivate);
    Assert.IsFalse(LJWK.N.IsEmpty);
    Assert.IsFalse(LJWK.E.IsEmpty);

    LKeyPair := LJWK.ToKeyPair;
    try
      LToken := TJWT.Create;
      try
        LToken.Claims.Subject := 'jwk-rsa-roundtrip';
        LCompact := TJOSE.SerializeCompact(LKeyPair.PrivateKey, TJOSEAlgorithmId.RS256, LToken);
      finally
        LToken.Free;
      end;

      LVerified := TJOSE.Verify(LKeyPair.PublicKey, LCompact);
      try
        Assert.AreEqual('jwk-rsa-roundtrip', LVerified.Claims.Subject);
      finally
        LVerified.Free;
      end;
    finally
      LKeyPair.Free;
    end;
  finally
    LJWK.Free;
  end;
end;

procedure TTestJWK.TestEC_FromPEM_ToPEM_SignVerify(AAlg: TJOSEAlgorithmId; const AKeyFilePrefix: string;
  ACurve: TJOSEEllipticCurve);
var
  LPem: TBytes;
  LJWK: TJSONWebKey;
  LKeyPair: TKeyPair;
  LToken, LVerified: TJWT;
  LCompact: TJOSEBytes;
begin
  LPem := TFile.ReadAllBytes(TPath.Combine(FKeysPath, AKeyFilePrefix + '-private.pem'));

  LJWK := TJSONWebKey.FromPEM(LPem);
  try
    Assert.AreEqual(TJOSEKeyType.EC, LJWK.Kty);
    Assert.AreEqual(ACurve, LJWK.Crv);
    Assert.IsTrue(LJWK.IsPrivate);
    Assert.IsFalse(LJWK.X.IsEmpty);
    Assert.IsFalse(LJWK.Y.IsEmpty);

    LKeyPair := LJWK.ToKeyPair;
    try
      LToken := TJWT.Create;
      try
        LToken.Claims.Subject := 'jwk-ec-roundtrip';
        LCompact := TJOSE.SerializeCompact(LKeyPair.PrivateKey, AAlg, LToken);
      finally
        LToken.Free;
      end;

      LVerified := TJOSE.Verify(LKeyPair.PublicKey, LCompact);
      try
        Assert.AreEqual('jwk-ec-roundtrip', LVerified.Claims.Subject);
      finally
        LVerified.Free;
      end;
    finally
      LKeyPair.Free;
    end;
  finally
    LJWK.Free;
  end;
end;

procedure TTestJWK.TestJWKS_RoundTrip;
var
  LSet, LParsed: TJSONWebKeySet;
  LKey1, LKey2: TJSONWebKey;
  LFound: TJSONWebKey;
  LJson: string;
begin
  LSet := TJSONWebKeySet.Create;
  try
    LKey1 := TJSONWebKey.CreateOct('secret-one');
    LKey1.Kid := 'key-one';
    LSet.AddKey(LKey1);

    LKey2 := TJSONWebKey.CreateRSAPublic(TBase64.URLDecode('0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78L'), TBase64.URLDecode('AQAB'));
    LKey2.Kid := 'key-two';
    LSet.AddKey(LKey2);

    Assert.AreEqual<Integer>(2, LSet.Keys.Count);

    LJson := LSet.ToJSON;
  finally
    LSet.Free;
  end;

  LParsed := TJSONWebKeySet.FromJSON(LJson);
  try
    Assert.AreEqual<Integer>(2, LParsed.Keys.Count);

    LFound := LParsed.FindByKid('key-one');
    Assert.IsNotNull(LFound, 'key-one should be found in the parsed JWKS');
    Assert.AreEqual(TJOSEKeyType.Oct, LFound.Kty);
    Assert.AreEqual('secret-one', LFound.K.AsString);

    LFound := LParsed.FindByKid('key-two');
    Assert.IsNotNull(LFound, 'key-two should be found in the parsed JWKS');
    Assert.AreEqual(TJOSEKeyType.RSA, LFound.Kty);
  finally
    LParsed.Free;
  end;
end;

procedure TTestJWK.TestJWKS_ReflectsEditsAfterAddKey;
var
  LSet: TJSONWebKeySet;
  LKey: TJSONWebKey;
begin
  LSet := TJSONWebKeySet.Create;
  try
    LKey := TJSONWebKey.CreateOct('secret-one');
    LKey.Kid := 'original';
    LSet.AddKey(LKey);

    // Keys hands out live, mutable keys, so the set cannot snapshot its JSON at AddKey time.
    LKey.Kid := 'edited';

    Assert.IsTrue(Pos('"edited"', LSet.ToJSON) > 0,
      'ToJSON should reflect a kid changed after AddKey');
    Assert.IsTrue(Pos('"original"', LSet.ToJSON) = 0,
      'ToJSON should not still carry the kid the key had when it was added');
  finally
    LSet.Free;
  end;
end;

procedure TTestJWK.TestJWKS_ReflectsRemovalThroughKeys;
var
  LSet: TJSONWebKeySet;
  LKey: TJSONWebKey;
begin
  LSet := TJSONWebKeySet.Create;
  try
    LKey := TJSONWebKey.CreateOct('secret-one');
    LKey.Kid := 'removed-later';
    LSet.AddKey(LKey);

    LKey := TJSONWebKey.CreateOct('secret-two');
    LKey.Kid := 'kept';
    LSet.AddKey(LKey);

    // Keys is the source of truth, including when it is mutated directly rather than via AddKey.
    LSet.Keys.Delete(0);

    Assert.AreEqual<Integer>(1, LSet.Keys.Count);
    Assert.IsTrue(Pos('"removed-later"', LSet.ToJSON) = 0,
      'ToJSON should reflect a key removed through Keys');
    Assert.IsTrue(Pos('"kept"', LSet.ToJSON) > 0,
      'ToJSON should still carry the remaining key');
  finally
    LSet.Free;
  end;
end;

procedure TTestJWK.TestJWKS_FromJSON_RejectsMalformedDocuments;

  procedure CheckRaises(const AJson, AWhy: string);
  begin
    Assert.WillRaise(
      procedure
      begin
        TJSONWebKeySet.FromJSON(AJson).Free;
      end,
      EJOSEJWKException, AWhy + ': ' + AJson);
  end;

begin
  // Not a JSON object at all.
  CheckRaises('not json', 'Malformed JSON');
  CheckRaises('[]', 'A JSON array is not a JWKS document');
  CheckRaises('123', 'A JSON number is not a JWKS document');

  // RFC 7517 5: [keys] is required, and it has to be an array.
  CheckRaises('{}', 'Missing [keys]');
  CheckRaises('{"keys":{}}', '[keys] is an object, not an array');
  CheckRaises('{"keys":"nope"}', '[keys] is a string, not an array');

  // Elements have to be JWK objects.
  CheckRaises('{"keys":[1,2]}', '[keys] holds numbers, not JWK objects');
  CheckRaises('{"keys":[{"kty":"XYZ"}]}', 'Unrecognized [kty]');
  CheckRaises('{"keys":[{"use":"sig"}]}', 'Missing [kty]');
end;

procedure TTestJWK.TestJWKS_FromJSON_AcceptsEmptyKeysArray;
var
  LSet: TJSONWebKeySet;
begin
  // A JWKS with no keys is a valid document - only an absent or non-array [keys] is malformed.
  LSet := TJSONWebKeySet.FromJSON('{"keys":[]}');
  try
    Assert.AreEqual<Integer>(0, LSet.Keys.Count);
  finally
    LSet.Free;
  end;
end;

procedure TTestJWK.TestJWKS_AddKey_RejectsNil;
var
  LSet: TJSONWebKeySet;
begin
  LSet := TJSONWebKeySet.Create;
  try
    // Rejected at the call, not later inside the JSON synchronisation.
    Assert.WillRaise(
      procedure
      begin
        LSet.AddKey(nil);
      end,
      EJOSEJWKException);
    Assert.AreEqual<Integer>(0, LSet.Keys.Count);
  finally
    LSet.Free;
  end;
end;

procedure TTestJWK.TestJWKS_FindByKid_EmptyKidNeverMatches;
var
  LSet: TJSONWebKeySet;
  LKey: TJSONWebKey;
begin
  LSet := TJSONWebKeySet.Create;
  try
    // Carries no [kid] at all, so its Kid property reports ''.
    LSet.AddKey(TJSONWebKey.CreateOct('unidentified'));

    LKey := TJSONWebKey.CreateOct('identified');
    LKey.Kid := 'the-kid';
    LSet.AddKey(LKey);

    // The empty term is what a JWS header with no [kid] yields. Matching it against the
    // unidentified key would silently pick a key by position rather than by identity.
    Assert.IsNull(LSet.FindByKid(''),
      'An empty kid should not match the key that merely has no kid of its own');
    Assert.IsNull(LSet.FindByKid('absent'),
      'An unknown kid should not match anything');

    Assert.IsNotNull(LSet.FindByKid('the-kid'),
      'A named key should still be found by its kid');
    Assert.AreEqual('identified', LSet.FindByKid('the-kid').K.AsString);
  finally
    LSet.Free;
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TTestJWK);

end.
