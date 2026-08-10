{******************************************************************************}
{                                                                              }
{  Delphi JOSE-JWT Library                                                     }
{  Copyright (c) 2015 Paolo Rossi                                              }
{  https://github.com/paolo-rossi/delphi-jose-jwt                              }
{                                                                              }
{  Licensed under the MIT license                                              }
{                                                                              }
{******************************************************************************}
unit JOSE.Tests.JWA.RSA;

interface

uses
  System.Classes, System.Rtti, System.SysUtils, DUnitX.TestFramework,

  JOSE.Types.Bytes,
  JOSE.Encoding.Base64,
  JOSE.Hashing.HMAC,
  JOSE.Crypto.Algorithms,
  JOSE.Core.Base,
  JOSE.Core.JWT,
  JOSE.Core.JWS,
  JOSE.Core.JWK,
  JOSE.Core.JWA,
  JOSE.Signing.Base,
  JOSE.Signing.RSA,

  JOSE.Tests.Classes;

type
  [TestFixture]
  [Category('RSA')]
  TTestJWA = class(TTestBase)
  private const
    COMPACT_PAYLOAD = 'eyJpYXQiOjE1MTYyMzkwMjIsImV4cCI6MTUxNjI0OTAyMiwiaXNzIjoiRGVscGhpIEpPU0UgYW5kIEpXVCBMaWJyYXJ5In0';
    // Same shape as COMPACT_PAYLOAD, one claim value altered.
    TAMPERED_PAYLOAD = 'eyJpYXQiOjE1MTYyMzkwMjIsImV4cCI6OTk5OTk5OTk5OSwiaXNzIjoiRGVscGhpIEpPU0UgYW5kIEpXVCBMaWJyYXJ5In0';
    HEADER_RS256 = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9';
    HEADER_RS384 = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzM4NCJ9';
    HEADER_RS512 = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiJ9';
    SIGN_RS256 =
      'puUywUz6ExPzAX6lDFhQ2kItfxwjVVBQ77gq5uFOkoN3SWSYqgHK02FnyLf4zl57OjTgVZzhSYM2FUPmmuH9UcOikLGpbuv0qd6_bdgFBrWeQbxD_Iup1t4spcADliT9SH-EaEqkQ4UYbVkBj3Xbv7pTF2otKcteU19lcwF8ayKcqCRWK' +
      '8VCXGZKCugle7fVME3FcuECsDa-HnVe4SpXCJ8m8Gt3hWD8S3ui8j5CnxNGMByS4qSLXcmRlg1DqoGjnZp34KRjbI_bnPe8X_VIQ9srJPhMAQ-vBuRSHMaq3Vjo6K1a3RBrN9lK1Z7_so3tq76PgOGYCPGHm7ymnBO2Og';
    SIGN_RS384 =
      'VffJTuXJgSIRjiltPJIAHxYaRipjmi5v7SVwzuTcKlT8GW-r7BdDg4zyMxzVRCFjy9YGmOECIxL1oaj_KV14V-mTHQwTHKDCASVzPPku9NNIEeUJlD-2Klg0--4QsCnBjar6dJQdEewXBJSoumBnE8PXWjV6qX5PuxO7Dv1XSbPDx1qkv' +
      'qO5KZxLkxviMk9WZ8-AYDXVqfxvXIfSUWj9vQx002xPPl66GoTfvzJtB0IuEBLfjPo8ZfcwgDh5ukzwd46bXeAwpCE6LFjle4OXS8FES136MrDWAdmoQAIvys8yOb-SWpaUpaDKeSaKCny1rpLx5QLPzAPZCUdQZ7K-Mw';
    SIGN_RS512 =
      'v5999Qte0ENzgRX1kDLusP8dgTFWX2wcckfYsiDN7SSROAh9Dpx3lNMOd1GnXTTyBoSCn3NzjxsVzqFn2su0oh-eMHa94UBPBZ-6iZrpYLzm1Wy761tideYONq-QoQg492cmp7Jbzu2sZOti3If2xEQYF0dPzGk48weN1d87vG6Sv8UA7' +
      'yWAoAOvKz9UJzURKdRNAVsETVdRBEG6mmPawv1v-N1xljwdJSnLLRmcGYEBZeJLjTWL973asL8I2gEwHzEqmuNp4TE5NBoXg5xAJQ62iwSWNcnPbupmh3SbatwPwVOmHotzDyrCCG_FKwQnmhHC7efRm3L9TizRueBLfA';
    // RSASSA-PSS vectors produced by the OpenSSL CLI over
    //   <header>.<COMPACT_PAYLOAD>
    // with Tests/Keys/rsa-private.pem, salt length = digest length (RFC 7518 3.5):
    //   openssl dgst -shaNNN -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:NN \
    //     -sign rsa-private.pem -binary signing_input
    // PSS is randomised, so these cannot be reproduced by signing again - they exist to prove we
    // can *verify* what another implementation produced.
    HEADER_PS256 = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJQUzI1NiJ9';
    HEADER_PS384 = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJQUzM4NCJ9';
    HEADER_PS512 = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJQUzUxMiJ9';
    SIGN_PS256 =
      'CDIklTimRsc32WC8lQYBMAVpi3JaLQrVivfyqTzcy4wcP_zwDZKDjoNhCgoFdrgGyZlPYNu2R-a1EuRu2ZvI29UuhOGkz1a5uU5LbRebDBW7wiHby4Q0BhGRqclubV1g78SJ1QCUmce70Ax9WDObzFiZTsXP_hfx6m57XvmjNdTwh8-d7ltPT3Rp7GkI4MNmX00B84ZOVnQ_1oYRG6Gw8YT2' +
      '5hIu4C90DsGVUztxAyF1GVzDjR1o4nYWgoT7v-QokwWyihqU9Ypk_MhzoN9iK5I490JY4uAb214WH_XXxz2GMU2osOQbdNv84W6sLD1jRu2L8Neo9oAHYN_4sE2v3g';
    SIGN_PS384 =
      'NZpdK2wq0PLvPtYlIvfyD7Meo4gUEUnmuaHzk8UEF0WbRX-vcj66rwXJuFPaLOL09UngJCKZRBhkSRFfFyNBzwjahJ3Rx5pc1wYooGKEtczXHCEQT7tqD0LsVZE0-5pJxCnse-nULo9vzVa5ckv1tJfZfXCKnCIb-ahKuHjf_jeN8v-J7hA70dTEx_xmJddHtz6h8YXxHaahnQv5DX8PONwX' +
      'wrjCv-vnzxt6_7y5gvVTERj8LaadDuK4xdJb9dzjyav_lzkSlqMckWY4c6RiCuVFDzpOFTA9qkE2ej_vKsuuMlQxLychH_TG7c0pDBpJi-XOar06HFnPp4bNuKdW5Q';
    SIGN_PS512 =
      '33Ebf1qgmGWhseTbF2Cs-vjFL_K8Ek0ZXsqENzUqK9z_8XrsISdqZ87l_nzRppvgOo6suzjiZZgDT6EUTfFdtkKpyS6r09EudnoMxBAw0D_aepIAfB03OpXefOzN6FONDfQvtWDn3MppkIMJP_zl3CnzVaYdY36E0FQwymUXZTIK7fX7o2EJL1Dbt_6DXbgqQLu3-eNgs5d4I8q_8nv_bEx-' +
      'Ox5BbXvgQzwk2t4wPNh5BxcHE9SY3sqaFso0MHOWe1IWadoW-dV6CdM0EeI-8CSyJ-m28uOV-GzdGg_iVaobyuyCglpu4ruuG1MuU8S6hgcChrz0sKb5HIXWhEBRCA';
  private
    FKeys: TKeyPair;
    /// <summary>An unrelated RSA public key, for the "must not verify under the wrong key" tests.</summary>
    FOtherPublicKey: TJWK;
    function SignWith(AAlg: TJOSEAlgorithmId): string;
  public
    [Setup]
    procedure Setup;
    [TearDown]
    procedure TearDown;

    [Test]
    [TestCase('PS256', 'PS256')]
    [TestCase('PS384', 'PS384')]
    [TestCase('PS512', 'PS512')]
    procedure TestPSSSignVerifyRoundTrip(AAlg: TJOSEAlgorithmId);

    [Test]
    [TestCase('PS256', 'PS256')]
    [TestCase('PS384', 'PS384')]
    [TestCase('PS512', 'PS512')]
    procedure TestPSSSignaturesAreNonDeterministic(AAlg: TJOSEAlgorithmId);

    [Test]
    [TestCase('PS256', 'PS256,' + HEADER_PS256 + ',' + SIGN_PS256)]
    [TestCase('PS384', 'PS384,' + HEADER_PS384 + ',' + SIGN_PS384)]
    [TestCase('PS512', 'PS512,' + HEADER_PS512 + ',' + SIGN_PS512)]
    procedure TestPSSVerifyOpenSSLVector(AAlg: TJOSEAlgorithmId; const AHeader, ASignature: string);

    [Test]
    [TestCase('PS256', 'PS256,' + HEADER_PS256 + ',' + SIGN_PS256)]
    [TestCase('PS384', 'PS384,' + HEADER_PS384 + ',' + SIGN_PS384)]
    [TestCase('PS512', 'PS512,' + HEADER_PS512 + ',' + SIGN_PS512)]
    procedure TestPSSRejectsTamperedPayload(AAlg: TJOSEAlgorithmId; const AHeader, ASignature: string);

    [Test]
    procedure TestPSSAndPKCS1SignaturesAreNotInterchangeable;
    [Test]
    [TestCase('TestRSASign256', 'RS256,' + SIGN_RS256)]
    [TestCase('TestRSASign384', 'RS384,' + SIGN_RS384)]
    [TestCase('TestRSASign512', 'RS512,' + SIGN_RS512)]
    procedure TestRSASign(AAlg: TJOSEAlgorithmId; const ASignature: string);

    [Test]
    [TestCase('TestRSAVerify256', 'RS256,' + HEADER_RS256 + ',' + SIGN_RS256)]
    [TestCase('TestRSAVerify384', 'RS384,' + HEADER_RS384 + ',' + SIGN_RS384)]
    [TestCase('TestRSAVerify512', 'RS512,' + HEADER_RS512 + ',' + SIGN_RS512)]
    procedure TestRSAVerify(AAlg: TJOSEAlgorithmId; const AHeader, ASignature: string);

    [Test]
    [TestCase('RS256', HEADER_RS256 + ',' + SIGN_RS256)]
    [TestCase('RS384', HEADER_RS384 + ',' + SIGN_RS384)]
    [TestCase('RS512', HEADER_RS512 + ',' + SIGN_RS512)]
    procedure TestRSARejectsTamperedPayload(const AHeader, ASignature: string);

    [Test]
    [TestCase('RS256', HEADER_RS256 + ',' + SIGN_RS256)]
    [TestCase('RS384', HEADER_RS384 + ',' + SIGN_RS384)]
    [TestCase('RS512', HEADER_RS512 + ',' + SIGN_RS512)]
    procedure TestRSARejectsTamperedSignature(const AHeader, ASignature: string);

    [Test]
    [TestCase('RS256', HEADER_RS256 + ',' + SIGN_RS256)]
    [TestCase('RS384', HEADER_RS384 + ',' + SIGN_RS384)]
    [TestCase('RS512', HEADER_RS512 + ',' + SIGN_RS512)]
    procedure TestRSARejectsWrongKey(const AHeader, ASignature: string);

    [Test]
    procedure TestRSARejectsSwappedHeaderAlgorithm;

    [Test]
    procedure TestRSAPublicKeyIsRejectedAsHmacSecret;
  end;

implementation

uses
  System.DateUtils, System.IOUtils,
  JOSE.Tests.Utils;

procedure TTestJWA.Setup;
var
  LFileName: string;
  LOtherPem: TJOSEBytes;
begin
  FKeys := TKeyPair.Create;

  LFileName := TPath.Combine(FKeysPath, 'rsa-private.pem');
  FKeys.PrivateKey.Key :=  TFile.ReadAllBytes(LFileName);

  LFileName := TPath.Combine(FKeysPath, 'rsa-public.pem');
  FKeys.PublicKey.Key :=  TFile.ReadAllBytes(LFileName);

  LFileName := TPath.Combine(FKeysPath, 'rsa-other-public.pem');
  LOtherPem := TFile.ReadAllBytes(LFileName);
  FOtherPublicKey := TJWK.Create(LOtherPem);
end;

procedure TTestJWA.TearDown;
begin
  FreeAndNil(FOtherPublicKey);
  FreeAndNil(FKeys);
end;

procedure TTestJWA.TestRSASign(AAlg: TJOSEAlgorithmId; const ASignature: string);
var
  LToken: TJWT;
  LSigner: TJWS;
  LSignature, LCompact: string;
begin
  LToken := TJWT.Create;
  try
    LToken.Header.Algorithm := AAlg.AsString;
    LToken.Claims.IssuedAt := UnixToDateTime(1516239022, False);
    LToken.Claims.Expiration := UnixToDateTime(1516249022, False);
    LToken.Claims.Issuer := 'Delphi JOSE and JWT Library';

    LSigner := TJWS.Create(LToken);
    try
      // With this option you can have keys < algorithm length
      LSigner.SkipKeyValidation := True;

      LSigner.Sign(FKeys.PrivateKey, AAlg);
      LCompact := LSigner.CompactToken;
      LSignature := LSigner.Signature;

      Assert.AreEqual(ASignature, LSignature, 'Expected signature doesn''t match calculated signature');
    finally
      LSigner.Free;
    end;
  finally
    LToken.Free;
  end;
end;

function TTestJWA.SignWith(AAlg: TJOSEAlgorithmId): string;
var
  LToken: TJWT;
  LSigner: TJWS;
begin
  LToken := TJWT.Create;
  try
    LToken.Header.Algorithm := AAlg.AsString;
    LToken.Claims.IssuedAt := UnixToDateTime(1516239022, False);
    LToken.Claims.Expiration := UnixToDateTime(1516249022, False);
    LToken.Claims.Issuer := 'Delphi JOSE and JWT Library';

    LSigner := TJWS.Create(LToken);
    try
      LSigner.SkipKeyValidation := True;
      LSigner.Sign(FKeys.PrivateKey, AAlg);
      Result := LSigner.CompactToken;
    finally
      LSigner.Free;
    end;
  finally
    LToken.Free;
  end;
end;

function VerifyCompact(AKey: TJWK; const ACompact: string): Boolean;
var
  LToken: TJWT;
  LSigner: TJWS;
begin
  LToken := TJWT.Create;
  try
    LSigner := TJWS.Create(LToken);
    try
      LSigner.SetKey(AKey);
      LSigner.SkipKeyValidation := True;
      LSigner.CompactToken := ACompact;
      Result := LSigner.VerifySignature;
    finally
      LSigner.Free;
    end;
  finally
    LToken.Free;
  end;
end;

procedure TTestJWA.TestPSSSignVerifyRoundTrip(AAlg: TJOSEAlgorithmId);
begin
  Assert.IsTrue(VerifyCompact(FKeys.PublicKey, SignWith(AAlg)),
    'A PSS token should verify against its own public key');
end;

procedure TTestJWA.TestPSSSignaturesAreNonDeterministic(AAlg: TJOSEAlgorithmId);
var
  LFirst, LSecond: string;
begin
  LFirst := SignWith(AAlg);
  LSecond := SignWith(AAlg);

  // The load-bearing test for this feature. PSS draws a fresh random salt per signature, so two
  // signings of identical input must differ. A provider that quietly fell back to PKCS#1 v1.5 -
  // which is deterministic - would produce two identical tokens and pass every other test here.
  Assert.AreNotEqual(LFirst, LSecond,
    'PSS signatures must differ between signings; identical output means PKCS#1 v1.5 padding');

  Assert.IsTrue(VerifyCompact(FKeys.PublicKey, LFirst), 'First signature should verify');
  Assert.IsTrue(VerifyCompact(FKeys.PublicKey, LSecond), 'Second signature should verify');
end;

procedure TTestJWA.TestPSSVerifyOpenSSLVector(AAlg: TJOSEAlgorithmId; const AHeader, ASignature: string);
begin
  // Signed by the OpenSSL CLI, not by this library - the only test here that proves
  // interoperability rather than self-consistency.
  Assert.IsTrue(
    VerifyCompact(FKeys.PublicKey, AHeader + '.' + COMPACT_PAYLOAD + '.' + ASignature),
    'An OpenSSL-produced PSS signature should verify');
end;

procedure TTestJWA.TestPSSRejectsTamperedPayload(AAlg: TJOSEAlgorithmId; const AHeader, ASignature: string);
begin
  Assert.IsFalse(
    VerifyCompact(FKeys.PublicKey, AHeader + '.' + TAMPERED_PAYLOAD + '.' + ASignature),
    'A PSS signature must not verify over a payload it did not cover');
end;

procedure TTestJWA.TestPSSAndPKCS1SignaturesAreNotInterchangeable;
var
  LPSSToken, LPKCS1Token: string;
  LParts: TArray<string>;
begin
  LPSSToken := SignWith(TJOSEAlgorithmId.PS256);
  LPKCS1Token := SignWith(TJOSEAlgorithmId.RS256);

  // Swap the signatures between the two tokens. Both are RSA-SHA256 over the same claims with the
  // same key and differ only in padding scheme, so this is exactly the confusion that would go
  // unnoticed if a provider ignored the PS/RS distinction.
  LParts := LPSSToken.Split(['.']);
  Assert.IsFalse(
    VerifyCompact(FKeys.PublicKey, LParts[0] + '.' + LParts[1] + '.' + LPKCS1Token.Split(['.'])[2]),
    'A PKCS#1 v1.5 signature must not verify under a PS256 header');

  LParts := LPKCS1Token.Split(['.']);
  Assert.IsFalse(
    VerifyCompact(FKeys.PublicKey, LParts[0] + '.' + LParts[1] + '.' + LPSSToken.Split(['.'])[2]),
    'A PSS signature must not verify under an RS256 header');
end;

procedure TTestJWA.TestRSAVerify(AAlg: TJOSEAlgorithmId; const AHeader, ASignature: string);
var
  LToken: TJWT;
  LSigner: TJWS;
  LCompact: string;
begin
  LToken := TJWT.Create;
  try
    LSigner := TJWS.Create(LToken);
    try
      LSigner.SetKey(FKeys.PublicKey);
      LSigner.SkipKeyValidation := True;
      LCompact := AHeader + '.' + COMPACT_PAYLOAD + '.' + ASignature;
      LSigner.CompactToken := LCompact;

      Assert.IsTrue(LSigner.VerifySignature, 'Signature (RSA) should validate');
    finally
      LSigner.Free;
    end;
  finally
    LToken.Free;
  end;
end;

procedure TTestJWA.TestRSARejectsTamperedPayload(const AHeader, ASignature: string);
begin
  // The counterpart to TestRSAVerify: without this, a VerifySignature that returned True
  // unconditionally would still pass every other RS* test in this fixture.
  Assert.IsFalse(
    VerifyCompact(FKeys.PublicKey, AHeader + '.' + TAMPERED_PAYLOAD + '.' + ASignature),
    'An RS* signature must not verify over a payload it did not cover');
end;

procedure TTestJWA.TestRSARejectsTamperedSignature(const AHeader, ASignature: string);
var
  LTampered: string;
begin
  // Alter the leading base64url character, which carries real signature bits - unlike the trailing
  // one, whose low bits are padding and can change without altering the decoded signature.
  LTampered := ASignature;
  if LTampered[1] = 'A' then
    LTampered[1] := 'B'
  else
    LTampered[1] := 'A';
  Assert.AreNotEqual(ASignature, LTampered, 'The signature should actually have been altered');

  Assert.IsFalse(
    VerifyCompact(FKeys.PublicKey, AHeader + '.' + COMPACT_PAYLOAD + '.' + LTampered),
    'A signature with an altered byte must not verify');
end;

procedure TTestJWA.TestRSARejectsWrongKey(const AHeader, ASignature: string);
begin
  // Right algorithm, right payload, genuinely valid signature - just not this key's.
  Assert.IsFalse(
    VerifyCompact(FOtherPublicKey, AHeader + '.' + COMPACT_PAYLOAD + '.' + ASignature),
    'An RS* signature must not verify under an unrelated public key');
end;

procedure TTestJWA.TestRSARejectsSwappedHeaderAlgorithm;
begin
  // The header is part of the signing input, so re-labelling a token's algorithm has to break its
  // signature. This is the signature-level half of the alg-substitution defence - the other half
  // being the TJOSEConsumer algorithm allowlist.
  Assert.IsFalse(
    VerifyCompact(FKeys.PublicKey, HEADER_RS384 + '.' + COMPACT_PAYLOAD + '.' + SIGN_RS256),
    'An RS256 signature must not verify under an RS384 header');
  Assert.IsFalse(
    VerifyCompact(FKeys.PublicKey, HEADER_RS512 + '.' + COMPACT_PAYLOAD + '.' + SIGN_RS384),
    'An RS384 signature must not verify under an RS512 header');
  Assert.IsFalse(
    VerifyCompact(FKeys.PublicKey, HEADER_RS256 + '.' + COMPACT_PAYLOAD + '.' + SIGN_RS512),
    'An RS512 signature must not verify under an RS256 header');
end;

procedure TTestJWA.TestRSAPublicKeyIsRejectedAsHmacSecret;
var
  LToken: TJWT;
  LJWS: TJWS;
  LSigningInput, LSignature: TJOSEBytes;
  LForged: string;
begin
  // The RS256 -> HS256 substitution attack. The verifier holds an RSA public key; the attacker,
  // who by definition also holds it, re-signs claims of their choosing as HS256 using that key's
  // PEM text as the HMAC secret. Since TJWS takes the algorithm from the token header, only the
  // key check stands between this token and a successful verification.
  LSigningInput := TBase64.URLEncode('{"typ":"JWT","alg":"HS256"}') + '.' +
    TBase64.URLEncode('{"iss":"Delphi JOSE and JWT Library","sub":"attacker"}');
  LSignature := THMAC.Sign(LSigningInput, FKeys.PublicKey.Key, THMACAlgorithm.SHA256);
  LForged := LSigningInput + '.' + TBase64.URLEncode(LSignature.AsBytes);

  LToken := TJWT.Create;
  try
    LJWS := TJWS.Create(LToken);
    try
      LJWS.SetKey(FKeys.PublicKey);
      // Deliberately NOT SkipKeyValidation - that flag opts out of this defence, as documented.
      LJWS.CompactToken := LForged;

      Assert.WillRaise(
        procedure
        begin
          LJWS.VerifySignature;
        end,
        EJOSEException,
        'PEM key material must be refused as an HMAC secret');
    finally
      LJWS.Free;
    end;
  finally
    LToken.Free;
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TTestJWA);

end.

