{******************************************************************************}
{                                                                              }
{  Delphi JOSE Library                                                         }
{  Copyright (c) 2015 Paolo Rossi                                              }
{  https://github.com/paolo-rossi/delphi-jose-jwt                              }
{                                                                              }
{******************************************************************************}
{                                                                              }
{  Licensed under the Apache License, Version 2.0 (the "License");             }
{  you may not use this file except in compliance with the License.            }
{  You may obtain a copy of the License at                                     }
{                                                                              }
{      http://www.apache.org/licenses/LICENSE-2.0                              }
{                                                                              }
{  Unless required by applicable law or agreed to in writing, software         }
{  distributed under the License is distributed on an "AS IS" BASIS,           }
{  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.    }
{  See the License for the specific language governing permissions and         }
{  limitations under the License.                                              }
{                                                                              }
{******************************************************************************}

unit JOSE.Providers.CryptoLib;

{$I ..\JOSE.inc}

interface

uses
  System.SysUtils,
  JOSE.Types.Bytes,
  JOSE.Providers.Interfaces,
  JOSE.Crypto.Algorithms,
  ClpIAsymmetricKeyParameter,
  ClpIAsn1Objects;

type
  TCryptoLibBase64Provider = class(TInterfacedObject, IJOSEBase64Provider)
  public
    function Encode(const ASource: TJOSEBytes): TJOSEBytes;
    function Decode(const ASource: TJOSEBytes): TJOSEBytes;
    function TryDecode(const ASource: TJOSEBytes): TJOSEBytes;
    function URLEncode(const ASource: TJOSEBytes): TJOSEBytes;
    function URLDecode(const ASource: TJOSEBytes): TJOSEBytes;
    function TryURLDecode(const ASource: TJOSEBytes): TJOSEBytes;
  end;

  TCryptoLibHmacProvider = class(TInterfacedObject, IJOSEHmacProvider)
  strict private
    function HmacMechanism(AAlg: THMACAlgorithm): string;
  public
    function Sign(const AInput, AKey: TBytes; AAlg: THMACAlgorithm): TBytes;
  end;

  TCryptoLibCertificateProvider = class(TInterfacedObject, IJOSECertificateProvider)
  strict private
    function ExpectedCertPkAlg(AExpected: TJOSECertificatePublicKey): IDerObjectIdentifier;
    function WritePublicKeyPem(const APublicKey: IAsymmetricKeyParameter): TBytes;
  public
    function PublicKeyFromCertificate(const ACertificate: TBytes): TBytes;
    function VerifyCertificate(const ACertificate: TBytes; AExpected: TJOSECertificatePublicKey): Boolean;
  end;

  TCryptoLibRSAProvider = class(TInterfacedObject, IJOSESignerRSA)
  strict private
    FCertificate: IJOSECertificateProvider;
    function PemToPublicKey(const APem: TBytes): IAsymmetricKeyParameter;
    function PemToPrivateKey(const APem: TBytes): IAsymmetricKeyParameter;
    function RsaMechanism(AAlg: TRSAAlgorithm): string;
    function SignWithRsa(const AInput: TBytes; const AKey: IAsymmetricKeyParameter; AAlg: TRSAAlgorithm): TBytes;
    function VerifyWithRsa(const AInput, ASignature: TBytes; const AKey: IAsymmetricKeyParameter; AAlg: TRSAAlgorithm): Boolean;
  public
    constructor Create(const ACertificate: IJOSECertificateProvider);
    function Sign(const AInput, AKey: TBytes; AAlg: TRSAAlgorithm): TBytes;
    function Verify(const AInput, ASignature, AKey: TBytes; AAlg: TRSAAlgorithm): Boolean;
    function VerifyWithCertificate(const AInput, ASignature, ACertificate: TBytes; AAlg: TRSAAlgorithm): Boolean;
    function VerifyPublicKey(const AKey: TBytes): Boolean;
    function VerifyPrivateKey(const AKey: TBytes): Boolean;
  end;

  TCryptoLibECDSAProvider = class(TInterfacedObject, IJOSESignerECDSA)
  strict private
    FCertificate: IJOSECertificateProvider;
    function ExpectedEcCurveOid(AAlg: TECDSAAlgorithm): IDerObjectIdentifier;
    procedure EnsureNamedCurve(const AKey: IAsymmetricKeyParameter; AAlg: TECDSAAlgorithm);
    function EcdsaMechanism(AAlg: TECDSAAlgorithm): string;
    function PemToPublicKey(const APem: TBytes): IAsymmetricKeyParameter;
    function PemToPrivateKey(const APem: TBytes): IAsymmetricKeyParameter;
    function SignWithEc(const AInput: TBytes; const AKey: IAsymmetricKeyParameter; AAlg: TECDSAAlgorithm): TBytes;
    function VerifyWithEc(const AInput, ASignature: TBytes; const AKey: IAsymmetricKeyParameter; AAlg: TECDSAAlgorithm): Boolean;
  public
    constructor Create(const ACertificate: IJOSECertificateProvider);
    function Sign(const AInput, APrivateKey: TBytes; AAlg: TECDSAAlgorithm): TBytes;
    function Verify(const AInput, ASignature, APublicKey: TBytes; AAlg: TECDSAAlgorithm): Boolean;
    function VerifyWithCertificate(const AInput, ASignature, ACertificate: TBytes; AAlg: TECDSAAlgorithm): Boolean;
    function VerifyPublicKey(const AKey: TBytes): Boolean;
    function VerifyPrivateKey(const AKey: TBytes): Boolean;
  end;

  TJOSECryptoLibProviders = class
  public
    /// <summary>Wires CryptoLib implementations into <see cref="JOSE.Providers|TJOSEProviders"/> (Base64, HMAC, cert, RSA, ECDSA).</summary>
    class procedure Register; static;
    /// <summary>Clears <see cref="JOSE.Providers|TJOSEProviders"/> slots previously set by <see cref="Register"/>.</summary>
    class procedure Unregister; static;
  end;

implementation

uses
  JOSE.Providers,
  System.Classes,
  System.Rtti,
  ClpMacUtilities,
  ClpKeyParameter,
  ClpICipherParameters,
  ClpCryptoLibTypes,
  ClpSignerUtilities,
  ClpISigner,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpOpenSslPemReader,
  ClpOpenSslPemWriter,
  ClpX509CertificateParser,
  ClpIX509CertificateParser,
  ClpIX509Certificate,
  ClpIAsymmetricCipherKeyPair,
  ClpIX509Asn1Objects,
  ClpPkcsObjectIdentifiers,
  ClpX9ObjectIdentifiers,
  ClpSecObjectIdentifiers,
  ClpIRsaParameters,
  ClpIECParameters,
  SbpBase64,
  JOSE.Signing.Base;

{ TJOSECryptoLibPem }

type
  TJOSECryptoLibPem = class
  strict private
    /// <summary>First PEM object must be SPKI / public key (not an X.509 certificate).</summary>
    class function ReadPublicKeyMaterial(const APem: TBytes): IAsymmetricKeyParameter; static;
    class function ParsePublicKeyFromDecodedPem(const LVal: TValue): IAsymmetricKeyParameter; static;
  public
    class function ReadPrivateKey(const APem: TBytes): IAsymmetricKeyParameter; static;
    /// <summary>
    /// Reads a public key from PEM. Dispatches on PEM type (e.g. CERTIFICATE vs PUBLIC KEY).
    /// For certificate PEM, <paramref name="ACertProvider"/> must decode and validate <paramref name="ACertExpected"/>.
    /// </summary>
    class function ReadPublicKey(const APem: TBytes; const ACertProvider: IJOSECertificateProvider;
      ACertExpected: TJOSECertificatePublicKey): IAsymmetricKeyParameter; static;
  end;

{ TCryptoLibBase64Provider }

function TCryptoLibBase64Provider.Encode(const ASource: TJOSEBytes): TJOSEBytes;
begin
  Result := SbpBase64.TBase64.Default.Encode(ASource.AsBytes);
end;

function TCryptoLibBase64Provider.Decode(const ASource: TJOSEBytes): TJOSEBytes;
begin
  Result := SbpBase64.TBase64.Default.Decode(Trim(ASource.AsString));
end;

function TCryptoLibBase64Provider.TryDecode(const ASource: TJOSEBytes): TJOSEBytes;
var
  LBuf: TBytes;
  LWritten: Int32;
  LText: string;
begin
  Result.Clear;
  LText := Trim(ASource.AsString);
  if LText = '' then
    Exit;
  SetLength(LBuf, SbpBase64.TBase64.Default.GetSafeByteCountForDecoding(LText));
  if SbpBase64.TBase64.Default.TryDecode(LText, LBuf, LWritten) then
    Result := Copy(LBuf, 0, LWritten);
end;

function TCryptoLibBase64Provider.URLDecode(const ASource: TJOSEBytes): TJOSEBytes;
begin
  Result := SbpBase64.TBase64.Url.Decode(Trim(ASource.AsString));
end;

function TCryptoLibBase64Provider.URLEncode(const ASource: TJOSEBytes): TJOSEBytes;
begin
  Result := SbpBase64.TBase64.Url.Encode(ASource.AsBytes);
end;

function TCryptoLibBase64Provider.TryURLDecode(const ASource: TJOSEBytes): TJOSEBytes;
var
  LBuf: TBytes;
  LWritten: Int32;
  LText: string;
  LBufChars: Integer;
begin
  Result.Clear;
  LText := Trim(ASource.AsString);
  if LText = '' then
    Exit;
  LBufChars := Length(LText);
  SetLength(LBuf, (LBufChars + 3) div 4 * 3);
  if SbpBase64.TBase64.Url.TryDecode(LText, LBuf, LWritten) then
    Result := Copy(LBuf, 0, LWritten);
end;

{ TCryptoLibHmacProvider }

function TCryptoLibHmacProvider.HmacMechanism(AAlg: THMACAlgorithm): string;
begin
  case AAlg of
    THMACAlgorithm.SHA256:
      Result := 'HMAC-SHA256';
    THMACAlgorithm.SHA384:
      Result := 'HMAC-SHA384';
    THMACAlgorithm.SHA512:
      Result := 'HMAC-SHA512';
  else
    raise Exception.Create('[CryptoLib] Unsupported HMAC digest');
  end;
end;

function TCryptoLibHmacProvider.Sign(const AInput, AKey: TBytes; AAlg: THMACAlgorithm): TBytes;
var
  LKeyParam: ICipherParameters;
begin
  try
    LKeyParam := TKeyParameter.Create(AKey);
    Result := TMacUtilities.CalculateMac(HmacMechanism(AAlg), LKeyParam, AInput);
  except
    on E: Exception do
      raise Exception.Create('[CryptoLib] HMAC error: ' + E.Message);
  end;
end;

class function TJOSECryptoLibPem.ReadPrivateKey(const APem: TBytes): IAsymmetricKeyParameter;
var
  LStream: TStringStream;
  LReader: TOpenSslPemReader;
  LVal: TValue;
  LKp: IAsymmetricCipherKeyPair;
begin
  Result := nil;
  LStream := TStringStream.Create(TEncoding.ASCII.GetString(APem));
  try
    LReader := TOpenSslPemReader.Create(LStream);
    try
      LVal := LReader.ReadObject();
      if LVal.IsEmpty then
        raise ESignException.Create('[CryptoLib] Empty PEM object');
      if LVal.TryAsType<IAsymmetricKeyParameter>(Result) and (Result <> nil) then
        Exit;
      if LVal.TryAsType<IAsymmetricCipherKeyPair>(LKp) and (LKp <> nil) then
      begin
        Result := LKp.Private;
        Exit;
      end;
      raise ESignException.Create('[CryptoLib] PEM does not contain a private key');
    finally
      LReader.Free;
    end;
  finally
    LStream.Free;
  end;
end;

class function TJOSECryptoLibPem.ParsePublicKeyFromDecodedPem(const LVal: TValue): IAsymmetricKeyParameter;
var
  LKp: IAsymmetricCipherKeyPair;
begin
  if LVal.TryAsType<IAsymmetricKeyParameter>(Result) and (Result <> nil) then
    Exit;
  if LVal.TryAsType<IAsymmetricCipherKeyPair>(LKp) and (LKp <> nil) then
  begin
    Result := LKp.Public;
    Exit;
  end;
  raise ESignException.Create('[CryptoLib] PEM does not contain a public key');
end;

class function TJOSECryptoLibPem.ReadPublicKeyMaterial(const APem: TBytes): IAsymmetricKeyParameter;
var
  LStream: TStringStream;
  LReader: TOpenSslPemReader;
  LVal: TValue;
  LCert: IX509Certificate;
begin
  LStream := TStringStream.Create(TEncoding.ASCII.GetString(APem));
  try
    LReader := TOpenSslPemReader.Create(LStream);
    try
      LVal := LReader.ReadObject();
      if LVal.IsEmpty then
        raise ESignException.Create('[CryptoLib] Empty PEM object');
      if LVal.TryAsType<IX509Certificate>(LCert) and (LCert <> nil) then
        raise ESignException.Create('[CryptoLib] Expected a public key PEM (SPKI), not an X.509 certificate PEM');
      Result := ParsePublicKeyFromDecodedPem(LVal);
    finally
      LReader.Free;
    end;
  finally
    LStream.Free;
  end;
end;

class function TJOSECryptoLibPem.ReadPublicKey(const APem: TBytes; const ACertProvider: IJOSECertificateProvider;
  ACertExpected: TJOSECertificatePublicKey): IAsymmetricKeyParameter;
var
  LStream: TStringStream;
  LReader: TOpenSslPemReader;
  LVal: TValue;
  LCert: IX509Certificate;
  LSpkiPem: TBytes;
begin
  LStream := TStringStream.Create(TEncoding.ASCII.GetString(APem));
  try
    LReader := TOpenSslPemReader.Create(LStream);
    try
      LVal := LReader.ReadObject();
      if LVal.IsEmpty then
        raise ESignException.Create('[CryptoLib] Empty PEM object');

      if LVal.TryAsType<IX509Certificate>(LCert) and (LCert <> nil) then
      begin
        if ACertProvider = nil then
          raise ESignException.Create('[CryptoLib] Certificate supplied but no IJOSECertificateProvider was configured');
        if not ACertProvider.VerifyCertificate(APem, ACertExpected) then
        begin
          case ACertExpected of
            TJOSECertificatePublicKey.RSA:
              raise ESignException.Create('[CryptoLib] Certificate does not contain an RSA public key');
            TJOSECertificatePublicKey.EC:
              raise ESignException.Create('[CryptoLib] Certificate does not contain an EC public key');
          end;
        end;
        LSpkiPem := ACertProvider.PublicKeyFromCertificate(APem);
        Result := ReadPublicKeyMaterial(LSpkiPem);
        Exit;
      end;

      Result := ParsePublicKeyFromDecodedPem(LVal);
    finally
      LReader.Free;
    end;
  finally
    LStream.Free;
  end;
end;

{ TCryptoLibCertificateProvider }

function TCryptoLibCertificateProvider.ExpectedCertPkAlg(AExpected: TJOSECertificatePublicKey): IDerObjectIdentifier;
begin
  case AExpected of
    TJOSECertificatePublicKey.RSA:
      Result := TPkcsObjectIdentifiers.RsaEncryption;
    TJOSECertificatePublicKey.EC:
      Result := TX9ObjectIdentifiers.IdECPublicKey;
  else
    raise EArgumentException.Create('Unhandled TJOSECertificatePublicKey value');
  end;
end;

function TCryptoLibCertificateProvider.WritePublicKeyPem(const APublicKey: IAsymmetricKeyParameter): TBytes;
var
  LStream: TMemoryStream;
  LWriter: TOpenSslPemWriter;
begin
  LStream := TMemoryStream.Create;
  try
    LWriter := TOpenSslPemWriter.Create(LStream);
    try
      LWriter.WriteObject(TValue.From<IAsymmetricKeyParameter>(APublicKey));
    finally
      LWriter.Free;
    end;
    SetLength(Result, LStream.Size);
    if LStream.Size > 0 then
      Move(LStream.Memory^, Result[0], LStream.Size);
  finally
    LStream.Free;
  end;
end;

function TCryptoLibCertificateProvider.PublicKeyFromCertificate(const ACertificate: TBytes): TBytes;
var
  LParser: IX509CertificateParser;
  LCert: IX509Certificate;
  LPub: IAsymmetricKeyParameter;
begin
  try
    LParser := TX509CertificateParser.Create;
    LCert := LParser.ReadCertificate(ACertificate);
    LPub := LCert.GetPublicKey;
    if LPub = nil then
      raise ESignException.Create('[CryptoLib] Unable to read public key from certificate');
    Result := WritePublicKeyPem(LPub);
  except
    on E: ESignException do
      raise;
    on E: Exception do
      raise ESignException.Create('[CryptoLib] Certificate error: ' + E.Message);
  end;
end;

function TCryptoLibCertificateProvider.VerifyCertificate(const ACertificate: TBytes; AExpected: TJOSECertificatePublicKey): Boolean;
var
  LParser: IX509CertificateParser;
  LCert: IX509Certificate;
  LAlg, LExp: IDerObjectIdentifier;
begin
  try
    LParser := TX509CertificateParser.Create;
    LCert := LParser.ReadCertificate(ACertificate);
    LAlg := LCert.SubjectPublicKeyInfo.Algorithm.Algorithm;
    LExp := ExpectedCertPkAlg(AExpected);
    Result := (LAlg <> nil) and (LExp <> nil) and LAlg.Equals(LExp);
  except
    Result := False;
  end;
end;

{ TCryptoLibRSAProvider }

constructor TCryptoLibRSAProvider.Create(const ACertificate: IJOSECertificateProvider);
begin
  inherited Create;
  FCertificate := ACertificate;
end;

function TCryptoLibRSAProvider.PemToPublicKey(const APem: TBytes): IAsymmetricKeyParameter;
begin
  Result := TJOSECryptoLibPem.ReadPublicKey(APem, FCertificate, TJOSECertificatePublicKey.RSA);
  if not Supports(Result, IRsaKeyParameters) then
    raise ESignException.Create('[CryptoLib] Key is not an RSA key');
end;

function TCryptoLibRSAProvider.PemToPrivateKey(const APem: TBytes): IAsymmetricKeyParameter;
begin
  Result := TJOSECryptoLibPem.ReadPrivateKey(APem);
  if not Supports(Result, IRsaKeyParameters) then
    raise ESignException.Create('[CryptoLib] Key is not an RSA private key');
  if not Result.IsPrivate then
    raise ESignException.Create('[CryptoLib] RSA PEM did not contain a private key');
end;

function TCryptoLibRSAProvider.RsaMechanism(AAlg: TRSAAlgorithm): string;
begin
  case AAlg of
    TRSAAlgorithm.RS256:
      Result := 'SHA-256withRSA';
    TRSAAlgorithm.RS384:
      Result := 'SHA-384withRSA';
    TRSAAlgorithm.RS512:
      Result := 'SHA-512withRSA';
  else
    raise ESignException.Create('[CryptoLib] Unsupported RSA JWS algorithm');
  end;
end;

function TCryptoLibRSAProvider.SignWithRsa(const AInput: TBytes; const AKey: IAsymmetricKeyParameter; AAlg: TRSAAlgorithm): TBytes;
var
  LSigner: ISigner;
  LRnd: ISecureRandom;
begin
  try
    LRnd := TSecureRandom.Create();
    LSigner := TSignerUtilities.InitSigner(RsaMechanism(AAlg), True, AKey, LRnd);
    LSigner.BlockUpdate(AInput, 0, Length(AInput));
    Result := LSigner.GenerateSignature();
  except
    on E: ESignException do
      raise;
    on E: Exception do
      raise ESignException.Create('[CryptoLib] RSA sign error: ' + E.Message);
  end;
end;

function TCryptoLibRSAProvider.VerifyWithRsa(const AInput, ASignature: TBytes; const AKey: IAsymmetricKeyParameter; AAlg: TRSAAlgorithm): Boolean;
var
  LSigner: ISigner;
begin
  try
    LSigner := TSignerUtilities.InitSigner(RsaMechanism(AAlg), False, AKey, nil);
    LSigner.BlockUpdate(AInput, 0, Length(AInput));
    Result := LSigner.VerifySignature(ASignature);
  except
    Result := False;
  end;
end;

function TCryptoLibRSAProvider.Sign(const AInput, AKey: TBytes; AAlg: TRSAAlgorithm): TBytes;
var
  LPriv: IAsymmetricKeyParameter;
begin
  LPriv := PemToPrivateKey(AKey);
  Result := SignWithRsa(AInput, LPriv, AAlg);
end;

function TCryptoLibRSAProvider.Verify(const AInput, ASignature, AKey: TBytes; AAlg: TRSAAlgorithm): Boolean;
var
  LPub: IAsymmetricKeyParameter;
begin
  try
    LPub := PemToPublicKey(AKey);
    Result := VerifyWithRsa(AInput, ASignature, LPub, AAlg);
  except
    Result := False;
  end;
end;

function TCryptoLibRSAProvider.VerifyWithCertificate(const AInput, ASignature, ACertificate: TBytes; AAlg: TRSAAlgorithm): Boolean;
var
  LPub: IAsymmetricKeyParameter;
begin
  try
    LPub := PemToPublicKey(ACertificate);
    Result := VerifyWithRsa(AInput, ASignature, LPub, AAlg);
  except
    Result := False;
  end;
end;

function TCryptoLibRSAProvider.VerifyPublicKey(const AKey: TBytes): Boolean;
begin
  try
    PemToPublicKey(AKey);
    Result := True;
  except
    Result := False;
  end;
end;

function TCryptoLibRSAProvider.VerifyPrivateKey(const AKey: TBytes): Boolean;
begin
  try
    PemToPrivateKey(AKey);
    Result := True;
  except
    Result := False;
  end;
end;

{ TCryptoLibECDSAProvider }

constructor TCryptoLibECDSAProvider.Create(const ACertificate: IJOSECertificateProvider);
begin
  inherited Create;
  FCertificate := ACertificate;
end;

function TCryptoLibECDSAProvider.ExpectedEcCurveOid(AAlg: TECDSAAlgorithm): IDerObjectIdentifier;
begin
  case AAlg of
    TECDSAAlgorithm.ES256:
      Result := TSecObjectIdentifiers.SecP256r1;
    TECDSAAlgorithm.ES256K:
      Result := TSecObjectIdentifiers.SecP256k1;
    TECDSAAlgorithm.ES384:
      Result := TSecObjectIdentifiers.SecP384r1;
    TECDSAAlgorithm.ES512:
      Result := TSecObjectIdentifiers.SecP521r1;
  else
    raise ESignException.Create('[CryptoLib] Unsupported ECDSA JWS algorithm');
  end;
end;

procedure TCryptoLibECDSAProvider.EnsureNamedCurve(const AKey: IAsymmetricKeyParameter; AAlg: TECDSAAlgorithm);
var
  LEc: IECKeyParameters;
  LExp, LHave: IDerObjectIdentifier;
begin
  if not Supports(AKey, IECKeyParameters, LEc) then
    raise ESignException.Create('[CryptoLib] Key is not an EC key');
  LExp := ExpectedEcCurveOid(AAlg);
  LHave := LEc.PublicKeyParamSet;
  if (LHave = nil) or (LExp = nil) or (LHave.ID <> LExp.ID) then
    raise ESignException.Create('[CryptoLib] EC key curve does not match the selected JOSE algorithm');
end;

function TCryptoLibECDSAProvider.EcdsaMechanism(AAlg: TECDSAAlgorithm): string;
begin
  case AAlg of
    TECDSAAlgorithm.ES256, TECDSAAlgorithm.ES256K:
      Result := 'SHA-256withPLAIN-ECDSA';
    TECDSAAlgorithm.ES384:
      Result := 'SHA-384withPLAIN-ECDSA';
    TECDSAAlgorithm.ES512:
      Result := 'SHA-512withPLAIN-ECDSA';
  else
    raise ESignException.Create('[CryptoLib] Unsupported ECDSA JWS algorithm');
  end;
end;

function TCryptoLibECDSAProvider.PemToPublicKey(const APem: TBytes): IAsymmetricKeyParameter;
begin
  Result := TJOSECryptoLibPem.ReadPublicKey(APem, FCertificate, TJOSECertificatePublicKey.EC);
  if not Supports(Result, IECPublicKeyParameters) then
    raise ESignException.Create('[CryptoLib] Key is not an EC public key');
end;

function TCryptoLibECDSAProvider.PemToPrivateKey(const APem: TBytes): IAsymmetricKeyParameter;
begin
  Result := TJOSECryptoLibPem.ReadPrivateKey(APem);
  if not Supports(Result, IECPrivateKeyParameters) then
    raise ESignException.Create('[CryptoLib] Key is not an EC private key');
end;

function TCryptoLibECDSAProvider.SignWithEc(const AInput: TBytes; const AKey: IAsymmetricKeyParameter; AAlg: TECDSAAlgorithm): TBytes;
var
  LSigner: ISigner;
  LRnd: ISecureRandom;
begin
  EnsureNamedCurve(AKey, AAlg);
  try
    LRnd := TSecureRandom.Create();
    LSigner := TSignerUtilities.InitSigner(EcdsaMechanism(AAlg), True, AKey, LRnd);
    LSigner.BlockUpdate(AInput, 0, Length(AInput));
    Result := TBytes(LSigner.GenerateSignature());
  except
    on E: ESignException do
      raise;
    on E: Exception do
      raise ESignException.Create('[CryptoLib] ECDSA sign error: ' + E.Message);
  end;
end;

function TCryptoLibECDSAProvider.VerifyWithEc(const AInput, ASignature: TBytes; const AKey: IAsymmetricKeyParameter; AAlg: TECDSAAlgorithm): Boolean;
var
  LSigner: ISigner;
begin
  try
    EnsureNamedCurve(AKey, AAlg);
    LSigner := TSignerUtilities.InitSigner(EcdsaMechanism(AAlg), False, AKey, nil);
    LSigner.BlockUpdate(AInput, 0, Length(AInput));
    Result := LSigner.VerifySignature(ASignature);
  except
    Result := False;
  end;
end;

function TCryptoLibECDSAProvider.Sign(const AInput, APrivateKey: TBytes; AAlg: TECDSAAlgorithm): TBytes;
var
  LPriv: IAsymmetricKeyParameter;
begin
  LPriv := PemToPrivateKey(APrivateKey);
  Result := SignWithEc(AInput, LPriv, AAlg);
end;

function TCryptoLibECDSAProvider.Verify(const AInput, ASignature, APublicKey: TBytes; AAlg: TECDSAAlgorithm): Boolean;
var
  LPub: IAsymmetricKeyParameter;
begin
  try
    LPub := PemToPublicKey(APublicKey);
    Result := VerifyWithEc(AInput, ASignature, LPub, AAlg);
  except
    Result := False;
  end;
end;

function TCryptoLibECDSAProvider.VerifyWithCertificate(const AInput, ASignature, ACertificate: TBytes; AAlg: TECDSAAlgorithm): Boolean;
var
  LPub: IAsymmetricKeyParameter;
begin
  try
    LPub := PemToPublicKey(ACertificate);
    Result := VerifyWithEc(AInput, ASignature, LPub, AAlg);
  except
    Result := False;
  end;
end;

function TCryptoLibECDSAProvider.VerifyPublicKey(const AKey: TBytes): Boolean;
begin
  try
    PemToPublicKey(AKey);
    Result := True;
  except
    Result := False;
  end;
end;

function TCryptoLibECDSAProvider.VerifyPrivateKey(const AKey: TBytes): Boolean;
begin
  try
    PemToPrivateKey(AKey);
    Result := True;
  except
    Result := False;
  end;
end;

{ TJOSECryptoLibProviders }

class procedure TJOSECryptoLibProviders.Register;
var
  LCert: IJOSECertificateProvider;
begin
  TJOSEProviders.Base64 := TCryptoLibBase64Provider.Create;
  TJOSEProviders.HMAC := TCryptoLibHmacProvider.Create;
  LCert := TCryptoLibCertificateProvider.Create;
  TJOSEProviders.Certificate := LCert;
  TJOSEProviders.RSA := TCryptoLibRSAProvider.Create(LCert);
  TJOSEProviders.ECDSA := TCryptoLibECDSAProvider.Create(LCert);
end;

class procedure TJOSECryptoLibProviders.Unregister;
begin
  TJOSEProviders.Base64 := nil;
  TJOSEProviders.HMAC := nil;
  TJOSEProviders.Certificate := nil;
  TJOSEProviders.RSA := nil;
  TJOSEProviders.ECDSA := nil;
end;

end.
