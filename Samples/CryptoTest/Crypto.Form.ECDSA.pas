{******************************************************************************}
{                                                                              }
{  Delphi JOSE Library                                                         }
{  Copyright (c) 2015-2021 Paolo Rossi                                         }
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

unit Crypto.Form.ECDSA;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Crypto.Utils,

  JOSE.Encoding.Base64,
  JOSE.Signing.ECDSA,
  JOSE.Types.Bytes,
  IdSSLOpenSSLHeaders,
  JOSE.OpenSSL.Headers, Vcl.ExtDlgs;

type
  TfrmCryptoECDSA = class(TForm)
    btnSignECDSA: TButton;
    memoPayload: TMemo;
    memoPrivateKey: TMemo;
    memoSignature: TMemo;
    btnVerify: TButton;
    memoPublicKey: TMemo;
    memoCertificate: TMemo;
    btnCertificate: TButton;
    memoPublicKey2: TMemo;
    btnVerifyPublic: TButton;
    dlgOpenPEMFile: TOpenTextFileDialog;
    Button1: TButton;
    procedure btnCertificateClick(Sender: TObject);
    procedure btnSignECDSAClick(Sender: TObject);
    procedure btnVerifyClick(Sender: TObject);
    procedure btnVerifyPublicClick(Sender: TObject);
    procedure memoCertificateDblClick(Sender: TObject);
    procedure memoPrivateKeyDblClick(Sender: TObject);
    procedure memoPublicKey2DblClick(Sender: TObject);
    procedure memoPublicKeyDblClick(Sender: TObject);
  private
    FFileName: string;
  protected
    function HashFromSignature(const AInput: TBytes): TBytes;

    function ToOctect(AAlg: TECDSAAlgorithm; ASignature: PECDSA_SIG): TBytes;

    function OpenPEMFile(const ATitle: string): string;
    procedure SetFromPEMFile(const ATitle: string; AMemo: TObject);
    function LoadPrivateKey: PEC_KEY;
    function Sanitize(const AText: string): string;
    function Sign(const AInput, AKey: TBytes; AAlg: TECDSAAlgorithm): TBytes;
    function Verify(const AInput, ASignature, AKeyOrCertificate: TBytes; AAlg: TECDSAAlgorithm): Boolean;
  public
    { Public declarations }
  end;

implementation

uses
  JOSE.Core.JWK, JOSE.Core.JWT, JOSE.Core.JWS, System.JSON,
  JOSE.Core.JWA, JOSE.Core.Builder;

{$R *.dfm}

procedure TfrmCryptoECDSA.btnCertificateClick(Sender: TObject);
var
  LCert: TJOSEBytes;
begin
  LCert := Sanitize(memoCertificate.Lines.Text);
  if TECDSA.VerifyCertificate(LCert.AsBytes, JoseSSL.NID_X9_62_id_ecPublicKey) then
    ShowMessage('certificate verified. EC Key detected')
  else
    ShowMessage('certificate not verified')
end;

procedure TfrmCryptoECDSA.btnSignECDSAClick(Sender: TObject);
var
  LInput, LKey, LSignature: TJOSEBytes;
begin
  LInput := Sanitize(memoPayload.Lines.Text);
  LKey := Sanitize(memoPrivateKey.Lines.Text);

  //LSignature := Sign(LInput.AsBytes, LKey.AsBytes, TECDSAAlgorithm.ES256);
  LSignature := TECDSA.Sign(LInput.AsBytes, LKey.AsBytes, TECDSAAlgorithm.ES256);

  memoSignature.Lines.Text := TBase64.URLEncode(LSignature).AsString;
end;

procedure TfrmCryptoECDSA.btnVerifyClick(Sender: TObject);
var
  LInput, LKey: TJOSEBytes;
  LBinarySig: TBytes;
begin
  LBinarySig := TBase64.URLDecode(memoSignature.Lines.Text).AsBytes;
  LInput := Sanitize(memoPayload.Lines.Text);
  LKey := Sanitize(memoPublicKey.Lines.Text);

  // test version
  //if Verify(LInput.AsBytes, LBinarySig, LKey.AsBytes, TECDSAAlgorithm.ES256) then
  if TECDSA.Verify(LInput.AsBytes, LBinarySig, LKey.AsBytes, TECDSAAlgorithm.ES256) then
    ShowMessage('Success!!!')
  else
    ShowMessage('Signature tampered')

end;

procedure TfrmCryptoECDSA.btnVerifyPublicClick(Sender: TObject);
var
  LKey: TJOSEBytes;
begin
  LKey := Sanitize(memoPublicKey2.Lines.Text);
  if TECDSA.VerifyPublicKey(LKey.AsBytes) then
    ShowMessage('key verified')
  else
    ShowMessage('key not verified')
end;

function TfrmCryptoECDSA.HashFromSignature(const AInput: TBytes): TBytes;
var
  LShaLen: Integer;
  AAlg: TECDSAAlgorithm;
begin
  AALg := TECDSAAlgorithm.ES256;

  case AAlg of
    ES256:
    begin
      LShaLen := SHA256_DIGEST_LENGTH;
      SetLength(Result, LShaLen);
      JoseSSL.SHA256(@AInput[0], Length(AInput), @Result[0]);
    end;
    ES384:
    begin
      LShaLen := SHA384_DIGEST_LENGTH;
      SetLength(Result, LShaLen);
      JoseSSL.SHA384(@AInput[0], Length(AInput), @Result[0]);
    end;
    ES512:
    begin
      LShaLen := SHA512_DIGEST_LENGTH;
      SetLength(Result, LShaLen);
      JoseSSL.SHA512(@AInput[0], Length(AInput), @Result[0]);
    end
  else
    raise Exception.Create('[ECDSA] Unsupported signing algorithm!');
  end;
end;

function TfrmCryptoECDSA.LoadPrivateKey: PEC_KEY;
begin
  Result := nil;
end;

procedure TfrmCryptoECDSA.memoCertificateDblClick(Sender: TObject);
begin
  SetFromPEMFile('EC X509 Certificate', Sender);
end;

procedure TfrmCryptoECDSA.memoPrivateKeyDblClick(Sender: TObject);
begin
  SetFromPEMFile('Private EC Key', Sender);
end;

procedure TfrmCryptoECDSA.memoPublicKey2DblClick(Sender: TObject);
begin
  SetFromPEMFile('Test Public EC Key', Sender);
end;

procedure TfrmCryptoECDSA.memoPublicKeyDblClick(Sender: TObject);
begin
  SetFromPEMFile('Public EC Key', Sender);
end;

function TfrmCryptoECDSA.OpenPEMFile(const ATitle: string): string;
begin
  Result := '';
  dlgOpenPEMFile.Title := ATitle;
  if dlgOpenPEMFile.Execute then
    Result := dlgOpenPEMFile.FileName;
end;

function TfrmCryptoECDSA.Sanitize(const AText: string): string;
begin
  if AText.EndsWith(sLineBreak) then
    Result := AText.Remove(AText.Length - 2, 2)
  else
    Result := AText;
end;

procedure TfrmCryptoECDSA.SetFromPEMFile(const ATitle: string; AMemo: TObject);
begin
  FFileName := OpenPEMFile(ATitle);
  if not FFileName.IsEmpty then
    (AMemo as TMemo).Lines.LoadFromFile(FFileName);
end;

function TfrmCryptoECDSA.Sign(const AInput, AKey: TBytes; AAlg: TECDSAAlgorithm): TBytes;
var
  LBIO: PBIO;
  LKey: PEVP_PKEY;
  LL: Pointer;
var
  eckey: PEC_KEY;
  sig: PECDSA_SIG;
  sigder: TBytes;

  LHash: TBytes;
begin
  TECDSA.LoadOpenSSL;

  LHash := HashFromSignature(AInput);

  // Load Private Key into ECDSA object
  LBIO := BIO_new(BIO_s_mem);
  try
    BIO_write(LBIO, @AKey[0], Length(AKey));
    LKey := PEM_read_bio_PrivateKey(LBIO, nil, nil, nil);
    if LKey = nil then
      raise Exception.Create('[ECDSA] Unable to load private key: ' + JOSESSL.GetLastError);
  finally
    BIO_free(LBIO);
  end;

  // Convert to a RAW format for the R/S
  ecKey := EVP_PKEY_get1_EC_KEY(LKey);
  try
    if ecKey = nil then
      raise Exception.Create('[ECDSA] Error getting EC Key: ' + JOSESSL.GetLastError);

    // ***************************************
    sig := JoseSSL.ECDSA_do_sign(@LHash[0], Length(LHash), eckey);

    Result := ToOctect(AAlg, sig);
    Exit;

    try
      SetLength(sigder, JoseSSL.ECDSA_size(eckey));

      LL := @sigder[0];
      JoseSSL.i2d_ECDSA_SIG(sig, @LL);
    finally
      JoseSSL.ECDSA_SIG_free(sig);
    end;

  finally
    JoseSSL.EC_KEY_free(ecKey);
  end;

  Result := sigder;
end;

function TfrmCryptoECDSA.ToOctect(AAlg: TECDSAAlgorithm; ASignature: PECDSA_SIG): TBytes;
var
  LNumR, LNumS: PBIGNUM;
  LSigLength, LRLength, LSLength: Integer;
begin
  LSigLength := 0;

  case AAlg of
    ES256:  LSigLength := 32 * 2;
    ES256K: LSigLength := 32 * 2;
    ES384:  LSigLength := 48 * 2;
    ES512:  LSigLength := 66 * 2;
  end;

  LNumR := ASignature.r;
  LNumS := ASignature.s;

  LRLength := JoseSSL.BN_num_bytes(LNumR);
  LSLength := JoseSSL.BN_num_bytes(LNumS);

  SetLength(Result, LSigLength);
  //FillChar(buffer, 32*2, 0);

  JoseSSL.BN_bn2bin(LNumR, Pointer(Integer(Result) + (LSigLength div 2) - LRLength));
  JoseSSL.BN_bn2bin(LNumS, Pointer(Integer(Result) + LSigLength-LSLength));
end;

function TfrmCryptoECDSA.Verify(const AInput, ASignature, AKeyOrCertificate:
    TBytes; AAlg: TECDSAAlgorithm): Boolean;
var
  bufkey: PBIO;
  pkey: PEVP_PKEY;

  ec_key: PEC_KEY;

  sig: PECDSA_SIG;
  psig: Pointer;
begin
  TECDSA.LoadOpenSSL;
  sig := nil;

  // Load Public RSA Key into RSA object
  bufkey := BIO_new(BIO_s_mem);
  try
    // Check Key prologue
    BIO_write(bufkey, @AKeyOrCertificate[0], Length(AKeyOrCertificate));

    pkey := JoseSSL.PEM_read_bio_PUBKEY(bufkey, nil, nil, nil);
    if pkey = nil then
      raise Exception.Create('[ECDSA] Unable to load public key: ' + JOSESSL.GetLastError);
  finally
    BIO_free(bufkey);
  end;

  try
    // Get the actual ec_key
    ec_key := EVP_PKEY_get1_EC_KEY(pkey);
    if ec_key = nil then
      raise Exception.Create('[ECDSA] Error getting memory for ECDSA');
  finally
    EVP_PKEY_free(pkey);
  end;

  try
    psig := @ASignature[0];
    sig := JoseSSL.d2i_ECDSA_SIG(@sig, @psig, Length(AKeyOrCertificate));
    if sig = nil then
      raise Exception.Create('[ECDSA] Can''t decode ECDSA signature');
    try
      Result := JoseSSL.ECDSA_do_verify(@AInput[0], Length(AInput), sig, ec_key) = 1;
    finally
      JoseSSL.ECDSA_SIG_free(sig);
    end;

  finally
    JoseSSL.EC_KEY_free(ec_key);
  end;

end;

end.
