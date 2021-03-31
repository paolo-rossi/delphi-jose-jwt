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

unit Crypto.Form.SSL;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Crypto.Utils,

  JOSE.Encoding.Base64,
  JOSE.Signing.ECDSA,
  JOSE.Signing.RSA,
  JOSE.Types.Bytes,
  IdSSLOpenSSLHeaders,
  JOSE.OpenSSL.Headers;

type
  TfrmCryptoSSL = class(TForm)
    Button1: TButton;
    Memo1: TMemo;
    btnBuildKey: TButton;
    Edit1: TEdit;
    btnURLDecode: TButton;
    Edit2: TEdit;
    edtJWTIO: TEdit;
    memoPrivateKey: TMemo;
    btnECDSASign: TButton;
    btnECDSAVerify: TButton;
    memoSignature: TMemo;
    memoPayload: TMemo;
    Button2: TButton;
    btnSSLVersion: TButton;
    memoPublicKey: TMemo;
    btnCertificate: TButton;
    memoCertificate: TMemo;
    btnPublicKeyFromCert: TButton;
    procedure Button1Click(Sender: TObject);
    procedure btnBuildKeyClick(Sender: TObject);
    procedure btnECDSASignClick(Sender: TObject);
    procedure btnECDSAVerifyClick(Sender: TObject);
    procedure Button2Click(Sender: TObject);
    procedure btnURLDecodeClick(Sender: TObject);
    procedure btnSSLVersionClick(Sender: TObject);
    procedure btnCertificateClick(Sender: TObject);
    procedure btnPublicKeyFromCertClick(Sender: TObject);
  private
    function LoadCertificate(const ACertificate: TBytes): Integer;
    function Sanitize(const AText: string): string;

    function Sign_ECDSA(const APayload, APrivateKey: TJOSEBytes): TJOSEBytes;
    function Verify_ECDSA(const APayload, APublicKey, ASignature: TJOSEBytes): Boolean;
    function VerifyToken(const aToken, aPublicKey: string): Boolean;
  public
    { Public declarations }
  end;

implementation

uses
  System.JSON,
  JOSE.Types.Utils,
  JOSE.Core.JWK,
  JOSE.Core.JWT,
  JOSE.Core.JWS,
  JOSE.Core.JWA,
  JOSE.Core.Builder;

{$R *.dfm}

procedure TfrmCryptoSSL.Button1Click(Sender: TObject);
begin
  //Memo1.WordWrap := False;
  if VerifyToken(edtJWTIO.Text, JWTIO_PK) then
    ShowMessage('Token verified with public key')
  else
    ShowMessage('Token INVALID, not verified with public key!!');
  //Memo1.WordWrap := True;

end;

procedure TfrmCryptoSSL.btnBuildKeyClick(Sender: TObject);
var
  n64, e64: string;
  nJOSE, eJOSE: TJOSEBytes;
  nArr, eArr: TArray<Byte>;

  r: PRSA;
  bp: pBIO;
  Len: Integer;

  buf: TArray<Byte>;
  xbuf: TJOSEBytes;
begin
  n64 :=
    'ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-' +
    'Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6' +
    'b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-' +
    'KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I' +
    '5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb' +
    '54h4FRWyuXpoQ';
  e64 := 'AQAB';

  nJOSE := TBase64.Decode(n64);
  eJOSE := TBase64.Decode(e64);

  nArr := nJOSE;
  eArr := eJOSE;

  IdSSLOpenSSLHeaders.Load;
  JoseSSL.Load;

  r := RSA_new;

  r.n := JoseSSL.BN_bin2bn(@nArr, Length(nArr), nil);
  r.e := JoseSSL.BN_bin2bn(@nArr, Length(nArr), nil);

  bp := BIO_new(BIO_s_mem);

  PEM_write_bio_RSAPublicKey(bp, r);

  Len := BIO_pending(bp);

  SetLength(buf, Len);
  BIO_read(bp, @buf[0], Len);

  xbuf := buf;

  Memo1.Lines.Add(xbuf);

  BIO_free(bp);
  RSA_free(r);
end;

procedure TfrmCryptoSSL.btnECDSASignClick(Sender: TObject);
begin
  Sign_ECDSA(Sanitize(memoPayload.Lines.Text), Sanitize(memoPrivateKey.Lines.Text));
end;

procedure TfrmCryptoSSL.btnECDSAVerifyClick(Sender: TObject);
begin
  Verify_ECDSA(Sanitize(memoPayload.Lines.Text), Sanitize(memoPublicKey.Lines.Text), Sanitize(memoSignature.Lines.Text));
end;

procedure TfrmCryptoSSL.Button2Click(Sender: TObject);
var
  B: TBytes;
  F: TFileStream;
begin
  F := TFileStream.Create('D:\projects\GitHub\Project JWT\openssl\signature.bin', fmOpenRead);
  SetLength(B, F.Size);
  F.Read(B[0], F.Size);
  F.Free;

  memoSignature.Lines.Text := TBase64.URLEncode(B);
end;

procedure TfrmCryptoSSL.btnURLDecodeClick(Sender: TObject);
var
  LS: TJOSEBytes;
begin
  LS := TBase64.URLDecode(Edit1.Text);

  Edit2.Text := LS.AsString;
end;

procedure TfrmCryptoSSL.btnSSLVersionClick(Sender: TObject);
var
  p: PAnsiChar;
begin
  IdSSLOpenSSLHeaders.Load;
  JoseSSL.Load;

  p := JoseSSL.SSLeay_version(SSLEAY_VERSION);
  memoSignature.Lines.Text := string(p);
end;

procedure TfrmCryptoSSL.btnCertificateClick(Sender: TObject);
var
  LCer: TJOSEBytes;
begin
  LCer.AsString := Sanitize(memoCertificate.Lines.Text);

  ShowMessage(LoadCertificate(LCer).ToString);
end;

procedure TfrmCryptoSSL.btnPublicKeyFromCertClick(Sender: TObject);
{
var
  LKey: PEVP_PKEY;
  LBio: PBIO;
  LBuffer, LResult: TBytes;
  LJOSEBytes: TJOSEBytes;
  LBytesRead: Integer;
}
begin
  IdSSLOpenSSLHeaders.Load;
  JoseSSL.Load;

  {
  LResult := [];
  LBuffer := [1,2,3,0,0,0,0,0];
  TJOSEUtils.ArrayPush(LBuffer, LResult, 3);

  LBuffer := [8,9,0,0,0,0,0,0];
  TJOSEUtils.ArrayPush(LBuffer, LResult, 2);

  LBuffer := [6,6,3,7,1,0,0,0];
  TJOSEUtils.ArrayPush(LBuffer, LResult, 5);
  }

  {
  LJOSEBytes := Sanitize(memoCertificate.Text);

  LResult := [];
  LKey := TRSA.LoadPublicKeyFromCert(LJOSEBytes.AsBytes);
  LBio := BIO_new(BIO_s_mem);
  try
    JoseSSL.PEM_write_bio_PUBKEY(LBio, LKey);
    SetLength(LBuffer, 50);

    repeat
      LBytesRead := BIO_read(LBio, @LBuffer[0], 50);
      TJOSEUtils.ArrayPush(LBuffer, LResult, LBytesRead);
    until (LBytesRead <= 0);

    LJOSEBytes := LResult;
    memoPayload.Lines.Text := LJOSEBytes;
  finally
    BIO_free(LBio);
  end;
  }
end;

function TfrmCryptoSSL.LoadCertificate(const ACertificate: TBytes): Integer;
var
  LBio: PBIO;
  LCer: PX509;
  //LKey: PEVP_PKEY;
  LAlg: Integer;
begin
  TECDSA.LoadOpenSSL;
  LBio := BIO_new(BIO_s_mem);
  try
    BIO_write(LBio, @ACertificate[0], Length(ACertificate));
    LCer := PEM_read_bio_X509(LBio, nil, nil, nil);
    if not Assigned(LCer) then
    begin
      ShowMessage(JoseSSL.GetLastError);
      Exit(0);
    end;
    //LKey := X509_PUBKEY_get(LCer.cert_info.key);
    LAlg := OBJ_obj2nid(LCer.cert_info.key.algor.algorithm);
    Result := LAlg;
  finally
    BIO_free(LBio);
  end;
end;

function TfrmCryptoSSL.Sanitize(const AText: string): string;
begin
  if AText.EndsWith(sLineBreak) then
    Result := AText.Remove(AText.Length - 2, 2);
end;

function TfrmCryptoSSL.Sign_ECDSA(const APayload, APrivateKey: TJOSEBytes): TJOSEBytes;
var
  LSignature: TJOSEBytes;
begin
  LSignature := TECDSA.Sign(APayload.AsBytes, APrivateKey.AsBytes, TECDSAAlgorithm.ES256);
  memoSignature.Lines.Text := TBase64.URLEncode(LSignature).AsString;
end;

function TfrmCryptoSSL.VerifyToken(const aToken, aPublicKey: string): Boolean;
var
  key: TJWK;
  token: TJWT;
  signer: TJWS;
begin
  //Result := False;
  key := TJWK.Create(aPublicKey);
  try
    token := TJWT.Create;
    try
      signer := TJWS.Create(token);
      try
        signer.SkipKeyValidation := False;
        signer.SetKey(key);
        signer.CompactToken := aToken;
        signer.VerifySignature;
      finally
        signer.Free;
      end;

      Result := token.Verified;
    finally
      token.Free;
    end;
  finally
    key.Free;
  end;
end;

function TfrmCryptoSSL.Verify_ECDSA(const APayload, APublicKey, ASignature: TJOSEBytes): Boolean;
var
  LBinarySig: TBytes;
begin
  Result := False;
  LBinarySig := TBase64.URLDecode(ASignature).AsBytes;
  if TECDSA.Verify(APayload.AsBytes, LBinarySig, APublicKey.AsBytes, TECDSAAlgorithm.ES256) then
    ShowMessage('Verified')
  else
    ShowMessage('Not verified')
end;

end.
