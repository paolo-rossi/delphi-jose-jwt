{******************************************************************************}
{                                                                              }
{  Delphi JOSE-JWT Library                                                     }
{  Copyright (c) 2015 Paolo Rossi                                              }
{  https://github.com/paolo-rossi/delphi-jose-jwt                              }
{                                                                              }
{  Licensed under the MIT license                                              }
{                                                                              }
{******************************************************************************}

unit Crypto.Form.RSA;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls,

  JOSE.Crypto.Algorithms,
  JOSE.Encoding.Base64,
  JOSE.Signing.RSA,
  JOSE.Types.Bytes;

type
  TfrmCryptoRSA = class(TForm)
    memoPayload: TMemo;
    memoSignature: TMemo;
    memoPrivateKey: TMemo;
    memoPublicKey: TMemo;
    memoCertificate: TMemo;
    btnCertificate: TButton;
    btnRSASign: TButton;
    procedure btnCertificateClick(Sender: TObject);
    procedure btnRSASignClick(Sender: TObject);
  private
    function Sign_RSA(const APayload, APrivateKey: TJOSEBytes): TJOSEBytes;
    function Sanitize(const AText: string): string;
  public
    { Public declarations }
  end;

implementation

{$R *.dfm}

procedure TfrmCryptoRSA.btnCertificateClick(Sender: TObject);
var
  LCert: TJOSEBytes;
begin
  LCert := Sanitize(memoCertificate.Lines.Text);
  if TRSA.VerifyCertificate(LCert.AsBytes, TJOSECertificatePublicKey.RSA) then
    ShowMessage('certificate verified. RSA Key detected')
  else
    ShowMessage('certificate not verified')
end;

procedure TfrmCryptoRSA.btnRSASignClick(Sender: TObject);
begin
  Sign_RSA(memoPayload.Lines.Text, memoPrivateKey.Lines.Text);
end;

function TfrmCryptoRSA.Sanitize(const AText: string): string;
begin
  if AText.EndsWith(sLineBreak) then
    Result := AText.Remove(AText.Length - 2, 2);
end;

function TfrmCryptoRSA.Sign_RSA(const APayload, APrivateKey: TJOSEBytes):
    TJOSEBytes;
var
  LSignature: TJOSEBytes;
begin
  LSignature := TRSA.Sign(APayload.AsBytes, APrivateKey.AsBytes, TRSAAlgorithm.RS256);
  memoSignature.Lines.Text := TBase64.URLEncode(LSignature).AsString;
end;

end.
