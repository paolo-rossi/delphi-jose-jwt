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

unit Crypto.Form.RSA;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls,

  JOSE.Encoding.Base64,
  JOSE.Signing.RSA,
  JOSE.Types.Bytes,
  IdSSLOpenSSLHeaders,
  JOSE.OpenSSL.Headers;

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
  if TRSA.VerifyCertificate(LCert.AsBytes, NID_rsaEncryption) then
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
