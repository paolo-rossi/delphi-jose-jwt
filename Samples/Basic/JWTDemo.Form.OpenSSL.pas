unit JWTDemo.Form.OpenSSL;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Vcl.ExtCtrls,

  JOSE.Core.JWT,
  JOSE.Core.JWS,
  JOSE.Core.JWE,
  JOSE.Core.JWK,
  JOSE.Core.JWA,
  JOSE.Core.JWA.Signing,
  JOSE.Types.Bytes,
  JOSE.Types.JSON,
  JOSE.Signing.RSA,
  JOSE.Encoding.Base64;

type
  TfrmOpenSSL = class(TForm)
    pnlSignatureRSA: TPanel;
    lblSignatureRSA: TLabel;
    memoPublicKey: TMemo;
    memoPrivateKey: TMemo;
    lblRSA: TLabel;
    Label1: TLabel;
    pnlPlainText: TPanel;
    lblPlainText: TLabel;
    memoPlainText: TMemo;
    pnlAlgorithm: TPanel;
    lblAlgorithm: TLabel;
    cbbDebuggerAlgo: TComboBox;
    pnlSignedText: TPanel;
    lblSignedText: TLabel;
    memoSignedText: TMemo;
    btnSign: TButton;
    rgTerminator: TRadioGroup;
    procedure btnSignClick(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  frmOpenSSL: TfrmOpenSSL;

implementation

{$R *.dfm}

procedure TfrmOpenSSL.btnSignClick(Sender: TObject);
var
  LAlg: TRSAAlgorithm;
  LInputStr: string;
  LInput, LKey, LSign: TJOSEBytes;
begin
  LAlg := TRSAAlgorithm.RS256;

  case cbbDebuggerAlgo.ItemIndex of
    0: LAlg := TRSAAlgorithm.RS256;
    1: LAlg := TRSAAlgorithm.RS384;
    2: LAlg := TRSAAlgorithm.RS512;
  end;

  LInputStr := memoPlainText.Text;
  if LInputStr.EndsWith(sLineBreak) then
    LInputStr := LInputStr.Remove(LInputStr.Length-2, 2);

  case rgTerminator.ItemIndex of
    1: LInputStr := StringReplace(LInputStr, sLineBreak, #13, [rfReplaceAll]);
    2: LInputStr := StringReplace(LInputStr, sLineBreak, #10, [rfReplaceAll]);
    3: LInputStr := StringReplace(LInputStr, sLineBreak, '', [rfReplaceAll]);
  end;
  LInput := LInputStr;
  LKey := memoPrivateKey.Text;
  LSign := TRSA.Sign(LInput, LKey, LAlg);
  memoSignedText.Text := TBase64.Encode(LSign);
end;

end.
