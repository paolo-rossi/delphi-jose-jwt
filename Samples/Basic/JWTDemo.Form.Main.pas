unit JWTDemo.Form.Main;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, IdGlobal,
  System.Generics.Defaults, System.Generics.Collections,
  JOSE.Core.JWT, JOSE.Core.JWS, JOSE.Core.JWK, JOSE.Core.JWA, Vcl.ExtCtrls,
  Vcl.ComCtrls;

type
  TfrmMain = class(TForm)
    mmoJSON: TMemo;
    Button8: TButton;
    Button9: TButton;
    mmoCompact: TMemo;
    Label1: TLabel;
    Label2: TLabel;
    edtIssuer: TLabeledEdit;
    edtIssuedAtTime: TDateTimePicker;
    edtNotBeforeDate: TDateTimePicker;
    edtExpiresDate: TDateTimePicker;
    Label3: TLabel;
    Label4: TLabel;
    Label5: TLabel;
    chkIssuer: TCheckBox;
    chkIssuedAt: TCheckBox;
    chkExpires: TCheckBox;
    chkNotBefore: TCheckBox;
    Button1: TButton;
    edtIssuedAtDate: TDateTimePicker;
    edtExpiresTime: TDateTimePicker;
    edtNotBeforeTime: TDateTimePicker;
    cbbAlgorithm: TComboBox;
    Label6: TLabel;
    procedure Button8Click(Sender: TObject);
    procedure Button9Click(Sender: TObject);
  private
    FToken: TJWT;
  public
    { Public declarations }
  end;

var
  frmMain: TfrmMain;

implementation

uses
  System.Rtti, System.NetEncoding,
  IdCoderMIME, IdHMAC, IdSSLOpenSSL, IdHMACSHA1,
  JOSE.Types.Bytes,
  JOSE.Core.Builder;

{$R *.dfm}

procedure TfrmMain.Button8Click(Sender: TObject);
var
  LToken: TJWT;
  LSigned: TJWS;
  LKey: TJWK;
begin
  LToken := TJWT.Create(TJWTClaims);
  LKey := TJWK.Create('secret');

  LToken.Claims.Issuer := 'WiRL';

  LSigned := TJWS.Create(LToken);

  mmoJSON.Lines.Add(LToken.Header.JSON.ToJSON);
  mmoJSON.Lines.Add(LToken.Claims.JSON.ToJSON);

  LSigned.Verify(LKey, 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJXaVJMIn0.w3BAZ_GwfQYY6dkS8xKUNZ_sOnkDUMELxBN0mKKNhJ4');

  if LToken.Verified then
    mmoCompact.Lines.Add(LSigned.Signature);
end;

procedure TfrmMain.Button9Click(Sender: TObject);
var
  LToken: TJWT;
begin
  LToken := TJWT.Create(TJWTClaims);
  LToken.Claims.IssuedAt := Now;
  LToken.Claims.Expiration := Now + 1;
  LToken.Claims.Issuer := 'WiRL';

  mmoCompact.Lines.Add(TJOSE.SHA256CompactToken('secret', LToken));

  mmoJSON.Lines.Add(LToken.Header.JSON.ToJSON);
  mmoJSON.Lines.Add(LToken.Claims.JSON.ToJSON);
end;

end.
