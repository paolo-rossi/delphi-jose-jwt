{******************************************************************************}
{                                                                              }
{  Delphi JOSE Library                                                         }
{  Copyright (c) 2015-2019 Paolo Rossi                                         }
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

unit JWTDemo.Form.Debugger;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Vcl.ComCtrls, Vcl.ExtCtrls,
  JOSE.Core.JWT,
  JOSE.Core.JWS,
  JOSE.Core.JWE,
  JOSE.Core.JWK,
  JOSE.Core.JWA,
  JOSE.Types.JSON,
  JOSE.Encoding.Base64;

type
  TfrmDebugger = class(TForm)
    lblEncoded: TLabel;
    lblDecoded: TLabel;
    lblHMAC: TLabel;
    memoHeader: TMemo;
    memoPayload: TMemo;
    richEncoded: TRichEdit;
    edtKey: TEdit;
    chkKeyBase64: TCheckBox;
    shpStatus: TShape;
    lblStatus: TLabel;
    pnlSignatureSHA: TPanel;
    pnlSignatureRSA: TPanel;
    lblSignatureSHA: TLabel;
    pnlPayload: TPanel;
    lblPayload: TLabel;
    lblSignatureRSA: TLabel;
    pnlHeader: TPanel;
    lblHeader: TLabel;
    lblRSA: TLabel;
    memoPublicKey: TMemo;
    memoPrivateKey: TMemo;
    pnlAlgorithm: TPanel;
    lblAlgorithm: TLabel;
    cbbDebuggerAlgo: TComboBox;
    statusDebugger: TStatusBar;
    procedure cbbDebuggerAlgoChange(Sender: TObject);
    procedure chkKeyBase64Click(Sender: TObject);
    procedure edtKeyChange(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure memoHeaderChange(Sender: TObject);
    procedure memoPayloadChange(Sender: TObject);
    procedure memoPrivateKeyChange(Sender: TObject);
    procedure memoPublicKeyChange(Sender: TObject);
  private const
    clSignatureOk = $00F1B900;
  private
    FJWT: TJWT;
    FAlg: TJOSEAlgorithmId;

    FHeaderText: string;
    FSignatureSHAText: string;
    FSignatureRSAText: string;
    FSecretText: string;

    procedure AlgorithmChanged;
    function GenerateKeyPair: TKeyPair;
    procedure GenerateToken;
    procedure WriteCompactHeader(const AHeader: string);
    procedure WriteCompactClaims(const AClaims: string);
    procedure WriteCompactSignature(const ASignature: string);
    procedure WriteCompactSeparator;
    procedure SetStatus(AVerified: Boolean);
    procedure SetErrorJSON;
    function VerifyToken(AKey: TJWK): Boolean;
    procedure WriteDefault;
  public
    { Public declarations }
  end;

var
  frmDebugger: TfrmDebugger;

implementation

{$R *.dfm}

procedure TfrmDebugger.AlgorithmChanged;
var
  LOnChange: TNotifyEvent;
begin
  case cbbDebuggerAlgo.ItemIndex of
    0: FAlg := TJOSEAlgorithmId.HS256;
    1: FAlg := TJOSEAlgorithmId.HS384;
    2: FAlg := TJOSEAlgorithmId.HS512;

    3: FAlg := TJOSEAlgorithmId.RS256;
    4: FAlg := TJOSEAlgorithmId.RS384;
    5: FAlg := TJOSEAlgorithmId.RS512;
  end;

  case cbbDebuggerAlgo.ItemIndex of
    0..2:
    begin
      pnlSignatureSHA.Visible := True;
      pnlSignatureRSA.Visible := False;
    end;

    3..5:
    begin
      pnlSignatureSHA.Visible := False;
      pnlSignatureRSA.Visible := True;
    end;
  end;

  LOnChange := memoHeader.OnChange;
  memoHeader.OnChange := nil;
  memoHeader.Lines.Text := Format(FHeaderText, [FAlg.AsString]);
  memoHeader.OnChange := LOnChange;

  lblHMAC.Caption := Format(FSignatureSHAText, [FAlg.Length.ToString]);
  lblRSA.Caption := Format(FSignatureRSAText, [FAlg.Length.ToString]);

  LOnChange := edtKey.OnChange;
  edtKey.OnChange := nil;
  edtKey.Text := Format(FSecretText, [FAlg.Length.ToString]);
  edtKey.OnChange := LOnChange;

  GenerateToken;
end;

procedure TfrmDebugger.cbbDebuggerAlgoChange(Sender: TObject);
begin
  AlgorithmChanged;
end;

procedure TfrmDebugger.chkKeyBase64Click(Sender: TObject);
begin
  GenerateToken;
end;

procedure TfrmDebugger.edtKeyChange(Sender: TObject);
var
  LKey: TJWK;
begin
  if chkKeyBase64.Checked then
    LKey := TJWK.Create(TBase64.Decode(edtKey.Text))
  else
    LKey := TJWK.Create(edtKey.Text);

  try
    SetStatus(VerifyToken(LKey));
  finally
    LKey.Free;
  end;
end;

procedure TfrmDebugger.FormDestroy(Sender: TObject);
begin
  FJWT.Free;
end;

procedure TfrmDebugger.FormCreate(Sender: TObject);
begin
  FHeaderText := memoHeader.Lines.Text;
  FSignatureSHAText := lblHMAC.Caption;
  FSignatureRSAText := lblRSA.Caption;
  FSecretText := edtKey.Text;

  FJWT := TJWT.Create(TJWTClaims);

  FJWT.Header.JSON.Free;
  FJWT.Header.JSON := TJSONObject(TJSONObject.ParseJSONValue(memoHeader.Lines.Text));

  FJWT.Claims.JSON.Free;
  FJWT.Claims.JSON := TJSONObject(TJSONObject.ParseJSONValue(memoPayload.Lines.Text));

  FAlg := TJOSEAlgorithmId.HS256;

  AlgorithmChanged;

  WriteDefault;
end;

function TfrmDebugger.GenerateKeyPair: TKeyPair;
begin
  Result := TKeyPair.Create;

  case FAlg of
    TJOSEAlgorithmId.HS256,
    TJOSEAlgorithmId.HS384,
    TJOSEAlgorithmId.HS512:
    begin
      if chkKeyBase64.Checked then
        Result.PrivateKey.Key := TBase64.Decode(edtKey.Text)
      else
        Result.PrivateKey.Key := edtKey.Text;
      Result.PublicKey.Key := Result.PrivateKey.Key;
    end;

    TJOSEAlgorithmId.RS256,
    TJOSEAlgorithmId.RS384,
    TJOSEAlgorithmId.RS512:
    begin
      Result.PrivateKey.Key := memoPrivateKey.Lines.Text;
      Result.PublicKey.Key := memoPublicKey.Lines.Text;
    end;
  end;
end;

procedure TfrmDebugger.GenerateToken;
var
  LSigner: TJWS;
  LKeyPair: TKeyPair;
begin
  richEncoded.Lines.Clear;
  statusDebugger.Panels[1].Text := '';
  try
    if Assigned(FJWT.Header.JSON) and Assigned(FJWT.Claims.JSON) then
    begin
      richEncoded.Color := clWindow;

      LSigner := TJWS.Create(FJWT);

      LKeyPair := GenerateKeyPair;
      try
        LSigner.SkipKeyValidation := True;
        LSigner.Sign(LKeyPair.PrivateKey, FAlg);

        WriteCompactHeader(LSigner.Header);
        WriteCompactSeparator;
        WriteCompactClaims(LSigner.Payload);
        WriteCompactSeparator;
        WriteCompactSignature(LSigner.Signature);

        SetStatus(VerifyToken(LKeyPair.PublicKey));
      finally
        LKeyPair.Free;
        LSigner.Free;
      end;
    end
    else
    begin
      richEncoded.Color := $00CBC0FF;
      SetErrorJSON;
    end;
  except
    on E: Exception do
    begin
      statusDebugger.Panels[1].Text := E.Message;
      SetStatus(False);
    end;
  end;
end;

procedure TfrmDebugger.memoHeaderChange(Sender: TObject);
begin
  FJWT.Header.JSON.Free;
  FJWT.Header.JSON := TJSONObject(TJSONObject.ParseJSONValue((Sender as TMemo).Lines.Text));
  GenerateToken;
end;

procedure TfrmDebugger.memoPayloadChange(Sender: TObject);
begin
  FJWT.Claims.JSON.Free;
  FJWT.Claims.JSON := TJSONObject(TJSONObject.ParseJSONValue((Sender as TMemo).Lines.Text));
  GenerateToken;
end;

procedure TfrmDebugger.memoPrivateKeyChange(Sender: TObject);
begin
  GenerateToken;
end;

procedure TfrmDebugger.memoPublicKeyChange(Sender: TObject);
var
  LKeys: TKeyPair;
begin
  statusDebugger.Panels[1].Text := '';
  LKeys := TKeyPair.Create(memoPublicKey.Lines.Text, memoPrivateKey.Lines.Text);
  try
    SetStatus(VerifyToken(LKeys.PublicKey));
  except
    on E: Exception do
      statusDebugger.Panels[1].Text := E.Message;
  end;
  LKeys.Free;
end;

procedure TfrmDebugger.SetErrorJSON;
begin
  shpStatus.Brush.Color := clRed;
  lblStatus.Caption := 'JSON Data Error';
end;

procedure TfrmDebugger.SetStatus(AVerified: Boolean);
begin
  if AVerified then
  begin
    shpStatus.Brush.Color := clSignatureOk;
    lblStatus.Caption := 'Signature Verified';
  end
  else
  begin
    shpStatus.Brush.Color := clRed;
    lblStatus.Caption := 'Invalid Signature';
  end;
end;

function TfrmDebugger.VerifyToken(AKey: TJWK): Boolean;
var
  LToken: TJWT;
  LSigner: TJWS;
  LCompactToken: string;
begin
  Result := False;
  LCompactToken := StringReplace(richEncoded.Lines.Text, sLineBreak, '', [rfReplaceAll]);

  statusDebugger.Panels[1].Text := '';
  try
    LToken := TJWT.Create;
    try
      LSigner := TJWS.Create(LToken);
      LSigner.SkipKeyValidation := True;
      try
        LSigner.SetKey(AKey);
        LSigner.CompactToken := LCompactToken;
        LSigner.VerifySignature;
      finally
        LSigner.Free;
      end;

      if LToken.Verified then
        Result := True;
    finally
      LToken.Free;
    end;
  except
    on E: Exception do
      statusDebugger.Panels[1].Text := E.Message;
  end;
end;

procedure TfrmDebugger.WriteCompactClaims(const AClaims: string);
begin
  richEncoded.SelAttributes.Color := clFuchsia;
  richEncoded.SelText := AClaims;
end;

procedure TfrmDebugger.WriteCompactHeader(const AHeader: string);
begin
  richEncoded.SelAttributes.Color := clRed;
  richEncoded.SelText := AHeader;
end;

procedure TfrmDebugger.WriteCompactSeparator;
begin
  richEncoded.SelAttributes.Color := clBlack;
  richEncoded.SelText := '.';
end;

procedure TfrmDebugger.WriteCompactSignature(const ASignature: string);
begin
  richEncoded.SelAttributes.Color := clSignatureOk;
  richEncoded.SelText := ASignature;
end;

procedure TfrmDebugger.WriteDefault;
begin
  richEncoded.Lines.Clear;
  WriteCompactHeader('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9');
  WriteCompactSeparator;
  WriteCompactClaims('eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9');
  WriteCompactSeparator;
  WriteCompactSignature('TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ');

  SetStatus(True);
end;

end.
