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

unit JWTDemo.Form.Debugger;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Vcl.ComCtrls, Vcl.ExtCtrls, Vcl.ExtDlgs,
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
    memoPublicKeyRSA: TMemo;
    memoPrivateKeyRSA: TMemo;
    pnlAlgorithm: TPanel;
    lblAlgorithm: TLabel;
    cbbDebuggerAlgo: TComboBox;
    statusDebugger: TStatusBar;
    pnlSignatureECDSA: TPanel;
    lblSignatureECDSA: TLabel;
    lblECDSA: TLabel;
    memoPublicKeyECDSA: TMemo;
    memoPrivateKeyECDSA: TMemo;
    dlgOpenPEMFile: TOpenTextFileDialog;
    memoSecretHMAC: TMemo;
    procedure cbbDebuggerAlgoChange(Sender: TObject);
    procedure chkKeyBase64Click(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure memoHeaderChange(Sender: TObject);
    procedure memoPayloadChange(Sender: TObject);
    procedure memoPrivateKeyECDSAChange(Sender: TObject);
    procedure memoPrivateKeyRSAChange(Sender: TObject);
    procedure memoPublicKeyECDSAChange(Sender: TObject);
    procedure memoPublicKeyRSAChange(Sender: TObject);
    procedure memoSecretHMACChange(Sender: TObject);
  private const
    clSignatureOk = $00F1B900;
  private
    FStartup: Boolean;
    FKeysDir: string;
    FJWT: TJWT;
    FAlg: TJOSEAlgorithmId;

    FHeaderText: string;
    FSignatureSHAText: string;
    FSignatureRSAText: string;
    FSignatureECDSAText: string;

    procedure MemoLoad(AMemo: TMemo; const AFileName: string);
    procedure LoadKeys(AAlgorithm: TJOSEAlgorithmId);
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

uses
  System.IOUtils,
  JOSE.Types.Utils;

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

    6: FAlg := TJOSEAlgorithmId.ES256;
    7: FAlg := TJOSEAlgorithmId.ES256K;
    8: FAlg := TJOSEAlgorithmId.ES384;
    9: FAlg := TJOSEAlgorithmId.ES512;
  end;

  LoadKeys(FAlg);

  case cbbDebuggerAlgo.ItemIndex of
    0..2: pnlSignatureSHA.BringToFront;
    3..5: pnlSignatureRSA.BringToFront;
    6..9: pnlSignatureECDSA.BringToFront;
  end;

  LOnChange := memoHeader.OnChange;
  memoHeader.OnChange := nil;
  memoHeader.Lines.Text := Format(FHeaderText, [FAlg.AsString]);
  memoHeader.OnChange := LOnChange;

  lblHMAC.Caption := Format(FSignatureSHAText, [FAlg.Length.ToString]);
  lblRSA.Caption := Format(FSignatureRSAText, [FAlg.Length.ToString]);
  lblECDSA.Caption := Format(FSignatureECDSAText, [FAlg.Length.ToString]);

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

procedure TfrmDebugger.FormDestroy(Sender: TObject);
begin
  FJWT.Free;
end;

procedure TfrmDebugger.FormCreate(Sender: TObject);
begin
  FStartup := True;
  try
    FKeysDir := TJOSEUtils.DirectoryUp(Application.ExeName, 2);
    FKeysDir := TPath.Combine(FKeysDir, 'Keys');
    FHeaderText := memoHeader.Lines.Text;

    FSignatureSHAText := lblHMAC.Caption;
    FSignatureRSAText := lblRSA.Caption;
    FSignatureECDSAText := lblECDSA.Caption;

    FJWT := TJWT.Create(TJWTClaims);

    FJWT.Header.JSON.Free;
    FJWT.Header.JSON := TJSONObject(TJSONObject.ParseJSONValue(memoHeader.Lines.Text));

    FJWT.Claims.JSON.Free;
    FJWT.Claims.JSON := TJSONObject(TJSONObject.ParseJSONValue(memoPayload.Lines.Text));

    FAlg := TJOSEAlgorithmId.HS256;

    AlgorithmChanged;

    WriteDefault;
  finally
    FStartup := False;
  end;
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
        Result.PrivateKey.Key := TBase64.Decode(memoSecretHMAC.Lines.Text)
      else
        Result.PrivateKey.Key := memoSecretHMAC.Lines.Text;
      Result.PublicKey.Key := Result.PrivateKey.Key;
    end;

    TJOSEAlgorithmId.RS256,
    TJOSEAlgorithmId.RS384,
    TJOSEAlgorithmId.RS512:
    begin
      Result.PrivateKey.Key := memoPrivateKeyRSA.Lines.Text;
      Result.PublicKey.Key := memoPublicKeyRSA.Lines.Text;
    end;

    TJOSEAlgorithmId.ES256,
    TJOSEAlgorithmId.ES256K,
    TJOSEAlgorithmId.ES384,
    TJOSEAlgorithmId.ES512:
    begin
      Result.PrivateKey.Key := memoPrivateKeyECDSA.Lines.Text;
      Result.PublicKey.Key := memoPublicKeyECDSA.Lines.Text;
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

procedure TfrmDebugger.LoadKeys(AAlgorithm: TJOSEAlgorithmId);
var
  LFileName: string;
  LPrefix: string;
begin
  case AAlgorithm of
    TJOSEAlgorithmId.HS256..TJOSEAlgorithmId.HS512:
    begin
      LPrefix := LowerCase(AAlgorithm.AsString);
      LFileName := TPath.Combine(FKeysDir, LPrefix + '.key');
      MemoLoad(memoSecretHMAC, LFileName);
    end;

    TJOSEAlgorithmId.RS256..TJOSEAlgorithmId.RS512:
    begin
      LPrefix := 'rsa';
      LFileName := TPath.Combine(FKeysDir, LPrefix + '-private.pem');
      MemoLoad(memoPrivateKeyRSA, LFileName);
      LFileName := TPath.Combine(FKeysDir, LPrefix + '-public.pem');
      MemoLoad(memoPublicKeyRSA, LFileName);
    end;

    TJOSEAlgorithmId.ES256..TJOSEAlgorithmId.ES512:
    begin
      LPrefix := LowerCase(AAlgorithm.AsString);
      LFileName := TPath.Combine(FKeysDir, LPrefix + '-private.pem');
      MemoLoad(memoPrivateKeyECDSA, LFileName);
      LFileName := TPath.Combine(FKeysDir, LPrefix + '-public.pem');
      MemoLoad(memoPublicKeyECDSA, LFileName);
    end;
  end;
end;

procedure TfrmDebugger.memoHeaderChange(Sender: TObject);
begin
  if FStartup then
    Exit;

  FJWT.Header.JSON.Free;
  FJWT.Header.JSON := TJSONObject(TJSONObject.ParseJSONValue((Sender as TMemo).Lines.Text));
  GenerateToken;
end;

procedure TfrmDebugger.MemoLoad(AMemo: TMemo; const AFileName: string);
var
  LEvent: TNotifyEvent;
begin
  LEvent := AMemo.OnChange;
  AMemo.OnChange := nil;
  AMemo.Lines.LoadFromFile(AFileName);
  AMemo.OnChange := LEvent;
end;

procedure TfrmDebugger.memoPayloadChange(Sender: TObject);
begin
  if FStartup then
    Exit;

  FJWT.Claims.JSON.Free;
  FJWT.Claims.JSON := TJSONObject(TJSONObject.ParseJSONValue((Sender as TMemo).Lines.Text));
  GenerateToken;
end;

procedure TfrmDebugger.memoPrivateKeyECDSAChange(Sender: TObject);
begin
  if FStartup then
    Exit;

  GenerateToken;
end;

procedure TfrmDebugger.memoPrivateKeyRSAChange(Sender: TObject);
begin
  if FStartup then
    Exit;

  GenerateToken;
end;

procedure TfrmDebugger.memoPublicKeyECDSAChange(Sender: TObject);
var
  LKeys: TKeyPair;
begin
  if FStartup then
    Exit;

  statusDebugger.Panels[1].Text := '';
  LKeys := TKeyPair.Create(memoPublicKeyECDSA.Lines.Text, memoPrivateKeyECDSA.Lines.Text);
  try
    SetStatus(VerifyToken(LKeys.PublicKey));
  except
    on E: Exception do
      statusDebugger.Panels[1].Text := E.Message;
  end;
  LKeys.Free;
end;

procedure TfrmDebugger.memoPublicKeyRSAChange(Sender: TObject);
var
  LKeys: TKeyPair;
begin
  if FStartup then
    Exit;

  statusDebugger.Panels[1].Text := '';
  LKeys := TKeyPair.Create(memoPublicKeyRSA.Lines.Text, memoPrivateKeyRSA.Lines.Text);
  try
    SetStatus(VerifyToken(LKeys.PublicKey));
  except
    on E: Exception do
      statusDebugger.Panels[1].Text := E.Message;
  end;
  LKeys.Free;
end;

procedure TfrmDebugger.memoSecretHMACChange(Sender: TObject);
var
  LKey: TJWK;
begin
  if FStartup then
    Exit;

  if chkKeyBase64.Checked then
    LKey := TJWK.Create(TBase64.Decode(memoSecretHMAC.Lines.Text))
  else
    LKey := TJWK.Create(memoSecretHMAC.Lines.Text);

  try
    SetStatus(VerifyToken(LKey));
  finally
    LKey.Free;
  end;
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
  WriteCompactClaims('eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ');
  WriteCompactSeparator;
  WriteCompactSignature('SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c');

  SetStatus(True);
end;

end.
