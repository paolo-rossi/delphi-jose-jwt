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

unit JWTDemo.Form.Simple;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Vcl.ExtCtrls,

  JOSE.Core.JWT,
  JOSE.Core.JWS,
  JOSE.Core.JWK,
  JOSE.Core.JWA,
  JOSE.Types.JSON;

type
  TfrmSimple = class(TForm)
    lblJSON: TLabel;
    lblCompact: TLabel;
    btnBuildClasses: TButton;
    btnBuildTJOSE: TButton;
    btnVerifyTJOSE: TButton;
    btnTestClaims: TButton;
    memoJSON: TMemo;
    memoCompact: TMemo;
    lblAlgorithm: TLabel;
    cbbAlgorithm: TComboBox;
    edtSecret: TLabeledEdit;
    btnDeserializeTJOSE: TButton;
    btnVerifyClasses: TButton;
    procedure btnBuildClassesClick(Sender: TObject);
    procedure btnTestClaimsClick(Sender: TObject);
    procedure btnBuildTJOSEClick(Sender: TObject);
    procedure btnVerifyTJOSEClick(Sender: TObject);
    procedure btnDeserializeTJOSEClick(Sender: TObject);
    procedure btnVerifyClassesClick(Sender: TObject);
    procedure edtSecretChange(Sender: TObject);
  private
    const SECRET_CAPTION = 'Secret (%dbit)';
  private
    FCompact: string;
    procedure BuildToken;
    procedure BuildTokenComplete;
    function VerifyToken: Boolean;
    function VerifyTokenComplete: Boolean;
    procedure DeserializeToken;
  public
    { Public declarations }
  end;

implementation

uses
  System.Rtti,
  JOSE.Types.Bytes,
  JOSE.Core.Builder;

{$R *.dfm}

procedure TfrmSimple.btnBuildClassesClick(Sender: TObject);
begin
  BuildTokenComplete;
end;

procedure TfrmSimple.btnTestClaimsClick(Sender: TObject);
var
  LToken: TJWT;
begin
  // Unpack and verify the token
  LToken := TJOSE.Verify(edtSecret.Text, FCompact);

  if Assigned(LToken) then
  begin
    try
      if LToken.Verified then
      begin
        // Claims validation (for more see the JOSE.Consumer unit)

        if LToken.Claims.Subject <> 'Paolo Rossi' then
          memoJSON.Lines.Add('Subject [sub] claim value doesn''t match expected value');

        if LToken.Claims.Expiration > Now then
          memoJSON.Lines.Add('Expiration time passed: ' + DateTimeToStr(LToken.Claims.Expiration));

      end;
    finally
      LToken.Free;
    end;
  end;
end;

procedure TfrmSimple.btnBuildTJOSEClick(Sender: TObject);
begin
  BuildToken;
end;

procedure TfrmSimple.btnVerifyTJOSEClick(Sender: TObject);
begin
  if VerifyToken then
    memoJSON.Lines.Add('Token signature is verified')
  else
    memoJSON.Lines.Add('Token signature is not verified')
end;

procedure TfrmSimple.BuildToken;
var
  LToken: TJWT;
  LAlg: TJOSEAlgorithmId;
begin
  // Create a JWT Object
  LToken := TJWT.Create;
  try
    // Token claims

    LToken.Claims.Subject := 'Paolo Rossi';
    LToken.Claims.IssuedAt := Now;
    LToken.Claims.Expiration := Now + 1;
    LToken.Claims.Issuer := 'Delphi JOSE Library';

    // Signing algorithm
    case cbbAlgorithm.ItemIndex of
      0: LAlg := TJOSEAlgorithmId.HS256;
      1: LAlg := TJOSEAlgorithmId.HS384;
      2: LAlg := TJOSEAlgorithmId.HS512;
    else LAlg := TJOSEAlgorithmId.HS256;
    end;

    // Signing and compact format creation.
    FCompact := TJOSE.SerializeCompact(edtSecret.Text, LAlg, LToken);

    // Token in compact representation
    memoCompact.Lines.Add(FCompact);

    // Header and Claims JSON representation
    memoJSON.Lines.Add('Header: ' + TJSONUtils.ToJSON(LToken.Header.JSON));
    memoJSON.Lines.Add('Claims: ' + TJSONUtils.ToJSON(LToken.Claims.JSON));
  finally
    LToken.Free;
  end;
end;

procedure TfrmSimple.btnDeserializeTJOSEClick(Sender: TObject);
begin
  DeserializeToken;
end;

procedure TfrmSimple.btnVerifyClassesClick(Sender: TObject);
begin
  if VerifyTokenComplete then
    memoJSON.Lines.Add('Token signature is verified')
  else
    memoJSON.Lines.Add('Token signature is not verified')
end;

procedure TfrmSimple.BuildTokenComplete;
var
  LToken: TJWT;
  LSigner: TJWS;
  LKey: TJWK;
  LAlg: TJOSEAlgorithmId;
begin
  LToken := TJWT.Create;
  try
    LToken.Claims.Issuer := 'Delphi JOSE Library';
    LToken.Claims.IssuedAt := Now;
    LToken.Claims.Expiration := Now + 1;

    // Signing algorithm
    case cbbAlgorithm.ItemIndex of
      0: LAlg := TJOSEAlgorithmId.HS256;
      1: LAlg := TJOSEAlgorithmId.HS384;
      2: LAlg := TJOSEAlgorithmId.HS512;
    else LAlg := TJOSEAlgorithmId.HS256;
    end;

    LSigner := TJWS.Create(LToken);
    try
      LKey := TJWK.Create(edtSecret.Text);
      try
        // With this option you can have keys < algorithm length
        LSigner.SkipKeyValidation := True;

        LSigner.Sign(LKey, LAlg);
        FCompact := LSigner.CompactToken;

        memoJSON.Lines.Add('Header: ' + TJSONUtils.ToJSON(LToken.Header.JSON));
        memoJSON.Lines.Add('Claims: ' + TJSONUtils.ToJSON(LToken.Claims.JSON));

        memoCompact.Lines.Add('Header: ' + LSigner.Header);
        memoCompact.Lines.Add('Payload: ' + LSigner.Payload);
        memoCompact.Lines.Add('Signature: ' + LSigner.Signature);
        memoCompact.Lines.Add('Compact Token: ' + LSigner.CompactToken);
      finally
        LKey.Free;
      end;
    finally
      LSigner.Free;
    end;
  finally
    LToken.Free;
  end;
end;

procedure TfrmSimple.DeserializeToken;
var
  LToken: TJWT;
begin
  // Unpack and verify the token
  LToken := TJOSE.DeserializeCompact(edtSecret.Text, FCompact);
  try
    if Assigned(LToken) then
      memoJSON.Lines.Add(LToken.Claims.JSON.ToJSON);
  finally
    LToken.Free;
  end;
end;

procedure TfrmSimple.edtSecretChange(Sender: TObject);
begin
  edtSecret.EditLabel.Caption := Format(SECRET_CAPTION, [Length(edtSecret.Text) * 8]);
end;

function TfrmSimple.VerifyToken: Boolean;
var
  LToken: TJWT;
begin
  Result := False;

  // Unpack and verify the token
  LToken := TJOSE.Verify(edtSecret.Text, FCompact);

  if Assigned(LToken) then
  begin
    try
      Result := LToken.Verified;
    finally
      LToken.Free;
    end;
  end;
end;

function TfrmSimple.VerifyTokenComplete: Boolean;
var
  LKey: TJWK;
  LToken: TJWT;
  LSigner: TJWS;
begin
  LKey := TJWK.Create(edtSecret.Text);
  try
    LToken := TJWT.Create;
    try
      LSigner := TJWS.Create(LToken);
      try
        LSigner.SetKey(LKey);
        LSigner.CompactToken := FCompact;
        Result := LSigner.VerifySignature;
      finally
        LSigner.Free;
      end;
    finally
      LToken.Free;
    end;
  finally
    LKey.Free;
  end;
end;

end.
