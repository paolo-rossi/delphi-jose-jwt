{******************************************************************************}
{                                                                              }
{  Delphi JOSE Library                                                         }
{  Copyright (c) 2015-2017 Paolo Rossi                                         }
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

unit JWTDemo.Form.Claims;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Vcl.ComCtrls, Vcl.ExtCtrls,
  System.Rtti, System.Generics.Collections, Vcl.ImgList, System.Actions, Vcl.ActnList,
  JOSE.Core.JWT,
  JOSE.Core.JWS,
  JOSE.Core.JWE,
  JOSE.Core.JWK,
  JOSE.Core.JWA,
  JOSE.Types.JSON,
  JOSE.Types.Bytes,
  JOSE.Core.Builder,
  JOSE.Hashing.HMAC,
  JOSE.Consumer,
  JOSE.Encoding.Base64, System.ImageList;

type
  TMyClaims = class(TJWTClaims)
  private
    function GetAppIssuer: string;
    function GetEmail: string;
    procedure SetAppIssuer(const Value: string);
    procedure SetEmail(const Value: string);
    function GetAppSite: string;
    procedure SetAppSite(const Value: string);
  public
    property AppIssuer: string read GetAppIssuer write SetAppIssuer;
    property AppSite: string read GetAppSite write SetAppSite;
    property Email: string read GetEmail write SetEmail;
  end;

  TfrmClaims = class(TForm)
    memoLog: TMemo;
    grpClaims: TGroupBox;
    Label3: TLabel;
    Label4: TLabel;
    Label5: TLabel;
    Label6: TLabel;
    edtIssuer: TLabeledEdit;
    edtIssuedAtTime: TDateTimePicker;
    edtNotBeforeDate: TDateTimePicker;
    edtExpiresDate: TDateTimePicker;
    chkIssuer: TCheckBox;
    chkIssuedAt: TCheckBox;
    chkExpires: TCheckBox;
    chkNotBefore: TCheckBox;
    edtIssuedAtDate: TDateTimePicker;
    edtExpiresTime: TDateTimePicker;
    edtNotBeforeTime: TDateTimePicker;
    cbbAlgorithm: TComboBox;
    edtSubject: TLabeledEdit;
    chkSubject: TCheckBox;
    edtAudience: TLabeledEdit;
    chkAudience: TCheckBox;
    actListMain: TActionList;
    actBuildJWS: TAction;
    imgListMain: TImageList;
    actBuildJWTConsumer: TAction;
    btnCustomJWS: TButton;
    edtJWTId: TLabeledEdit;
    chkJWTId: TCheckBox;
    edtSecret: TLabeledEdit;
    edtHeader: TLabeledEdit;
    edtPayload: TLabeledEdit;
    edtSignature: TLabeledEdit;
    actBuildJWTCustomConsumer: TAction;
    memoJSON: TMemo;
    procedure actBuildJWSExecute(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
  private
    const JWT_SUB =
      'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.' +
      'eyJzdWIiOiJQYW9sbyIsImlhdCI6NTEzMTgxNzcxOX0.' +
      'KhWaLAR2_VUaID1hjwDwy6p7FEYCIVkFhGAetvtfBQw';
  private
    FJWT: TJWT;
    FNow: TDateTime;
    FCompact: TJOSEBytes;
    FCompactHeader: string;
    FCompactPayload: string;
    FCompactSignature: string;

    procedure SetNow;
    procedure SetCompact(const Value: TJOSEBytes);
  protected
    function BuildJWT: TJOSEBytes;
  public
    property Compact: TJOSEBytes read FCompact write SetCompact;
  end;


implementation

uses
  System.DateUtils,
  JOSE.Core.Base,
  JOSE.Types.Arrays,
  JOSE.Consumer.Validators;

{$R *.dfm}

{ TfrmClaims }

procedure TfrmClaims.actBuildJWSExecute(Sender: TObject);
var
  LToken: TJWT;
  LSigner: TJWS;
  LKey: TJWK;
begin
  LToken := TJWT.Create(TMyClaims);
  try
    LToken.Claims.Issuer := 'Delphi JOSE Library';
    LToken.Claims.IssuedAt := Now;
    LToken.Claims.Expiration := Now + 1;

    // Custom Claims
    (LToken.Claims as TMyClaims).AppIssuer := 'WiRL REST Library';
    (LToken.Claims as TMyClaims).AppSite := 'https://github.com/delphi-blocks/WiRL';
    (LToken.Claims as TMyClaims).Email := 'my@mail.com';
    // End Custom Claims

    LSigner := TJWS.Create(LToken);
    LKey := TJWK.Create(edtSecret.Text);
    try
      LSigner.Sign(LKey, TJOSEAlgorithmId.HS256);

      memoJSON.Lines.Add('Header: ' + TJSONUtils.ToJSON(LToken.Header.JSON));
      memoJSON.Lines.Add('Claims: ' + TJSONUtils.ToJSON(LToken.Claims.JSON));

      edtHeader.Text := LSigner.Header;
      edtPayload.Text := LSigner.Payload;
      edtSignature.Text := LSigner.Signature;

      memoLog.Lines.Add('Compact Token: ' + LSigner.CompactToken);
    finally
      LKey.Free;
      LSigner.Free;
    end;
  finally
    LToken.Free;
  end;
end;

procedure TfrmClaims.FormCreate(Sender: TObject);
begin
  SetNow;
end;

function TfrmClaims.BuildJWT: TJOSEBytes;
var
  LJWT: TJWT;
  LAlg: TJOSEAlgorithmId;
begin
  LJWT := TJWT.Create;
  try
    SetNow;

    if chkIssuer.Checked then
      LJWT.Claims.Issuer := edtIssuer.Text;

    if chkSubject.Checked then
      LJWT.Claims.Subject := edtSubject.Text;

    if chkAudience.Checked then
      LJWT.Claims.Audience := edtAudience.Text;

    if chkJWTId.Checked then
      LJWT.Claims.JWTId := edtJWTId.Text;

    if chkIssuedAt.Checked then
      LJWT.Claims.IssuedAt := edtIssuedAtDate.Date + edtIssuedAtTime.Time;

    if chkExpires.Checked then
      LJWT.Claims.Expiration := edtExpiresDate.Date + edtExpiresTime.Time;

    if chkNotBefore.Checked then
      LJWT.Claims.NotBefore := edtNotBeforeDate.Date + edtNotBeforeTime.Time;

    case cbbAlgorithm.ItemIndex of
      0: LAlg := TJOSEAlgorithmId.HS256;
      1: LAlg := TJOSEAlgorithmId.HS384;
      2: LAlg := TJOSEAlgorithmId.HS512;
      else LAlg := TJOSEAlgorithmId.HS256;
    end;

    Result := TJOSE.SerializeCompact(edtSecret.Text,  LAlg, LJWT);
  finally
    LJWT.Free;
  end;
end;

procedure TfrmClaims.FormDestroy(Sender: TObject);
begin
  FJWT.Free;
end;

procedure TfrmClaims.SetCompact(const Value: TJOSEBytes);
var
  LSplit: TArray<string>;
begin
  FCompact := Value;
  LSplit := FCompact.AsString.Split(['.']);

  if Length(LSplit) < 3 then
    raise Exception.Create('Malformed compact representation');

  FCompactHeader := LSplit[0];
  FCompactPayload := LSplit[1];
  FCompactSignature := LSplit[2];
end;

procedure TfrmClaims.SetNow;
begin
  FNow := Now;

  edtIssuedAtDate.Date := FNow;
  edtIssuedAtTime.Time := FNow;

  edtExpiresDate.Date := IncSecond(FNow, 5);
  edtExpiresTime.Time := IncSecond(FNow, 5);

  edtNotBeforeDate.Date := IncMinute(FNow, -10);
  edtNotBeforeTime.Time := IncMinute(FNow, -10);
end;

function TMyClaims.GetAppIssuer: string;
begin
  Result := TJSONUtils.GetJSONValue('appissuer', FJSON).AsString;
end;

function TMyClaims.GetAppSite: string;
begin
  Result := TJSONUtils.GetJSONValue('appsite', FJSON).AsString;
end;

function TMyClaims.GetEmail: string;
begin
  Result := TJSONUtils.GetJSONValue('email', FJSON).AsString;
end;

procedure TMyClaims.SetAppIssuer(const Value: string);
begin
  TJSONUtils.SetJSONValueFrom<string>('appissuer', Value, FJSON);
end;

procedure TMyClaims.SetAppSite(const Value: string);
begin
  TJSONUtils.SetJSONValueFrom<string>('appsite', Value, FJSON);
end;

procedure TMyClaims.SetEmail(const Value: string);
begin
  TJSONUtils.SetJSONValueFrom<string>('email', Value, FJSON);
end;


end.
