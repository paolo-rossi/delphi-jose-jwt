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

unit JWTDemo.Form.Claims;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Vcl.ComCtrls, Vcl.ExtCtrls, System.ImageList,
  System.Rtti, System.Generics.Collections, Vcl.ImgList, System.Actions, Vcl.ActnList,
  JOSE.Core.JWT,
  JOSE.Core.JWS,
  JOSE.Core.JWE,
  JOSE.Core.JWK,
  JOSE.Core.JWA,
  JOSE.Types.JSON,
  JOSE.Types.Bytes,
  JOSE.Core.Builder,
  JOSE.Consumer,
  JOSE.Hashing.HMAC,
  JOSE.Encoding.Base64;

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
    btnCustomJWS: TButton;
    edtJWTId: TLabeledEdit;
    chkJWTId: TCheckBox;
    edtSecret: TLabeledEdit;
    edtHeader: TLabeledEdit;
    edtPayload: TLabeledEdit;
    edtSignature: TLabeledEdit;
    memoJSON: TMemo;
    bvlClaims: TBevel;
    edtAppIssuer: TLabeledEdit;
    edtAppSite: TLabeledEdit;
    edtEmail: TLabeledEdit;
    lblClaims: TLabel;
    procedure actBuildJWSExecute(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
  private
    const JWT_SUB =
      'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.' +
      'eyJzdWIiOiJQYW9sbyIsImlhdCI6NTEzMTgxNzcxOX0.' +
      'KhWaLAR2_VUaID1hjwDwy6p7FEYCIVkFhGAetvtfBQw';
  private
    FToken: TJWT;

    FNow: TDateTime;
    FCompact: TJOSEBytes;
    FCompactHeader: string;
    FCompactPayload: string;
    FCompactSignature: string;

    procedure SetNow;
    procedure SetCompact(const Value: TJOSEBytes);
  protected
    function BuildJWT(AClaimsClass: TJWTClaimsClass): TJOSEBytes;
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
begin
  Compact := BuildJWT(TMyClaims);

  edtHeader.Text := FCompactHeader;
  edtPayload.Text := FCompactPayload;
  edtSignature.Text := FCompactSignature;
end;

procedure TfrmClaims.FormCreate(Sender: TObject);
begin
  SetNow;
end;

function TfrmClaims.BuildJWT(AClaimsClass: TJWTClaimsClass): TJOSEBytes;
var
  LAlg: TJOSEAlgorithmId;
  LCustomClaims: TMyClaims;
begin
  if Assigned(FToken) then
    FToken.Free;

  FToken := TJWT.Create(AClaimsClass);

  SetNow;

  if chkIssuer.Checked then
    FToken.Claims.Issuer := edtIssuer.Text;

  if chkSubject.Checked then
    FToken.Claims.Subject := edtSubject.Text;

  if chkAudience.Checked then
    FToken.Claims.Audience := edtAudience.Text;

  if chkJWTId.Checked then
    FToken.Claims.JWTId := edtJWTId.Text;

  if chkIssuedAt.Checked then
    FToken.Claims.IssuedAt := edtIssuedAtDate.Date + edtIssuedAtTime.Time;

  if chkExpires.Checked then
    FToken.Claims.Expiration := edtExpiresDate.Date + edtExpiresTime.Time;

  if chkNotBefore.Checked then
    FToken.Claims.NotBefore := edtNotBeforeDate.Date + edtNotBeforeTime.Time;

  case cbbAlgorithm.ItemIndex of
    0: LAlg := TJOSEAlgorithmId.HS256;
    1: LAlg := TJOSEAlgorithmId.HS384;
    2: LAlg := TJOSEAlgorithmId.HS512;
    else LAlg := TJOSEAlgorithmId.HS256;
  end;

  // Custom claims
  LCustomClaims := FToken.ClaimsAs<TMyClaims>;
  LCustomClaims.AppIssuer := edtAppIssuer.Text;
  LCustomClaims.AppSite := edtAppSite.Text;
  LCustomClaims.Email := edtEmail.Text;

  Result := TJOSE.SerializeCompact(edtSecret.Text, LAlg, FToken);
end;

procedure TfrmClaims.FormDestroy(Sender: TObject);
begin
  FToken.Free;
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

{ TMyClaims }

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
