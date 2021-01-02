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

unit JWTDemo.Form.Consumer;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Vcl.ComCtrls, Vcl.ExtCtrls,
  System.Rtti, System.Generics.Collections, Vcl.ImgList, System.Actions, Vcl.ActnList,
  System.ImageList,
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
  JOSE.Encoding.Base64;

type
  TfrmConsumer = class(TForm)
    memoLog: TMemo;
    grpClaims: TGroupBox;
    lblIssuedAt: TLabel;
    lblExpirationTime: TLabel;
    lblNotBefore: TLabel;
    lblHashAlgorithm: TLabel;
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
    grpConsumer: TGroupBox;
    btnConsumerBuild: TButton;
    actBuildJWTCustomConsumer: TAction;
    btnBuildJWTCustomConsumer: TButton;
    edtConsumerSecret: TLabeledEdit;
    chkConsumerSecret: TCheckBox;
    chkConsumerSkipVerificationKey: TCheckBox;
    chkConsumerSetDisableRequireSignature: TCheckBox;
    edtConsumerSubject: TLabeledEdit;
    chkConsumerSubject: TCheckBox;
    edtConsumerAudience: TLabeledEdit;
    chkConsumerAudience: TCheckBox;
    edtConsumerIssuer: TLabeledEdit;
    chkConsumerIssuer: TCheckBox;
    edtConsumerJWTId: TLabeledEdit;
    chkConsumerJWTId: TCheckBox;
    lblEvaluationTime: TLabel;
    edtConsumerEvaluationDate: TDateTimePicker;
    chkConsumerIssuedAt: TCheckBox;
    chkConsumerExpires: TCheckBox;
    chkConsumerNotBefore: TCheckBox;
    edtSkewTime: TLabeledEdit;
    edtMaxFutureValidity: TLabeledEdit;
    edtConsumerEvaluationTime: TDateTimePicker;
    procedure actBuildJWSExecute(Sender: TObject);
    procedure actBuildJWTConsumerExecute(Sender: TObject);
    procedure actBuildJWTConsumerUpdate(Sender: TObject);
    procedure actBuildJWTCustomConsumerExecute(Sender: TObject);
    procedure actBuildJWTCustomConsumerUpdate(Sender: TObject);
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

    function BuildJWT: TJOSEBytes;
    procedure SetNow;
    procedure SetCompact(const Value: TJOSEBytes);
    procedure ProcessConsumer(AConsumer: IJOSEConsumer);
    function GetCompact: TJOSEBytes;
  public
    property Compact: TJOSEBytes read GetCompact write SetCompact;
  end;


implementation

uses
  System.DateUtils,
  JOSE.Core.Base,
  JOSE.Types.Arrays,
  JOSE.Consumer.Validators;

{$R *.dfm}

{ TfrmConsumer }

procedure TfrmConsumer.actBuildJWSExecute(Sender: TObject);
begin
  Compact := BuildJWT;

  edtHeader.Text := FCompactHeader;
  edtPayload.Text := FCompactPayload;
  edtSignature.Text := FCompactSignature;
end;

procedure TfrmConsumer.actBuildJWTConsumerExecute(Sender: TObject);
var
  LAud: TArray<string>;
begin
  SetLength(LAud, 2);
  LAud[0] := 'Paolo';
  LAud[1] := 'Luca';

  ProcessConsumer(TJOSEConsumerBuilder.NewConsumer
    .SetClaimsClass(TJWTClaims)

    // JWS-related validation
    .SetVerificationKey(edtConsumerSecret.Text)
    .SetSkipVerificationKeyValidation
    .SetDisableRequireSignature

    // string-based claims validation
    .SetExpectedSubject('paolo-rossi')
    .SetExpectedAudience(True, LAud)

    // Time-related claims validation
    .SetRequireIssuedAt
    .SetRequireExpirationTime
    .SetEvaluationTime(IncSecond(FNow, 26))
    .SetAllowedClockSkew(20, TJOSETimeUnit.Seconds)
    .SetMaxFutureValidity(20, TJOSETimeUnit.Minutes)

    // Build the consumer object
    .Build()
  );

  if memoLog.Lines.Count = 0 then
    memoLog.Lines.Add('JWT Validated!')
  else
  begin
    memoLog.Lines.Add(sLineBreak + '==========================================');
    memoLog.Lines.Add('Errors in the validation process!');
  end
end;

procedure TfrmConsumer.actBuildJWTConsumerUpdate(Sender: TObject);
begin
  (Sender as TAction).Enabled := FCompact <> '';
end;

procedure TfrmConsumer.actBuildJWTCustomConsumerExecute(Sender: TObject);
var
  LBuilder: IJOSEConsumerBuilder;
begin
  LBuilder := TJOSEConsumerBuilder.NewConsumer;
  LBuilder.SetClaimsClass(TJWTClaims);

  // JWS-related validation
  if chkConsumerSecret.Checked then
    LBuilder.SetVerificationKey(edtConsumerSecret.Text);

  if chkConsumerSkipVerificationKey.Checked then
    LBuilder.SetSkipVerificationKeyValidation;

  if chkConsumerSetDisableRequireSignature.Checked then
    LBuilder.SetDisableRequireSignature;
  // End JWS-related validation

  // subject claim validation
  if chkConsumerSubject.Checked then
    LBuilder.SetExpectedSubject(edtSubject.Text);

  // audience claim validation
  if chkConsumerAudience.Checked then
    LBuilder.SetExpectedAudience(True, string(edtConsumerAudience.Text).Split([',']))
  else
    LBuilder.SetSkipDefaultAudienceValidation;

  // JWT Id claim validation
  if chkConsumerJWTId.Checked then
    LBuilder.SetRequireJwtId;

  // Issued At claim validation
  if chkConsumerIssuedAt.Checked then
    LBuilder.SetRequireIssuedAt;

  // Expires claim validation
  if chkConsumerExpires.Checked then
    LBuilder.SetRequireExpirationTime;

  // NotBefore claim validation
  if chkConsumerNotBefore.Checked then
    LBuilder.SetRequireNotBefore;

  LBuilder.SetEvaluationTime(edtConsumerEvaluationDate.Date + edtConsumerEvaluationTime.Time);

  LBuilder.SetAllowedClockSkew(StrToInt(edtSkewTime.Text), TJOSETimeUnit.Seconds);
  LBuilder.SetMaxFutureValidity(StrToInt(edtMaxFutureValidity.Text), TJOSETimeUnit.Minutes);

  // Build the consumer object
  memoLog.Lines.Clear;
  ProcessConsumer(LBuilder.Build());
  if memoLog.Lines.Count = 0 then
    memoLog.Lines.Add('JWT Validated!')
  else
  begin
    memoLog.Lines.Add(sLineBreak + '==========================================');
    memoLog.Lines.Add('Errors in the validation process!');
  end
end;

procedure TfrmConsumer.actBuildJWTCustomConsumerUpdate(Sender: TObject);
begin
  (Sender as TAction).Enabled := FCompact <> '';
end;

procedure TfrmConsumer.FormCreate(Sender: TObject);
begin
  SetNow;
end;

function TfrmConsumer.BuildJWT: TJOSEBytes;
var
  LJWT: TJWT;
  LAlg: TJOSEAlgorithmId;
begin
  LJWT := TJWT.Create;
  try

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

procedure TfrmConsumer.FormDestroy(Sender: TObject);
begin
  FJWT.Free;
end;

function TfrmConsumer.GetCompact: TJOSEBytes;
begin
  Result := edtHeader.Text + '.' + edtPayload.Text + '.' + edtSignature.Text;
end;

procedure TfrmConsumer.ProcessConsumer(AConsumer: IJOSEConsumer);
begin
  if Assigned(AConsumer) then
  try
    AConsumer.Process(Compact);
  except
    on E: Exception do
      memoLog.Lines.Add(E.Message);
  end;
end;

procedure TfrmConsumer.SetCompact(const Value: TJOSEBytes);
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

procedure TfrmConsumer.SetNow;
begin
  FNow := Now;

  edtIssuedAtDate.Date := FNow;
  edtIssuedAtTime.Time := FNow;

  edtExpiresDate.Date := IncSecond(FNow, 30);
  edtExpiresTime.Time := IncSecond(FNow, 30);

  edtNotBeforeDate.Date := IncMinute(FNow, -10);
  edtNotBeforeTime.Time := IncMinute(FNow, -10);

  edtConsumerEvaluationDate.Date := FNow;
  edtConsumerEvaluationTime.Time := FNow;
end;


end.
