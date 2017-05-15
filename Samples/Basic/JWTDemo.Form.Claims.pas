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
  System.Rtti, System.Generics.Collections,
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
  TMyClaims = class(TJWTClaims)
  private
    function GetAppIssuer: string;
    procedure SetAppIssuer(const Value: string);
  public
    property AppIssuer: string read GetAppIssuer write SetAppIssuer;
  end;

  TfrmClaims = class(TForm)
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
    btnCustomJWS: TButton;
    edtIssuedAtDate: TDateTimePicker;
    edtExpiresTime: TDateTimePicker;
    edtNotBeforeTime: TDateTimePicker;
    cbbAlgorithm: TComboBox;
    Button1: TButton;
    Button2: TButton;
    Memo1: TMemo;
    btnConsumerBuild: TButton;
    edtSubject: TLabeledEdit;
    chkSubject: TCheckBox;
    edtAudience: TLabeledEdit;
    chkAudience: TCheckBox;
    Button3: TButton;
    Button4: TButton;
    btnArray: TButton;
    Label1: TLabel;
    btnConsumerProcess: TButton;
    Button5: TButton;
    procedure btnArrayClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure btnConsumerBuildClick(Sender: TObject);
    procedure btnCustomJWSClick(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure Button1Click(Sender: TObject);
    procedure Button2Click(Sender: TObject);
    procedure Button3Click(Sender: TObject);
    procedure Button4Click(Sender: TObject);
    procedure btnConsumerProcessClick(Sender: TObject);
    procedure Button5Click(Sender: TObject);
  private
    const JWT_SUB =
      'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.' +
      'eyJzdWIiOiJQYW9sbyIsImlhdCI6NTEzMTgxNzcxOX0.' +
      'KhWaLAR2_VUaID1hjwDwy6p7FEYCIVkFhGAetvtfBQw';
  private
    FJWT: TJWT;
    FConsumer: TJOSEConsumer;
    FCompact: TJOSEBytes;
  public
    { Public declarations }
  end;


implementation

uses
  System.DateUtils,
  JOSE.Types.Arrays,
  JOSE.Consumer.Validators;

{$R *.dfm}

procedure TfrmClaims.btnArrayClick(Sender: TObject);
var
  LJA, LJB, LJC: TJOSEArray<string>;
  LA, LB, LC: TArray<string>;
begin
  LJA := TJOSEArray<string>.Create;

  LJA.Push('Paolo');
  LJA.Push('Pluto');
  LJA.Push('Pippo');

  LA := LJA;

  LJA.Pop;

  Memo1.Lines.Add(LJA.ToString);

  LB := LA;

  LJA := LJA + LA + LB;

  Memo1.Lines.Add(LJA.ToString);
end;

procedure TfrmClaims.FormCreate(Sender: TObject);
begin
  edtIssuedAtDate.Date := Now;
  edtIssuedAtTime.Time := Now;

  edtExpiresDate.Date := Now;
  edtExpiresTime.Time := Now;

  edtNotBeforeDate.Date := Now;
  edtNotBeforeTime.Time := Now;
end;

procedure TfrmClaims.btnConsumerBuildClick(Sender: TObject);
begin
  if not Assigned(FConsumer) then
    FConsumer := TJOSEConsumerBuilder.NewConsumer
      .SetRequireIssuedAt
      .SetClaimsClass(TJWTClaims)
      .SetVerificationKey('secret')
      .SetSkipVerificationKeyValidation
      .SetDisableRequireSignature
      .SetExpectedSubject('paolo-rossi')
      .SetRequireExpirationTime
      .SetExpectedAudience()
      .SetAllowedClockSkewInSeconds(2)
      .Build();
end;

procedure TfrmClaims.btnConsumerProcessClick(Sender: TObject);
begin
  if Assigned(FConsumer) then
    FConsumer.Process(FCompact);
end;

procedure TfrmClaims.btnCustomJWSClick(Sender: TObject);
var
  LJWT: TJWT;
begin
  LJWT := TJWT.Create;

  if chkIssuer.Checked then
    LJWT.Claims.Issuer := edtIssuer.Text;

  if chkSubject.Checked then
    LJWT.Claims.Subject := edtSubject.Text;

  if chkAudience.Checked then
    LJWT.Claims.Audience := edtAudience.Text;

  if chkIssuedAt.Checked then
    LJWT.Claims.IssuedAt := edtIssuedAtDate.Date + edtIssuedAtTime.Time;

  if chkNotBefore.Checked then
    LJWT.Claims.NotBefore := edtNotBeforeDate.Date + edtNotBeforeTime.Time;

  FCompact := TJOSE.SHA256CompactToken('secret', LJWT);

  Memo1.Lines.Text := FCompact;
  LJWT.Free;
end;

procedure TfrmClaims.FormDestroy(Sender: TObject);
begin
  FJWT.Free;
  FConsumer.Free;
end;

procedure TfrmClaims.Button1Click(Sender: TObject);
begin
  FJWT := TJWT.Create(TMyClaims);

  //FJWT.Claims.Audience := 'paolo';
  FJWT.GetClaimsAs<TMyClaims>.AppIssuer := 'WiRL';
end;

procedure TfrmClaims.Button2Click(Sender: TObject);
begin

  Memo1.Lines.Add(TJSONUtils.ToJSON(FJWT.Claims.JSON));
  //if FJWT.Claims.HasAudience then
    Memo1.Lines.Add(FJWT.Claims.Audience);
  Memo1.Lines.Add(FJWT.GetClaimsAs<TMyClaims>.AppIssuer);

end;

procedure TfrmClaims.Button3Click(Sender: TObject);
begin
  //THMAC.Sign([3, 45, 44, 55, 43, 56], [56, 48, 52, 53, 54, 55, 56], THMACAlgorithm.SHA256);
end;

procedure TfrmClaims.Button4Click(Sender: TObject);
var
  LJWT: TJWT;
begin
  LJWT := TJWT.Create;

  if chkAudience.Checked then
    LJWT.Claims.Audience := edtAudience.Text;

  if chkSubject.Checked then
    LJWT.Claims.Subject := edtSubject.Text;

  if chkIssuer.Checked then
    LJWT.Claims.Issuer := edtIssuer.Text;

  if chkIssuedAt.Checked then
    LJWT.Claims.IssuedAt := Now;

  if chkExpires.Checked then
    LJWT.Claims.Expiration := IncSecond(Now, 5);

  FCompact := TJOSE.SHA256CompactToken('secret', LJWT);

  Memo1.Lines.Text := FCompact;
  LJWT.Free;
end;

procedure TfrmClaims.Button5Click(Sender: TObject);
var
  E: EStringListError;
begin
  E := EStringListError.Create('errore');
  raise E;

end;

{ TMyClaims }

function TMyClaims.GetAppIssuer: string;
begin
  Result := TJSONUtils.GetJSONValue('ais', FJSON).AsString;
end;

procedure TMyClaims.SetAppIssuer(const Value: string);
begin
  TJSONUtils.SetJSONValueFrom<string>('ais', Value, FJSON);
end;


end.
