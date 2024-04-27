{******************************************************************************}
{                                                                              }
{  Delphi JOSE Library                                                         }
{  Copyright (c) 2015 Paolo Rossi                                              }
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

unit Demo.Form.Main;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, IdGlobal, System.Generics.Defaults,
  System.Generics.Collections, Vcl.ExtCtrls, Vcl.ComCtrls, Vcl.Mask,

  JOSE.Core.JWT,
  JOSE.Core.JWS,
  JOSE.Core.JWK,
  JOSE.Core.JWA,
  JOSE.Types.JSON,
  JOSE.Types.Bytes,
  JOSE.Core.Builder,
  JOSE.Context,
  JOSE.Consumer,
  JOSE.Consumer.Validators;

type
  TMyClaims = class(TJWTClaims)
  private
    function GetNonce: string;
    procedure SetNonce(const Value: string);
    function GetAppIssuer: string;
    procedure SetAppIssuer(const Value: string);
  public
    property Nonce: string read GetNonce write SetNonce;
    property AppIssuer: string read GetAppIssuer write SetAppIssuer;
  end;

  TfrmMain = class(TForm)
    mmoJSON: TMemo;
    btnCustomClaims: TButton;
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
    edtIssuedAtDate: TDateTimePicker;
    edtExpiresTime: TDateTimePicker;
    edtNotBeforeTime: TDateTimePicker;
    cbbAlgorithm: TComboBox;
    Label6: TLabel;
    btnCheckCustom: TButton;
    procedure btnCheckCustomClick(Sender: TObject);
    procedure btnCustomClaimsClick(Sender: TObject);
    procedure Button1Click(Sender: TObject);
  private
    FCompact: TJOSEBytes;
  public
    { Public declarations }
  end;

var
  frmMain: TfrmMain;

implementation

uses
  System.Rtti,
  System.DateUtils;

{$R *.dfm}

procedure TfrmMain.btnCustomClaimsClick(Sender: TObject);
var
  LToken: TJWT;
  LClaims: TMyClaims;
begin
  LToken := TJWT.Create(TMyClaims);
  try
    LClaims := LToken.Claims as TMyClaims;

    LClaims.IssuedAt := Now;
    LClaims.Expiration := Now + 1;
    LClaims.Subject := 'paolo-rossi';
    LClaims.Issuer := 'WiRL REST Library';
    LClaims.AppIssuer :='CustomClaims';
    LClaims.Nonce := '9876543';

    FCompact := TJOSE.SHA256CompactToken('secret', LToken);
    mmoCompact.Lines.Add(FCompact);

    mmoJSON.Lines.Add(TJSONUtils.ToJSON(LToken.Header.JSON));
    mmoJSON.Lines.Add(TJSONUtils.ToJSON(LToken.Claims.JSON));
  finally
    LToken.Free;
  end;
end;

procedure TfrmMain.btnCheckCustomClick(Sender: TObject);
var
  LConsumer: IJOSEConsumer;
begin
  LConsumer := TJOSEConsumerBuilder.NewConsumer
    .SetClaimsClass(TMyClaims)

    // JWS-related validation
    .SetVerificationKey('secret')
    .SetSkipVerificationKeyValidation
    .SetDisableRequireSignature

    // string-based claims validation
    .SetExpectedSubject('paolo-rossi')

    .RegisterValidator(
      function (AJOSEContext: TJOSEContext): string
      var
        LNonce: string;
      begin
        Result := '';
        LNonce := AJOSEContext.GetClaims<TMyClaims>.Nonce;

        if not AJOSEContext.GetClaims.ClaimExists('nonce') then
          Exit('Nonce was not present');

        if not (LNonce = '9876543') then
          Exit(Format('Nonce [nonce] claim value [%s] doesn''t match expected value of [%s]',
            [LNonce, '9876543']));
      end
    )
    // Build the consumer object
    .Build();

  mmoCompact.Lines.Add('======================================');
  try
    LConsumer.Process(FCompact);
    mmoCompact.Lines.Add('Validation process passed');
  except
    on E: EInvalidJWTException do
      mmoCompact.Lines.Add(E.Message);
  end;
end;

procedure TfrmMain.Button1Click(Sender: TObject);
begin

end;

{ TMyClaims }

function TMyClaims.GetAppIssuer: string;
begin
  Result := TJSONUtils.GetJSONValue('ais', FJSON).AsString;
end;

function TMyClaims.GetNonce: string;
begin
  Result := TJSONUtils.GetJSONValue('nonce', FJSON).AsString;
end;

procedure TMyClaims.SetAppIssuer(const Value: string);
begin
  TJSONUtils.SetJSONValueFrom<string>('ais', Value, FJSON);
end;

procedure TMyClaims.SetNonce(const Value: string);
begin
  TJSONUtils.SetJSONValueFrom<string>('nonce', Value, FJSON);
end;

end.
