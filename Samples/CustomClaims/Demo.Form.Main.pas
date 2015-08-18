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
  System.Generics.Collections, Vcl.ExtCtrls, Vcl.ComCtrls,
  JOSE.Core.JWT, JOSE.Core.JWS, JOSE.Core.JWK, JOSE.Core.JWA, JOSE.Types.JSON;

type
  TMyClaims = class(TJWTClaims)
  private
    function GetAppIssuer: string;
    procedure SetAppIssuer(const Value: string);
  public
    property AppIssuer: string read GetAppIssuer write SetAppIssuer;
  end;

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
    { Private declarations }
  public
    { Public declarations }
  end;

var
  frmMain: TfrmMain;

implementation

uses
  System.Rtti,
  JOSE.Types.Bytes,
  JOSE.Core.Builder;

{$R *.dfm}

procedure TfrmMain.Button8Click(Sender: TObject);
var
  LToken: TJWT;
  LSigned: TJWS;
  LKey: TJWK;
  LClaims: TMyClaims;
begin
  LToken := TJWT.Create(TMyClaims);
  LKey := TJWK.Create('secret');

  LClaims := LToken.Claims as TMyClaims;

  LClaims.Issuer := 'WiRL';
  LClaims.AppIssuer :='JWTDemo';

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

function TMyClaims.GetAppIssuer: string;
begin
  Result := TJSONUtils.GetJSONValue('ais', FJSON).AsString;
end;

procedure TMyClaims.SetAppIssuer(const Value: string);
begin
  TJSONUtils.SetJSONValueFrom<string>('ais', Value, FJSON);
end;

end.
