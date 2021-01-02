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

unit Demo.Form.Main;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, IdGlobal, System.Generics.Defaults,
  System.Generics.Collections, Vcl.ExtCtrls, Vcl.ComCtrls,

  JOSE.Core.JWT,
  JOSE.Core.JWS,
  JOSE.Core.JWK,
  JOSE.Core.JWA,
  JOSE.Types.JSON;

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
    Button1: TButton;
    edtIssuedAtDate: TDateTimePicker;
    edtExpiresTime: TDateTimePicker;
    edtNotBeforeTime: TDateTimePicker;
    cbbAlgorithm: TComboBox;
    Label6: TLabel;
    procedure btnCustomClaimsClick(Sender: TObject);
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
    LClaims.Issuer := 'WiRL REST Library';
    LClaims.AppIssuer :='CustomClaims';

    mmoCompact.Lines.Add(TJOSE.SHA256CompactToken('secret', LToken));

    mmoJSON.Lines.Add(TJSONUtils.ToJSON(LToken.Header.JSON));
    mmoJSON.Lines.Add(TJSONUtils.ToJSON(LToken.Claims.JSON));
  finally
    LToken.Free;
  end;
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
