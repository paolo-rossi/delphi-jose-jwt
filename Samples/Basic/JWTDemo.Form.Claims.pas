{******************************************************************************}
{                                                                              }
{  Delphi JOSE Library                                                         }
{  Copyright (c) 2015-2016 Paolo Rossi                                              }
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
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Vcl.ComCtrls, Vcl.ExtCtrls;

type
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
  private
    { Private declarations }
  public
    { Public declarations }
  end;


implementation

{$R *.dfm}

end.
