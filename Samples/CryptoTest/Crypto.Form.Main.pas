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

unit Crypto.Form.Main;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Classes,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Vcl.ExtCtrls, Vcl.ComCtrls,

  Crypto.Form.SSL,
  Crypto.Form.RSA,
  Crypto.Form.ECDSA;

type
  TfrmMain = class(TForm)
    pgcMain: TPageControl;
    procedure FormCreate(Sender: TObject);
  private
    procedure PasteForm(AFormClass: TFormClass; const ATabName, ATabTitle: string);
  public
    { Public declarations }
  end;

var
  frmMain: TfrmMain;

implementation

{$R *.dfm}

procedure TfrmMain.FormCreate(Sender: TObject);
begin
  PasteForm(TfrmCryptoRSA,   'tsRSA',   'RSA stuff');
  PasteForm(TfrmCryptoECDSA, 'tsECDSA', 'ECDSA stuff');
  PasteForm(TfrmCryptoSSL,   'tsSSL',   'Misc SSL stuff');
  pgcMain.ActivePageIndex := 0;
end;

procedure TfrmMain.PasteForm(AFormClass: TFormClass; const ATabName, ATabTitle: string);
var
  LView: TForm;
  LTab: TTabSheet;
begin
  LTab := TTabSheet.Create(Self);
  LTab.PageControl := pgcMain;
  LTab.Name := ATabName;
  LTab.Caption := ATabTitle;

  LView := AFormClass.Create(Application);
  LView.BorderStyle := bsNone;
  LView.Top := 0;
  LView.Left := 0;
  LView.Parent := LTab;
  LView.Align := alClient;
  LView.Show;
end;

end.
