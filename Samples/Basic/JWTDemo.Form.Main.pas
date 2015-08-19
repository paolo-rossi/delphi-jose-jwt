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

unit JWTDemo.Form.Main;

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
    btnBuild: TButton;
    btnTJOSEBuild: TButton;
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
    btnTJOSEVerify: TButton;
    procedure btnTJOSEVerifyClick(Sender: TObject);
    procedure btnBuildClick(Sender: TObject);
    procedure btnTJOSEBuildClick(Sender: TObject);
  private
    //FToken: TJWT;
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

procedure TfrmMain.btnTJOSEVerifyClick(Sender: TObject);
var
  LKey: TJWK;
  LToken: TJWT;
begin
  LKey := TJWK.Create('secret');
  // Unpack and verify the token
  LToken := TJOSE.Verify(LKey, 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJXaVJMIn0.w3BAZ_GwfQYY6dkS8xKUNZ_sOnkDUMELxBN0mKKNhJ4');

  if Assigned(LToken) then
  begin
    try
      if LToken.Verified then
        mmoJSON.Lines.Add('Token signature is verified')
      else
        mmoJSON.Lines.Add('Token signature is not verified')
    finally
      LToken.Free;
    end;
  end;
end;

procedure TfrmMain.btnBuildClick(Sender: TObject);
var
  LToken: TJWT;
  LSigner: TJWS;
  LKey: TJWK;
  LClaims: TMyClaims;
begin
  LToken := TJWT.Create(TJWTClaims);
  try
    LToken.Claims.Issuer := 'WiRL REST Library';
    LToken.Claims.IssuedAt := Now;
    LToken.Claims.Expiration := Now + 1;

    LSigner := TJWS.Create(LToken);
    LKey := TJWK.Create('secret');
    try
      LSigner.Sign(LKey, HS256);

      mmoJSON.Lines.Add('Header: ' + LToken.Header.JSON.ToJSON);
      mmoJSON.Lines.Add('Claims: ' + LToken.Claims.JSON.ToJSON);

      mmoCompact.Lines.Add('Header: ' + LSigner.Header);
      mmoCompact.Lines.Add('Payload: ' + LSigner.Payload);
      mmoCompact.Lines.Add('Signature: ' + LSigner.Signature);
      mmoCompact.Lines.Add('Compact Token: ' + LSigner.CompactToken);
    finally
      LKey.Free;
      LSigner.Free;
    end;
  finally
    LToken.Free;
  end;
end;

procedure TfrmMain.btnTJOSEBuildClick(Sender: TObject);
var
  LToken: TJWT;
begin
  LToken := TJWT.Create(TJWTClaims);
  try
    // Token claims
    LToken.Claims.IssuedAt := Now;
    LToken.Claims.Expiration := Now + 1;
    LToken.Claims.Issuer := 'WiRL REST Library';

    // Signing and Compact format creation
    mmoCompact.Lines.Add(TJOSE.SHA256CompactToken('secret', LToken));

    // Header and Claims JSON representation
    mmoJSON.Lines.Add(LToken.Header.JSON.ToJSON);
    mmoJSON.Lines.Add(LToken.Claims.JSON.ToJSON);
  finally
    LToken.Free;
  end;
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
