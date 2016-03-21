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
  JWTDemo.Form.Debugger,
  JOSE.Core.JWT,
  JOSE.Core.JWS,
  JOSE.Core.JWK,
  JOSE.Core.JWA,
  JOSE.Types.JSON;

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

  TfrmMain = class(TForm)
    PageControl1: TPageControl;
    tsSimple: TTabSheet;
    tsCustom: TTabSheet;
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
    btnBuild: TButton;
    btnTJOSEBuild: TButton;
    btnTJOSEVerify: TButton;
    btnTestClaims: TButton;
    tsDebugger: TTabSheet;
    Label1: TLabel;
    mmoJSON: TMemo;
    Label2: TLabel;
    mmoCompact: TMemo;
    procedure FormCreate(Sender: TObject);
    procedure btnTJOSEVerifyClick(Sender: TObject);
    procedure btnBuildClick(Sender: TObject);
    procedure btnTestClaimsClick(Sender: TObject);
    procedure btnTJOSEBuildClick(Sender: TObject);
  private
    FDebuggerView: TfrmDebugger;
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

procedure TfrmMain.FormCreate(Sender: TObject);
begin
  FDebuggerView := TfrmDebugger.Create(Application);
  FDebuggerView.BorderStyle := bsNone;
  FDebuggerView.Top := 0;
  FDebuggerView.Left := 0;
  FDebuggerView.Parent := tsDebugger;
  FDebuggerView.Align := alClient;
  FDebuggerView.Show;
end;

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
begin
  LToken := TJWT.Create(TMyClaims);
  try
    LToken.Claims.Issuer := 'Delphi JOSE Library';
    LToken.Claims.IssuedAt := Now;
    LToken.Claims.Expiration := Now + 1;
    //Custom Claims
    (LToken.Claims as TMyClaims).AppIssuer := 'MARS REST Library';
    (LToken.Claims as TMyClaims).AppSite := 'https://github.com/MARS-library/MARS';
    (LToken.Claims as TMyClaims).Email := 'my@mail.com';

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

procedure TfrmMain.btnTestClaimsClick(Sender: TObject);
var
  LToken: TJWT;
begin
  // Create a JWT Object
  LToken := TJWT.Create(TJWTClaims);
  try
    LToken.Claims.IssuedAt := Now;
    mmoJSON.Lines.Add('IssuedAt: ' + DateTimeToStr(LToken.Claims.IssuedAt));
  finally
    LToken.Free;
  end;
end;

procedure TfrmMain.btnTJOSEBuildClick(Sender: TObject);
var
  LToken: TJWT;
begin
  // Create a JWT Object
  LToken := TJWT.Create(TJWTClaims);
  try
    // Token claims
    LToken.Claims.IssuedAt := Now;
    LToken.Claims.Expiration := Now + 1;
    LToken.Claims.Issuer := 'Delphi JOSE Library';

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
