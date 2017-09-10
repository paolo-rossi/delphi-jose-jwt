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

unit JWTDemo.Form.Simple;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls,

  JOSE.Core.JWT,
  JOSE.Core.JWS,
  JOSE.Core.JWK,
  JOSE.Core.JWA,
  JOSE.Types.JSON;

type
  TfrmSimple = class(TForm)
    lbl1: TLabel;
    lbl2: TLabel;
    btnBuild: TButton;
    btnTJOSEBuild: TButton;
    btnTJOSEVerify: TButton;
    btnTestClaims: TButton;
    memoJSON: TMemo;
    memoCompact: TMemo;
    procedure btnBuildClick(Sender: TObject);
    procedure btnTestClaimsClick(Sender: TObject);
    procedure btnTJOSEBuildClick(Sender: TObject);
    procedure btnTJOSEVerifyClick(Sender: TObject);
  private
    procedure BuildJWT;
    procedure VerifyJWT;
  public
    { Public declarations }
  end;

implementation

uses
  System.Rtti,
  JOSE.Types.Bytes,
  JOSE.Core.Builder;

{$R *.dfm}

procedure TfrmSimple.btnBuildClick(Sender: TObject);
var
  LToken: TJWT;
  LSigner: TJWS;
  LKey: TJWK;
begin
  LToken := TJWT.Create;
  try
    LToken.Claims.Issuer := 'Delphi JOSE Library';
    LToken.Claims.IssuedAt := Now;
    LToken.Claims.Expiration := Now + 1;

    LSigner := TJWS.Create(LToken);
    LKey := TJWK.Create('secret');
    try
      LSigner.Sign(LKey, TJOSEAlgorithmId.HS256);

      memoJSON.Lines.Add('Header: ' + TJSONUtils.ToJSON(LToken.Header.JSON));
      memoJSON.Lines.Add('Claims: ' + TJSONUtils.ToJSON(LToken.Claims.JSON));

      memoCompact.Lines.Add('Header: ' + LSigner.Header);
      memoCompact.Lines.Add('Payload: ' + LSigner.Payload);
      memoCompact.Lines.Add('Signature: ' + LSigner.Signature);
      memoCompact.Lines.Add('Compact Token: ' + LSigner.CompactToken);
    finally
      LKey.Free;
      LSigner.Free;
    end;
  finally
    LToken.Free;
  end;
end;

procedure TfrmSimple.btnTestClaimsClick(Sender: TObject);
var
  LToken: TJWT;
begin
  // Create a JWT Object
  LToken := TJWT.Create;
  try
    LToken.Claims.IssuedAt := Now;
    memoJSON.Lines.Add('IssuedAt: ' + DateTimeToStr(LToken.Claims.IssuedAt));
  finally
    LToken.Free;
  end;
end;

procedure TfrmSimple.btnTJOSEBuildClick(Sender: TObject);
begin
  BuildJWT;
end;

procedure TfrmSimple.btnTJOSEVerifyClick(Sender: TObject);
begin
  VerifyJWT;
end;

procedure TfrmSimple.BuildJWT;
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

    // Signing and Compact format creation.
    // Please use a different secret key in production!!!!!
    memoCompact.Lines.Add(TJOSE.SHA256CompactToken('secret', LToken));

    // Header and Claims JSON representation
    memoJSON.Lines.Add(TJSONUtils.ToJSON(LToken.Header.JSON));
    memoJSON.Lines.Add(TJSONUtils.ToJSON(LToken.Claims.JSON));
  finally
    LToken.Free;
  end;
end;

procedure TfrmSimple.VerifyJWT;
var
  LKey: TJWK;
  LToken: TJWT;
begin
  // 'secret' is the value of the secret key. Only suitable for a demo!!!
  LKey := TJWK.Create('secret');
  // Unpack and verify the token
  LToken := TJOSE.Verify(LKey, 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJXaVJMIn0.w3BAZ_GwfQYY6dkS8xKUNZ_sOnkDUMELxBN0mKKNhJ4');

  if Assigned(LToken) then
  begin
    try
      if LToken.Verified then
        memoJSON.Lines.Add('Token signature is verified')
      else
        memoJSON.Lines.Add('Token signature is not verified')
    finally
      LToken.Free;
    end;
  end;
end;

end.
