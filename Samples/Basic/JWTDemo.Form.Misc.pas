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

unit JWTDemo.Form.Misc;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, System.JSON,
  JOSE.Core.JWT,
  JOSE.Core.JWS,
  JOSE.Core.JWK,
  JOSE.Core.JWA,
  JOSE.Types.JSON;

type
  TfrmMisc = class(TForm)
    memoLog: TMemo;
    btnTestJSON: TButton;
    memoInput: TMemo;
    btnArray: TButton;
    btnSign: TButton;
    procedure btnArrayClick(Sender: TObject);
    procedure btnSignClick(Sender: TObject);
    procedure btnTestJSONClick(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure FormCreate(Sender: TObject);
  private
    FJWT: TJWT;
  protected
    procedure SetJSONValue(const AName: string; const AValue: Int64; AJSON: TJSONObject); overload;
    procedure SetJSONValue(const AName: string; const AValue: string; AJSON: TJSONObject); overload;
    procedure TestJSON;
  public
    { Public declarations }
  end;

implementation

uses
  JOSE.Types.Arrays;

{$R *.dfm}

procedure TfrmMisc.btnArrayClick(Sender: TObject);
var
  LJA: TJOSEArray<string>;
  LA, LB: TArray<string>;
begin
  LJA := TJOSEArray<string>.Create;

  LJA.Push('Paolo');
  LJA.Push('Pluto');
  LJA.Push('Pippo');

  LA := LJA;

  LJA.Pop;

  memoLog.Lines.Add(LJA.ToString);

  LB := LA;

  LJA := LJA + LA + LB;

  memoLog.Lines.Add(LJA.ToString);
end;

procedure TfrmMisc.btnSignClick(Sender: TObject);
begin
  //THMAC.Sign([3, 45, 44, 55, 43, 56], [56, 48, 52, 53, 54, 55, 56], THMACAlgorithm.SHA256);
end;

procedure TfrmMisc.btnTestJSONClick(Sender: TObject);
begin
  TestJSON;
end;

procedure TfrmMisc.FormDestroy(Sender: TObject);
begin
  FJWT.Free;
end;

procedure TfrmMisc.SetJSONValue(const AName, AValue: string; AJSON: TJSONObject);
var
  LJSONValue: TJSONValue;
  LValue: string;
begin
  LJSONValue := AJSON.GetValue(AName);
  if Assigned(LJSONValue) then
  begin
    if LJSONValue.TryGetValue(LValue) then
      if LValue = AValue then
        Exit;
    AJSON.RemovePair(AName).Free;
  end;

  AJSON.AddPair(TJSONPair.Create(AName, TJSONNumber.Create(AValue)));
end;

procedure TfrmMisc.FormCreate(Sender: TObject);
begin
  FJWT := TJWT.Create(TJWTClaims);
end;

procedure TfrmMisc.SetJSONValue(const AName: string; const AValue: Int64; AJSON: TJSONObject);
var
  LJSONValue: TJSONValue;
  LValue: Int64;
begin
  LJSONValue := AJSON.GetValue(AName);
  if Assigned(LJSONValue) then
  begin
    if LJSONValue.TryGetValue(LValue) then
      if LValue = AValue then
        Exit;
    AJSON.RemovePair(AName).Free;
  end;

  AJSON.AddPair(TJSONPair.Create(AName, TJSONNumber.Create(AValue)));
end;

procedure TfrmMisc.TestJSON;
const
  JSON_TEST = '{"alg":"HS256","typ":"JWT"}';
  JSON_TEST_NESTED = '{"alg":{"f1":"value1","f2":150},"typ":"JWT"}';
var
  //LPair: TJSONPair;
  LJObj: TJSONObject;
begin
  LJObj := TJSONObject(TJSONObject.ParseJSONValue(JSON_TEST));

  SetJSONValue('alg', 'RS256', LjObj);


  {
  TJSONUtils.RemoveJSONNode('alg');

  LPair := LJObj.RemovePair('alg');
  if Assigned(LPair) then
    LPair.Free;
  }

  //TJSONUtils.SetJSONValueFrom<Double>('alg', 10.44, LJObj);
  memoLog.Lines.Add(TJSONUtils.ToJSON(LJObj));


  LJObj.AddPair('alg', 'SHSHSH');

  memoLog.Lines.Add(TJSONUtils.ToJSON(LJObj));
  FJWT.Header.Algorithm := 'HS256';

  LJObj.Free;
end;

end.
