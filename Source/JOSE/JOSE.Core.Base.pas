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

/// <summary>
///   Base class for the JOSE entities
/// </summary>
unit JOSE.Core.Base;

interface

uses
  System.SysUtils,
  System.Generics.Collections,
  JOSE.Types.Bytes,
  JOSE.Types.JSON;

const
  PART_SEPARATOR: Char = '.';

type
  EJOSEException = class(Exception);

  TJOSEBase = class
  private
    function GetEncoded: TJOSEBytes;
    function GetURLEncoded: TJOSEBytes;
    procedure SetEncoded(const Value: TJOSEBytes);
    procedure SetURLEncoded(const Value: TJOSEBytes);
  protected
    FJSON: TJSONObject;

    procedure AddPairOfType<T>(const AName: string; const AValue: T);
  public
    constructor Create;
    destructor Destroy; override;

    property JSON: TJSONObject read FJSON write FJSON;
    property Encoded: TJOSEBytes read GetEncoded write SetEncoded;
    property URLEncoded: TJOSEBytes read GetURLEncoded write SetURLEncoded;
  end;


implementation

uses
  JOSE.Encoding.Base64;

{ TJOSEBase }

constructor TJOSEBase.Create;
begin
  FJSON := TJSONObject.Create;
end;

destructor TJOSEBase.Destroy;
begin
  FJSON.Free;
  inherited;
end;

function TJOSEBase.GetEncoded: TJOSEBytes;
begin
  Result := TBase64.Encode(FJSON.ToJSON);
end;

function TJOSEBase.GetURLEncoded: TJOSEBytes;
begin
  Result := TBase64.URLEncode(FJSON.ToJSON);
end;

procedure TJOSEBase.SetEncoded(const Value: TJOSEBytes);
var
  LJSONStr: TJOSEBytes;
begin
  LJSONStr := TBase64.Decode(Value);
  FJSON.Parse(LJSONStr, 0)
end;

procedure TJOSEBase.SetURLEncoded(const Value: TJOSEBytes);
var
  LJSONStr: TJOSEBytes;
  LValue: TJSONValue;
begin
  LJSONStr := TBase64.URLDecode(Value);
  LValue := TJSONObject.ParseJSONValue(LJSONStr.AsBytes, 0, True);

  if Assigned(LValue) then
  begin
    FJSON.Free;
    FJSON := LValue as TJSONObject;
  end;

end;

procedure TJOSEBase.AddPairOfType<T>(const AName: string; const AValue: T);
begin
  TJSONUtils.SetJSONValueFrom<T>(AName, AValue, FJSON);
end;

end.
