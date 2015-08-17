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
///   Token Parts
/// </summary>
unit JOSE.Core.Parts;

interface

uses
  System.SysUtils,
  System.Generics.Collections,
  JOSE.Types.Bytes,
  JOSE.Core.JWT;

type
  TJOSEParts = class
  protected
    FParts: TList<TSuperBytes>;
    FToken: TJWT;
    function GetCompactToken: TSuperBytes; virtual; abstract;
    procedure SetCompactToken(const Value: TSuperBytes); virtual; abstract;
  public
    constructor Create(AToken: TJWT); virtual;
    destructor Destroy; override;

    procedure Clear;
    procedure Empty;
    property CompactToken: TSuperBytes read GetCompactToken write SetCompactToken;
  end;

implementation

{ TJOSEParts }

procedure TJOSEParts.Clear;
begin
  FParts.Clear;
end;

constructor TJOSEParts.Create(AToken: TJWT);
begin
  FToken := AToken;
  FParts := TList<TSuperBytes>.Create;
end;

destructor TJOSEParts.Destroy;
begin
  FParts.Free;
  inherited;
end;

procedure TJOSEParts.Empty;
var
  LIndex: Integer;
begin
  for LIndex := 0 to FParts.Count - 1 do
    FParts[LIndex] := TSuperBytes.Empty;
end;

end.
