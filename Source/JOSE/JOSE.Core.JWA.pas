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
///   JSON Web Algorithms (JWA) RFC implementation (partial) <br />
/// </summary>
/// <seealso href="https://tools.ietf.org/html/rfc7518">
///   JWA RFC Document
/// </seealso>
unit JOSE.Core.JWA;

interface

type
  TJWAEnum = (None, HS256, HS384, HS512, RS256, RS348, RS512);

  TJWAEnumHelper = record helper for TJWAEnum
  private
    function GetAsString: string;
    procedure SetAsString(const Value: string);
  public
    property AsString: string read GetAsString write SetAsString;
  end;

implementation

function TJWAEnumHelper.GetAsString: string;
begin
  case Self of
    None:  Result := 'none';
    HS256: Result := 'HS256';
    HS384: Result := 'HS384';
    HS512: Result := 'HS512';
    RS256: Result := 'RS256';
    RS348: Result := 'RS348';
    RS512: Result := 'RS512';
  end;
end;

procedure TJWAEnumHelper.SetAsString(const Value: string);
begin
  if Value = 'none' then
    Self := None
  else if Value = 'HS256' then
    Self := HS256
  else if Value = 'HS384' then
    Self := HS384
  else if Value = 'HS512' then
    Self := HS512
  else if Value = 'RS256' then
    Self := RS256
  else if Value = 'RS348' then
    Self := RS348
  else if Value = 'RS512' then
    Self := RS512;
end;

end.
