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

unit JOSE.Core.JWE;

interface

uses
  System.SysUtils,
  JOSE.Types.Bytes,
  JOSE.Core.Base,
  JOSE.Core.Parts,
  JOSE.Core.JWT;

type
  /// <summary>
  ///   JSON Web Encryption (JWE) RFC implementation (initial)
  /// </summary>
  /// <seealso href="https://tools.ietf.org/html/rfc7516">
  ///   JWE RFC Document
  /// </seealso>
  TJWE = class(TJOSEParts)
  private
    const COMPACT_PARTS = 5;
  public
    constructor Create(AToken: TJWT); override;
    //class function Encrypt(AKey: TJWK; AAlg: TJWAEnum): string;
    //class function Decrypt(AKey: TJWK; AInput: TBytes): Boolean;
  end;

implementation

{ TJWEParts }

constructor TJWE.Create(AToken: TJWT);
var
  LIndex: Integer;
begin
  inherited Create(AToken);

  for LIndex := 0 to COMPACT_PARTS - 1 do
    FParts.Add(TJOSEBytes.Empty);
end;

end.
