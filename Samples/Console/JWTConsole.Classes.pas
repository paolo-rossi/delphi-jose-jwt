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

unit JWTConsole.Classes;

interface

uses
  System.SysUtils, System.Classes,

  JOSE.Core.JWT,
  JOSE.Core.JWS,
  JOSE.Core.JWK,
  JOSE.Core.JWA,
  JOSE.Types.JSON;

type
  TSampleJWTConsole = class
  public
    class function CompileSampleToken: string;
  end;

implementation

uses
  System.DateUtils,
  JOSE.Types.Bytes,
  JOSE.Core.Builder;

{ TSampleJWTConsole }

class function TSampleJWTConsole.CompileSampleToken: string;
var
  LToken: TJWT;
  LSigner: TJWS;
  LKey: TJWK;
begin
  LToken := TJWT.Create();
  try
    LToken.Claims.Issuer := 'Delphi JOSE Library';
    LToken.Claims.IssuedAt := EncodeDateTime(2021, 10, 2, 2, 30, 50, 0);
    LToken.Claims.Expiration := LToken.Claims.IssuedAt + 1;

    LSigner := TJWS.Create(LToken);
    LKey := TJWK.Create('secret');
    try
      LSigner.SkipKeyValidation := True;
      LSigner.Sign(LKey, TJOSEAlgorithmId.HS256);

      Result := LSigner.CompactToken;

      Writeln('Header: ' + LToken.Header.JSON.ToJSON);
      Writeln('Claims: ' + LToken.Claims.JSON.ToJSON);

      Writeln('Header: ' + LSigner.Header.AsString);
      Writeln('Payload: ' + LSigner.Payload.AsString);
      Writeln('Signature: ' + LSigner.Signature.AsString);
      Writeln('Compact Token: ' + Result);
    finally
      LKey.Free;
      LSigner.Free;
    end;
  finally
    LToken.Free;
  end;
end;

end.
