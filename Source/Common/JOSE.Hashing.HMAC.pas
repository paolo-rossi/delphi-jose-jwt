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
///   HMAC utility class
/// </summary>
unit JOSE.Hashing.HMAC;

interface

uses
  System.SysUtils,
  IdGlobal,
  IdHMAC,
  IdHMACSHA1,
  IdSSLOpenSSL,
  IdHash,
  JOSE.Encoding.Base64;

type
  THMACAlgorithm = (SHA256, SHA384, SHA512);
  TIdHMACClass = class of TIdHMAC;

  THMAC = class
  public
    class function Sign(const AInput, AKey: TBytes; AAlg: THMACAlgorithm): TBytes;

  end;

implementation

class function THMAC.Sign(const AInput, AKey: TBytes; AAlg: THMACAlgorithm): TBytes;
var
  LSigner: TIdHMAC;
begin
  LSigner := nil;

  if not IdSSLOpenSSL.LoadOpenSSLLibrary then
    raise Exception.Create('Cannot load OpenSSL Library.');

  case AAlg of
    SHA256: LSigner := TIdHMACSHA256.Create;
    SHA384: LSigner := TIdHMACSHA384.Create;
    SHA512: LSigner := TIdHMACSHA512.Create;
  end;

  try
    LSigner.Key := TIdBytes(AKey);
    Result:= TBytes(LSigner.HashValue(TIdBytes(AInput)));
  finally
    LSigner.Free;
  end;
end;

end.
