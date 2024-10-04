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

{$I ..\JOSE.inc}

interface

uses
  System.SysUtils,
  {$IF CompilerVersion >= 30 }  // Delphi 10 Seattle or greater
  System.Hash,
  {$ELSE}
  IdGlobal,
  IdHMAC,
  IdHMACSHA1,
  IdSSLOpenSSL,
  IdHash,
  {$IFEND}
  JOSE.Encoding.Base64;

type
  THMACAlgorithm = (SHA256, SHA384, SHA512);
  THMACAlgorithmHelper = record helper for THMACAlgorithm
    procedure FromString(const AValue: string);
    function ToString: string;
  end;

  THMAC = class
  public
    class function Sign(const AInput, AKey: TBytes; AAlg: THMACAlgorithm): TBytes;
  end;

implementation

{$IF CompilerVersion >= 30 }  // Delphi 10 Seattle or greater
class function THMAC.Sign(const AInput, AKey: TBytes; AAlg: THMACAlgorithm): TBytes;
var
  LHashAlg: THashSHA2.TSHA2Version;
begin
  LHashAlg := THashSHA2.TSHA2Version.SHA256;
  case AAlg of
    SHA256: LHashAlg := THashSHA2.TSHA2Version.SHA256;
    SHA384: LHashAlg := THashSHA2.TSHA2Version.SHA384;
    SHA512: LHashAlg := THashSHA2.TSHA2Version.SHA512;
  end;
  Result := THashSHA2.GetHMACAsBytes(AInput, AKey, LHashAlg);
end;

{$ELSE}
class function THMAC.Sign(const AInput, AKey: TBytes; AAlg: THMACAlgorithm): TBytes;
var
  LSigner: TIdHMAC;
begin
  LSigner := nil;

  if not IdSSLOpenSSL.LoadOpenSSLLibrary then
    raise Exception.Create('Error Loading OpenSSL libraries');

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
{$IFEND}


{ THMACAlgorithmHelper }

procedure THMACAlgorithmHelper.FromString(const AValue: string);
begin
  if AValue = 'SHA256' then
    Self := SHA256
  else if AValue = 'SHA384' then
    Self := SHA384
  else if AValue = 'SHA512' then
    Self := SHA512
  else
    raise Exception.Create('Invalid HMAC algorithm type');
end;

function THMACAlgorithmHelper.ToString: string;
begin
  case Self of
    SHA256: Result := 'SHA256';
    SHA384: Result := 'SHA384';
    SHA512: Result := 'SHA512';
  end;
end;

end.
