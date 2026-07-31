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
  JOSE.Crypto.Algorithms;

type
  THMACAlgorithm = JOSE.Crypto.Algorithms.THMACAlgorithm;
  THMACAlgorithmHelper = JOSE.Crypto.Algorithms.THMACAlgorithmHelper;

  THMAC = class
  public
    class function Sign(const AInput, AKey: TBytes; AAlg: THMACAlgorithm): TBytes;
  end;

implementation

uses
  JOSE.Providers;

{ THMAC }

class function THMAC.Sign(const AInput, AKey: TBytes; AAlg: THMACAlgorithm): TBytes;
begin
  Result := TJOSEProviders.HMAC.Sign(AInput, AKey, AAlg);
end;

end.
