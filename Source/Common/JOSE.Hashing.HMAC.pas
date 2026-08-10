{******************************************************************************}
{                                                                              }
{  Delphi JOSE-JWT Library                                                     }
{  Copyright (c) 2015 Paolo Rossi                                              }
{  https://github.com/paolo-rossi/delphi-jose-jwt                              }
{                                                                              }
{  Licensed under the MIT license                                              }
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
