{******************************************************}
{  Copyright (C) 2015                                  }
{  Delphi JOSE Library                                 }
{                                                      }
{  https://github.com/paolo-rossi/delphi-jose-jwt      }
{                                                      }
{  Authors:                                            }
{  Paolo Rossi <paolo(at)paolorossi(dot)net>           }
{                                                      }
{******************************************************}
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
    raise Exception.Create('Error Message');

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
