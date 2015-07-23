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
unit JOSE.Core.JWE;

interface

uses
  System.SysUtils,
  JOSE.Types.Bytes,
  JOSE.Core.Base,
  JOSE.Core.Parts,
  JOSE.Core.JWT;

type
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
    FParts.Add(TSuperBytes.Empty);
end;

end.
