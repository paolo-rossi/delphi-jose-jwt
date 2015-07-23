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
unit JOSE.Core.JWK;

interface

uses
  System.SysUtils,
  JOSE.Types.Bytes,
  JOSE.Core.Base;

type
  TJWK = class(TJOSEBase)
  private
    FKey: TSuperBytes;
  public
    constructor Create(AKey: TSuperBytes);
    property Key: TSuperBytes read FKey write FKey;
  end;

implementation

{ TJWK }

constructor TJWK.Create(AKey: TSuperBytes);
begin
  inherited Create;
  FKey := AKey;
end;

end.
