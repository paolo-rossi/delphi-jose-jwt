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
unit JOSE.Core.Parts;

interface

uses
  System.SysUtils,
  System.Generics.Collections,
  JOSE.Types.Bytes,
  JOSE.Core.JWT;

type
  TJOSEParts = class
  protected
    FParts: TList<TSuperBytes>;
    FToken: TJWT;
    function GetCompactToken: TSuperBytes; virtual; abstract;
    procedure SetCompactToken(const Value: TSuperBytes); virtual; abstract;
  public
    constructor Create(AToken: TJWT); virtual;
    destructor Destroy; override;

    procedure Clear;
    procedure Empty;
    property CompactToken: TSuperBytes read GetCompactToken write SetCompactToken;
  end;

implementation

{ TJOSEParts }

procedure TJOSEParts.Clear;
begin
  FParts.Clear;
end;

constructor TJOSEParts.Create(AToken: TJWT);
begin
  FToken := AToken;
  FParts := TList<TSuperBytes>.Create;
end;

destructor TJOSEParts.Destroy;
begin
  FParts.Free;
  inherited;
end;

procedure TJOSEParts.Empty;
var
  LIndex: Integer;
begin
  for LIndex := 0 to FParts.Count - 1 do
    FParts[LIndex] := TSuperBytes.Empty;
end;

end.
