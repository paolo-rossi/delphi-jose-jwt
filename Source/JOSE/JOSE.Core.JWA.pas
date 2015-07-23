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
unit JOSE.Core.JWA;

interface

type
  TJWAEnum = (None, HS256, HS384, HS512, RS256, RS348, RS512);

  TJWAEnumHelper = record helper for TJWAEnum
  private
    function GetAsString: string;
    procedure SetAsString(const Value: string);
  public
    property AsString: string read GetAsString write SetAsString;
  end;

implementation

function TJWAEnumHelper.GetAsString: string;
begin
  case Self of
    None:  Result := 'none';
    HS256: Result := 'HS256';
    HS384: Result := 'HS384';
    HS512: Result := 'HS512';
    RS256: Result := 'RS256';
    RS348: Result := 'RS348';
    RS512: Result := 'RS512';
  end;
end;

procedure TJWAEnumHelper.SetAsString(const Value: string);
begin
  if Value = 'none' then
    Self := None
  else if Value = 'HS256' then
    Self := HS256
  else if Value = 'HS384' then
    Self := HS384
  else if Value = 'HS512' then
    Self := HS512
  else if Value = 'RS256' then
    Self := RS256
  else if Value = 'RS348' then
    Self := RS348
  else if Value = 'RS512' then
    Self := RS512;
end;

end.
