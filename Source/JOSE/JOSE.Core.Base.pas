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
unit JOSE.Core.Base;

interface

uses
  System.SysUtils,
  System.Generics.Collections,
  JOSE.Types.Bytes,
  JOSE.Types.JSON;

const
  PART_SEPARATOR: Char = '.';

type
  EJOSEException = class(Exception);

  TJOSEBase = class
  private
    function GetEncoded: TSuperBytes;
    function GetURLEncoded: TSuperBytes;
    procedure SetEncoded(const Value: TSuperBytes);
    procedure SetURLEncoded(const Value: TSuperBytes);
  protected
    FJSON: TJSONObject;

    procedure AddPairOfType<T>(const AName: string; const AValue: T);
  public
    constructor Create;
    destructor Destroy; override;

    property JSON: TJSONObject read FJSON write FJSON;
    property Encoded: TSuperBytes read GetEncoded write SetEncoded;
    property URLEncoded: TSuperBytes read GetURLEncoded write SetURLEncoded;
  end;


implementation

uses
  JOSE.Encoding.Base64;

{ TJOSEBase }

constructor TJOSEBase.Create;
begin
  FJSON := TJSONObject.Create;
end;

destructor TJOSEBase.Destroy;
begin
  FJSON.Free;
  inherited;
end;

function TJOSEBase.GetEncoded: TSuperBytes;
begin
  Result := TBase64.Encode(FJSON.ToJSON);
end;

function TJOSEBase.GetURLEncoded: TSuperBytes;
begin
  Result := TBase64.URLEncode(FJSON.ToJSON);
end;

procedure TJOSEBase.SetEncoded(const Value: TSuperBytes);
var
  LJSONStr: TSuperBytes;
begin
  LJSONStr := TBase64.Decode(Value);
  FJSON.Parse(LJSONStr, 0)

end;

procedure TJOSEBase.SetURLEncoded(const Value: TSuperBytes);
var
  LJSONStr: TSuperBytes;
  LValue: TJSONValue;
begin
  LJSONStr := TBase64.URLDecode(Value);
  LValue := TJSONObject.ParseJSONValue(LJSONStr.AsBytes, 0, True);

  if Assigned(LValue) then
  begin
    FJSON.Free;
    FJSON := LValue as TJSONObject;
  end;

end;

procedure TJOSEBase.AddPairOfType<T>(const AName: string; const AValue: T);
begin
  TJSONUtils.SetJSONValueFrom<T>(AName, AValue, FJSON);
end;

end.
