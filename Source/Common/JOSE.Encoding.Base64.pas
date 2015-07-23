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
unit JOSE.Encoding.Base64;

interface

uses
  System.SysUtils,
  System.NetEncoding,
  JOSE.Types.Bytes;

type
  TBase64 = class
    class function Encode(const ASource: TSuperBytes): TSuperBytes; overload;
    class function Decode(const ASource: TSuperBytes): TSuperBytes; overload;
    class function URLEncode(const ASource: TSuperBytes): TSuperBytes; overload;
    class function URLDecode(const ASource: TSuperBytes): TSuperBytes; overload;
  end;

implementation

{ TBase64 }

class function TBase64.Decode(const ASource: TSuperBytes): TSuperBytes;
begin
  Result := TNetEncoding.Base64.Decode(ASource.AsBytes);
end;

class function TBase64.Encode(const ASource: TSuperBytes): TSuperBytes;
begin
  Result := TNetEncoding.Base64.Encode(ASource.AsBytes);
end;

class function TBase64.URLDecode(const ASource: TSuperBytes): TSuperBytes;
var
  LBase64Str: string;
begin
  LBase64Str := ASource;

  LBase64Str := LBase64Str + StringOfChar('=', (4 - ASource.Size mod 4) mod 4);
  LBase64Str := StringReplace(LBase64Str, '-', '+', [rfReplaceAll]);
  LBase64Str := StringReplace(LBase64Str, '_', '/', [rfReplaceAll]);
  Result := TBase64.Decode(LBase64Str);
end;

class function TBase64.URLEncode(const ASource: TSuperBytes): TSuperBytes;
var
  LBase64Str: string;
begin
  LBase64Str := TBase64.Encode(ASource);

  LBase64Str := StringReplace(LBase64Str, #13#10, '', [rfReplaceAll]);
  LBase64Str := StringReplace(LBase64Str, #13, '', [rfReplaceAll]);
  LBase64Str := StringReplace(LBase64Str, #10, '', [rfReplaceAll]);
  LBase64Str := LBase64Str.TrimRight(['=']);

  LBase64Str := StringReplace(LBase64Str, '+', '-', [rfReplaceAll]);
  LBase64Str := StringReplace(LBase64Str, '/', '_', [rfReplaceAll]);

  Result := LBase64Str;
end;

end.
