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
///   Base64 utility class
/// </summary>
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
