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

{$I ..\JOSE.inc}

interface

uses
  System.SysUtils,
  JOSE.Types.Bytes;

type
  TBase64 = class
    class function Encode(const ASource: TJOSEBytes): TJOSEBytes; overload;
    class function Decode(const ASource: TJOSEBytes): TJOSEBytes; overload;
    class function TryDecode(const ASource: TJOSEBytes): TJOSEBytes;

    class function URLEncode(const ASource: TJOSEBytes): TJOSEBytes; overload;
    class function URLDecode(const ASource: TJOSEBytes): TJOSEBytes; overload;
    class function TryURLDecode(const ASource: TJOSEBytes): TJOSEBytes;
  end;

implementation

uses
  JOSE.Providers;

{ TBase64 }

class function TBase64.Decode(const ASource: TJOSEBytes): TJOSEBytes;
begin
  Result := TJOSEProviders.Base64.Decode(ASource);
end;

class function TBase64.Encode(const ASource: TJOSEBytes): TJOSEBytes;
begin
  Result := TJOSEProviders.Base64.Encode(ASource);
end;

class function TBase64.TryDecode(const ASource: TJOSEBytes): TJOSEBytes;
begin
  Result := TJOSEProviders.Base64.TryDecode(ASource);
end;

class function TBase64.TryURLDecode(const ASource: TJOSEBytes): TJOSEBytes;
begin
  Result := TJOSEProviders.Base64.TryURLDecode(ASource);
end;

class function TBase64.URLDecode(const ASource: TJOSEBytes): TJOSEBytes;
begin
  Result := TJOSEProviders.Base64.URLDecode(ASource);
end;

class function TBase64.URLEncode(const ASource: TJOSEBytes): TJOSEBytes;
begin
  Result := TJOSEProviders.Base64.URLEncode(ASource);
end;

end.
