{******************************************************************************}
{                                                                              }
{  Delphi JOSE-JWT Library                                                     }
{  Copyright (c) 2015 Paolo Rossi                                              }
{  https://github.com/paolo-rossi/delphi-jose-jwt                              }
{                                                                              }
{  Licensed under the MIT license                                              }
{                                                                              }
{******************************************************************************}
unit JOSE.Tests.Utils;

interface

uses
  System.SysUtils, System.Classes, System.Rtti, System.JSON;

type

  TTestUtils = class
  public
    class function ExpectedFromFile(const AFileName: string): string;
  end;

implementation

uses
  System.IOUtils;

class function TTestUtils.ExpectedFromFile(const AFileName: string): string;
var
  LReader: TStreamReader;
begin
  LReader := TStreamReader.Create(AFileName, TEncoding.UTF8);
  try
    Result := LReader.ReadToEnd;
  finally
    LReader.Free;
  end;
end;

end.
