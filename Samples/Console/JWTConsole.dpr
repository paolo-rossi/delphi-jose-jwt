{******************************************************************************}
{                                                                              }
{  Delphi JOSE-JWT Library                                                     }
{  Copyright (c) 2015 Paolo Rossi                                              }
{  https://github.com/paolo-rossi/delphi-jose-jwt                              }
{                                                                              }
{  Licensed under the MIT license                                              }
{                                                                              }
{******************************************************************************}

program JWTConsole;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  JWTConsole.Classes in 'JWTConsole.Classes.pas';

begin
  try
    TSampleJWTConsole.CompileSampleToken;
    Writeln('Press Enter...');
    Readln;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
