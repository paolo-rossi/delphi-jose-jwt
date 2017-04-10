program JWTConsole;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  JWTConsole.Classes in 'JWTConsole.Classes.pas';

begin
  try
    TSampleJWTConsole.CompileSampleToken;
    Writeln('Press any key...');
    Readln;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
