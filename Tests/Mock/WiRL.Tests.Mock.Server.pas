{******************************************************************************}
{                                                                              }
{       WiRL: RESTful Library for Delphi                                       }
{                                                                              }
{       Copyright (c) 2015-2017 WiRL Team                                      }
{                                                                              }
{       https://github.com/delphi-blocks/WiRL                                  }
{                                                                              }
{******************************************************************************}
unit WiRL.Tests.Mock.Server;

interface

uses
  System.Classes, System.SysUtils, System.RegularExpressions,
  System.Json, System.NetEncoding,

  WiRL.http.Accept.MediaType,
  WiRL.Core.Engine,
  WiRL.Core.Response,
  WiRL.Core.Request,
  WiRL.Core.Context;

type
  TWiRLResponseError = class(TObject)
  private
    FMessage: string;
    FStatus: string;
    FException: string;
  public
    property Message: string read FMessage write FMessage;
    property Status: string read FStatus write FStatus;
    property Exception: string read FException write FException;
  end;

  TWiRLTestServer = class(TObject)
  private
    FEngine: TWiRLEngine;
    FActive: Boolean;
  public
    constructor Create; virtual;
    destructor Destroy; override;

    procedure DoCommand(ARequest: TWiRLRequest; AResponse: TWiRLResponse);
    function ConfigureEngine(const ABasePath: string): TWiRLEngine;
    property Engine: TWiRLEngine read FEngine;
    property Active: Boolean read FActive write FActive;
  end;

  TWiRLTestResponse = class(TWiRLResponse)
  private
    FContentStream: TStream;
    FCustomHeaders: TStrings;
    FStatusCode: Integer;
    FContent: string;
    FContentCharSet: string;
    FContentType: string;
    FContentLength: Int64;
    FDate: TDateTime;
    FExpires: TDateTime;
    FLastModified: TDateTime;
    FReasonString: string;
    FResponseError: TWiRLResponseError;
  protected
    function GetContent: string; override;
    function GetContentStream: TStream; override;
    function GetCustomHeaders: TStrings; override;
    function GetDate: TDateTime; override;
    function GetExpires: TDateTime; override;
    function GetLastModified: TDateTime; override;
    procedure SetContent(const Value: string); override;
    procedure SetContentStream(const Value: TStream); override;
    procedure SetCustomHeaders(const Value: TStrings); override;
    procedure SetDate(const Value: TDateTime); override;
    procedure SetExpires(const Value: TDateTime); override;
    procedure SetLastModified(const Value: TDateTime); override;
    function GetStatusCode: Integer; override;
    procedure SetStatusCode(const Value: Integer); override;
    function GetContentType: string; override;
    procedure SetContentType(const Value: string); override;
    function GetReasonString: string; override;
    procedure SetReasonString(const Value: string); override;
    function GetContentLength: Int64; override;
    procedure SetContentLength(const Value: Int64); override;
    function GetContentCharSet: string; override;
    procedure SetContentCharSet(const Value: string); override;
  public
    property Error: TWiRLResponseError read FResponseError;
    constructor Create;
    destructor Destroy; override;
  end;

  TWiRLTestRequest = class(TWiRLRequest)
  private
    FCookieFields: TStrings;
    FQueryFields: TStrings;
    FContentFields: TStrings;
    FUrl: string;
    FProtocol: string;
    FHost: string;
    FPathInfo: string;
    FRawPathInfo: string;
    FQuery: string;
    FMethod: string;
    FContentType: string;
    FServerPort: Integer;
    FContentStream: TStream;
    FContentVersion: string;
    procedure ParseQueryParams;
    procedure SetUrl(const Value: string);
    function GetContent: string;
    procedure SetContent(const Value: string);
    procedure SetContentType(const Value: string);
  protected
    function GetPathInfo: string; override;
    function GetQuery: string; override;
    function GetHost: string; override;
    function GetServerPort: Integer; override;
    function GetMethod: string; override;
    function GetQueryFields: TStrings; override;
    function GetContentFields: TStrings; override;
    function GetCookieFields: TStrings; override;
    function GetContentStream: TStream; override;
    function GetAuthorization: string; override;
    function GetAccept: string; override;
    function GetAcceptCharSet: string; override;
    function GetAcceptEncoding: string; override;
    function GetAcceptLanguage: string; override;
    function GetContentType: string; override;
    function GetContentLength: Integer; override;
    function GetContentVersion: string; override;
    function GetRawPathInfo: string; override;
    function DoGetFieldByName(const Name: string): string; override;
  public
    property Url: string read FUrl write SetUrl;
    property Method: string read FMethod write FMethod;
    property Content: string read GetContent write SetContent;
    property ContentType: string read GetContentType write SetContentType;
    constructor Create;
    destructor Destroy; override;
  end;


implementation

{ TWiRLTestServer }

function TWiRLTestServer.ConfigureEngine(const ABasePath: string): TWiRLEngine;
begin
  FEngine.SetBasePath(ABasePath);
  Result := FEngine;
end;

constructor TWiRLTestServer.Create;
begin
  FEngine := TWiRLEngine.Create;
end;

destructor TWiRLTestServer.Destroy;
begin
  FEngine.Free;
  inherited;
end;

procedure TWiRLTestServer.DoCommand(ARequest: TWiRLRequest;
  AResponse: TWiRLResponse);
var
  LContext: TWiRLContext;
  LContentJson: TJSONValue;
begin
  inherited;

  LContext := TWiRLContext.Create;
  try
    LContext.Engine := FEngine;
    LContext.Request := ARequest;
    LContext.Response := AResponse;

    ARequest.ContentStream.Position := 0;

    FEngine.HandleRequest(LContext);
//    AResponseInfo.CustomHeaders.AddStrings(LContext.Response.CustomHeaders);
    if AResponse.StatusCode <> 200 then
    begin
      if AResponse.ContentType = TMediaType.APPLICATION_JSON then
      begin
        LContentJson := TJSONObject.ParseJSONValue(AResponse.Content);
        (AResponse as TWiRLTestResponse).Error.Message := LContentJson.GetValue<string>('message');
        (AResponse as TWiRLTestResponse).Error.Status := LContentJson.GetValue<string>('status');
        (AResponse as TWiRLTestResponse).Error.Exception := LContentJson.GetValue<string>('exception');
        //raise TWiRLTestException.Create(LMessage, LStatus, LException);
      end
      else
      raise Exception.Create(IntToStr(AResponse.StatusCode) + ' - ' + AResponse.ReasonString);
    end;

  finally
    LContext.Free;
  end;
end;

{ TWiRLTestRequest }

constructor TWiRLTestRequest.Create;
begin
  inherited;
  FContentStream := TMemoryStream.Create;
  FCookieFields := TStringList.Create;
  FQueryFields := TStringList.Create;
  FContentFields := TStringList.Create;
  FMethod := 'GET';
  FServerPort := 80;
end;

destructor TWiRLTestRequest.Destroy;
begin
  FCookieFields.Free;
  FQueryFields.Free;
  FContentFields.Free;
  inherited;
end;

function TWiRLTestRequest.DoGetFieldByName(const Name: string): string;
begin

end;

function TWiRLTestRequest.GetAccept: string;
begin

end;

function TWiRLTestRequest.GetAcceptCharSet: string;
begin

end;

function TWiRLTestRequest.GetAcceptEncoding: string;
begin

end;

function TWiRLTestRequest.GetAcceptLanguage: string;
begin

end;

function TWiRLTestRequest.GetAuthorization: string;
begin

end;

function TWiRLTestRequest.GetContent: string;
begin
  Result := inherited Content;
end;

function TWiRLTestRequest.GetContentFields: TStrings;
begin
  Result := FContentFields;
end;

function TWiRLTestRequest.GetContentLength: Integer;
begin
  Result := ContentLength;
end;

function TWiRLTestRequest.GetContentStream: TStream;
begin
  Result := FContentStream;
end;

function TWiRLTestRequest.GetContentType: string;
begin
  Result := FContentType;
end;

function TWiRLTestRequest.GetContentVersion: string;
begin
  Result := FContentVersion;
end;

function TWiRLTestRequest.GetCookieFields: TStrings;
begin
  Result := FCookieFields;
end;

function TWiRLTestRequest.GetHost: string;
begin
  Result := FHost;
end;

function TWiRLTestRequest.GetMethod: string;
begin
  Result := FMethod;
end;

function TWiRLTestRequest.GetPathInfo: string;
begin
  Result := FPathInfo;
end;

function TWiRLTestRequest.GetQuery: string;
begin
  Result := FQuery;
end;

function TWiRLTestRequest.GetQueryFields: TStrings;
begin
  Result := FQueryFields;
end;

function TWiRLTestRequest.GetRawPathInfo: string;
begin
  Result := FRawPathInfo;
end;

function TWiRLTestRequest.GetServerPort: Integer;
begin
  Result := FServerPort;
end;

procedure TWiRLTestRequest.ParseQueryParams;
var
  Params: TArray<string>;
  Param: string;
  EqualIndex: Integer;
begin
  FQueryFields.Clear;
  if FQuery <> '' then
  begin
    Params := FQuery.Split(['&']);
    for Param in Params do
    begin
      // I can't use split: I need only the first equal symbol
      EqualIndex := Param.IndexOf('=');
      if EqualIndex > 0 then
      begin
        FQueryFields.AddPair(TNetEncoding.URL.Decode(Param.Substring(0, EqualIndex)), TNetEncoding.URL.Decode(Param.Substring(EqualIndex + 1)));
      end;
    end;
  end;

end;

procedure TWiRLTestRequest.SetContent(const Value: string);
var
  Buffer: TBytes;
begin
  Buffer := TEncoding.UTF8.GetBytes(Value);
  FContentStream.Write(Buffer[0], Length(Buffer));
  FContentStream.Position := 0;
end;

procedure TWiRLTestRequest.SetContentType(const Value: string);
begin
  FContentType := Value;
end;

procedure TWiRLTestRequest.SetUrl(const Value: string);
const
  Pattern = '(https{0,1}):\/\/([^\/]+)(\/[^?\n]+)\?*(.*)';
var
  LRegEx: TRegEx;
  LMatch: TMatch;
  LPortIndex: Integer;
begin
  FUrl := Value;
  LRegEx := TRegEx.Create(Pattern, [roIgnoreCase, roMultiLine]);
  LMatch := LRegEx.Match(FUrl);
  if LMatch.Groups.Count > 1 then
    FProtocol := LMatch.Groups[1].Value;
  if LMatch.Groups.Count > 2 then
    FHost := LMatch.Groups[2].Value;
  if LMatch.Groups.Count > 3 then
  begin
    FPathInfo := LMatch.Groups[3].Value;
    FRawPathInfo := LMatch.Groups[3].Value;
  end;
  if LMatch.Groups.Count > 4 then
    FQuery := LMatch.Groups[4].Value;

  LPortIndex := FHost.IndexOf(':');
  if LPortIndex >= 0 then
    FServerPort := FHost.Substring(LPortIndex + 1).ToInteger
  else
    FServerPort := 80;

  ParseQueryParams;
end;

{ TWiRLTestResponse }

constructor TWiRLTestResponse.Create;
begin
  inherited;
  FResponseError := TWiRLResponseError.Create;
  FCustomHeaders := TStringList.Create;
  FStatusCode := 200;
  FReasonString := 'OK';
end;

destructor TWiRLTestResponse.Destroy;
begin
  FCustomHeaders.Free;
  inherited;
end;

function TWiRLTestResponse.GetContent: string;
var
  LBuffer: TBytes;
begin
  if Assigned(FContentStream) and (FContentStream.Size > 0)  then
  begin
    FContentStream.Position := 0;
    SetLength(LBuffer, FContentStream.Size);
    FContentStream.Read(LBuffer[0], FContentStream.Size);
    // Should read the content-type
    Result := TEncoding.UTF8.GetString(LBuffer);
  end
  else
    Result := FContent;
end;

function TWiRLTestResponse.GetContentCharSet: string;
begin
  Result := FContentCharSet;
end;

function TWiRLTestResponse.GetContentLength: Int64;
begin
  Result := FContentLength;
end;

function TWiRLTestResponse.GetContentStream: TStream;
begin
  Result := FContentStream;
end;

function TWiRLTestResponse.GetContentType: string;
begin
  Result := FContentType;
end;

function TWiRLTestResponse.GetCustomHeaders: TStrings;
begin
  Result := FCustomHeaders;
end;

function TWiRLTestResponse.GetDate: TDateTime;
begin
  Result := FDate;
end;

function TWiRLTestResponse.GetExpires: TDateTime;
begin
  Result := FExpires;
end;

function TWiRLTestResponse.GetLastModified: TDateTime;
begin
  Result := FLastModified;
end;

function TWiRLTestResponse.GetReasonString: string;
begin
  Result := FReasonString;
end;

function TWiRLTestResponse.GetStatusCode: Integer;
begin
  Result := FStatusCode;
end;

procedure TWiRLTestResponse.SetContent(const Value: string);
begin
  inherited;
  FContent := Value;
end;

procedure TWiRLTestResponse.SetContentCharSet(const Value: string);
begin
  inherited;
  FContentCharSet := Value;
end;

procedure TWiRLTestResponse.SetContentLength(const Value: Int64);
begin
  inherited;
  FContentLength := Value;
end;

procedure TWiRLTestResponse.SetContentStream(const Value: TStream);
begin
  inherited;
  FContentStream := Value;
end;

procedure TWiRLTestResponse.SetContentType(const Value: string);
begin
  inherited;
  FContentType := Value;
end;

procedure TWiRLTestResponse.SetCustomHeaders(const Value: TStrings);
begin
  inherited;
  if Assigned(Value) then
    FCustomHeaders.Assign(Value)
  else
    FCustomHeaders.Clear;
end;

procedure TWiRLTestResponse.SetDate(const Value: TDateTime);
begin
  inherited;
  FDate := Value;
end;

procedure TWiRLTestResponse.SetExpires(const Value: TDateTime);
begin
  inherited;
  FExpires := Value;
end;

procedure TWiRLTestResponse.SetLastModified(const Value: TDateTime);
begin
  inherited;
  FLastModified := Value;
end;

procedure TWiRLTestResponse.SetReasonString(const Value: string);
begin
  inherited;
  FReasonString := Value;
end;

procedure TWiRLTestResponse.SetStatusCode(const Value: Integer);
begin
  inherited;
  FStatusCode := Value;
end;

end.
