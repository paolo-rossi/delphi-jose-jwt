{******************************************************************************}
{                                                                              }
{       WiRL: RESTful Library for Delphi                                       }
{                                                                              }
{       Copyright (c) 2015-2017 WiRL Team                                      }
{                                                                              }
{       https://github.com/delphi-blocks/WiRL                                  }
{                                                                              }
{******************************************************************************}
unit WiRL.Tests.Framework.Resources;

interface

uses
  System.Classes, System.SysUtils, System.StrUtils, System.JSON,
  System.NetEncoding,

  DUnitX.TestFramework,

  WiRL.http.Accept.MediaType,
  WiRL.Tests.Mock.Server;

type
  [TestFixture]
  TTestResource = class(TObject)
  private
    FServer: TWiRLTestServer;
    FRequest: TWiRLTestRequest;
    FResponse: TWiRLTestResponse;
  public
    [Setup]
    procedure Setup;
    [TearDown]
    procedure TearDown;

    [Test]
    procedure TestHelloWorld;
    [Test]
    procedure TestEcho;
    [Test]
    procedure TestReverse;
    [Test]
    procedure TestParams;
    [Test]
    [TestCase('Low', '1,2')]
    [TestCase('Big', '123456,45678')]
    procedure TestSum(AOne, ATwo: Integer);
    [Test]
    [TestCase('Low', '1,2')]
    [TestCase('Big', '123456,45678')]
    procedure TestQueryParam(AOne, ATwo: Integer);
    [Test]
    procedure TestException;
    [Test]
    procedure TestPostEcho;
    [Test]
    procedure TestPostJSON;
    [Test]
    procedure TestBinary;
    [Test]
    procedure TestInvalidPostMediaType;
    [Test]
    procedure TestInvalidMethod;
  end;

implementation

const
  BinaryFile =
    'AAAAAUJ1ZDEAABAAAAAIAAAAEAAAAAQKAAAAAAAAaWRlYmFyXVNob3dTdGF0dXNCYXJbU2hvd1Bh' +
    'dGhiYXJbU2hvd1Rvb2xiYXJcU2lkZWJhcldpZHRoXxAYe3sxMTcsIDE3Nn0sIHs5ODEsIDU4NH19' +
    'CQkICRDACBUiLjxIVGF8fX5/gAAAAAAAAAEBAAAAAAAAAA0AAAAAAAAAAAAAAAAAAACCAAAAAQAu' +
    'bHN2cGJsb2IAAAKAYnBsaXN0MDDYAQIDBAUGBwgJCgsMSEkKS18QEnZpZXdPcHRpb25zVmVyc2lv' +
    'bl8QD3Nob3dJY29uUHJldmlld18QEWNhbGN1bGF0ZUFsbFNpemVzV2NvbHVtbnNYdGV4dFNpemVa' +
    'c29ydENvbHVtbl8QEHVzZVJlbGF0aXZlRGF0ZXNYaWNvblNpemUQAAkI2Q0ODxAREhMUFRYfJCku' +
    'Mzg9Qlhjb21tZW50c1RuYW1lW2RhdGVDcmVhdGVkVHNpemVVbGFiZWxUa2luZFd2ZXJzaW9uXmRh' +
    'dGVMYXN0T3BlbmVkXGRhdGVNb2RpZmllZNQXGBkaCxwKHld2aXNpYmxlVXdpZHRoWWFzY2VuZGlu' +
    'Z1VpbmRleAgRASwJEAfUIBgZGgoiCglXdmlzaWJsZQkRASwJ1BcYGRoLJgsoCBC1CBAC1BcYGRoK' +
    'KwstCRBhCBAD1BcYGRoLMAoyCBBkCRAF1BcYGRoKNQo3CRBzCRAE1BcYGRoLOgo8CBBLCRAG1BcY' +
    'GRoLPwtBCBDICBAI1BcYQxoKRQtHWWFzY2VuZGluZwkQtQgQASNAKAAAAAAAAFxkYXRlTW9kaWZp' +
    'ZWQJAKwAsQC9AMIAyADNANUA5ADxAAoAAAAAAAAAAAA=';


{ TTestResource }

procedure TTestResource.Setup;
begin
  FServer := TWiRLTestServer.Create;

  // Engine configuration
  FServer.ConfigureEngine('/rest')
    .SetName('WiRL Test Demo')
    .SetThreadPoolSize(75)

    .AddApplication('/app')
      .SetSystemApp(True)
      .SetName('Test Application')
      .SetResources(['*']);

  if not FServer.Active then
    FServer.Active := True;

  FRequest := TWiRLTestRequest.Create;
  FResponse := TWiRLTestResponse.Create;

end;

procedure TTestResource.TearDown;
begin
  FServer.Free;

// Destroyed by TWiRLContext
//  FRequest.Free;
//  FResponse.Free;
end;

procedure TTestResource.TestBinary;
var
  BinaryRequest, BinaryResponse: TBytes;
begin
  BinaryRequest := TNetEncoding.Base64.DecodeStringToBytes(BinaryFile);
  FRequest.Method := 'POST';
  FRequest.Url := 'http://localhost:1234/rest/app/helloworld/postbinary';
  FRequest.ContentType := TMediaType.APPLICATION_OCTET_STREAM;
  FRequest.ContentStream.Write(BinaryRequest[0], Length(BinaryRequest));

  FServer.DoCommand(FRequest, FResponse);

  SetLength(BinaryResponse, FResponse.ContentStream.Size);
  FResponse.ContentStream.Read(BinaryResponse[0], FResponse.ContentStream.Size);

  Assert.AreEqual<TBytes>(BinaryRequest, BinaryResponse);
end;

procedure TTestResource.TestEcho;
begin
  FRequest.Method := 'GET';
  FRequest.Url := 'http://localhost:1234/rest/app/helloworld/echostring/ciao';
  FServer.DoCommand(FRequest, FResponse);
  Assert.AreEqual('ciao', FResponse.Content);
end;

procedure TTestResource.TestException;
begin
  FRequest.Method := 'GET';
  FRequest.Url := 'http://localhost:1234/rest/app/helloworld/exception';
  FServer.DoCommand(FRequest, FResponse);
  Assert.AreEqual(500, FResponse.StatusCode);
  Assert.AreEqual('User Error Message', FResponse.Error.Message);
end;

procedure TTestResource.TestHelloWorld;
begin
  FRequest.Method := 'GET';
  FRequest.Url := 'http://localhost:1234/rest/app/helloworld';
  FServer.DoCommand(FRequest, FResponse);
  Assert.AreEqual('Hello, world!', FResponse.Content);
end;

procedure TTestResource.TestInvalidMethod;
begin
  FRequest.Method := 'POST';
  FRequest.Url := 'http://localhost:1234/rest/app/helloworld';
  FServer.DoCommand(FRequest, FResponse);
  Assert.AreEqual(404, FResponse.StatusCode);
end;

procedure TTestResource.TestInvalidPostMediaType;
begin
  FRequest.Method := 'POST';
  FRequest.Url := 'http://localhost:1234/rest/app/helloworld/postjson';
  FRequest.ContentType := TMediaType.TEXT_XML;
  FRequest.Content := '<xml><name>test</name></xml>';
  FServer.DoCommand(FRequest, FResponse);
  Assert.AreEqual(400, FResponse.StatusCode);
end;

procedure TTestResource.TestParams;
begin
  FRequest.Method := 'GET';
  FRequest.Url := 'http://localhost:1234/rest/app/helloworld/params/ciao/luca';
  FServer.DoCommand(FRequest, FResponse);
  Assert.AreEqual('ciaoluca', FResponse.Content);
end;

procedure TTestResource.TestPostEcho;
begin
  FRequest.Method := 'POST';
  FRequest.Url := 'http://localhost:1234/rest/app/helloworld/postecho';
  FRequest.Content := 'ciao';
  FServer.DoCommand(FRequest, FResponse);
  Assert.AreEqual('ciao', FResponse.Content);
end;

procedure TTestResource.TestPostJSON;
begin
  FRequest.Method := 'POST';
  FRequest.Url := 'http://localhost:1234/rest/app/helloworld/postjson';
  FRequest.ContentType := TMediaType.APPLICATION_JSON;
  FRequest.Content := '{"name": "luca"}';
  FServer.DoCommand(FRequest, FResponse);
  Assert.AreEqual('luca', FResponse.Content);
end;

procedure TTestResource.TestQueryParam(AOne, ATwo: Integer);
begin
  FRequest.Method := 'GET';
  FRequest.Url := 'http://localhost:1234/rest/app/helloworld/sumwithqueryparam?AOne=' + IntToStr(AOne) + '&ATwo=' + IntToStr(ATwo);
  FServer.DoCommand(FRequest, FResponse);
  Assert.AreEqual(IntToStr(AOne + ATwo), FResponse.Content);
end;

procedure TTestResource.TestReverse;
begin
  FRequest.Method := 'GET';
  FRequest.Url := 'http://localhost:1234/rest/app/helloworld/reversestring/ciao';
  FServer.DoCommand(FRequest, FResponse);
  Assert.AreEqual('oaic', FResponse.Content);
end;

procedure TTestResource.TestSum(AOne, ATwo: Integer);
begin
  FRequest.Method := 'GET';
  FRequest.Url := 'http://localhost:1234/rest/app/helloworld/sum/' + IntToStr(AOne) + '/' + IntToStr(ATwo);
  FServer.DoCommand(FRequest, FResponse);
  Assert.AreEqual(IntToStr(AOne + ATwo), FResponse.Content);
end;

initialization
  TDUnitX.RegisterTestFixture(TTestResource);

end.
