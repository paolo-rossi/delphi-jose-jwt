unit JOSE.Tests.Consumer;

interface

uses
  System.SysUtils,
  DUnitX.TestFramework,

  // Common
  JOSE.Types.Bytes,
  JOSE.Types.JSON,
  JOSE.Consumer,
  JOSE.Consumer.Validators;

type
  [TestFixture]
  TTestJOSEConsumer = class
  private
    const JWT_SUB = '';
    const JWT_DATES = '';
  public
    [Setup]
    procedure Setup;
    [TearDown]
    procedure TearDown;

    [Test] [TestCase(1300819372)]
    procedure TestDateClaims(AEvaluationDate: Integer);
    [Test]
    procedure TestEquals(A, B: TJOSEBytes);
  end;

implementation

end.
