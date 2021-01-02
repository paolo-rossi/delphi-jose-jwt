object frmMisc: TfrmMisc
  Left = 0
  Top = 0
  Caption = 'frmMisc'
  ClientHeight = 467
  ClientWidth = 630
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  OnCreate = FormCreate
  OnDestroy = FormDestroy
  PixelsPerInch = 96
  TextHeight = 13
  object memoLog: TMemo
    Left = 0
    Top = 235
    Width = 630
    Height = 232
    Align = alBottom
    TabOrder = 0
  end
  object btnTestJSON: TButton
    Left = 8
    Top = 32
    Width = 75
    Height = 25
    Caption = 'Test JSON'
    TabOrder = 1
    OnClick = btnTestJSONClick
  end
  object memoInput: TMemo
    Left = 0
    Top = 88
    Width = 302
    Height = 107
    Font.Charset = ANSI_CHARSET
    Font.Color = clRed
    Font.Height = -16
    Font.Name = 'Consolas'
    Font.Style = []
    Lines.Strings = (
      '{'
      '  "alg": "HS256",'
      '  "typ": "JWT"'
      '}')
    ParentFont = False
    ScrollBars = ssVertical
    TabOrder = 2
  end
  object btnArray: TButton
    Left = 547
    Top = 32
    Width = 75
    Height = 25
    Caption = 'btnArray'
    TabOrder = 3
    OnClick = btnArrayClick
  end
  object btnSign: TButton
    Left = 547
    Top = 63
    Width = 75
    Height = 25
    Caption = 'btnSign'
    TabOrder = 4
    OnClick = btnSignClick
  end
end
