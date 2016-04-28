object frmMisc: TfrmMisc
  Left = 0
  Top = 0
  Caption = 'frmMisc'
  ClientHeight = 448
  ClientWidth = 635
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  OnCreate = FormCreate
  OnDestroy = FormDestroy
  DesignSize = (
    635
    448)
  PixelsPerInch = 96
  TextHeight = 13
  object memoLog: TMemo
    Left = 0
    Top = 216
    Width = 635
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
    Anchors = [akLeft, akTop, akRight]
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
end
