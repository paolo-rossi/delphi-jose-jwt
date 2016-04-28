object frmSimple: TfrmSimple
  Left = 0
  Top = 0
  Caption = 'frmSimple'
  ClientHeight = 528
  ClientWidth = 827
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  DesignSize = (
    827
    528)
  PixelsPerInch = 96
  TextHeight = 13
  object lbl1: TLabel
    Left = 376
    Top = 0
    Width = 91
    Height = 13
    Caption = 'JSON Visualization:'
  end
  object lbl2: TLabel
    Left = 0
    Top = 293
    Width = 107
    Height = 13
    Caption = 'Compact Visualization:'
  end
  object btnBuild: TButton
    Left = 0
    Top = 81
    Width = 135
    Height = 25
    Caption = 'Build JWS (JWT && JWK)'
    TabOrder = 0
    OnClick = btnBuildClick
  end
  object btnTJOSEBuild: TButton
    Left = 0
    Top = 50
    Width = 135
    Height = 25
    Caption = 'Build JWS using TJOSE'
    TabOrder = 1
    OnClick = btnTJOSEBuildClick
  end
  object btnTJOSEVerify: TButton
    Left = 141
    Top = 50
    Width = 135
    Height = 25
    Caption = 'Verify JWS using TJOSE'
    TabOrder = 2
    OnClick = btnTJOSEVerifyClick
  end
  object btnTestClaims: TButton
    Left = 0
    Top = 19
    Width = 135
    Height = 25
    Caption = 'Test Date Claims'
    TabOrder = 3
    OnClick = btnTestClaimsClick
  end
  object memoJSON: TMemo
    Left = 376
    Top = 19
    Width = 433
    Height = 186
    Anchors = [akLeft, akTop, akRight, akBottom]
    Font.Charset = ANSI_CHARSET
    Font.Color = clWindowText
    Font.Height = -13
    Font.Name = 'Courier New'
    Font.Style = []
    ParentFont = False
    TabOrder = 4
  end
  object memoCompact: TMemo
    Left = 0
    Top = 312
    Width = 827
    Height = 216
    Align = alBottom
    Font.Charset = ANSI_CHARSET
    Font.Color = clWindowText
    Font.Height = -13
    Font.Name = 'Courier New'
    Font.Style = []
    ParentFont = False
    TabOrder = 5
  end
end
