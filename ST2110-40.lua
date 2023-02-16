-- Lua Dissector for SMPTE ST 2110-40
-- (which references RFC 8331)
-- Author: Arthur Bowers
--
-- To use in WireShark:
-- 1) Ensure your WireShark works with Lua plugins - "About Wireshark" should say it is compiled with Lua.
-- 2) Install this dissector in the proper plugin dirctory - see "About Wireshark/Folders" to see Personal
--    and Global plugin directories. After putting this dissector in the proper folder,
--    "About Wireshark/Plugins" should list "ST-2110_40.lua"
-- 3) In WireShark preferences, under "Protocols", set st_2110_40 as dynamic payload type being used.
-- 4) Capture packets of ST 2110-40.
-- 5) "Decode As" those UDP packets as RTP.
-- 6) You will now see the ST 2110_40 Data dissection of the RTP payload.
--
-- This program is free software; you can redistribute is and/or
-- modify it under the terms of the GNY General Public License
-- as published by the Free Software Foundation; either version 2 of the License,
-- or (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful, but
-- WITHOUT ANY WARRANTY; without even the implied warranty of MECHANTABILITY
-- or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
-- for more details.
--
--
-- --------------------------------------------------------------------------------------------------------
do
  local st_2110_40 = Proto("st_2110_40", "ST 2110_40")

  local prefs = st_2110_40.prefs
  prefs.dyn_pt = Pref.uint("ST 2110_40 dynamic payload type", 0, "The value > 95")

  local F = st_2110_40.fields

  F.ESN = ProtoField.uint("st_2110_40.ExtendedSequenceNumber", "Extended Sequence Number", base.HEX, nil)
  F.Length = ProtoField.uint16("st_2110_40.Length", "Length", base.DEC, nil)
  F.ANC_Count = ProtoField.uint8("st_2110_40.ANC_Count", "ANC_Count", base.DEC, nil)
  local VALS_F = { [0] = "unspecified or progressive scan",[1] = "not valid",[2] = "Field 1",[3] = "Field 2" }
  F.F = ProtoField.uint8("st_2110_40.F", "(F)ield", base.HEX, VALS_F, 0xC0)
  F.C = ProtoField.bool("st_2110_40.C, ", "(C) or Y", 8, { "C:Color-difference", "Y:Luma" }, 0x80)
  F.Data_Count = ProtoField.uint16("st_2110_40.Data_Count", "Data Count", base.DEC, nil, 0x03FC)
  F.Line_Number = ProtoField.uint16("st_2110_40.Line_Number", "Line Number", base.DEC, nil, 0x7FF0)
  F.HO = ProtoField.uint16("st_2110_40.HO", "Horizontal Offset", base.DEC, nil, 0x0FFF)
  F.S = ProtoField.bool("st_2110_40.S", "S", 8, { "StreamNum used", "StreamNum not used" }, 0x80)
  F.StreamNum = ProtoField.uint8("st_2110_40.StreamNum", "StreamNum", base.DEC, nil, 0x7F)
  F.DID = ProtoField.uint16("st_2110_40.DID", "DID", base.HEX, nil, 0x3FC0)
  F.SDID = ProtoField.uint16("st_2110_40.SDID", "SDID", base.HEX, nil, 0x0FF0)
  F.UDW = ProtoField.bytes("st_2110_40.UDW", "UDW Bytes", base.SPACE)
  F.UDW_array = ProtoField.bytes("st_2110_40.UDW_array", "UDW Array", base.SPACE)
  F.Checksum = ProtoField.uint16("st_2110_40.Checksum", "Checksum Word", base.HEX, nil)
  F.Checksum_Calc = ProtoField.uint16("st_2110_40.Checksum_Calculated", "Calculated Checksum", base.HEX, nil)

  -- User Data Structure

  F.Magic = ProtoField.uint16("st_2110_40.Data.Magic", "MagicHeader", base.HEX, nil)
  F.DataWord_Count = ProtoField.uint8("st_2110_40.Data.DW_Count", "Data Count", base.DEC, nil)
  F.Frame_Rate = ProtoField.uint8("st_2110_40.Data.FrameRate", "Frame Rate", base.HEX, nil)
  F.Section_Available = ProtoField.uint8("st_2110_40.Data.Section_Available", "Section Available", base.HEX, nil, 0xFF)
  F.CDP_Section_Type = ProtoField.uint8("st_2110_40.Data.Section_Type", "CDP Section Type", base.HEX, nil)
  F.CDP_Seq_Counter = ProtoField.uint16("st_2110_40.Data.CDP_Seq_Counter", "CDP Sequence Counter", base.HEX, nil)

  -- VBI Data
  -- Spec: EN 301 775 - V1.2.1
  local PES_DATA_ID = {}
  for i = 0, 255 do
    if (i >= 0x10 and i <= 0x1F or i >= 0x99 and i <= 0x9B) then
      PES_DATA_ID[i] = "EBU Teletext/VPS/WSS/CC/VBI sample data"
    elseif (i >= 0x80 and i <= 0x98 or i >= 0x9C and i <= 0xFF) then
      PES_DATA_ID[i] = "User Defined"
    else
      PES_DATA_ID[i] = "Reserved for future use"
    end
  end
  F.Data_Identifier = ProtoField.uint8("st_2110_40.Data.Data_Identifier", "Data Identifier", base.HEX, PES_DATA_ID)

  -- Spec: ST2031-2007
  local PES_DATA_UNIT_ID = {}
  for i = 0, 255 do
    if (i == 0x00 or i == 0x01) then
      PES_DATA_UNIT_ID[i] = "DVB Reserved"
    elseif (i == 0x02) then
      PES_DATA_UNIT_ID[i] = "EBU Teletext non-subtitle data"
    elseif (i == 0x03) then
      PES_DATA_UNIT_ID[i] = "EBU Teletext subtitle data"
    elseif (i >= 0x04 or i <= 0x7F) then
      PES_DATA_UNIT_ID[i] = "DVB Reserved"
    elseif (i >= 0x80 or i <= 0xBF) then
      PES_DATA_UNIT_ID[i] = "User Defined"
    elseif (i >= 0xC0) then
      PES_DATA_UNIT_ID[i] = "Inverted Teletext"
    elseif (i == 0xC1 or i == 0xC2) then
      PES_DATA_UNIT_ID[i] = "DVB Reserved"
    elseif (i >= 0xC3) then
      PES_DATA_UNIT_ID[i] = "VPS"
    elseif (i >= 0xC4) then
      PES_DATA_UNIT_ID[i] = "WSS"
    elseif (i >= 0xC5) then
      PES_DATA_UNIT_ID[i] = "CEA-608 Closed Captioning"
    elseif (i >= 0xC6) then
      PES_DATA_UNIT_ID[i] = "monochrome 4:2:2 samples"
    elseif (i >= 0xC7 or i <= 0xCF) then
      PES_DATA_UNIT_ID[i] = "User Defined"
    elseif (i >= 0xD0) then
      PES_DATA_UNIT_ID[i] = "AMOL48"
    elseif (i >= 0xD1) then
      PES_DATA_UNIT_ID[i] = "AMOL96"
    elseif (i == 0xD2 or i >= 0xDA and i <= 0xE5) then
      PES_DATA_UNIT_ID[i] = "SCTE Reserved"
    elseif (i == 0xD3 or i == 0xD4 or i == 0xD8) then
      PES_DATA_UNIT_ID[i] = "Protected"
    elseif (i == 0xD5) then
      PES_DATA_UNIT_ID[i] = "NABTS"
    elseif (i == 0xD6) then
      PES_DATA_UNIT_ID[i] = "TVG2X"
    elseif (i == 0xD7) then
      PES_DATA_UNIT_ID[i] = "Copy Protection"
    elseif (i == 0xD8) then
      PES_DATA_UNIT_ID[i] = "VITC"
    elseif (i >= 0xE6 and i <= 0xFE) then
      PES_DATA_UNIT_ID[i] = "SCTE User Defined"
    elseif (i == 0xFF) then
      PES_DATA_UNIT_ID[i] = "MPEG Stuffing"
    else
      PES_DATA_UNIT_ID[i] = "Reserved or user defined"
    end
  end
  F.Data_UnitId = ProtoField.uint8("st_2110_40.Data.Data_UnitId", "Data Unit ID", base.HEX, PES_DATA_UNIT_ID)
  F.Data_UnitLength = ProtoField.uint8("st_2110_40.Data.Data_UnitLength", "Data Unit Length", base.DEC)

  -- Spec: ST RDD 08, aka OP-47 Subtitle Distribution Packet
  F.SDP_Identifier = ProtoField.uint16("st_2110_40.Data.SDP_Identifier", "Identifier", base.HEX)
  F.SDP_Length = ProtoField.uint8("st_2110_40.Data.SDP_Length", "Length", base.HEX)
  F.SDP_FormatCode = ProtoField.uint8("st_2110_40.Data.SDP_FormatCode", "Format Code", base.HEX)
  F.SDP_AdaptionHeader = ProtoField.bytes("st_2110_40.Data.SDP_AdaptionHeader", "Adaption Header", base.SPACE)
  F.SDP_PktDescB = ProtoField.bytes("st_2110_40.Data.SDP_PktDescB", "Packet Descriptor B", base.SPACE)

  -- Spec: EN 300 472
  F.Field_Parity = ProtoField.bool("st_2110_40.Data.Field_Parity", "Field Parity", 8,
          { "First field of a frame", "Second field of a frame" }, 0x20)
  F.Line_Offset = ProtoField.uint8("st_2110_40.Data.Line_Number", "Line Offset", base.DEC, nil, 0x1F)

  -- Spec: EN 300 706
  F.Clock_RunIn = ProtoField.uint16("st_2110_40.Data.Clock_RunIn", "Clock Run-In", base.HEX, nil, 0xFFFF)
  F.Framing_Code = ProtoField.uint8("st_2110_40.Data.Framing_Code", "Framing Code", base.HEX, nil, 0xFF)
  F.Magazine_Hamming = ProtoField.uint16("st_2110_40.Data.Magazine_Hamming", "Magazine (Hamming 8/4)", base.DEC, nil,
          0xFC00)
  F.Magazine = ProtoField.uint8("st_2110_40.Data.Magazine", "Magazine", base.DEC, nil)
  F.PacketNumber_Hamming = ProtoField.uint16("st_2110_40.Data.PacketNumber_Hamming", "Packet Number (Hamming 8/4",
          base.DEC, nil, 0x3FF)
  F.PacketNumber = ProtoField.uint8("st_2110_40.Data.PacketNumber", "Packet Number", base.DEC, nil)
  F.PageUnits_Hamming = ProtoField.uint8("st_2110_40.Data.PageUnits_Hamming", "Page Units (Hamming 8/4)", base.HEX, nil,
          0xFF)
  F.PageUnits = ProtoField.uint8("st_2110_40.Data.PageUnits", "Page Units", base.HEX, nil)

  F.PageTens_Hamming = ProtoField.uint8("st_2110_40.Data.PageTens_Hamming", "Page Tens (Hamming 8/4)", base.HEX, nil,
          0xFF)
  F.PageTens = ProtoField.uint8("st_2110_40.Data.PageTens", "Page Tens", base.HEX, nil)

  F.DataString = ProtoField.string("st_2110_40.Data.Data_String", "Data String")
  F.TextData_Array = ProtoField.bytes("st_2110_40.Data.TextData", "Text Data", base.SPACE)
