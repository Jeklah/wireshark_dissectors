-- Lua Dissector for SMPTE 2022-6
-- Author: Arthur Bowers
--
-- This dissector is based on the SMPTE 2022-6 specification
-- http://www.smpte-ra.org/mdd/documents/SMPTE%202022-6%202012.pdf
--
-- To use in Wireshark:
-- 1. Ensure that the Lua plugin is enabled in Wireshark
-- 2. Copy this file to the Wireshark plugins directory
-- 3. Restart Wireshark
-- 4. In Wireshark Preferences, under "Protocols", set "SMPTE 2022-6" as dynamic payload type 98 ##?? prin said not 98?
-- 5. Decode UDP packets as RTP.
-- 6. You will now see the SMPTE 2022-6 Data dissection of the RTP payload
--
-- This program is free software; you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation; either version 2 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
---------------------------------------------------------------------------
do
  local smpte_2022_6 = Proto("smpte_2022_6", "SMPTE 2022-6")
  local prefs = smpte_2022_6.prefs
  prefs.dyn_pt = Pref.uint("SMPTE 2022-6 Dynamic Payload Type", 0, "The value > 95")

  local F = smpte_2022_6.fields

  F.Ext = ProtoField.uint8("smpte_2022_6.Ext", "Extension field (Ext)", base.HEX, nil, 0xF0)
  F.F = ProtoField.bool("smpte_2022_6.F", "Video source format flag (F)", 8, { "Present", "Not Present" }, 0x08)
  F.VSID = ProtoField.uint8("smpte_2022_6.VSID", "Video source ID (VSID)", base.HEX,
          {
              [0] = "primary stream",
              [1] = "protect stream",
              [2] = "reserved",
              [4] = "reserved",
              [5] = "reserved",
              [6] = "reserved",
              [7] = "reserved"
          }, 0x0E)
  F.FRCount = ProtoField.uint8("smpte_2022_6.FRCount", "Frame Count (FRCount)")
  F.R = ProtoField.uint8("smpte_2022_6.R", "Reference for time stamp (R)", base.HEX,
          {
              [0] = "not locked",
              [1] = "reserved",
              [2] = "locked to UTC time/frequency reference",
              [3] = "localed to a private time/frequency reference"
          }, 0xC0)
  F.S = ProtoField.uint8("smpte_2022_6.S", "Video Payload Scambling (S)", base.HEX,
          { [0] = "not scrambled",[1] = "reserved",[2] = "reserved",[3] = "reserved" }, 0x30)
  F.FEC = ProtoField.uint8("smpte_2022_6.FEC", "FEC Usage (FEC)", base.HEX,
          {
              [0] = "No FEC Stream",
              [1] = "L(Column) FEC Utilized",
              [2] = "L&D (Column and Row) FEC Utilized",
              [3] = "reserved",
              [4] = "reserved",
              [5] = "reserved",
              [6] = "reserved",
              [7] = "reserved"
          }, 0x0E)
  F.CF = ProtoField.uint16("smpte_2022_6.CF", "Clock Frequency (CF)", base.HEX,
          {
              [0] = "No time stamp",
              [1] = "27 Mhz",
              [2] = "148.5Mhz",
              [3] = "148.5/1.001 Mhz",
              [4] = "297 Mhz",
              [5] = "297/1.001 Mhz"
          }, 0x01E0)
  F.MAP = ProtoField.uint8("smpte_2022_6.MAP", "Video Source Format (MAP)", base.HEX,
          {
              [0] = "Direct sample structure",
              [1] = "SMPTE ST 425-1 Level B-DL Mapping of 372 Dual-Link",
              [2] = "SMPTE ST 425-1 Level B-DS Mapping of two ST 292-1 Streams"
          }, 0xF0)
  F.FRAME = ProtoField.uint16("smpte_2022_6.FRAME", "Frame Structure (FRAME)", base.HEX,
          {
              [0x10] = "720x486 active, interlaced",
              [0x11] = "720x576 active, interlaced",
              [0x20] = "1920x1080 active, progressive",
              [0x22] = "1920x1080 active PsF",
              [0x23] = "2048x1080 active, progressive",
              [0x24] = "2048x1080, PsF",
              [0x30] = "1280x720 active, progressive"
          },
          0x0FF0)

  frame_rates = {
      [0x00] = "Unknown/Unspecified frame rate 2.970 GHz signal",
      [0x01] = "Unknown/Unspecified frame rate 2.970/1.001 GHz Signal",
      [0x02] = "Unknown/Unspecified frame rate 1.485 GHz Signal",
      [0x03] = "Unknown/Unspecified frame rate 1.485/1.001 GHz Signal",
      [0x04] = "Unknown/Unspecified frame rate 0.270 GHz Signal",
      [0x10] = "60",
      [0x11] = "60/1.001",
      [0x12] = "50",
      [0x13] = "reserved",
      [0x14] = "48",
      [0x15] = "48/1.001",
      [0x16] = "30",
      [0x17] = "30/1.001",
      [0x18] = "25",
      [0x19] = "reserved",
      [0x1A] = "24",
      [0x1B] = "24/1.001"
  }

  F.FRATE = ProtoField.uint16("smpte_2022_6.FRATE", "Frame Rate (FRATE)", base.HEX, frame_rates, 0x0FF0)

  sampling = {
      [0x00] = "Unknown/Unspecified",
      [0x01] = "4:2:2 10 bits",
      [0x02] = "4:4:4 10 bits",
      [0x03] = "4:4:4:4 10 bits",
      [0x04] = "Reserved",
      [0x05] = "4:2:2 12 bits",
      [0x06] = "4:4:4 12 bits",
      [0x07] = "4:4:4:4 12 bits",
      [0x08] = "4:2:2:4 12 bits"
  }

  F.SAMPLE = ProtoField.uint8("smpte_2022_6.SAMPLE", "Picture sampling (SAMPLE)", base.HEX, sampling, 0x0F)
