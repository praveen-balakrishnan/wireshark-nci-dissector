/*

    This file is part of wireshark-nci-dissector.

    wireshark-nci-dissector is free software: you can redistribute it and/or
    modify it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or (at your
    option) any later version.

    wireshark-nci-dissector is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
    Public License for more details.

    You should have received a copy of the GNU General Public License along
    with wireshark-nci-dissector. If not, see <https://www.gnu.org/licenses/>. 

*/

#ifndef NCI_CORE_H
#define NCI_CORE_H

#include <epan/packet.h>

#define NCI_CORE_RESET_KEEP_CONFIG          0x00
#define NCI_CORE_RESET_RESET_CONFIG         0x01

#define NCI_CORE_RESET_ERROR                0x00
#define NCI_CORE_RESET_PWR_ON               0x01
#define NCI_CORE_RESET_RESET_CMD_RCVD       0x02

#define NCI_CORE_RESET_V10                  0x10
#define NCI_CORE_RESET_V11                  0x11
#define NCI_CORE_RESET_V20                  0x20

#define NCI_CORE_O0_DISCOVER_FREQ           0b00000001
#define NCI_CORE_O0_MULTICONFIG             0b00000010
#define NCI_CORE_O0_HCI_NETWORK             0b00001000
#define NCI_CORE_O0_ACTIVE_COMM             0b00010000

#define NCI_CORE_O1_TECH_ROUTING            0b00000010
#define NCI_CORE_O1_PROTOCOL_ROUTING        0b00000100
#define NCI_CORE_O1_AID_ROUTING             0b00001000
#define NCI_CORE_O1_SYSTEM_CODE_ROUTING     0b00010000
#define NCI_CORE_O1_APDU_ROUTING            0b00100000
#define NCI_CORE_O1_FORCED_NFCEE_ROUTING    0b01000000

#define NCI_CORE_O2_BATTERY_OFF_STATE       0b00000001
#define NCI_CORE_O2_SWITCH_OFF_STATE        0b00000010
#define NCI_CORE_O2_SWITCH_ON_SUBMODE_STATE 0b00000100
#define NCI_CORE_O2_RF_CONF_SWITCH_OFF      0b00001000



extern hf_register_info nci_core_hf[];

void handle_nci_core(int oid, int pkt_type, proto_tree* tree, tvbuff_t *tvb, int* hoffset);

#endif
