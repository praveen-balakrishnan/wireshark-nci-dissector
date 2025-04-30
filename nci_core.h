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

extern hf_register_info nci_core_hf[];

void handle_nci_core(int oid, int pkt_type, proto_tree* tree, tvbuff_t *tvb, int* hoffset);

#endif
