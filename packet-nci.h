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

#ifndef PACKET_NCI_H
#define PACKET_NCI_H

#define NCI_MT_DATA                         0b000
#define NCI_MT_CMD                          0b001
#define NCI_MT_RSP                          0b010
#define NCI_MT_NTF                          0b011

#define NCI_PBF_COMPLETE                    0b0
#define NCI_PBF_SEGMENT                     0b1

#define NCI_GID_NCI_CORE                    0b0000
#define NCI_GID_RF_MGMT                     0b0001
#define NCI_GID_NFCEE_MGMT                  0b0010
#define NCI_GID_NFCC_MGMT                   0b0011
#define NCI_GID_TEST_MGMT                   0b0100
#define NCI_GID_PROP                        0b1111

// NCI Core (0000b)
#define NCI_OID_CORE_RESET                  0b000000
#define NCI_OID_CORE_INIT                   0b000001
#define NCI_OID_CORE_SET_CONFIG             0b000010
#define NCI_OID_CORE_GET_CONFIG             0b000011
#define NCI_OID_CORE_CONN_CREATE            0b000100
#define NCI_OID_CORE_CONN_CLOSE             0b000101
#define NCI_OID_CORE_CONN_CREDITS           0b000110
#define NCI_OID_CORE_GENERIC_ERROR          0b000111
#define NCI_OID_CORE_INTERFACE_ERROR        0b001000
#define NCI_OID_CORE_SET_POWER_SUB_STATE    0b001001

// RF Management (0001b)
#define NCI_OID_RF_DISCOVER_MAP             0b000000
#define NCI_OID_RF_SET_LISTEN_MODE_ROUTING  0b000001
#define NCI_OID_RF_GET_LISTEN_MODE_ROUTING  0b000010
#define NCI_OID_RF_DISCOVER                 0b000011
#define NCI_OID_RF_DISCOVER_SELECT          0b000100
#define NCI_OID_RF_INTF_ACTIVATED           0b000101
#define NCI_OID_RF_DEACTIVATE               0b000110
#define NCI_OID_RF_FIELD_INFO               0b000111
#define NCI_OID_RF_T3T_POLLING              0b001000
#define NCI_OID_RF_NFCEE_ACTION             0b001001
#define NCI_OID_RF_NFCEE_DISCOVERY_REQ      0b001010
#define NCI_OID_RF_PARAMETER_UPDATE         0b001011
#define NCI_OID_RF_INTF_EXT_START           0b001100
#define NCI_OID_RF_INTF_EXT_STOP            0b001101
#define NCI_OID_RF_EXT_AGG_ABORT            0b001110
#define NCI_OID_RF_NDEF_ABORT               0b001111
#define NCI_OID_RF_ISO_DEP_NAK_PRESENCE     0b010000
#define NCI_OID_RF_SET_FORCED_NFCEE_ROUTING 0b010001

// NFCEE Management (0010b)
#define NCI_OID_NFCEE_DISCOVER              0b000000
#define NCI_OID_NFCEE_MODE_SET              0b000001
#define NCI_OID_NFCEE_STATUS                0b000010
#define NCI_OID_NFCEE_POWER_AND_LINK_CNTRL  0b000011





#endif