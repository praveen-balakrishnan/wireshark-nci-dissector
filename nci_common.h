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

#ifndef NCI_COMMON_H
#define NCI_COMMON_H

#define NCI_STATUS_OK                                           0x00
#define NCI_STATUS_REJECTED                                     0x01
#define NCI_STATUS_FAILED                                       0x03
#define NCI_STATUS_NOT_INITIALIZED                              0x04
#define NCI_STATUS_SYNTAX_ERROR                                 0x05
#define NCI_STATUS_SEMANTIC_ERROR                               0x06
#define NCI_STATUS_INVALID_PARAM                                0x09
#define NCI_STATUS_MESSAGE_SIZE_EXCEEDED                        0x0A
#define NCI_STATUS_OK_1_BIT                                     0x11
#define NCI_STATUS_OK_2_BIT                                     0x12
#define NCI_STATUS_OK_3_BIT                                     0x13
#define NCI_STATUS_OK_4_BIT                                     0x14
#define NCI_STATUS_OK_5_BIT                                     0x15
#define NCI_STATUS_OK_6_BIT                                     0x16
#define NCI_STATUS_OK_7_BIT                                     0x17
#define NCI_STATUS_DISCOVERY_ALREADY_STARTED                    0xA0
#define NCI_STATUS_DISCOVERY_TARGET_ACTIVATION_FAILED           0xA1
#define NCI_STATUS_DISCOVERY_TEAR_DOWN                          0xA2
#define NCI_STATUS_RF_FRAME_CORRUPTED                           0x02
#define NCI_STATUS_RF_TRANSMISSION_EXCEPTION                    0xB0
#define NCI_STATUS_RF_PROTOCOL_EXCEPTION                        0xB1
#define NCI_STATUS_RF_TIMEOUT_EXCEPTION                         0xB2
#define NCI_STATUS_RF_UNEXPECTED_DATA                           0xB3
#define NCI_STATUS_NFCEE_INTERFACE_ACTIVATION_FAILED            0xC0
#define NCI_STATUS_NFCEE_TRANSMISSION_ERROR                     0xC1
#define NCI_STATUS_NFCEE_PROTOCOL_ERROR                         0xC2
#define NCI_STATUS_NFCEE_TIMEOUT_ERROR                          0xC3

#endif
