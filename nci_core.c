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

#include "nci_common.h"
#include "nci_core.h"
#include "packet-nci.h"

static int hf_reset_cmd_type;
static int hf_reset_rsp_status;
static int hf_reset_ntf_rtrigger;
static int hf_reset_ntf_config_status;
static int hf_reset_ntf_nci_ver;
static int hf_reset_ntf_mfr_id;
static int hf_reset_ntf_mfr_silen;
static int hf_reset_ntf_mfr_si;

static const value_string nci_reset_type_strs[] = {
    {NCI_CORE_RESET_KEEP_CONFIG, "Keep config"},
    {NCI_CORE_RESET_RESET_CONFIG, "Reset config"},
    {0, NULL}
};

static const value_string nci_reset_trigger_strs[] = {
    {NCI_CORE_RESET_ERROR, "Unrecoverable error"},
    {NCI_CORE_RESET_PWR_ON, "NFCC power on"},
    {NCI_CORE_RESET_RESET_CMD_RCVD, "Reset CMD received"},
    {0, NULL}
};

static const value_string nci_status_strs[] = {
    {NCI_STATUS_OK, "STATUS_OK"},
    {NCI_STATUS_REJECTED, "STATUS_REJECTED"},
    {NCI_STATUS_FAILED, "STATUS_FAILED"},
    {NCI_STATUS_NOT_INITIALIZED, "STATUS_NOT_INITIALIZED"},
    {NCI_STATUS_SYNTAX_ERROR, "STATUS_SYNTAX_ERROR"},
    {NCI_STATUS_SEMANTIC_ERROR, "STATUS_SEMANTIC_ERROR"},
    {NCI_STATUS_INVALID_PARAM, "STATUS_INVALID_PARAM"},
    {NCI_STATUS_MESSAGE_SIZE_EXCEEDED, "STATUS_MESSAGE_SIZE_EXCEEDED"},
    {NCI_STATUS_OK_1_BIT, "STATUS_OK_1_BIT"},
    {NCI_STATUS_OK_2_BIT, "STATUS_OK_2_BIT"},
    {NCI_STATUS_OK_3_BIT, "STATUS_OK_3_BIT"},
    {NCI_STATUS_OK_4_BIT, "STATUS_OK_4_BIT"},
    {NCI_STATUS_OK_5_BIT, "STATUS_OK_5_BIT"},
    {NCI_STATUS_OK_6_BIT, "STATUS_OK_6_BIT"},
    {NCI_STATUS_OK_7_BIT, "STATUS_OK_7_BIT"},
    {0, NULL}
};

static const value_string nci_version_strs[] = {
    {NCI_CORE_RESET_V10, "V1.0"},
    {NCI_CORE_RESET_V11, "V1.1"},
    {NCI_CORE_RESET_V20, "V2.0"},
    {0, NULL}
};

hf_register_info hf[] = {
    { &hf_reset_cmd_type,
        { "Reset Type", "nci.core_reset_cmd.type",
        FT_UINT8, BASE_DEC,
        VALS(nci_reset_type_strs), 0x0,
        NULL, HFILL }
    },
    { &hf_reset_rsp_status,
        { "Status", "nci.core_reset_rsp.status",
        FT_UINT8, BASE_DEC,
        VALS(nci_status_strs), 0x0,
        NULL, HFILL }
    },
    { &hf_reset_ntf_rtrigger,
        { "Reset Trigger", "nci.core_reset_ntf.reset_trigger",
        FT_UINT8, BASE_DEC,
        VALS(nci_reset_trigger_strs), 0x0,
        NULL, HFILL }
    },
    { &hf_reset_ntf_config_status,
        { "Configuration Status", "nci.core_reset_ntf.status",
        FT_UINT8, BASE_DEC,
        VALS(nci_reset_type_strs), 0x0,
        NULL, HFILL }
    },
    { &hf_reset_ntf_nci_ver,
        { "Version", "nci.core_reset_ntf.ver",
        FT_UINT8, BASE_DEC,
        VALS(nci_version_strs), 0x0,
        NULL, HFILL }
    },
    { &hf_reset_ntf_mfr_id,
        { "Mfr. ID", "nci.core_reset_ntf.mfr_id",
        FT_UINT8, BASE_DEC,
        NULL, 0x00,
        NULL, HFILL }
    },
    { &hf_reset_ntf_mfr_silen,
        { "Mfr. Specific Info. Length", "nci.core_reset_ntf.mfr_si_len",
        FT_UINT8, BASE_DEC,
        NULL, 0x00,
        NULL, HFILL }
    },
    { &hf_reset_ntf_mfr_si,
        { "Mfr. Specific Info.", "nci.core_reset_ntf.mfr_si",
        FT_UINT8, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    }
};

void handle_reset(int pkt_type, proto_tree* tree, tvbuff_t *tvb, int* hoffset)
{
    if ((pkt_type & NCI_MT_CMD) == NCI_MT_CMD) {
        proto_tree_add_item(tree, hf_reset_cmd_type, tvb, *hoffset, 1, ENC_BIG_ENDIAN);
        *hoffset += 1;
    } else if ((pkt_type & NCI_MT_RSP) == NCI_MT_RSP) {
        proto_tree_add_item(tree, hf_reset_rsp_status, tvb, *hoffset, 1, ENC_BIG_ENDIAN);
        *hoffset += 1;
    } else if ((pkt_type & NCI_MT_NTF) == NCI_MT_NTF) {
        proto_tree_add_item(tree, hf_reset_ntf_rtrigger, tvb, *hoffset, 1, ENC_BIG_ENDIAN);
        *hoffset += 1;
        proto_tree_add_item(tree, hf_reset_ntf_config_status, tvb, *hoffset, 1, ENC_BIG_ENDIAN);
        *hoffset += 1;
        proto_tree_add_item(tree, hf_reset_ntf_nci_ver, tvb, *hoffset, 1, ENC_BIG_ENDIAN);
        *hoffset += 1;
        proto_tree_add_item(tree, hf_reset_ntf_mfr_id, tvb, *hoffset, 1, ENC_BIG_ENDIAN);
        *hoffset += 1;
        proto_tree_add_item(tree, hf_reset_ntf_mfr_silen, tvb, *hoffset, 1, ENC_BIG_ENDIAN);
        uint8_t silen = tvb_get_uint8(tvb, *hoffset);
        *hoffset += 1;
        proto_tree_add_item(tree, hf_reset_ntf_mfr_si, tvb, *hoffset, silen, ENC_BIG_ENDIAN);
        *hoffset += silen;
    }
}

void handle_init(int pkt_type, proto_tree* tree, tvbuff_t *tvb, int* hoffset)
{
    if ((pkt_type & NCI_MT_CMD) == NCI_MT_CMD) {
    } else if ((pkt_type & NCI_MT_RSP) == NCI_MT_RSP) {
    } else if ((pkt_type & NCI_MT_NTF) == NCI_MT_NTF) {
    }
}

void handle_nci_core(int oid, int pkt_type, proto_tree* tree, tvbuff_t *tvb, int* hoffset) {
    switch (oid) {
    case NCI_OID_CORE_RESET:
        handle_reset(pkt_type, tree, tvb, hoffset);
        break;
    }
}