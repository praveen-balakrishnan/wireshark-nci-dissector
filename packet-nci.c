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
    
#include "config.h"
#include "packet-nci.h"
#include <epan/packet.h>

// Refer to the NFC Controller Interface (NCI) Specification v2.0

static int proto_nci;

static int hf_nci_mt;
static int hf_nci_pbf;
static int hf_nci_gid;
static int hf_nci_oid_nciCore;
static int hf_nci_oid_rfMgmt;
static int hf_nci_oid_nfceeMgmt;
//static int hf_nci_oid_nfccMgmt;
//static int hf_nci_oid_testMgmt;
//static int hf_nci_oid_prop;
static int hf_nic_payload_len;

static int ett_nci;

static const value_string nci_mt_vals[] = {
    {NCI_MT_DATA, "DATA"},
    {NCI_MT_CMD, "CMD"},
    {NCI_MT_RSP, "RSP"},
    {NCI_MT_NTF, "NTF"},
    {0, NULL}
};

static const value_string nci_pbf_vals[] = {
    {NCI_PBF_COMPLETE, "COMPLETE"},
    {NCI_PBF_SEGMENT, "SEGMENT"},
    {0, NULL}
};

static const value_string nci_gid_vals[] = {
    {NCI_GID_NCI_CORE, "NCI_CORE"},
    {NCI_GID_RF_MGMT, "RF_MGMT"},
    {NCI_GID_NFCEE_MGMT, "NFCEE_MGMT"},
    {NCI_GID_NFCC_MGMT, "NFCC_MGMT"},
    {NCI_GID_TEST_MGMT, "TEST_MGMT"},
    {NCI_GID_PROP, "PROP"},
    {0, NULL}
};

// NCI Core (0000b)
static const value_string nci_oid_nci_core_vals[] = {
    {NCI_OID_CORE_RESET, "CORE_RESET"},
    {NCI_OID_CORE_INIT, "CORE_INIT"},
    {NCI_OID_CORE_SET_CONFIG, "CORE_SET_CONFIG"},
    {NCI_OID_CORE_GET_CONFIG, "CORE_GET_CONFIG"},
    {NCI_OID_CORE_CONN_CREATE, "CORE_CONN_CREATE"},
    {NCI_OID_CORE_CONN_CLOSE, "CORE_CONN_CLOSE"},
    {NCI_OID_CORE_CONN_CREDITS, "CORE_CONN_CREDITS"},
    {NCI_OID_CORE_GENERIC_ERROR, "CORE_GENERIC_ERROR"},
    {NCI_OID_CORE_INTERFACE_ERROR, "CORE_INTERFACE_ERROR"},
    {NCI_OID_CORE_SET_POWER_SUB_STATE, "CORE_SET_POWER_SUB_STATE"},
    {0, NULL}
};

// RF Management (0001b)
static const value_string nci_oid_rf_mgmt_vals[] = {
    {NCI_OID_RF_DISCOVER_MAP, "RF_DISCOVER_MAP"},
    {NCI_OID_RF_SET_LISTEN_MODE_ROUTING, "RF_SET_LISTEN_MODE_ROUTING"},
    {NCI_OID_RF_GET_LISTEN_MODE_ROUTING, "RF_GET_LISTEN_MODE_ROUTING"},
    {NCI_OID_RF_DISCOVER, "RF_DISCOVER"},
    {NCI_OID_RF_DISCOVER_SELECT, "RF_DISCOVER_SELECT"},
    {NCI_OID_RF_INTF_ACTIVATED, "RF_INTF_ACTIVATED"},
    {NCI_OID_RF_DEACTIVATE, "RF_DEACTIVATE"},
    {NCI_OID_RF_FIELD_INFO, "RF_FIELD_INFO"},
    {NCI_OID_RF_T3T_POLLING, "RF_T3T_POLLING"},
    {NCI_OID_RF_NFCEE_ACTION, "RF_NFCEE_ACTION"},
    {NCI_OID_RF_NFCEE_DISCOVERY_REQ, "RF_NFCEE_DISCOVERY_REQ"},
    {NCI_OID_RF_PARAMETER_UPDATE, "RF_PARAMETER_UPDATE"},
    {NCI_OID_RF_INTF_EXT_START, "RF_INTF_EXT_START"},
    {NCI_OID_RF_INTF_EXT_STOP, "RF_INTF_EXT_STOP"},
    {NCI_OID_RF_EXT_AGG_ABORT, "RF_EXT_AGG_ABORT"},
    {NCI_OID_RF_NDEF_ABORT, "RF_NDEF_ABORT"},
    {NCI_OID_RF_ISO_DEP_NAK_PRESENCE, "RF_ISO_DEP_NAK_PRESENCE"},
    {NCI_OID_RF_SET_FORCED_NFCEE_ROUTING, "RF_SET_FORCED_NFCEE_ROUTING"},
    {0, NULL}
};

// NFCEE Management (0010b)
static const value_string nci_oid_nfcee_mgmt_vals[] = {
    {NCI_OID_NFCEE_DISCOVER, "NFCEE_DISCOVER"},
    {NCI_OID_NFCEE_MODE_SET, "NFCEE_MODE_SET"},
    {NCI_OID_NFCEE_STATUS, "NFCEE_STATUS"},
    {NCI_OID_NFCEE_POWER_AND_LINK_CNTRL, "NFCEE_POWER_AND_LINK_CNTRL"},
    {0, NULL}
};


static dissector_handle_t nci_handle;

static void handle_cmd(proto_tree* tree, tvbuff_t *tvb, int* hoffset, proto_item* ti)
{
    proto_tree_add_item(tree, hf_nci_gid, tvb, *hoffset, 1, ENC_BIG_ENDIAN);

    uint8_t gid = tvb_get_uint8(tvb, *hoffset) & 0x0F;
    *hoffset += 1;

    uint8_t oid = tvb_get_uint8(tvb, *hoffset) & 0x3F;
    *hoffset += 1;

    switch (gid) {
    case NCI_GID_NCI_CORE:
        proto_item_append_text(ti, ", Packet: %s",
            val_to_str(oid, nci_oid_nci_core_vals, "Unknown (0x%02x)"));
        proto_tree_add_item(tree, hf_nci_oid_nciCore, tvb, *hoffset, 1, ENC_BIG_ENDIAN);
        break;
    case NCI_GID_RF_MGMT:
        proto_item_append_text(ti, ", Packet: %s",
            val_to_str(oid, nci_oid_rf_mgmt_vals, "Unknown (0x%02x)"));
        proto_tree_add_item(tree, hf_nci_oid_rfMgmt, tvb, *hoffset, 1, ENC_BIG_ENDIAN);
        break;
    case NCI_GID_NFCEE_MGMT:
        proto_item_append_text(ti, ", Packet: %s",
            val_to_str(oid, nci_oid_nfcee_mgmt_vals, "Unknown (0x%02x)"));
        proto_tree_add_item(tree, hf_nci_oid_nfceeMgmt, tvb, *hoffset, 1, ENC_BIG_ENDIAN);
        break;
    }

    //uint8_t payload_length = tvb_get_uint8(tvb, *hoffset);
    proto_item* plen_item = proto_tree_add_item(tree, hf_nic_payload_len, tvb, *hoffset, 1, ENC_BIG_ENDIAN);
    proto_item_append_text(plen_item, " bytes");
}

static void handle_data(void)
{
    /// TODO: Implement.
}

static int dissect_nci(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NCI");
    col_clear(pinfo->cinfo,COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, proto_nci, tvb, 0, -1, ENC_NA);
    uint8_t packet_type = tvb_get_uint8(tvb, 0) >> 5;
    proto_item_append_text(ti, ", Type %s",
        val_to_str(packet_type, nci_mt_vals, "Unknown (0x%02x)"));
    proto_tree *nci_tree = proto_item_add_subtree(ti, ett_nci);
    int offset = 0;
    proto_tree_add_item(nci_tree, hf_nci_mt, tvb, 0, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(nci_tree, hf_nci_pbf, tvb, 0, 1, ENC_BIG_ENDIAN);

    if ((packet_type & NCI_MT_CMD) == NCI_MT_CMD) {
        col_set_str(pinfo->cinfo, COL_DEF_SRC, "DH");
        col_set_str(pinfo->cinfo, COL_DEF_DST, "NFCC");
    } else if ((packet_type & NCI_MT_NTF) == NCI_MT_NTF
                || (packet_type & NCI_MT_DATA) == NCI_MT_DATA) {
        col_set_str(pinfo->cinfo, COL_DEF_SRC, "NFCC");
        col_set_str(pinfo->cinfo, COL_DEF_DST, "DH");
    }

    // CMD/RESP/Notif
    if (packet_type)
        handle_cmd(nci_tree, tvb, &offset, ti);
    else
        handle_data();

    return tvb_captured_length(tvb);
}

void proto_register_nci(void)
{
    static hf_register_info hf[] = {
        { &hf_nci_mt,
            { "Message Type", "nci.mt",
            FT_UINT8, BASE_DEC,
            VALS(nci_mt_vals), 0xE0,
            NULL, HFILL }
        },
        { &hf_nci_pbf,
            { "Packet Boundary Flag", "nci.pbf",
            FT_UINT8, BASE_DEC,
            VALS(nci_pbf_vals), 0x10,
            NULL, HFILL }
        },
        { &hf_nci_gid,
            { "GID", "nci.gid",
            FT_UINT8, BASE_DEC,
            VALS(nci_gid_vals), 0x0F,
            NULL, HFILL }
        },
        { &hf_nci_oid_nciCore,
            { "OID", "nci.oid",
            FT_UINT8, BASE_DEC,
            VALS(nci_oid_nci_core_vals), 0x3F,
            NULL, HFILL }
        },
        { &hf_nci_oid_rfMgmt,
            { "OID", "nci.oid",
            FT_UINT8, BASE_DEC,
            VALS(nci_oid_rf_mgmt_vals), 0x3F,
            NULL, HFILL }
        },
        { &hf_nci_oid_nfceeMgmt,
            { "OID", "nci.oid",
            FT_UINT8, BASE_DEC,
            VALS(nci_oid_nfcee_mgmt_vals), 0x3F,
            NULL, HFILL }
        },
        { &hf_nic_payload_len,
            { "Payload length", "nci.plen",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        }
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_nci
    };

    proto_nci = proto_register_protocol (
        "NCI Protocol", /* protocol name        */
        "NCI",          /* protocol short name  */
        "nci"           /* protocol filter_name */
        );

    proto_register_field_array(proto_nci, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    nci_handle = register_dissector_with_description (
        "nci",          /* dissector name           */
        "NCI Protocol", /* dissector description    */
        dissect_nci,    /* dissector function       */
        proto_nci       /* protocol being dissected */
        );
}

void proto_reg_handoff_nci(void)
{
    dissector_add_uint("wtap_encap", NCI_DLT_USER, nci_handle);
}
