/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

//My includes
#include "include/headers.p4"
#include "include/parsers.p4"

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_is_ingress_border() {
        meta.is_ingress_border = (bit<1>)1;
    }

    // TODO: Change the matching condition, this won't work for the project
    table check_is_ingress_border {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            NoAction;
            set_is_ingress_border;
        }
        default_action = NoAction;
        size = CONST_MAX_PORTS;
    }

    action add_mpls_header(bit<20> tag){
        hdr.mpls.setValid();
        hdr.mpls.label = tag;
        hdr.mpls.s = 0;
        hdr.mpls.ttl = 255;
        hdr.ethernet.etherType = TYPE_MPLS;
    }

    // Define the fec table -> adding label to the packet
    table fec_to_label {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            NoAction;
            add_mpls_header;
        }
        default_action = NoAction;
        size = CONST_MAX_LABELS;
    }

    // Define MPLS Label forwarding method
    action mpls_forward(macAddr_t dstAddr, egressSpec_t port) {
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;

        standard_metadata.egress_spec = port;
        hdr.mpls.ttl = hdr.mpls.ttl - 1;
    }

    table mpls_tbl {
        key = {
            hdr.mpls.label: exact;
        }
        actions = {
            mpls_forward;
            drop;
        }
        default_action = drop;
        size = CONST_MAX_LABELS;
    }

    // Define default ipv4 forwarding
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
        }
        default_action = drop;
        size = 128;
    }

    apply {
        // First, check whether it is an ingress border or not
        check_is_ingress_border.apply();
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {

    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
    update_checksum(
        hdr.ipv4.isValid(),{
            hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.diffserv,
            hdr.ipv4.totalLen,
            hdr.ipv4.identification,
            hdr.ipv4.flags,
            hdr.ipv4.fragOffset,
            hdr.ipv4.ttl,
            hdr.ipv4.protocol,
            hdr.ipv4.srcAddr,
            hdr.ipv4.dstAddr
        },
        hdr.ipv4.hdrChecksum,
        HashAlgorithm.csum16
    );
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

//switch architecture
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;