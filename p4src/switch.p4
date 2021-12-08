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

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {

        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;

        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    // // Define default ipv4 forwarding
    // table ipv4_lpm {
    //     key = {
    //         hdr.ipv4.dstAddr: lpm;
    //     }
    //     actions = {
    //         ipv4_forward;
    //         drop;
    //     }
    //     default_action = drop;
    //     size = 128;
    // }

    // Build label stack in LER
    action mpls_ingress_1_hop(label_t label_1) {

        hdr.ethernet.etherType = TYPE_MPLS;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_1;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 1;
    }

    action mpls_ingress_2_hop(label_t label_1, label_t label_2) {

        hdr.ethernet.etherType = TYPE_MPLS;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_1;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 1;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_2;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;
    }

    action mpls_ingress_3_hop(label_t label_1, label_t label_2, label_t label_3) {

        hdr.ethernet.etherType = TYPE_MPLS;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_1;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 1;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_2;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_3;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;
    }

    action mpls_ingress_4_hop(label_t label_1, label_t label_2, label_t label_3, label_t label_4) {

        hdr.ethernet.etherType = TYPE_MPLS;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_1;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 1;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_2;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_3;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_4;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;
    }

    action mpls_ingress_5_hop(label_t label_1, label_t label_2, label_t label_3, label_t label_4, label_t label_5) {

        hdr.ethernet.etherType = TYPE_MPLS;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_1;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 1;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_2;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_3;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_4;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_5;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;
    }

    action mpls_ingress_6_hop(label_t label_1, label_t label_2, label_t label_3, label_t label_4, label_t label_5, label_t label_6) {
        // rsvp_meter.read(meta.meter_color);

        hdr.ethernet.etherType = TYPE_MPLS;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_1;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 1;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_2;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_3;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_4;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_5;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_6;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;
    }

    action mpls_ingress_7_hop(label_t label_1, label_t label_2, label_t label_3, label_t label_4, label_t label_5, label_t label_6, label_t label_7) {
        // rsvp_meter.read(meta.meter_color);

        hdr.ethernet.etherType = TYPE_MPLS;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_1;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 1;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_2;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_3;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_4;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_5;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_6;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_7;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;
    }

    action mpls_ingress_8_hop(label_t label_1, label_t label_2, label_t label_3, label_t label_4, label_t label_5, label_t label_6, label_t label_7, label_t label_8) {
        // rsvp_meter.read(meta.meter_color);

        hdr.ethernet.etherType = TYPE_MPLS;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_1;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 1;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_2;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_3;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_4;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_5;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_6;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_7;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_8;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;
    }

    // Define FEC Table for ingress port
    table FEC_tbl {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            mpls_ingress_1_hop;
            mpls_ingress_2_hop;
            mpls_ingress_3_hop;
            mpls_ingress_4_hop;
            mpls_ingress_5_hop;
            mpls_ingress_6_hop;
            mpls_ingress_7_hop;
            mpls_ingress_8_hop;
            NoAction;
        }
        default_action = NoAction();
        size = 256;
    }

    // Define MPLS forward table
    action mpls_forward(macAddr_t dstAddr, egressSpec_t port) {
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;

        standard_metadata.egress_spec = port;

        hdr.mpls[1].ttl = hdr.mpls[0].ttl - 1;

        hdr.mpls.pop_front(1);
    }

    action penultimate(macAddr_t dstAddr, egressSpec_t port){
        hdr.ethernet.etherType = TYPE_IPV4;

        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;

        hdr.ipv4.ttl = hdr.mpls[0].ttl - 1;

        standard_metadata.egress_spec = port;
        hdr.mpls.pop_front(1);
    }

    table mpls_tbl {
        key = {
            hdr.mpls[0].label: exact;
            hdr.mpls[0].s: exact;
        }
        actions = {
            mpls_forward;
            penultimate;
            NoAction;
        }
        default_action = NoAction();
        size = CONST_MAX_LABELS;
    }

    apply {
        /* Ingress Pipeline Control Logic */
        if(hdr.ipv4.isValid()){
            FEC_tbl.apply();
        }
        if(hdr.mpls[0].isValid()){
            mpls_tbl.apply();
        }
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