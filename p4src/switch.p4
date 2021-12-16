/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

//My includes
#include "include/headers.p4"
#include "include/parsers.p4"

#define N_PORTS 12

// Define Linkstate Register, used to indicate failure, 0 = Fine, 1 = Failed
register<bit<1>>(N_PORTS) linkState;
register<bit<48>>(N_PORTS) linkStamp;
register<bit<64>>(N_PORTS) linkIngressSize;
register<bit<64>>(N_PORTS) linkEgressSize;

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

    /* Define Dirtect Meter(Attached to tables) */
    direct_meter<bit<2>>(MeterType.bytes) rate_limiting_meter;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    table tcp_sla {
        key = {
            standard_metadata.ingress_port: exact;
            hdr.ipv4.dstAddr: lpm;
            hdr.tcp.srcPort: range;
            hdr.tcp.dstPort: range;
        }

        actions = {
            drop;
            NoAction;
        }
        default_action = NoAction();
        size = 4096;
    }

    table udp_sla {
        key = {
            standard_metadata.ingress_port: exact;
            hdr.ipv4.dstAddr: lpm;
            hdr.udp.srcPort: range;
            hdr.udp.dstPort: range;
        }

        actions = {
            drop;
            NoAction;
        }
        default_action = NoAction();
        size = 4096;
    }

    action read_port(bit<9> port_index) {
        linkState.read(meta.link_State, (bit<32>)port_index);
        
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        
        hdr.ethernet.etherType = TYPE_IPV4;
        hdr.mpls.push_front(9); // Force invalidation

        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;

        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    // Build label stack in LER
    action mpls_ingress_1_hop(label_t label_1) {

        rate_limiting_meter.read(meta.meter_color);

        hdr.ethernet.etherType = TYPE_MPLS;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_1;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 1;
    }

    action mpls_ingress_2_hop(label_t label_1, label_t label_2) {
        
        rate_limiting_meter.read(meta.meter_color);

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

        rate_limiting_meter.read(meta.meter_color);
        
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

        rate_limiting_meter.read(meta.meter_color);
        
        hdr.ethernet.etherType = TYPE_MPLS;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_1;
        // hdr.mpls[0].index = 1;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 1;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_2;
        // hdr.mpls[0].index = 2;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_3;
        // hdr.mpls[0].index = 3;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_4;
        // hdr.mpls[0].index = 4;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;
    }

    action mpls_ingress_5_hop(label_t label_1, label_t label_2, label_t label_3, label_t label_4, label_t label_5) {

        rate_limiting_meter.read(meta.meter_color);
        
        hdr.ethernet.etherType = TYPE_MPLS;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_1;
        // hdr.mpls[0].index = 1;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 1;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_2;
        // hdr.mpls[0].index = 2;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_3;
        // hdr.mpls[0].index = 3;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_4;
        // hdr.mpls[0].index = 4;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_5;
        // hdr.mpls[0].index = 5;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;
    }

    action mpls_ingress_6_hop(label_t label_1, label_t label_2, label_t label_3, label_t label_4, label_t label_5, label_t label_6) {
        rate_limiting_meter.read(meta.meter_color);

        hdr.ethernet.etherType = TYPE_MPLS;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_1;
        // hdr.mpls[0].index = 1;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 1;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_2;
        // hdr.mpls[0].index = 2;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_3;
        // hdr.mpls[0].index = 3;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_4;
        // hdr.mpls[0].index = 4;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_5;
        // hdr.mpls[0].index = 5;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_6;
        // hdr.mpls[0].index = 6;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;
    }

    action mpls_ingress_7_hop(label_t label_1, label_t label_2, label_t label_3, label_t label_4, label_t label_5, label_t label_6, label_t label_7) {
        rate_limiting_meter.read(meta.meter_color);

        hdr.ethernet.etherType = TYPE_MPLS;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_1;
        // hdr.mpls[0].index = 1;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 1;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_2;
        // hdr.mpls[0].index = 2;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_3;
        // hdr.mpls[0].index = 3;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_4;
        // hdr.mpls[0].index = 4;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_5;
        // hdr.mpls[0].index = 5;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_6;
        // hdr.mpls[0].index = 6;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_7;
        // hdr.mpls[0].index = 7;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;
    }

    action mpls_ingress_8_hop(label_t label_1, label_t label_2, label_t label_3, label_t label_4, label_t label_5, label_t label_6, label_t label_7, label_t label_8) {
        rate_limiting_meter.read(meta.meter_color);

        hdr.ethernet.etherType = TYPE_MPLS;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_1;
        // hdr.mpls[0].index = 1;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 1;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_2;
        // hdr.mpls[0].index = 2;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_3;
        // hdr.mpls[0].index = 3;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_4;
        // hdr.mpls[0].index = 4;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_5;
        // hdr.mpls[0].index = 5;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_6;
        // hdr.mpls[0].index = 6;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_7;
        // hdr.mpls[0].index = 7;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_8;
        // hdr.mpls[0].index = 8;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;
    }

    action mpls_ingress_9_hop(label_t label_1, label_t label_2, label_t label_3, label_t label_4, label_t label_5, label_t label_6, label_t label_7, label_t label_8, label_t label_9) {
        rate_limiting_meter.read(meta.meter_color);

        hdr.ethernet.etherType = TYPE_MPLS;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_1;
        // hdr.mpls[0].index = 1;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 1;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_2;
        // hdr.mpls[0].index = 2;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_3;
        // hdr.mpls[0].index = 3;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_4;
        // hdr.mpls[0].index = 4;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_5;
        // hdr.mpls[0].index = 5;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_6;
        // hdr.mpls[0].index = 6;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_7;
        // hdr.mpls[0].index = 7;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_8;
        // hdr.mpls[0].index = 8;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;

        hdr.mpls.push_front(1);
        hdr.mpls[0].setValid();
        hdr.mpls[0].label = label_9;
        // hdr.mpls[0].index = 9;
        hdr.mpls[0].ttl = hdr.ipv4.ttl - 1;
        hdr.mpls[0].s = 0;
    }

    // Define FEC Table for ingress port
    table FEC_tbl {
        key = {
            hdr.ipv4.srcAddr: lpm;
            hdr.ipv4.dstAddr: exact;
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
            mpls_ingress_9_hop;
            NoAction;
        }
        default_action = NoAction();
        meters = rate_limiting_meter;
        size = 256;
    }

    // Define MPLS forward table
    action mpls_forward(macAddr_t dstAddr, egressSpec_t port) {
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;

        standard_metadata.egress_spec = port;
        read_port(standard_metadata.egress_spec);
        // hdr.mpls[1].failure_indication = meta.link_State;

        hdr.mpls[1].ttl = hdr.mpls[0].ttl - 1;
        // hdr.mpls[1].index = hdr.mpls[1].index - 1;

        hdr.mpls.pop_front(1);
    }

    action penultimate(macAddr_t dstAddr, egressSpec_t port){
        hdr.ethernet.etherType = TYPE_IPV4;

        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;

        hdr.ipv4.ttl = hdr.mpls[0].ttl - 1;

        standard_metadata.egress_spec = port;
        read_port(standard_metadata.egress_spec);
        hdr.mpls.push_front(9);
        
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
        size = 256;
    }

    // Define the failure handling table
    action lfa_replace_1_hop(label_t label_1) {
        // First Pop the whole MPLS label stack
        hdr.mpls.push_front(9);

        // Invoke the mpls building function
        mpls_ingress_1_hop(label_1);
    }

    action lfa_replace_2_hop(label_t label_1, label_t label_2) {
        // First Pop the whole MPLS label stack
        hdr.mpls.push_front(9);

        // Invoke the mpls building function
        mpls_ingress_2_hop(label_1, label_2);
    }

    action lfa_replace_3_hop(label_t label_1, label_t label_2, label_t label_3) {
        // First Pop the whole MPLS label stack
        hdr.mpls.push_front(9);

        // Invoke the mpls building function
        mpls_ingress_3_hop(label_1, label_2, label_3);
    }

    action lfa_replace_4_hop(label_t label_1, label_t label_2, label_t label_3, label_t label_4) {
        // First Pop the whole MPLS label stack
        hdr.mpls.push_front(9);

        // Invoke the mpls building function
        mpls_ingress_4_hop(label_1, label_2, label_3, label_4);
    }

    action lfa_replace_5_hop(label_t label_1, label_t label_2, label_t label_3, label_t label_4, label_t label_5) {
        // First Pop the whole MPLS label stack
        hdr.mpls.push_front(9);

        // Invoke the mpls building function
        mpls_ingress_5_hop(label_1, label_2, label_3, label_4, label_5);
    }

    action lfa_replace_6_hop(label_t label_1, label_t label_2, label_t label_3, label_t label_4, label_t label_5, label_t label_6) {
        // First Pop the whole MPLS label stack
        hdr.mpls.push_front(9);

        // Invoke the mpls building function
        mpls_ingress_6_hop(label_1, label_2, label_3, label_4, label_5, label_6);
    }

    action lfa_replace_7_hop(label_t label_1, label_t label_2, label_t label_3, label_t label_4, label_t label_5, label_t label_6, label_t label_7) {
        // First Pop the whole MPLS label stack
        hdr.mpls.push_front(9);

        // Invoke the mpls building function
        mpls_ingress_7_hop(label_1, label_2, label_3, label_4, label_5, label_6, label_7);
    }

    action lfa_replace_8_hop(label_t label_1, label_t label_2, label_t label_3, label_t label_4, label_t label_5, label_t label_6, label_t label_7, label_t label_8) {
        // First Pop the whole MPLS label stack
        hdr.mpls.push_front(9);

        // Invoke the mpls building function
        mpls_ingress_8_hop(label_1, label_2, label_3, label_4, label_5, label_6, label_7, label_8);
    }

    action lfa_replace_9_hop(label_t label_1, label_t label_2, label_t label_3, label_t label_4, label_t label_5, label_t label_6, label_t label_7, label_t label_8, label_t label_9) {
        // First Pop the whole MPLS label stack
        hdr.mpls.push_front(9);

        // Invoke the mpls building function
        mpls_ingress_9_hop(label_1, label_2, label_3, label_4, label_5, label_6, label_7, label_8, label_9);
    }

    table LFA_REP_tbl {
        key = {
            // hdr.ipv4.srcAddr: lpm;
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            // ipv4_forward;
            lfa_replace_1_hop;
            lfa_replace_2_hop;
            lfa_replace_3_hop;
            lfa_replace_4_hop;
            lfa_replace_5_hop;
            lfa_replace_6_hop;
            lfa_replace_7_hop;
            lfa_replace_8_hop;
            lfa_replace_9_hop;
            NoAction;
        }
        default_action = NoAction();
        size = 256;
    }

    // Define link update table
    // action update_link() {
    //     linkState.write((bit<32>)hdr.link_state.port, hdr.link_state.value);
    // }

    table lfa_mpls_tbl {
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
        size = 256;
    }

    apply {
        /* Ingress Pipeline Control Logic */
        if (hdr.heart.isValid()) {
            if (hdr.heart.from_cp == 1) {
                hdr.heart.from_cp = 0;
                standard_metadata.egress_spec = hdr.heart.port;
            } else {
                // meta.hb.stamp = standard_metadata.ingress_global_timestamp;
                // meta.hb.port = standard_metadata.ingress_port;
                // digest<digest_t>(1, meta.hb);
                mark_to_drop(standard_metadata);
            }
        }  else {
            if(hdr.ethernet.isValid()) {

                @atomic {
                    linkStamp.read(meta.tmp_stamp, (bit<32>)standard_metadata.ingress_port);
                    if (standard_metadata.ingress_global_timestamp > meta.tmp_stamp) {
                        linkStamp.write((bit<32>)standard_metadata.ingress_port, standard_metadata.ingress_global_timestamp);
                    }
                }
                
                @atomic {
                    linkIngressSize.read(meta.tmp_size, (bit<32>)standard_metadata.ingress_port);
                    linkIngressSize.write((bit<32>)standard_metadata.ingress_port, meta.tmp_size + (bit<64>)standard_metadata.packet_length);
                }
            }
            // if (hdr.tcp.isValid() && (!tcp_sla.apply().hit)) {
            //     return;
            // }
            // if (hdr.udp.isValid() && (!udp_sla.apply().hit)) {
            //     return;
            // }
            if(hdr.ipv4.isValid()){
                FEC_tbl.apply();
            }
            if(hdr.mpls[0].isValid()){
                mpls_tbl.apply();
            }
            // This part can be optimized , waste one cycle of manipulating the packet
            // if(meta.link_State > 0){
            //     LFA_REP_tbl.apply();
            //     if(hdr.mpls[0].isValid()){
            //         lfa_mpls_tbl.apply();
            //     }
            // }
        }

        /* If meter is not green then drop (Can be optimized, may not be that strict) */
        // if (meta.meter_color != 0) {
        //     drop();
        // }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {
        if(hdr.ethernet.isValid()) {

            @atomic {
                linkStamp.read(meta.tmp_stamp, (bit<32>)standard_metadata.egress_port);
                if (standard_metadata.egress_global_timestamp > meta.tmp_stamp) {
                    linkStamp.write((bit<32>)standard_metadata.egress_port, standard_metadata.egress_global_timestamp);
                }
            }
            
            @atomic {
                linkEgressSize.read(meta.tmp_size, (bit<32>)standard_metadata.egress_port);
                linkEgressSize.write((bit<32>)standard_metadata.egress_port, meta.tmp_size + (bit<64>)standard_metadata.packet_length);
            }
        }
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
