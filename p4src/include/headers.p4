/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

#define CONST_MAX_HOPS        9

// Define constants
const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_MPLS = 0x8847;

// Define headers
typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<20> label_t;

header ethernet_t {
    macAddr_t dstAddr;
	macAddr_t srcAddr;
	bit<16>   etherType;
}

// Header definition for MPLS
header mpls_t {
	bit<20>  label;
	bit<3>   exp;  // Experimental Use
	bit<1>   s;    // Bottom of the stack
	bit<8>   ttl;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

// Instantiate metadata fields
struct metadata {
	
}

// Instantiate packet headers
struct headers {
	ethernet_t                    ethernet;
	mpls_t[CONST_MAX_HOPS]        mpls;
	ipv4_t                        ipv4;
}

