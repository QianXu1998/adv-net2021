/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

#define CONST_MAX_LABELS      4

// Define constants
const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_MPLS = 0x8847;

// Define headers
typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
	macAddr_t srcAddr;
	macAddr_t dstAddr;
}
// Instantiate metadata fields
struct metadata {

}

// Instantiate packet headers
struct headers {

}

