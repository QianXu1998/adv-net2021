/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

#define CONST_MAX_HOPS        9

// Define constants
const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_MPLS = 0x8847;
const bit<16> TYPE_HEART = 0x1926;

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
	bit<20>  label; // The MPLS label (the egress_port)
	bit<3>   exp;
	bit<1>   s;    // Bottom of the stack
	bit<8>   ttl;
}

header heart_t {
    bit<9>    port;
    bit<1>    from_cp;
    bit<6>    padding;
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

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> checksum;
}

// Instantiate metadata fields
struct metadata {
    bit<1>   link_State; // The link state of egress port.
    bit<2>   meter_color; // Current meter color.
    bit<48>  tmp_stamp; // Temp values to store timestamps.
}

struct headers {
	ethernet_t                    ethernet;
    heart_t                       heart;
	mpls_t[CONST_MAX_HOPS]        mpls;
	ipv4_t                        ipv4;
    tcp_t                         tcp;
    udp_t                         udp;
}

