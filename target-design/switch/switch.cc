#include <functional>
#include <vector>
#include <queue>
#include <algorithm>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <unistd.h>
#include <omp.h>
#include <cstdlib>
#include <arpa/inet.h>
#include <string>
#include <sstream>
#include <random>
#include <set>

#include <time.h>
#include <netinet/ether.h>
#include <net/ethernet.h>
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "classbench_trace.h"
#include "zipf_dist.cc"

#define IGNORE_PRINTF

#ifdef IGNORE_PRINTF
#define printf(fmt, ...) (0)
#endif

// param: link latency in cycles
// assuming 3.2 GHz, this number / 3.2 = link latency in ns
// e.g. setting this to 35000 gives you 35000/3.2 = 10937.5 ns latency
// IMPORTANT: this must be a multiple of 7
//
// THIS IS SET BY A COMMAND LINE ARGUMENT. DO NOT CHANGE IT HERE.
//#define LINKLATENCY 6405
int LINKLATENCY = 0;

// param: switching latency in cycles
// assuming 3.2 GHz, this number / 3.2 = switching latency in ns
//
// THIS IS SET BY A COMMAND LINE ARGUMENT. DO NOT CHANGE IT HERE.
int switchlat = 0;

#define SWITCHLATENCY (switchlat)

// param: numerator and denominator of bandwidth throttle
// Used to throttle outbound bandwidth from port
//
// THESE ARE SET BY A COMMAND LINE ARGUMENT. DO NOT CHANGE IT HERE.
int throttle_numer = 1;
int throttle_denom = 1;

const int NUM_BANDS = 4; // Number of queues on a port

// uncomment to use a limited output buffer size, OUTPUT_BUF_SIZE
//#define LIMITED_BUFSIZE

// size of output buffers, in # of flits
// only if LIMITED BUFSIZE is set
// TODO: expose in manager
#define OUTPUT_BUF_SIZE (131072L)

// pull in # clients config
#define NUMCLIENTSCONFIG
#include "switchconfig.h"
#undef NUMCLIENTSCONFIG

// DO NOT TOUCH
#define NUM_TOKENS (LINKLATENCY)
#define TOKENS_PER_BIGTOKEN (7)
#define BIGTOKEN_BYTES (64)
#define NUM_BIGTOKENS (NUM_TOKENS/TOKENS_PER_BIGTOKEN)
#define BUFSIZE_BYTES (NUM_BIGTOKENS*BIGTOKEN_BYTES)

// DO NOT TOUCH
#define SWITCHLAT_NUM_TOKENS (SWITCHLATENCY)
#define SWITCHLAT_NUM_BIGTOKENS (SWITCHLAT_NUM_TOKENS/TOKENS_PER_BIGTOKEN)
#define SWITCHLAT_BUFSIZE_BYTES (SWITCHLAT_NUM_BIGTOKENS*BIGTOKEN_BYTES)

uint64_t this_iter_cycles_start = 0;

// pull in mac2port array
#define MACPORTSCONFIG
#include "switchconfig.h"
#undef MACPORTSCONFIG

#include "flit.h"
#include "baseport.h"
#include "shmemport.h"
#include "socketport.h"
#include "sshport.h"

#define ETHER_HEADER_SIZE          14
#define IP_DST_FIELD_OFFSET        16 // Dest field immediately after, in same 64-bit flit
#define IP_PROTOCOL_OFFSET         9
#define IP_TOS_OFFSET              1
#define IP_SUBNET_OFFSET           2
#define IP_HEADER_SIZE             20 // TODO: Not always, just currently the case with L-NIC.

#define LNIC_DATA_FLAG_MASK        0b1
#define LNIC_ACK_FLAG_MASK         0b10
#define LNIC_NACK_FLAG_MASK        0b100
#define LNIC_PULL_FLAG_MASK        0b1000
#define LNIC_CHOP_FLAG_MASK        0b10000
#define LNIC_HEADER_MSG_LEN_OFFSET 5
#define LNIC_HEADER_PKT_IDX_OFFSET 7
#define LNIC_HEADER_SIZE           30
static const char* lnicFlagNames[8] = {
    "DATA", "ACK", "NACK", "PULL", "CHOP", "UNKNOWN", "UNKNOWN", "UNKNOWN"
};

#define NDP_DATA_FLAG_MASK        0b1
#define NDP_ACK_FLAG_MASK         0b10
#define NDP_NACK_FLAG_MASK        0b100
#define NDP_PULL_FLAG_MASK        0b1000
#define NDP_CHOP_FLAG_MASK        0b10000
#define NDP_HEADER_MSG_LEN_OFFSET 5
#define NDP_HEADER_PKT_IDX_OFFSET 7
#define NDP_HEADER_SIZE           30
static const char* ndpFlagNames[8] = {
    "DATA", "ACK", "NACK", "PULL", "CHOP", "UNKNOWN", "UNKNOWN", "UNKNOWN"
};

#define HOMA_DATA_FLAG_MASK        0b1
#define HOMA_ACK_FLAG_MASK         0b10
#define HOMA_NACK_FLAG_MASK        0b100
#define HOMA_GRANT_FLAG_MASK       0b1000
#define HOMA_CHOP_FLAG_MASK        0b10000
#define HOMA_RESEND_FLAG_MASK      0b100000
#define HOMA_BUSY_FLAG_MASK        0b1000000
#define HOMA_BOGUS_FLAG_MASK       0b10000000
#define HOMA_HEADER_MSG_LEN_OFFSET 5
#define HOMA_HEADER_PKT_IDX_OFFSET 7
#define HOMA_HEADER_SIZE           30
static const char* homaFlagNames[8] = {
    "DATA", "ACK", "NACK", "GRANT", "CHOP", "RESEND", "BUSY", "BOGUS"
};

#define CHOPPED_PKT_SIZE          72 // Bytes, the minimum trimmed packet size

#define MICA_R_TYPE 1
#define MICA_W_TYPE 2
#define MICA_VALUE_SIZE_WORDS 64
#define MICA_KEY_SIZE_WORDS   2
struct __attribute__((__packed__)) mica_hdr_t {
  uint64_t op_type;
  uint64_t key[MICA_KEY_SIZE_WORDS];
  uint64_t key_hash;
  uint64_t value[MICA_VALUE_SIZE_WORDS];
};

struct __attribute__((__packed__)) intersect_hdr_t {
  uint64_t query_word_cnt;
  uint64_t query_word_ids[16];
};
struct __attribute__((__packed__)) resp_intersect_hdr_t {
  uint64_t doc_cnt;
  uint64_t doc_ids[16];
};

#define EUCLIDEAN_DIST_VECTOR_SIZE 64
struct __attribute__((__packed__)) euclidean_dist_hdr_t {
  uint16_t query_vector[EUCLIDEAN_DIST_VECTOR_SIZE];
  uint64_t haystack_vector_cnt;
  uint64_t haystack_vector_ids[12];
};

#define CHAINREP_FLAGS_FROM_TESTER    (1 << 7)
#define CHAINREP_FLAGS_OP_READ        (1 << 6)
#define CHAINREP_FLAGS_OP_WRITE       (1 << 5)
#define CHAINREP_CHAIN_SIZE           3
#define CHAINREP_VALUE_SIZE_WORDS     8
#define CHAINREP_KEY_SIZE_WORDS       2
struct __attribute__((__packed__)) chainrep_w_hdr_t {
  uint8_t flags;
  uint8_t seq;
  uint8_t node_cnt;
  uint8_t client_ctx;
  uint32_t client_ip;
  uint64_t nodes[2];
  uint64_t key[CHAINREP_KEY_SIZE_WORDS];
  uint64_t key_hash;
  uint64_t value[CHAINREP_VALUE_SIZE_WORDS];
};
struct __attribute__((__packed__)) chainrep_r_hdr_t {
  uint8_t flags;
  uint8_t seq;
  uint8_t node_cnt;
  uint8_t client_ctx;
  uint32_t client_ip;
  uint64_t key[CHAINREP_KEY_SIZE_WORDS];
};

const uint64_t kAppKeySize = 16; // 16B keys
const uint64_t kAppValueSize = 64; // 64B values
struct __attribute__((packed)) raft_req_header_t {
    uint8_t padding[6];
    uint16_t msg_id;
    // TODO: This should potentially include the hash as well.
    uint64_t key[kAppKeySize / sizeof(uint64_t)];
    uint64_t value[kAppValueSize / sizeof(uint64_t)];
};

struct __attribute__((packed)) raft_resp_t {
    uint8_t padding[6];
    uint16_t msg_id;
    uint32_t leader_ip;
    uint32_t resp_type;
};

#define CLASSIFICATION_HEADER_WORDS 3
struct __attribute__((__packed__)) classification_hdr_t {
  uint32_t trace_idx;
  uint32_t match_priority;
  uint64_t headers[CLASSIFICATION_HEADER_WORDS];
};

//const char* trace_filename = "/tmp/classbench_trace";
const char* trace_filename = NULL; // set to null to use small inline trace
uint32_t num_trace_packets;
trace_packet* trace_packets;
uint32_t next_trace_idx = 0;

// Comment this out to disable pkt trimming
// TODO: Make this a command line argument for easy configuration
#define TRIM_PKTS

// TODO: these should really be exposed via config_runtime.ini
#define LOG_QUEUE_SIZE
#define LOG_EVENTS
#define LOG_ALL_PACKETS
#define LOG_PKT_TRACE

// Pull in load generator parameters, if any
#define LOADGENSTATS
#include "switchconfig.h"
#undef LOADGENSTATS
#ifdef USE_LOAD_GEN
#include "LnicLayer.h" // This is equivalent to NDP, but kept for backward compatibility
#include "NdpLayer.h"
#include "HomaLayer.h"
#include "AppLayer.h"
#include "PayloadLayer.h"
class parsed_packet_t {
 private:
    pcpp::Packet* pcpp_packet;
 public:
    pcpp::EthLayer* eth;
    pcpp::IPv4Layer* ip;
    pcpp::LnicLayer* lnic;
    pcpp::NdpLayer* ndp;
    pcpp::HomaLayer* homa;
    pcpp::AppLayer* app;
    switchpacket* tsp;

    parsed_packet_t() {
        eth = nullptr;
        ip = nullptr;
        lnic = nullptr;
        ndp = nullptr;
        homa = nullptr;
        app = nullptr;
        tsp = nullptr;
        pcpp_packet = nullptr;
    }

    ~parsed_packet_t() {
        if (pcpp_packet != nullptr) {
            delete pcpp_packet;
        }
    }

    bool parse(switchpacket* tsp) {
        uint64_t packet_size_bytes = tsp->amtwritten * sizeof(uint64_t);
        struct timeval format_time;
        format_time.tv_sec = tsp->timestamp / 1000000000;
        format_time.tv_usec = (tsp->timestamp % 1000000000) / 1000;
        pcpp::RawPacket raw_packet((const uint8_t*)tsp->dat, 200*sizeof(uint64_t), format_time, false, pcpp::LINKTYPE_ETHERNET);
        pcpp::Packet* parsed_packet = new pcpp::Packet(&raw_packet);
        pcpp::EthLayer* eth_layer = parsed_packet->getLayerOfType<pcpp::EthLayer>();
        pcpp::IPv4Layer* ip_layer = parsed_packet->getLayerOfType<pcpp::IPv4Layer>();
        pcpp::LnicLayer* lnic_layer = (pcpp::LnicLayer*)parsed_packet->getLayerOfType(pcpp::LNIC, 0);
        pcpp::NdpLayer* ndp_layer = (pcpp::NdpLayer*)parsed_packet->getLayerOfType(pcpp::NDP, 0);
        pcpp::HomaLayer* homa_layer = (pcpp::HomaLayer*)parsed_packet->getLayerOfType(pcpp::HOMA, 0);
        pcpp::AppLayer* app_layer = (pcpp::AppLayer*)parsed_packet->getLayerOfType(pcpp::GenericPayload, 0);
        if (!eth_layer || !ip_layer || (!ndp_layer && !homa_layer && !lnic_layer) || !app_layer) {
            if (!eth_layer) fprintf(stdout, "Null eth layer\n");
            if (!ip_layer) fprintf(stdout, "Null ip layer\n");
            if (!lnic_layer && !ndp_layer && !homa_layer) fprintf(stdout, "Null transport layer\n");
            if (!app_layer) fprintf(stdout, "Null app layer\n");
            this->eth = nullptr;
            this->ip = nullptr;
            this->lnic = nullptr;
            this->ndp = nullptr;
            this->homa = nullptr;
            this->app = nullptr;
            this->tsp = nullptr;
            delete parsed_packet;
            this->pcpp_packet = nullptr;
            return false;
        }
        this->eth = eth_layer;
        this->ip = ip_layer;
        this->lnic = lnic_layer;
        this->ndp = ndp_layer;
        this->homa = homa_layer;
        this->app = app_layer;
        this->tsp = tsp;
        this->pcpp_packet = parsed_packet;
        return true;
    }
};
#define LOAD_GEN_MAC "08:55:66:77:88:08"
#define LOAD_GEN_IP "10.0.0.1"
#define NIC_MAC "00:26:E1:00:00:00"
#define NIC_IP "10.0.0.2"
#define NIC_IP_BIGENDIAN 0x0a000002
#define MAX_TX_MSG_ID 127
#define APP_HEADER_SIZE 16
uint64_t tx_request_count = 0;
uint64_t rx_request_count = 0;
uint64_t request_rate_lambda_inverse;
bool load_generator_complete = false;
bool request_tx_done = false;
uint64_t request_tx_done_time;
uint64_t next_threshold = 0;
uint16_t global_tx_msg_id = 0;
bool start_message_received = false;
uint64_t global_start_message_count = 0;
std::exponential_distribution<double>* gen_dist;
std::default_random_engine* gen_rand;
std::mt19937 *dist_rand_gen;
std::exponential_distribution<double>* service_exp_dist;
std::uniform_int_distribution<>* service_key_uniform_dist;
zipf_distribution<> *service_key_zipf_dist;
std::default_random_engine* dist_rand;
std::normal_distribution<double>* service_normal_high;
std::normal_distribution<double>* service_normal_low;
std::binomial_distribution<int>* service_select_dist;
bool load_gen_hook(switchpacket* tsp);
void generate_load_packets();
void check_request_timeout();
static inline uint64_t cityhash(const uint64_t *s);
bool global_raft_leader_found = false;
bool is_raft = false;
uint32_t global_raft_leader_ip = 0;
uint32_t raft_client_ip = 0x0a000005;
#endif

// These are both set by command-line arguments. Don't change them here.
int HIGH_PRIORITY_OBUF_SIZE = 0;
int LOW_PRIORITY_OBUF_SIZE = 0;

// TODO: replace these port mapping hacks with a mac -> port mapping,
// could be hardcoded

BasePort * ports[NUMPORTS];
void send_with_priority(uint16_t port, switchpacket* tsp);

// State to keep track of the last queue size samples.
// Index 0 is highest-priority
int last_qsize_samples[NUMPORTS][NUM_BANDS];

/* switch from input ports to output ports */
void do_fast_switching() {
#pragma omp parallel for
    for (int port = 0; port < NUMPORTS; port++) {
        ports[port]->setup_send_buf();
    }


// preprocess from raw input port to packets
#pragma omp parallel for
for (int port = 0; port < NUMPORTS; port++) {
    BasePort * current_port = ports[port];
    uint8_t * input_port_buf = current_port->current_input_buf;

    for (int tokenno = 0; tokenno < NUM_TOKENS; tokenno++) {
        if (is_valid_flit(input_port_buf, tokenno)) {
            uint64_t flit = get_flit(input_port_buf, tokenno);

            switchpacket * sp;
            if (!(current_port->input_in_progress)) {
                sp = (switchpacket*)calloc(sizeof(switchpacket), 1);
                current_port->input_in_progress = sp;

                // here is where we inject switching latency. this is min port-to-port latency
                sp->timestamp = this_iter_cycles_start + tokenno + SWITCHLATENCY;
                sp->sender = port;
            }
            sp = current_port->input_in_progress;

            sp->dat[sp->amtwritten++] = flit;
            if (is_last_flit(input_port_buf, tokenno)) {
                current_port->input_in_progress = NULL;
                if (current_port->push_input(sp)) {
                    printf("packet timestamp: %ld, len: %ld, sender: %d\n",
                            this_iter_cycles_start + tokenno,
                            sp->amtwritten, port);
                }
            }
        }
    }
}

// next do the switching. but this switching is just shuffling pointers,
// so it should be fast. it has to be serial though...

// NO PARALLEL!
// shift pointers to output queues, but in order. basically.
// until the input queues have no more complete packets
// 1) find the next switchpacket with the lowest timestamp across all the inputports
// 2) look at its mac, copy it into the right ports
//          i) if it's a broadcast: sorry, you have to make N-1 copies of it...
//          to put into the other queues

struct tspacket {
    uint64_t timestamp;
    switchpacket * switchpack;

    bool operator<(const tspacket &o) const
    {
        return timestamp > o.timestamp;
    }
};

typedef struct tspacket tspacket;


// TODO thread safe priority queue? could do in parallel?
std::priority_queue<tspacket> pqueue;

for (int i = 0; i < NUMPORTS; i++) {
    while (!(ports[i]->inputqueue.empty())) {
        switchpacket * sp = ports[i]->inputqueue.front();
        ports[i]->inputqueue.pop();
        pqueue.push( tspacket { sp->timestamp, sp });
    }
}

// next, put back into individual output queues
while (!pqueue.empty()) {
    switchpacket * tsp = pqueue.top().switchpack;
    pqueue.pop();

    struct timeval format_time;
    format_time.tv_sec = tsp->timestamp / 1000000000;
    format_time.tv_usec = (tsp->timestamp % 1000000000) / 1000;
    pcpp::RawPacket raw_packet((const uint8_t*)tsp->dat, 200*sizeof(uint64_t), format_time, false, pcpp::LINKTYPE_ETHERNET);
    pcpp::Packet parsed_packet(&raw_packet);
    pcpp::EthLayer* ethernet_layer = parsed_packet.getLayerOfType<pcpp::EthLayer>();
    pcpp::IPv4Layer* ip_layer = parsed_packet.getLayerOfType<pcpp::IPv4Layer>();
    if (ethernet_layer == NULL) {
        fprintf(stdout, "NULL ethernet layer\n");
        free(tsp);
        continue;
    }
    if (ip_layer == NULL) {
        fprintf(stdout, "NULL ip layer from %d with amtread %d and amtwritten %d\n", tsp->sender, tsp->amtread, tsp->amtwritten);
        if (ethernet_layer != NULL) {
            fprintf(stdout, "Source MAC %s, dest MAC %s\n", ethernet_layer->getSourceMac().toString().c_str(), ethernet_layer->getDestMac().toString().c_str());
        }
        for (int i = 0; i < tsp->amtwritten; i++) {
            fprintf(stdout, "%d: %#lx\n", i, __builtin_bswap64(tsp->dat[i]));
        }
        free(tsp);
        continue;
    }

// If this is a load generator, we need to do something completely different with all incoming packets.
#ifdef USE_LOAD_GEN
    if (load_gen_hook(tsp)) {
      free(tsp);
      continue;
    }
#endif

    int flit_offset_doublebytes = (ETHER_HEADER_SIZE + IP_DST_FIELD_OFFSET + IP_SUBNET_OFFSET) / sizeof(uint16_t);
    uint16_t switching_flit = ((uint16_t*)tsp->dat)[flit_offset_doublebytes];

    uint16_t send_to_port = get_port_from_flit(switching_flit, 0);
    if (send_to_port == UNKNOWN_ADDRESS) {
        fprintf(stdout, "Packet with unknown destination address, dropping\n");
        free(tsp);
        // Do nothing for a packet with an unknown destination address
    } else if (send_to_port == BROADCAST_ADJUSTED) {
#define ADDUPLINK (NUMUPLINKS > 0 ? 1 : 0)
        // this will only send broadcasts to the first (zeroeth) uplink.
        // on a switch receiving broadcast packet from an uplink, this should
        // automatically prevent switch from sending the broadcast to any uplink
        for (int i = 0; i < NUMDOWNLINKS + ADDUPLINK; i++) {
            if (i != tsp->sender ) {
                switchpacket * tsp2 = (switchpacket*)malloc(sizeof(switchpacket));
                memcpy(tsp2, tsp, sizeof(switchpacket));
                send_with_priority(i, tsp2);
            }
        }
        free(tsp);
    } else {
        send_with_priority(send_to_port, tsp);
    }
}

#ifdef USE_LOAD_GEN
generate_load_packets();
check_request_timeout();
#endif

// Log queue sizes if logging is enabled
#ifdef LOG_QUEUE_SIZE
for (int i = 0; i < NUMPORTS; i++) {
    size_t tot_queue_size = 0;
    bool queue_size_changed = false;
    for (int j = 0; j < NUM_BANDS ; j++) {
        tot_queue_size += ports[i]->outputqueues_size[j];
        if (ports[i]->outputqueues_size[j] != last_qsize_samples[i][j]) {
            queue_size_changed = true;
            last_qsize_samples[i][j] = ports[i]->outputqueues_size[j];
        }
    }
    if (queue_size_changed)
        fprintf(stdout, "&&CSV&&QueueSize,%ld,%d,%d\n", this_iter_cycles_start, i, tot_queue_size);
}
#endif

// finally in parallel, flush whatever we can to the output queues based on timestamp

#pragma omp parallel for
for (int port = 0; port < NUMPORTS; port++) {
    BasePort * thisport = ports[port];
    thisport->write_flits_to_output();
}

}

// Load generator specific code begin
#ifdef USE_LOAD_GEN
void print_packet(char* direction, parsed_packet_t* packet) {
    
    uint8_t l4_protocol = (packet->ip->getIPv4Header()->protocol);
    uint16_t msg_len;
    if (l4_protocol == pcpp::IPProtocolTypes::PACKETPP_IPPROTO_NDP)
        msg_len = ntohs(packet->ndp->getNdpHeader()->msg_len);
    else if (l4_protocol == pcpp::IPProtocolTypes::PACKETPP_IPPROTO_HOMA)
        msg_len = ntohs(packet->homa->getHomaHeader()->msg_len);
    else if (l4_protocol == pcpp::IPProtocolTypes::PACKETPP_IPPROTO_LNIC)
        msg_len = ntohs(packet->lnic->getLnicHeader()->msg_len);
    else 
        msg_len = ntohs(packet->ip->getIPv4Header()->totalLength) - sizeof(iphdr);
    
    uint64_t* payload_base = (uint64_t*)packet->app->getLayerPayload();
    uint64_t* last_word = payload_base + (msg_len / sizeof(uint64_t)) - 3;

    fprintf(stdout, "%s IP(src=%s, dst=%s), ", direction, packet->ip->getSrcIpAddress().toString().c_str(), 
            packet->ip->getDstIpAddress().toString().c_str());
    if (l4_protocol == pcpp::IPProtocolTypes::PACKETPP_IPPROTO_NDP)
        fprintf(stdout, "%s, ", packet->ndp->toString().c_str());
    else if (l4_protocol == pcpp::IPProtocolTypes::PACKETPP_IPPROTO_HOMA)
        fprintf(stdout, "%s, ", packet->homa->toString().c_str());
    else if (l4_protocol == pcpp::IPProtocolTypes::PACKETPP_IPPROTO_LNIC)
        fprintf(stdout, "%s, ", packet->lnic->toString().c_str());
    else 
        fprintf(stdout, "!Transport Layer Not Recognised! ");
    fprintf(stdout, "%s, packet_len=%d, timestamp=%ld, last_word=%ld\n", packet->app->toString().c_str(), 
            packet->tsp->amtwritten * sizeof(uint64_t), packet->tsp->timestamp, be64toh(*last_word));
}

bool count_start_message() {
    global_start_message_count++;
    if (strcmp(test_type, "ONE_CONTEXT_ONE_CORE") == 0) {
        return global_start_message_count >= NUMPORTS;
    } else if (strcmp(test_type, "ONE_CONTEXT_FOUR_CORES") == 0) {
        return global_start_message_count >= 4 * NUMPORTS;
    } else if (strcmp(test_type, "FOUR_CONTEXTS_FOUR_CORES") == 0) {
        return global_start_message_count >= 4 * NUMPORTS;
    } else if (strcmp(test_type, "TWO_CONTEXTS_FOUR_SHARED_CORES") == 0) {
        return global_start_message_count >= 8 * NUMPORTS;
    } else if ((strcmp(test_type, "DIF_PRIORITY_LNIC_DRIVEN") == 0) ||
              (strcmp(test_type, "DIF_PRIORITY_TIMER_DRIVEN") == 0) ||
              (strcmp(test_type, "HIGH_PRIORITY_C1_STALL") == 0) ||
              (strcmp(test_type, "LOW_PRIORITY_C1_STALL") == 0)) {
        return global_start_message_count >= 2 * NUMPORTS;
    } else {
        fprintf(stdout, "Unknown test type: %s\n", test_type);
        exit(-1);
    }
}

double get_avg_service_time() {
    // Compute avg_service_time
    double avg_service_time;
    if (strcmp(service_dist_type, "FIXED") == 0) {
        avg_service_time = (double)fixed_dist_cycles;
    } else if (strcmp(service_dist_type, "EXP") == 0) {
        avg_service_time = exp_dist_scale_factor * (1.0 / exp_dist_decay_const);
    } else if (strcmp(service_dist_type, "BIMODAL") == 0) {
        avg_service_time = bimodal_dist_high_mean * bimodal_dist_fraction_high + bimodal_dist_low_mean * (1.0 - bimodal_dist_fraction_high);
    } else {
        fprintf(stdout, "Unknown distribution type: %s\n", service_dist_type);
        exit(-1);
    }
    return avg_service_time;
}

void log_packet_response_time(parsed_packet_t* packet) {
    // TODO: We need to print a header as well to record what the parameters for this run were.
    uint64_t service_time = be64toh(packet->app->getAppHeader()->service_time);
    uint64_t sent_time = be64toh(packet->app->getAppHeader()->sent_time);
    // TODO: Make this protocol agnostic
    uint16_t src_context = be16toh(packet->lnic->getLnicHeader()->src_context);
    uint64_t recv_time = packet->tsp->timestamp; // TODO: This accounts for tokens, even though sends don't. Is that a problem?
    uint64_t iter_time = this_iter_cycles_start;
    uint64_t delta_time = (recv_time > sent_time) ? (recv_time - sent_time) : 0;
    fprintf(stdout, "&&CSV&&ResponseTimes,%ld,%ld,%ld,%ld,%ld,%d,%f,%ld\n",
      service_time, delta_time, sent_time, recv_time, iter_time, src_context, get_avg_service_time(), request_rate_lambda_inverse);

    if (is_raft) {
        // TODO: Make this protocol agnostic
        uint16_t msg_len = ntohs(packet->lnic->getLnicHeader()->msg_len);
        if (msg_len != sizeof(raft_resp_t) + 2*sizeof(uint64_t)) {
            // Make sure response is the right length
            fprintf(stdout, "ERROR -- response message length is %d, should be %d\n", msg_len, sizeof(raft_resp_t) + 2*sizeof(uint64_t));
            return;
        }
        raft_resp_t* resp_msg = (raft_resp_t*)packet->app->getLayerPayload();
        uint64_t* msg_words = (uint64_t*)resp_msg;
        fprintf(stdout, "%#lx, %#lx\n", msg_words[0], msg_words[1]);
        if (be16toh(resp_msg->msg_id) != 5) {
            fprintf(stdout, "Incorrect raft response msg id %d\n", be16toh(resp_msg->msg_id));
            // Dump anything other than ReqType::kClientReqResponse messages
            return;
        }
        uint32_t resp_type = be32toh(resp_msg->resp_type);
        fprintf(stdout, "Raft message response type is %d\n", resp_type);
    }
#if 0
    // Verify EUCLIDEAN_DIST response:
    // TODO: Make this protocol agnostic
    uint16_t msg_len = ntohs(packet->lnic->getLnicHeader()->msg_len);
    if (msg_len > 16) {
      uint64_t *resp = (uint64_t *)packet->app->getLayerPayload();
      uint64_t closest_vector_id = be64toh(*resp);
      fprintf(stdout, "<<<<<<<< %ld closest vector: %ld\n", 1, closest_vector_id);
    }
#endif
#if 0
    // Verify INTERSECT response:
    // TODO: Make this protocol agnostic
    uint16_t msg_len = ntohs(packet->lnic->getLnicHeader()->msg_len);
    if (msg_len > 16) {
      struct resp_intersect_hdr_t *resp = (struct resp_intersect_hdr_t *)packet->app->getLayerPayload();
      uint64_t doc_cnt = be64toh(resp->doc_cnt);
      uint64_t d0 = be64toh(resp->doc_ids[0]);
      uint64_t d1 = be64toh(resp->doc_ids[1]);
      fprintf(stdout, "<<<<<<<< %ld docs: ", doc_cnt);
      for (unsigned i = 0; i < doc_cnt; i++)
        fprintf(stdout, "%ld ", be64toh(resp->doc_ids[i]));
      fprintf(stdout, "\n");
    }
#endif
#if 0
    // Verify MICA READ response:
    // TODO: Make this protocol agnostic
    uint16_t msg_len = ntohs(packet->lnic->getLnicHeader()->msg_len);
    if (msg_len > 60) {
      uint64_t *msg_value = (uint64_t *)packet->app->getLayerPayload();
      uint64_t w0 = be64toh(msg_value[0]);
      uint64_t w1 = be64toh(msg_value[1]);
      uint64_t w2 = be64toh(msg_value[2]);
      fprintf(stdout, "GOT VALUE: 0x%lx 0x%lx 0x%lx\n", w0, w1, w2);
    }
#endif
#if 0
    // Verify classification response:
    // TODO: Make this protocol agnostic
    uint16_t msg_len = ntohs(packet->lnic->getLnicHeader()->msg_len);
    if (msg_len > 32) {
      struct classification_hdr_t *h = (struct classification_hdr_t *)packet->app->getLayerPayload();
      uint32_t trace_idx = be32toh(h->trace_idx);
      int32_t match_priority = (int32_t)be32toh(h->match_priority);
      if (trace_idx < num_trace_packets) {
        if (match_priority != trace_packets[trace_idx].match_priority)
          fprintf(stdout, "WARNING: packet %u matched priority %d (should be %d)\n", trace_idx, match_priority, trace_packets[trace_idx].match_priority);
        else fprintf(stdout, "CORRECT MATCH: packet %u matched priority %u\n", trace_idx, match_priority);
      } else
        fprintf(stdout, "ERROR: invalid trace idx: %u (match_priority: %d)\n", trace_idx, match_priority);
    }
#endif
}

void find_raft_leader(parsed_packet_t* packet) {
    // TODO: Make this protocol agnostic
    uint16_t msg_len = ntohs(packet->lnic->getLnicHeader()->msg_len);
    fprintf(stdout, "Finding raft leader recv message with length %d\n", msg_len);
    if (msg_len != sizeof(raft_resp_t) + 2*sizeof(uint64_t)) {
        // Dump anything other than raft response packets
        return;
    }
    raft_resp_t* resp_msg = (raft_resp_t*)packet->app->getLayerPayload();
    uint64_t* msg_words = (uint64_t*)resp_msg;
    fprintf(stdout, "%#lx, %#lx, %#lx, %#lx\n", msg_words[0], msg_words[1]);
    if (be16toh(resp_msg->msg_id) != 5) {
        fprintf(stdout, "While finding leader, unknown msg type id %d\n", be16toh(resp_msg->msg_id));
        // Dump anything other than ReqType::kClientReqResponse messages
        return;
    }
    uint32_t resp_type = be32toh(resp_msg->resp_type);
    fprintf(stdout, "While finding leader, resp type is %d\n", resp_type);
    if (resp_type == 0) {
        // Raft leader has been found
        global_raft_leader_found = true;
        global_raft_leader_ip = resp_msg->leader_ip;
    } else if (resp_type == 1) {
        // Leader redirection
        global_raft_leader_ip = resp_msg->leader_ip;
    } else if (resp_type == 2) {
        // Unknown leader, do nothing
        return;
    } else {

    }
}

void send_done_packet(); // function prototype -- implemented below ...

void update_load() {
    // We've sent and received all required requests for the current load.
    // OR we've timed out and some requests were dropped.
    // Check if we are done or if we should move to the next load.
    if (request_rate_lambda_inverse <= request_rate_lambda_inverse_stop) {
        load_generator_complete = true;
        fprintf(stdout, "---- Load Generator Complete! ----\n");
        send_done_packet();
    } else {
        // Move to the next load
        // Update the load generation distribution
        // Reduce request_rate_lambda_inverse by request_rate_lambda_inverse_dec %
        request_rate_lambda_inverse -= request_rate_lambda_inverse_dec;
//        request_rate_lambda_inverse = request_rate_lambda_inverse * ((double)request_rate_lambda_inverse_dec/100);
        double request_rate_lambda = 1.0 / (double)request_rate_lambda_inverse;
        std::exponential_distribution<double>::param_type new_lambda(request_rate_lambda);
        gen_dist->param(new_lambda);
        // Reset accounting state
        tx_request_count = 0;
        rx_request_count = 0;
        request_tx_done = false;
        fprintf(stdout, "---- New Avg Arrival Time: %ld ----\n", request_rate_lambda_inverse);
    }
}

void check_request_timeout() {
    // It's possible that the DUT dropped some requests so we will never receive all the responses.
    // In this case, we need to timeout and move onto the next load.
    // NOTE: if we timeout too early then we will receive too many responses in the next iteration ...
    uint64_t timeout_cycles = get_avg_service_time() * num_requests * 2;
    if (!load_generator_complete && request_tx_done && (this_iter_cycles_start >= request_tx_done_time + timeout_cycles)) {
        fprintf(stdout, "---- Timeout! Not all responses received! ----\n");
        update_load();
    }
}

bool should_generate_packet_this_cycle() {
    if (!start_message_received || (tx_request_count >= num_requests)) {
        return false;
    }
    if (this_iter_cycles_start >= next_threshold) {
        // compute when the next request should be sent
        if (strcmp(request_dist_type, "FIXED") == 0) {
            next_threshold = this_iter_cycles_start + request_rate_lambda_inverse;
        } else if (strcmp(request_dist_type, "EXP") == 0) {
            next_threshold = this_iter_cycles_start + (uint64_t)(*gen_dist)(*gen_rand);
        } else {
            fprintf(stdout, "Unknown distribution type: %s\n", service_dist_type);
            exit(-1);
        }
        return true;
    }
    return false;
}

uint64_t get_service_time(int &dist) {
    if (strcmp(service_dist_type, "FIXED") == 0) {
        dist = 0;
        return fixed_dist_cycles;
    } else if (strcmp(service_dist_type, "EXP") == 0) {
        double exp_value = exp_dist_scale_factor * (*service_exp_dist)(*dist_rand);
        dist = 0;
        return std::min(std::max((uint64_t)exp_value, min_service_time), max_service_time);
    } else if (strcmp(service_dist_type, "BIMODAL") == 0) {
        double service_low = (*service_normal_low)(*dist_rand);
        double service_high = (*service_normal_high)(*dist_rand);
        int select_high = (*service_select_dist)(*dist_rand);
        if (select_high) {
            dist = 1;
            return std::min(std::max((uint64_t)service_high, min_service_time), max_service_time);
        } else {
            dist = 0;
            return std::min(std::max((uint64_t)service_low, min_service_time), max_service_time);
        }
    } else {
        fprintf(stdout, "Unknown distribution type: %s\n", service_dist_type);
        exit(-1);
    }

}

uint64_t get_service_key(int context_id) {
  return (max_service_key * context_id) + (*service_key_uniform_dist)(*dist_rand);
}

uint16_t get_next_tx_msg_id() {
    uint16_t to_return = global_tx_msg_id;
    global_tx_msg_id++;
    if (global_tx_msg_id == MAX_TX_MSG_ID) {
        global_tx_msg_id = 0;
    }
    return to_return;
}

void send_load_packet(uint16_t dst_context, uint64_t service_time, uint64_t sent_time, bool log_request) {
    // Build the new ethernet/ip packet layers
    pcpp::EthLayer new_eth_layer(pcpp::MacAddress(LOAD_GEN_MAC), pcpp::MacAddress(NIC_MAC));
    pcpp::IPv4Layer new_ip_layer(pcpp::IPv4Address(std::string(LOAD_GEN_IP)), pcpp::IPv4Address(std::string(NIC_IP)));
    new_ip_layer.getIPv4Header()->ipId = htons(1);
    new_ip_layer.getIPv4Header()->timeToLive = 64;
    // TODO: Make this protocol agnostic
    new_ip_layer.getIPv4Header()->protocol = pcpp::IPProtocolTypes::PACKETPP_IPPROTO_LNIC; // Protocol code for LNIC

    uint16_t tx_msg_id = get_next_tx_msg_id();

    // Build the new lnic and application packet layers
    // TODO: Make this protocol agnostic
    pcpp::LnicLayer new_lnic_layer(0, 0, 0, 0, 0, 0, 0, 0, 0);
    new_lnic_layer.getLnicHeader()->flags = (uint8_t)LNIC_DATA_FLAG_MASK;
    new_lnic_layer.getLnicHeader()->src_context = htons(0);
    new_lnic_layer.getLnicHeader()->dst_context = htons(dst_context);
    new_lnic_layer.getLnicHeader()->tx_msg_id = htons(tx_msg_id);
    pcpp::AppLayer new_app_layer(service_time, sent_time);

    if (is_raft) {
        new_ip_layer.getIPv4Header()->ipDst = be32toh(raft_client_ip);
        uint64_t service_time_ip = (uint64_t)global_raft_leader_ip << 32;
        new_app_layer.getAppHeader()->service_time = service_time_ip;
    }

    uint16_t msg_len = new_app_layer.getHeaderLen();
    pcpp::PayloadLayer new_payload_layer(0, 0, false);

    if (strcmp(load_type, "MICA") == 0) {
      struct mica_hdr_t mica_hdr;
      uint16_t mica_hdr_size;
      uint64_t host_endian_key[MICA_VALUE_SIZE_WORDS];
      host_endian_key[0] = get_service_key(dst_context);
      host_endian_key[1] = 0x0;
      mica_hdr.key[0] = htobe64(host_endian_key[0]);
      mica_hdr.key[1] = htobe64(host_endian_key[1]);
      mica_hdr.key_hash = htobe64(cityhash(host_endian_key));
      if (tx_msg_id % 2 == 0) {
        mica_hdr.op_type = htobe64(MICA_W_TYPE);
        mica_hdr.value[0] = htobe64(host_endian_key[0]);
        mica_hdr.value[1] = htobe64(host_endian_key[0]+1);
        mica_hdr.value[2] = htobe64(host_endian_key[0]+2);
        mica_hdr_size = sizeof(mica_hdr);
      }
      else {
        mica_hdr.op_type = htobe64(MICA_R_TYPE);
        mica_hdr_size = sizeof(mica_hdr) - sizeof(mica_hdr.value);
      }
      new_payload_layer = pcpp::PayloadLayer((uint8_t*)&mica_hdr, mica_hdr_size, false);
      msg_len += new_payload_layer.getHeaderLen();
    }
    else if (strcmp(load_type, "CLASSIFICATION") == 0) {
      struct classification_hdr_t class_hdr;
      uint32_t trace_idx = next_trace_idx;
      next_trace_idx = (next_trace_idx + 1) % num_trace_packets;
      const uint32_t *trace_headers = trace_packets[trace_idx].get();
      class_hdr.trace_idx = htobe32(trace_idx);
      class_hdr.match_priority = 0;
      for (int i = 0; i < CLASSIFICATION_HEADER_WORDS; i++)
        class_hdr.headers[i] = htobe64(*(uint64_t*)&trace_headers[i*2]);
      new_payload_layer = pcpp::PayloadLayer((uint8_t*)&class_hdr, sizeof(class_hdr), false);
      msg_len += new_payload_layer.getHeaderLen();
    }
    else if (strcmp(load_type, "CHAINREP") == 0) {
      struct chainrep_w_hdr_t w_hdr;
#define CHAINREP_CLIENT_IP 0x0a000002
#define CHAINREP_NODE1_IP  0x0a000003
// send requests directly to the chain, without the proxy client:
//#define CHAINREP_CLIENT_IP 0x0a000001
//#define CHAINREP_NODE1_IP  0x0a000002
      uint32_t node_ips[] = {CHAINREP_NODE1_IP+0, CHAINREP_NODE1_IP+1, CHAINREP_NODE1_IP+2};
      uint8_t node_ctxs[] = {0, 0, 0};
      w_hdr.flags = CHAINREP_FLAGS_OP_WRITE;
      w_hdr.seq = 0;
      w_hdr.node_cnt = CHAINREP_CHAIN_SIZE - 1;
      w_hdr.client_ctx = 0;
      w_hdr.client_ip = htobe32(CHAINREP_CLIENT_IP);
      for (unsigned i = 1; i < CHAINREP_CHAIN_SIZE; i++)
        w_hdr.nodes[i-1] = htobe64(((uint64_t)node_ctxs[i] << 32) | node_ips[i]);
      uint64_t host_endian_key[MICA_VALUE_SIZE_WORDS];
      host_endian_key[0] = get_service_key(dst_context);
      host_endian_key[1] = 0x0;
      w_hdr.key[0] = htobe64(host_endian_key[0]);
      w_hdr.key[1] = htobe64(host_endian_key[1]);
      w_hdr.key_hash = htobe64(cityhash(host_endian_key));
      w_hdr.value[0] = htobe64(host_endian_key[0]);
      w_hdr.value[1] = htobe64(host_endian_key[0]+1);
      w_hdr.value[2] = htobe64(host_endian_key[0]+2);
      new_payload_layer = pcpp::PayloadLayer((uint8_t*)&w_hdr, sizeof(w_hdr), false);
      msg_len += new_payload_layer.getHeaderLen();
    }
    else if (strcmp(load_type, "CHAINREP_READ") == 0) {
      struct chainrep_r_hdr_t r_hdr;
      r_hdr.flags = CHAINREP_FLAGS_OP_READ;
      r_hdr.seq = 0;
      r_hdr.node_cnt = 0;
      r_hdr.client_ctx = 0;
      r_hdr.client_ip = htobe32(CHAINREP_CLIENT_IP);
      r_hdr.key[0] = htobe64(get_service_key(dst_context));
      r_hdr.key[1] = htobe64(0x0);
      new_payload_layer = pcpp::PayloadLayer((uint8_t*)&r_hdr, sizeof(r_hdr), false);
      msg_len += new_payload_layer.getHeaderLen();
    } else if (strcmp(load_type, "INTERSECT") == 0) {
      struct intersect_hdr_t h;
      uint64_t word_cnt = 1 + ((*service_key_uniform_dist)(*dist_rand) % 4);
      std::set<uint64_t> word_ids;
      while (word_ids.size() != word_cnt)
        word_ids.insert((*service_key_zipf_dist)(*dist_rand_gen));
      h.query_word_cnt = htobe64(word_cnt);
      fprintf(stdout, ">>>>>>>> %ld words: ", word_cnt);
      unsigned i = 0;
      for (uint64_t word_id : word_ids) {
        fprintf(stdout, "%ld ", word_id);
        h.query_word_ids[i++] = htobe64(word_id);
      }
      fprintf(stdout, "\n");
      new_payload_layer = pcpp::PayloadLayer((uint8_t*)&h, 8 + word_cnt*8, false);
      msg_len += new_payload_layer.getHeaderLen();
    } else if (strcmp(load_type, "EUCLIDEAN_DIST") == 0) {
      struct euclidean_dist_hdr_t h;
      uint64_t haystack_vector_cnt = 2 + ((*service_key_uniform_dist)(*dist_rand) % 4);
      std::set<uint64_t> vector_ids;
      while (vector_ids.size() != haystack_vector_cnt)
        vector_ids.insert((*service_key_uniform_dist)(*dist_rand));
      memset(h.query_vector, 1, sizeof(h.query_vector));
      h.haystack_vector_cnt = htobe64(haystack_vector_cnt);
      fprintf(stdout, ">>>>>>>> %ld vectors: ", haystack_vector_cnt);
      unsigned i = 0;
      for (uint64_t vector_id : vector_ids) {
        fprintf(stdout, "%ld ", vector_id);
        h.haystack_vector_ids[i++] = htobe64(vector_id);
      }
      fprintf(stdout, "\n");
      unsigned payload_size = EUCLIDEAN_DIST_VECTOR_SIZE*sizeof(uint16_t) + 8 + haystack_vector_cnt*8;
      new_payload_layer = pcpp::PayloadLayer((uint8_t*)&h, payload_size, false);
      msg_len += new_payload_layer.getHeaderLen();
    } else if (strcmp(load_type, "RAFT_WRITE") == 0) {
        struct raft_req_header_t raft_req_hdr;
        uint64_t rand_key = (*service_key_uniform_dist)(*dist_rand);
        raft_req_hdr.msg_id = htobe16(2); // Raft ReqType::kClientReq
        raft_req_hdr.key[0] = htobe64(rand_key);
        raft_req_hdr.value[0] = htobe64(rand_key); // TODO: Check that this is the right endianness
        fprintf(stdout, "raft req header is %#lx\n", *(uint64_t*)&raft_req_hdr);
        new_payload_layer = pcpp::PayloadLayer((uint8_t*)&raft_req_hdr, sizeof(raft_req_header_t), false);
        msg_len += new_payload_layer.getHeaderLen();
        fprintf(stdout, "Raw dst ip is %#lx\n", new_ip_layer.getIPv4Header()->ipDst);
    } else if (strcmp(load_type, "RAFT_READ") == 0) {
        
    }

    // TODO: Make this protocol agnostic
    new_lnic_layer.getLnicHeader()->msg_len = htons(msg_len);

    // Join the layers into a new packet
    // TODO: Make this protocol agnostic
    uint64_t data_packet_size_bytes = ETHER_HEADER_SIZE + IP_HEADER_SIZE + LNIC_HEADER_SIZE + msg_len;
    pcpp::Packet new_packet(data_packet_size_bytes);
    new_packet.addLayer(&new_eth_layer);
    new_packet.addLayer(&new_ip_layer);
    // TODO: Make this protocol agnostic
    new_packet.addLayer(&new_lnic_layer);
    new_packet.addLayer(&new_app_layer);
    if (strcmp(load_type, "MICA") == 0 ||
        strcmp(load_type, "CLASSIFICATION") == 0 ||
        strcmp(load_type, "CHAINREP") == 0 ||
        strcmp(load_type, "CHAINREP_READ") == 0 ||
        strcmp(load_type, "INTERSECT") == 0 ||
        strcmp(load_type, "EUCLIDEAN_DIST") == 0 ||
        strcmp(load_type, "RAFT_WRITE") == 0 ||
        strcmp(load_type, "RAFT_READ") == 0
        )
      new_packet.addLayer(&new_payload_layer);

    new_packet.computeCalculateFields();

    // Convert the packet to a switchpacket
    switchpacket* new_tsp = (switchpacket*)calloc(sizeof(switchpacket), 1);
    new_tsp->timestamp = this_iter_cycles_start;
    new_tsp->amtwritten = data_packet_size_bytes / sizeof(uint64_t);
    new_tsp->amtread = 0;
    new_tsp->sender = 0;
    memcpy(new_tsp->dat, new_packet.getRawPacket()->getRawData(), data_packet_size_bytes);

    // Verify and log the switchpacket
    // TODO: For now we only work with port 0.
    parsed_packet_t sent_packet;
    if (!sent_packet.parse(new_tsp)) {
        fprintf(stdout, "Invalid generated packet.\n");
        free(new_tsp);
        return;
    }
#ifdef LOG_ALL_PACKETS
    print_packet("LOAD", &sent_packet);
#endif
    int flit_offset_doublebytes = (ETHER_HEADER_SIZE + IP_DST_FIELD_OFFSET + IP_SUBNET_OFFSET) / sizeof(uint16_t);
    uint16_t switching_flit = ((uint16_t*)new_tsp->dat)[flit_offset_doublebytes];
    uint16_t send_to_port = get_port_from_flit(switching_flit, 0);
    send_with_priority(send_to_port, new_tsp);
    tx_request_count++;
    if (log_request) {
      fprintf(stdout, "&&CSV&&RequestStats,%ld,%ld,%d,%f,%ld\n",
        sent_time, service_time, dst_context, get_avg_service_time(), request_rate_lambda_inverse);
    }
    // check if we are done sending requests
    if (tx_request_count >= num_requests) {
        request_tx_done = true;
        request_tx_done_time = sent_time;
    }
}

void send_done_packet() {
  uint16_t dst_context = 0;
  uint64_t service_time = 0;
  uint64_t sent_time = this_iter_cycles_start;
  send_load_packet(dst_context, service_time, sent_time, false);
}

// Returns true if this packet is for the load generator, otherwise returns
// false, indicating that the switch should process the packet as usual
bool load_gen_hook(switchpacket* tsp) {
    // Parse and log the incoming packet
    parsed_packet_t packet;
    bool is_valid = packet.parse(tsp);
    if (!is_valid) {
        fprintf(stdout, "Invalid received packet.\n");
        return false;
    }
    // Ignore packets that aren't for the load generator:
    if (packet.ip->getDstIpAddress() != pcpp::IPv4Address(std::string(LOAD_GEN_IP))) {
#ifdef LOG_ALL_PACKETS
    print_packet("FWD", &packet);
#endif
      return false;
    }
#ifdef LOG_ALL_PACKETS
    print_packet("RECV", &packet);
#endif
    // Send ACK+PULL responses to DATA packets
    // TODO: This only works for one-packet messages for now
    // TODO: Make this protocol agnostic
    if (packet.lnic->getLnicHeader()->flags & LNIC_DATA_FLAG_MASK) {
        // Calculate the ACK+PULL values
        pcpp::lnichdr* lnic_hdr = packet.lnic->getLnicHeader();
        uint16_t pull_offset = lnic_hdr->pkt_offset + rtt_pkts;
        uint8_t flags = LNIC_ACK_FLAG_MASK | LNIC_PULL_FLAG_MASK;
        uint64_t ack_packet_size_bytes = ETHER_HEADER_SIZE + IP_HEADER_SIZE + LNIC_HEADER_SIZE + APP_HEADER_SIZE;

        // Build the new packet layers
        pcpp::EthLayer new_eth_layer(packet.eth->getDestMac(), packet.eth->getSourceMac());
        pcpp::IPv4Layer new_ip_layer(packet.ip->getDstIpAddress(), packet.ip->getSrcIpAddress());
        new_ip_layer.getIPv4Header()->ipId = htons(1);
        new_ip_layer.getIPv4Header()->timeToLive = 64;
        // TODO: Make this protocol agnostic
        new_ip_layer.getIPv4Header()->protocol = pcpp::IPProtocolTypes::PACKETPP_IPPROTO_LNIC; // Protocol code for LNIC
        pcpp::LnicLayer new_lnic_layer(flags, ntohs(lnic_hdr->dst_context), ntohs(lnic_hdr->src_context),
                                       ntohs(lnic_hdr->msg_len), lnic_hdr->pkt_offset, pull_offset,
                                       ntohs(lnic_hdr->tx_msg_id), ntohs(lnic_hdr->buf_ptr), lnic_hdr->buf_size_class);
        pcpp::AppLayer new_app_layer(0, 0);

        // Join the layers into a new packet
        pcpp::Packet new_packet(ack_packet_size_bytes);
        new_packet.addLayer(&new_eth_layer);
        new_packet.addLayer(&new_ip_layer);
        // TODO: Make this protocol agnostic
        new_packet.addLayer(&new_lnic_layer);
        new_packet.addLayer(&new_app_layer);
        new_packet.computeCalculateFields();

        // Convert the packet to a switchpacket
        switchpacket* new_tsp = (switchpacket*)calloc(sizeof(switchpacket), 1);
        new_tsp->timestamp = tsp->timestamp;
        new_tsp->amtwritten = ack_packet_size_bytes / sizeof(uint64_t);
        new_tsp->amtread = 0;
        new_tsp->sender = 0;
        memcpy(new_tsp->dat, new_packet.getRawPacket()->getRawData(), ack_packet_size_bytes);

        // Verify and log the switchpacket
        parsed_packet_t sent_packet;
        if (!sent_packet.parse(new_tsp)) {
            fprintf(stdout, "Invalid sent packet.\n");
            free(new_tsp);
            return true;
        }
#ifdef LOG_ALL_PACKETS
        print_packet("SEND", &sent_packet);
#endif
        send_with_priority(tsp->sender, new_tsp);

        // Check for nanoPU startup messages
        if (!start_message_received) {
            if(count_start_message()) {
                start_message_received = true;
                fprintf(stdout, "---- All Start Msgs Received! ---\n");
            }
        } else if (is_raft && !global_raft_leader_found) {
            // If this is a raft test, we need to find the raft leader first.
            rx_request_count++;
            find_raft_leader(&packet);
        } else {
        // Raft-specific, we might need to send 
            log_packet_response_time(&packet);
            rx_request_count++;
            if (rx_request_count >= num_requests) {
                // All responses received -- move to the next load
                update_load();
            }
        }
    }
    return true;
}

// Figure out which load packets to generate.
// TODO: This should really have an enum instead of a strcmp.
void generate_load_packets() {
    if (!should_generate_packet_this_cycle()) {
        return;
    }
    int dist; // indicates which distribution is selected
    uint64_t service_time = get_service_time(dist);
    uint64_t sent_time = this_iter_cycles_start; // TODO: Check this

    if (strcmp(test_type, "ONE_CONTEXT_ONE_CORE") == 0) {
        send_load_packet(0, service_time, sent_time, true);
    } else if (strcmp(test_type, "ONE_CONTEXT_FOUR_CORES") == 0) {
        send_load_packet(0, service_time, sent_time, true);
    } else if (strcmp(test_type, "FOUR_CONTEXTS_FOUR_CORES") == 0) {
        send_load_packet(rand() % 4, service_time, sent_time, true);
    } else if (strcmp(test_type, "TWO_CONTEXTS_FOUR_SHARED_CORES") == 0) {
        // send request to context 0 if low distribution is selected
        // send request to context 1 if high distribution is selected
        send_load_packet(dist, service_time, sent_time, true);
    } else if ((strcmp(test_type, "DIF_PRIORITY_LNIC_DRIVEN") == 0) ||
               (strcmp(test_type, "DIF_PRIORITY_TIMER_DRIVEN") == 0) ||
               (strcmp(test_type, "HIGH_PRIORITY_C1_STALL") == 0) ||
               (strcmp(test_type, "LOW_PRIORITY_C1_STALL") == 0)) {
        send_load_packet(rand() % 2, service_time, sent_time, true);
    } else {
        fprintf(stdout, "Unknown test type: %s\n", test_type);
        exit(-1);
    }
}

// Load generator specific code end.
#endif

std::string flags_to_string (uint8_t flags, const char* flagNames[], 
                             const std::string delimiter)
{
  std::string flagsDescription = "";
  for (uint8_t i = 0; i < 8; ++i)
    {
      if (flags & (1 << i))
        {
          if (flagsDescription.length () > 0)
            {
              flagsDescription += delimiter;
            }
          flagsDescription.append (flagNames[i]);
        }
    }
  return flagsDescription;
}

void send_with_priority(uint16_t port, switchpacket* tsp) {

    uint64_t packet_size_bytes = tsp->amtwritten * sizeof(uint64_t);
    uint64_t packet_msg_words_offset = (uint64_t)tsp->dat + ETHER_HEADER_SIZE + IP_HEADER_SIZE;

    uint8_t l4_protocol = *((uint8_t*)tsp->dat + ETHER_HEADER_SIZE + IP_PROTOCOL_OFFSET);

    uint8_t l4_header_flags;
    uint64_t l4_pkt_idx_offset;
    uint64_t l4_msg_len_bytes_offset;
    uint64_t l4_src_context_offset;
    uint64_t l4_dst_context_offset;

    if (l4_protocol == pcpp::IPProtocolTypes::PACKETPP_IPPROTO_NDP) { // This is an NDP Packet
        packet_msg_words_offset += NDP_HEADER_SIZE;

        l4_header_flags = *((uint8_t*)tsp->dat + ETHER_HEADER_SIZE + IP_HEADER_SIZE);
        l4_pkt_idx_offset = (uint64_t)tsp->dat + ETHER_HEADER_SIZE + IP_HEADER_SIZE + NDP_HEADER_PKT_IDX_OFFSET;
        l4_src_context_offset = (uint64_t)tsp->dat + ETHER_HEADER_SIZE + IP_HEADER_SIZE + 1;
        l4_dst_context_offset = (uint64_t)tsp->dat + ETHER_HEADER_SIZE + IP_HEADER_SIZE + 3;
        l4_msg_len_bytes_offset = (uint64_t)tsp->dat + ETHER_HEADER_SIZE + IP_HEADER_SIZE + NDP_HEADER_MSG_LEN_OFFSET;
    }
    else if (l4_protocol == pcpp::IPProtocolTypes::PACKETPP_IPPROTO_HOMA) { // This is a Homa Packet
        packet_msg_words_offset += HOMA_HEADER_SIZE;

        l4_header_flags = *((uint8_t*)tsp->dat + ETHER_HEADER_SIZE + IP_HEADER_SIZE);
        l4_pkt_idx_offset = (uint64_t)tsp->dat + ETHER_HEADER_SIZE + IP_HEADER_SIZE + HOMA_HEADER_PKT_IDX_OFFSET;
        l4_src_context_offset = (uint64_t)tsp->dat + ETHER_HEADER_SIZE + IP_HEADER_SIZE + 1;
        l4_dst_context_offset = (uint64_t)tsp->dat + ETHER_HEADER_SIZE + IP_HEADER_SIZE + 3;
        l4_msg_len_bytes_offset = (uint64_t)tsp->dat + ETHER_HEADER_SIZE + IP_HEADER_SIZE + HOMA_HEADER_MSG_LEN_OFFSET;
    }
    else if (l4_protocol == pcpp::IPProtocolTypes::PACKETPP_IPPROTO_LNIC) { // This is an LNIC Packet
        packet_msg_words_offset += LNIC_HEADER_SIZE;

        l4_header_flags = *((uint8_t*)tsp->dat + ETHER_HEADER_SIZE + IP_HEADER_SIZE);
        l4_pkt_idx_offset = (uint64_t)tsp->dat + ETHER_HEADER_SIZE + IP_HEADER_SIZE + LNIC_HEADER_PKT_IDX_OFFSET;
        l4_src_context_offset = (uint64_t)tsp->dat + ETHER_HEADER_SIZE + IP_HEADER_SIZE + 1;
        l4_dst_context_offset = (uint64_t)tsp->dat + ETHER_HEADER_SIZE + IP_HEADER_SIZE + 3;
        l4_msg_len_bytes_offset = (uint64_t)tsp->dat + ETHER_HEADER_SIZE + IP_HEADER_SIZE + LNIC_HEADER_MSG_LEN_OFFSET;
    }
    else { // This is an unknown packet drop it
#ifdef LOG_EVENTS
        fprintf(stdout, "&&CSV&&Events,DroppedUnknown,%ld,%d\n", this_iter_cycles_start, port);
#endif // LOG_EVENTS
        free(tsp);
        return;
    }

    uint64_t* packet_msg_words = (uint64_t*)packet_msg_words_offset;

    uint16_t l4_msg_len_bytes = __builtin_bswap16(*(uint16_t*)l4_msg_len_bytes_offset);
    uint16_t l4_src_context = __builtin_bswap16(*(uint16_t*)l4_src_context_offset);
    uint16_t l4_dst_context = __builtin_bswap16(*(uint16_t*)l4_dst_context_offset);
    uint8_t l4_pkt_idx = (*(uint8_t*)l4_pkt_idx_offset);

#ifdef LOG_ALL_PACKETS
    struct timeval format_time;
    format_time.tv_sec = tsp->timestamp / 1000000000;
    format_time.tv_usec = (tsp->timestamp % 1000000000) / 1000;
    pcpp::RawPacket raw_packet((const uint8_t*)tsp->dat, 200*sizeof(uint64_t), format_time, false, pcpp::LINKTYPE_ETHERNET);
    pcpp::Packet parsed_packet(&raw_packet);
    pcpp::IPv4Layer* ip_layer = parsed_packet.getLayerOfType<pcpp::IPv4Layer>();
    std::string ip_src_addr = ip_layer->getSrcIpAddress().toString();
    std::string ip_dst_addr = ip_layer->getDstIpAddress().toString();

    std::string flags_str;
    std::string l4_protocol_name = "UNKNOWN";
    if (l4_protocol == pcpp::IPProtocolTypes::PACKETPP_IPPROTO_NDP) {
        flags_str = flags_to_string(l4_header_flags, ndpFlagNames, " ");
        l4_protocol_name = "NDP";
    }
    else if (l4_protocol == pcpp::IPProtocolTypes::PACKETPP_IPPROTO_HOMA) {
        flags_str = flags_to_string(l4_header_flags, homaFlagNames, " ");
        l4_protocol_name = "HOMA";
    }
    else if (l4_protocol == pcpp::IPProtocolTypes::PACKETPP_IPPROTO_LNIC) {
        flags_str = flags_to_string(l4_header_flags, lnicFlagNames, " ");
        l4_protocol_name = "LNIC";
    }
    fprintf(stdout, "%ld: IP(src=%s, dst=%s), %s(flags=%s, msg_len=%d, src_context=%d, dst_context=%d, pkt_offset=%d), pkt_len=%d, port=%d\n",
                     tsp->timestamp, ip_src_addr.c_str(), ip_dst_addr.c_str(),
                     l4_protocol_name.c_str(), flags_str.c_str(), l4_msg_len_bytes, l4_src_context, l4_dst_context, 
                     (uint16_t)l4_pkt_idx, packet_size_bytes, port);
#endif // LOG_ALL_PACKETS

    int selectedBand = NUM_BANDS - 1; // By default select the lowest priority band to enqueue, then update it
    if (l4_protocol == pcpp::IPProtocolTypes::PACKETPP_IPPROTO_NDP) {
        if (l4_header_flags & NDP_CHOP_FLAG_MASK)
            selectedBand = 0;
        else if (l4_header_flags & NDP_DATA_FLAG_MASK)
            selectedBand = 1;
        else
            selectedBand = 0;
    }
    else if (l4_protocol == pcpp::IPProtocolTypes::PACKETPP_IPPROTO_LNIC) {
        if (l4_header_flags & LNIC_CHOP_FLAG_MASK)
            selectedBand = 0;
        else if (l4_header_flags & LNIC_DATA_FLAG_MASK)
            selectedBand = 1;
        else
            selectedBand = 0;
    } 
    else if (l4_protocol == pcpp::IPProtocolTypes::PACKETPP_IPPROTO_HOMA) {
        uint8_t tos = *((uint8_t*)tsp->dat + ETHER_HEADER_SIZE + IP_TOS_OFFSET);
        selectedBand = std::min((int)tos, NUM_BANDS);
    }

    int OBUF_SIZE = (selectedBand == 0) ? HIGH_PRIORITY_OBUF_SIZE : LOW_PRIORITY_OBUF_SIZE;

    if (packet_size_bytes + ports[port]->outputqueues_size[selectedBand] < OBUF_SIZE) {
        ports[port]->outputqueues[selectedBand].push(tsp);
        ports[port]->outputqueues_size[selectedBand] += packet_size_bytes;
#if defined(LOG_ALL_PACKETS) && defined(LOG_PKT_TRACE)
    fprintf(stdout, "&&CSV&&PktTrace,%ld,%s,%d,%s,%d,%s,%s,%d,%d\n", 
                    tsp->timestamp, ip_src_addr.c_str(), l4_src_context, 
                    ip_dst_addr.c_str(), l4_dst_context, l4_protocol_name.c_str(), 
                    flags_str.c_str(), l4_msg_len_bytes, l4_pkt_idx);
#endif // LOG_PKT_TRACE
    } else {
#ifdef TRIM_PKTS
        // Try to chop the packet
        int targetBand = selectedBand;
        if (l4_protocol == pcpp::IPProtocolTypes::PACKETPP_IPPROTO_NDP)
            targetBand = 0;
        if (l4_protocol == pcpp::IPProtocolTypes::PACKETPP_IPPROTO_LNIC)
            targetBand = 0;
        else if (l4_protocol == pcpp::IPProtocolTypes::PACKETPP_IPPROTO_HOMA)
            targetBand = std::min(selectedBand+1, NUM_BANDS);
        OBUF_SIZE = (targetBand == 0) ? HIGH_PRIORITY_OBUF_SIZE : LOW_PRIORITY_OBUF_SIZE;

        if (CHOPPED_PKT_SIZE + ports[port]->outputqueues_size[targetBand] < OBUF_SIZE) {
#ifdef LOG_EVENTS
            fprintf(stdout, "&&CSV&&Events,Chopped,%ld,%d\n", this_iter_cycles_start, port);
#endif // LOG_EVENTS
            switchpacket * tsp2 = (switchpacket*)calloc(sizeof(switchpacket), 1);
            tsp2->timestamp = tsp->timestamp;
            tsp2->amtwritten = CHOPPED_PKT_SIZE / sizeof(uint64_t);
            tsp2->amtread = tsp->amtread;
            tsp2->sender = tsp->sender;
            memcpy(tsp2->dat, tsp->dat, CHOPPED_PKT_SIZE);

            if (l4_protocol == pcpp::IPProtocolTypes::PACKETPP_IPPROTO_NDP) {
                uint64_t l4_flag_offset = (uint64_t)tsp2->dat + ETHER_HEADER_SIZE + IP_HEADER_SIZE;
                *(uint8_t*)(l4_flag_offset) |= NDP_CHOP_FLAG_MASK;
            }
            else if (l4_protocol == pcpp::IPProtocolTypes::PACKETPP_IPPROTO_LNIC) {
                uint64_t l4_flag_offset = (uint64_t)tsp2->dat + ETHER_HEADER_SIZE + IP_HEADER_SIZE;
                *(uint8_t*)(l4_flag_offset) |= LNIC_CHOP_FLAG_MASK;
            }
            else if (l4_protocol == pcpp::IPProtocolTypes::PACKETPP_IPPROTO_HOMA) {
                uint64_t l4_flag_offset = (uint64_t)tsp2->dat + ETHER_HEADER_SIZE + IP_HEADER_SIZE;
                *(uint8_t*)(l4_flag_offset) |= HOMA_CHOP_FLAG_MASK;
            }

            free(tsp);
            ports[port]->outputqueues[targetBand].push(tsp2);
            ports[port]->outputqueues_size[targetBand] += CHOPPED_PKT_SIZE;

            } else {
                // TODO: We should really drop the lowest priority packet sometimes, not always the newly arrived packet
#ifdef LOG_EVENTS
                fprintf(stdout, "&&CSV&&Events,DroppedPkt,%ld,%d\n", this_iter_cycles_start, port);
#endif // LOG_EVENTS
                free(tsp);
            }
#else // TRIM_PKTS is not defined
#ifdef LOG_EVENTS
        fprintf(stdout, "&&CSV&&Events,DroppedPkt,%ld,%d\n", this_iter_cycles_start, port);
#endif // LOG_EVENTS
        free(tsp);
#endif // TRIM_PKTS
    }
}

static void simplify_frac(int n, int d, int *nn, int *dd)
{
    int a = n, b = d;

    // compute GCD
    while (b > 0) {
        int t = b;
        b = a % b;
        a = t;
    }

    *nn = n / a;
    *dd = d / a;
}

#ifdef WORDS_BIGENDIAN
#define uint32_in_expected_order(x) (bswap_32(x))
#define uint64_in_expected_order(x) (bswap_64(x))
#else
#define uint32_in_expected_order(x) (x)
#define uint64_in_expected_order(x) (x)
#endif

static uint64_t UNALIGNED_LOAD64(const char *p) {
  uint64_t result;
  memcpy(&result, p, sizeof(result));
  return result;
}

static uint64_t Fetch64(const char *p) {
  return uint64_in_expected_order(UNALIGNED_LOAD64(p));
}

// Bitwise right rotate.  Normally this will compile to a single
// instruction, especially if the shift is a manifest constant.
static uint64_t Rotate(uint64_t val, int shift) {
  // Avoid shifting by 64: doing so yields an undefined result.
  return shift == 0 ? val : ((val >> shift) | (val << (64 - shift)));
}

static inline uint64_t HashLen16(uint64_t u, uint64_t v, uint64_t mul) {
  // Murmur-inspired hashing.
  uint64_t a = (u ^ v) * mul;
  a ^= (a >> 47);
  uint64_t b = (v ^ a) * mul;
  b ^= (b >> 47);
  b *= mul;
  return b;
}
// This was extracted from the cityhash library. It's the codepath for hashing
// 16 byte values.
static inline uint64_t cityhash(const uint64_t *s) {
  static const uint64_t k2 = 0x9ae16a3b2f90404fULL;
  uint64_t mul = k2 + (MICA_KEY_SIZE_WORDS * 8) * 2;
  //uint64_t a = s[0] + k2;
  //uint64_t b = s[1];
  //uint64_t c = rotate(b, 37) * mul + a;
  //uint64_t d = (rotate(a, 25) + b) * mul;
  uint64_t a = Fetch64((char*)s) + k2;
  uint64_t b = Fetch64(((char*)s) + (MICA_KEY_SIZE_WORDS * 8) - 8);
  uint64_t c = Rotate(b, 37) * mul + a;
  uint64_t d = (Rotate(a, 25) + b) * mul;
  return HashLen16(c, d, mul);
}

int main (int argc, char *argv[]) {
    int bandwidth;

    if (argc < 6) {
        // if insufficient args, error out
        fprintf(stdout, "usage: ./switch LINKLATENCY SWITCHLATENCY BANDWIDTH HIGH_PRIORITY_OBUF_SIZE LOW_PRIORITY_OBUF_SIZE\n");
        fprintf(stdout, "insufficient args provided\n.");
        fprintf(stdout, "LINKLATENCY and SWITCHLATENCY should be provided in cycles.\n");
        fprintf(stdout, "BANDWIDTH should be provided in Gbps\n");
        fprintf(stdout, "OBUF SIZES should be provided in bytes.\n");
        exit(1);
    }

    LINKLATENCY = atoi(argv[1]);
    switchlat = atoi(argv[2]);
    bandwidth = atoi(argv[3]);
    HIGH_PRIORITY_OBUF_SIZE = atoi(argv[4]);
    LOW_PRIORITY_OBUF_SIZE = atoi(argv[5]);

#ifdef USE_LOAD_GEN
    request_rate_lambda_inverse = request_rate_lambda_inverse_start;
    double request_rate_lambda = 1.0 / (double)request_rate_lambda_inverse;
    gen_rand = new std::default_random_engine;
    gen_dist = new std::exponential_distribution<double>(request_rate_lambda);
    dist_rand = new std::default_random_engine;
    service_key_uniform_dist = new std::uniform_int_distribution<>(min_service_key, max_service_key);
    service_exp_dist = new std::exponential_distribution<double>(exp_dist_decay_const);
    service_normal_high = new std::normal_distribution<double>(bimodal_dist_high_mean, bimodal_dist_high_stdev);
    service_normal_low = new std::normal_distribution<double>(bimodal_dist_low_mean, bimodal_dist_low_stdev);
    service_select_dist = new std::binomial_distribution<int>(1, bimodal_dist_fraction_high);

    std::random_device rd;
    dist_rand_gen = new std::mt19937(rd());
    service_key_zipf_dist = new zipf_distribution<>(max_service_key);

    if (strcmp(load_type, "RAFT_WRITE") == 0 || strcmp(load_type, "RAFT_READ") == 0) {
        is_raft = true;
        global_raft_leader_ip = be32toh(NIC_IP_BIGENDIAN);
    }
    fprintf(stdout, "---- New Avg Arrival Time: %ld ----\n", request_rate_lambda_inverse);

    if (trace_filename) {
      std::vector<uint32_t> arbitrary_fields;
      trace_packets = read_trace_file(trace_filename, arbitrary_fields, &num_trace_packets);
      if (!trace_packets) {
        fprintf(stderr, "error while reading trace file: %s\n", trace_filename);
        exit(1);
      }
    }
    else {
      // A small trace that's matched by the first 100 rules of acl1_seed_100k
      num_trace_packets = 10;
      trace_packets = new trace_packet[10];
      trace_packets[0].header = {532746804, 3397109384, 43204, 1521,  6, 0}; trace_packets[0].match_priority = 94;
      trace_packets[1].header = {520899175, 3396744005, 33500, 1715,  6, 0}; trace_packets[1].match_priority = 73;
      trace_packets[2].header = {525102834, 3396784787, 26901, 6790,  6, 0}; trace_packets[2].match_priority = 85;
      trace_packets[3].header = {475623671, 3396388276, 10205, 5631,  6, 0}; trace_packets[3].match_priority = 34;
      trace_packets[4].header = {492908153, 3396476695, 11394, 19856, 6, 0}; trace_packets[4].match_priority = 9;
      trace_packets[5].header = {520346879, 3396746798, 14598, 20,    6, 0}; trace_packets[5].match_priority = 76;
      trace_packets[6].header = {496792388, 3396337836, 8702,  1711,  6, 0}; trace_packets[6].match_priority = 26;
      trace_packets[7].header = {533223626, 219940546,  47855, 1705,  6, 0}; trace_packets[7].match_priority = 93;
      trace_packets[8].header = {492908153, 3396476695, 43418, 19856, 6, 0}; trace_packets[8].match_priority = 9;
      trace_packets[9].header = {520382556, 3396746440, 6686,  2121,  6, 0}; trace_packets[9].match_priority = 77;
    }

#endif

    simplify_frac(bandwidth, 200, &throttle_numer, &throttle_denom);

    fprintf(stdout, "Using link latency: %d\n", LINKLATENCY);
    fprintf(stdout, "Using switching latency: %d\n", SWITCHLATENCY);
    fprintf(stdout, "BW throttle set to %d/%d\n", throttle_numer, throttle_denom);
    fprintf(stdout, "High priority obuf size: %d\n", HIGH_PRIORITY_OBUF_SIZE);
    fprintf(stdout, "Low priority obuf size: %d\n", LOW_PRIORITY_OBUF_SIZE);
    fprintf(stdout, "Number of ports on switch: %d\n", NUMPORTS);

    if ((LINKLATENCY % 7) != 0) {
        // if invalid link latency, error out.
        fprintf(stdout, "INVALID LINKLATENCY. Currently must be multiple of 7 cycles.\n");
        exit(1);
    }

    omp_set_num_threads(NUMPORTS); // we parallelize over ports, so max threads = # ports

#define PORTSETUPCONFIG
#include "switchconfig.h"
#undef PORTSETUPCONFIG

#ifdef LOG_QUEUE_SIZE
    // initialize last_qsize_samples
    int n_actual_bands;
    for (int p = 0; p < NUMPORTS; p++) {
        n_actual_bands = ports[p]->get_numBands();
        fprintf(stdout, "Created a port with %d bands\n", n_actual_bands);
        for (int b = 0; b < n_actual_bands; b++) {
            last_qsize_samples[p][b] = 0;
        }
        fprintf(stdout, "&&CSV&&QueueSize,%ld,%d,%d\n", this_iter_cycles_start, p, 0);
    }
#endif


    while (true) {

        // handle sends
#pragma omp parallel for
        for (int port = 0; port < NUMPORTS; port++) {
            ports[port]->send();
        }

        // handle receives. these are blocking per port
#pragma omp parallel for
        for (int port = 0; port < NUMPORTS; port++) {
            ports[port]->recv();
        }
 
#pragma omp parallel for
        for (int port = 0; port < NUMPORTS; port++) {
            ports[port]->tick_pre();
        }

        do_fast_switching();

        this_iter_cycles_start += LINKLATENCY; // keep track of time

        // some ports need to handle extra stuff after each iteration
        // e.g. shmem ports swapping shared buffers
#pragma omp parallel for
        for (int port = 0; port < NUMPORTS; port++) {
            ports[port]->tick();
        }

    }
}
