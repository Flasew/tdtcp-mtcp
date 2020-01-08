#ifndef TDTCP_H
#define TDTCP_H

/* Header file definition of everything needed in TDTCP
 */

#include "rbtree.h"
#include "tcp_util.h"

#define TDTCP_ENABLED TRUE

#define TDTCP_TX_NSUBFLOWS 2
#define TDTCP_FLOW_RETX_THRESH 10

/**** Mapping */
struct tdtcp_mapping {
  RBTNode rbnode;
  uint32_t ssn;
  uint32_t dsn;
  uint16_t size;
  uint8_t  carrier;
};

// functions used for RBTree management
int tdtcp_mapping_comp(const RBTNode *a, const RBTNode *b, void *arg);
void tdtcp_mapping_comb (RBTNode *existing, const RBTNode *newdata, void *arg);
RBTNode * tdtcp_mapping_alloc (void *arg);
void tdtcp_mapping_free (RBTNode *x, void *arg);

/**** Option */
#define TCP_OPT_TDTCP 123
#define TD_CAPABLE 0
#define TD_DSS     1
#define TCP_OPT_TDCAPABLE_LEN 4
#define TCP_OPT_TDDSS_LEN 16

// Bit-fields position 
#define TDTCP_ACK  1
#define TDTCP_DATA 2

struct tdtcp_option_capable {
  uint8_t kind;
  uint8_t length;
#if BYTE_ORDER == LITTLE_ENDIAN 
  uint8_t unused:4,       
          subtype:4;        
#endif
#if BYTE_ORDER == BIG_ENDIAN 
  uint8_t subtype:4,        
          unused:4;       
#endif
  uint8_t nsubflows;
};

struct tdtcp_option_tddss {
  uint8_t kind;
  uint8_t length;
#if BYTE_ORDER == LITTLE_ENDIAN 
  uint8_t hasack:1,
          hasdata:1,
          unused:2,     
          subtype:4;        
#endif
#if BYTE_ORDER == BIG_ENDIAN 
  uint8_t subtype:4,        
          hasack:1,
          hasdata:1,
          unused:2;    
#endif
  uint8_t dsubflow;
  uint8_t dcarrier;
  uint8_t asubflow;
  uint8_t acarrier;

  uint32_t subseq;
  uint32_t suback;
};

/**** Rx */

typedef struct tdtcp_rxsubflow tdtcp_rxsubflow;
struct tdtcp_rxsubflow {
  uint8_t subflow_id;
  /* receiver variables */
  uint32_t rcv_wnd;   /* receive window (unscaled) */
  //uint32_t rcv_up;    /* receive urgent pointer */
  uint32_t irs;     /* initial receiving sequence */
  uint32_t snd_wl1;   /* segment seq number for last window update */
  uint32_t snd_wl2;   /* segment ack number for last window update */
  uint32_t rcv_nxt;

  /* variables for fast retransmission */
  uint8_t dup_acks;   /* number of duplicated acks */
  uint32_t last_ack_seq;  /* highest ackd seq */

  uint8_t is_wack:1,      /* is ack for window adertisement? */
    ack_cnt:6;      /* number of acks to send. max 64 */
  
  // /* timestamps */
  // uint32_t ts_recent;     /* recent peer timestamp */
  // uint32_t ts_lastack_rcvd; /* last ack rcvd time */
  // uint32_t ts_last_ts_upd;  /* last peer ts update time */
  // uint32_t ts_tw_expire;  // timestamp for timewait expire

  // /* RTT estimation variables */
  // uint32_t srtt;      /* smoothed round trip time << 3 (scaled) */
  // uint32_t mdev;      /* medium deviation */
  // uint32_t mdev_max;    /* maximal mdev ffor the last rtt period */
  // uint32_t rttvar;    /* smoothed mdev_max */
  // uint32_t rtt_seq;   /* sequence number to update rttvar */

  uint8_t on_ack_list;
  uint8_t on_ackq;

  TAILQ_ENTRY(tdtcp_rxsubflow) ack_link;

  struct tcp_ring_buffer *rcvbuf;
  tcp_stream *meta;

  RBTree * rxmappings;

// #if USE_SPIN_LOCK
//   pthread_spinlock_t read_lock;
// #else
//   pthread_mutex_t read_lock;
// #endif

};

struct tdtcp_recv_vars * tdtcp_new_rxsubflow(int id, struct tcp_recv_vars *meta);
void tdtcp_rxsubflow_receive ();
uint8_t * extract_one_mapping();

/**** Tx */

typedef struct tdtcp_txsubflow tdtcp_txsubflow;
struct tdtcp_txsubflow {

  uint8_t subflow_id;
  /* IP-level information */
  uint16_t mss;     /* maximum segment size */
  uint16_t eff_mss;   /* effective segment size (excluding tcp option) */

  /* send sequence variables */
  uint32_t snd_una;   /* send unacknoledged */
  uint32_t snd_wnd;   /* send window (unscaled) */
  uint32_t peer_wnd;    /* client window size */
  //uint32_t snd_up;    /* send urgent pointer (not used) */
  uint32_t iss;     /* initial sending sequence */
  uint32_t fss;     /* final sending sequence */

  uint32_t snd_wl1;   /* segment seq number for last window update */
  uint32_t snd_wl2;   /* segment ack number for last window update */

    /* timestamps */
  uint32_t ts_recent;     /* recent peer timestamp */
  uint32_t ts_lastack_rcvd; /* last ack rcvd time */
  uint32_t ts_last_ts_upd;  /* last peer ts update time */
  uint32_t ts_tw_expire;  // timestamp for timewait expire

  /* RTT estimation variables */
  uint32_t srtt;      /* smoothed round trip time << 3 (scaled) */
  uint32_t mdev;      /* medium deviation */
  uint32_t mdev_max;    /* maximal mdev ffor the last rtt period */
  uint32_t rttvar;    /* smoothed mdev_max */
  uint32_t rtt_seq;   /* sequence number to update rttvar */

  /* variables for fast retransmission */
  uint8_t dup_acks;   /* number of duplicated acks */
  uint32_t last_ack_seq;  /* highest ackd seq */

  uint8_t saw_timestamp;
  // uint32_t high_tx; /* highest TX sequence number */

  /* retransmission timeout variables */
  uint8_t nrtx;     /* number of retransmission */
  uint8_t max_nrtx;   /* max number of retransmission */
  uint32_t rto;     /* retransmission timeout */
  uint32_t ts_rto;    /* timestamp for retransmission timeout */

  /* congestion control variables */
  uint32_t cwnd;        /* congestion window */
  uint32_t ssthresh;      /* slow start threshold */

  uint32_t snd_nxt;

  /* timestamp */
  uint32_t ts_lastack_sent; /* last ack sent time */

  uint8_t on_control_list;
  uint8_t on_send_list;
  uint8_t on_retransmit_list;
  // uint8_t on_sendq;
  // uint8_t on_closeq;
  // uint8_t on_resetq;

  uint8_t on_closeq_int:1, 
      on_resetq_int:1, 
      is_fin_sent:1, 
      is_fin_ackd:1;

  // TAILQ_ENTRY(tcp_stream) control_link;
  // TAILQ_ENTRY(tcp_stream) send_link;

  TAILQ_ENTRY(tdtcp_txsubflow) retransmit_link;

  // TAILQ_ENTRY(tcp_stream) timer_link;   /* timer link (rto list, tw list) */
  // TAILQ_ENTRY(tcp_stream) timeout_link; /* connection timeout link */

  struct tcp_send_buffer *sndbuf;
  tcp_stream *meta;

  RBTree * txmappings;

  uint8_t paced;
  struct packet_pacer *pacer;

// #if USE_SPIN_LOCK
//   pthread_spinlock_t write_lock;
// #else
//   pthread_mutex_t write_lock;
// #endif

// #if BLOCKING_SUPPORT
//   TAILQ_ENTRY(tcp_stream) snd_br_link;
//   pthread_cond_t write_cond;
// #endif

};

/**** Connection level */
struct tdtcp_seq2subflow_map {
  RBTNode node;
  uint32_t dsn;
  uint8_t subflow_id;
};

int tdtcp_seq2subflow_comp(const RBTNode *a, const RBTNode *b, void *arg);
void tdtcp_seq2subflow_comb(RBTNode *existing, const RBTNode *newdata, void *arg);
RBTNode * tdtcp_seq2subflow_alloc(void *arg);
void tdtcp_seq2subflow_free(RBTNode *x, void *arg);

struct tdtcp_xretrans_map {
  RBTNode node;
  uint32_t dsn;
  uint16_t subflow_sz[TDTCP_TX_NSUBFLOWS];
};

int tdtcp_xretrans_comp(const RBTNode *a, const RBTNode *b, void *arg);
void tdtcp_xretrans_comb(RBTNode *existing, const RBTNode *newdata, void *arg);
RBTNode * tdtcp_xretrans_alloc(void *arg);
void tdtcp_xretrans_free(RBTNode *x, void *arg);

inline void ProcessACKSubflow(mtcp_manager_t mtcp, tcp_stream *cur_stream,
  uint32_t cur_ts, uint8_t *tcph);
inline void EstimateRTTSubflow(mtcp_manager_t mtcp, tdtcp_txsubflow *subflow, 
  uint32_t mrtt);
inline int ProcessTCPPayloadSubflow(mtcp_manager_t mtcp, tcp_stream *cur_stream, 
  uint32_t cur_ts, uint8_t *payload, uint32_t seq, int payloadlen);
int SendTCPDataPacketSubflow(struct mtcp_manager *mtcp, tcp_stream *cur_stream, 
    tdtcp_txsubflow * subflow, struct tdtcp_mapping * mapping,
    uint32_t cur_ts, uint8_t flags, uint8_t *payload, uint16_t payloadlen);
inline int WriteTDTCPRetransList(mtcp_manager_t mtcp, 
  struct mtcp_sender *sender, uint32_t cur_ts, int thresh);
inline int RetransmitPacketTDTCP(mtcp_manager_t mtcp, 
  tdtcp_txsubflow *txsubflow, uint32_t cur_ts);
inline int WriteTCPACKListSubflow(mtcp_manager_t mtcp,
    struct mtcp_sender *sender, uint32_t cur_ts, int thresh);
inline int SendSubflowACK(struct mtcp_manager *mtcp, tcp_stream *cur_stream, 
  tdtcp_rxsubflow * rxsubflow, uint32_t cur_ts);
inline void AddtoACKListSubflow(mtcp_manager_t mtcp, tdtcp_rxsubflow *rxsubflow);
inline void AddtoRetxList(mtcp_manager_t mtcp, tdtcp_txsubflow *txsubflow);
inline void EnqueueACKSubflow(mtcp_manager_t mtcp, tcp_stream *cur_stream, 
  tdtcp_rxsubflow * rxsubflow, uint32_t cur_ts, uint8_t opt);
inline void RemoveFromRetxList(mtcp_manager_t mtcp, tdtcp_txsubflow * tx_subflow);
inline void RemoveFromAckListSubflow(mtcp_manager_t mtcp, tdtcp_rxsubflow * rx_subflow);

void UpdateAdaptivePacingRate(tdtcp_txsubflow * subflow, bool resetEnable);

#endif // TDTCP_H
