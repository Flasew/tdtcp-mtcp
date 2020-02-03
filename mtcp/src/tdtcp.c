#include "timer.h"
#include "ip_out.h"
#include "tcp_in.h"
#include "tcp_out.h"
#include "tcp_stream.h"
#include "tcp_util.h"
#include "rbtree.h"
#include "tdtcp.h"
#include "icmp.h"
#include "debug.h"

#define TCP_MAX_WINDOW 65535
#define MAX(a, b) ((a)>(b)?(a):(b))
#define MIN(a, b) ((a)<(b)?(a):(b))

#define PRINT_CHANGE(x, y) (void)0
#define IP_NEXT_PTR(iph) ((uint8_t *)iph + (iph->ihl << 2))

/* used to be in tcp_in */
inline void
ProcessACKSubflow(mtcp_manager_t mtcp, tcp_stream *cur_stream, 
  uint32_t cur_ts, struct tcphdr *tcph) 
{
  // TRACE_INFO("ProcessACKSubflow\n");

  // PrintTCPHeader((uint8_t*)tcph);

  struct tcp_send_vars *sndvar = cur_stream->sndvar;
  struct tdtcp_option_tddss *tddss = cur_stream->tddss_pass;
  tdtcp_txsubflow *subflow = cur_stream->tx_subflows + tddss->asubflow;
  // uint32_t cwindow, cwindow_prev;
  // uint32_t snd_wnd_prev;
  // uint32_t right_wnd_edge;
  uint32_t ack_seq = ntohl(tddss->suback);

  TRACE_INFO("ack_seq=%u\n", ack_seq);

  uint32_t rmlen;
  uint8_t dup;
  int ret;


#if 0
  if (!tcph->rst && cur_stream->saw_timestamp) {
  // if (!tcph->rst) {
    struct tcp_timestamp ts;
    
    if (!ParseTCPTimestamp(cur_stream, &ts, 
        (uint8_t *)tcph + TCP_HEADER_LEN, 
        (tcph->doff << 2) - TCP_HEADER_LEN)) {
      TRACE_DBG("No timestamp found.\n");
      // return FALSE;
    }

    // Protect against wrapped timestemp: TODO
    /* RFC1323: if SEG.TSval < TS.Recent, drop and send ack */
    // if (TCP_SEQ_LT(ts.ts_val, cur_stream->rcvvar->ts_recent)) {
    //  /* TODO: ts_recent should be invalidated 
    //       before timestamp wraparound for long idle flow */
    //  TRACE_DBG("PAWS Detect wrong timestamp. "
    //      "seq: %u, ts_val: %u, prev: %u\n", 
    //      seq, ts.ts_val, cur_stream->rcvvar->ts_recent);
    //  EnqueueACK(mtcp, cur_stream, cur_ts, ACK_OPT_NOW);
    //  return FALSE;
    // } 
    // else {
      /* valid timestamp */
      if (TCP_SEQ_GT(ts.ts_val, cur_stream->rcvvar->ts_recent)) {
        TRACE_TSTAMP("Timestamp update. cur: %u, prior: %u "
          "(time diff: %uus)\n", 
          ts.ts_val, cur_stream->rcvvar->ts_recent, 
          TS_TO_USEC(cur_ts - cur_stream->rcvvar->ts_last_ts_upd));
        cur_stream->rcvvar->ts_last_ts_upd = cur_ts;
      // }

      cur_stream->rcvvar->ts_recent = ts.ts_val;
      cur_stream->rcvvar->ts_lastack_rcvd = ts.ts_ref;
    }
  }
#endif

  // cwindow = window;
  // if (!tcph->syn) {
  //  cwindow = cwindow << sndvar->wscale_peer;
  // }
  // right_wnd_edge = sndvar->peer_wnd + cur_stream->rcvvar->snd_wl2;

  /* If ack overs the sending buffer, return */
  // if (cur_stream->state == TCP_ST_FIN_WAIT_1 || 
  //    cur_stream->state == TCP_ST_FIN_WAIT_2 ||
  //    cur_stream->state == TCP_ST_CLOSING || 
  //    cur_stream->state == TCP_ST_CLOSE_WAIT || 
  //    cur_stream->state == TCP_ST_LAST_ACK) {
  //  if (sndvar->is_fin_sent && ack_seq == sndvar->fss + 1) {
  //    ack_seq--;
  //  }
  // }
  
  if (TCP_SEQ_GT(ack_seq, subflow->sndbuf->head_seq + subflow->sndbuf->len)) {
    TRACE_INFO("Stream %d subflow %u (%s): invalid acknologement. "
        "ack_seq: %u, possible max_ack_seq: %u\n", cur_stream->id, subflow->subflow_id,
        TCPStateToString(cur_stream), ack_seq, 
        subflow->sndbuf->head_seq + subflow->sndbuf->len);
    return;
  }

  /* Update window */
  //  if (TCP_SEQ_LT(cur_stream->rcvvar->snd_wl1, seq) ||
  //      (cur_stream->rcvvar->snd_wl1 == seq && 
  //      TCP_SEQ_LT(cur_stream->rcvvar->snd_wl2, ack_seq)) ||
  //      (cur_stream->rcvvar->snd_wl2 == ack_seq && 
  //      cwindow > sndvar->peer_wnd)) {
  //    cwindow_prev = sndvar->peer_wnd;
  //    sndvar->peer_wnd = cwindow;
  //    cur_stream->rcvvar->snd_wl1 = seq;
  //    cur_stream->rcvvar->snd_wl2 = ack_seq;
  // #if 0
  //    TRACE_CLWND("Window update. "
  //        "ack: %u, peer_wnd: %u, snd_nxt-snd_una: %u\n", 
  //        ack_seq, cwindow, cur_stream->snd_nxt - sndvar->snd_una);
  // #endif
  //    if (cwindow_prev < cur_stream->snd_nxt - sndvar->snd_una && 
  //        sndvar->peer_wnd >= cur_stream->snd_nxt - sndvar->snd_una) {
  //      TRACE_CLWND("%u Broadcasting client window update! "
  //          "ack_seq: %u, peer_wnd: %u (before: %u), "
  //          "(snd_nxt - snd_una: %u)\n", 
  //          cur_stream->id, ack_seq, sndvar->peer_wnd, cwindow_prev, 
  //          cur_stream->snd_nxt - sndvar->snd_una);
  //      RaiseWriteEvent(mtcp, cur_stream);
  //    }
  //  }

  /* Check duplicated ack count */
  /* Duplicated ack if 
     1) ack_seq is old
     2) payload length is 0.
     3) advertised window not changed.
     4) there is outstanding unacknowledged data
     5) ack_seq == snd_una
   */

  dup = FALSE;
  if (TCP_SEQ_LT(ack_seq, subflow->snd_nxt)) {
    if (ack_seq == subflow->last_ack_seq) {
      // if (subflow->snd_wl2 + sndvar->peer_wnd == right_wnd_edge) {
        if (subflow->dup_acks + 1 > subflow->dup_acks) {
          subflow->dup_acks++;
// #if USE_CCP
//          ccp_record_event(mtcp, cur_stream, EVENT_DUPACK,
//               (cur_stream->snd_nxt - ack_seq));
// #endif
        }
        dup = TRUE;
      // }
    }
  }
  if (!dup) {
// #if USE_CCP
//    if (cur_stream->rcvvar->dup_acks >= 3) {
//      TRACE_DBG("passed dup_acks, ack=%u, snd_nxt=%u, last_ack=%u len=%u wl2=%u peer_wnd=%u right=%u\n",
//          ack_seq-sndvar->iss, cur_stream->snd_nxt-sndvar->iss, cur_stream->rcvvar->last_ack_seq-sndvar->iss,
//          payloadlen, cur_stream->rcvvar->snd_wl2-sndvar->iss, sndvar->peer_wnd / sndvar->mss,
//          right_wnd_edge - sndvar->iss);
//    }
// #endif
    subflow->dup_acks = 0;
    subflow->last_ack_seq = ack_seq;
    RemoveFromRetxList(mtcp, subflow);
    AddtoSendList(mtcp, cur_stream);
  }
// #if USE_CCP
//  if(cur_stream->wait_for_acks) {
//    TRACE_DBG("got ack, but waiting to send... ack=%u, snd_next=%u cwnd=%u\n",
//        ack_seq-sndvar->iss, cur_stream->snd_nxt-sndvar->iss,
//        sndvar->cwnd / sndvar->mss);
//  }
// #endif
  /* Fast retransmission */
  if (dup && subflow->dup_acks == 3) {
    TRACE_LOSS("Triple duplicated ACKs!! ack_seq: %u\n", ack_seq);
    TRACE_CCP("tridup ack %u (%u)!\n", ack_seq - subflow->iss, ack_seq);
    if (TCP_SEQ_LT(ack_seq, subflow->snd_nxt)) {
      TRACE_LOSS("Reducing snd_nxt from %u to %u\n",
                                        subflow->snd_nxt-subflow->iss,
                                        ack_seq - subflow->iss);

#if RTM_STAT
      sndvar->rstat.tdp_ack_cnt++;
      sndvar->rstat.tdp_ack_bytes += (subflow->snd_nxt - ack_seq);
#endif

// #if USE_CCP
//      ccp_record_event(mtcp, subflow, EVENT_TRI_DUPACK, ack_seq);
// #endif
      if (ack_seq != subflow->snd_una) {
        TRACE_INFO("ack_seq and snd_una mismatch on tdp ack. "
            "ack_seq: %u, snd_una: %u\n", 
            ack_seq, subflow->snd_una);
      }
// #if USE_CCP
//      sndvar->missing_seq = ack_seq;
// #else
      subflow->snd_nxt = ack_seq; 
      AddtoRetxList(mtcp, subflow);
      //AddtoSendList(mtcp, subflow);
// #endif
    }

    /* update congestion control variables */
    /* ssthresh to half of min of cwnd and peer wnd */
    subflow->ssthresh = subflow->cwnd / 2;
    if (subflow->ssthresh < 2 * subflow->mss) {
      subflow->ssthresh = 2 * subflow->mss;
    }
    subflow->cwnd = subflow->ssthresh + 3 * subflow->mss;

    TRACE_CONG("fast retrans: cwnd = ssthresh(%u)+3*mss = %u\n",
                                subflow->ssthresh / subflow->mss,
                                subflow->cwnd / subflow->mss);

    /* count number of retransmissions */
    // if (subflow->nrtx < TCP_MAX_RTX) {
    //   subflow->nrtx++;
    // } else {
    //   TRACE_DBG("Exceed MAX_RTX.\n");
    // }


  } else if (subflow->dup_acks > 3) {
    /* Inflate congestion window until before overflow */
    if ((uint32_t)(subflow->cwnd + subflow->mss) > subflow->cwnd) {
      subflow->cwnd += subflow->mss;
      TRACE_CONG("Dupack cwnd inflate. cwnd: %u, ssthresh: %u\n", 
          subflow->cwnd, subflow->ssthresh);
    }
  }
  //AddtoSendList(mtcp, cur_stream);

// #if TCP_OPT_SACK_ENABLED
//  ParseSACKOption(cur_stream, ack_seq, (uint8_t *)tcph + TCP_HEADER_LEN, 
//      (tcph->doff << 2) - TCP_HEADER_LEN);
// #endif /* TCP_OPT_SACK_ENABLED */

// #if RECOVERY_AFTER_LOSS
// #if USE_CCP
//  /* updating snd_nxt (when recovered from loss) */
//  if (TCP_SEQ_GT(ack_seq, cur_stream->snd_nxt) ||
//      (cur_stream->wait_for_acks && TCP_SEQ_GT(ack_seq, cur_stream->seq_at_last_loss)
// #if TCP_OPT_SACK_ENABLED 
//    && cur_stream->rcvvar->sacked_pkts == 0
// #endif
//  ))
// #else
        if (TCP_SEQ_GT(ack_seq, subflow->snd_nxt))
// #endif /* USE_CCP */
  {
#if RTM_STAT
    sndvar->rstat.ack_upd_cnt++;
    sndvar->rstat.ack_upd_bytes += (ack_seq - subflow->snd_nxt);
#endif
    // fast retransmission exit: cwnd=ssthresh
    subflow->cwnd = subflow->ssthresh;

    TRACE_LOSS("Updating snd_nxt from %u to %u\n", subflow->snd_nxt, ack_seq);
// #if USE_CCP
//    subflow->wait_for_acks = FALSE;
// #endif
    subflow->snd_nxt = ack_seq;
    TRACE_DBG("Sending again..., ack_seq=%u sndlen=%u cwnd=%u\n",
                        ack_seq-subflow->iss,
                        subflow->sndbuf->len,
                        subflow->cwnd / subflow->mss);
    if (sndvar->sndbuf->len == 0) {
      RemoveFromSendList(mtcp, cur_stream);
    } else {
      AddtoSendList(mtcp, cur_stream);
    }
  }
// #endif  /* RECOVERY_AFTER_LOSS */

  rmlen = ack_seq - subflow->sndbuf->head_seq;
  uint16_t packets = rmlen / subflow->mss;
  if (packets * subflow->mss > rmlen || packets == 0) {
    packets++;
  }

// #if USE_CCP
//  ccp_cong_control(mtcp, cur_stream, ack_seq, rmlen, packets);
// #else
//  // log_cwnd_rtt(cur_stream);
// #endif

  /* If ack_seq is previously acked, return */
  if (TCP_SEQ_GEQ(subflow->sndbuf->head_seq, ack_seq)) {
    TRACE_INFO("subflow->sndbuf->head_seq=%u>ack_seq=%u\n", 
      subflow->sndbuf->head_seq, ack_seq);
    return;
  }

  /* Remove acked sequence from send buffer */
  if (rmlen > 0) {
    /* Routine goes here only if there is new payload (not retransmitted) */
    
    /* Estimate RTT and calculate rto */
    // if (subflow->saw_timestamp) {
      EstimateRTTSubflow(mtcp, subflow, 
          cur_ts - cur_stream->rcvvar->ts_lastack_rcvd);
      // subflow->rto = 
      cur_stream->sndvar->rto = (subflow->srtt >> 3) + subflow->rttvar;
      UpdateAdaptivePacingRate(subflow, FALSE);
    // } else {
    //   //TODO: Need to implement timestamp estimation without timestamp
    //   TRACE_RTT("NOT IMPLEMENTED.\n");
    // }

    // TODO CCP should comment this out? 
    /* Update congestion control variables */

    TRACE_INFO("before altering cwnd, cwnd=%u, packets=%d\n", 
      subflow->cwnd, packets);

    if (cur_stream->state >= TCP_ST_ESTABLISHED) {
      if (subflow->cwnd < subflow->ssthresh) {
        if ((subflow->cwnd + subflow->mss) > subflow->cwnd) {
          subflow->cwnd += (subflow->mss * packets);
        }
        TRACE_INFO("slow start cwnd: %u, ssthresh: %u\n", 
            subflow->cwnd, subflow->ssthresh);
      } else {
        uint32_t new_cwnd = subflow->cwnd + 
            packets * subflow->mss * subflow->mss / 
            subflow->cwnd;
        if (new_cwnd > subflow->cwnd) {
          subflow->cwnd = new_cwnd;
        }
        TRACE_INFO("congestion avoidance cwnd: %u, ssthresh: %u\n", 
            subflow->cwnd, subflow->ssthresh);
      }
    }

    TRACE_INFO("after altering cwnd, cwnd=%u, packets=%d\n", 
      subflow->cwnd, packets);

    if (SBUF_LOCK(&sndvar->write_lock)) {
      if (errno == EDEADLK)
        perror("ProcessACKSubflow: write_lock blocked\n");
      assert(0);
    }
    TRACE_INFO("REMOVING SUBFLOW BUFFER\n");
    ret = SBRemove(mtcp->rbm_snd, subflow->sndbuf, rmlen);
    subflow->snd_una = ack_seq;
    // snd_wnd_prev = subflow->snd_wnd;
    // subflow->snd_wnd = subflow->sndbuf->size - subflow->sndbuf->len;

    struct tdtcp_mapping * tnode = 
      (struct tdtcp_mapping *)(rbt_leftmost(subflow->txmappings));
    // DELETE UP TO
    while (tnode && (tnode->ssn + tnode->size) < ack_seq) {
      rbt_delete(subflow->txmappings, (RBTNode *)tnode);
      tnode = (struct tdtcp_mapping *)(rbt_leftmost(subflow->txmappings));
    }

    /* If there was no available sending window */
    /* notify the newly available window to application */
// #if SELECTIVE_WRITE_EVENT_NOTIFY
//    if (snd_wnd_prev <= 0) {
// #endif  /* SELECTIVE_WRITE_EVENT_NOTIFY */ 
//      RaiseWriteEvent(mtcp, cur_stream);
// #if SELECTIVE_WRITE_EVENT_NOTIFY
//    }
// #endif /* SELECTIVE_WRITE_EVENT_NOTIFY */

    SBUF_UNLOCK(&sndvar->write_lock);
    UpdateRetransmissionTimerSubflow(mtcp, cur_stream, subflow, cur_ts);
  }

  UNUSED(ret);
}

inline void 
EstimateRTTSubflow(mtcp_manager_t mtcp, tdtcp_txsubflow *subflow, uint32_t mrtt)
{
  /* This function should be called for not retransmitted packets */
  /* TODO: determine tcp_rto_min */
#define TCP_RTO_MIN 0
  long m = mrtt;
  uint32_t tcp_rto_min = TCP_RTO_MIN;
  // struct tcp_recv_vars *rcvvar = cur_stream->rcvvar;

  if (m == 0) {
    m = 1;
  }
  if (subflow->srtt != 0) {
    /* rtt = 7/8 rtt + 1/8 new */
    m -= (subflow->srtt >> 3);
    subflow->srtt += m;
    if (m < 0) {
      m = -m;
      m -= (subflow->mdev >> 2);
      if (m > 0) {
        m >>= 3;
      }
    } else {
      m -= (subflow->mdev >> 2);
    }
    subflow->mdev += m;
    if (subflow->mdev > subflow->mdev_max) {
      subflow->mdev_max = subflow->mdev;
      if (subflow->mdev_max > subflow->rttvar) {
        subflow->rttvar = subflow->mdev_max;
      }
    }
    if (TCP_SEQ_GT(subflow->snd_una, subflow->rtt_seq)) {
      if (subflow->mdev_max < subflow->rttvar) {
        subflow->rttvar -= (subflow->rttvar - subflow->mdev_max) >> 2;
      }
      subflow->rtt_seq = subflow->snd_nxt;
      subflow->mdev_max = tcp_rto_min;
    }
  } else {
    /* fresh measurement */
    subflow->srtt = m << 3;
    subflow->mdev = m << 1;
    subflow->mdev_max = subflow->rttvar = MAX(subflow->mdev, tcp_rto_min);
    subflow->rtt_seq = subflow->snd_nxt;
  }

  TRACE_INFO("Subflow %u EstimateRTT: mrtt: %u (%uus), srtt: %u (%ums), mdev: %u, mdev_max: %u, "
      "rttvar: %u, rtt_seq: %u\n", subflow->subflow_id, mrtt, mrtt * TIME_TICK, 
      subflow->srtt, TS_TO_MSEC((subflow->srtt) >> 3), subflow->mdev, 
      subflow->mdev_max, subflow->rttvar, subflow->rtt_seq);
}

inline int 
ProcessTCPPayloadSubflow(mtcp_manager_t mtcp, tcp_stream *cur_stream, 
    uint32_t cur_ts, uint8_t *payload, uint32_t seq, int payloadlen) {

  struct tcp_recv_vars *rcvvar = cur_stream->rcvvar; 
  uint32_t prev_rcv_nxt;
  int ret;

  struct tdtcp_option_tddss * tddss = cur_stream->tddss_pass;
  tdtcp_rxsubflow * subflow;
  uint8_t dsubflow, dcarrier;
  uint32_t sseq, dseq;

  /* populate tdtcp variables */
  dsubflow = tddss->dsubflow;
  dcarrier = tddss->dcarrier;
  subflow = cur_stream->rx_subflows + dsubflow;
  sseq = ntohl(tddss->subseq);
  dseq = seq;

  /* if seq and segment length is lower than rcv_nxt, ignore and send ack */
  if (TCP_SEQ_LT(seq + payloadlen, cur_stream->rcv_nxt)) {
    return FALSE;
  }
  uint32_t old_rcv_nxt = cur_stream->rcv_nxt;
  uint32_t old_rwnd = rcvvar->rcv_wnd;
  /* if payload exceeds receiving buffer, drop and send ack */
  if (TCP_SEQ_GT(seq + payloadlen, cur_stream->rcv_nxt + rcvvar->rcv_wnd)) {
    return FALSE; 
  }

  /* same logic for subflow */
  if (TCP_SEQ_LT(sseq + payloadlen, subflow->rcv_nxt)) {
    return FALSE;
  }

  /* allocate receive buffer if not exist */
  if (!subflow->rcvbuf) {
    subflow->rcvbuf = RBInit(mtcp->rbm_rcv, subflow->irs + 1);
    if (!subflow->rcvbuf) {
      TRACE_ERROR("Stream %d subflow %u: Failed to allocate receive buffer.\n", 
          cur_stream->id, dsubflow);
      cur_stream->state = TCP_ST_CLOSED;
      cur_stream->close_reason = TCP_NO_MEM;
      RaiseErrorEvent(mtcp, cur_stream);

      return ERROR;
    }
  }

  if (SBUF_LOCK(&rcvvar->read_lock)) {
    if (errno == EDEADLK)
      perror("ProcessTCPPayloadSubflow: read_lock blocked\n");
    assert(0);
  }

  prev_rcv_nxt = subflow->rcv_nxt;
  ret = RBPut(mtcp->rbm_rcv, 
      subflow->rcvbuf, payload, (uint32_t)payloadlen, sseq);
  if (ret < 0) {
    TRACE_ERROR("Cannot merge payload. reason: %d\n", ret);
  }
  /* add mapping */
  struct tdtcp_mapping newmap = {
    .ssn = sseq,
    .dsn = dseq,
    .size = payloadlen,
    .carrier = dcarrier
  };
  bool isNew = TRUE;
  RBTNode * new_node = rbt_insert(subflow->rxmappings, (RBTNode *)(&newmap), &isNew);

  /* discard the buffer if the state is FIN_WAIT_1 or FIN_WAIT_2, 
     meaning that the connection is already closed by the application */
  if (cur_stream->state == TCP_ST_FIN_WAIT_1 || 
      cur_stream->state == TCP_ST_FIN_WAIT_2) {
    RBRemove(mtcp->rbm_rcv, 
        subflow->rcvbuf, subflow->rcvbuf->merged_len, AT_MTCP);
    rbt_delete(subflow->rxmappings, new_node);
  }
  subflow->rcv_nxt = subflow->rcvbuf->head_seq + subflow->rcvbuf->merged_len;
  
  /* XXX: Need lock entire receiver buffer here? */
  rcvvar->rcv_wnd = subflow->rcvbuf->size - subflow->rcvbuf->merged_len;

  SBUF_UNLOCK(&rcvvar->read_lock);

  if (TCP_SEQ_LEQ(subflow->rcv_nxt, prev_rcv_nxt)) {
    /* There are some lost packets */
    return FALSE; 
  }
  /* "OnSubflowReceive" */
  else {
    // uint32_t expectedDSN = cur_stream->rcv_nxt;
    struct tdtcp_mapping * min_map = 
        (struct tdtcp_mapping *)rbt_leftmost(subflow->rxmappings);

    while (min_map) {
      if (TCP_SEQ_GT(seq + payloadlen, cur_stream->rcv_nxt + rcvvar->rcv_wnd))
          break;

      uint32_t extracted_ssn = min_map->ssn;
      uint16_t extracted_sz = min_map->size;

      /* try to add this piece of data to the main rx buffer */
      uint8_t * data = subflow->rcvbuf->head + (min_map->ssn - subflow->rcvbuf->head_seq);
      int proc_ret = ProcessTCPPayload(mtcp, cur_stream, cur_ts, data, min_map->dsn, min_map->size);
      if (proc_ret != ERROR) {
        RBRemove(mtcp->rbm_rcv, subflow->rcvbuf, min_map->size, AT_MTCP);
        rbt_delete(subflow->rxmappings, (RBTNode *)min_map);
      }
      else {
        TRACE_ERROR("Entered error on subflow receive!\n");
        TRACE_ERROR("in packet: seq + payloadlen=%u, cur_stream->rcv_nxt + rcvvar->rcv_wnd=%u\n",
			    seq + payloadlen, old_rcv_nxt + old_rwnd);
        assert(0);
        break;
      }
      if (extracted_ssn + extracted_sz == subflow->rcv_nxt) {
        break;
      }

      min_map = (struct tdtcp_mapping *)rbt_leftmost(subflow->rxmappings);

    }
  }
  // AddtoACKListSubflow(mtcp, subflow);
  EnqueueACKSubflow(mtcp, cur_stream, subflow, cur_ts, ACK_OPT_NOW);

  // TRACE_EPOLL("Stream %d data arrived. "
  //    "len: %d, ET: %u, IN: %u, OUT: %u\n", 
  //    cur_stream->id, payloadlen, 
  //    cur_stream->socket? cur_stream->socket->epoll & MTCP_EPOLLET : 0, 
  //    cur_stream->socket? cur_stream->socket->epoll & MTCP_EPOLLIN : 0, 
  //    cur_stream->socket? cur_stream->socket->epoll & MTCP_EPOLLOUT : 0);

  // if (cur_stream->state == TCP_ST_ESTABLISHED) {
  //  RaiseReadEvent(mtcp, cur_stream);
  // }

  return TRUE;
}

/* out */
int
SendTCPDataPacketSubflow(struct mtcp_manager *mtcp, tcp_stream *cur_stream, 
    tdtcp_txsubflow * subflow, struct tdtcp_mapping * mapping,
    uint32_t cur_ts, uint8_t flags, uint8_t *payload, uint16_t payloadlen)
{
  struct tcphdr *tcph;
  uint16_t optlen;
  uint8_t wscale = 0;
  uint32_t window32 = 0;
  //int rc = -1;

  optlen = CalculateOptionLength(flags);

  tcph = (struct tcphdr *)IPOutput(mtcp, cur_stream, 
      TCP_HEADER_LEN + optlen + payloadlen);
  if (tcph == NULL) {
    return -2;
  }
  memset(tcph, 0, TCP_HEADER_LEN + optlen);

  tcph->source = cur_stream->sport;
  tcph->dest = cur_stream->dport;

  if (flags & TCP_FLAG_PSH)
    tcph->psh = TRUE;

  // struct tdtcp_mapping retx_node_search = {.ssn = subflow->snd_nxt};
  // struct tdtcp_mapping * retx_node = 
  //   (struct tdtcp_mapping *)rbt_find(subflow->txmappings, (RBTNode*)&retx_node_search);

  // if (retx_node) {
  //   tcph->seq = htonl(retx_node->dsn);
  //   if (flags & TCP_FLAG_FIN) tcph->fin = TRUE;
  // } 

  else if (flags & TCP_FLAG_FIN) {
    tcph->fin = TRUE;
    
    if (cur_stream->sndvar->fss == 0) {
      TRACE_ERROR("Stream %u: not fss set. closed: %u\n", 
          cur_stream->id, cur_stream->closed);
    }
    tcph->seq = htonl(cur_stream->sndvar->fss);
    cur_stream->sndvar->is_fin_sent = TRUE;
    TRACE_FIN("Stream %d: Sending FIN. seq: %u, ack_seq: %u\n", 
        cur_stream->id, cur_stream->snd_nxt, cur_stream->rcv_nxt);
  } else {
    tcph->seq = htonl(mapping->dsn);
  }

  if (flags & TCP_FLAG_ACK) {
    tcph->ack = TRUE;
    tcph->ack_seq = htonl(cur_stream->rcv_nxt);
    cur_stream->sndvar->ts_lastack_sent = cur_ts;
    cur_stream->last_active_ts = cur_ts;
    UpdateTimeoutList(mtcp, cur_stream);
  }

  wscale = cur_stream->sndvar->wscale_mine;

  window32 = cur_stream->rcvvar->rcv_wnd >> wscale;
  tcph->window = htons((uint16_t)MIN(window32, TCP_MAX_WINDOW));
  /* if the advertised window is 0, we need to advertise again later */
  if (window32 == 0) {
    cur_stream->need_wnd_adv = TRUE;
  }

  // GenerateTCPOptions(cur_stream, cur_ts, flags, 
  //    (uint8_t *)tcph + TCP_HEADER_LEN, optlen);
  uint8_t * tcpopt = (uint8_t *)tcph + TCP_HEADER_LEN;

  int i = 0;
#if TCP_OPT_TIMESTAMP_ENABLED
  tcpopt[i++] = TCP_OPT_NOP;
  tcpopt[i++] = TCP_OPT_NOP;
  GenerateTCPTimestamp(cur_stream, tcpopt + i, cur_ts);
    i += TCP_OPT_TIMESTAMP_LEN;
#endif

  struct tdtcp_option_tddss tddss = {
    .kind = TCP_OPT_TDTCP,
    .length = TCP_OPT_TDDSS_LEN,
    .subtype = TD_DSS,
    .hasack = 0,
    .hasdata = 1,
    .unused = 0,
    .dsubflow = subflow->subflow_id,
    .dcarrier = 0, // unused
    .asubflow = 0,
    .acarrier = 0, // unused
    .subseq = htonl(mapping->ssn),
    .suback = 0
  };
  memcpy(&(tcpopt[i]), &tddss, sizeof(tddss));

  tcph->doff = (TCP_HEADER_LEN + optlen) >> 2;
  // copy payload if exist
  memcpy((uint8_t *)tcph + TCP_HEADER_LEN + optlen, payload, payloadlen);
#if defined(NETSTAT) && defined(ENABLELRO)
  mtcp->nstat.tx_gdptbytes += payloadlen;
#endif /* NETSTAT */

#if TCP_CALCULATE_CHECKSUM
#ifndef DISABLE_HWCSUM
  if (mtcp->iom->dev_ioctl != NULL)
    rc = mtcp->iom->dev_ioctl(mtcp->ctx, cur_stream->sndvar->nif_out,
            PKT_TX_TCPIP_CSUM, NULL);
#endif
  if (rc == -1)
    tcph->check = TCPCalcChecksum((uint16_t *)tcph, 
                TCP_HEADER_LEN + optlen + payloadlen, 
                cur_stream->saddr, cur_stream->daddr);
#endif
  
  // if (subflow->snd_nxt == mapping->ssn)
  //   subflow->snd_nxt += payloadlen;
  // if (cur_stream->snd_nxt == mapping->dsn)
  //   cur_stream->snd_nxt += payloadlen;
  
  if (tcph->syn || tcph->fin) {
    PRINT_CHANGE(cur_stream->snd_nxt, cur_stream->snd_nxt+1);
    cur_stream->snd_nxt++;
    payloadlen++;
  }

  if (payloadlen > 0) {
    if (cur_stream->state > TCP_ST_ESTABLISHED) {
      TRACE_FIN("Payload after ESTABLISHED: length: %d, snd_nxt: %u\n", 
          payloadlen, cur_stream->snd_nxt);
    }

    /* update retransmission timer if have payload */
    cur_stream->sndvar->ts_rto = cur_ts + cur_stream->sndvar->rto;
    TRACE_INFO("Updating retransmission timer. "
        "cur_ts: %u, rto: %u, ts_rto: %u\n", 
        cur_ts, cur_stream->sndvar->rto, cur_stream->sndvar->ts_rto);
    AddtoRTOList(mtcp, cur_stream);
  }
#ifdef PHEADER
  fprintf(stderr, "Sending - tdtcp.c\n");
  PrintTCPHeader((uint8_t*)tcph);
#endif
    
  return payloadlen;
}
// #if 0
inline int 
WriteTDTCPRetransList(mtcp_manager_t mtcp, struct mtcp_sender *sender, 
  uint32_t cur_ts, int thresh)
{

  tdtcp_txsubflow *txsubflow;
  tdtcp_txsubflow *next, *last;

  int cnt = 0;
  int ret;

  cnt = 0;
  txsubflow = TAILQ_FIRST(&sender->retransmit_list);
  last = TAILQ_LAST(&sender->retransmit_list, retrans_head);

  while (txsubflow) {
    if (++cnt > thresh)
      break;

    TRACE_LOOP("Inside retransmit loop. cnt: %u, stream: %d\n", 
        cnt, txsubflow->subflow_id);
    next = TAILQ_NEXT(txsubflow, retransmit_link);

    TAILQ_REMOVE(&sender->retransmit_list, txsubflow, retransmit_link);
    if (txsubflow->on_retransmit_list) {
      ret = 0;

      /* Send data here */
      /* Only can send data when ESTABLISHED or CLOSE_WAIT */
      if (txsubflow->meta->state == TCP_ST_ESTABLISHED) {
        if (txsubflow->on_control_list) {
          /* delay sending data after until on_control_list becomes off */
          //TRACE_DBG("Stream %u: delay sending data.\n", txsubflow->id);
          ret = -1;
        } else {
          ret = RetransmitPacketTDTCP(mtcp, txsubflow, cur_ts);
        }
      } else if (txsubflow->meta->state == TCP_ST_CLOSE_WAIT || 
          txsubflow->meta->state == TCP_ST_FIN_WAIT_1 || 
          txsubflow->meta->state == TCP_ST_LAST_ACK) {
        ret = RetransmitPacketTDTCP(mtcp, txsubflow, cur_ts);
      } else {
        TRACE_DBG("Stream %d subflow %u: on_retrans_list at state %s\n", 
            txsubflow->meta->id, txsubflow->subflow_id, TCPStateToString(txsubflow->meta));
#if DUMP_STREAM
        DumpStream(mtcp, txsubflow->meta);
#endif
      }

      if (ret < 0) {
        TAILQ_INSERT_TAIL(&sender->retransmit_list, txsubflow, retransmit_link);
        /* since there is no available write buffer, break */
        break;

      } else {
        txsubflow->on_retransmit_list = FALSE;
        sender->retransmit_list_cnt--;
//        /* retransmits shouldn't mess up with ack... */
//        /* the ret value is the number of packets sent. */
//        /* decrease ack_cnt for the piggybacked acks */
// #if ACK_PIGGYBACK
//        if (txsubflow->sndvar->ack_cnt > 0) {
//          if (txsubflow->sndvar->ack_cnt > ret) {
//            txsubflow->sndvar->ack_cnt -= ret;
//          } else {
//            txsubflow->sndvar->ack_cnt = 0;
//          }
//        }
// #endif
// #if 1
//        if (txsubflow->control_list_waiting) {
//          if (!txsubflow->sndvar->on_ack_list) {
//            txsubflow->control_list_waiting = FALSE;
//            AddtoControlList(mtcp, txsubflow, cur_ts);
//          }
//        }
// #endif
      }
    } else {
      TRACE_ERROR("Stream %d, subflow %u: not on send list.\n", 
        txsubflow->meta->id, txsubflow->subflow_id);
#ifdef DUMP_STREAM
      DumpStream(mtcp, txsubflow->meta);
#endif
    }

    if (txsubflow == last) 
      break;
    txsubflow = next;
  }

  return cnt;

}


inline int
RetransmitPacketTDTCP(mtcp_manager_t mtcp, tdtcp_txsubflow *txsubflow, uint32_t cur_ts)
{
  // get the indicated missing SEQ's mapping
  tcp_stream *cur_stream = txsubflow->meta;
  struct tdtcp_mapping retx_mapdata = {.ssn = txsubflow->snd_nxt};
  struct tdtcp_mapping * retx_map = 
    (struct tdtcp_mapping *)rbt_find(txsubflow->txmappings, (RBTNode*)(&retx_mapdata));
  if (!retx_map) {
    TRACE_ERROR("Flow %d Subflow %u: cannot find mapping associated with SSN %u in retransmit. Head: %u\n", 
        cur_stream->id, txsubflow->subflow_id, txsubflow->snd_nxt, txsubflow->sndbuf->head_seq);
    // AddtoSendList(mtcp, cur_stream);
    return -1;
  }

  // add this to the cross retx list if necessary
  if (txsubflow->subflow_id != cur_stream->curr_tx_subflow) {
    struct tdtcp_xretrans_map newxtrans = {0};
    bool isNew = TRUE;
    newxtrans.dsn = retx_map->dsn;
    newxtrans.subflow_sz[txsubflow->subflow_id] = retx_map->size;
    rbt_insert(cur_stream->seq_cross_retrans, (RBTNode*)&newxtrans, &isNew);
  }

  // do retransmit
  uint8_t * data = txsubflow->sndbuf->head + (retx_map->ssn - txsubflow->sndbuf->head_seq);
  int retxlen = 0;
  if ((retxlen = SendTCPDataPacketSubflow(mtcp, cur_stream, txsubflow, 
        retx_map, cur_ts, TCP_FLAG_ACK, data, retx_map->size)) <= 0) {
    TRACE_ERROR("Flow %d Subflow %u: Retransmit failed\n", cur_stream->id, txsubflow->subflow_id);
    assert(0);
  }
  return retxlen;
}

inline int 
WriteTCPACKListSubflow(mtcp_manager_t mtcp, 
    struct mtcp_sender *sender, uint32_t cur_ts, int thresh)
{
  tdtcp_rxsubflow *cur_subflow;
  tdtcp_rxsubflow *next, *last;
  tcp_stream *cur_stream;
  int to_ack;
  int cnt = 0;
  int ret;

  /* Send aggregated acks */
  cur_subflow = TAILQ_FIRST(&sender->subflow_ack_list);
  last = TAILQ_LAST(&sender->subflow_ack_list, subflowack_head);
  TRACE_INFO("WriteACKSubflow, cur_subflow=%p, thresh=%d\n", cur_subflow, thresh);
  while (cur_subflow) {
    if (++cnt > thresh)
      break;

    cur_stream = cur_subflow->meta;

    TRACE_INFO("Inside ack loop. cnt: %u\n", cnt);
    next = TAILQ_NEXT(cur_subflow, ack_link);

    if (cur_subflow->on_ack_list) {
      /* this list is only to ack the data packets */
      /* if the ack is not data ack, then it will not process here */
      to_ack = FALSE;
      if (cur_stream->state == TCP_ST_ESTABLISHED || 
          cur_stream->state == TCP_ST_CLOSE_WAIT || 
          cur_stream->state == TCP_ST_FIN_WAIT_1 || 
          cur_stream->state == TCP_ST_FIN_WAIT_2 || 
          cur_stream->state == TCP_ST_TIME_WAIT) {
        /* TIMEWAIT is possible since the ack is queued 
           at FIN_WAIT_2 */
        if (cur_subflow->rcvbuf) {
          if (TCP_SEQ_LEQ(cur_subflow->rcv_nxt, 
                cur_subflow->rcvbuf->head_seq + 
                cur_subflow->rcvbuf->merged_len)) {
            to_ack = TRUE;
          }
        }
      } else {
        TRACE_DBG("Stream %u subflow %u (%s): "
            "Try sending ack at not proper state. "
            "seq: %u, ack_sseq: %u, on_control_list: %u\n", 
            cur_stream->id, cur_subflow->subflow_id, TCPStateToString(cur_stream), 
            cur_stream->snd_nxt, cur_stream->rcv_nxt, cur_subflow->rcv_nxt,
            cur_stream->sndvar->on_control_list);
#ifdef DUMP_STREAM
        DumpStream(mtcp, cur_stream);
#endif
      }
      TRACE_INFO("to_ack: %d\n", to_ack);

      if (to_ack) {
        /* send the queued ack packets */
        TRACE_INFO("subflow %u ack_cnt %u\n", cur_subflow->subflow_id, cur_subflow->ack_cnt);
        while (cur_subflow->ack_cnt > 0) {
          ret = SendSubflowACK(mtcp, cur_stream, cur_subflow, cur_ts);
          if (ret < 0) {
            // since there is no available write buffer, break 
            break;
          }
          cur_subflow->ack_cnt--;
        }

        // WACK shouldn't appear...
        // /* if is_wack is set, send packet to get window advertisement */
        // if (cur_stream->sndvar->is_wack) {
        //  cur_stream->sndvar->is_wack = FALSE;
        //  ret = SendTCPPacket(mtcp, cur_stream, 
        //      cur_ts, TCP_FLAG_ACK | TCP_FLAG_WACK, NULL, 0);
        //  if (ret < 0) {
        //    /* since there is no available write buffer, break */
        //    cur_stream->sndvar->is_wack = TRUE;
        //  }
        // }

        if (!(cur_subflow->ack_cnt)) {
          cur_subflow->on_ack_list = FALSE;
          TAILQ_REMOVE(&sender->subflow_ack_list, cur_subflow, ack_link);
          sender->subflow_ack_list_cnt--;
        }
      } else {
        cur_subflow->on_ack_list = FALSE;
        cur_subflow->ack_cnt = 0;
        cur_subflow->is_wack = 0;
        TAILQ_REMOVE(&sender->subflow_ack_list, cur_subflow, ack_link);
        sender->subflow_ack_list_cnt--;
      }

      // if (cur_stream->control_list_waiting) {
      //  if (!cur_stream->sndvar->on_send_list) {
      //    cur_stream->control_list_waiting = FALSE;
      //    AddtoControlList(mtcp, cur_stream, cur_ts);
      //  }
      // }
    } else {
      TRACE_ERROR("Stream %d subflow %u: not on ack list.\n", cur_stream->id, cur_subflow->subflow_id);
      TAILQ_REMOVE(&sender->subflow_ack_list, cur_subflow, ack_link);
      sender->subflow_ack_list_cnt--;
#ifdef DUMP_STREAM
      thread_printf(mtcp, mtcp->log_fp, 
          "Stream %u: not on ack list.\n", cur_stream->id);
      DumpStream(mtcp, cur_stream);
#endif
    }

    if (cur_subflow == last)
      break;
    cur_subflow = next;
  }

  return cnt;
}

inline int 
SendSubflowACK(struct mtcp_manager *mtcp, tcp_stream *cur_stream, 
  tdtcp_rxsubflow * rxsubflow, uint32_t cur_ts)
{
  TRACE_INFO("subflow %u Sending SubflowAck\n", rxsubflow->subflow_id);

  struct tcphdr *tcph;
  uint16_t optlen;
  uint8_t wscale = 0;
  uint32_t window32 = 0;
  //int rc = -1;

  optlen = CalculateOptionLength(TCP_FLAG_ACK);

  tcph = (struct tcphdr *)IPOutput(mtcp, cur_stream, 
      TCP_HEADER_LEN + optlen);
  if (tcph == NULL) {
    return -2;
  }
  memset(tcph, 0, TCP_HEADER_LEN + optlen);

  tcph->source = cur_stream->sport;
  tcph->dest = cur_stream->dport;
  tcph->seq = htonl(cur_stream->snd_nxt);

  tcph->ack = TRUE;
  tcph->ack_seq = htonl(cur_stream->rcv_nxt);
  cur_stream->sndvar->ts_lastack_sent = cur_ts;
  cur_stream->last_active_ts = cur_ts;
  UpdateTimeoutList(mtcp, cur_stream);

  wscale = cur_stream->sndvar->wscale_mine;

  window32 = cur_stream->rcvvar->rcv_wnd >> wscale;
  tcph->window = htons((uint16_t)MIN(window32, TCP_MAX_WINDOW));
  /* if the advertised window is 0, we need to advertise again later */
  if (window32 == 0) {
    cur_stream->need_wnd_adv = TRUE;
  }

  // GenerateTCPOptions(cur_stream, cur_ts, flags, 
  //    (uint8_t *)tcph + TCP_HEADER_LEN, optlen);
  uint8_t * tcpopt = (uint8_t *)tcph + TCP_HEADER_LEN;

  int i = 0;
#if TCP_OPT_TIMESTAMP_ENABLED
  tcpopt[i++] = TCP_OPT_NOP;
  tcpopt[i++] = TCP_OPT_NOP;
  GenerateTCPTimestamp(cur_stream, tcpopt + i, cur_ts);
    i += TCP_OPT_TIMESTAMP_LEN;
#endif

  struct tdtcp_option_tddss tddss = {
    .kind = TCP_OPT_TDTCP,
    .length = TCP_OPT_TDDSS_LEN,
    .subtype = TD_DSS,
    .hasack = 1,
    .hasdata = 0,
    .unused = 0,
    .dsubflow = 0,
    .dcarrier = 0,
    .asubflow = rxsubflow->subflow_id,
    .acarrier = 0, // unused
    .subseq = 0,
    .suback = htonl(rxsubflow->rcv_nxt)
  };
  memcpy(&(tcpopt[i]), &tddss, sizeof(tddss));

  tcph->doff = (TCP_HEADER_LEN + optlen) >> 2;
  // copy payload if exist

#if TCP_CALCULATE_CHECKSUM
#ifndef DISABLE_HWCSUM
  if (mtcp->iom->dev_ioctl != NULL)
    rc = mtcp->iom->dev_ioctl(mtcp->ctx, cur_stream->sndvar->nif_out,
            PKT_TX_TCPIP_CSUM, NULL);
#endif
  if (rc == -1)
    tcph->check = TCPCalcChecksum((uint16_t *)tcph, 
                TCP_HEADER_LEN + optlen, 
                cur_stream->saddr, cur_stream->daddr);
#endif

  //PrintTCPHeader((uint8_t*)tcph);
  TRACE_INFO("subflow %u Sending SubflowAck finished\n", rxsubflow->subflow_id);
    
  return 0;
}
// #endif
inline void 
AddtoACKListSubflow(mtcp_manager_t mtcp, tdtcp_rxsubflow *rxsubflow)
{
  struct mtcp_sender *sender = GetSender(mtcp, rxsubflow->meta);
  assert(sender != NULL);
  TRACE_INFO("AddtoACKListSubflow, subflow_id=%u\n", rxsubflow->subflow_id);

  if (!rxsubflow->on_ack_list) {
    rxsubflow->on_ack_list = TRUE;
    TAILQ_INSERT_TAIL(&sender->subflow_ack_list, rxsubflow, ack_link);
    sender->subflow_ack_list_cnt++;
  }
}

inline void 
AddtoRetxList(mtcp_manager_t mtcp, tdtcp_txsubflow *txsubflow) {
  struct mtcp_sender *sender = GetSender(mtcp, txsubflow->meta);
  assert(sender != NULL);

  // if(!txsubflow->meta->sndvar->sndbuf) {
  //  TRACE_ERROR("[%d] Stream %d: No send buffer available.\n", 
  //      mtcp->ctx->cpu,
  //      txsubflow->meta->id);
  //  assert(0);
  //  return;
  // }

  if (!txsubflow->on_retransmit_list) {
    txsubflow->on_retransmit_list = TRUE;
    TAILQ_INSERT_TAIL(&sender->retransmit_list, txsubflow, retransmit_link);
    sender->retransmit_list_cnt++;
  }
}

inline void 
EnqueueACKSubflow(mtcp_manager_t mtcp, 
    tcp_stream *cur_stream, tdtcp_rxsubflow * rxsubflow, 
    uint32_t cur_ts, uint8_t opt)
{
  if (!(cur_stream->state == TCP_ST_ESTABLISHED || 
      cur_stream->state == TCP_ST_CLOSE_WAIT || 
      cur_stream->state == TCP_ST_FIN_WAIT_1 || 
      cur_stream->state == TCP_ST_FIN_WAIT_2)) {
    TRACE_DBG("Stream %u: Enqueueing ack at state %s\n", 
        cur_stream->id, TCPStateToString(cur_stream));
  }

  if (opt == ACK_OPT_NOW) {
    if (rxsubflow->ack_cnt < rxsubflow->ack_cnt + 1) {
      rxsubflow->ack_cnt++;
    }
  } else if (opt == ACK_OPT_AGGREGATE) {
    if (rxsubflow->ack_cnt == 0) {
      rxsubflow->ack_cnt = 1;
    }
  } else if (opt == ACK_OPT_WACK) {
    TRACE_ERROR("RX Subflows shouldn't handle window update broadcasts.\n")
  }
  AddtoACKListSubflow(mtcp, rxsubflow);
}

inline void 
RemoveFromRetxList(mtcp_manager_t mtcp, tdtcp_txsubflow * tx_subflow)
{
  struct mtcp_sender *sender = GetSender(mtcp, tx_subflow->meta);
  assert(sender != NULL);

  if (tx_subflow->on_retransmit_list) {
    tx_subflow->on_retransmit_list = FALSE;
    TAILQ_REMOVE(&sender->retransmit_list, tx_subflow, retransmit_link);
    sender->retransmit_list_cnt--;
  }
}


inline void 
RemoveFromAckListSubflow(mtcp_manager_t mtcp, tdtcp_rxsubflow * rx_subflow)
{
  struct mtcp_sender *sender = GetSender(mtcp, rx_subflow->meta);
  assert(sender != NULL);

  if (rx_subflow->on_ack_list) {
    rx_subflow->on_ack_list = FALSE;
    TAILQ_REMOVE(&sender->subflow_ack_list, rx_subflow, ack_link);
    sender->subflow_ack_list_cnt--;
  }
}

// Stream level
void UpdateAdaptivePacingRate(tdtcp_txsubflow * subflow,
                              bool resetEnable)
{
  // NS_LOG_INFO ("Proposed spreading cwnd " << win << " across " << 
  //               proposeSpread.GetSeconds() << "seconds");
  if (resetEnable)
    subflow->paced = TRUE;

  double rate = (double)subflow->cwnd / TS_TO_USEC((subflow->srtt) >> 3) * 8e6;
  // rate *= (1 + std::cbrt((double)m_tcb->m_segmentSize/win) + std::cbrt((double)m_tcb->m_segmentSize/(std::max(AvailableWindow () - m_tcb->m_segmentSize, (uint32_t)1))));
  // rate *= (1 + (double)BytesInFlight()/win);
  subflow->pacer->rate_bps = rate;
  TRACE_INFO("Updated pacing rate for flow %u subflow %u, new rate = %.0f\n", 
      subflow->meta->id, subflow->subflow_id, rate);
  // 
  // m_tcb->m_currentPacingRate = DataRate((uint64_t)2 * m_rateNextRound);
  // NS_LOG_INFO ("Updated pacing rate of subflow " << (int)m_subflowid << " to " << m_tcb->m_currentPacingRate);
}

int ProcessICMPNetworkUpdate(mtcp_manager_t mtcp, struct iphdr *iph, int len) {
  // just for now, update not for per destination
  int ret = 0;

  struct icmphdr *icmph = (struct icmphdr *) IP_NEXT_PTR(iph);
  if (ICMPChecksum((uint16_t *) icmph, len - (iph->ihl << 2)) ) {
    ret = ERROR;
  }
  else {
    uint8_t newnet_id = icmph->un.tdupdate.newnet_id;
    TRACE_INFO("Updating current network id from %u to %u\n", 
      mtcp->curr_tx_subflow, newnet_id);
    mtcp->curr_tx_subflow = newnet_id;
  }
  return ret;
}

// void 
// AddtoRTOListSubflow(mtcp_manager_t mtcp, tcp_stream *cur_stream, 
//   tdtcp_txsubflow * subflow)
// {
//   if (!mtcp->rto_list_cnt) {
//     mtcp->rto_store->rto_now_idx = 0;
//     mtcp->rto_store->rto_now_ts = subflow->ts_rto;
//   }

//   if (cur_stream->on_rto_idx < 0 ) {
//     if (cur_stream->on_timewait_list) {
//       TRACE_ERROR("Stream %u: cannot be in both "
//           "rto and timewait list.\n", cur_stream->id);
// #ifdef DUMP_STREAM
//       DumpStream(mtcp, cur_stream);
// #endif
//       return;
//     }

//     int diff = (int32_t)(subflow->ts_rto - mtcp->rto_store->rto_now_ts);
//     if (diff < RTO_HASH) {
//       int offset= (diff + mtcp->rto_store->rto_now_idx) % RTO_HASH;
//       cur_stream->on_rto_idx = offset;
//       TAILQ_INSERT_TAIL(&(mtcp->rto_store->rto_list[offset]), 
//           cur_stream, sndvar->timer_link);
//     } else {
//       cur_stream->on_rto_idx = RTO_HASH;
//       TAILQ_INSERT_TAIL(&(mtcp->rto_store->rto_list[RTO_HASH]), 
//           cur_stream, sndvar->timer_link);
//     }
//     mtcp->rto_list_cnt++;
//   }
// }

inline void
UpdateRetransmissionTimerSubflow(mtcp_manager_t mtcp, 
    tcp_stream *cur_stream, tdtcp_txsubflow * subflow, uint32_t cur_ts)
{
  /* Update the retransmission timer */
  // assert(cur_stream->sndvar->rto > 0);
  cur_stream->sndvar->nrtx = 0;

  /* if in rto list, remove it */
  if (cur_stream->on_rto_idx >= 0) {
    RemoveFromRTOList(mtcp, cur_stream);
  }

  /* Reset retransmission timeout */
  if (TCP_SEQ_GT(subflow->snd_nxt, subflow->snd_una)) {
    /* there are packets sent but not acked */
    /* update rto timestamp */
    cur_stream->sndvar->ts_rto = cur_ts + cur_stream->sndvar->rto;
    cur_stream->timeout_subflow = subflow->subflow_id;
    AddtoRTOList(mtcp, cur_stream);

  } else {
    /* all packets are acked */
    TRACE_RTO("All packets are acked. snd_una: %u, snd_nxt: %u\n", 
        subflow->snd_una, subflow->snd_nxt);
  }
}
