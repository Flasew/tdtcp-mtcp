#include <assert.h>
#include <time.h>
#include <inttypes.h>

#include "tcp_util.h"
#include "tcp_in.h"
#include "tcp_out.h"
#include "tcp_ring_buffer.h"
#include "eventpoll.h"
#include "debug.h"
#include "timer.h"
#include "ip_in.h"
#include "clock.h"
#if USE_CCP
#include "ccp.h"
#endif
#if TDTCP_ENABLED
#include "tdtcp.h"
#endif
#include "pacing.h"

#define PRINT_CHANGE(x, y) fprintf(stderr, "[%10s:%4d] CHANGE %s: %d->%d\n",__FUNCTION__, __LINE__, #x, x, y)

#define MAX(a, b) ((a)>(b)?(a):(b))
#define MIN(a, b) ((a)<(b)?(a):(b))

#define VERIFY_RX_CHECKSUM TRUE
#define RECOVERY_AFTER_LOSS TRUE
#define SELECTIVE_WRITE_EVENT_NOTIFY TRUE

static void MarkEmptyAckIncomming() {return;}

/*----------------------------------------------------------------------------*/
static inline int 
FilterSYNPacket(mtcp_manager_t mtcp, uint32_t ip, uint16_t port)
{
	struct sockaddr_in *addr;
	struct tcp_listener *listener;

	/* TODO: This listening logic should be revised */

	/* if not the address we want, drop */
	listener = (struct tcp_listener *)ListenerHTSearch(mtcp->listeners, &port);
	if (listener == NULL)	return FALSE;

	addr = &listener->socket->saddr;

	if (addr->sin_port == port) {
		if (addr->sin_addr.s_addr != INADDR_ANY) {
			if (ip == addr->sin_addr.s_addr) {
				return TRUE;
			}
			return FALSE;
		} else {
			int i;

			for (i = 0; i < CONFIG.eths_num; i++) {
				if (ip == CONFIG.eths[i].ip_addr) {
					return TRUE;
				}
			}
			return FALSE;
		}
	}

	return FALSE;
}
/*----------------------------------------------------------------------------*/
static inline tcp_stream *
HandlePassiveOpen(mtcp_manager_t mtcp, uint32_t cur_ts, const struct iphdr *iph, 
		const struct tcphdr *tcph, uint32_t seq, uint16_t window)
{
	tcp_stream *cur_stream = NULL;

	/* create new stream and add to flow hash table */
	cur_stream = CreateTCPStream(mtcp, NULL, MTCP_SOCK_STREAM, 
			iph->daddr, tcph->dest, iph->saddr, tcph->source);
	if (!cur_stream) {
		TRACE_ERROR("INFO: Could not allocate tcp_stream!\n");
		return FALSE;
	}
	cur_stream->rcvvar->irs = seq;
	cur_stream->sndvar->peer_wnd = window;
	cur_stream->rcv_nxt = cur_stream->rcvvar->irs;
	cur_stream->sndvar->cwnd = 1;
	ParseTCPOptions(cur_stream, cur_ts, (uint8_t *)tcph + TCP_HEADER_LEN, 
			(tcph->doff << 2) - TCP_HEADER_LEN);

#if TDTCP_ENABLED
	// allocate RX subflows according to the flag
	cur_stream->rx_subflows = calloc(sizeof(tdtcp_rxsubflow), cur_stream->td_nrxsubflows);
	for (int x = 0; x < cur_stream->td_nrxsubflows; x++) {
		cur_stream->rx_subflows[x].subflow_id = x;
		cur_stream->rx_subflows[x].rcvbuf = RBInit(mtcp->rbm_rcv, 0);
		cur_stream->rx_subflows[x].meta = cur_stream;
		cur_stream->rx_subflows[x].rxmappings = rbt_create(sizeof(struct tdtcp_mapping), 
											                        &tdtcp_mapping_comp, 
											                        &tdtcp_mapping_comb,
											                        &tdtcp_mapping_alloc, 
											                        &tdtcp_mapping_free,
                                              NULL);
	}

	// Allocate TX subflows
	if (cur_stream->tx_subflows == NULL) {
		cur_stream->tx_subflows = calloc(sizeof(tdtcp_txsubflow), TDTCP_TX_NSUBFLOWS);
		for (int x = 0; x < TDTCP_TX_NSUBFLOWS; x++) {
			cur_stream->tx_subflows[x].subflow_id = x;
			cur_stream->tx_subflows[x].mss = cur_stream->sndvar->mss;
			cur_stream->tx_subflows[x].eff_mss = cur_stream->sndvar->eff_mss;
			cur_stream->tx_subflows[x].sndbuf = SBInit(mtcp->rbm_snd, 0);
			cur_stream->tx_subflows[x].meta = cur_stream;
			cur_stream->tx_subflows[x].txmappings = rbt_create(sizeof(struct tdtcp_mapping), 
												                        &tdtcp_mapping_comp, 
												                        &tdtcp_mapping_comb,
												                        &tdtcp_mapping_alloc, 
												                        &tdtcp_mapping_free,
                                                NULL);
			cur_stream->tx_subflows[x].paced= TRUE;
			cur_stream->tx_subflows[x].pacer = NewPacketPacer();
			cur_stream->tx_subflows[x].cwnd = ((cur_stream->sndvar->cwnd == 1)? 
				(cur_stream->tx_subflows[x].mss * TCP_INIT_CWND): cur_stream->tx_subflows[x].mss);
			cur_stream->tx_subflows[x].ssthresh = cur_stream->tx_subflows[x].mss * 10;
		}
	}
	cur_stream->curr_tx_subflow = mtcp->curr_tx_subflow;
	cur_stream->timeout_subflow = mtcp->curr_tx_subflow;
	cur_stream->seq_subflow_map = rbt_create(sizeof(struct tdtcp_seq2subflow_map), 
		                           &tdtcp_seq2subflow_comp, 
		                           &tdtcp_seq2subflow_comb,
		                           &tdtcp_seq2subflow_alloc,
		                           &tdtcp_seq2subflow_free,
                               NULL);
	cur_stream->seq_cross_retrans = rbt_create(sizeof(struct tdtcp_xretrans_map), 
		                           &tdtcp_xretrans_comp, 
		                           &tdtcp_xretrans_comb,
		                           &tdtcp_xretrans_alloc,
		                           &tdtcp_xretrans_free,
                               NULL);
#endif

	return cur_stream;
}
/*----------------------------------------------------------------------------*/
static inline int
HandleActiveOpen(mtcp_manager_t mtcp, tcp_stream *cur_stream, uint32_t cur_ts, 
		struct tcphdr *tcph, uint32_t seq, uint32_t ack_seq, uint16_t window)
{
	cur_stream->rcvvar->irs = seq;
	PRINT_CHANGE(cur_stream->snd_nxt, ack_seq);
	cur_stream->snd_nxt = ack_seq;
	cur_stream->sndvar->peer_wnd = window;
	cur_stream->rcvvar->snd_wl1 = cur_stream->rcvvar->irs - 1;
	cur_stream->rcv_nxt = cur_stream->rcvvar->irs + 1;
	cur_stream->rcvvar->last_ack_seq = ack_seq;
	ParseTCPOptions(cur_stream, cur_ts, (uint8_t *)tcph + TCP_HEADER_LEN, 
			(tcph->doff << 2) - TCP_HEADER_LEN);

#if TDTCP_ENABLED
	// allocate RX subflows according to the flag
	if (cur_stream->rx_subflows == NULL) {
		cur_stream->rx_subflows = calloc(sizeof(tdtcp_rxsubflow), cur_stream->td_nrxsubflows);
		for (int x = 0; x < cur_stream->td_nrxsubflows; x++) {
			cur_stream->rx_subflows[x].subflow_id = x;
			cur_stream->rx_subflows[x].rcvbuf = RBInit(mtcp->rbm_rcv, 0);
			cur_stream->rx_subflows[x].meta = cur_stream;
			cur_stream->rx_subflows[x].rxmappings = rbt_create(sizeof(struct tdtcp_mapping), 
												                        &tdtcp_mapping_comp, 
												                        &tdtcp_mapping_comb,
												                        &tdtcp_mapping_alloc, 
												                        &tdtcp_mapping_free,
                                                NULL);
		}
	}

	// Allocate TX subflows
	if (cur_stream->tx_subflows == NULL) {
		cur_stream->tx_subflows = calloc(sizeof(tdtcp_txsubflow), TDTCP_TX_NSUBFLOWS);
		for (int x = 0; x < TDTCP_TX_NSUBFLOWS; x++) {
			cur_stream->tx_subflows[x].subflow_id = x;
			cur_stream->tx_subflows[x].mss = cur_stream->sndvar->mss;
			cur_stream->tx_subflows[x].eff_mss = cur_stream->sndvar->eff_mss;
			cur_stream->tx_subflows[x].sndbuf = SBInit(mtcp->rbm_snd, 0);
			cur_stream->tx_subflows[x].meta = cur_stream;
			cur_stream->tx_subflows[x].txmappings = rbt_create(sizeof(struct tdtcp_mapping), 
												                        &tdtcp_mapping_comp, 
												                        &tdtcp_mapping_comb,
												                        &tdtcp_mapping_alloc, 
												                        &tdtcp_mapping_free,
                                                NULL);
			cur_stream->tx_subflows[x].paced = TRUE;
			cur_stream->tx_subflows[x].pacer = NewPacketPacer();
			cur_stream->tx_subflows[x].pacer->rate_bps = 10000000000;
			cur_stream->tx_subflows[x].cwnd = ((cur_stream->sndvar->cwnd == 1)? 
				(cur_stream->tx_subflows[x].mss * TCP_INIT_CWND): cur_stream->tx_subflows[x].mss);
			cur_stream->tx_subflows[x].ssthresh = cur_stream->tx_subflows[x].mss * 10;
		}
	}
	cur_stream->curr_tx_subflow = mtcp->curr_tx_subflow;
	cur_stream->timeout_subflow = mtcp->curr_tx_subflow;
	cur_stream->seq_subflow_map = rbt_create(sizeof(struct tdtcp_seq2subflow_map), 
		                           &tdtcp_seq2subflow_comp, 
		                           &tdtcp_seq2subflow_comb,
		                           &tdtcp_seq2subflow_alloc,
		                           &tdtcp_seq2subflow_free, 
                               NULL);
	cur_stream->seq_cross_retrans = rbt_create(sizeof(struct tdtcp_xretrans_map), 
		                           &tdtcp_xretrans_comp, 
		                           &tdtcp_xretrans_comb,
		                           &tdtcp_xretrans_alloc,
		                           &tdtcp_xretrans_free,
                               NULL);
#endif

	cur_stream->sndvar->cwnd = ((cur_stream->sndvar->cwnd == 1)? 
			(cur_stream->sndvar->mss * TCP_INIT_CWND): cur_stream->sndvar->mss);
	cur_stream->sndvar->ssthresh = cur_stream->sndvar->mss * 10;
	UpdateRetransmissionTimer(mtcp, cur_stream, cur_ts);

	return TRUE;
}
/*----------------------------------------------------------------------------*/
/* ValidateSequence: validates sequence number of the segment                 */
/* Return: TRUE if acceptable, FALSE if not acceptable                        */
/*----------------------------------------------------------------------------*/
static inline int
ValidateSequence(mtcp_manager_t mtcp, tcp_stream *cur_stream, uint32_t cur_ts, 
		struct tcphdr *tcph, uint32_t seq, uint32_t ack_seq, int payloadlen)
{
	/* Protect Against Wrapped Sequence number (PAWS) */
	// TDTCP: leave this here. Implement RTT measurement 
	// in another method.
	if (!tcph->rst && cur_stream->saw_timestamp) {
		struct tcp_timestamp ts;
		
		if (!ParseTCPTimestamp(cur_stream, &ts, 
				(uint8_t *)tcph + TCP_HEADER_LEN, 
				(tcph->doff << 2) - TCP_HEADER_LEN)) {
			/* if there is no timestamp */
			/* TODO: implement here */
			TRACE_DBG("No timestamp found.\n");
			return FALSE;
		}

		/* RFC1323: if SEG.TSval < TS.Recent, drop and send ack */
		if (TCP_SEQ_LT(ts.ts_val, cur_stream->rcvvar->ts_recent)) {
			/* TODO: ts_recent should be invalidated 
					 before timestamp wraparound for long idle flow */
			TRACE_DBG("PAWS Detect wrong timestamp. "
					"seq: %u, ts_val: %u, prev: %u\n", 
					seq, ts.ts_val, cur_stream->rcvvar->ts_recent);
			EnqueueACK(mtcp, cur_stream, cur_ts, ACK_OPT_NOW);
			return FALSE;
		} else {
			/* valid timestamp */
			if (TCP_SEQ_GT(ts.ts_val, cur_stream->rcvvar->ts_recent)) {
				TRACE_TSTAMP("Timestamp update. cur: %u, prior: %u "
					"(time diff: %uus)\n", 
					ts.ts_val, cur_stream->rcvvar->ts_recent, 
					TS_TO_USEC(cur_ts - cur_stream->rcvvar->ts_last_ts_upd));
				cur_stream->rcvvar->ts_last_ts_upd = cur_ts;
			}

			cur_stream->rcvvar->ts_recent = ts.ts_val;
			cur_stream->rcvvar->ts_lastack_rcvd = ts.ts_ref;
		}
	}

	/* TCP sequence validation */
	if (!TCP_SEQ_BETWEEN(seq + payloadlen, cur_stream->rcv_nxt, 
				cur_stream->rcv_nxt + cur_stream->rcvvar->rcv_wnd)) {

		/* if RST bit is set, ignore the segment */
		if (tcph->rst)
			return FALSE;

		if (cur_stream->state == TCP_ST_ESTABLISHED) {
			/* check if it is to get window advertisement */
			if (seq + 1 == cur_stream->rcv_nxt) {
#if 0
				TRACE_DBG("Window update request. (seq: %u, rcv_wnd: %u)\n", 
						seq, cur_stream->rcvvar->rcv_wnd);
#endif
				EnqueueACK(mtcp, cur_stream, cur_ts, ACK_OPT_AGGREGATE);
				return FALSE;

			}

			if (TCP_SEQ_LEQ(seq, cur_stream->rcv_nxt)) {
				EnqueueACK(mtcp, cur_stream, cur_ts, ACK_OPT_AGGREGATE);
			} else {
				EnqueueACK(mtcp, cur_stream, cur_ts, ACK_OPT_NOW);
			}
		} else {
			if (cur_stream->state == TCP_ST_TIME_WAIT) {
				TRACE_DBG("Stream %d: tw expire update to %u\n", 
						cur_stream->id, cur_stream->rcvvar->ts_tw_expire);
				AddtoTimewaitList(mtcp, cur_stream, cur_ts);
			}
			AddtoControlList(mtcp, cur_stream, cur_ts);
		}
		return FALSE;
	}

	return TRUE;
}
/*----------------------------------------------------------------------------*/
static inline void 
NotifyConnectionReset(mtcp_manager_t mtcp, tcp_stream *cur_stream)
{
	TRACE_DBG("Stream %d: Notifying connection reset.\n", cur_stream->id);
	/* TODO: implement this function */
	/* signal to user "connection reset" */
}
/*----------------------------------------------------------------------------*/
static inline int 
ProcessRST(mtcp_manager_t mtcp, tcp_stream *cur_stream, uint32_t ack_seq)
{
	/* TODO: we need reset validation logic */
	/* the sequence number of a RST should be inside window */
	/* (in SYN_SENT state, it should ack the previous SYN */

	TRACE_DBG("Stream %d: TCP RESET (%s)\n", 
			cur_stream->id, TCPStateToString(cur_stream));
#if DUMP_STREAM
	DumpStream(mtcp, cur_stream);
#endif
	
	if (cur_stream->state <= TCP_ST_SYN_SENT) {
		/* not handled here */
		return FALSE;
	}

	if (cur_stream->state == TCP_ST_SYN_RCVD) {
		if (ack_seq == cur_stream->snd_nxt) {
			cur_stream->state = TCP_ST_CLOSED;
			cur_stream->close_reason = TCP_RESET;
			DestroyTCPStream(mtcp, cur_stream);
		}
		return TRUE;
	}

	/* if the application is already closed the connection, 
	   just destroy the it */
	if (cur_stream->state == TCP_ST_FIN_WAIT_1 || 
			cur_stream->state == TCP_ST_FIN_WAIT_2 || 
			cur_stream->state == TCP_ST_LAST_ACK || 
			cur_stream->state == TCP_ST_CLOSING || 
			cur_stream->state == TCP_ST_TIME_WAIT) {
		cur_stream->state = TCP_ST_CLOSED;
		cur_stream->close_reason = TCP_ACTIVE_CLOSE;
		DestroyTCPStream(mtcp, cur_stream);
		return TRUE;
	}

	if (cur_stream->state >= TCP_ST_ESTABLISHED && 
			cur_stream->state <= TCP_ST_CLOSE_WAIT) {
		/* ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2, CLOSE_WAIT */
		/* TODO: flush all the segment queues */
		//NotifyConnectionReset(mtcp, cur_stream);
	}

	if (!(cur_stream->sndvar->on_closeq || cur_stream->sndvar->on_closeq_int || 
				cur_stream->sndvar->on_resetq || cur_stream->sndvar->on_resetq_int)) {
		//cur_stream->state = TCP_ST_CLOSED;
		//DestroyTCPStream(mtcp, cur_stream);
		cur_stream->state = TCP_ST_CLOSE_WAIT;
		cur_stream->close_reason = TCP_RESET;
		RaiseCloseEvent(mtcp, cur_stream);
	}

	return TRUE;
}
/*----------------------------------------------------------------------------*/
inline void 
EstimateRTT(mtcp_manager_t mtcp, tcp_stream *cur_stream, uint32_t mrtt)
{
	/* This function should be called for not retransmitted packets */
	/* TODO: determine tcp_rto_min */
#define TCP_RTO_MIN 0
	long m = mrtt;
	uint32_t tcp_rto_min = TCP_RTO_MIN;
	struct tcp_recv_vars *rcvvar = cur_stream->rcvvar;

	if (m == 0) {
		m = 1;
	}
	if (rcvvar->srtt != 0) {
		/* rtt = 7/8 rtt + 1/8 new */
		m -= (rcvvar->srtt >> 3);
		rcvvar->srtt += m;
		if (m < 0) {
			m = -m;
			m -= (rcvvar->mdev >> 2);
			if (m > 0) {
				m >>= 3;
			}
		} else {
			m -= (rcvvar->mdev >> 2);
		}
		rcvvar->mdev += m;
		if (rcvvar->mdev > rcvvar->mdev_max) {
			rcvvar->mdev_max = rcvvar->mdev;
			if (rcvvar->mdev_max > rcvvar->rttvar) {
				rcvvar->rttvar = rcvvar->mdev_max;
			}
		}
		if (TCP_SEQ_GT(cur_stream->sndvar->snd_una, rcvvar->rtt_seq)) {
			if (rcvvar->mdev_max < rcvvar->rttvar) {
				rcvvar->rttvar -= (rcvvar->rttvar - rcvvar->mdev_max) >> 2;
			}
			rcvvar->rtt_seq = cur_stream->snd_nxt;
			rcvvar->mdev_max = tcp_rto_min;
		}
	} else {
		/* fresh measurement */
		rcvvar->srtt = m << 3;
		rcvvar->mdev = m << 1;
		rcvvar->mdev_max = rcvvar->rttvar = MAX(rcvvar->mdev, tcp_rto_min);
		rcvvar->rtt_seq = cur_stream->snd_nxt;
	}

	TRACE_RTT("mrtt: %u (%uus), srtt: %u (%ums), mdev: %u, mdev_max: %u, "
			"rttvar: %u, rtt_seq: %u\n", mrtt, mrtt * TIME_TICK, 
			rcvvar->srtt, TS_TO_MSEC((rcvvar->srtt) >> 3), rcvvar->mdev, 
			rcvvar->mdev_max, rcvvar->rttvar, rcvvar->rtt_seq);
}

/*----------------------------------------------------------------------------*/
static inline void
ProcessACK(mtcp_manager_t mtcp, tcp_stream *cur_stream, uint32_t cur_ts, 
		struct tcphdr *tcph, uint32_t seq, uint32_t ack_seq, 
		uint16_t window, int payloadlen)
{
	struct tcp_send_vars *sndvar = cur_stream->sndvar;
	uint32_t cwindow, cwindow_prev;
	uint32_t rmlen;
	uint32_t snd_wnd_prev;
	uint32_t right_wnd_edge;
	uint8_t dup;
	int ret;

	// TRACE_INFO("ProcessACK: ack_seq=%u, cur_stream->snd_nxt=%u\n", ack_seq, cur_stream->snd_nxt);
	cwindow = window;
	if (!tcph->syn) {
		cwindow = cwindow << sndvar->wscale_peer;
	}
	right_wnd_edge = sndvar->peer_wnd + cur_stream->rcvvar->snd_wl2;
	// TRACE_INFO("ProcessACK: ack_seq=%u, cur_stream->snd_nxt=%u\n", ack_seq, cur_stream->snd_nxt);

	/* If ack overs the sending buffer, return */
	if (cur_stream->state == TCP_ST_FIN_WAIT_1 || 
			cur_stream->state == TCP_ST_FIN_WAIT_2 ||
			cur_stream->state == TCP_ST_CLOSING || 
			cur_stream->state == TCP_ST_CLOSE_WAIT || 
			cur_stream->state == TCP_ST_LAST_ACK) {
		if (sndvar->is_fin_sent && ack_seq == sndvar->fss + 1) {
			ack_seq--;
		}
	}
	// TRACE_INFO("ProcessACK: ack_seq=%u, cur_stream->snd_nxt=%u\n", ack_seq, cur_stream->snd_nxt);
	
	if (TCP_SEQ_GT(ack_seq, sndvar->sndbuf->head_seq + sndvar->sndbuf->len)) {
		TRACE_DBG("Stream %d (%s): invalid acknologement. "
				"ack_seq: %u, possible max_ack_seq: %u\n", cur_stream->id, 
				TCPStateToString(cur_stream), ack_seq, 
				sndvar->sndbuf->head_seq + sndvar->sndbuf->len);
		// TRACE_INFO("ProcessACK: ack_seq=%u, cur_stream->snd_nxt=%u\n", ack_seq, cur_stream->snd_nxt);
		return;
	}
	// TRACE_INFO("ProcessACK: ack_seq=%u, cur_stream->snd_nxt=%u\n", ack_seq, cur_stream->snd_nxt);

	/* Update window */
	if (TCP_SEQ_LT(cur_stream->rcvvar->snd_wl1, seq) ||
			(cur_stream->rcvvar->snd_wl1 == seq && 
			TCP_SEQ_LT(cur_stream->rcvvar->snd_wl2, ack_seq)) ||
			(cur_stream->rcvvar->snd_wl2 == ack_seq && 
			cwindow > sndvar->peer_wnd)) {
		cwindow_prev = sndvar->peer_wnd;
		sndvar->peer_wnd = cwindow;
		cur_stream->rcvvar->snd_wl1 = seq;
		cur_stream->rcvvar->snd_wl2 = ack_seq;
		// TRACE_INFO("ProcessACK: ack_seq=%u, cur_stream->snd_nxt=%u\n", ack_seq, cur_stream->snd_nxt);
#if 0
		TRACE_CLWND("Window update. "
				"ack: %u, peer_wnd: %u, snd_nxt-snd_una: %u\n", 
				ack_seq, cwindow, cur_stream->snd_nxt - sndvar->snd_una);
#endif
		if (cwindow_prev < cur_stream->snd_nxt - sndvar->snd_una && 
				sndvar->peer_wnd >= cur_stream->snd_nxt - sndvar->snd_una) {
			TRACE_CLWND("%u Broadcasting client window update! "
					"ack_seq: %u, peer_wnd: %u (before: %u), "
					"(snd_nxt - snd_una: %u)\n", 
					cur_stream->id, ack_seq, sndvar->peer_wnd, cwindow_prev, 
					cur_stream->snd_nxt - sndvar->snd_una);
			RaiseWriteEvent(mtcp, cur_stream);
		}
	}
	// TRACE_INFO("ProcessACK: ack_seq=%u, cur_stream->snd_nxt=%u\n", ack_seq, cur_stream->snd_nxt);

	/* Check duplicated ack count */
	/* Duplicated ack if 
	   1) ack_seq is old
	   2) payload length is 0.
	   3) advertised window not changed.
	   4) there is outstanding unacknowledged data
	   5) ack_seq == snd_una
	 */

	dup = FALSE;
	if (TCP_SEQ_LT(ack_seq, cur_stream->snd_nxt)) {
		if (ack_seq == cur_stream->rcvvar->last_ack_seq && payloadlen == 0) {
			if (cur_stream->rcvvar->snd_wl2 + sndvar->peer_wnd == right_wnd_edge) {
				if (cur_stream->rcvvar->dup_acks + 1 > cur_stream->rcvvar->dup_acks) {
					cur_stream->rcvvar->dup_acks++;
#if USE_CCP
					ccp_record_event(mtcp, cur_stream, EVENT_DUPACK,
							 (cur_stream->snd_nxt - ack_seq));
#endif
				}
				// TRACE_INFO("ProcessACK: ack_seq=%u, cur_stream->snd_nxt=%u\n", ack_seq, cur_stream->snd_nxt);
				TRACE_INFO("DUP=true\n");
				dup = TRUE;
			}
		}
	}
	// TRACE_INFO("ProcessACK: ack_seq=%u, cur_stream->snd_nxt=%u\n", ack_seq, cur_stream->snd_nxt);
	if (!dup) {
#if USE_CCP
		if (cur_stream->rcvvar->dup_acks >= 3) {
			TRACE_DBG("passed dup_acks, ack=%u, snd_nxt=%u, last_ack=%u len=%u wl2=%u peer_wnd=%u right=%u\n",
				  ack_seq-sndvar->iss, cur_stream->snd_nxt-sndvar->iss, cur_stream->rcvvar->last_ack_seq-sndvar->iss,
				  payloadlen, cur_stream->rcvvar->snd_wl2-sndvar->iss, sndvar->peer_wnd / sndvar->mss,
				  right_wnd_edge - sndvar->iss);
		}
#endif
		cur_stream->rcvvar->dup_acks = 0;
		cur_stream->rcvvar->last_ack_seq = ack_seq;
		// TRACE_INFO("ProcessACK: ack_seq=%u, cur_stream->snd_nxt=%u\n", ack_seq, cur_stream->snd_nxt);
	}
#if USE_CCP
	if(cur_stream->wait_for_acks) {
		TRACE_DBG("got ack, but waiting to send... ack=%u, snd_next=%u cwnd=%u\n",
			  ack_seq-sndvar->iss, cur_stream->snd_nxt-sndvar->iss,
			  sndvar->cwnd / sndvar->mss);
	}
#endif
	/* Fast retransmission */
#if TDTCP_ENABLED
	if (dup && cur_stream->rcvvar->dup_acks == TDTCP_FLOW_RETX_THRESH) 
#else
	if (dup && cur_stream->rcvvar->dup_acks == 3) 
#endif
	{
		TRACE_INFO("Triple duplicated ACKs!! ack_seq: %u\n", ack_seq);
		// TRACE_INFO("ProcessACK: ack_seq=%u, cur_stream->snd_nxt=%u\n", ack_seq, cur_stream->snd_nxt);
		TRACE_CCP("tridup ack %u (%u)!\n", ack_seq - cur_stream->sndvar->iss, ack_seq);
		if (TCP_SEQ_LT(ack_seq, cur_stream->snd_nxt)) {
			TRACE_INFO("Reducing snd_nxt from %u to %u\n",
                                        cur_stream->snd_nxt-sndvar->iss,
                                        ack_seq - cur_stream->sndvar->iss);

#if RTM_STAT
			sndvar->rstat.tdp_ack_cnt++;
			sndvar->rstat.tdp_ack_bytes += (cur_stream->snd_nxt - ack_seq);
#endif

#if USE_CCP
			ccp_record_event(mtcp, cur_stream, EVENT_TRI_DUPACK, ack_seq);
#endif
			if (ack_seq != sndvar->snd_una) {
				TRACE_DBG("ack_seq and snd_una mismatch on tdp ack. "
						"ack_seq: %u, snd_una: %u\n", 
						ack_seq, sndvar->snd_una);
			}
#if USE_CCP
			sndvar->missing_seq = ack_seq;
#else
#if TDTCP_ENABLED
		struct tdtcp_seq2subflow_map s2ssearch = {.dsn = ack_seq};
		struct tdtcp_seq2subflow_map *s2smap = 
      (struct tdtcp_seq2subflow_map*)rbt_find(cur_stream->seq_subflow_map, (RBTNode*)&s2ssearch);
		if (s2smap) {
			struct tdtcp_txsubflow * tx = cur_stream->tx_subflows + s2smap->subflow_id;
			tx->snd_nxt = s2smap->ssn;
			AddtoRetxList(mtcp, tx);
			// TRACE_INFO("ProcessACK: ack_seq=%u, cur_stream->snd_nxt=%u\n", ack_seq, cur_stream->snd_nxt);
		}
		else {
			TRACE_ERROR("Can't find transmitted subflow for dsn %u\n", ack_seq);
			// TRACE_INFO("ProcessACK: ack_seq=%u, cur_stream->snd_nxt=%u\n", ack_seq, cur_stream->snd_nxt);
		}
#else 
			PRINT_CHANGE(cur_stream->snd_nxt, ack_seq);
			cur_stream->snd_nxt = ack_seq;
#endif
#endif
		}

		/* update congestion control variables */
		/* ssthresh to half of min of cwnd and peer wnd */
		sndvar->ssthresh = MIN(sndvar->cwnd, sndvar->peer_wnd) / 2;
		if (sndvar->ssthresh < 2 * sndvar->mss) {
			sndvar->ssthresh = 2 * sndvar->mss;
		}
		sndvar->cwnd = sndvar->ssthresh + 3 * sndvar->mss;
// TRACE_INFO("ProcessACK: ack_seq=%u, cur_stream->snd_nxt=%u\n", ack_seq, cur_stream->snd_nxt);
		TRACE_CONG("fast retrans: cwnd = ssthresh(%u)+3*mss = %u\n",
                                sndvar->ssthresh / sndvar->mss,
                                sndvar->cwnd / sndvar->mss);

		/* count number of retransmissions */
		if (sndvar->nrtx < TCP_MAX_RTX) {
			sndvar->nrtx++;
		} else {
			TRACE_DBG("Exceed MAX_RTX.\n");
		}
		// TRACE_INFO("ProcessACK: ack_seq=%u, cur_stream->snd_nxt=%u\n", ack_seq, cur_stream->snd_nxt);

		AddtoSendList(mtcp, cur_stream);

		// for TD reset every TDTCP_FLOW_RETX_THRESH acks
#if TDTCP_ENABLED
		cur_stream->rcvvar->dup_acks = 0;
#endif
	} 
	// well this actually doesn't matter...
#if TDTCP_ENABLED
	else if (cur_stream->rcvvar->dup_acks > TDTCP_FLOW_RETX_THRESH) 
#else
	else if (cur_stream->rcvvar->dup_acks > 3) 
#endif
	{
		/* Inflate congestion window until before overflow */
		if ((uint32_t)(sndvar->cwnd + sndvar->mss) > sndvar->cwnd) {
			sndvar->cwnd += sndvar->mss;
			TRACE_INFO("Dupack cwnd inflate. cwnd: %u, ssthresh: %u\n", 
					sndvar->cwnd, sndvar->ssthresh);
			// TRACE_INFO("ProcessACK: ack_seq=%u, cur_stream->snd_nxt=%u\n", ack_seq, cur_stream->snd_nxt);
		}
	}

#if TCP_OPT_SACK_ENABLED
	ParseSACKOption(cur_stream, ack_seq, (uint8_t *)tcph + TCP_HEADER_LEN, 
			(tcph->doff << 2) - TCP_HEADER_LEN);
#endif /* TCP_OPT_SACK_ENABLED */

#if RECOVERY_AFTER_LOSS
#if USE_CCP
	/* updating snd_nxt (when recovered from loss) */
	if (TCP_SEQ_GT(ack_seq, cur_stream->snd_nxt) ||
	    (cur_stream->wait_for_acks && TCP_SEQ_GT(ack_seq, cur_stream->seq_at_last_loss)
#if TCP_OPT_SACK_ENABLED 
		&& cur_stream->rcvvar->sacked_pkts == 0
#endif
	))
#else
        if (TCP_SEQ_GT(ack_seq, cur_stream->snd_nxt))
#endif /* USE_CCP */
	{
#if RTM_STAT
		sndvar->rstat.ack_upd_cnt++;
		sndvar->rstat.ack_upd_bytes += (ack_seq - cur_stream->snd_nxt);
#endif
		// fast retransmission exit: cwnd=ssthresh
		cur_stream->sndvar->cwnd = cur_stream->sndvar->ssthresh;
		// TRACE_INFO("ProcessACK: ack_seq=%u, cur_stream->snd_nxt=%u\n", ack_seq, cur_stream->snd_nxt);

		// TRACE_INFO("Updating snd_nxt from %u to %u\n", cur_stream->snd_nxt, ack_seq);
#if USE_CCP
		cur_stream->wait_for_acks = FALSE;
#endif

#if TDTCP_ENABLED
		struct tdtcp_seq2subflow_map s2ssearch = {.dsn = ack_seq};
		struct tdtcp_seq2subflow_map *s2smap = 
      (struct tdtcp_seq2subflow_map*)rbt_find(cur_stream->seq_subflow_map, (RBTNode*)&s2ssearch);
		if (s2smap) {
			tdtcp_txsubflow * tx = cur_stream->tx_subflows + s2smap->subflow_id;
			// TRACE_INFO("ProcessACK: ack_seq=%u, cur_stream->snd_nxt=%u\n", ack_seq, cur_stream->snd_nxt);
			AddtoRetxList(mtcp, tx);
			tx->snd_nxt = s2smap->ssn;
		}
		else {
			// TRACE_INFO("ProcessACK: ack_seq=%u, cur_stream->snd_nxt=%u\n", ack_seq, cur_stream->snd_nxt);
			TRACE_ERROR("Can't find transmitted subflow for dsn %u\n", ack_seq);
		}
#else 
		PRINT_CHANGE(cur_stream->snd_nxt, ack_seq);
		cur_stream->snd_nxt = ack_seq;
		// TRACE_INFO("ProcessACK: ack_seq=%u, cur_stream->snd_nxt=%u\n", ack_seq, cur_stream->snd_nxt);

		TRACE_DBG("Sending again..., ack_seq=%u sndlen=%u cwnd=%u\n",
                        ack_seq-sndvar->iss,
                        sndvar->sndbuf->len,
                        sndvar->cwnd / sndvar->mss);
		if (sndvar->sndbuf->len == 0) {
			RemoveFromSendList(mtcp, cur_stream);
		} else {
			AddtoSendList(mtcp, cur_stream);
		}
#endif
	}
#endif /* RECOVERY_AFTER_LOSS */

	rmlen = ack_seq - sndvar->sndbuf->head_seq;
	uint16_t packets = rmlen / sndvar->eff_mss;
	if (packets * sndvar->eff_mss > rmlen) {
		packets++;
	}
	// TRACE_INFO("ProcessACK: ack_seq=%u, cur_stream->snd_nxt=%u\n", ack_seq, cur_stream->snd_nxt);

#if USE_CCP
	ccp_cong_control(mtcp, cur_stream, ack_seq, rmlen, packets);
#else
	// log_cwnd_rtt(cur_stream);
#endif

	/* If ack_seq is previously acked, return */
	if (TCP_SEQ_GEQ(sndvar->sndbuf->head_seq, ack_seq)) {
		// TRACE_INFO("ProcessACK: ack_seq=%u, cur_stream->snd_nxt=%u\n", ack_seq, cur_stream->snd_nxt);
		return;
	}

	/* Remove acked sequence from send buffer */
	if (rmlen > 0) {
		/* Routine goes here only if there is new payload (not retransmitted) */
		
		/* Estimate RTT and calculate rto */
		if (cur_stream->saw_timestamp) {
			// TRACE_INFO("ProcessACK: ack_seq=%u, cur_stream->snd_nxt=%u\n", ack_seq, cur_stream->snd_nxt);
			EstimateRTT(mtcp, cur_stream, 
					cur_ts - cur_stream->rcvvar->ts_lastack_rcvd);
			sndvar->rto = (cur_stream->rcvvar->srtt >> 3) + cur_stream->rcvvar->rttvar;
			assert(sndvar->rto > 0);
		} else {
			//TODO: Need to implement timestamp estimation without timestamp
			TRACE_RTT("NOT IMPLEMENTED.\n");
		}

		// TODO CCP should comment this out? 
		/* Update congestion control variables */
		if (cur_stream->state >= TCP_ST_ESTABLISHED) {
			if (sndvar->cwnd < sndvar->ssthresh) {
				if ((sndvar->cwnd + sndvar->mss) > sndvar->cwnd) {
					sndvar->cwnd += (sndvar->mss * packets);
				}
				// TRACE_INFO("ProcessACK: ack_seq=%u, cur_stream->snd_nxt=%u\n", ack_seq, cur_stream->snd_nxt);
				TRACE_CONG("slow start cwnd: %u, ssthresh: %u\n", 
						sndvar->cwnd, sndvar->ssthresh);
			} else {
				uint32_t new_cwnd = sndvar->cwnd + 
						packets * sndvar->mss * sndvar->mss / 
						sndvar->cwnd;
				if (new_cwnd > sndvar->cwnd) {
					sndvar->cwnd = new_cwnd;
				}
				//TRACE_CONG("congestion avoidance cwnd: %u, ssthresh: %u\n", 
				//		sndvar->cwnd, sndvar->ssthresh);
			}
		}

		if (SBUF_LOCK(&sndvar->write_lock)) {
			if (errno == EDEADLK)
				perror("ProcessACK: write_lock blocked\n");
			assert(0);
		}
		ret = SBRemove(mtcp->rbm_snd, sndvar->sndbuf, rmlen);
		sndvar->snd_una = ack_seq;
		snd_wnd_prev = sndvar->snd_wnd;
		sndvar->snd_wnd = sndvar->sndbuf->size - sndvar->sndbuf->len;
		// TRACE_INFO("ProcessACK: ack_seq=%u, cur_stream->snd_nxt=%u\n", ack_seq, cur_stream->snd_nxt);

#if TDTCP_ENABLED
		// cleanup the subflow mapping and retx mapping
		struct tdtcp_seq2subflow_map * tnodes2s = 
			(struct tdtcp_seq2subflow_map *)(rbt_leftmost(cur_stream->seq_subflow_map));
		// DELETE UP TO
		while (tnodes2s && (tnodes2s->dsn) < ack_seq) {
			rbt_delete(cur_stream->seq_subflow_map, (RBTNode*)tnodes2s);
			tnodes2s = (struct tdtcp_seq2subflow_map *)(rbt_leftmost(cur_stream->seq_subflow_map));
		}

		struct tdtcp_xretrans_map * tnodexretrans = 
			(struct tdtcp_xretrans_map *)(rbt_leftmost(cur_stream->seq_cross_retrans));
		// DELETE UP TO
		while (tnodexretrans && (tnodexretrans->dsn) < ack_seq) {
			rbt_delete(cur_stream->seq_cross_retrans, (RBTNode*)tnodexretrans);
			tnodexretrans = (struct tdtcp_xretrans_map *)(rbt_leftmost(cur_stream->seq_cross_retrans));
		}
		// TRACE_INFO("ProcessACK: ack_seq=%u, cur_stream->snd_nxt=%u\n", ack_seq, cur_stream->snd_nxt);
#endif

		/* If there was no available sending window */
		/* notify the newly available window to application */
#if SELECTIVE_WRITE_EVENT_NOTIFY
		if (snd_wnd_prev <= 0) {
#endif /* SELECTIVE_WRITE_EVENT_NOTIFY */
			RaiseWriteEvent(mtcp, cur_stream);
#if SELECTIVE_WRITE_EVENT_NOTIFY
		}
#endif /* SELECTIVE_WRITE_EVENT_NOTIFY */

		SBUF_UNLOCK(&sndvar->write_lock);
		// TRACE_INFO("ProcessACK: ack_seq=%u, cur_stream->snd_nxt=%u\n", ack_seq, cur_stream->snd_nxt);
		UpdateRetransmissionTimer(mtcp, cur_stream, cur_ts);
	}
	// TRACE_INFO("ProcessACK exit: ack_seq=%u, cur_stream->snd_nxt=%u\n", ack_seq, cur_stream->snd_nxt);

	UNUSED(ret);
}
/*----------------------------------------------------------------------------*/
/* ProcessTCPPayload: merges TCP payload using receive ring buffer            */
/* Return: TRUE (1) in normal case, FALSE (0) if immediate ACK is required    */
/* CAUTION: should only be called at ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2      */
/*----------------------------------------------------------------------------*/
inline int 
ProcessTCPPayload(mtcp_manager_t mtcp, tcp_stream *cur_stream, 
		uint32_t cur_ts, uint8_t *payload, uint32_t seq, int payloadlen)
{
	struct tcp_recv_vars *rcvvar = cur_stream->rcvvar;
	uint32_t prev_rcv_nxt;
	int ret;

	/* if seq and segment length is lower than rcv_nxt, ignore and send ack 
	   BTW These should never happen for TDTCP as we have checked all these
	   in the subflow enqueue function. */
	if (TCP_SEQ_LT(seq + payloadlen, cur_stream->rcv_nxt)) {
#if TDTCP_ENABLED
		return ERROR;
#else 
		return FALSE;
#endif
	}
	/* if payload exceeds receiving buffer, drop and send ack */
	if (TCP_SEQ_GT(seq + payloadlen, cur_stream->rcv_nxt + rcvvar->rcv_wnd)) {
#if TDTCP_ENABLED
		return ERROR;
#else 
		return FALSE;
#endif
	}

	/* allocate receive buffer if not exist */
	if (!rcvvar->rcvbuf) {
		rcvvar->rcvbuf = RBInit(mtcp->rbm_rcv, rcvvar->irs + 1);
		if (!rcvvar->rcvbuf) {
			TRACE_ERROR("Stream %d: Failed to allocate receive buffer.\n", 
					cur_stream->id);
			cur_stream->state = TCP_ST_CLOSED;
			cur_stream->close_reason = TCP_NO_MEM;
			RaiseErrorEvent(mtcp, cur_stream);

			return ERROR;
		}
	}

	if (SBUF_LOCK(&rcvvar->read_lock)) {
		if (errno == EDEADLK)
			perror("ProcessTCPPayload: read_lock blocked\n");
		assert(0);
	}

	prev_rcv_nxt = cur_stream->rcv_nxt;
	ret = RBPut(mtcp->rbm_rcv, 
			rcvvar->rcvbuf, payload, (uint32_t)payloadlen, seq);
	if (ret < 0) {
		TRACE_ERROR("Cannot merge payload. reason: %d\n", ret);
	}

	/* discard the buffer if the state is FIN_WAIT_1 or FIN_WAIT_2, 
	   meaning that the connection is already closed by the application */
	if (cur_stream->state == TCP_ST_FIN_WAIT_1 || 
			cur_stream->state == TCP_ST_FIN_WAIT_2) {
		RBRemove(mtcp->rbm_rcv, 
				rcvvar->rcvbuf, rcvvar->rcvbuf->merged_len, AT_MTCP);
	}
	cur_stream->rcv_nxt = rcvvar->rcvbuf->head_seq + rcvvar->rcvbuf->merged_len;
#if !TDTCP_ENABLED
	rcvvar->rcv_wnd = rcvvar->rcvbuf->size - rcvvar->rcvbuf->merged_len;
#endif

	SBUF_UNLOCK(&rcvvar->read_lock);

	if (TCP_SEQ_LEQ(cur_stream->rcv_nxt, prev_rcv_nxt)) {
		/* There are some lost packets */
		return FALSE;
	}

	TRACE_EPOLL("Stream %d data arrived. "
			"len: %d, ET: %u, IN: %u, OUT: %u\n", 
			cur_stream->id, payloadlen, 
			cur_stream->socket? cur_stream->socket->epoll & MTCP_EPOLLET : 0, 
			cur_stream->socket? cur_stream->socket->epoll & MTCP_EPOLLIN : 0, 
			cur_stream->socket? cur_stream->socket->epoll & MTCP_EPOLLOUT : 0);

	if (cur_stream->state == TCP_ST_ESTABLISHED) {
		RaiseReadEvent(mtcp, cur_stream);
	}

	return TRUE;
}

/*----------------------------------------------------------------------------*/
static inline tcp_stream *
CreateNewFlowHTEntry(mtcp_manager_t mtcp, uint32_t cur_ts, const struct iphdr *iph, 
		int ip_len, const struct tcphdr* tcph, uint32_t seq, uint32_t ack_seq,
		int payloadlen, uint16_t window)
{
	tcp_stream *cur_stream;
	int ret; 
	
	if (tcph->syn && !tcph->ack) {
		/* handle the SYN */
		ret = FilterSYNPacket(mtcp, iph->daddr, tcph->dest);
		if (!ret) {
			TRACE_DBG("Refusing SYN packet.\n");
#ifdef DBGMSG
			DumpIPPacket(mtcp, iph, ip_len);
#endif
			SendTCPPacketStandalone(mtcp, 
					iph->daddr, tcph->dest, iph->saddr, tcph->source, 
					0, seq + payloadlen + 1, 0, TCP_FLAG_RST | TCP_FLAG_ACK, 
					NULL, 0, cur_ts, 0);

			return NULL;
		}

		/* now accept the connection */
		cur_stream = HandlePassiveOpen(mtcp, 
				cur_ts, iph, tcph, seq, window);
		if (!cur_stream) {
			TRACE_DBG("Not available space in flow pool.\n");
#ifdef DBGMSG
			DumpIPPacket(mtcp, iph, ip_len);
#endif
			SendTCPPacketStandalone(mtcp, 
					iph->daddr, tcph->dest, iph->saddr, tcph->source, 
					0, seq + payloadlen + 1, 0, TCP_FLAG_RST | TCP_FLAG_ACK, 
					NULL, 0, cur_ts, 0);

			return NULL;
		}

		return cur_stream;
	} else if (tcph->rst) {
		TRACE_DBG("Reset packet comes\n");
#ifdef DBGMSG
		DumpIPPacket(mtcp, iph, ip_len);
#endif
		/* for the reset packet, just discard */
		return NULL;
	} else {
		TRACE_DBG("Weird packet comes.\n");
#ifdef DBGMSG
		DumpIPPacket(mtcp, iph, ip_len);
#endif
		/* TODO: for else, discard and send a RST */
		/* if the ACK bit is off, respond with seq 0: 
		   <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>
		   else (ACK bit is on):
		   <SEQ=SEG.ACK><CTL=RST>
		   */
		if (tcph->ack) {
			SendTCPPacketStandalone(mtcp, 
					iph->daddr, tcph->dest, iph->saddr, tcph->source, 
					ack_seq, 0, 0, TCP_FLAG_RST, NULL, 0, cur_ts, 0);
		} else {
			SendTCPPacketStandalone(mtcp, 
					iph->daddr, tcph->dest, iph->saddr, tcph->source, 
					0, seq + payloadlen, 0, TCP_FLAG_RST | TCP_FLAG_ACK, 
					NULL, 0, cur_ts, 0);
		}
		return NULL;
	}
}
/*----------------------------------------------------------------------------*/
static inline void 
Handle_TCP_ST_LISTEN (mtcp_manager_t mtcp, uint32_t cur_ts, 
		tcp_stream* cur_stream, struct tcphdr* tcph) {
	
	if (tcph->syn) {
		if (cur_stream->state == TCP_ST_LISTEN)
			cur_stream->rcv_nxt++;
		cur_stream->state = TCP_ST_SYN_RCVD;
		TRACE_STATE("Stream %d: TCP_ST_SYN_RCVD\n", cur_stream->id);
		AddtoControlList(mtcp, cur_stream, cur_ts);
	} else {
		CTRACE_ERROR("Stream %d (TCP_ST_LISTEN): "
				"Packet without SYN.\n", cur_stream->id);
	}

}
/*----------------------------------------------------------------------------*/
static inline void 
Handle_TCP_ST_SYN_SENT (mtcp_manager_t mtcp, uint32_t cur_ts, 
		tcp_stream* cur_stream, const struct iphdr* iph, struct tcphdr* tcph,
		uint32_t seq, uint32_t ack_seq, int payloadlen, uint16_t window)
{
	/* when active open */
	if (tcph->ack) {
		/* filter the unacceptable acks */
		if (TCP_SEQ_LEQ(ack_seq, cur_stream->sndvar->iss) || 
				TCP_SEQ_GT(ack_seq, cur_stream->snd_nxt)) {
			if (!tcph->rst) {
				SendTCPPacketStandalone(mtcp, 
						iph->daddr, tcph->dest, iph->saddr, tcph->source, 
						ack_seq, 0, 0, TCP_FLAG_RST, NULL, 0, cur_ts, 0);
			}
			return;
		}
		/* accept the ack */
		cur_stream->sndvar->snd_una++;
	}
	
	if (tcph->rst) {
		if (tcph->ack) {
			cur_stream->state = TCP_ST_CLOSE_WAIT;
			cur_stream->close_reason = TCP_RESET;
			if (cur_stream->socket) {
				RaiseErrorEvent(mtcp, cur_stream);
			} else {
				DestroyTCPStream(mtcp, cur_stream);
			}
		}
		return;
	}

	if (tcph->syn) {
		if (tcph->ack) {
			int ret = HandleActiveOpen(mtcp, 
					cur_stream, cur_ts, tcph, seq, ack_seq, window);
			if (!ret) {
				return;
			}
			
			cur_stream->sndvar->nrtx = 0;
			cur_stream->rcv_nxt = cur_stream->rcvvar->irs + 1;
			RemoveFromRTOList(mtcp, cur_stream);
			cur_stream->state = TCP_ST_ESTABLISHED;
			TRACE_STATE("Stream %d: TCP_ST_ESTABLISHED\n", cur_stream->id);

			if (cur_stream->socket) {
				RaiseWriteEvent(mtcp, cur_stream);
			} else {
				TRACE_STATE("Stream %d: ESTABLISHED, but no socket\n", cur_stream->id);
				SendTCPPacketStandalone(mtcp, 
						iph->daddr, tcph->dest, iph->saddr, tcph->source, 
						0, seq + payloadlen + 1, 0, TCP_FLAG_RST | TCP_FLAG_ACK, 
						NULL, 0, cur_ts, 0);
				cur_stream->close_reason = TCP_ACTIVE_CLOSE;
				DestroyTCPStream(mtcp, cur_stream);
				return;
			}
			AddtoControlList(mtcp, cur_stream, cur_ts);
			if (CONFIG.tcp_timeout > 0)
				AddtoTimeoutList(mtcp, cur_stream);

		} else {
			cur_stream->state = TCP_ST_SYN_RCVD;
			TRACE_STATE("Stream %d: TCP_ST_SYN_RCVD\n", cur_stream->id);
			PRINT_CHANGE(cur_stream->snd_nxt, cur_stream->sndvar->iss);
			cur_stream->snd_nxt = cur_stream->sndvar->iss;
			AddtoControlList(mtcp, cur_stream, cur_ts);
		}
	}
}
/*----------------------------------------------------------------------------*/
static inline void 
Handle_TCP_ST_SYN_RCVD (mtcp_manager_t mtcp, uint32_t cur_ts,
		tcp_stream* cur_stream, struct tcphdr* tcph, uint32_t ack_seq) 
{
	struct tcp_send_vars *sndvar = cur_stream->sndvar;
	int ret;
	if (tcph->ack) {
		struct tcp_listener *listener;
		uint32_t prior_cwnd;
		/* check if ACK of SYN */
		if (ack_seq != sndvar->iss + 1) {
			CTRACE_ERROR("Stream %d (TCP_ST_SYN_RCVD): "
					"weird ack_seq: %u, iss: %u\n", 
					cur_stream->id, ack_seq, sndvar->iss);
			TRACE_DBG("Stream %d (TCP_ST_SYN_RCVD): "
					"weird ack_seq: %u, iss: %u\n", 
					cur_stream->id, ack_seq, sndvar->iss);
			return;
		}

		sndvar->snd_una++;
		PRINT_CHANGE(cur_stream->snd_nxt, ack_seq);
		cur_stream->snd_nxt = ack_seq;
		prior_cwnd = sndvar->cwnd;
		sndvar->cwnd = ((prior_cwnd == 1)? 
				(sndvar->mss * TCP_INIT_CWND): sndvar->mss);
		TRACE_DBG("sync_recvd: updating cwnd from %u to %u\n", prior_cwnd, sndvar->cwnd);
		
		//UpdateRetransmissionTimer(mtcp, cur_stream, cur_ts);
		sndvar->nrtx = 0;
		cur_stream->rcv_nxt = cur_stream->rcvvar->irs + 1;
		RemoveFromRTOList(mtcp, cur_stream);

		cur_stream->state = TCP_ST_ESTABLISHED;
		TRACE_STATE("Stream %d: TCP_ST_ESTABLISHED\n", cur_stream->id);

		/* update listening socket */
		listener = (struct tcp_listener *)ListenerHTSearch(mtcp->listeners, &tcph->dest);

		ret = StreamEnqueue(listener->acceptq, cur_stream);
		if (ret < 0) {
			TRACE_ERROR("Stream %d: Failed to enqueue to "
					"the listen backlog!\n", cur_stream->id);
			cur_stream->close_reason = TCP_NOT_ACCEPTED;
			cur_stream->state = TCP_ST_CLOSED;
			TRACE_STATE("Stream %d: TCP_ST_CLOSED\n", cur_stream->id);
			AddtoControlList(mtcp, cur_stream, cur_ts);
		}
		//TRACE_DBG("Stream %d inserted into acceptq.\n", cur_stream->id);
		if (CONFIG.tcp_timeout > 0)
			AddtoTimeoutList(mtcp, cur_stream);

		/* raise an event to the listening socket */
		if (listener->socket && (listener->socket->epoll & MTCP_EPOLLIN)) {
			AddEpollEvent(mtcp->ep, 
					MTCP_EVENT_QUEUE, listener->socket, MTCP_EPOLLIN);
		}

	} else {
		TRACE_DBG("Stream %d (TCP_ST_SYN_RCVD): No ACK.\n", 
				cur_stream->id);
		/* retransmit SYN/ACK */
		PRINT_CHANGE(cur_stream->snd_nxt, sndvar->iss);
		cur_stream->snd_nxt = sndvar->iss;

		AddtoControlList(mtcp, cur_stream, cur_ts);
	}
}
/*----------------------------------------------------------------------------*/
static inline void 
Handle_TCP_ST_ESTABLISHED (mtcp_manager_t mtcp, uint32_t cur_ts,
		tcp_stream* cur_stream, struct tcphdr* tcph, uint32_t seq, uint32_t ack_seq,
		uint8_t *payload, int payloadlen, uint16_t window) 
{

  TRACE_INFO("Handle_TCP_ST_ESTABLISHED\n");
#if TDTCP_ENABLED
	ParseTCPOptions(cur_stream, cur_ts, (uint8_t *)tcph + TCP_HEADER_LEN, 
		(tcph->doff << 2) - TCP_HEADER_LEN);
#endif

	if (tcph->syn) {
		TRACE_INFO("Stream %d (TCP_ST_ESTABLISHED): weird SYN. "
				"seq: %u, expected: %u, ack_seq: %u, expected: %u\n", 
				cur_stream->id, seq, cur_stream->rcv_nxt, 
				ack_seq, cur_stream->snd_nxt);
		PRINT_CHANGE(cur_stream->snd_nxt, ack_seq);
		cur_stream->snd_nxt = ack_seq;
		AddtoControlList(mtcp, cur_stream, cur_ts);
		return;
	}

	if (payloadlen > 0) {
#if TDTCP_ENABLED
		if (cur_stream->tddss_pass && cur_stream->tddss_pass->hasdata) {
			ProcessTCPPayloadSubflow(mtcp, cur_stream, cur_ts, 
				payload, seq, payloadlen);
				// ntohl(cur_stream->tddss_pass->subseq), 
				// cur_stream->tddss_pass->dsubflow, 
				// cur_stream->tddss_pass->dcarrier
		}
		else {
			TRACE_ERROR("TDTCP received payload > 0 but without hasdata flag\n");
		}
#else
		if (ProcessTCPPayload(mtcp, cur_stream, 
				cur_ts, payload, seq, payloadlen)) {
			/* if return is TRUE, send ACK */
			EnqueueACK(mtcp, cur_stream, cur_ts, ACK_OPT_AGGREGATE);
		} else {
			EnqueueACK(mtcp, cur_stream, cur_ts, ACK_OPT_NOW);
		}
#endif
	}
#if !TDTCP_ENABLED
	if (tcph->ack) {
		if (cur_stream->sndvar->sndbuf) {
			ProcessACK(mtcp, cur_stream, cur_ts, 
					tcph, seq, ack_seq, window, payloadlen);
		}
	}

#else
	if (cur_stream->tddss_pass && cur_stream->tddss_pass->hasack) {
		ProcessACKSubflow(mtcp, cur_stream, cur_ts, tcph);
			// ntohl(cur_stream->tddss_pass->suback), 
			// cur_stream->tddss_pass->asubflow, 
			// cur_stream->tddss_pass->acarrier);
		if (tcph->ack) {
			if (cur_stream->sndvar->sndbuf) {
				ProcessACK(mtcp, cur_stream, cur_ts, 
						tcph, seq, ack_seq, window, payloadlen);
		}
	} else if (tcph->ack) {
		MarkEmptyAckIncomming();
	}

	}
#endif
	

	if (tcph->fin) {
		/* process the FIN only if the sequence is valid */
		/* FIN packet is allowed to push payload (should we check for PSH flag)? */
		if (seq + payloadlen == cur_stream->rcv_nxt) {
			cur_stream->state = TCP_ST_CLOSE_WAIT;
			TRACE_STATE("Stream %d: TCP_ST_CLOSE_WAIT\n", cur_stream->id);
			cur_stream->rcv_nxt++;
			AddtoControlList(mtcp, cur_stream, cur_ts);

			/* notify FIN to application */
			RaiseReadEvent(mtcp, cur_stream);
		} else {
			EnqueueACK(mtcp, cur_stream, cur_ts, ACK_OPT_NOW);
			return;
		}
	}
}
/*----------------------------------------------------------------------------*/
static inline void 
Handle_TCP_ST_CLOSE_WAIT (mtcp_manager_t mtcp, uint32_t cur_ts, 
		tcp_stream* cur_stream, struct tcphdr* tcph, uint32_t seq, uint32_t ack_seq, 
		int payloadlen, uint16_t window) 
{
	if (TCP_SEQ_LT(seq, cur_stream->rcv_nxt)) {
		TRACE_DBG("Stream %d (TCP_ST_CLOSE_WAIT): "
				"weird seq: %u, expected: %u\n", 
				cur_stream->id, seq, cur_stream->rcv_nxt);
		AddtoControlList(mtcp, cur_stream, cur_ts);
		return;
	}

	if (cur_stream->sndvar->sndbuf) {
		ProcessACK(mtcp, cur_stream, cur_ts, 
				tcph, seq, ack_seq, window, payloadlen);
	}
}
/*----------------------------------------------------------------------------*/
static inline void 
Handle_TCP_ST_LAST_ACK (mtcp_manager_t mtcp, uint32_t cur_ts, const struct iphdr *iph,
		int ip_len, tcp_stream* cur_stream, struct tcphdr* tcph, 
		uint32_t seq, uint32_t ack_seq, int payloadlen, uint16_t window) 
{

	if (TCP_SEQ_LT(seq, cur_stream->rcv_nxt)) {
		TRACE_DBG("Stream %d (TCP_ST_LAST_ACK): "
				"weird seq: %u, expected: %u\n", 
				cur_stream->id, seq, cur_stream->rcv_nxt);
		return;
	}

	if (tcph->ack) {
		if (cur_stream->sndvar->sndbuf) {
			ProcessACK(mtcp, cur_stream, cur_ts, 
					tcph, seq, ack_seq, window, payloadlen);
		}

		if (!cur_stream->sndvar->is_fin_sent) {
			/* the case that FIN is not sent yet */
			/* this is not ack for FIN, ignore */
			TRACE_DBG("Stream %d (TCP_ST_LAST_ACK): "
					"No FIN sent yet.\n", cur_stream->id);
#ifdef DBGMSG
			DumpIPPacket(mtcp, iph, ip_len);
#endif
#if DUMP_STREAM
			DumpStream(mtcp, cur_stream);
			DumpControlList(mtcp, mtcp->n_sender[0]);
#endif
			return;
		}

		/* check if ACK of FIN */
		if (ack_seq == cur_stream->sndvar->fss + 1) {
			cur_stream->sndvar->snd_una++;
			UpdateRetransmissionTimer(mtcp, cur_stream, cur_ts);
			cur_stream->state = TCP_ST_CLOSED;
			cur_stream->close_reason = TCP_PASSIVE_CLOSE;
			TRACE_STATE("Stream %d: TCP_ST_CLOSED\n", 
					cur_stream->id);
			DestroyTCPStream(mtcp, cur_stream);
		} else {
			TRACE_DBG("Stream %d (TCP_ST_LAST_ACK): Not ACK of FIN. "
					"ack_seq: %u, expected: %u\n", 
					cur_stream->id, ack_seq, cur_stream->sndvar->fss + 1);
			//cur_stream->snd_nxt = cur_stream->sndvar->fss;
			AddtoControlList(mtcp, cur_stream, cur_ts);
		}
	} else {
		CTRACE_ERROR("Stream %d (TCP_ST_LAST_ACK): No ACK\n", 
				cur_stream->id);
		//cur_stream->snd_nxt = cur_stream->sndvar->fss;
		AddtoControlList(mtcp, cur_stream, cur_ts);
	}
}
/*----------------------------------------------------------------------------*/
static inline void 
Handle_TCP_ST_FIN_WAIT_1 (mtcp_manager_t mtcp, uint32_t cur_ts,
		tcp_stream* cur_stream, struct tcphdr* tcph, uint32_t seq, uint32_t ack_seq, 
		uint8_t *payload, int payloadlen, uint16_t window) 
{
#if TDTCP_ENABLED
	ParseTCPOptions(cur_stream, cur_ts, (uint8_t *)tcph + TCP_HEADER_LEN, 
		(tcph->doff << 2) - TCP_HEADER_LEN);
#endif

	if (TCP_SEQ_LT(seq, cur_stream->rcv_nxt)) {
		TRACE_DBG("Stream %d (TCP_ST_LAST_ACK): "
				"weird seq: %u, expected: %u\n", 
				cur_stream->id, seq, cur_stream->rcv_nxt);
		AddtoControlList(mtcp, cur_stream, cur_ts);
		return;
	}

	if (tcph->ack) {
		if (cur_stream->sndvar->sndbuf) {
			ProcessACK(mtcp, cur_stream, cur_ts, 
					tcph, seq, ack_seq, window, payloadlen);
		}

#if TDTCP_ENABLED
		if (cur_stream->tddss_pass && cur_stream->tddss_pass->hasack) {
			ProcessACKSubflow(mtcp, cur_stream, cur_ts, tcph);
				// ntohl(cur_stream->tddss_pass->suback), 
				// cur_stream->tddss_pass->asubflow, 
				// cur_stream->tddss_pass->acarrier);
		}
#endif

		if (cur_stream->sndvar->is_fin_sent && 
				ack_seq == cur_stream->sndvar->fss + 1) {
			cur_stream->sndvar->snd_una = ack_seq;
			if (TCP_SEQ_GT(ack_seq, cur_stream->snd_nxt)) {
				TRACE_DBG("Stream %d: update snd_nxt to %u\n", 
						cur_stream->id, ack_seq);
				PRINT_CHANGE(cur_stream->snd_nxt, ack_seq);
				cur_stream->snd_nxt = ack_seq;

			}
			//cur_stream->sndvar->snd_una++;
			//UpdateRetransmissionTimer(mtcp, cur_stream, cur_ts);
			cur_stream->sndvar->nrtx = 0;
			RemoveFromRTOList(mtcp, cur_stream);
			cur_stream->state = TCP_ST_FIN_WAIT_2;
			TRACE_STATE("Stream %d: TCP_ST_FIN_WAIT_2\n", 
					cur_stream->id);
		}

	} else {
		TRACE_DBG("Stream %d: does not contain an ack!\n", 
				cur_stream->id);
		return;
	}

	if (payloadlen > 0) {
		if (ProcessTCPPayload(mtcp, cur_stream, 
				cur_ts, payload, seq, payloadlen)) {
			/* if return is TRUE, send ACK */
			EnqueueACK(mtcp, cur_stream, cur_ts, ACK_OPT_AGGREGATE);
		} else {
			EnqueueACK(mtcp, cur_stream, cur_ts, ACK_OPT_NOW);
		}
	}

	if (tcph->fin) {
		/* process the FIN only if the sequence is valid */
		/* FIN packet is allowed to push payload (should we check for PSH flag)? */
		if (seq + payloadlen == cur_stream->rcv_nxt) {
			cur_stream->rcv_nxt++;

			if (cur_stream->state == TCP_ST_FIN_WAIT_1) {
				cur_stream->state = TCP_ST_CLOSING;
				TRACE_STATE("Stream %d: TCP_ST_CLOSING\n", cur_stream->id);

			} else if (cur_stream->state == TCP_ST_FIN_WAIT_2) {
				cur_stream->state = TCP_ST_TIME_WAIT;
				TRACE_STATE("Stream %d: TCP_ST_TIME_WAIT\n", cur_stream->id);
				AddtoTimewaitList(mtcp, cur_stream, cur_ts);
			}
			AddtoControlList(mtcp, cur_stream, cur_ts);
		}
	}
}
/*----------------------------------------------------------------------------*/
static inline void 
Handle_TCP_ST_FIN_WAIT_2 (mtcp_manager_t mtcp, uint32_t cur_ts,
		tcp_stream* cur_stream, struct tcphdr* tcph, uint32_t seq, uint32_t ack_seq,
		uint8_t *payload, int payloadlen, uint16_t window)
{
#if TDTCP_ENABLED
	ParseTCPOptions(cur_stream, cur_ts, (uint8_t *)tcph + TCP_HEADER_LEN, 
		(tcph->doff << 2) - TCP_HEADER_LEN);
#endif
	
	if (tcph->ack) {
		if (cur_stream->sndvar->sndbuf) {
			ProcessACK(mtcp, cur_stream, cur_ts, 
					tcph, seq, ack_seq, window, payloadlen);
		}

#if TDTCP_ENABLED
		if (cur_stream->tddss_pass && cur_stream->tddss_pass->hasack) {
			ProcessACKSubflow(mtcp, cur_stream, cur_ts, tcph);
				// ntohl(cur_stream->tddss_pass->suback), 
				// cur_stream->tddss_pass->asubflow, 
				// cur_stream->tddss_pass->acarrier);
		}
#endif

	} else {
		TRACE_DBG("Stream %d: does not contain an ack!\n", 
				cur_stream->id);
		return;
	}

	if (payloadlen > 0) {
		if (ProcessTCPPayload(mtcp, cur_stream, 
				cur_ts, payload, seq, payloadlen)) {
			/* if return is TRUE, send ACK */
			EnqueueACK(mtcp, cur_stream, cur_ts, ACK_OPT_AGGREGATE);
		} else {
			EnqueueACK(mtcp, cur_stream, cur_ts, ACK_OPT_NOW);
		}
	}

	if (tcph->fin) {
		/* process the FIN only if the sequence is valid */
		/* FIN packet is allowed to push payload (should we check for PSH flag)? */
		if (seq + payloadlen == cur_stream->rcv_nxt) {
			cur_stream->state = TCP_ST_TIME_WAIT;
			cur_stream->rcv_nxt++;
			TRACE_STATE("Stream %d: TCP_ST_TIME_WAIT\n", cur_stream->id);

			AddtoTimewaitList(mtcp, cur_stream, cur_ts);
			AddtoControlList(mtcp, cur_stream, cur_ts);
		}
#if 0
	} else {
		TRACE_DBG("Stream %d (TCP_ST_FIN_WAIT_2): No FIN. "
				"seq: %u, ack_seq: %u, snd_nxt: %u, snd_una: %u\n", 
				cur_stream->id, seq, ack_seq, 
				cur_stream->snd_nxt, cur_stream->sndvar->snd_una);
#if DBGMSG
		DumpIPPacket(mtcp, iph, ip_len);
#endif
#endif
	}

}
/*----------------------------------------------------------------------------*/
static inline void
Handle_TCP_ST_CLOSING (mtcp_manager_t mtcp, uint32_t cur_ts, 
		tcp_stream* cur_stream, struct tcphdr* tcph, uint32_t seq, uint32_t ack_seq,
		int payloadlen, uint16_t window) {

	if (tcph->ack) {
		if (cur_stream->sndvar->sndbuf) {
			ProcessACK(mtcp, cur_stream, cur_ts, 
					tcph, seq, ack_seq, window, payloadlen);
		}

		if (!cur_stream->sndvar->is_fin_sent) {
			TRACE_DBG("Stream %d (TCP_ST_CLOSING): "
					"No FIN sent yet.\n", cur_stream->id);
			return;
		}

		// check if ACK of FIN
		if (ack_seq != cur_stream->sndvar->fss + 1) {
#if 0
			CTRACE_ERROR("Stream %d (TCP_ST_CLOSING): Not ACK of FIN. "
					"ack_seq: %u, snd_nxt: %u, snd_una: %u, fss: %u\n", 
					cur_stream->id, ack_seq, cur_stream->snd_nxt, 
					cur_stream->sndvar->snd_una, cur_stream->sndvar->fss);
			DumpIPPacketToFile(stderr, iph, ip_len);
			DumpStream(mtcp, cur_stream);
#endif
			//assert(0);
			/* if the packet is not the ACK of FIN, ignore */
			return;
		}
		
		cur_stream->sndvar->snd_una = ack_seq;
		PRINT_CHANGE(cur_stream->snd_nxt, ack_seq);
		cur_stream->snd_nxt = ack_seq;
		UpdateRetransmissionTimer(mtcp, cur_stream, cur_ts);

		cur_stream->state = TCP_ST_TIME_WAIT;
		TRACE_STATE("Stream %d: TCP_ST_TIME_WAIT\n", cur_stream->id);
		
		AddtoTimewaitList(mtcp, cur_stream, cur_ts);

	} else {
		CTRACE_ERROR("Stream %d (TCP_ST_CLOSING): Not ACK\n", 
				cur_stream->id);
		return;
	}
}
/*----------------------------------------------------------------------------*/
int
ProcessTCPPacket(mtcp_manager_t mtcp, 
		 uint32_t cur_ts, const int ifidx, const struct iphdr *iph, int ip_len)
{
	struct tcphdr* tcph = (struct tcphdr *) ((u_char *)iph + (iph->ihl << 2));
	uint8_t *payload    = (uint8_t *)tcph + (tcph->doff << 2);
	int payloadlen = ip_len - (payload - (u_char *)iph);
	tcp_stream s_stream;
	tcp_stream *cur_stream = NULL;
	uint32_t seq = ntohl(tcph->seq);
	uint32_t ack_seq = ntohl(tcph->ack_seq);
	uint16_t window = ntohs(tcph->window);
	uint16_t check;
	int ret;
	int rc = -1;

	fprintf(stderr, "Receiving\n");
	PrintTCPHeader((uint8_t*)tcph);
	/* Check ip packet invalidation */	
	if (ip_len < ((iph->ihl + tcph->doff) << 2)) {
    TRACE_INFO("ip len error!\n");
		return ERROR;
  }

#if VERIFY_RX_CHECKSUM
#ifndef DISABLE_HWCSUM
	if (mtcp->iom->dev_ioctl != NULL)
		rc = mtcp->iom->dev_ioctl(mtcp->ctx, ifidx,
					  PKT_RX_TCP_CSUM, NULL);
#endif
	if (rc == -1) {
		check = TCPCalcChecksum((uint16_t *)tcph, 
					(tcph->doff << 2) + payloadlen, iph->saddr, iph->daddr);
		if (check) {
			TRACE_DBG("Checksum Error: Original: 0x%04x, calculated: 0x%04x\n", 
				  tcph->check, TCPCalcChecksum((uint16_t *)tcph, 
				  (tcph->doff << 2) + payloadlen, iph->saddr, iph->daddr));
			tcph->check = 0;
      TRACE_INFO("TCP Checksum error!\n");
			return ERROR;
		}
	}
#endif

#if defined(NETSTAT) && defined(ENABLELRO)
	mtcp->nstat.rx_gdptbytes += payloadlen;
#endif /* NETSTAT */

	s_stream.saddr = iph->daddr;
	s_stream.sport = tcph->dest;
	s_stream.daddr = iph->saddr;
	s_stream.dport = tcph->source;

	if (!(cur_stream = StreamHTSearch(mtcp->tcp_flow_table, &s_stream))) {
		/* not found in flow table */
		cur_stream = CreateNewFlowHTEntry(mtcp, cur_ts, iph, ip_len, tcph, 
				seq, ack_seq, payloadlen, window);
		if (!cur_stream)
			return TRUE;
	}

	/* Validate sequence. if not valid, ignore the packet */
	if (cur_stream->state > TCP_ST_SYN_RCVD) {
		ret = ValidateSequence(mtcp, cur_stream, 
				cur_ts, tcph, seq, ack_seq, payloadlen);
		if (!ret) {
			TRACE_DBG("Stream %d: Unexpected sequence: %u, expected: %u\n",
					cur_stream->id, seq, cur_stream->rcv_nxt);
#ifdef DBGMSG
			DumpIPPacket(mtcp, iph, ip_len);
#endif
#ifdef DUMP_STREAM
			DumpStream(mtcp, cur_stream);
#endif
			return TRUE;
		}
	}

	/* Update receive window size */
	if (tcph->syn) {
		cur_stream->sndvar->peer_wnd = window;
	} else {
		cur_stream->sndvar->peer_wnd = 
				(uint32_t)window << cur_stream->sndvar->wscale_peer;
	}
				
	cur_stream->last_active_ts = cur_ts;
	UpdateTimeoutList(mtcp, cur_stream);

	/* Process RST: process here only if state > TCP_ST_SYN_SENT */
	if (tcph->rst) {
		cur_stream->have_reset = TRUE;
		if (cur_stream->state > TCP_ST_SYN_SENT) {
			if (ProcessRST(mtcp, cur_stream, ack_seq)) {
				return TRUE;
			}
		}
	}

  TRACE_INFO("Switching state, state is %s!\n", TCPStateToString(cur_stream));
	switch (cur_stream->state) {

	case TCP_ST_LISTEN:
		Handle_TCP_ST_LISTEN(mtcp, cur_ts, cur_stream, tcph);
		break;

	case TCP_ST_SYN_SENT:
		Handle_TCP_ST_SYN_SENT(mtcp, cur_ts, cur_stream, iph, tcph, 
				seq, ack_seq, payloadlen, window);
		break;

	case TCP_ST_SYN_RCVD:
		/* SYN retransmit implies our SYN/ACK was lost. Resend */
		if (tcph->syn && seq == cur_stream->rcvvar->irs)
			Handle_TCP_ST_LISTEN(mtcp, cur_ts, cur_stream, tcph);
		else {
			Handle_TCP_ST_SYN_RCVD(mtcp, cur_ts, cur_stream, tcph, ack_seq);
			if (payloadlen > 0 && cur_stream->state == TCP_ST_ESTABLISHED) {
				Handle_TCP_ST_ESTABLISHED(mtcp, cur_ts, cur_stream, tcph,
							  seq, ack_seq, payload,
							  payloadlen, window);
			}
		}
		break;

	case TCP_ST_ESTABLISHED:
		Handle_TCP_ST_ESTABLISHED(mtcp, cur_ts, cur_stream, tcph, 
				seq, ack_seq, payload, payloadlen, window);
		break;

	case TCP_ST_CLOSE_WAIT:
		Handle_TCP_ST_CLOSE_WAIT(mtcp, cur_ts, cur_stream, tcph, seq, ack_seq,
				payloadlen, window);
		break;

	case TCP_ST_LAST_ACK:
		Handle_TCP_ST_LAST_ACK(mtcp, cur_ts, iph, ip_len, cur_stream, tcph, 
				seq, ack_seq, payloadlen, window);
		break;
	
	case TCP_ST_FIN_WAIT_1:
		Handle_TCP_ST_FIN_WAIT_1(mtcp, cur_ts, cur_stream, tcph, seq, ack_seq,
				payload, payloadlen, window);
		break;

	case TCP_ST_FIN_WAIT_2:
		Handle_TCP_ST_FIN_WAIT_2(mtcp, cur_ts, cur_stream, tcph, seq, ack_seq, 
				payload, payloadlen, window);
		break;

	case TCP_ST_CLOSING:
		Handle_TCP_ST_CLOSING(mtcp, cur_ts, cur_stream, tcph, seq, ack_seq,
				payloadlen, window);
		break;

	case TCP_ST_TIME_WAIT:
		/* the only thing that can arrive in this state is a retransmission 
		   of the remote FIN. Acknowledge it, and restart the 2 MSL timeout */
		if (cur_stream->on_timewait_list) {
			RemoveFromTimewaitList(mtcp, cur_stream);
			AddtoTimewaitList(mtcp, cur_stream, cur_ts);
		}
		AddtoControlList(mtcp, cur_stream, cur_ts);
		break;

	case TCP_ST_CLOSED:
		break;

	}
	TRACE_INFO("cur_stream->snd_nxt=%u\n", cur_stream->snd_nxt);

	return TRUE;
}
