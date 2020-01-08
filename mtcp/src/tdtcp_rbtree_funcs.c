/**
 * Implementation of rbtree functions used in tdtcp.
 */
#include "rbtree.h"
#include "tdtcp.h"
#include "tcp_in.h"
#include "debug.h"

/*** mappings */
#define MAP_SSN(node) (((struct tdtcp_mapping *)(node))->ssn)
#define MAP_DSN(node) (((struct tdtcp_mapping *)(node))->dsn)

int tdtcp_mapping_comp(const RBTNode *a, const RBTNode *b, void *arg) {
  if (TCP_SEQ_LT(MAP_SSN(a), MAP_SSN(b))) {
    return -1; 
  }
  else if (MAP_SSN(a) == MAP_SSN(b)) {
    return 0;
  }
  return 1;
}

void tdtcp_mapping_comb (RBTNode *existing, const RBTNode *newdata, void *arg) {
  TRACE_ERROR("Inserting duplicated mapping, ssn=%u, "
    "dsn_existing=%u, dsn_new=%u - this shouldn't happen.\n", 
    MAP_SSN(existing), MAP_DSN(existing), MAP_DSN(newdata));
}

RBTNode * tdtcp_mapping_alloc (void *arg) {
  struct tdtcp_mapping * newmap = malloc(sizeof(struct tdtcp_mapping));
  return (RBTNode*)newmap;
}

void tdtcp_mapping_free (RBTNode *x, void *arg) {
  free((struct tdtcp_mapping *)x);
}

/*** sequence to subflow map */
#define S2S_DSN(node) (((struct tdtcp_seq2subflow_map *)(node))->dsn)
#define S2S_SUBF(node) (((struct tdtcp_seq2subflow_map *)(sub))->subflow_id)

int tdtcp_seq2subflow_comp(const RBTNode *a, const RBTNode *b, void *arg) {
  if (TCP_SEQ_LT(S2S_DSN(a), S2S_DSN(b))) {
    return -1; 
  }
  else if (S2S_DSN(a) == S2S_DSN(b)) {
    return 0;
  }
  return 1;
}

void tdtcp_seq2subflow_comb(RBTNode *existing, const RBTNode *newdata, void *arg) {
  TRACE_ERROR("Inserting duplicated dsn to subflow mapping, dsn=%u, "
    "subf_existing=%u, subf_new=%u - this shouldn't happen.\n", 
    S2S_DSN(existing), S2S_SUBF(existing), S2S_SUBF(newdata));
}

RBTNode * tdtcp_seq2subflow_alloc(void *arg) {
  struct tdtcp_seq2subflow_map * newmap = malloc(sizeof(struct tdtcp_seq2subflow_map));
  return (RBTNode *)newmap;
}

void tdtcp_seq2subflow_free(RBTNode *x, void *arg){
  free((struct tdtcp_seq2subflow_map *)x);
}

/*** Cross subflow retransmit map */
#define XRETRANS_DSN(node) (((struct tdtcp_xretrans_map *)(node))->dsn)
#define XRETRANS_CONTAINER(node) ((struct tdtcp_xretrans_map *)(node)) 

int tdtcp_xretrans_comp(const RBTNode *a, const RBTNode *b, void *arg) {
    if (TCP_SEQ_LT(XRETRANS_DSN(a), XRETRANS_DSN(b))) {
    return -1; 
  }
  else if (XRETRANS_DSN(a) == XRETRANS_DSN(b)) {
    return 0;
  }
  return 1;
}

void tdtcp_xretrans_comb(RBTNode *existing, const RBTNode *newdata, void *arg) {
  for (int i = 0; i < TDTCP_TX_NSUBFLOWS; i++) {
    XRETRANS_CONTAINER(existing)->subflow_sz[i] += XRETRANS_CONTAINER(newdata)->subflow_sz[i];
  }
}

RBTNode * tdtcp_xretrans_alloc(void *arg) {
  struct tdtcp_xretrans_map * newmap = malloc(sizeof(struct tdtcp_xretrans_map));
  return (RBTNode *) newmap; 
}

void tdtcp_xretrans_free(RBTNode *x, void *arg) {
  free(XRETRANS_CONTAINER(x));
}



