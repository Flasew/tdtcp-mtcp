/*-------------------------------------------------------------------------
 *
 * rbtree.h
 *    adopted from PostgreSQL RBTree library. License follows:
 *
 * PostgreSQL Database Management System
 * (formerly known as Postgres, then as Postgres95)
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * 
 * Portions Copyright (c) 1994, The Regents of the University of California
 * 
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose, without fee, and without a written agreement
 * is hereby granted, provided that the above copyright notice and this
 * paragraph and the following two paragraphs appear in all copies.
 * 
 * IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO ANY PARTY FOR
 * DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING
 * LOST PROFITS, ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS
 * DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA HAS BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 * 
 * THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS
 * ON AN "AS IS" BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATIONS TO
 * PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS.
 *
 *
 *-------------------------------------------------------------------------
 */
#ifndef RBTREE_H
#define RBTREE_H

#include <stdbool.h>
#include <stddef.h>
/*
 * RBTNode is intended to be used as the first field of a larger struct,
 * whose additional fields carry whatever payload data the caller needs
 * for a tree entry.  (The total size of that larger struct is passed to
 * rbt_create.) RBTNode is declared here to support this usage, but
 * callers must treat it as an opaque struct.
 */
typedef struct RBTNode
{
    char color;                 /* node's current color, red or black */
    struct RBTNode *left;       /* left child, or RBTNIL if none */
    struct RBTNode *right;      /* right child, or RBTNIL if none */
    struct RBTNode *parent;     /* parent, or NULL (not RBTNIL!) if none */
} RBTNode;

/* Opaque struct representing a whole tree */
typedef struct RBTree RBTree;

/* Available tree iteration orderings */
typedef enum RBTOrderControl
{
    LeftRightWalk,              /* inorder: left child, node, right child */
    RightLeftWalk               /* reverse inorder: right, node, left */
} RBTOrderControl;

/*
 * RBTreeIterator holds state while traversing a tree.  This is declared
 * here so that callers can stack-allocate this, but must otherwise be
 * treated as an opaque struct.
 */
typedef struct RBTreeIterator RBTreeIterator;

struct RBTreeIterator
{
    RBTree     *rbt;
    RBTNode    *(*iterate) (RBTreeIterator *iter);
    RBTNode    *last_visited;
    bool        is_over;
};

/* Support functions to be provided by caller */
typedef int (*rbt_comparator) (const RBTNode *a, const RBTNode *b, void *arg);
typedef void (*rbt_combiner) (RBTNode *existing, const RBTNode *newdata, void *arg);
typedef RBTNode *(*rbt_allocfunc) (void *arg);
typedef void (*rbt_freefunc) (RBTNode *x, void *arg);

extern RBTree *rbt_create(size_t node_size,
                          rbt_comparator comparator,
                          rbt_combiner combiner,
                          rbt_allocfunc allocfunc,
                          rbt_freefunc freefunc,
                          void *arg);

extern RBTNode *rbt_find(RBTree *rbt, const RBTNode *data);
extern RBTNode *rbt_leftmost(RBTree *rbt);
extern RBTNode *rbt_rightmost(RBTree *rbt);

extern RBTNode *rbt_insert(RBTree *rbt, const RBTNode *data, bool *isNew);
extern void rbt_delete(RBTree *rbt, RBTNode *node);

extern void rbt_begin_iterate(RBTree *rbt, RBTOrderControl ctrl,
                              RBTreeIterator *iter);
extern RBTNode *rbt_iterate(RBTreeIterator *iter);
extern void rbt_free(RBTree * tree);
// extern void * rbt_delete_upto(RBTree * rbt, const RBTNode * bound);

#endif                          /* RBTREE_H */