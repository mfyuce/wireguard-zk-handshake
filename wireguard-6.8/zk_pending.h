#ifndef ZK_PENDING_H
#define ZK_PENDING_H

#include <linux/types.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include "peer.h"

struct zk_pending_entry {
	struct hlist_node node;
	u32 sender_index;
	struct wg_peer *peer;
	u64 created_ns;
};

extern struct hlist_head zk_pending_table[];
extern spinlock_t zk_lock;

void zk_pending_add(u32 sender_index, struct wg_peer *peer);
struct wg_peer *zk_pending_get(u32 sender_index);
void zk_pending_cleanup_expired(void);

void zk_pending_init_cleanup_timer(void);
void zk_pending_cleanup_timer_exit(void);

#endif
