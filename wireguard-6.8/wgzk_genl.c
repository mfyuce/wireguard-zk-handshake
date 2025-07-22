// wgzk_genl.c

#include <linux/kernel.h>
#include <linux/netlink.h>
#include <net/genetlink.h>

#include "peer.h"
#include "zk_pending.h"

extern struct hlist_head zk_pending_table[];
extern spinlock_t zk_lock;

//
// Attribute enum
//
enum {
	WGZK_ATTR_UNSPEC,
	WGZK_ATTR_PEER_INDEX,
	WGZK_ATTR_RESULT,
	__WGZK_ATTR_MAX,
};
#define WGZK_ATTR_MAX (__WGZK_ATTR_MAX - 1)

//
// Command enum
//
enum {
    WGZK_CMD_UNSPEC,
	WGZK_CMD_VERIFY,
    __WGZK_CMD_MAX,
};
#define WGZK_CMD_MAX (__WGZK_CMD_MAX - 1)

//
// Attribute policy
//
static const struct nla_policy wgzk_genl_policy[WGZK_ATTR_MAX + 1] = {
	[WGZK_ATTR_PEER_INDEX] = { .type = NLA_U32 },
	[WGZK_ATTR_RESULT]     = { .type = NLA_U8 },
};

//
// VERIFY handler
//
static int wgzk_verify_handler(struct sk_buff *skb, struct genl_info *info)
{
    u32 sender_index;
    u8 result;
    struct zk_pending_entry *entry = NULL;
    bool found = false;

    if (!info->attrs[WGZK_ATTR_PEER_INDEX] || !info->attrs[WGZK_ATTR_RESULT])
        return -EINVAL;

    sender_index = nla_get_u32(info->attrs[WGZK_ATTR_PEER_INDEX]);
    result = nla_get_u8(info->attrs[WGZK_ATTR_RESULT]);

    pr_info("WG-ZK: Received ZK result=%u for index=%u\n", result, sender_index);

	// Search for matching pending entry
    spin_lock_bh(&zk_lock);
    hash_for_each_possible(zk_pending_table, entry, node, sender_index) {
        if (entry->sender_index == sender_index) {
			hash_del(&entry->node);
            found = true;
            break;
        }
    }
    spin_unlock_bh(&zk_lock);

    if (!found) {
        pr_warn("WG-ZK: Unknown or expired sender_index=%u\n", sender_index);
        return -ENOENT;
    }

    // ZK proof accepted
    if (result == 1 && entry->peer) {
        struct wg_peer *peer = entry->peer;
		char peer_name[INET6_ADDRSTRLEN + 8] = "(unknown)";

        // Trigger response
        handshake_send_response(peer);

        // Logging like core WireGuard
        snprintf(peer_name, sizeof(peer_name), "%pISpf", &peer->endpoint.addr);
		net_dbg_ratelimited("WG-ZK: Handshake response sent to %s for peer index=%u\n",
                            peer_name, sender_index);
    } else {
        // ZK proof rejected
		pr_info("WG-ZK: Proof failed or rejected — dropping peer %u\n", sender_index);
		// Optionally: wg_peer_remove(entry->peer);
    }

	kfree(entry);
    return 0;
}

//
// Command dispatch table
//
static const struct genl_ops wgzk_genl_ops[] = {
	{
		.cmd = WGZK_CMD_VERIFY,
		.flags = 0,
		.policy = wgzk_genl_policy,
		.doit = wgzk_verify_handler,
	},
};

//
// Family registration
//
static struct genl_family wgzk_genl_family = {
	.name     = "wgzk",
	.version  = 1,
	.maxattr  = WGZK_ATTR_MAX,
	.module   = THIS_MODULE,
	.ops      = wgzk_genl_ops,
	.n_ops    = ARRAY_SIZE(wgzk_genl_ops),
};

//
// Called by wireguard's wg_device_init()
//
int wgzk_genl_init(void)
{
	int ret = genl_register_family(&wgzk_genl_family);
	if (ret)
		pr_err("WG-ZK: Failed to register netlink family\n");
	else
		pr_info("WG-ZK: Generic Netlink interface registered\n");
	return ret;
}

void wgzk_genl_exit(void)
{
	genl_unregister_family(&wgzk_genl_family);
	pr_info("WG-ZK: Generic Netlink interface unregistered\n");
}
