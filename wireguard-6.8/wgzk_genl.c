// wgzk_genl.c

#include <linux/kernel.h>
#include <linux/netlink.h>
#include <net/genetlink.h>

#include "peer.h"
#include "zk_pending.h"
#include "wgzk_genl.h"
#include "zk_proof.h"
// + include for ifindex helper
#include <linux/netdevice.h>

struct wg_peer *wg_noise_handshake_consume_initiation(void *raw_msg,
                                                      struct wg_device *wg);
void wg_packet_send_handshake_response(struct wg_peer *peer);
static int wgzk_set_proof_handler(struct sk_buff *skb, struct genl_info *info);

extern struct hlist_head zk_pending_table[];
extern spinlock_t zk_lock;

//
// Attribute enum
//
enum {
	WGZK_ATTR_UNSPEC,
	WGZK_ATTR_PEER_INDEX,
	WGZK_ATTR_RESULT,
    /* new: for setting proof */
    WGZK_ATTR_PEER_ID,   /* NLA_U64: peer->internal_id (initiator)*/
    WGZK_ATTR_R,         /* NLA_BINARY, len=32 */
    WGZK_ATTR_S,         /* NLA_BINARY, len=32 */
    WGZK_ATTR_IFINDEX,   /* u32: netdev ifindex (initiator interface) */
    WGZK_ATTR_PEER_PUB,  /* bin[32]: optional, remote static pk */
    WGZK_ATTR_TOKEN,     /* u32: optional correlation */
	__WGZK_ATTR_MAX,
};
#define WGZK_ATTR_MAX (__WGZK_ATTR_MAX - 1)

//
// Command enum
//
enum {
    WGZK_CMD_UNSPEC,
	WGZK_CMD_VERIFY,
    WGZK_CMD_SET_PROOF,
    WGZK_CMD_NEED_PROOF,   /* multicast event */
    __WGZK_CMD_MAX,
};
#define WGZK_CMD_MAX (__WGZK_CMD_MAX - 1)

//
// Attribute policy
//
static const struct nla_policy wgzk_genl_policy[WGZK_ATTR_MAX + 1] = {
	[WGZK_ATTR_PEER_INDEX] = { .type = NLA_U32 },
	[WGZK_ATTR_RESULT]     = { .type = NLA_U8 },
    [WGZK_ATTR_PEER_ID]    = { .type = NLA_U64 },
    [WGZK_ATTR_R]          = { .type = NLA_BINARY, .len = 32 },
    [WGZK_ATTR_S]          = { .type = NLA_BINARY, .len = 32 },
    [WGZK_ATTR_IFINDEX]    = { .type = NLA_U32 },
    [WGZK_ATTR_PEER_PUB]   = { .type = NLA_BINARY, .len = 32 },
    [WGZK_ATTR_TOKEN]      = { .type = NLA_U32 },
};

/* === Define one multicast group === */
enum { WGZK_MCGRP_EVENTS, __WGZK_MCGRP_MAX };
static const struct genl_multicast_group wgzk_mcgrps[] = {
    [WGZK_MCGRP_EVENTS] = { .name = "events" },
};
//
// VERIFY handler
//
static int wgzk_verify_handler(struct sk_buff *skb, struct genl_info *info) {
    u32 sender_index;
    u8 result;
    struct zk_pending_entry *entry = NULL;

    if (!info->attrs[WGZK_ATTR_PEER_INDEX] || !info->attrs[WGZK_ATTR_RESULT])
        return -EINVAL;

    sender_index = nla_get_u32(info->attrs[WGZK_ATTR_PEER_INDEX]);
    result = nla_get_u8(info->attrs[WGZK_ATTR_RESULT]);

    pr_info("WG-ZK: Received ZK result=%u for index=%u\n", result, sender_index);

    /* Ask pending subsystem to remove & return the entry atomically */
    entry = zk_pending_take(sender_index);
    if (!entry) {
        pr_warn("WG-ZK: Unknown or expired sender_index=%u\n", sender_index);
        return -ENOENT;
    }

    // ZK proof accepted
    if (result == 1) {
        struct wg_peer *peer = NULL;
        if (entry->raw && entry->wg) {
            struct message_handshake_initiation *norm = (void *)entry->raw;
            norm->header.type = cpu_to_le32(MESSAGE_HANDSHAKE_INITIATION);
            /* Re-run the normal handshake path; it will decrypt static,
             * bind to the correct peer, and return it on success. */
            peer = wg_noise_handshake_consume_initiation(entry->raw, entry->wg);
        }
        if (!IS_ERR(peer) && peer) {
            wg_packet_send_handshake_response(peer);
            net_dbg_ratelimited("WG-ZK: Proof accepted; response sent to %pISpf (idx=%u)\n",
                                &peer->endpoint.addr, sender_index);
        } else {
            pr_warn("WG-ZK: Re-consume failed for idx=%u\n", sender_index);
        }
    } else {
        // ZK proof rejected
        pr_info("WG-ZK: Proof failed or rejected — dropping peer %u\n", sender_index);
        // Optionally: wg_peer_remove(entry->peer);
    }

    kfree(entry->raw);
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
    {
        .cmd = WGZK_CMD_SET_PROOF,
        .flags = 0,
        .policy = wgzk_genl_policy,
        .doit = wgzk_set_proof_handler,
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
    .mcgrps   = wgzk_mcgrps,
    .n_mcgrps = ARRAY_SIZE(wgzk_mcgrps),
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

static int wgzk_set_proof_handler(struct sk_buff *skb, struct genl_info *info)
{
    u64 peer_id;
    u8 *r, *s;

    if (!info->attrs[WGZK_ATTR_PEER_ID] ||
        !info->attrs[WGZK_ATTR_R] ||
        !info->attrs[WGZK_ATTR_S])
        return -EINVAL;

    if (nla_len(info->attrs[WGZK_ATTR_R]) != 32 ||
        nla_len(info->attrs[WGZK_ATTR_S]) != 32)
        return -EINVAL;

    peer_id = nla_get_u64(info->attrs[WGZK_ATTR_PEER_ID]);
    r = nla_data(info->attrs[WGZK_ATTR_R]);
    s = nla_data(info->attrs[WGZK_ATTR_S]);

    zk_proof_set(peer_id, r, s);
    pr_info("WG-ZK: cached proof for peer_id=%llu\n",
            (unsigned long long)peer_id);
    return 0;
}
/* Multicast NEED_PROOF{IFINDEX, PEER_ID, PEER_PUB?, TOKEN?} */
static void wgzk_multicast_need_proof(struct net *netns, u32 ifindex,
                                      u64 peer_id, const u8 *peer_pub, u32 token)
{
    struct sk_buff *skb;
    void *hdr;

    skb = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_ATOMIC);
    if (!skb)
        return;

    hdr = genlmsg_put(skb, 0, 0, &wgzk_genl_family, 0, WGZK_CMD_NEED_PROOF);
    if (!hdr) { kfree_skb(skb); return; }

    nla_put_u32(skb, WGZK_ATTR_IFINDEX, ifindex);
    nla_put_u64_64bit(skb, WGZK_ATTR_PEER_ID, peer_id, WGZK_ATTR_UNSPEC);
    if (peer_pub)
        nla_put(skb, WGZK_ATTR_PEER_PUB, 32, peer_pub);
    if (token)
        nla_put_u32(skb, WGZK_ATTR_TOKEN, token);

    genlmsg_end(skb, hdr);
    genlmsg_multicast_netns(&wgzk_genl_family, netns, skb,
                            0 /*portid*/, WGZK_MCGRP_EVENTS, GFP_ATOMIC);
}
