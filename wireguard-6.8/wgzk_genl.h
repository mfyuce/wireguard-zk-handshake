/* wgzk_genl.h - WireGuard ZK Generic Netlink interface */
#ifndef _WGZK_GENL_H
#define _WGZK_GENL_H

/* Initialize the wg-zk Generic Netlink family */
int wgzk_genl_init(void);

/* Tear down the wg-zk Generic Netlink family */
void wgzk_genl_exit(void);

void wgzk_multicast_need_proof(struct net *netns, u32 ifindex,
                               u64 peer_id, const u8 *peer_pub, u32 token,
                               const u8 r[32], const u8 s[32]);
/* Gateway verify flow: kernel -> userspace (r/s/nonce are from the ZK packet) */
void wgzk_multicast_need_verify(struct net *netns, u32 ifindex,
                                u32 sender_index, u32 token,
                                const u8 r[32], const u8 s[32],
                                const u8 nonce[32]);
#endif /* _WGZK_GENL_H */
