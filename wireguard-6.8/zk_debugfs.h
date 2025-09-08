#ifndef WG_ZK_DEBUGFS_H
#define WG_ZK_DEBUGFS_H

#include <linux/types.h>
#include <linux/debugfs.h>
#include <linux/debugfs.h>
#include <linux/dcache.h>   /* for debugfs_lookup() */

int zk_debugfs_init(struct dentry *parent);
void zk_debugfs_cleanup(void);
int wgzk_debugfs_add_device(struct wg_device *wg);
#endif /* WG_ZK_DEBUGFS_H */
