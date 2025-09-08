#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>
#include <linux/seq_file.h>
#include <linux/atomic.h>
#include <linux/string.h>
#include "zk_pending.h"
#include "zk_debugfs.h"


#include "device.h"
static struct dentry *parent;  // module-global
static int zk_require_proof_show(struct seq_file *m, void *v)
{
    struct wg_device *wg = m->private;
    if (!wg) return -ENOENT;
    seq_printf(m, "%u\n", READ_ONCE(wg->zk_require_proof) ? 1 : 0);
    return 0;
}

static int zk_require_proof_open(struct inode *inode, struct file *file)
{
    /* Pass wg_device* as m->private */
    return single_open(file, zk_require_proof_show, inode->i_private);
}

static const struct file_operations zk_require_proof_fops = {
    .owner   = THIS_MODULE,
    .open    = zk_require_proof_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = single_release,
};
int zk_debugfs_init(struct dentry *wg_dbg_dir){
    parent = wg_dbg_dir;
    return 0;
}
int wgzk_debugfs_add_device(struct wg_device *wg)
{
    struct dentry *dir = parent;
    if (!dir) return -ENOENT;
    if (!debugfs_create_file("zk_require_proof", 0444, dir, wg,
                             &zk_require_proof_fops))
        return -ENOMEM;
    return 0;
}

void zk_debugfs_cleanup(void) {
}
