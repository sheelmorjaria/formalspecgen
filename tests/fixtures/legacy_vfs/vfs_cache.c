#include "vfs_cache.h"

void inode_open(struct legacy_inode *inode, struct list_head *free_inodes) {
    if (inode->open_count < VFS_INODE_CAPACITY) {
        list_del(&inode->free_links);
        inode->open_count++;
    }
}

void inode_close(struct legacy_inode *inode, struct list_head *free_inodes) {
    if (inode->open_count > 0) {
        inode->open_count--;
        list_add(&inode->free_links, free_inodes);
    }
}
