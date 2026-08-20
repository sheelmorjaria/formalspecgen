/* Synthetic legacy VFS fixture: Apache-2.0, purpose-built for extraction. */
#define VFS_INODE_CAPACITY 4

struct list_head {
    struct list_head *next;
    struct list_head *prev;
};

struct rb_node {
    struct rb_node *left;
    struct rb_node *right;
};

struct hlist_node {
    struct hlist_node *next;
    struct hlist_node **pprev;
};

struct legacy_inode {
    int open_count;
    struct list_head free_links;
    struct rb_node directory_index;
    struct hlist_node name_hash;
};
