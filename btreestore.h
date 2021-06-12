#ifndef BTREESTORE_H
#define BTREESTORE_H

#include <stdint.h>
#include <stddef.h>

struct info {
    uint32_t size;
    uint32_t key[4];
    uint64_t nonce;
    void * data;
};

struct node {
    uint16_t num_keys;
    uint32_t * keys;
};

struct kv_pair {
    uint32_t key;
    uint32_t size;
    uint32_t encryption_key[4];
    uint64_t nonce;
    void * data;
};

struct tree_node {
    uint16_t num_keys;
    struct kv_pair * pairs;
    struct tree_node * parent;
    struct tree_node * children;
};


void * init_store(uint16_t branching, uint8_t n_processors);

void post_order_clean(struct tree_node * root);

void close_store(void * helper);

int btree_insert(uint32_t key, void * plaintext, size_t count, uint32_t encryption_key[4], uint64_t nonce, void * helper);

int btree_retrieve(uint32_t key, struct info * found, void * helper);

int btree_decrypt(uint32_t key, void * output, void * helper);

void swap_key(struct tree_node * node1, int key_index1, struct tree_node * node2, int key_index2);

void delete_key_from_leaf_node(struct tree_node * node, int key_index);

struct kv_pair* delete_key_from_leaf_node_with_return(struct tree_node * node, int key_index);

void insert_key_into_leaf_node(struct tree_node * leaf_node, struct kv_pair * kv);

void move_key_to_leaf(struct tree_node *source_node, int key_index, struct tree_node * leaf_node);

void merge_from_left(struct tree_node * left_node, struct tree_node * right_node, struct tree_node * parent, int inter_key_idx);

void merge_from_right(struct tree_node * left_node, struct tree_node * right_node, struct tree_node * parent, int inter_key_idx);

void move_c_from_right_to_left(struct tree_node * left_node, struct tree_node * right_node);

void move_c_from_left_to_right(struct tree_node * left_node, struct tree_node * right_node);

int pre_order(struct tree_node * root, int count, struct node ** ls);

int pre_order_count(struct tree_node * root, int count);

int btree_delete(uint32_t key, void * helper);

uint64_t btree_export(void * helper, struct node ** list);

void encrypt_tea(uint32_t plain[2], uint32_t cipher[2], uint32_t key[4]);

void decrypt_tea(uint32_t cipher[2], uint32_t plain[2], uint32_t key[4]);

void encrypt_tea_ctr(uint64_t * plain, uint32_t key[4], uint64_t nonce, uint64_t * cipher, uint32_t num_blocks);

void decrypt_tea_ctr(uint64_t * cipher, uint32_t key[4], uint64_t nonce, uint64_t * plain, uint32_t num_blocks);

#endif
