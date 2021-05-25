#include "btreestore.h"

void * init_store(uint16_t branching, uint8_t n_processors) {
    // Your code here
    return NULL;
}

void close_store(void * helper) {
    // Your code here
    return;
}

int btree_insert(uint32_t key, void * plaintext, size_t count, uint32_t encryption_key[4], uint64_t nonce, void * helper) {
    // Your code here
    return -1;
}

int btree_retrieve(uint32_t key, struct info * found, void * helper) {
    // Your code here
    return -1;
}

int btree_decrypt(uint32_t key, void * output, void * helper) {
    // Your code here
    return -1;
}

int btree_delete(uint32_t key, void * helper) {
    // Your code here
    return -1;
}

uint64_t btree_export(void * helper, struct node ** list) {
    // Your code here
    return 0;
}

void encrypt_tea(uint32_t plain[2], uint32_t cipher[2], uint32_t key[4]) {
    // Your code here
    return;
}

void decrypt_tea(uint32_t cipher[2], uint32_t plain[2], uint32_t key[4]) {
    // Your code here
    return;
}

void encrypt_tea_ctr(uint64_t * plain, uint32_t key[4], uint64_t nonce, uint64_t * cipher, uint32_t num_blocks) {
    // Your code here
    return;
}

void decrypt_tea_ctr(uint64_t * cipher, uint32_t key[4], uint64_t nonce, uint64_t * plain, uint32_t num_blocks) {
    // Your code here
    return;
}
