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
    // plain contains the 64 bit plaintext
    uint32_t sum = 0;
    uint32_t delta = 0x9E3779B9;
    cipher[0] = plain[0];
    cipher[1] = plain[1];
    // loop 1024 times:
    for (int i = 0; i < 1024; i++) {
        sum = (sum + delta);
        uint32_t tmp1 = ((cipher[1] << 4) + key[0]);
        uint32_t tmp2 = (cipher[1] + sum);
        uint32_t tmp3 = ((cipher[1] >> 5) + key[1]);
        cipher[0] = (cipher[0] + (tmp1 ^ tmp2 ^ tmp3)); 
        uint32_t tmp4 = ((cipher[0] << 4) + key[2]);
        uint32_t tmp5 = (cipher[0] + sum);
        uint32_t tmp6 = ((cipher[0] >> 5) + key[3]);
        cipher[1] = (cipher[1] + (tmp4 ^ tmp5 ^ tmp6));
    }
    return;
}

void decrypt_tea(uint32_t cipher[2], uint32_t plain[2], uint32_t key[4]) {
    uint32_t sum = 0xDDE6E400;
    uint32_t delta = 0x9E3779B9;
    for (int i = 0; i < 1024; i++) {
        uint32_t tmp4 = ((cipher[0] << 4) + key[2]);
        uint32_t tmp5 = (cipher[0] + sum);
        uint32_t tmp6 = ((cipher[0] >> 5) + key[3]);
        cipher[1] = (cipher[1] - (tmp4 ^ tmp5 ^ tmp6));
        uint32_t tmp1 = ((cipher[1] << 4) + key[0]);
        uint32_t tmp2 = (cipher[1] + sum);
        uint32_t tmp3 = ((cipher[1] >> 5) + key[1]);
        cipher[0] = (cipher[0] - (tmp1 ^ tmp2 ^ tmp3));
        sum = (sum - delta);
        plain[0] = cipher[0];
        plain[1] = cipher[1];
        // plain now contains the 64 bit plaintext
    }
    return;
}

void encrypt_tea_ctr(uint64_t * plain, uint32_t key[4], uint64_t nonce, uint64_t * cipher, uint32_t num_blocks) {
    for (int i = 0; i < num_blocks; i++) {
        uint64_t tmp1 = i ^ nonce;
        uint64_t tmp2;
        encrypt_tea((uint32_t *) &tmp1, (uint32_t *) &tmp2, key);
        cipher[i] = plain[i] ^ tmp2;
    }
    return;
}

void decrypt_tea_ctr(uint64_t * cipher, uint32_t key[4], uint64_t nonce, uint64_t * plain, uint32_t num_blocks) {
    // Your code here
    return;
}
