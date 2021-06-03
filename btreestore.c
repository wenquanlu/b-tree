#include "btreestore.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

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
    //char is_leaf;
};


void * init_store(uint16_t branching, uint8_t n_processors) {
    //fprintf(stderr, "branch: %d\n", branching);
    // Your code here
    struct tree_node * root = malloc(sizeof(struct tree_node) + 2 * sizeof(uint16_t) );
    root -> num_keys = 0;
    root -> pairs = NULL;
    root -> parent = NULL;
    root -> children = NULL;
    uint16_t * info = (uint16_t *) (root + 1);
    *info = branching;
    *(info + 1) = n_processors;
    //root -> is_leaf = 1;
    return (void *) root;
}


void post_order_clean(struct tree_node * root) {
    //fprintf(stderr, "keyer: %d\n", root -> pairs -> key);
    int num_keys = root -> num_keys;
    if (root -> children == NULL) {
        for (int i = 0; i < num_keys; i++) {
            free(((root -> pairs) + i) -> data);
        }
        free(root -> pairs);
        //fprintf(stderr, "freed :%p\n", root);
        //free(root);
        return;
    }
    for (int i = 0; i < num_keys + 1; i++) {
        //fprintf(stderr, "num key: %d\n", num_keys);
        //fprintf(stderr, "child root: %p\n", root -> children + i);
        post_order_clean(root -> children + i);
    }
    for (int i = 0; i < num_keys; i++) {
        free(((root -> pairs) + i) -> data);
    }
    free(root -> pairs);
    free(root -> children);
    //free(root);

}

void close_store(void * helper) {
    // Your code here
    struct tree_node * root = helper;
    //fprintf(stderr, "the final root: %d\n", root -> pairs -> key);
    //fprintf(stderr, "then left %d\n", root -> children -> pairs ->key);
    //fprintf(stderr, "the right %d\n", (root -> children + 1) -> pairs -> key);
    //fprintf(stderr, "the left left %d\n", root -> children -> children -> pairs -> key);
    //fprintf(stderr, "the left right %d\n", (root -> children -> children + 1) -> pairs -> key);
    //fprintf(stderr, "the right left %d\n", (root -> children + 1) -> children -> pairs -> key);
    //fprintf(stderr, "the right right %d\n", ((root -> children + 1)-> children +1) -> pairs -> key);
    post_order_clean(root);
    free(helper);
    return;
}

void insert_key_into_node(uint32_t key, struct tree_node node, int position) {

}

int btree_insert(uint32_t key, void * plaintext, size_t count, uint32_t encryption_key[4], uint64_t nonce, void * helper) {
    //fprintf(stderr, "key!: %d\n", key);
    // Your code here
    struct tree_node * root = helper;
    uint16_t * info = (uint16_t *) (root + 1);
    uint16_t branching = *info;
    uint16_t n_processors = *(info + 1);
    //printf("branch: %d\n", branching);
    //fprintf(stderr, "branching: %d\n", branching);

    while (root -> children != NULL) {
        int count = 0;
        while (count < (root -> num_keys)) {
            //fprintf(stderr, "numkey!!: %d\n", root -> num_keys);
            uint32_t curr_key = ((root -> pairs) + count) -> key;
            if (curr_key > key) {
                break;
            }
            if (curr_key == key) {
                //fprintf(stderr, "same!\n");
                return 1;
            }
            count ++;
        }
        //fprintf(stderr, "changed root\n");
        root = (root -> children) + count;
    }
    int leaf_count = 0;
    while (leaf_count < (root -> num_keys)) {
        uint32_t curr_key = ((root -> pairs) + leaf_count) -> key;
        if (curr_key > key) {
            break;
        }
        if (curr_key == key) {
            //fprintf(stderr, "same!\n");
            return 1;
        }
        leaf_count ++;
    }
    //fprintf(stderr, "haliluya\n");
    // reserve a larger space in root
    root -> pairs = realloc(root -> pairs, sizeof(struct kv_pair) * (root -> num_keys + 1));

    // shift right to right
    if (leaf_count != root -> num_keys) {
        memmove((root -> pairs) + leaf_count + 1, (root -> pairs) + leaf_count, 
        sizeof(struct kv_pair) * (root -> num_keys - leaf_count));
    }

    // Insert new kv in 
    struct kv_pair * new_kv = root -> pairs + leaf_count;
    new_kv -> key = key;
    new_kv -> size = count;

    // encrypts the data
    for (int i = 0; i < 4; i++) {
        (new_kv -> encryption_key)[i] = encryption_key[i];
    }
    new_kv -> nonce = nonce;
    int num_blocks = count / 8;
    if (count % 8 != 0) {
        num_blocks ++;
    }
    fprintf(stderr, "size in byte: %d\n", count);
    fprintf(stderr, "size in block: %d\n", num_blocks);
    // initialise with 0
    new_kv -> data = calloc(1, num_blocks * 8);
    encrypt_tea_ctr(plaintext, encryption_key, nonce, new_kv -> data, num_blocks);

    // update num keys of root node
    root -> num_keys ++;
    //fprintf(stderr, "root nk ++: %p\n", root -> num_keys);
    if (root -> num_keys <= branching - 1) {
        return 0;
    }
    //fprintf(stderr, "exceeded!, root -> parent: %p\n");
    // if haven't reached root and number of keys > branch - 1
    if (key == 80) {
        //fprintf(stderr, "god!!!!!!!; %d\n", ((struct tree_node *) helper) ->children ->pairs-> key);
    }
    while (root -> parent != NULL && root -> num_keys > branching - 1) {
        int midindex = (root -> num_keys - 1)/2;
        int midindex_key = (root -> pairs)[midindex].key;
        struct tree_node * original_child_ptr = root -> children;
        struct kv_pair * original_kv_ptr = root -> pairs;
        //fprintf(stderr, "prey to god: %d\n", root -> pairs -> key);
        //fprintf(stderr, "prey to god: %d\n", (root -> pairs + 1) -> key);
        //fprintf(stderr, "prey to god: %d\n", (root -> pairs + 2) -> key);
        int original_num_keys = root -> num_keys;
        struct tree_node * parent = root -> parent;
        int counter = 0;
        for (; counter < parent -> num_keys; counter ++) {
            uint32_t curr_key = ((parent -> pairs) + counter) -> key;
            if (curr_key > midindex_key) {
                break;
            }
        }
        parent -> pairs = realloc(parent -> pairs, 
        (parent -> num_keys + 1) * sizeof(struct kv_pair));
        memmove((parent -> pairs) + counter + 1, (parent -> pairs) + counter, 
        sizeof(struct kv_pair) * (parent -> num_keys - counter));

        struct kv_pair * new_kv = parent -> pairs + counter;
        memcpy(new_kv, original_kv_ptr + midindex, sizeof(struct kv_pair));
        
        parent -> children = realloc(parent -> children,
        (parent -> num_keys + 1 + 1) * sizeof(struct tree_node));

        if (counter != parent -> num_keys) {
            memmove((parent -> children) + counter + 2, (parent -> children) + counter + 1,
            sizeof(struct tree_node) * (parent -> num_keys - counter)); //needs double check           
        }

        int num_key_left = midindex;
        int num_key_right = original_num_keys - midindex - 1; //changed

        struct tree_node * left_node = (parent -> children)+ counter;
        struct tree_node * right_node = (parent -> children)+ counter + 1;

        right_node -> num_keys = num_key_right;
        right_node -> children = malloc(sizeof(struct tree_node) * (num_key_right + 1));
        right_node -> pairs = malloc(sizeof(struct kv_pair) * (num_key_right));
        //fprintf(stderr, "original child pointer: here : %p\n", original_child_ptr);
        if (original_child_ptr != NULL) {
            memcpy(right_node -> children, original_child_ptr + midindex + 1, (num_key_right + 1) * sizeof(struct tree_node));
        } else {
            free(right_node -> children);
            right_node -> children = NULL;
        }
        //fprintf(stderr, "num key right: %d\n", num_key_right);
        //fprintf(stderr, "original kv ptr: %p\n", original_kv_ptr);
        //fprintf(stderr, "mi: %d\n", midindex);
        //fprintf(stderr, "original num keys: %d\n", original_num_keys);
        memcpy(right_node -> pairs, original_kv_ptr + midindex + 1, (num_key_right) * sizeof(struct kv_pair));
        right_node -> parent = parent;

        left_node -> num_keys = num_key_left;
        left_node -> children = malloc(sizeof(struct tree_node) * (num_key_left + 1));
        left_node -> pairs = malloc(sizeof(struct kv_pair) * (num_key_left));
        if (original_child_ptr != NULL) {
            memcpy(left_node -> children, original_child_ptr, (num_key_left + 1) * sizeof(struct tree_node));
        } else {
            free(left_node -> children);
            left_node -> children = NULL;
        }
        memcpy(left_node -> pairs, original_kv_ptr, num_key_left * sizeof(struct kv_pair));
        left_node -> parent = parent;

        free(original_child_ptr);
        /*
        for (int i = 0; i < original_num_keys; i++) {
            free((original_kv_ptr + i) -> data);
        }*/
        free(original_kv_ptr);
        //free(root);
        parent -> num_keys += 1;
        //fprintf(stderr, "now print parent: %p\n", parent -> num_keys);
        root = parent;
    }
    //fprintf(stderr, "should come here\n");
    if (root -> parent == NULL && root -> num_keys > branching -1) {
        //fprintf(stderr, "shouldn't go in here right?\n");
        int midindex = (root -> num_keys - 1)/2;
        //fprintf(stderr, "midindedx: %d\n", midindex);
        int midindex_key = (root -> pairs)[midindex].key;
        int num_key_left = midindex;
        int num_key_right = root -> num_keys - midindex - 1;
        int original_num_keys = root ->num_keys;
        struct tree_node * original_child_ptr = root -> children;
        struct kv_pair * original_kv_ptr = root -> pairs;

        root -> children = malloc(2 * sizeof(struct tree_node));
        struct tree_node * left_node = root -> children;
        struct tree_node * right_node = (root -> children) + 1;

        right_node -> num_keys = num_key_right;
        //fprintf(stderr, "num key right: %d\n", num_key_right);
        right_node -> children = malloc(sizeof(struct tree_node) * (num_key_right + 1));
        right_node -> pairs = malloc(sizeof(struct kv_pair) * (num_key_right));
        //fprintf(stderr, "malloced pointer %p\n", right_node -> children);
        //fprintf(stderr, "orginal child ptr: %p\n", original_child_ptr);
        if (original_child_ptr != NULL) {
            memcpy(right_node -> children, original_child_ptr + midindex + 1, sizeof(struct tree_node) * (num_key_right + 1));
        } else {
            free(right_node -> children);
            right_node -> children = NULL;
        }
        //fprintf(stderr, "original kv pointer: %p\n", original_kv_ptr);
        //fprintf(stderr, "right node pairs: %p\n", right_node -> pairs);
        memcpy(right_node -> pairs, original_kv_ptr + midindex + 1, num_key_right * sizeof(struct kv_pair));
        right_node -> parent = root;

        left_node -> num_keys = num_key_left;
        //fprintf(stderr, "num key left: %d\n", left_node -> num_keys);
        left_node -> children = malloc(sizeof(struct tree_node) * (num_key_left + 1));
        left_node -> pairs = malloc(sizeof(struct kv_pair) * num_key_left);
        if (original_child_ptr != NULL) {
            memcpy(left_node -> children, original_child_ptr, (num_key_left + 1) * sizeof(struct tree_node));
        } else {
            free(left_node -> children);
            left_node -> children = NULL;
        }
        memcpy(left_node -> pairs, original_kv_ptr, num_key_left * sizeof(struct kv_pair));
        left_node -> parent = root;
        //fprintf(stderr, "left node key: !!!!!!!%d\n", root -> children -> pairs -> key);
        root -> pairs = malloc(sizeof(struct kv_pair));
        memcpy(root -> pairs, original_kv_ptr + midindex, sizeof(struct kv_pair));

        free(original_child_ptr);
        /*
        for (int i = 0; i < original_num_keys; i++) {
            if (i != midindex) {
                free((original_kv_ptr + i) -> data);
            }
        }*/
        free(original_kv_ptr);

        root -> num_keys = 1;        
    }
    return 0;
}

int btree_retrieve(uint32_t key, struct info * found, void * helper) {
    struct tree_node * root = helper;
    uint16_t * info = (uint16_t *) (root + 1);
    uint16_t branching = *info;
    uint16_t n_processors = *(info + 1);

    while (root -> children != NULL) {
            int count = 0;
            while (count < (root -> num_keys)) {
                //fprintf(stderr, "numkey!!: %d\n", root -> num_keys);
                uint32_t curr_key = ((root -> pairs) + count) -> key;
                if (curr_key > key) {
                    break;
                }
                if (curr_key == key) {
                    //fprintf(stderr, "same!\n");
                    found -> data = ((root -> pairs) + count) -> data;
                    memcpy(found -> key, ((root -> pairs) + count) -> encryption_key, 
                    4 * sizeof(uint32_t));
                    found -> nonce = ((root -> pairs) + count) -> nonce;
                    found -> size = ((root -> pairs) + count) -> size;
                    return 0;
                }
                count ++;
            }
            //fprintf(stderr, "changed root\n");
            root = (root -> children) + count;
        }
    int leaf_count = 0;
    while (leaf_count < (root -> num_keys)) {
        uint32_t curr_key = ((root -> pairs) + leaf_count) -> key;
        if (curr_key > key) {
            break;
        }
        if (curr_key == key) {
            //fprintf(stderr, "same!\n");
            found -> data = ((root -> pairs) + leaf_count) -> data;
            memcpy(found -> key, ((root -> pairs) + leaf_count) -> encryption_key, 
            4 * sizeof(uint32_t));
            found -> nonce = ((root -> pairs) + leaf_count) -> nonce;
            found -> size = ((root -> pairs) + leaf_count) -> size;
            return 0;
        }
        leaf_count ++;
    }

    return 1;
}

int btree_decrypt(uint32_t key, void * output, void * helper) {
    struct tree_node * root = helper;
    uint16_t * info = (uint16_t *) (root + 1);
    uint16_t branching = *info;
    uint16_t n_processors = *(info + 1);

    while (root -> children != NULL) {
            int count = 0;
            while (count < (root -> num_keys)) {
                //fprintf(stderr, "numkey!!: %d\n", root -> num_keys);
                uint32_t curr_key = ((root -> pairs) + count) -> key;
                if (curr_key > key) {
                    break;
                }
                if (curr_key == key) {
                    int num_bytes = ((root -> pairs) + count) -> size;
                    int num_blocks;
                    if (num_bytes % 8 == 0) {
                        num_blocks = num_bytes/8;
                    } else {
                        num_blocks = num_bytes/8 + 1;
                    }
                    decrypt_tea_ctr(output, ((root -> pairs) + count) -> encryption_key,
                    ((root -> pairs) + count) -> nonce, output, num_blocks);
                    return 0;
                }
                count ++;
            }
            //fprintf(stderr, "changed root\n");
            root = (root -> children) + count;
        }
    int leaf_count = 0;
    while (leaf_count < (root -> num_keys)) {
        uint32_t curr_key = ((root -> pairs) + leaf_count) -> key;
        if (curr_key > key) {
            break;
        }
        if (curr_key == key) {
                int num_bytes = ((root -> pairs) + leaf_count) -> size;
                int num_blocks;
                if (num_bytes % 8 == 0) {
                    num_blocks = num_bytes/8;
                } else {
                    num_blocks = num_bytes/8 + 1;
                }
                decrypt_tea_ctr(output, ((root -> pairs) + leaf_count) -> encryption_key,
                ((root -> pairs) + leaf_count) -> nonce, output, num_blocks);
                return 0;
        }
        leaf_count ++;
    }
    return 1;
}

int btree_delete(uint32_t key, void * helper) {
    // Your code here
    return 1;
}

int pre_order(struct tree_node * root, int count, struct node ** ls) {
    if (root -> children == NULL) {
        *ls = realloc(*ls, (count + 1) * sizeof(struct node));
        struct node * new_node = *ls + count;
        int num_keys = root -> num_keys;
        new_node -> num_keys = num_keys;
        new_node -> keys = malloc(num_keys * sizeof(uint32_t));
        for (int i = 0; i < num_keys; i++) {
            *((new_node -> keys) + i) = (root -> pairs + i) -> key;
        }
        return count + 1; //?
    }
    int root_num_keys = root -> num_keys;
    count ++; //?
    *ls = realloc(*ls, (count) * sizeof(struct node));
    struct node * new_node = *ls + count - 1;
    new_node -> num_keys = root_num_keys;
    new_node -> keys = malloc(root_num_keys * sizeof(uint32_t));
    for (int i = 0; i < root_num_keys; i++) {
        *((new_node -> keys) + i) = (root -> pairs + i) -> key;
    }
    for (int i = 0; i < root_num_keys + 1; i++) {
        count = pre_order((root -> children) + i, count, ls); //?
    }
    return count;
} 

uint64_t btree_export(void * helper, struct node ** list) {
    
    int count = 0;
    struct tree_node * root = helper;
    *list = NULL;
    return pre_order(root, count, list);
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
    for (int i = 0; i < num_blocks; i++) {
        uint64_t tmp1 = i ^ nonce;
        uint64_t tmp2;
        encrypt_tea((uint32_t *) &tmp1, (uint32_t *) &tmp2, key);
        plain[i] = cipher[i] ^ tmp2;
    }
    return;
}
