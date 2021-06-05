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
    //fprintf(stderr, "root!: %p\n", root);
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
    //fprintf(stderr, "size in byte: %d\n", count);
    //fprintf(stderr, "size in block: %d\n", num_blocks);
    // initialise with 0
    new_kv -> data = calloc(1, num_blocks * 8);
    uint64_t * plain = malloc(num_blocks  * 8);
    memcpy(plain, plaintext, count);
    encrypt_tea_ctr(plain, encryption_key, nonce, new_kv -> data, num_blocks);
    free(plain);
    // update num keys of root node
    root -> num_keys ++;
    //fprintf(stderr, "root nk ++: %p\n", root -> num_keys);
    if (root -> num_keys <= branching - 1) {
        return 0;
    }
    //fprintf(stderr, "exceeded!, root -> parent: %p\n");
    // if haven't reached root and number of keys > branch - 1
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
        ////////
        if (right_node -> children != NULL) {
            for (int i = 0; i <= right_node -> num_keys; i++) {
                (right_node -> children + i) -> parent = right_node;
            }
        }
        ////////    
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
        //////
        if (left_node -> children != NULL) {
            for (int i = 0; i <= left_node -> num_keys; i++) {
                (left_node -> children + i) -> parent = left_node;
            }
        }
        ///////
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
        ///////
        if (right_node -> children != NULL) {
            for (int i = 0; i <= right_node -> num_keys; i++) {
                (right_node -> children + i) -> parent = right_node;
            }
        }
        ///////
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
        /////////
        if (left_node -> children != NULL) {
            for (int i = 0; i <= left_node -> num_keys; i++) {
                (left_node -> children + i) -> parent = left_node;
            }
        }
        ////////
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
                    uint64_t * plain = malloc(num_blocks * 8);
                    decrypt_tea_ctr(((root -> pairs) + count) -> data
                    , ((root -> pairs) + count) -> encryption_key,
                    ((root -> pairs) + count) -> nonce, plain, num_blocks);
                    memcpy(output, plain, ((root -> pairs) + count) -> size);
                    free(plain);
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
                uint64_t * plain = malloc(num_blocks * 8);
                decrypt_tea_ctr(((root -> pairs) + leaf_count) -> data
                , ((root -> pairs) + leaf_count) -> encryption_key,
                ((root -> pairs) + leaf_count) -> nonce, plain, num_blocks);
                memcpy(output, plain, ((root -> pairs) + leaf_count) -> size);
                free(plain);
                return 0;
        }
        leaf_count ++;
    }
    return 1;
}

void swap_key(struct tree_node * node1, int key_index1, struct tree_node * node2, int key_index2) {
    struct kv_pair tmp = {};
    memcpy(&tmp, (node1 -> pairs) + key_index1, sizeof(struct kv_pair));
    memcpy((node1 -> pairs) + key_index1, (node2 -> pairs) + key_index2, sizeof(struct kv_pair));
    memcpy((node2 -> pairs) + key_index2, &tmp, sizeof(struct kv_pair));
}

void delete_key_from_leaf_node(struct tree_node * node, int key_index) {
    struct kv_pair * original_key = node -> pairs;
    node -> pairs = malloc((node -> num_keys - 1) * sizeof(struct kv_pair));
    for (int i = 0; i < key_index; i++) {
        memcpy((node -> pairs) + i, (original_key + i), sizeof(struct kv_pair));
    }
    for (int i = key_index + 1; i < node -> num_keys; i++) {
        memcpy((node -> pairs) + i - 1, (original_key + i), sizeof(struct kv_pair));
    }
    free((original_key + key_index) -> data);
    free(original_key);
    (node -> num_keys) --;
}

struct kv_pair* delete_key_from_leaf_node_with_return(struct tree_node * node, 
        int key_index) {
    struct kv_pair * original_key = node -> pairs;
    node -> pairs = malloc((node -> num_keys - 1) * sizeof(struct kv_pair));
    for (int i = 0; i < key_index; i++) {
        memcpy((node -> pairs) + i, (original_key + i), sizeof(struct kv_pair));
    }
    for (int i = key_index + 1; i < node -> num_keys; i++) {
        memcpy((node -> pairs) + i - 1, (original_key + i), sizeof(struct kv_pair));
    }
    struct kv_pair * deleted_key = malloc(sizeof(struct kv_pair));
    memcpy(deleted_key, original_key + key_index, sizeof(struct kv_pair));
    free(original_key);
    (node -> num_keys) --;
    return deleted_key;
}

void insert_key_into_leaf_node(struct tree_node * leaf_node, struct kv_pair * kv) {
    int count = 0;
    struct kv_pair * original_key = leaf_node -> pairs;
    while (count < (leaf_node -> num_keys)) {
        uint32_t curr_key = ((leaf_node -> pairs) + count) -> key;
        if (curr_key > kv -> key) {
            break;
        }
        count ++;
    }
    leaf_node -> pairs = malloc((leaf_node -> num_keys + 1) * sizeof(struct kv_pair));
    for (int i = 0; i < count; i++) {
        memcpy((leaf_node -> pairs) + i, original_key + i, sizeof(struct kv_pair));
    }
    memcpy((leaf_node -> pairs) + count, kv, sizeof(struct kv_pair));
    for (int i = count + 1; i < leaf_node -> num_keys; i++) {
        memcpy((leaf_node -> pairs) + i + 1, original_key + i, sizeof(struct kv_pair));
    }
    free(original_key);
    (leaf_node -> num_keys) ++;
}

void move_key_to_leaf(struct tree_node *source_node, int key_index, struct tree_node * leaf_node) {
    struct kv_pair tmp = {};
    memcpy(&tmp, (source_node -> pairs) + key_index, sizeof(struct kv_pair));
    insert_key_into_leaf_node(leaf_node, &tmp);
}


void merge_from_left(struct tree_node * left_node, struct tree_node * right_node,
                 struct tree_node * parent, int inter_key_idx) {
    struct kv_pair * original_left_child_keys = left_node -> pairs;
    struct tree_node * original_left_children = left_node -> children;
    struct kv_pair * original_right_child_keys = right_node -> pairs;
    // remember to fee original left and right
    struct kv_pair * original_right_children = right_node -> children;
    struct kv_pair * original_parent_keys = parent -> pairs;
    struct tree_node * original_parent_children = parent -> children;
    int left_node_num_keys = left_node -> num_keys;
    right_node -> pairs = malloc(((right_node -> num_keys) + 
    left_node_num_keys + 1) * sizeof(struct kv_pair));
    memcpy(right_node -> pairs, left_node -> pairs, 
            left_node_num_keys * sizeof(struct kv_pair));
    memcpy(right_node -> pairs + (left_node -> num_keys), parent -> pairs + inter_key_idx,
            sizeof(struct kv_pair));
    memcpy(right_node -> pairs + left_node_num_keys + 1, original_right_child_keys,
            sizeof(struct kv_pair) * (right_node-> num_keys));
    free(original_right_child_keys);
    free(original_left_child_keys);
    if (left_node -> children != NULL) {
        right_node -> children = malloc(((right_node ->num_keys + 1) + (left_node_num_keys + 1)) * 
                                        sizeof(struct tree_node));
        memcpy(right_node -> children, original_left_children, (left_node_num_keys + 1) * sizeof(struct tree_node));
        if (original_right_children != NULL) {
            memcpy(right_node -> children + left_node_num_keys + 1, original_right_children,
                    (right_node -> num_keys + 1) * sizeof(struct tree_node));
        }
        free(original_right_children);
        //free(original_left_children);
    }
    free(left_node -> children);
    right_node -> num_keys = (right_node -> num_keys) + left_node_num_keys + 1;
    ////////
    if (right_node -> children != NULL) {
        for (int i = 0; i <= right_node -> num_keys; i++) {
            struct tree_node * right_node_child = right_node -> children + i;
            if (right_node_child -> children != NULL) {
                for (int j = 0; j <= right_node_child -> num_keys; j++) {
                    (right_node_child -> children + j) -> parent = right_node_child;
                }
            }
        }
    }
    ////////
    parent -> children = malloc(((parent -> num_keys) * sizeof(struct tree_node)));
    parent -> pairs = malloc(((parent -> num_keys) - 1) * sizeof(struct kv_pair));
    memcpy(parent -> pairs, original_parent_keys, inter_key_idx * sizeof(struct kv_pair));
    memcpy(parent -> pairs + inter_key_idx, 
            original_parent_keys + (inter_key_idx) + 1, 
            ((parent -> num_keys) - inter_key_idx - 1) * sizeof(struct kv_pair));
    
    memcpy(parent -> children, original_parent_children, inter_key_idx * sizeof(struct tree_node)); // changed from keys to children
    memcpy((parent -> children) + inter_key_idx,
            original_parent_children + inter_key_idx + 1,
            ((parent -> num_keys) - inter_key_idx) * sizeof(struct tree_node));
    free(original_parent_children);
    free(original_parent_keys);
    (parent -> num_keys) --;
    ////////
    for (int i = 0; i <= parent -> num_keys; i++) {
        struct tree_node * child = parent -> children + i;
        if (child -> children != NULL) {
            for (int j = 0; j <= child -> num_keys; j++) {
                (child -> children + j) -> parent = child;
            }
        }
    }
    /////////
}

void merge_from_right(struct tree_node * left_node, struct tree_node * right_node,
                    struct tree_node * parent, int inter_key_idx) {
    struct kv_pair * original_left_child_keys = left_node -> pairs;
    struct tree_node * original_left_children = left_node -> children;
    struct kv_pair * original_right_child_keys = right_node -> pairs;
    struct tree_node * original_right_children = right_node -> children;
    struct kv_pair * original_parent_keys = parent -> pairs;
    struct tree_node * original_parent_children = parent -> children;
    fprintf(stderr, "left node: %p\n", left_node);
    fprintf(stderr, "right node: %p\n", right_node);
    fprintf(stderr,"right nodi k: %d\n", right_node -> pairs -> key); //edited
    if (right_node -> pairs -> key == 21) {
        fprintf(stderr, "a: %p\n", original_left_children ->children);
        fprintf(stderr, "b: %p\n", original_right_children -> children);
        fprintf(stderr, "c: %p\n", (original_right_children + 1) -> children);
    }
    int right_node_num_keys = right_node -> num_keys;
    left_node -> pairs = realloc(left_node -> pairs, (left_node -> num_keys + 
    right_node_num_keys + 1) * sizeof(struct kv_pair));

    memcpy(left_node -> pairs + (left_node -> num_keys), parent -> pairs + inter_key_idx,
            sizeof(struct kv_pair));
    memcpy(left_node -> pairs + (left_node -> num_keys) + 1, right_node -> pairs,
            sizeof(struct kv_pair) * right_node_num_keys);
    free(original_right_child_keys); // edit, deleted another free
    if (right_node -> children != NULL) {
        fprintf(stderr, "shouldn't go here\n");
        left_node -> children = realloc(left_node -> children
        ,((left_node -> num_keys + 1) + 
        (right_node_num_keys + 1)) * sizeof(struct tree_node));
        memcpy(left_node -> children + (left_node -> num_keys + 1) //edited added (left_node -> num_keys + 1)
        , original_right_children, (right_node_num_keys + 1) * sizeof(struct tree_node));
    }
    if (left_node -> children != NULL) {
        fprintf(stderr, "a: %p\n", left_node -> children ->children);
        fprintf(stderr, "b: %p\n", (left_node -> children + 1) -> children);
        fprintf(stderr, "c: %p\n", (left_node  -> children + 2)-> children);
    }
    free(right_node -> children);
    fprintf(stderr, "lef num key prev: %d\n", left_node -> num_keys);
    left_node -> num_keys = (left_node -> num_keys) + right_node_num_keys + 1;
    fprintf(stderr, "lef num key: %d\n", left_node -> num_keys);
    fprintf(stderr, "right nod num: %d\n", right_node_num_keys);
    /////////
    if (left_node -> children != NULL) {
        for (int i = 0; i <= left_node -> num_keys; i++) {
            struct tree_node * left_node_child = left_node -> children + i;
            if (left_node_child -> children != NULL) {
                for (int j = 0; j <= left_node_child -> num_keys; j++) {
                    (left_node_child -> children + j) -> parent = left_node_child;
                }
            }
        }
    }
    /////////
    /*
    for (int i = 0; i <= parent -> num_keys; i++) {
        struct tree_node * child = parent -> children + i;
        fprintf(stderr, "child's child: %p\n", child -> children);
        fprintf(stderr, "child: %p\n", child);
    }*/
    parent -> children = malloc(((parent -> num_keys) * sizeof(struct tree_node)));
    fprintf(stderr, "len %d\n", parent -> num_keys);
    fprintf(stderr, "malloc %d\n", ((parent -> num_keys) - 1) * sizeof(struct kv_pair));
    parent -> pairs = malloc(((parent -> num_keys) - 1) * sizeof(struct kv_pair));
    memcpy(parent -> pairs, original_parent_keys, inter_key_idx * sizeof(struct kv_pair));
    memcpy(parent -> pairs + inter_key_idx, 
            original_parent_keys + (inter_key_idx) + 1, 
            ((parent -> num_keys) - inter_key_idx - 1) * sizeof(struct kv_pair));
    //fprintf(stderr, "odcbwdo: %p\n", original_parent_children -> children);
    //fprintf(stderr, "inter: %d\n", inter_key_idx);
    //fprintf(stderr, "njsa: %p\n", (original_parent_children + 2) -> children);
    memcpy(parent -> children, original_parent_children, (inter_key_idx + 1) * sizeof(struct tree_node)); // changed from key to children
    memcpy((parent -> children) + inter_key_idx + 1,
            original_parent_children + inter_key_idx + 2,
            ((parent -> num_keys) - inter_key_idx - 1) * sizeof(struct tree_node));
    free(original_parent_children);
    free(original_parent_keys);
    (parent -> num_keys) --;
    ///////////
    for (int i = 0; i <= parent -> num_keys; i++) {
        struct tree_node * child = parent -> children + i;
        if (child -> children != NULL) {
            fprintf(stderr, "i: %d\n", i);
            fprintf(stderr, "children: %p\n", child -> children);
            fprintf(stderr, "chilchil: %p\n", child);
            //fprintf(stderr, "num: %d\n", child -> num_keys);
            //fprintf(stderr, "key: %d\n", child -> pairs ->key);
            for (int j = 0; j <= child -> num_keys; j++) {
                (child -> children + j) -> parent = child;
            }
        }
    }
    ///////////
}
////////////////////////////////////////////////////////////////////////////////////////////////////
void move_c_from_right_to_left(struct tree_node * left_node, struct tree_node * right_node) {
    struct tree_node * original_right_children = right_node -> children;
    struct tree_node * original_left_children = left_node -> children;
    left_node -> children = realloc(left_node -> children, (left_node -> num_keys + 1)* sizeof(struct tree_node));
    right_node -> children = malloc((right_node -> num_keys + 1) * sizeof(struct tree_node));
    memcpy(left_node -> children + (left_node -> num_keys), original_right_children, sizeof(struct tree_node));
    memcpy(right_node -> children, original_right_children + 1, sizeof(struct tree_node) * (right_node -> num_keys + 1));
    free(original_right_children);
    //(right_node -> num_keys) --;
    //(left_node -> num_keys) ++;
    for (int i = 0; i <= right_node -> num_keys; i++) {
        struct tree_node * child = right_node -> children + i;
        if (child -> children != NULL) {
            for (int j = 0; j <= child -> num_keys; j++) {
                (child -> children + j) -> parent = child;
            }
        }
    }
    for (int i = 0; i <= left_node -> num_keys; i++) {
        struct tree_node * child = left_node -> children + i;
        if (child -> children != NULL) {
            for (int j = 0; j <= child -> num_keys; j++) {
                (child -> children + j) -> parent = child;
            }
        }
    }
}

void move_c_from_left_to_right(struct tree_node * left_node, struct tree_node * right_node) {
    struct tree_node * original_right_children = right_node -> children;
    struct tree_node * original_left_children = left_node -> children;
    struct tree_node tmp = {};
    memcpy(&tmp, left_node -> children + (left_node -> num_keys + 1), sizeof(struct tree_node));
    left_node -> children = realloc(left_node -> children, (left_node -> num_keys + 1) * sizeof(struct tree_node));
    right_node -> children = malloc((right_node -> num_keys + 1) * sizeof(struct tree_node));
    memcpy(right_node -> children, &tmp, sizeof(struct tree_node));
    memcpy(right_node -> children + 1, original_right_children, (right_node -> num_keys) * sizeof(struct tree_node));
    free(original_right_children);
    for (int i = 0; i <= right_node -> num_keys; i++) {
        struct tree_node * child = right_node -> children + i;
        if (child -> children != NULL) {
            for (int j = 0; j <= child -> num_keys; j++) {
                (child -> children + j) -> parent = child;
            }
        }
    }
    for (int i = 0; i <= left_node -> num_keys; i++) {
        struct tree_node * child = left_node -> children + i;
        if (child -> children != NULL) {
            for (int j = 0; j <= child -> num_keys; j++) {
                (child -> children + j) -> parent = child;
            }
        }
    }
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int btree_delete(uint32_t key, void * helper) {
    fprintf(stderr, "key:: %d\n", key);
    struct tree_node * root = helper;
    uint16_t * info = (uint16_t *) (root + 1);
    uint16_t branching = *info;
    fprintf(stderr, "branching: %d\n", branching);
    uint16_t n_processors = *(info + 1);
    int lower_bound = (branching)/2 + ((branching)%2 != 0);
    int found = 0;
    struct tree_node * leaf_node;
    int leaf_key_index;
    while (root -> children != NULL) {
        int count = 0;
        while (count < (root -> num_keys)) {
            //fprintf(stderr, "numkey!!: %d\n", root -> num_keys);
            uint32_t curr_key = ((root -> pairs) + count) -> key;
            if (curr_key > key) {
                break;
            }
            if (curr_key == key) {
                found = 1;
                struct tree_node * left_child_root = ((root -> children) + count);
                while (left_child_root -> children != NULL) {
                    left_child_root = 
                    left_child_root -> children + left_child_root -> num_keys;
                }
                swap_key(root, count, left_child_root, left_child_root -> num_keys - 1);
                leaf_key_index = left_child_root -> num_keys - 1;
                leaf_node = left_child_root;
                fprintf(stderr, "leaf: %p\n", leaf_node);
                if (key == 22) {
                    fprintf(stderr, "key: %d\n", (leaf_node ->pairs +1) -> key);
                }
                break;
            }
            count ++;
        }
        //fprintf(stderr, "changed root\n");
        root = (root -> children) + count;
    }
    
    int leaf_count = 0;
    if (!found) {
        while (leaf_count < (root -> num_keys)) {
            uint32_t curr_key = ((root -> pairs) + leaf_count) -> key;
            if (curr_key > key) {
                break;
            }
            if (curr_key == key) {
                fprintf(stderr, "root: %p\n", root);
                found = 1;
                leaf_key_index = leaf_count;
                leaf_node = root;
                fprintf(stderr, "key: %d\n", leaf_node ->pairs -> key);
                break;
            }
            leaf_count ++;
        }
    }
    if (found) {
        //fprintf(stderr, "key: %d\n", leaf_node ->pairs -> key);
        struct tree_node * parent = leaf_node -> parent;
        fprintf(stderr, "pchi: %p\n", parent -> children);
        fprintf(stderr, "actual father: %p\n", parent);
        delete_key_from_leaf_node(leaf_node, leaf_key_index);
        if (leaf_node -> num_keys + 1 >= lower_bound) {
            return 0;
        } else {
            int parent_num_keys = leaf_node -> parent -> num_keys;
            fprintf(stderr, "parent num1: %d\n", parent_num_keys);
            struct tree_node * p_children = leaf_node -> parent -> children;
            int child_index = 0;
            fprintf(stderr, "children %p\n", leaf_node);
            while (child_index <= parent_num_keys) { // edited <= changed to < /wrong change
                fprintf(stderr, "search %p\n", p_children + child_index);
                if ((p_children + child_index) == leaf_node) {
                    break;
                }
                child_index ++;
            }
            if (child_index == 0) {
                fprintf(stderr, "how are you\n");
                if (((p_children + 1) -> num_keys) + 1 > lower_bound) {
                    fprintf(stderr, "I am fine\n");
                    struct tree_node * right_sib = p_children + 1;
                    struct kv_pair * min = delete_key_from_leaf_node_with_return(
                        right_sib, 0
                    );
                    //remember to free min
                    move_key_to_leaf(
                        leaf_node -> parent, child_index, p_children + child_index
                    );
                    memcpy((leaf_node -> parent -> pairs) + child_index, min, sizeof(struct kv_pair));
                    free(min);
                    return 0;
                }
            } else if (child_index == parent_num_keys) {
                fprintf(stderr, "hi\n");
                if ((p_children + parent_num_keys - 1) -> num_keys + 1 > lower_bound) {
                    fprintf(stderr, "hello\n");
                    struct tree_node * left_sib = p_children + parent_num_keys - 1;
                    struct kv_pair * max = delete_key_from_leaf_node_with_return(
                        left_sib, left_sib -> num_keys - 1
                    );
                    move_key_to_leaf(
                        leaf_node -> parent, child_index - 1, p_children + child_index
                    );
                    //remember to free max
                    // replace
                    memcpy((leaf_node -> parent -> pairs) + child_index - 1, max, sizeof(struct kv_pair)); // edited leaf_node -> parent
                    free(max);
                    return 0;
                }
            } else {
                int suitable = 0;
                fprintf(stderr, "Thank you\n");
                fprintf(stderr, "c ind: %d\n", child_index);
                if ((p_children + child_index - 1) -> num_keys + 1 > lower_bound) {
                    fprintf(stderr, "And you\n");
                    suitable = 1;
                    struct tree_node * left_sib = p_children + child_index - 1;
                    struct kv_pair * max = delete_key_from_leaf_node_with_return(
                        left_sib, left_sib -> num_keys - 1
                    );
                    fprintf(stderr, "parent numkey %d\n", leaf_node -> parent -> num_keys);
                    fprintf(stderr, "child index %d\n", child_index);
                    move_key_to_leaf(
                        leaf_node -> parent, child_index - 1, p_children + child_index
                    );
                    //remember to free max
                    memcpy((leaf_node -> parent -> pairs) + child_index - 1, max, sizeof(struct kv_pair));
                    free(max);
                    return 0;
                }
                if (!suitable) {
                    fprintf(stderr, "hnjsaqsd\n");
                    fprintf(stderr, "nu %d\n", (p_children + child_index + 1) -> num_keys);
                    fprintf(stderr, "lower hound: %d\n", lower_bound);
                    if ((p_children + child_index + 1) -> num_keys + 1 > lower_bound) {
                        struct tree_node * right_sib = p_children + child_index + 1;
                        struct kv_pair * min = delete_key_from_leaf_node_with_return(
                            right_sib, 0
                        );
                        move_key_to_leaf(
                        leaf_node -> parent, child_index, p_children + child_index
                        );
                        //remember to free min
                        memcpy((leaf_node -> parent -> pairs) + child_index, min, sizeof(struct kv_pair));
                        free(min);
                        return 0;
                    }
                }
            }
            // now here means not returned, so no immediate sibling of the target node can share node
            if (child_index == 0) {
                fprintf(stderr, "let's see\n");
                struct tree_node * right_child = p_children + 1;
                merge_from_right(leaf_node, right_child, leaf_node -> parent, 0);
            } else {
                fprintf(stderr, "What's wrong\n");
                struct tree_node * left_child = p_children + child_index - 1;
                merge_from_left(left_child, leaf_node, leaf_node -> parent, child_index - 1);
            }

            ///////////////////////////////////////////////////////////////////////////
            while ((parent -> parent != NULL) && (parent -> num_keys + 1 < lower_bound)) {
                struct tree_node * p_parent = parent -> parent;
                int p_parent_num_keys = parent -> parent -> num_keys;
                struct tree_node * pp_children = parent -> parent -> children;
                int pc_index = 0;
                while (pc_index <= p_parent_num_keys) {
                    if (pp_children + pc_index == parent) {
                        break;
                    }
                    pc_index ++;
                }
                if (pc_index == 0) {
                    if (((pp_children + 1) -> num_keys) + 1 > lower_bound) {
                        struct tree_node * right_sib = pp_children + 1;
                        struct kv_pair * min = delete_key_from_leaf_node_with_return(
                            right_sib, 0
                        );
                        move_key_to_leaf(
                            p_parent, pc_index, pp_children + pc_index
                        );
                        memcpy((p_parent ->pairs) + pc_index, min, sizeof(struct kv_pair));
                        free(min);
                        move_c_from_right_to_left(pp_children, pp_children + 1);
                        return 0;
                    }

                } else if (pc_index == p_parent_num_keys) {
                    if (((pp_children + p_parent_num_keys - 1) -> num_keys + 1) > lower_bound) {
                        struct tree_node * left_sib = pp_children + p_parent_num_keys - 1;
                        struct kv_pair * max = delete_key_from_leaf_node_with_return(
                            left_sib, left_sib -> num_keys - 1
                        );
                        move_key_to_leaf(
                            p_parent, pc_index - 1, pp_children + pc_index
                        );
                        memcpy((p_parent -> pairs) + pc_index - 1, max, sizeof(struct kv_pair));
                        free(max);
                        move_c_from_left_to_right(pp_children + pc_index - 1, pp_children + pc_index);
                        return 0;
                    }

                } else {
                    int suitable = 0;
                    if ((pp_children + pc_index - 1) -> num_keys + 1 > lower_bound) {
                        suitable = 1;
                        struct tree_node * left_sib = pp_children + pc_index - 1;
                        struct kv_pair * max = delete_key_from_leaf_node_with_return(
                            left_sib, left_sib -> num_keys - 1
                        );
                        move_key_to_leaf(
                            p_parent, pc_index - 1, pp_children + pc_index
                        );
                        memcpy((p_parent -> pairs) + pc_index - 1, max, sizeof(struct kv_pair));
                        free(max);
                        move_c_from_left_to_right(pp_children + pc_index - 1, pp_children + pc_index);
                        return 0;
                    } 
                    if (!suitable) {
                        if ((pp_children + pc_index + 1) -> num_keys + 1 > lower_bound) {
                            struct tree_node * right_sib = pp_children + pc_index + 1;
                            struct kv_pair * min = delete_key_from_leaf_node_with_return(
                                right_sib, 0
                            );
                            move_key_to_leaf(
                                p_parent, pc_index, pp_children + pc_index
                            );
                            memcpy((p_parent -> pairs) + pc_index, min, sizeof(struct kv_pair));
                            free(min);
                            move_c_from_right_to_left(pp_children + pc_index, pp_children + pc_index + 1);
                            return 0;
                        }
                    }
                }
                if (pc_index == 0) {
                    struct tree_node * right_child = pp_children + 1;
                    fprintf(stderr, "parL: %p\n", parent -> children);
                    fprintf(stderr, "abc: %d\n", right_child -> pairs -> key);
                    merge_from_right(parent, right_child, parent -> parent, 0);
                } else {
                    struct tree_node * left_child = pp_children + pc_index - 1;
                    merge_from_left(parent, left_child, parent -> parent, pc_index - 1);
                }
                parent = p_parent;
            }
            if (parent -> num_keys < 1) {
                struct tree_node * new_king = parent -> children;
                new_king -> parent = NULL;
                memcpy(helper, new_king, sizeof(struct tree_node));
                free(new_king);
                struct tree_node * root = helper;
                if (root -> children != NULL) {
                    for (int i = 0; i <= root -> num_keys; i++) {
                        (root -> children + i) -> parent = root;
                    }
                }
                return 0;
            }
            return 0;
        }
        ///////////////////////////////////////////////////////////////////////////
    } else {
        return 1;
    }
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
