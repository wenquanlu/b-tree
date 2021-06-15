/*
 * Due to extreme sickness, I have special consideration for extension of 14 days
 * Sorry for any inconvenience caused.
 */
#include "btreestore.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <semaphore.h>

/*
 * initial store structure root, 
 * 3 * uint16_t: branching, n_processors, number of reading threads
 * 2 * sem_t: 2 semaphores, representing read, write locks respectively
 */
void * init_store(uint16_t branching, uint8_t n_processors) {
    struct tree_node * root = malloc(sizeof(struct tree_node) +
                                    3 * sizeof(uint16_t) + 
                                    2 * sizeof(sem_t));
    root -> num_keys = 0;
    root -> pairs = NULL;
    root -> parent = NULL;
    root -> children = NULL;
    uint16_t * info = (uint16_t *) (root + 1);
    *info = branching;
    *(info + 1) = n_processors;
    *(info + 2) = 0;
    sem_t * r_sem = (sem_t *) (info + 3);
    sem_t * w_sem = (sem_t *) (r_sem + 1);
    sem_init(r_sem, 0, 1);
    sem_init(w_sem, 0, 1);
    return (void *) root;
}

/*
 * free malloced resources in post order traversal
 * children first, then parent
 */
void post_order_clean(struct tree_node * root) {
    int num_keys = root -> num_keys;
    if (root -> children == NULL) {
        for (int i = 0; i < num_keys; i++) {
            free(((root -> pairs) + i) -> data);
        }
        free(root -> pairs);
        return;
    }
    for (int i = 0; i < num_keys + 1; i++) {
        post_order_clean(root -> children + i);
    }
    for (int i = 0; i < num_keys; i++) {
        free(((root -> pairs) + i) -> data);
    }
    free(root -> pairs);
    free(root -> children);

}

void close_store(void * helper) {
    struct tree_node * root = helper;
    post_order_clean(root);
    uint16_t * info = (uint16_t *) (root + 1);
    sem_t * r_sem = (sem_t *) (info + 3);
    sem_t * w_sem = (r_sem + 1);
    sem_destroy(r_sem);
    sem_destroy(w_sem);
    free(helper);
    return;
}

/*
 * Considering the overhead of pushing stack frame in function call,
 * which may increase run time of the program. Insert function is implemented
 * as a whole, but I have made detailed annotation and comments.
 */
////////////////////////////////////////////////////////////////////////////////
int btree_insert(uint32_t key, void * plaintext, size_t count, 
                 uint32_t encryption_key[4], uint64_t nonce, void * helper) {

    struct tree_node * root = helper;

    uint16_t * info = (uint16_t *) (root + 1);
    uint16_t branching = *info;
    //uint16_t n_processors = *(info + 1);

    sem_t * r_sem = (sem_t *) (info + 3);
    sem_t * w_sem = (r_sem + 1);
    sem_wait(w_sem); // lock the write lock

    // search for key in the tree first
    while (root -> children != NULL) {
        int count = 0;
        while (count < (root -> num_keys)) {

            uint32_t curr_key = ((root -> pairs) + count) -> key;
            if (curr_key > key) {
                break;
            }
            if (curr_key == key) {

                sem_post(w_sem);
                return 1;
            }
            count ++;
        }

        root = (root -> children) + count;
    }

    int leaf_count = 0;
    while (leaf_count < (root -> num_keys)) {
        uint32_t curr_key = ((root -> pairs) + leaf_count) -> key;
        if (curr_key > key) {
            break;
        }
        if (curr_key == key) {

            sem_post(w_sem);
            return 1;
        }
        leaf_count ++;
    }
    
    // reallocate one more space for the inserted node, "root" now should be a leaf node
    root -> pairs = realloc(root -> pairs, sizeof(struct kv_pair) * (root -> num_keys + 1));

    // shift nodes to the right of inserted node to right
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

    // initialise with 0 
    new_kv -> data = calloc(1, num_blocks * 8);
    memcpy(new_kv -> data, plaintext, count);
    encrypt_tea_ctr(new_kv -> data, encryption_key, 
                    nonce, new_kv -> data, num_blocks);

    // update num keys of root node
    root -> num_keys ++;

    if (root -> num_keys <= branching - 1) {
        sem_post(w_sem);
        return 0;
    }

    // if haven't reached tree root and number of keys > branch - 1
    // repeatedly perform split and move up median key operations
    while (root -> parent != NULL && root -> num_keys > branching - 1) {

        int midindex = (root -> num_keys - 1)/2;
        int midindex_key = (root -> pairs)[midindex].key;

        struct tree_node * original_child_ptr = root -> children;
        struct kv_pair * original_kv_ptr = root -> pairs;
        int original_num_keys = root -> num_keys;
        struct tree_node * parent = root -> parent;

        int counter = 0;
        for (; counter < parent -> num_keys; counter ++) {
            uint32_t curr_key = ((parent -> pairs) + counter) -> key;
            if (curr_key > midindex_key) {
                break;
            }
        }

        // reallocate one more space for new key inserted into parent
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
            sizeof(struct tree_node) * (parent -> num_keys - counter));         
        }

        int num_key_left = midindex;
        int num_key_right = original_num_keys - midindex - 1;

        // left and right nodes formed after split
        struct tree_node * left_node = (parent -> children)+ counter;
        struct tree_node * right_node = (parent -> children)+ counter + 1;

        right_node -> num_keys = num_key_right;
        right_node -> children = malloc(sizeof(struct tree_node) * (num_key_right + 1));
        right_node -> pairs = malloc(sizeof(struct kv_pair) * (num_key_right));

        if (original_child_ptr != NULL) {
            memcpy(right_node -> children, original_child_ptr + midindex + 1, 
                   (num_key_right + 1) * sizeof(struct tree_node));
        } else {
            free(right_node -> children);
            right_node -> children = NULL;
        }

        memcpy(right_node -> pairs, original_kv_ptr + midindex + 1, 
               (num_key_right) * sizeof(struct kv_pair));
        right_node -> parent = parent;

        // As right node's children has new addresses
        // let their children point to the new addresses
        if (right_node -> children != NULL) {
            for (int i = 0; i <= right_node -> num_keys; i++) {
                struct tree_node * child = right_node -> children + i;
                if (child -> children != NULL) {
                    for (int i = 0 ; i <= child -> num_keys; i++) {
                        (child -> children + i) -> parent = child;
                    }
                }
            }
        }

        left_node -> num_keys = num_key_left;
        left_node -> children = malloc(sizeof(struct tree_node) * (num_key_left + 1));
        left_node -> pairs = malloc(sizeof(struct kv_pair) * (num_key_left));
        if (original_child_ptr != NULL) {
            memcpy(left_node -> children, original_child_ptr, 
                   (num_key_left + 1) * sizeof(struct tree_node));
        } else {
            free(left_node -> children);
            left_node -> children = NULL;
        }
        memcpy(left_node -> pairs, original_kv_ptr, 
               num_key_left * sizeof(struct kv_pair));
        left_node -> parent = parent;

        // As left node's children has new addresses
        // let their children point to the new addresses     
        if (left_node -> children != NULL) {
            for (int i = 0; i <= left_node -> num_keys; i++) {
                struct tree_node * child = left_node -> children + i;
                if (child -> children != NULL) {
                    for (int i = 0; i <= child -> num_keys; i++) {
                        (child -> children + i) -> parent = child;
                    }
                }
            }
        }

        free(original_child_ptr);

        free(original_kv_ptr);

        (parent -> num_keys) += 1;

        // As parent's children has new addresses
        // let their children point to the new addresses
        for (int i = 0; i <= parent -> num_keys; i++) {
            struct tree_node * child = (parent -> children) + i;
            if (child -> children != NULL) {
                for (int i = 0; i <= child -> num_keys; i++) {
                    (child -> children + i) -> parent = child;
                }
            }
        }
        root = parent;
    }

    // If the tree root is splitted, Kmedian is inserted 
    // into a new root as the only key
    if (root -> parent == NULL && root -> num_keys > branching -1) {

        int midindex = (root -> num_keys - 1)/2;

        int num_key_left = midindex;
        int num_key_right = root -> num_keys - midindex - 1;

        struct tree_node * original_child_ptr = root -> children;
        struct kv_pair * original_kv_ptr = root -> pairs;

        // root now has only 2 new nodes as its children 
        root -> children = malloc(2 * sizeof(struct tree_node));
        struct tree_node * left_node = root -> children;
        struct tree_node * right_node = (root -> children) + 1;

        right_node -> num_keys = num_key_right;

        right_node -> children = malloc(sizeof(struct tree_node) * (num_key_right + 1));
        right_node -> pairs = malloc(sizeof(struct kv_pair) * (num_key_right));

        if (original_child_ptr != NULL) {
            memcpy(right_node -> children, original_child_ptr + midindex + 1, 
                   sizeof(struct tree_node) * (num_key_right + 1));
        } else {
            free(right_node -> children);
            right_node -> children = NULL;
        }

        memcpy(right_node -> pairs, original_kv_ptr + midindex + 1, 
               num_key_right * sizeof(struct kv_pair));
        right_node -> parent = root;

        if (right_node -> children != NULL) {
            for (int i = 0; i <= right_node -> num_keys; i++) {
                (right_node -> children + i) -> parent = right_node;
                struct tree_node * child = right_node -> children + i;
                if (child -> children != NULL) {
                    for (int i = 0; i <= child -> num_keys; i++) {
                        (child -> children + i) -> parent = child;
                    } 
                }
            }
        }

        left_node -> num_keys = num_key_left;

        left_node -> children = malloc(sizeof(struct tree_node) * (num_key_left + 1));
        left_node -> pairs = malloc(sizeof(struct kv_pair) * num_key_left);
        if (original_child_ptr != NULL) {
            memcpy(left_node -> children, original_child_ptr, 
                   (num_key_left + 1) * sizeof(struct tree_node));
        } else {
            free(left_node -> children);
            left_node -> children = NULL;
        }
        memcpy(left_node -> pairs, original_kv_ptr, 
               num_key_left * sizeof(struct kv_pair));
        left_node -> parent = root;

        root -> pairs = malloc(sizeof(struct kv_pair));
        memcpy(root -> pairs, original_kv_ptr + midindex, sizeof(struct kv_pair));

        if (left_node -> children != NULL) {
            for (int i = 0; i <= left_node -> num_keys; i++) {
                (left_node -> children + i) -> parent = left_node;
                struct tree_node * child = left_node -> children + i;
                if (child -> children != NULL) {
                    for (int i = 0; i <= child -> num_keys; i++) {
                        (child -> children + i) -> parent = child;
                    }
                }
            }
        }

        free(original_child_ptr);

        free(original_kv_ptr);

        root -> num_keys = 1;        
    }
    sem_post(w_sem);
    return 0;
}

int btree_retrieve(uint32_t key, struct info * found, void * helper) {
    struct tree_node * root = helper;
    uint16_t * info = (uint16_t *) (root + 1);
    uint16_t branching = *info;
    //uint16_t n_processors = *(info + 1);
    uint16_t * reading = info + 2;
    sem_t * r_sem = (sem_t *) (info + 3);
    sem_t * w_sem = (r_sem + 1);

    sem_wait(r_sem);
    (*reading) ++;  // increment the reading counter
    if (*reading == 1) {
        sem_wait(w_sem);
    }
    sem_post(r_sem); // release the read lock

    while (1) {
            int count = 0;
            while (count < (root -> num_keys)) {

                uint32_t curr_key = ((root -> pairs) + count) -> key;
                if (curr_key > key) {
                    break;
                }
                if (curr_key == key) {

                    found -> data = ((root -> pairs) + count) -> data;
                    memcpy(found -> key, ((root -> pairs) + count) -> encryption_key, 
                    4 * sizeof(uint32_t));
                    found -> nonce = ((root -> pairs) + count) -> nonce;
                    found -> size = ((root -> pairs) + count) -> size;
                    sem_wait(r_sem);
                    (*reading) --;
                    if (*reading == 0) {
                        sem_post(w_sem);
                    }
                    sem_post(r_sem);
                    return 0;
                }
                count ++;
            }
            if (root -> children == NULL) {
                break;
            }
            root = (root -> children) + count;
        }

    sem_wait(r_sem);
    (*reading) --;
    if (*reading == 0) {
        sem_post(w_sem);
    }
    sem_post(r_sem);
    return 1;
}


int btree_decrypt(uint32_t key, void * output, void * helper) {
    struct tree_node * root = helper;
    uint16_t * info = (uint16_t *) (root + 1);
    uint16_t branching = *info;
    //uint16_t n_processors = *(info + 1);
    uint16_t * reading = info + 2;
    sem_t * r_sem = (sem_t *) (info + 3);
    sem_t * w_sem = (r_sem + 1);

    sem_wait(r_sem);
    (*reading) ++;
    if (*reading == 1) {
        sem_wait(w_sem);
    }
    sem_post(r_sem);
    while (1) {
            int count = 0;
            while (count < (root -> num_keys)) {

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

                    sem_wait(r_sem);
                    (*reading) --;
                    if (*reading == 0) {
                        sem_post(w_sem);
                    }
                    sem_post(r_sem);
                    return 0;
                }
                count ++;
            }
            if (root -> children == NULL) {
                break;
            }
            root = (root -> children) + count;
        }

    sem_wait(r_sem);
    (*reading) --;
    if (*reading == 0) {
        sem_post(w_sem);
    }
    sem_post(r_sem);
    return 1; 
}


// swap key with key_index1 in node1 with key with key_index2 in node2
void swap_key(struct tree_node * node1, int key_index1, 
              struct tree_node * node2, int key_index2) {
    struct kv_pair tmp = {};
    memcpy(&tmp, (node1 -> pairs) + key_index1, sizeof(struct kv_pair));
    memcpy((node1 -> pairs) + key_index1, (node2 -> pairs) + key_index2, sizeof(struct kv_pair));
    memcpy((node2 -> pairs) + key_index2, &tmp, sizeof(struct kv_pair));
}

// delete key with key_index from the node
void delete_key_from_leaf_node(struct tree_node * node, int key_index) {
    struct kv_pair * original_key = node -> pairs;
    if ((node -> num_keys - 1) != 0) {
        node -> pairs = malloc((node -> num_keys - 1) * sizeof(struct kv_pair));
    } else {
        node -> pairs = NULL; // edited
    }
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

/*
 * delete key with key_index from the node, return pointer to 
 * memory allocated for the deleted key
 */
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

// insert key value pair into node
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

// move key with key_index from source_node to destination node which is leaf_node
void move_key_to_leaf(struct tree_node *source_node, int key_index, 
                      struct tree_node * leaf_node) {
    struct kv_pair tmp = {};
    memcpy(&tmp, (source_node -> pairs) + key_index, sizeof(struct kv_pair));
    insert_key_into_leaf_node(leaf_node, &tmp);
}

/*
 * merge left_node to right_node
 * inter_key_index is the index of key separated two nodes in the parent
 */
void merge_from_left(struct tree_node * left_node, struct tree_node * right_node,
                 struct tree_node * parent, int inter_key_idx) {
    
    struct kv_pair * original_left_child_keys = left_node -> pairs;
    struct tree_node * original_left_children = left_node -> children;
    struct kv_pair * original_right_child_keys = right_node -> pairs;
    struct tree_node * original_right_children = right_node -> children;
    struct kv_pair * original_parent_keys = parent -> pairs;
    struct tree_node * original_parent_children = parent -> children;

    int left_node_num_keys = left_node -> num_keys;
    right_node -> pairs = malloc(((right_node -> num_keys) + 
    left_node_num_keys + 1) * sizeof(struct kv_pair));

    memcpy(right_node -> pairs, left_node -> pairs, 
            left_node_num_keys * sizeof(struct kv_pair));
    memcpy(right_node -> pairs + (left_node -> num_keys), 
           parent -> pairs + inter_key_idx, sizeof(struct kv_pair));
    memcpy(right_node -> pairs + left_node_num_keys + 1, original_right_child_keys,
            sizeof(struct kv_pair) * (right_node-> num_keys));
    
    free(original_right_child_keys);
    free(original_left_child_keys);

    if (left_node -> children != NULL) {
        right_node -> children = malloc(((right_node ->num_keys + 1) + 
                                        (left_node_num_keys + 1)) * 
                                        sizeof(struct tree_node));

        memcpy(right_node -> children, original_left_children, 
               (left_node_num_keys + 1) * sizeof(struct tree_node));

        if (original_right_children != NULL) {
            memcpy(right_node -> children + left_node_num_keys + 1, original_right_children,
                    (right_node -> num_keys + 1) * sizeof(struct tree_node));
        }
        free(original_right_children);
    }

    free(left_node -> children);
    right_node -> num_keys = (right_node -> num_keys) + left_node_num_keys + 1;

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

    parent -> children = malloc(((parent -> num_keys) * sizeof(struct tree_node)));
    if (((parent -> num_keys) - 1) * sizeof(struct kv_pair) == 0) {
        parent -> pairs = NULL;
    } else {
        parent -> pairs = malloc(((parent -> num_keys) - 1) * sizeof(struct kv_pair));
    }

    memcpy(parent -> pairs, original_parent_keys, inter_key_idx * sizeof(struct kv_pair));
    memcpy(parent -> pairs + inter_key_idx, 
            original_parent_keys + (inter_key_idx) + 1, 
            ((parent -> num_keys) - inter_key_idx - 1) * sizeof(struct kv_pair));
    
    memcpy(parent -> children, original_parent_children, 
           inter_key_idx * sizeof(struct tree_node));
    memcpy((parent -> children) + inter_key_idx,
            original_parent_children + inter_key_idx + 1,
            ((parent -> num_keys) - inter_key_idx) * sizeof(struct tree_node));
    free(original_parent_children);
    free(original_parent_keys);
    (parent -> num_keys) --;

    for (int i = 0; i <= parent -> num_keys; i++) {
        struct tree_node * child = parent -> children + i;
        if (child -> children != NULL) {
            for (int j = 0; j <= child -> num_keys; j++) {
                (child -> children + j) -> parent = child;
            }
        }
    }

}

/*
 * merge right_node to left_node
 * inter_key_index is the index of key separated two nodes in the parent
 */
void merge_from_right(struct tree_node * left_node, struct tree_node * right_node,
                    struct tree_node * parent, int inter_key_idx) {
    
    struct kv_pair * original_right_child_keys = right_node -> pairs;
    struct tree_node * original_right_children = right_node -> children;
    struct kv_pair * original_parent_keys = parent -> pairs;
    struct tree_node * original_parent_children = parent -> children;

    int right_node_num_keys = right_node -> num_keys;
    left_node -> pairs = realloc(left_node -> pairs, (left_node -> num_keys + 
    right_node_num_keys + 1) * sizeof(struct kv_pair));

    memcpy(left_node -> pairs + (left_node -> num_keys), 
           parent -> pairs + inter_key_idx, sizeof(struct kv_pair));
    memcpy(left_node -> pairs + (left_node -> num_keys) + 1, right_node -> pairs,
            sizeof(struct kv_pair) * right_node_num_keys);
    free(original_right_child_keys);

    if (right_node -> children != NULL) {

        left_node -> children = realloc(left_node -> children,
        ((left_node -> num_keys + 1) + 
        (right_node_num_keys + 1)) * sizeof(struct tree_node));

        memcpy(left_node -> children + (left_node -> num_keys + 1), 
               original_right_children, (right_node_num_keys + 1) * sizeof(struct tree_node));
    }

    free(right_node -> children);

    left_node -> num_keys = (left_node -> num_keys) + right_node_num_keys + 1;


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


    parent -> children = malloc(((parent -> num_keys) * sizeof(struct tree_node)));

    if (((parent -> num_keys) - 1) * sizeof(struct kv_pair) == 0) {
        parent -> pairs = NULL;
    } else {
        parent -> pairs = malloc(((parent -> num_keys) - 1) * sizeof(struct kv_pair));
    }

    memcpy(parent -> pairs, original_parent_keys, 
           inter_key_idx * sizeof(struct kv_pair));
    memcpy(parent -> pairs + inter_key_idx, 
            original_parent_keys + (inter_key_idx) + 1, 
            ((parent -> num_keys) - inter_key_idx - 1) * sizeof(struct kv_pair));

    memcpy(parent -> children, original_parent_children, 
           (inter_key_idx + 1) * sizeof(struct tree_node));
    memcpy((parent -> children) + inter_key_idx + 1,
            original_parent_children + inter_key_idx + 2,
            ((parent -> num_keys) - inter_key_idx - 1) * sizeof(struct tree_node));
    
    free(original_parent_children);
    free(original_parent_keys);
    (parent -> num_keys) --;

    for (int i = 0; i <= parent -> num_keys; i++) {
        struct tree_node * child = parent -> children + i;
        if (child -> children != NULL) {

            for (int j = 0; j <= child -> num_keys; j++) {
                (child -> children + j) -> parent = child;
            }
        }
    }

}

// move children from right_node to left_node
void move_c_from_right_to_left(struct tree_node * left_node, struct tree_node * right_node) {

    struct tree_node * original_right_children = right_node -> children;

    left_node -> children 
    = realloc(left_node -> children, (left_node -> num_keys + 1) * sizeof(struct tree_node));

    right_node -> children 
    = malloc((right_node -> num_keys + 1) * sizeof(struct tree_node));

    memcpy(left_node -> children + (left_node -> num_keys), 
           original_right_children, sizeof(struct tree_node));

    memcpy(right_node -> children, original_right_children + 1, 
           sizeof(struct tree_node) * (right_node -> num_keys + 1));

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
    (left_node -> children + (left_node -> num_keys)) -> parent = left_node;
}

// move children from left_node to right_node
void move_c_from_left_to_right(struct tree_node * left_node, struct tree_node * right_node) {

    struct tree_node * original_right_children = right_node -> children;
    struct tree_node tmp = {};

    memcpy(&tmp, left_node -> children + (left_node -> num_keys + 1),
           sizeof(struct tree_node));

    left_node -> children 
    = realloc(left_node -> children, (left_node -> num_keys + 1) * sizeof(struct tree_node));

    right_node -> children 
    = malloc((right_node -> num_keys + 1) * sizeof(struct tree_node));

    memcpy(right_node -> children, &tmp, sizeof(struct tree_node));

    memcpy(right_node -> children + 1, original_right_children, 
           (right_node -> num_keys) * sizeof(struct tree_node));

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
    (right_node -> children) -> parent = right_node;
}

int btree_delete(uint32_t key, void * helper) {

    struct tree_node * root = helper;
    uint16_t * info = (uint16_t *) (root + 1);
    uint16_t branching = *info;

    //uint16_t n_processors = *(info + 1);
    sem_t * r_sem = (sem_t *) (info + 3);
    sem_t * w_sem = (r_sem + 1);
    sem_wait(w_sem);

    int lower_bound = (branching)/2 + ((branching)%2 != 0);
    int found = 0;
    struct tree_node * leaf_node;
    int leaf_key_index;
    while (root -> children != NULL) {
        int count = 0;
        while (count < (root -> num_keys)) {

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
                swap_key(root, count, left_child_root, 
                         left_child_root -> num_keys - 1);

                leaf_key_index = left_child_root -> num_keys - 1;
                leaf_node = left_child_root;

                break;
            }
            count ++;
        }

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

                found = 1;
                leaf_key_index = leaf_count;
                leaf_node = root;

                break;
            }
            leaf_count ++;
        }
    }
    if (found) {

        struct tree_node * parent = leaf_node -> parent;

        delete_key_from_leaf_node(leaf_node, leaf_key_index);
        if (leaf_node -> num_keys + 1 >= lower_bound) {
            sem_post(w_sem);
            return 0;
        } else {
            if (leaf_node -> parent == NULL) {
                sem_post(w_sem);
                return 0;
            }
            int parent_num_keys = leaf_node -> parent -> num_keys;

            struct tree_node * p_children = leaf_node -> parent -> children;
            int child_index = 0;

            // determine the index of leaf node in its parent's children
            while (child_index <= parent_num_keys) {

                if ((p_children + child_index) == leaf_node) {
                    break;
                }
                child_index ++;
            }

            // if first element, check if right sibling has excess key
            if (child_index == 0) {

                if (((p_children + 1) -> num_keys) + 1 > lower_bound) {

                    struct tree_node * right_sib = p_children + 1;
                    struct kv_pair * min = delete_key_from_leaf_node_with_return(
                        right_sib, 0
                    );

                    move_key_to_leaf(
                        leaf_node -> parent, child_index, p_children + child_index
                    );
                    memcpy((leaf_node -> parent -> pairs) + child_index, 
                            min, sizeof(struct kv_pair));
                    free(min);
                    sem_post(w_sem);
                    return 0;
                }
            
            // if last element, check if left sibling has excess key
            } else if (child_index == parent_num_keys) {

                if ((p_children + parent_num_keys - 1) -> num_keys + 1 > lower_bound) {

                    struct tree_node * left_sib = p_children + parent_num_keys - 1;
                    struct kv_pair * max = delete_key_from_leaf_node_with_return(
                        left_sib, left_sib -> num_keys - 1
                    );
                    move_key_to_leaf(
                        leaf_node -> parent, 
                        child_index - 1, 
                        p_children + child_index
                    );

                    memcpy((leaf_node -> parent -> pairs) + child_index - 1, 
                            max, sizeof(struct kv_pair));
                    free(max);
                    sem_post(w_sem);
                    return 0;
                }
            
            // otherwise, check both left and right siblings
            } else {
                int suitable = 0;

                if ((p_children + child_index - 1) -> num_keys + 1 > lower_bound) {

                    suitable = 1;
                    struct tree_node * left_sib = p_children + child_index - 1;
                    struct kv_pair * max = delete_key_from_leaf_node_with_return(
                        left_sib, left_sib -> num_keys - 1
                    );

                    move_key_to_leaf(
                        leaf_node -> parent, child_index - 1, p_children + child_index
                    );

                    memcpy((leaf_node -> parent -> pairs) + child_index - 1, 
                            max, sizeof(struct kv_pair));
                    free(max);
                    sem_post(w_sem);
                    return 0;
                }
                if (!suitable) {

                    if ((p_children + child_index + 1) -> num_keys + 1 > lower_bound) {
                        struct tree_node * right_sib = p_children + child_index + 1;
                        struct kv_pair * min = delete_key_from_leaf_node_with_return(
                            right_sib, 0
                        );
                        move_key_to_leaf(
                        leaf_node -> parent, 
                        child_index, 
                        p_children + child_index
                        );

                        memcpy((leaf_node -> parent -> pairs) + child_index, 
                                min, sizeof(struct kv_pair));
                        free(min);
                        sem_post(w_sem);
                        return 0;
                    }
                }
            }

            // now here means not returned, so no immediate sibling of the target node can share key
            if (child_index == 0) {

                struct tree_node * right_child = p_children + 1;
                merge_from_right(leaf_node, right_child, leaf_node -> parent, 0);
            } else {

                struct tree_node * left_child = p_children + child_index - 1;
                merge_from_left(left_child, 
                                leaf_node, 
                                leaf_node -> parent, 
                                child_index - 1);
            }

            // conduct the previous step recursively up the tree
            while ((parent -> parent != NULL) && 
                   (parent -> num_keys + 1 < lower_bound)) {

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
                        memcpy((p_parent ->pairs) + pc_index, 
                                min, sizeof(struct kv_pair));
                        free(min);
                        move_c_from_right_to_left(pp_children, pp_children + 1);
                        sem_post(w_sem);
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
                        sem_post(w_sem);
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
                        sem_post(w_sem);
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
                            sem_post(w_sem);
                            return 0;
                        }
                    }
                }
                if (pc_index == 0) {
                    struct tree_node * right_child = pp_children + 1;
                    merge_from_right(parent, right_child, parent -> parent, 0);
                } else {
                    struct tree_node * left_child = pp_children + pc_index - 1;
                    merge_from_left(left_child, parent, parent -> parent, pc_index - 1);
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
                sem_post(w_sem);
                return 0;
            }
            sem_post(w_sem);
            return 0;
        }

    } else {
        sem_post(w_sem);
        return 1;
    }
    sem_post(w_sem);
    return 1;
}

// pre-order traversal attaches node to ls
int pre_order(struct tree_node * root, int count, struct node ** ls) {
    if (root -> children == NULL) {
        struct node * new_node = *ls + count;
        int num_keys = root -> num_keys;
        new_node -> num_keys = num_keys;
        new_node -> keys = malloc(num_keys * sizeof(uint32_t));
        for (int i = 0; i < num_keys; i++) {
            *((new_node -> keys) + i) = (root -> pairs + i) -> key;
        }
        return count + 1;
    }
    int root_num_keys = root -> num_keys;
    count ++;
    struct node * new_node = *ls + count - 1;
    new_node -> num_keys = root_num_keys;
    new_node -> keys = malloc(root_num_keys * sizeof(uint32_t));
    for (int i = 0; i < root_num_keys; i++) {
        *((new_node -> keys) + i) = (root -> pairs + i) -> key;
    }
    for (int i = 0; i < root_num_keys + 1; i++) {
        count = pre_order((root -> children) + i, count, ls);
    }
    return count;
}

/*
 * conduct a pre-order traversal to count the number of nodes
 * will be used for determine the size when dynamically allocating memory
 */
int pre_order_count(struct tree_node * root, int count) {
    if (root -> children == NULL) {
        return count + 1;
    }
    count ++;
    for (int i = 0; i < (root -> num_keys) + 1; i++) {
        count = pre_order_count((root -> children) + i, count);
    }
    return count;
}

uint64_t btree_export(void * helper, struct node ** list) {
    struct tree_node * root = helper;
    uint16_t * info = (uint16_t *) (root + 1);
    uint16_t * reading = info + 2;
    sem_t * r_sem = (sem_t *) (info + 3);
    sem_t * w_sem = (r_sem + 1);

    sem_wait(r_sem);
    (*reading) ++;
    if (*reading == 1) {
        sem_wait(w_sem);
    }
    sem_post(r_sem);
    if (root -> num_keys == 0) {
        *list = NULL;
        return 0;
    }
    int count = 0;
    int length = pre_order_count(root, 0);
    *list = malloc(sizeof(struct node) * length);
    int result = pre_order(root, count, list);

    sem_wait(r_sem);
    (*reading) --;
    if (*reading == 0) {
        sem_post(w_sem);
    }
    sem_post(r_sem);

    return result;
}

void encrypt_tea(uint32_t plain[2], uint32_t cipher[2], uint32_t key[4]) {
    // plain contains the 64 bit plaintext
    uint32_t sum = 0;
    cipher[0] = plain[0];
    cipher[1] = plain[1];
    // loop 1024 times:
    for (int i = 0; i < 1024; i++) {
        sum = (sum + 0x9E3779B9);
        cipher[0] = (cipher[0] + (((cipher[1] << 4) + key[0]) ^ 
                                    (cipher[1] + sum) ^ 
                                    ((cipher[1] >> 5) + key[1]))); 
        cipher[1] = (cipher[1] + (((cipher[0] << 4) + key[2]) ^ 
                                    (cipher[0] + sum) ^ 
                                    ((cipher[0] >> 5) + key[3])));
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