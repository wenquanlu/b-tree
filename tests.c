#include "btreestore.h"
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include "cmocka.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>

void test_basic_insert_decrypt() {
    void * helper = init_store(3, 4);
    uint32_t encryptionz_key[4] = {1,2,3,4};
    int x = btree_insert(2, "abcdefg", 8, encryptionz_key, 12, helper);
    assert_int_equal(x, 0);
    char decrypt[10] = {};
    btree_decrypt(2, decrypt, helper);
    assert_string_equal("abcdefg", decrypt);
    int y = btree_insert(5, "hello", 6, encryptionz_key, 12, helper);
    assert_int_equal(y, 0);
    int z = btree_insert(3, "okfine", 7, encryptionz_key, 12, helper);
    assert_int_equal(z, 0);
    int m = btree_insert(6, "iamdavid",9, encryptionz_key, 12, helper);
    assert_int_equal(m, 0);
    btree_decrypt(6, decrypt, helper);
    assert_string_equal("iamdavid", decrypt);
    close_store(helper);
}

void test_basic_export() {
    void * helper = init_store(3, 4);
    uint32_t encryptionz_key[4] = {1,2,3,4};
    btree_insert(2, "abcdefg", 8, encryptionz_key, 12, helper);
    btree_insert(5, "hello", 6, encryptionz_key, 12, helper);
    btree_insert(3, "okfine", 7, encryptionz_key, 12, helper);
    btree_insert(6, "iamdavid",9, encryptionz_key, 12, helper);
    struct node *list = NULL;
    uint64_t num = btree_export(helper, &list);
    assert_int_equal(3, num);
    assert_int_equal(*(list[0].keys), 3);
    assert_int_equal(*(list[1].keys), 2);
    assert_int_equal(*(list[2].keys), 5);
    assert_int_equal(*(list[2].keys + 1), 6);
    free(list[0].keys);
    free(list[1].keys);
    free(list[2].keys);
    free(list);
    btree_insert(4, "world", 6, encryptionz_key, 12, helper);
    btree_insert(9, "efgh", 5, encryptionz_key, 12, helper);
    btree_insert(10, "wenwen", 7, encryptionz_key, 12, helper);
    btree_insert(13, "www", 4, encryptionz_key, 12, helper);
    num = btree_export(helper, &list);
    assert_int_equal(7, num);
    assert_int_equal(*(list[0].keys), 5);
    assert_int_equal(*(list[1].keys), 3);
    assert_int_equal(*(list[2].keys), 2);
    assert_int_equal(*(list[3].keys), 4);
    assert_int_equal(*(list[4].keys), 9);
    assert_int_equal(*(list[5].keys), 6);
    assert_int_equal(*(list[6].keys), 10);
    assert_int_equal(*(list[6].keys + 1), 13);
    for (int i = 0; i < 7; i++) {
        free(list[i].keys);
    }
    free(list);
    close_store(helper);
}


void test_retrieve() {
    struct info result = {};
    void * helper = init_store(5, 8);
    uint32_t encryptionz_key[4] = {5,6,7,8};
    uint32_t encryptionz_key2[4] = {1,2,3,4};
    uint32_t encryptionz_key3[4] = {3,1,4,1};
    btree_insert(68, "hello", 6, encryptionz_key, 9, helper);
    btree_insert(12, "world", 6, encryptionz_key2, 10, helper);
    btree_insert(42, "from", 5, encryptionz_key3, 11, helper);
    btree_insert(78, "david", 6, encryptionz_key, 12, helper);
    btree_insert(92, "good", 5, encryptionz_key2, 13, helper);
    btree_insert(81, "morning", 8, encryptionz_key3, 14, helper);
    btree_insert(33, "night", 6, encryptionz_key, 15, helper);
    btree_retrieve(12, &result, helper);
    assert_int_equal(result.nonce, 10);
    assert_int_equal(result.size, 6);
    assert_int_equal(result.key[0], 1);
    assert_int_equal(result.key[1], 2);
    assert_int_equal(result.key[2], 3);
    assert_int_equal(result.key[3], 4);

    btree_retrieve(81, &result, helper);
    assert_int_equal(result.nonce, 14);
    assert_int_equal(result.size, 8);
    
    assert_int_equal(result.key[0], 3);
    assert_int_equal(result.key[1], 1);
    assert_int_equal(result.key[2], 4);
    assert_int_equal(result.key[3], 1);

    close_store(helper);
}

void test_basic_delete() {
    void * helper = init_store(3, 4);
    uint32_t encryptionz_key[4] = {1,2,3,4};
    btree_insert(2, "abcdefg", 8, encryptionz_key, 12, helper);
    btree_insert(5, "hello", 6, encryptionz_key, 12, helper);
    btree_insert(3, "okfine", 7, encryptionz_key, 12, helper);
    btree_insert(6, "iamdavid",9, encryptionz_key, 12, helper);
    btree_insert(4, "world", 6, encryptionz_key, 12, helper);
    btree_insert(9, "efgh", 5, encryptionz_key, 12, helper);
    btree_insert(10, "wenwen", 7, encryptionz_key, 12, helper);
    btree_insert(13, "www", 4, encryptionz_key, 12, helper);
    btree_insert(1, "mmm", 4, encryptionz_key, 12, helper);
    btree_insert(8, "lll", 4, encryptionz_key, 12, helper);
    btree_delete(4, helper);
    struct node *list = NULL;
    uint64_t num = btree_export(helper, &list);
    assert_int_equal(7, num);
    assert_int_equal(*(list[0].keys), 5);
    assert_int_equal(*(list[1].keys), 2);
    assert_int_equal(*(list[2].keys), 1);
    assert_int_equal(*(list[3].keys), 3);
    assert_int_equal(*(list[4].keys), 9);
    assert_int_equal(*(list[5].keys), 6);
    assert_int_equal(*(list[5].keys + 1), 8);
    assert_int_equal(*(list[6].keys), 10);
    assert_int_equal(*(list[6].keys + 1), 13);
    for (int i = 0; i < 7; i++) {
        free(list[i].keys);
    }
    free(list);
    btree_delete(3, helper);
    num = btree_export(helper, &list);
    assert_int_equal(4, num);
    assert_int_equal(*(list[0].keys), 5);
    assert_int_equal(*(list[0].keys + 1), 9);
    assert_int_equal(*(list[1].keys), 1);
    assert_int_equal(*(list[1].keys + 1), 2);
    assert_int_equal(*(list[2].keys), 6);
    assert_int_equal(*(list[2].keys + 1), 8);
    assert_int_equal(*(list[3].keys), 10);
    assert_int_equal(*(list[3].keys + 1), 13);
    for (int i = 0; i < 4; i++) {
        free(list[i].keys);
    }
    free(list);
    btree_delete(6, helper);
    btree_delete(8, helper);
    num = btree_export(helper, &list);
    assert_int_equal(4, num);
    assert_int_equal(*(list[0].keys), 2);
    assert_int_equal(*(list[0].keys + 1), 9);
    assert_int_equal(*(list[1].keys), 1);
    assert_int_equal(*(list[2].keys), 5);
    assert_int_equal(*(list[3].keys), 10);
    assert_int_equal(*(list[3].keys + 1), 13);
    for (int i = 0; i < 4; i++) {
        free(list[i].keys);
    }
    free(list);
    btree_delete(10, helper);
    btree_delete(5, helper);
    num = btree_export(helper, &list);
    assert_int_equal(3, num);
    assert_int_equal(*(list[0].keys), 9);    
    assert_int_equal(*(list[1].keys), 1);
    assert_int_equal(*(list[1].keys + 1), 2);
    assert_int_equal(*(list[2].keys), 13);
    for (int i = 0; i < 3; i++) {
        free(list[i].keys);
    }
    free(list);
    btree_delete(1, helper);
    btree_delete(2, helper);
    num = btree_export(helper, &list);
    assert_int_equal(1, num);
    assert_int_equal(*(list[0].keys), 9);
    assert_int_equal(*(list[0].keys + 1), 13);
    free(list[0].keys);
    free(list);
    btree_delete(9, helper);
    //btree_delete(13, helper);  questionable
    close_store(helper);

}

void test_stress() {
    void * helper = init_store(3, 4);
    uint32_t encryptionz_key[4] = {1,2,3,4};  
    btree_insert(10200, "abcdefg", 8, encryptionz_key, 12, helper);
    btree_insert(200, "abcdefg", 8, encryptionz_key, 12, helper);
    btree_insert(20200, "abcdefg", 8, encryptionz_key, 12, helper);
    btree_insert(10201, "abcdefg", 8, encryptionz_key, 12, helper);
    btree_insert(201, "abcdefg", 8, encryptionz_key, 12, helper);
    btree_insert(10202, "abcdefg", 8, encryptionz_key, 12, helper);
    btree_insert(20201, "abcdefg", 8, encryptionz_key, 12, helper);
    btree_insert(202, "abcdefg", 8, encryptionz_key, 12, helper);
    btree_insert(10203, "abcdefg", 8, encryptionz_key, 12, helper);
    btree_insert(20202, "abcdefg", 8, encryptionz_key, 12, helper);
    btree_insert(203, "abcdefg", 8, encryptionz_key, 12, helper);
    btree_insert(10204, "abcdefg", 8, encryptionz_key, 12, helper);
    btree_insert(20203, "abcdefg", 8, encryptionz_key, 12, helper);
    btree_insert(204, "abcdefg", 8, encryptionz_key, 12, helper); ///<----
    btree_insert(10205, "abcdefg", 8, encryptionz_key, 12, helper);
    btree_insert(20204, "abcdefg", 8, encryptionz_key, 12, helper);
    btree_insert(205, "abcdefg", 8, encryptionz_key, 12, helper);
    btree_insert(10206, "abcdefg", 8, encryptionz_key, 12, helper);
    btree_insert(20205, "abcdefg", 8, encryptionz_key, 12, helper);
    btree_insert(206, "abcdefg", 8, encryptionz_key, 12, helper);
    btree_insert(10207, "abcdefg", 8, encryptionz_key, 12, helper);
    btree_insert(20206, "abcdefg", 8, encryptionz_key, 12, helper);
    btree_insert(207, "abcdefg", 8, encryptionz_key, 12, helper);
    btree_insert(10208, "abcdefg", 8, encryptionz_key, 12, helper);
    btree_insert(20207, "abcdefg", 8, encryptionz_key, 12, helper);
    btree_insert(208, "abcdefg", 8, encryptionz_key, 12, helper);
    btree_insert(10209, "abcdefg", 8, encryptionz_key, 12, helper);
    btree_insert(20208, "abcdefg", 8, encryptionz_key, 12, helper);
    btree_insert(209, "abcdefg", 8, encryptionz_key, 12, helper);
    btree_insert(10210, "abcdefg", 8, encryptionz_key, 12, helper);
    btree_insert(20209, "abcdefg", 8, encryptionz_key, 12, helper);
    btree_insert(210, "abcdefg", 8, encryptionz_key, 12, helper);
    btree_insert(10211, "abcdefg", 8, encryptionz_key, 12, helper);
    btree_insert(20210, "abcdefg", 8, encryptionz_key, 12, helper);
    btree_insert(211, "abcdefg", 8, encryptionz_key, 12, helper);
    btree_insert(10212, "abcdefg", 8, encryptionz_key, 12, helper);
    btree_insert(20211, "abcdefg", 8, encryptionz_key, 12, helper);
    btree_insert(212, "abcdefg", 8, encryptionz_key, 12, helper);
    btree_insert(10213, "abcdefg", 8, encryptionz_key, 12, helper);
    btree_insert(20212, "abcdefg", 8, encryptionz_key, 12, helper);
    btree_insert(213, "abcdefg", 8, encryptionz_key, 12, helper);
    btree_insert(10214, "abcdefg", 8, encryptionz_key, 12, helper);
    btree_insert(20213, "abcdefg", 8, encryptionz_key, 12, helper);
    btree_insert(214, "abcdefg", 8, encryptionz_key, 12, helper);
    btree_insert(10215, "abcdefg", 8, encryptionz_key, 12, helper);
    close_store(helper);
}

void test_empty_export() {
    void * helper = init_store(3, 4);
    uint32_t encryptionz_key[4] = {5,6,7,8};
    btree_insert(3, "mercifu", 8, encryptionz_key, 9, helper);
    btree_insert(4, "grace", 6, encryptionz_key, 9, helper);
    btree_insert(1, "good morning!", 14, encryptionz_key, 9, helper);
    btree_insert(6, "mercifu", 8, encryptionz_key, 9, helper);
    btree_delete(1, helper);
    btree_delete(3, helper);
    btree_delete(4, helper);
    btree_delete(6, helper);
    struct node *list = NULL;
    int x = btree_export(helper, &list);
    assert_int_equal(x, 0);
    assert_null(list);
    close_store(helper);
}

void test_error() {
    void * helper = init_store(3, 4);
    uint32_t encryptionz_key[4] = {5,6,7,8};
    int ret = btree_insert(3, "mercifu", 8, encryptionz_key, 9, helper);
    assert_int_equal(ret, 0);
    int ret1 = btree_insert(3, "mercifu", 8, encryptionz_key, 9, helper);
    btree_insert(4, "grace", 6, encryptionz_key, 9, helper);
    btree_insert(8, "good morning!", 14, encryptionz_key, 9, helper);
    btree_insert(6, "mercifu", 8, encryptionz_key, 9, helper);
    assert_int_equal(ret1, 1);
    int ret2 = btree_delete(1, helper);
    assert_int_equal(ret2, 1);
    char decrypt_result[10] = {};
    int ret3 = btree_decrypt(0, decrypt_result, helper);
    assert_int_equal(ret3, 1);
    close_store(helper);
}


void test_bulk_insert_delete() {
    void * helper = init_store(3, 4);
    uint32_t encryptionz_key[4] = {5,2,7,3};
    for (int i = 0; i < 5000; i++) {
        btree_insert(i, "ascending", 10, encryptionz_key, 9, helper);
        btree_insert(10001 - i, "descending", 10, encryptionz_key, 9, helper);
    }
    for (int i = 0; i < 4999; i++) {
        btree_delete(10001 - i, helper);
        btree_delete(i, helper);
    }
    char decrypt[12] = {};
    btree_decrypt(4999, decrypt, helper);
    assert_string_equal("ascending", decrypt);
    btree_decrypt(5002, decrypt, helper);
    assert_string_equal("descending", decrypt);
    close_store(helper);
}

void* insert_twenty(void * helper) {
    uint32_t encryptionz_key[4] = {5,2,7,3};
    for (int i = 0; i < 10; i++) {
        btree_insert(i, "text", 5, encryptionz_key, 11, helper);
    }
}

void test_concurrent_insert() {
    void * helper = init_store(3, 4);
    pthread_t thread_ids[3] = {};
    for (int i = 0; i < 3; i++) {
        pthread_create(&thread_ids[i], NULL, insert_twenty, helper);
    }
    for (int i = 0; i < 3; i++) {
        pthread_join(thread_ids[i], NULL);
    }
    struct node *list = NULL;
    int num = btree_export(helper, &list);
    assert_int_equal(num, 8);
    for (int i = 0; i < num; i++) {
        free(list[i].keys);
    }
    free(list);
    close_store(helper);
}

void * insert_key(void * helper) {
    uint32_t encryptionz_key[4] = {5,2,7,3};
    for (int i = 0; i < 10; i++) {
        //printf("btree_insert(%d, \"text\", 5, encryptionz_key, 11, helper);\n", i);
        btree_insert(i, "text", 5, encryptionz_key, 11, helper);
        sleep(0.1);
    }
}

void * delete_key(void * helper) {
    for (int i = 0; i < 10; i++) {
        //printf("btree_delete(%d, helper);\n", i);
        btree_delete(i, helper);
        sleep(0.1);
    }
}

void * insert_key2(void * helper) {
    uint32_t encryptionz_key[4] = {3,6,9,4};
    for (int i = 0; i < 10; i++) {
        btree_insert(9 - i, "text", 5, encryptionz_key, 11, helper);
        sleep(0.1);
    }
}

void * delete_key2(void * helper) {
    uint32_t encryptionz_key[4] = {3,6,9,4};
    for (int i = 0; i < 10; i++) {
        btree_delete(9 - i, helper);
        sleep(0.1);
    }
}
void test_interleave_insert_delete() {
    void * helper = init_store(3, 8);
    pthread_t thread_ids[7] = {};
    for (int i = 0; i < 7; i++) {
        if (i % 2 == 0) {
            pthread_create(&thread_ids[i], NULL, insert_key, helper);
        } else {
            pthread_create(&thread_ids[i], NULL, delete_key, helper);
        }
        //printf("i: %d\n", i);
    }
    for (int i = 0; i < 7; i++) {
        pthread_join(thread_ids[i], NULL);
    }
    /*
    struct node *list = NULL;
    int num = btree_export(helper, &list);
    assert_int_equal(num, 8);
    for (int i = 0; i < num; i++) {
        free(list[i].keys);
    }
    free(list);*/
    close_store(helper);
}

void test_interleave_insert_delete2() {
    void * helper = init_store(3, 8);
    pthread_t thread_ids[7] = {};
    for (int i = 0; i < 7; i++) {
        if (i % 2 == 0) {
            pthread_create(&thread_ids[i], NULL, insert_key2, helper);
        } else {
            pthread_create(&thread_ids[i], NULL, delete_key2, helper);
        }
        //printf("i: %d\n", i);
    }
    for (int i = 0; i < 7; i++) {
        pthread_join(thread_ids[i], NULL);
    }
    close_store(helper);
}


void * insert_key_random(void * helper) {
    uint32_t encryptionz_key[4] = {4,9,9,8};
    for (int i = 4; i < 10; i++) {
        btree_insert(i, "texts", 6, encryptionz_key, 11, helper);
        sleep(0.1);
    }
    for (int i = 7; i < 18; i++) {
        btree_insert(i, "text", 5, encryptionz_key, 11, helper);
        sleep(0.1);
    }
    for (int i = 0; i < 3; i++) {
        btree_insert(i, "text", 5, encryptionz_key, 11, helper);
        sleep(0.1);  
    }
}

void * retrieve_key(void * helper) {
    struct info result = {};
    btree_retrieve(4, &result, helper);
    //assert_int_equal(result.size, 5);
    //assert_int_equal(result.key[0], 4);

}

void test_interleave_insert_retrieve() {
    void * helper = init_store(3, 8);
    pthread_t thread_ids[2] = {};
    pthread_create(&thread_ids[0], NULL, insert_key_random, helper);
    sleep(0.3);
    pthread_create(&thread_ids[1], NULL, retrieve_key, helper);
    pthread_join(thread_ids[0], NULL);
    pthread_join(thread_ids[1], NULL);
    close_store(helper);
}

void test_encrypt_decrypt() {
    uint32_t encryptionz_key[4] = {4,9,9,8};
    uint32_t plain[2] = {0xaa998877, 0x66554433};
    uint32_t cipher[2] = {};
    encrypt_tea(plain, cipher, encryptionz_key);
    decrypt_tea(cipher, plain, encryptionz_key);
    assert_int_equal(plain[0], 0xaa998877);
    assert_int_equal(plain[1], 0x66554433);
}

void test_large_correctness() {
    void * helper = init_store(7, 4);
    uint32_t encryptionz_key[4] = {4,9,9,8};

    btree_insert(27, "abcd", 5, encryptionz_key, 12, helper);
    btree_insert(33, "abcd", 5, encryptionz_key, 12, helper);
    btree_insert(21, "abcd", 5, encryptionz_key, 12, helper);
    btree_insert(90, "abcd", 5, encryptionz_key, 12, helper);
    btree_insert(11, "abcd", 5, encryptionz_key, 12, helper);
    btree_insert(88, "abcd", 5, encryptionz_key, 12, helper);
    btree_insert(303, "abcd", 5, encryptionz_key, 12, helper);
    btree_insert(78, "abcd", 5, encryptionz_key, 12, helper);
    btree_insert(66, "abcd", 5, encryptionz_key, 12, helper);
    btree_insert(133, "abcd", 5, encryptionz_key, 12, helper);
    btree_insert(571, "abcd", 5, encryptionz_key, 12, helper);
    btree_insert(3, "abcd", 5, encryptionz_key, 12, helper);
    btree_insert(8, "abcd", 5, encryptionz_key, 12, helper);
    btree_insert(86, "abcd", 5, encryptionz_key, 12, helper);
    btree_insert(69, "abcd", 5, encryptionz_key, 12, helper);
    btree_insert(101, "abcd", 5, encryptionz_key, 12, helper);
    btree_insert(202, "abcd", 5, encryptionz_key, 12, helper);
    btree_insert(23, "abcd", 5, encryptionz_key, 12, helper);
    btree_insert(29, "abcd", 5, encryptionz_key, 12, helper);
    btree_insert(43, "abcd", 5, encryptionz_key, 12, helper);
    btree_insert(81, "abcd", 5, encryptionz_key, 12, helper);
    btree_insert(153, "abcd", 5, encryptionz_key, 12, helper);
    btree_insert(365, "abcd", 5, encryptionz_key, 12, helper);
    btree_insert(593, "abcd", 5, encryptionz_key, 12, helper);
    btree_insert(321, "abcd", 5, encryptionz_key, 12, helper);
    btree_insert(89, "abcd", 5, encryptionz_key, 12, helper);
    btree_insert(77, "abcd", 5, encryptionz_key, 12, helper);
    btree_insert(45, "abcd", 5, encryptionz_key, 12, helper);
    btree_insert(238, "abcd", 5, encryptionz_key, 12, helper);
    btree_insert(14, "abcd", 5, encryptionz_key, 12, helper);
    btree_insert(1, "abcd", 5, encryptionz_key, 12, helper);
    btree_insert(57, "abcd", 5, encryptionz_key, 12, helper);
    btree_insert(72, "abcd", 5, encryptionz_key, 12, helper);
    btree_insert(98, "abcd", 5, encryptionz_key, 12, helper);
    btree_insert(213, "abcd", 5, encryptionz_key, 12, helper);

    struct node * list = NULL;
    int num = btree_export(helper, &list);
    assert_int_equal(num, 11);
    assert_int_equal(*(list[0].keys), 78);
    assert_int_equal(*(list[1].keys), 21);
    assert_int_equal(*(list[2].keys), 1);
    assert_int_equal(*(list[3].keys), 23);
    assert_int_equal(*(list[4].keys), 43);
    assert_int_equal(*(list[5].keys), 69);
    assert_int_equal(*(list[6].keys), 90);
    assert_int_equal(*(list[7].keys), 81);
    assert_int_equal(*(list[8].keys), 98);
    assert_int_equal(*(list[9].keys), 213);
    assert_int_equal(*(list[10].keys), 365);
    for (int i = 0; i < num; i++) {
        free(list[i].keys);
    }
    free(list);
    close_store(helper);
}


int main() {
    // Your own testing code here
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_basic_insert_decrypt),
        cmocka_unit_test(test_basic_export),
        cmocka_unit_test(test_basic_delete),
        cmocka_unit_test(test_stress),
        cmocka_unit_test(test_empty_export),
        cmocka_unit_test(test_error),
        cmocka_unit_test(test_retrieve),
        cmocka_unit_test(test_bulk_insert_delete),
        cmocka_unit_test(test_concurrent_insert),
        cmocka_unit_test(test_interleave_insert_delete),
        cmocka_unit_test(test_interleave_insert_delete2),
        cmocka_unit_test(test_interleave_insert_retrieve),
        cmocka_unit_test(test_encrypt_decrypt),
        cmocka_unit_test(test_large_correctness)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}