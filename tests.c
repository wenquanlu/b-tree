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

int main() {
    // Your own testing code here
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_basic_insert_decrypt),
        cmocka_unit_test(test_basic_export),
        cmocka_unit_test(test_basic_delete)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}