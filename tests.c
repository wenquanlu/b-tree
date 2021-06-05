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

int main() {
    // Your own testing code here
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_basic_insert_decrypt)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}