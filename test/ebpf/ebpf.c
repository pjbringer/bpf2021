#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <stdio.h>

static const bool ops_exists[256] = {
        /* 0x.0 */                  /* 0x0.4 */                   /* Ox.8 */                  /* 0x.C */
/* 0x0. */ false, false, false, false, true , true , false, true ,   false, false, false, false, true , false, false, true ,
/* 0x1. */ false, false, false, false, true , true , false, true ,   true , false, false, false, true , true , false, true ,
/* 0x2. */ true , false, false, false, true , true , false, true ,   true , false, false, false, true , true , false, true ,
/* 0x3. */ true , false, false, false, true , true , false, true ,   true , false, false, false, true , true , false, true ,
/* 0x4. */ true , false, false, false, true , true , false, true ,   true , false, false, false, true , true , false, true ,
/* 0x5. */ true , false, false, false, true , true , false, true ,   true , false, false, false, true , true , false, true ,
/* 0x6. */ false, true , true , true , true , true , false, true ,   false, true , true , true , true , true , false, true ,
/* 0x7. */ false, true , true , true , true , true , false, true ,   false, true , true , true , true , true , false, true ,
/* 0x8. */ false, false, false, false, true , true , false, true ,   false, false, false, false, false, false, false, false,
/* 0x9. */ false, false, false, false, true , true , false, true ,   false, false, false, false, true , false, false, true ,
/* 0xA. */ false, false, false, false, true , true , false, true ,   false, false, false, false, true , true , false, true ,
/* 0xB. */ false, false, false, false, true , true , false, true ,   false, false, false, false, true , true , false, true ,
/* 0xC. */ false, false, false, false, true , true , false, true ,   false, false, false, false, true , true , false, true ,
/* 0xD. */ false, false, false, false, true , true , false, false,   false, false, false, false, true , true , false, false,
/* 0xE. */ false, false, false, false, false, false, false, false,   false, false, false, false, false, false, false, false,
/* 0xF. */ false, false, false, false, false, false, false, false,   false, false, false, false, false, false, false, false,
};

static int ops_tested[256];

static void print_missing_coverage() {
    static_assert(sizeof(ops_exists)/sizeof(ops_exists[0]) == 256);
    static_assert(sizeof(ops_tested)/sizeof(ops_tested[0]) == 256);
    for (int i = 0; i < 256; i++) {
        if (ops_exists[i] && ops_tested[i] == 0) {
            printf("Op 0x%02x exists but was not tested.\n", (unsigned)i);
        } else if (!ops_exists[i] && ops_tested[i] != 0) {
            printf("Op 0x%02x doesn't exist but was tested.\n", (unsigned)i);
        }
    }
}

int main() {

    print_missing_coverage();
    return 0;
}
