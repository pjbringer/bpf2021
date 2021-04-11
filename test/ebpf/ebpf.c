#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <stdio.h>

#include "interpreter.h"

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

/* Tests */
//
static const uint32_t retv0 = 0;
static const instruction prog0[] = {
    {0xb4, 0x0, 0x0, 0x0000, 0x00000000}, // Mov R0 0
    {0xb5, 0x0, 0x0, 0x0000, 0x00000000}, // Exit (ie Return R0)
};
static const size_t plen0 = sizeof(prog0)/sizeof(prog0[0]);

static const uint32_t retv1 = 1;
static const instruction prog1[] = {
    {0xb4, 0x0, 0x0, 0x0000, 0x00000001}, // Mov R0 1
    {0xb5, 0x0, 0x0, 0x0000, 0x00000000}, // Exit (ie Return R0)
};
static const size_t plen1 = sizeof(prog1)/sizeof(prog1[0]);


static const uint32_t retv[] = {
    retv0, retv1,
};
static const instruction* prog[] = {
    prog0, prog1,
};
static const size_t plen[] = {
    plen0, plen1,
};
static const size_t prog_count = sizeof(prog)/sizeof(prog[0]);
static_assert(sizeof(retv)/sizeof(retv[0]) == sizeof(prog)/sizeof(prog[0]));
static_assert(sizeof(plen)/sizeof(plen[0]) == sizeof(prog)/sizeof(prog[0]));

static int ops_tested[256];

static void print_missing_coverage() {
    static_assert(sizeof(ops_exists)/sizeof(ops_exists[0]) == 256);
    static_assert(sizeof(ops_tested)/sizeof(ops_tested[0]) == 256);
    int missing = 0;
    int extra   = 0;
    for (int i = 0; i < 256; i++) {
        if (ops_exists[i] && ops_tested[i] == 0) {
            printf("Op 0x%02x exists but was not tested.\n", (unsigned)i);
            missing++;
        } else if (!ops_exists[i] && ops_tested[i] != 0) {
            printf("Op 0x%02x doesn't exist but was tested.\n", (unsigned)i);
            extra++;
        }
    }
    if (missing)
        printf("%d ops are not covered by the tests.\n", missing);
    if (extra)
        printf("%d unknown ops are somehow covered by the tests. Please fix immediately.\n", extra);
}

static int run_tests() {
    int rc; // Return code from called functions
    uint32_t rv; // Return value from the BPF program
    int ret = 0; // If no error is found, we'll return 0, the success value.
    Intrp_ctx *ctx;

    // We'll run through all the programs, stopping at the first error
    for (int i = 0; i < (int)prog_count; i++) {
        printf("Running test %d\n", i);
        rv = 0;
        rc = intrp_create(&ctx, prog[i], plen[i]);
        if (rc) {
            printf("Failed creating interpreter context for program %d\n", i);
            ret = -1;
            break;
        }
        rc = intrp_start(ctx, 0 /* This will need to be changed somehow */);
        if (rc) {
            printf("Failed starting program %d\n", i);
            ret = -1;
            break;
        }
        while ((rc = intrp_step(ctx)) == 0) { /* Nothing */ }
        if (rc < 0) {
            printf("Program %d failed execution: %d\n", i, rc);
            ret = -1;
            continue;
        }
        rc = intrp_stop(ctx, &rv);
        if (rc) {
            printf("Could not stop program %d\n", i);
            ret = -1;
            break;
        }
        if (rv != retv[i]) {
            printf("Test %d returned %d (0x%08x) instead of the expected %d (0x%08x)\n",
                   i, (int32_t) rv, rv, (int32_t)retv[i], retv[i]);
        }
        rc = intrp_delete(&ctx);
        if (rc) {
            printf("Failed deleting interpreter context for program %d\n", i);
            ret = -1;
            break;
        }
    }

    return ret;
}

int main() {

    run_tests();
    print_missing_coverage();
    return 0;
}
