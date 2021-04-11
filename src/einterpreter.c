

/*
 * (extended) BPF Interpreter
 */

/* Documentation



Bibliography
------------
- networking/filter.txt from Linux Kernel Documentation
- https://docs.cilium.io/en/latest/bpf/
- https://github.com/iovisor/bpf-docs/blob/master/eBPF.md

*/

/* File includes and declarations */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>   /* To remove in favor of proper error reporting */
#include <stdlib.h>  /* Malloc/free */
#include <string.h>  /* Memset      */

#include "interpreter.h"

#define    MAXINST     4096  /* Maximum program length. Where is this from?  */
#define    STACK_SZ     512  /* BPF prog. stack size. Where is this from?    */


/* Internal structures */

struct Intrp_ctx_{ // This structure get typedef'd in interpreter.h
    const instruction *prog;
    int16_t pl;              /* Length of the program (in instructions)      */
    int16_t  pc;             /* Program counter in [-1;pl[                   */
    uint64_t regs[10];
    uint64_t sp;
    uint32_t stack[STACK_SZ/sizeof(uint32_t)];   /* Uint32_t for alignement  */
};


static Intrp_ctx* intrp_alloc();
static void intrp_free(Intrp_ctx*);

/* Code */

// XXX : Error cases: invalid parameters, program validation failure, allocation failure
int intrp_create(Intrp_ctx **ctx, const instruction *prog, int16_t pl) {
    Intrp_ctx *c;

    /* Step 1: Validate basic properties of the BPF program */
    // We also set the output variable to NULL (as soon as we are reasonably
    // confident that it's a valid pointer).
    if (ctx == NULL || prog == NULL || pl < 0 || pl > MAXINST) {
        return -1;
    }
    *ctx = NULL;

    /* Step 2: Validate the program */
    // There's a bunch to do at this point:
    // - ensure there are no backward loop
    // - ensure all registers read are first initialized
    // XXX

    /* Step 3: Allocate the context */
    c = intrp_alloc();
    if (c == NULL) {
        return -1;
    }

    /* Step 4: Fill the allocated structure */
    // We copy the input parameters, set the progam value to an invalid value
    c->prog = prog;
    c->pl = pl;
    c->pc = -1; 
    memset(c->regs, 0, sizeof(c->regs));
    uint32_t BPFd = ('B' << 0) | ('P' << 8) | ('F' << 16) | ('.' << 24);
    for (size_t i = 0; i < sizeof(c->stack)/sizeof(*c->stack); i++) { // XXX : Pick an ARRAY_SIZE macro and use it
        c->stack[i] = BPFd;
    }

    /* Step 5: Return the allocated context */
    *ctx = c;
    return 0;

}

int intrp_delete(Intrp_ctx **ctx) {
    /* Step 1: Validate input */
    if (ctx == NULL || *ctx == NULL) {
        return -1;
    }
    intrp_free(*ctx);
    *ctx = NULL;
    return 0;
}

int intrp_start(Intrp_ctx *ctx, uintptr_t arg) {
    /* Step 1: Validate the input parameters */
    if (ctx == NULL || ctx->prog == NULL || ctx->pc != -1) {
        return -1;
    }
    /* Step 2: Prepare the context for execution */
    // We set the program counter to the beginning of the program
    // We set the argument (arg) to regiser 1. XXX Source this ABI choice
    ctx->pc = 0;
    ctx->regs[1] = (uint64_t) arg; // XXX Not sure about arg's type and thus about this cast

    return 0;
}

int intrp_stop(Intrp_ctx *ctx, uint32_t *arg) {
    if (ctx == NULL) {
        return -1;
    }
    // XXX Somehow read output, maybe from register 0, or maybe more
    if (arg != NULL) {
       *arg = (uintptr_t) ctx->regs[0]; // Same as above, unsure about cast
    }
    /* Step 3: Place the context in a halted state */
    ctx->pc = -1;
    return 0;
}

int intrp_step(Intrp_ctx *ctx) {
    // The program counter may be set out of what by the jumps. Either check there or be ready to have weird things here.
    if (ctx == NULL || ctx->prog == NULL || ctx->pc < 0) {
        return -1;
    }

    int16_t pc = ctx->pc;
    if (pc >= ctx->pl) {
        return pc == ctx->pl ? 1 : -1;
    }

    uint8_t op = ctx->prog[pc].op;
    uint8_t dst = ctx->prog[pc].dst;
    uint8_t src = ctx->prog[pc].src;
    uint16_t off = ctx->prog[pc].off;
    uint32_t imm = ctx->prog[pc].imm;
    switch (op) {
      /*** 64-bit ALU ***/
      case 0x07: /* add dst, imm */
        ctx->regs[dst] += imm;
        break;
      case 0x0f: /* add dst, src */
        ctx->regs[dst] += ctx->regs[src];
        break;
      case 0x17: /* sub dst, imm */
        ctx->regs[dst] -= imm;
        break;
      case 0x1f: /* sub dst, src */
        ctx->regs[dst] -= ctx->regs[src];
        break;
      case 0x27: /* mul dst, imm */
        ctx->regs[dst] *= imm;
        break;
      case 0x2f: /* mul dst, src */
        ctx->regs[dst] *= ctx->regs[src];
        break;
      case 0x37: /* div dst, imm */
        ctx->regs[dst] /= imm;
        break;
      case 0x3f: /* div dst, src */
        ctx->regs[dst] /= ctx->regs[src];
        break;
      case 0x47: /* or dst, imm */
        ctx->regs[dst] |= imm;
        break;
      case 0x4f: /* or dst, src */
        ctx->regs[dst] |= ctx->regs[src];
        break;
      case 0x57: /* and dst, imm */
        ctx->regs[dst] &= imm;
        break;
      case 0x5f: /* and dst, src */
        ctx->regs[dst] &= ctx->regs[src];
        break;
      case 0x67: /* lsh dst, imm */
        ctx->regs[dst] <<= imm;
        break;
      case 0x6f: /* lsh dst, src */
        ctx->regs[dst] <<= ctx->regs[src];
        break;
      case 0x77: /* rsh dst, imm */
        ctx->regs[dst] >>= imm;
        break;
      case 0x7f: /* rsh dst, imm */
        ctx->regs[dst] >>= ctx->regs[src];
        break;
      case 0x87: /* neg dst */
        ctx->regs[dst] = -ctx->regs[dst];
        break;
      case 0x97: /* mod dst, imm */
        ctx->regs[dst] %= imm;
        break;
      case 0x9f: /* mod dst, src */
        ctx->regs[dst] %= ctx->regs[src];
        break;
      case 0xa7: /* xor dst, imm */
        ctx->regs[dst] ^= imm;
        break;
      case 0xaf: /* xor dst, src */
        ctx->regs[dst] ^= ctx->regs[src];
        break;
      case 0xb7: /* mov dst, imm */
        ctx->regs[dst] = imm;
        break;
      case 0xbf: /* mov dst, src */
        ctx->regs[dst] = ctx->regs[src];
        break;
      case 0xc7: /* arsh dst, imm */
        ctx->regs[dst] = (int64_t)ctx->regs[dst] >> (int64_t)imm;
        break;
      case 0xcf:
        ctx->regs[dst] = (int64_t)ctx->regs[dst] >> (int64_t)ctx->regs[src];
        break;

      /*** 32-bit ALU ***/
      case 0x04: /* add32 dst, imm */
        ctx->regs[dst] = (uint32_t)ctx->regs[dst] + imm;
        break;
      case 0x0c: /* add32 dst, src */
        ctx->regs[dst] = (uint32_t)ctx->regs[dst] + (uint32_t)ctx->regs[src];
        break;
      case 0x14: /* sub32 dst, imm */
        ctx->regs[dst] = (uint32_t)ctx->regs[dst] - imm;
        break;
      case 0x1c: /* sub32 dst, src */
        ctx->regs[dst] = (uint32_t)ctx->regs[dst] - (uint32_t)ctx->regs[src];
        break;
      case 0x24: /* mul32 dst, imm */
        ctx->regs[dst] = (uint32_t)ctx->regs[dst] * imm;
        break;
      case 0x2c: /* mul32 dst, src */
        ctx->regs[dst] = (uint32_t)ctx->regs[dst] * (uint32_t)ctx->regs[src];
        break;
      case 0x34: /* div32 dst, imm */
        ctx->regs[dst] = (uint32_t)ctx->regs[dst] / imm;
        break;
      case 0x3c: /* div32 dst, src */
        ctx->regs[dst] = (uint32_t)ctx->regs[dst] / (uint32_t)ctx->regs[src];
        break;
      case 0x44: /* or32 dst, imm */
        ctx->regs[dst] = (uint32_t)ctx->regs[dst] | imm;
        break;
      case 0x4c: /* or32 dst, src */
        ctx->regs[dst] = (uint32_t)ctx->regs[dst] | (uint32_t)ctx->regs[src];
        break;
      case 0x54: /* and32 dst, imm */
        ctx->regs[dst] = (uint32_t)ctx->regs[dst] & imm;
        break;
      case 0x5c: /* and32 dst, src */
        ctx->regs[dst] = (uint32_t)ctx->regs[dst] & (uint32_t)ctx->regs[src];
        break;
      case 0x64: /* lsh32 dst, imm */
        ctx->regs[dst] = (uint32_t)ctx->regs[dst] << imm;
        break;
      case 0x6c: /* lsh32 dst, src */
        ctx->regs[dst] = (uint32_t)ctx->regs[dst] << (uint32_t)ctx->regs[src];
        break;
      case 0x74: /* rsh32 dst, imm */
        ctx->regs[dst] = (uint32_t)ctx->regs[dst] >> imm;
        break;
      case 0x7c: /* rsh32 dst, src */
        ctx->regs[dst] = (uint32_t)ctx->regs[dst] >> (uint32_t)ctx->regs[src];
        break;
      case 0x84: /* neg32 dst, imm */
        ctx->regs[dst] = -(uint32_t)ctx->regs[dst];
        break;
      case 0x94: /* mod32 dst, imm */
        ctx->regs[dst] = (uint32_t)ctx->regs[dst] % imm;
        break;
      case 0x9c: /* mod32 dst, src */
        ctx->regs[dst] = (uint32_t)ctx->regs[dst] % (uint32_t)ctx->regs[src];
        break;
      case 0xa4: /* xor32 dst, imm */
        ctx->regs[dst] = (uint32_t)ctx->regs[dst] ^ imm;
        break;
      case 0xac: /* xor32 dst, src */
        ctx->regs[dst] = (uint32_t)ctx->regs[dst] ^ (uint32_t)ctx->regs[src];
        break;
      case 0xb4: /* mov32 dst, imm */ /* Is this different from mov ? */
        ctx->regs[dst] = imm;
        break;
      case 0xbc: /* mov32 dst, src */
        ctx->regs[dst] = (uint32_t)ctx->regs[src];
        break;
      case 0xc4: /* arsh32 dst, imm */
        ctx->regs[dst] = (int32_t)ctx->regs[dst] >> (int32_t)imm;
        break;
      case 0xcc: /* arsh32 dst, src */
        ctx->regs[dst] = (int32_t)ctx->regs[dst] >> (int32_t)ctx->regs[src];
        break;


      /*** Branch ***/
      case 0x05: /* j +off */
        ctx->pc += off;
        break;
      case 0x15: /* jeq dst, imm, +off */
        if (ctx->regs[dst] == imm) {
            ctx->pc += off;
        }
        break;
      case 0x1d: /* jeq dst, src, +off */
        if (ctx->regs[dst] == ctx->regs[src]) {
            ctx->pc += off;
        }
        break;
      case 0x25: /* jgt dst, imm, +off */
        if (ctx->regs[dst] > imm) {
            ctx->pc += off;
        }
        break;
      case 0x2d: /* jgt dst, src, +off */
        if (ctx->regs[dst] > ctx->regs[src]) {
            ctx->pc += off;
        }
        break;
      case 0x35: /* jge dst, imm, +off */
        if (ctx->regs[dst] >= imm) {
            ctx->pc += off;
        }
        break;
      case 0x3d: /* jge dst, src, +off */
        if (ctx->regs[dst] >= ctx->regs[src]) {
            ctx->pc += off;
        }
        break;
      case 0xa5: /* jlt dst, imm, +off */
        if (ctx->regs[dst] < imm) {
            ctx->pc += off;
        }
        break;
      case 0xad: /* jlt dst, src, +off */
        if (ctx->regs[dst] < ctx->regs[src]) {
            ctx->pc += off;
        }
        break;
      case 0xb5: /* jle dst, imm, +off */
        if (ctx->regs[dst] <= imm) {
            ctx->pc += off;
        }
        break;
      case 0xbd: /* jle dst, src, +off */
        if (ctx->regs[dst] <= ctx->regs[src]) {
            ctx->pc += off;
        }
        break;
      case 0x45: /* jset dst, imm, +off */
        if (ctx->regs[dst] & imm) {
            ctx->pc += off;
        }
        break;
      case 0x4d: /* jset dst, src, +off */
        if (ctx->regs[dst] & ctx->regs[src]) {
            ctx->pc += off;
        }
        break;
      case 0x55: /* jne dst, imm, +off */
        if (ctx->regs[dst] != imm) {
            ctx->pc += off;
        }
        break;
      case 0x5d: /* jne dst, src, +off */
        if (ctx->regs[dst] != ctx->regs[src]) {
            ctx->pc += off;
        }
        break;
      case 0x65: /* jsgt dst, imm, +off */
        if ((int64_t)ctx->regs[dst] > (int64_t)imm) {
            ctx->pc += off;
        }
        break;
      case 0x6d: /* jsgt dst, src, +off */
        if ((int64_t)ctx->regs[dst] > (int64_t)ctx->regs[src]) {
            ctx->pc += off;
        }
        break;
      case 0x75: /* jsge dst, imm, +off */
        if ((int64_t)ctx->regs[dst] >= (int64_t)imm) {
            ctx->pc += off;
        }
        break;
      case 0x7d: /* jsge dst, src, +off */
        if ((int64_t)ctx->regs[dst] >= (int64_t)ctx->regs[src]) {
            ctx->pc += off;
        }
        break;
      case 0xc5: /* jslt dst, imm, +off */
        if ((int64_t)ctx->regs[dst] < (int64_t)imm) {
            ctx->pc += off;
        }
        break;
      case 0xcd: /* jslt dst, src, +off */
        if ((int64_t)ctx->regs[dst] < (int64_t)ctx->regs[src]) {
            ctx->pc += off;
        }
        break;
      case 0xd5: /* jsle dst, imm, +off */
        if ((int64_t)ctx->regs[dst] <= (int64_t)imm) {
            ctx->pc += off;
        }
        break;
      case 0xdd: /* jsle dst, src, +off */
        if ((int64_t)ctx->regs[dst] <= (int64_t)ctx->regs[src]) {
            ctx->pc += off;
        }
        break;
      case 0x95: /* exit */
        return 1;

      case 0x85:
      default:
        fprintf(stderr, "Operation not implemented: 0x%02x\n", op);
        return -1;
    }
    ctx->pc++;
    return 0;
}

static Intrp_ctx* intrp_alloc() {
    return malloc(sizeof(Intrp_ctx));
}

static void intrp_free(Intrp_ctx *ctx) {
    free(ctx);
}

#ifdef TEST
#include <inttypes.h>

#define FAIL() do { fprintf(stderr, "FAILED at line %d\n", __LINE__); return -1; } while(0)

int main() {
    Intrp_ctx *ctx;
    int rc;
    uint32_t rv;

    instruction prog[] = {
      { .op=0x67, .dst=0x1, .src=0x0, .off = 0x0000, .imm=0x00000020},
      { .op=0x77, .dst=0x1, .src=0x0, .off = 0x0000, .imm=0x00000020},
      { .op=0xb7, .dst=0x0, .src=0x0, .off = 0x0000, .imm=0x00000001},
      { .op=0x15, .dst=0x1, .src=0x0, .off = 0x0001, .imm=0x0000002A},
      { .op=0xb7, .dst=0x0, .src=0x0, .off = 0x0000, .imm=0x00000000},
    };
    uint16_t pl = sizeof(prog)/sizeof(*prog);

    rc = intrp_create(&ctx, prog, pl);
    if (rc) FAIL();

    rc = intrp_start(ctx, 40);
    if (rc) FAIL();

    do {
        rc = intrp_step(ctx);
    } while (rc == 0);
    if (rc < 0) {
        FAIL();
    }

    rc = intrp_stop(ctx, &rv);
    if (rc) FAIL();
    printf("Called BPF program on 40: %" PRIu32 "\n", rv);

    rc = intrp_start(ctx, 42);
    if (rc) FAIL();

    do {
        rc = intrp_step(ctx);
    } while (rc == 0);
    if (rc < 0) {
        FAIL();
    }

    rc = intrp_stop(ctx, &rv);
    if (rc) FAIL();
    printf("Called BPF program on 42: %" PRIu32 "\n", rv);

    rc = intrp_delete(&ctx);
    if (rc) FAIL();

    return 0;
}

#endif
