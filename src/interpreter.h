#ifndef INTERPRETER_H
#define INTERPRETER_H

typedef struct {
    uint8_t  op;
    uint8_t  dst:4;
    uint8_t  src:4;
    uint16_t off;
    uint32_t imm;
} instruction;

struct Intrp_ctx_;
typedef struct Intrp_ctx_ Intrp_ctx;

int intrp_create(Intrp_ctx **ctx, const instruction *prog, int16_t pl);
int intrp_delete(Intrp_ctx **ctx);
int intrp_start(Intrp_ctx *ctx, uintptr_t);
int intrp_stop(Intrp_ctx *ctx, uint32_t*);
int intrp_step(Intrp_ctx *ctx);


#endif
