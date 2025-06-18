#include <oqs/oqs.h>
#include "../slh_dsa.h"

int slh_keygen_wrapper(uint8_t *pk, uint8_t *sk, const slh_param_t *prm);
int slh_sign_with_ctx_wrapper(uint8_t *sig, size_t *siglen, const uint8_t *m,
    size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *sk, const slh_param_t *prm);
int slh_sign_wrapper(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
    const uint8_t *sk, const slh_param_t *prm);
int slh_verify_with_ctx_wrapper(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, 
    const uint8_t *ctx, size_t ctxlen, const uint8_t *pk, const slh_param_t *prm);
int slh_verify_wrapper(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
    const uint8_t *pk, const slh_param_t *prm);
int hash_slh_sign_with_ctx_wrapper(uint8_t *sig, size_t *siglen,
 const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *sk,
    const slh_param_t *prm, const char *ph);
int hash_slh_verify_with_ctx_wrapper(const uint8_t *sig, size_t siglen, const uint8_t *m,
    size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *pk, const slh_param_t *prm,
    const char *ph);
int hash_slh_sign_wrapper(uint8_t *sig, size_t *siglen, const uint8_t *m,
    size_t mlen, const uint8_t *sk, const slh_param_t *prm, const char *ph);
int hash_slh_verify_wrapper(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
    const uint8_t *pk, const slh_param_t *prm, const char *ph);