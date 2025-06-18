#include "oqs/common.h"
#include "oqs/rand.h"
# include "../slh_dsa.h"
#include "../slh_prehash.h"
#include <oqs/oqs.h>
#include <stdint.h>

int slh_randombytes(uint8_t *x, size_t xlen)
{
    OQS_randombytes(x,xlen);
    return OQS_SUCCESS;
}

int slh_keygen_wrapper(uint8_t *pk, uint8_t *sk, const slh_param_t *prm)
{
    int (*rbg)(uint8_t *x, size_t xlen) = slh_randombytes;
    return slh_keygen(sk,pk, rbg,prm);
}

int slh_sign_with_ctx_wrapper(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
    const uint8_t *ctx, size_t ctxlen, const uint8_t *sk, const slh_param_t *prm)
{
    uint8_t addrnd[16];
    OQS_randombytes(addrnd, 16);

    *siglen = slh_sign(sig,m,mlen,ctx,ctxlen,sk,addrnd,prm);

    if(*siglen == 0)
    {
        return OQS_ERROR;
    }
    return OQS_SUCCESS;
}

int slh_sign_wrapper(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, 
    const uint8_t *sk, const slh_param_t *prm)
{
    const uint8_t *ctx;
    const size_t ctxlen = 0;
    uint8_t addrnd[16];
    OQS_randombytes(addrnd, 16);

    *siglen = slh_sign(sig,m,mlen,ctx,ctxlen,sk,addrnd,prm);

    if(*siglen == 0)
    {
        return OQS_ERROR;
    }
    return OQS_SUCCESS;
}

int slh_verify_with_ctx_wrapper(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, 
    const uint8_t *ctx, size_t ctxlen, const uint8_t *pk, const slh_param_t *prm)
{
    int res = slh_verify(m,mlen,sig,siglen,ctx,ctxlen,pk,prm);

    if(res == 0)
    {
        return OQS_ERROR;
    }
    return OQS_SUCCESS;
}

int slh_verify_wrapper(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk, 
    const slh_param_t *prm)
{
    const uint8_t *ctx;
    const size_t ctxlen = 0;

    int res = slh_verify(m,mlen,sig,siglen,ctx,ctxlen,pk,prm);

    if(res == 0)
    {
        return OQS_ERROR;
    }
    return OQS_SUCCESS;
}

int hash_slh_sign_with_ctx_wrapper(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
     const uint8_t *ctx, size_t ctxlen, const uint8_t *sk, const slh_param_t *prm, const char *ph)
{
    uint8_t addrnd[16];
    OQS_randombytes(addrnd, 16);

    *siglen = hash_slh_sign(sig,m,mlen,ctx,ctxlen,ph,sk,addrnd,prm);

    if(*siglen == 0)
    {
        return OQS_ERROR;
    }
    return OQS_SUCCESS;
}

int hash_slh_sign_wrapper(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk,
    const slh_param_t *prm, const char *ph)
{
    const uint8_t *ctx;
    const size_t ctxlen = 0;
    uint8_t addrnd[16];
    OQS_randombytes(addrnd, 16);

    *siglen = hash_slh_sign(sig,m,mlen,ctx,ctxlen,ph,sk,addrnd,prm);

    if(*siglen == 0)
    {
        return OQS_ERROR;
    }
    return OQS_SUCCESS;
}

int hash_slh_verify_with_ctx_wrapper(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *ctx,
    size_t ctxlen, const uint8_t *pk, const slh_param_t *prm, const char *ph)
{
   int res = hash_slh_verify(m,mlen,sig,siglen,ctx,ctxlen,ph,pk,prm);

   if(res == 0)
    {
        return OQS_ERROR;
    }
    return OQS_SUCCESS;
}


int hash_slh_verify_wrapper(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk, 
    const slh_param_t *prm, const char *ph)
{
    const uint8_t *ctx;
    const size_t ctxlen = 0;

    int res = hash_slh_verify(m,mlen,sig,siglen,ctx,ctxlen,ph,pk,prm);

    if(res == 0)
    {
        return OQS_ERROR;
    }
    return OQS_SUCCESS;
}