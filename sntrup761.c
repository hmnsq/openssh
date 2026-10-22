/*  $OpenBSD: sntrup761.c,v 1.9 2026/01/20 22:56:11 dtucker Exp $ */

/*
 * Public Domain, Authors:
 * - Daniel J. Bernstein
 * - Chitchanok Chuengsatiansup
 * - Tanja Lange
 * - Christine van Vredendaal
 */

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_SNTRUP761X25519

#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ "crypto_api.h"

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ crypto_declassify(x, y) ਕਰੋ {} ਜਦੋਂ (0)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ int8 crypto_int8
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ uint8 crypto_uint8
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ int16 crypto_int16
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ uint16 crypto_uint16
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ int32 crypto_int32
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ uint32 crypto_uint32
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ int64 crypto_int64
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ uint64 crypto_uint64
ਬਾਹਰੀ ਅਸਥਿਰ crypto_int16 crypto_int16_optblocker;
ਬਾਹਰੀ ਅਸਥਿਰ crypto_int32 crypto_int32_optblocker;
ਬਾਹਰੀ ਅਸਥਿਰ crypto_int64 crypto_int64_optblocker;

/* from supercop-20240808/cryptoint/crypto_int16.h */
/* auto-generated: cd cryptoint; ./autogen */
/* cryptoint 20240806 */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ crypto_int16_h
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ crypto_int16_h

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ crypto_int16 int16_t
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ crypto_int16_unsigned uint16_t



__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int16 crypto_int16_ਲੱਦੋ(ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *crypto_int16_s) {
  crypto_int16 crypto_int16_z = 0;
  crypto_int16_z |= ((crypto_int16) (*crypto_int16_s++)) << 0;
  crypto_int16_z |= ((crypto_int16) (*crypto_int16_s++)) << 8;
  ਵਾਪਸ crypto_int16_z;
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
ਖਾਲੀ crypto_int16_store(ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *crypto_int16_s,crypto_int16 crypto_int16_x) {
  *crypto_int16_s++ = crypto_int16_x >> 0;
  *crypto_int16_s++ = crypto_int16_x >> 8;
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int16 crypto_int16_negative_ਨਕਾਬ(crypto_int16 crypto_int16_x) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarw $15,%0" : "+r"(crypto_int16_x) : : "cc");
  ਵਾਪਸ crypto_int16_x;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_y;
  __asm__ ("sbfx %w0,%w1,15,1" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) : );
  ਵਾਪਸ crypto_int16_y;
#ਨਹੀਂਤਾਂ
  crypto_int16_x >>= 16-6;
  crypto_int16_x ^= crypto_int16_optblocker;
  crypto_int16_x >>= 5;
  ਵਾਪਸ crypto_int16_x;
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int16_unsigned crypto_int16_unsigned_topbit_01(crypto_int16_unsigned crypto_int16_x) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("shrw $15,%0" : "+r"(crypto_int16_x) : : "cc");
  ਵਾਪਸ crypto_int16_x;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_y;
  __asm__ ("ubfx %w0,%w1,15,1" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) : );
  ਵਾਪਸ crypto_int16_y;
#ਨਹੀਂਤਾਂ
  crypto_int16_x >>= 16-6;
  crypto_int16_x ^= crypto_int16_optblocker;
  crypto_int16_x >>= 5;
  ਵਾਪਸ crypto_int16_x;
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int16 crypto_int16_negative_01(crypto_int16 crypto_int16_x) {
  ਵਾਪਸ crypto_int16_unsigned_topbit_01(crypto_int16_x);
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int16 crypto_int16_topbit_ਨਕਾਬ(crypto_int16 crypto_int16_x) {
  ਵਾਪਸ crypto_int16_negative_ਨਕਾਬ(crypto_int16_x);
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int16 crypto_int16_topbit_01(crypto_int16 crypto_int16_x) {
  ਵਾਪਸ crypto_int16_unsigned_topbit_01(crypto_int16_x);
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int16 crypto_int16_bottombit_ਨਕਾਬ(crypto_int16 crypto_int16_x) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andw $1,%0" : "+r"(crypto_int16_x) : : "cc");
  ਵਾਪਸ -crypto_int16_x;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_y;
  __asm__ ("sbfx %w0,%w1,0,1" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) : );
  ਵਾਪਸ crypto_int16_y;
#ਨਹੀਂਤਾਂ
  crypto_int16_x &= 1 ^ crypto_int16_optblocker;
  ਵਾਪਸ -crypto_int16_x;
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int16 crypto_int16_bottombit_01(crypto_int16 crypto_int16_x) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andw $1,%0" : "+r"(crypto_int16_x) : : "cc");
  ਵਾਪਸ crypto_int16_x;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_y;
  __asm__ ("ubfx %w0,%w1,0,1" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) : );
  ਵਾਪਸ crypto_int16_y;
#ਨਹੀਂਤਾਂ
  crypto_int16_x &= 1 ^ crypto_int16_optblocker;
  ਵਾਪਸ crypto_int16_x;
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int16 crypto_int16_bitinrangepublicpos_ਨਕਾਬ(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarw %%cl,%0" : "+r"(crypto_int16_x) : "c"(crypto_int16_s) : "cc");
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("sxth %w0,%w0\n asr %w0,%w0,%w1" : "+&r"(crypto_int16_x) : "r"(crypto_int16_s) : );
#ਨਹੀਂਤਾਂ
  crypto_int16_x >>= crypto_int16_s ^ crypto_int16_optblocker;
#ਜੇ_ਅੰਤ
  ਵਾਪਸ crypto_int16_bottombit_ਨਕਾਬ(crypto_int16_x);
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int16 crypto_int16_bitinrangepublicpos_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarw %%cl,%0" : "+r"(crypto_int16_x) : "c"(crypto_int16_s) : "cc");
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("sxth %w0,%w0\n asr %w0,%w0,%w1" : "+&r"(crypto_int16_x) : "r"(crypto_int16_s) : );
#ਨਹੀਂਤਾਂ
  crypto_int16_x >>= crypto_int16_s ^ crypto_int16_optblocker;
#ਜੇ_ਅੰਤ
  ਵਾਪਸ crypto_int16_bottombit_01(crypto_int16_x);
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int16 crypto_int16_shlmod(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16_s &= 15;
  __asm__ ("shlw %%cl,%0" : "+r"(crypto_int16_x) : "c"(crypto_int16_s) : "cc");
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("and %w0,%w0,15\n and %w1,%w1,65535\n lsl %w1,%w1,%w0" : "+&r"(crypto_int16_s), "+r"(crypto_int16_x) : : );
#ਨਹੀਂਤਾਂ
  ਪੂਰਨ crypto_int16_k, crypto_int16_l;
  ਲਈ (crypto_int16_l = 0,crypto_int16_k = 1;crypto_int16_k < 16;++crypto_int16_l,crypto_int16_k *= 2)
    crypto_int16_x ^= (crypto_int16_x ^ (crypto_int16_x << crypto_int16_k)) & crypto_int16_bitinrangepublicpos_ਨਕਾਬ(crypto_int16_s,crypto_int16_l);
#ਜੇ_ਅੰਤ
  ਵਾਪਸ crypto_int16_x;
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int16 crypto_int16_shrmod(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16_s &= 15;
  __asm__ ("sarw %%cl,%0" : "+r"(crypto_int16_x) : "c"(crypto_int16_s) : "cc");
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("and %w0,%w0,15\n sxth %w1,%w1\n asr %w1,%w1,%w0" : "+&r"(crypto_int16_s), "+r"(crypto_int16_x) : : );
#ਨਹੀਂਤਾਂ
  ਪੂਰਨ crypto_int16_k, crypto_int16_l;
  ਲਈ (crypto_int16_l = 0,crypto_int16_k = 1;crypto_int16_k < 16;++crypto_int16_l,crypto_int16_k *= 2)
    crypto_int16_x ^= (crypto_int16_x ^ (crypto_int16_x >> crypto_int16_k)) & crypto_int16_bitinrangepublicpos_ਨਕਾਬ(crypto_int16_s,crypto_int16_l);
#ਜੇ_ਅੰਤ
  ਵਾਪਸ crypto_int16_x;
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int16 crypto_int16_bitmod_ਨਕਾਬ(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
  crypto_int16_x = crypto_int16_shrmod(crypto_int16_x,crypto_int16_s);
  ਵਾਪਸ crypto_int16_bottombit_ਨਕਾਬ(crypto_int16_x);
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int16 crypto_int16_bitmod_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
  crypto_int16_x = crypto_int16_shrmod(crypto_int16_x,crypto_int16_s);
  ਵਾਪਸ crypto_int16_bottombit_01(crypto_int16_x);
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int16 crypto_int16_nonzero_ਨਕਾਬ(crypto_int16 crypto_int16_x) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n testw %2,%2\n cmovnew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  ਵਾਪਸ crypto_int16_z;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("tst %w1,65535\n csetm %w0,ne" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  ਵਾਪਸ crypto_int16_z;
#ਨਹੀਂਤਾਂ
  crypto_int16_x |= -crypto_int16_x;
  ਵਾਪਸ crypto_int16_negative_ਨਕਾਬ(crypto_int16_x);
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int16 crypto_int16_nonzero_01(crypto_int16 crypto_int16_x) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n testw %2,%2\n cmovnew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  ਵਾਪਸ crypto_int16_z;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("tst %w1,65535\n cset %w0,ne" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  ਵਾਪਸ crypto_int16_z;
#ਨਹੀਂਤਾਂ
  crypto_int16_x |= -crypto_int16_x;
  ਵਾਪਸ crypto_int16_unsigned_topbit_01(crypto_int16_x);
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int16 crypto_int16_ਸਕਾਰਾਤਮਕ_ਨਕਾਬ(crypto_int16 crypto_int16_x) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n testw %2,%2\n cmovgw %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  ਵਾਪਸ crypto_int16_z;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,0\n csetm %w0,gt" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  ਵਾਪਸ crypto_int16_z;
#ਨਹੀਂਤਾਂ
  crypto_int16 crypto_int16_z = -crypto_int16_x;
  crypto_int16_z ^= crypto_int16_x & crypto_int16_z;
  ਵਾਪਸ crypto_int16_negative_ਨਕਾਬ(crypto_int16_z);
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int16 crypto_int16_ਸਕਾਰਾਤਮਕ_01(crypto_int16 crypto_int16_x) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n testw %2,%2\n cmovgw %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  ਵਾਪਸ crypto_int16_z;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,0\n cset %w0,gt" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  ਵਾਪਸ crypto_int16_z;
#ਨਹੀਂਤਾਂ
  crypto_int16 crypto_int16_z = -crypto_int16_x;
  crypto_int16_z ^= crypto_int16_x & crypto_int16_z;
  ਵਾਪਸ crypto_int16_unsigned_topbit_01(crypto_int16_z);
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int16 crypto_int16_zero_ਨਕਾਬ(crypto_int16 crypto_int16_x) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n testw %2,%2\n cmovew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  ਵਾਪਸ crypto_int16_z;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("tst %w1,65535\n csetm %w0,eq" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  ਵਾਪਸ crypto_int16_z;
#ਨਹੀਂਤਾਂ
  ਵਾਪਸ ~crypto_int16_nonzero_ਨਕਾਬ(crypto_int16_x);
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int16 crypto_int16_zero_01(crypto_int16 crypto_int16_x) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n testw %2,%2\n cmovew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  ਵਾਪਸ crypto_int16_z;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("tst %w1,65535\n cset %w0,eq" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  ਵਾਪਸ crypto_int16_z;
#ਨਹੀਂਤਾਂ
  ਵਾਪਸ 1-crypto_int16_nonzero_01(crypto_int16_x);
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int16 crypto_int16_unequal_ਨਕਾਬ(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n cmpw %3,%2\n cmovnew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ਵਾਪਸ crypto_int16_z;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("and %w0,%w1,65535\n cmp %w0,%w2,uxth\n csetm %w0,ne" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ਵਾਪਸ crypto_int16_z;
#ਨਹੀਂਤਾਂ
  ਵਾਪਸ crypto_int16_nonzero_ਨਕਾਬ(crypto_int16_x ^ crypto_int16_y);
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int16 crypto_int16_unequal_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n cmpw %3,%2\n cmovnew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ਵਾਪਸ crypto_int16_z;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("and %w0,%w1,65535\n cmp %w0,%w2,uxth\n cset %w0,ne" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ਵਾਪਸ crypto_int16_z;
#ਨਹੀਂਤਾਂ
  ਵਾਪਸ crypto_int16_nonzero_01(crypto_int16_x ^ crypto_int16_y);
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int16 crypto_int16_equal_ਨਕਾਬ(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n cmpw %3,%2\n cmovew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ਵਾਪਸ crypto_int16_z;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("and %w0,%w1,65535\n cmp %w0,%w2,uxth\n csetm %w0,eq" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ਵਾਪਸ crypto_int16_z;
#ਨਹੀਂਤਾਂ
  ਵਾਪਸ ~crypto_int16_unequal_ਨਕਾਬ(crypto_int16_x,crypto_int16_y);
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int16 crypto_int16_equal_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n cmpw %3,%2\n cmovew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ਵਾਪਸ crypto_int16_z;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("and %w0,%w1,65535\n cmp %w0,%w2,uxth\n cset %w0,eq" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ਵਾਪਸ crypto_int16_z;
#ਨਹੀਂਤਾਂ
  ਵਾਪਸ 1-crypto_int16_unequal_01(crypto_int16_x,crypto_int16_y);
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int16 crypto_int16_min(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpw %1,%0\n cmovgw %1,%0" : "+r"(crypto_int16_x) : "r"(crypto_int16_y) : "cc");
  ਵਾਪਸ crypto_int16_x;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("sxth %w0,%w0\n cmp %w0,%w1,sxth\n csel %w0,%w0,%w1,lt" : "+&r"(crypto_int16_x) : "r"(crypto_int16_y) : "cc");
  ਵਾਪਸ crypto_int16_x;
#ਨਹੀਂਤਾਂ
  crypto_int16 crypto_int16_r = crypto_int16_y ^ crypto_int16_x;
  crypto_int16 crypto_int16_z = crypto_int16_y - crypto_int16_x;
  crypto_int16_z ^= crypto_int16_r & (crypto_int16_z ^ crypto_int16_y);
  crypto_int16_z = crypto_int16_negative_ਨਕਾਬ(crypto_int16_z);
  crypto_int16_z &= crypto_int16_r;
  ਵਾਪਸ crypto_int16_x ^ crypto_int16_z;
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int16 crypto_int16_max(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpw %1,%0\n cmovlw %1,%0" : "+r"(crypto_int16_x) : "r"(crypto_int16_y) : "cc");
  ਵਾਪਸ crypto_int16_x;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("sxth %w0,%w0\n cmp %w0,%w1,sxth\n csel %w0,%w1,%w0,lt" : "+&r"(crypto_int16_x) : "r"(crypto_int16_y) : "cc");
  ਵਾਪਸ crypto_int16_x;
#ਨਹੀਂਤਾਂ
  crypto_int16 crypto_int16_r = crypto_int16_y ^ crypto_int16_x;
  crypto_int16 crypto_int16_z = crypto_int16_y - crypto_int16_x;
  crypto_int16_z ^= crypto_int16_r & (crypto_int16_z ^ crypto_int16_y);
  crypto_int16_z = crypto_int16_negative_ਨਕਾਬ(crypto_int16_z);
  crypto_int16_z &= crypto_int16_r;
  ਵਾਪਸ crypto_int16_y ^ crypto_int16_z;
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
ਖਾਲੀ crypto_int16_minmax(crypto_int16 *crypto_int16_p,crypto_int16 *crypto_int16_q) {
  crypto_int16 crypto_int16_x = *crypto_int16_p;
  crypto_int16 crypto_int16_y = *crypto_int16_q;
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("cmpw %2,%1\n movw %1,%0\n cmovgw %2,%1\n cmovgw %0,%2" : "=&r"(crypto_int16_z), "+&r"(crypto_int16_x), "+r"(crypto_int16_y) : : "cc");
  *crypto_int16_p = crypto_int16_x;
  *crypto_int16_q = crypto_int16_y;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_r, crypto_int16_s;
  __asm__ ("sxth %w0,%w0\n cmp %w0,%w3,sxth\n csel %w1,%w0,%w3,lt\n csel %w2,%w3,%w0,lt" : "+&r"(crypto_int16_x), "=&r"(crypto_int16_r), "=r"(crypto_int16_s) : "r"(crypto_int16_y) : "cc");
  *crypto_int16_p = crypto_int16_r;
  *crypto_int16_q = crypto_int16_s;
#ਨਹੀਂਤਾਂ
  crypto_int16 crypto_int16_r = crypto_int16_y ^ crypto_int16_x;
  crypto_int16 crypto_int16_z = crypto_int16_y - crypto_int16_x;
  crypto_int16_z ^= crypto_int16_r & (crypto_int16_z ^ crypto_int16_y);
  crypto_int16_z = crypto_int16_negative_ਨਕਾਬ(crypto_int16_z);
  crypto_int16_z &= crypto_int16_r;
  crypto_int16_x ^= crypto_int16_z;
  crypto_int16_y ^= crypto_int16_z;
  *crypto_int16_p = crypto_int16_x;
  *crypto_int16_q = crypto_int16_y;
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int16 crypto_int16_smaller_ਨਕਾਬ(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n cmpw %3,%2\n cmovlw %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ਵਾਪਸ crypto_int16_z;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,%w2,sxth\n csetm %w0,lt" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ਵਾਪਸ crypto_int16_z;
#ਨਹੀਂਤਾਂ
  crypto_int16 crypto_int16_r = crypto_int16_x ^ crypto_int16_y;
  crypto_int16 crypto_int16_z = crypto_int16_x - crypto_int16_y;
  crypto_int16_z ^= crypto_int16_r & (crypto_int16_z ^ crypto_int16_x);
  ਵਾਪਸ crypto_int16_negative_ਨਕਾਬ(crypto_int16_z);
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int16 crypto_int16_smaller_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n cmpw %3,%2\n cmovlw %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ਵਾਪਸ crypto_int16_z;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,%w2,sxth\n cset %w0,lt" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ਵਾਪਸ crypto_int16_z;
#ਨਹੀਂਤਾਂ
  crypto_int16 crypto_int16_r = crypto_int16_x ^ crypto_int16_y;
  crypto_int16 crypto_int16_z = crypto_int16_x - crypto_int16_y;
  crypto_int16_z ^= crypto_int16_r & (crypto_int16_z ^ crypto_int16_x);
  ਵਾਪਸ crypto_int16_unsigned_topbit_01(crypto_int16_z);
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int16 crypto_int16_leq_ਨਕਾਬ(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n cmpw %3,%2\n cmovlew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ਵਾਪਸ crypto_int16_z;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,%w2,sxth\n csetm %w0,le" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ਵਾਪਸ crypto_int16_z;
#ਨਹੀਂਤਾਂ
  ਵਾਪਸ ~crypto_int16_smaller_ਨਕਾਬ(crypto_int16_y,crypto_int16_x);
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int16 crypto_int16_leq_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n cmpw %3,%2\n cmovlew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ਵਾਪਸ crypto_int16_z;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,%w2,sxth\n cset %w0,le" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ਵਾਪਸ crypto_int16_z;
#ਨਹੀਂਤਾਂ
  ਵਾਪਸ 1-crypto_int16_smaller_01(crypto_int16_y,crypto_int16_x);
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
ਪੂਰਨ crypto_int16_ones_ਅੰਕ(crypto_int16 crypto_int16_x) {
  crypto_int16_unsigned crypto_int16_y = crypto_int16_x;
  ਅਚਲ crypto_int16 C0 = 0x5555;
  ਅਚਲ crypto_int16 C1 = 0x3333;
  ਅਚਲ crypto_int16 C2 = 0x0f0f;
  crypto_int16_y -= ((crypto_int16_y >> 1) & C0);
  crypto_int16_y = (crypto_int16_y & C1) + ((crypto_int16_y >> 2) & C1);
  crypto_int16_y = (crypto_int16_y + (crypto_int16_y >> 4)) & C2;
  crypto_int16_y = (crypto_int16_y + (crypto_int16_y >> 8)) & 0xff;
  ਵਾਪਸ crypto_int16_y;
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
ਪੂਰਨ crypto_int16_bottomzeros_ਅੰਕ(crypto_int16 crypto_int16_x) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 fallback = 16;
  __asm__ ("bsfw %0,%0\n cmovew %1,%0" : "+&r"(crypto_int16_x) : "r"(fallback) : "cc");
  ਵਾਪਸ crypto_int16_x;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  int64_t crypto_int16_y;
  __asm__ ("orr %w0,%w1,-65536\n rbit %w0,%w0\n clz %w0,%w0" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) : );
  ਵਾਪਸ crypto_int16_y;
#ਨਹੀਂਤਾਂ
  crypto_int16 crypto_int16_y = crypto_int16_x ^ (crypto_int16_x-1);
  crypto_int16_y = ((crypto_int16) crypto_int16_y) >> 1;
  crypto_int16_y &= ~(crypto_int16_x & (((crypto_int16) 1) << (16-1)));
  ਵਾਪਸ crypto_int16_ones_ਅੰਕ(crypto_int16_y);
#ਜੇ_ਅੰਤ
}

#ਜੇ_ਅੰਤ

/* from supercop-20240808/cryptoint/crypto_int32.h */
/* auto-generated: cd cryptoint; ./autogen */
/* cryptoint 20240806 */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ crypto_int32_h
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ crypto_int32_h

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ crypto_int32 int32_t
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ crypto_int32_unsigned uint32_t



__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int32 crypto_int32_ਲੱਦੋ(ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *crypto_int32_s) {
  crypto_int32 crypto_int32_z = 0;
  crypto_int32_z |= ((crypto_int32) (*crypto_int32_s++)) << 0;
  crypto_int32_z |= ((crypto_int32) (*crypto_int32_s++)) << 8;
  crypto_int32_z |= ((crypto_int32) (*crypto_int32_s++)) << 16;
  crypto_int32_z |= ((crypto_int32) (*crypto_int32_s++)) << 24;
  ਵਾਪਸ crypto_int32_z;
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
ਖਾਲੀ crypto_int32_store(ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *crypto_int32_s,crypto_int32 crypto_int32_x) {
  *crypto_int32_s++ = crypto_int32_x >> 0;
  *crypto_int32_s++ = crypto_int32_x >> 8;
  *crypto_int32_s++ = crypto_int32_x >> 16;
  *crypto_int32_s++ = crypto_int32_x >> 24;
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int32 crypto_int32_negative_ਨਕਾਬ(crypto_int32 crypto_int32_x) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarl $31,%0" : "+r"(crypto_int32_x) : : "cc");
  ਵਾਪਸ crypto_int32_x;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_y;
  __asm__ ("asr %w0,%w1,31" : "=r"(crypto_int32_y) : "r"(crypto_int32_x) : );
  ਵਾਪਸ crypto_int32_y;
#ਨਹੀਂਤਾਂ
  crypto_int32_x >>= 32-6;
  crypto_int32_x ^= crypto_int32_optblocker;
  crypto_int32_x >>= 5;
  ਵਾਪਸ crypto_int32_x;
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int32_unsigned crypto_int32_unsigned_topbit_01(crypto_int32_unsigned crypto_int32_x) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("shrl $31,%0" : "+r"(crypto_int32_x) : : "cc");
  ਵਾਪਸ crypto_int32_x;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_y;
  __asm__ ("lsr %w0,%w1,31" : "=r"(crypto_int32_y) : "r"(crypto_int32_x) : );
  ਵਾਪਸ crypto_int32_y;
#ਨਹੀਂਤਾਂ
  crypto_int32_x >>= 32-6;
  crypto_int32_x ^= crypto_int32_optblocker;
  crypto_int32_x >>= 5;
  ਵਾਪਸ crypto_int32_x;
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int32 crypto_int32_negative_01(crypto_int32 crypto_int32_x) {
  ਵਾਪਸ crypto_int32_unsigned_topbit_01(crypto_int32_x);
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int32 crypto_int32_topbit_ਨਕਾਬ(crypto_int32 crypto_int32_x) {
  ਵਾਪਸ crypto_int32_negative_ਨਕਾਬ(crypto_int32_x);
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int32 crypto_int32_topbit_01(crypto_int32 crypto_int32_x) {
  ਵਾਪਸ crypto_int32_unsigned_topbit_01(crypto_int32_x);
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int32 crypto_int32_bottombit_ਨਕਾਬ(crypto_int32 crypto_int32_x) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andl $1,%0" : "+r"(crypto_int32_x) : : "cc");
  ਵਾਪਸ -crypto_int32_x;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_y;
  __asm__ ("sbfx %w0,%w1,0,1" : "=r"(crypto_int32_y) : "r"(crypto_int32_x) : );
  ਵਾਪਸ crypto_int32_y;
#ਨਹੀਂਤਾਂ
  crypto_int32_x &= 1 ^ crypto_int32_optblocker;
  ਵਾਪਸ -crypto_int32_x;
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int32 crypto_int32_bottombit_01(crypto_int32 crypto_int32_x) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andl $1,%0" : "+r"(crypto_int32_x) : : "cc");
  ਵਾਪਸ crypto_int32_x;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_y;
  __asm__ ("ubfx %w0,%w1,0,1" : "=r"(crypto_int32_y) : "r"(crypto_int32_x) : );
  ਵਾਪਸ crypto_int32_y;
#ਨਹੀਂਤਾਂ
  crypto_int32_x &= 1 ^ crypto_int32_optblocker;
  ਵਾਪਸ crypto_int32_x;
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int32 crypto_int32_bitinrangepublicpos_ਨਕਾਬ(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarl %%cl,%0" : "+r"(crypto_int32_x) : "c"(crypto_int32_s) : "cc");
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %w0,%w0,%w1" : "+r"(crypto_int32_x) : "r"(crypto_int32_s) : );
#ਨਹੀਂਤਾਂ
  crypto_int32_x >>= crypto_int32_s ^ crypto_int32_optblocker;
#ਜੇ_ਅੰਤ
  ਵਾਪਸ crypto_int32_bottombit_ਨਕਾਬ(crypto_int32_x);
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int32 crypto_int32_bitinrangepublicpos_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarl %%cl,%0" : "+r"(crypto_int32_x) : "c"(crypto_int32_s) : "cc");
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %w0,%w0,%w1" : "+r"(crypto_int32_x) : "r"(crypto_int32_s) : );
#ਨਹੀਂਤਾਂ
  crypto_int32_x >>= crypto_int32_s ^ crypto_int32_optblocker;
#ਜੇ_ਅੰਤ
  ਵਾਪਸ crypto_int32_bottombit_01(crypto_int32_x);
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int32 crypto_int32_shlmod(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("shll %%cl,%0" : "+r"(crypto_int32_x) : "c"(crypto_int32_s) : "cc");
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("lsl %w0,%w0,%w1" : "+r"(crypto_int32_x) : "r"(crypto_int32_s) : );
#ਨਹੀਂਤਾਂ
  ਪੂਰਨ crypto_int32_k, crypto_int32_l;
  ਲਈ (crypto_int32_l = 0,crypto_int32_k = 1;crypto_int32_k < 32;++crypto_int32_l,crypto_int32_k *= 2)
    crypto_int32_x ^= (crypto_int32_x ^ (crypto_int32_x << crypto_int32_k)) & crypto_int32_bitinrangepublicpos_ਨਕਾਬ(crypto_int32_s,crypto_int32_l);
#ਜੇ_ਅੰਤ
  ਵਾਪਸ crypto_int32_x;
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int32 crypto_int32_shrmod(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarl %%cl,%0" : "+r"(crypto_int32_x) : "c"(crypto_int32_s) : "cc");
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %w0,%w0,%w1" : "+r"(crypto_int32_x) : "r"(crypto_int32_s) : );
#ਨਹੀਂਤਾਂ
  ਪੂਰਨ crypto_int32_k, crypto_int32_l;
  ਲਈ (crypto_int32_l = 0,crypto_int32_k = 1;crypto_int32_k < 32;++crypto_int32_l,crypto_int32_k *= 2)
    crypto_int32_x ^= (crypto_int32_x ^ (crypto_int32_x >> crypto_int32_k)) & crypto_int32_bitinrangepublicpos_ਨਕਾਬ(crypto_int32_s,crypto_int32_l);
#ਜੇ_ਅੰਤ
  ਵਾਪਸ crypto_int32_x;
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int32 crypto_int32_bitmod_ਨਕਾਬ(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
  crypto_int32_x = crypto_int32_shrmod(crypto_int32_x,crypto_int32_s);
  ਵਾਪਸ crypto_int32_bottombit_ਨਕਾਬ(crypto_int32_x);
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int32 crypto_int32_bitmod_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
  crypto_int32_x = crypto_int32_shrmod(crypto_int32_x,crypto_int32_s);
  ਵਾਪਸ crypto_int32_bottombit_01(crypto_int32_x);
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int32 crypto_int32_nonzero_ਨਕਾਬ(crypto_int32 crypto_int32_x) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n testl %2,%2\n cmovnel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  ਵਾਪਸ crypto_int32_z;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n csetm %w0,ne" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  ਵਾਪਸ crypto_int32_z;
#ਨਹੀਂਤਾਂ
  crypto_int32_x |= -crypto_int32_x;
  ਵਾਪਸ crypto_int32_negative_ਨਕਾਬ(crypto_int32_x);
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int32 crypto_int32_nonzero_01(crypto_int32 crypto_int32_x) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n testl %2,%2\n cmovnel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  ਵਾਪਸ crypto_int32_z;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n cset %w0,ne" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  ਵਾਪਸ crypto_int32_z;
#ਨਹੀਂਤਾਂ
  crypto_int32_x |= -crypto_int32_x;
  ਵਾਪਸ crypto_int32_unsigned_topbit_01(crypto_int32_x);
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int32 crypto_int32_ਸਕਾਰਾਤਮਕ_ਨਕਾਬ(crypto_int32 crypto_int32_x) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n testl %2,%2\n cmovgl %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  ਵਾਪਸ crypto_int32_z;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n csetm %w0,gt" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  ਵਾਪਸ crypto_int32_z;
#ਨਹੀਂਤਾਂ
  crypto_int32 crypto_int32_z = -crypto_int32_x;
  crypto_int32_z ^= crypto_int32_x & crypto_int32_z;
  ਵਾਪਸ crypto_int32_negative_ਨਕਾਬ(crypto_int32_z);
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int32 crypto_int32_ਸਕਾਰਾਤਮਕ_01(crypto_int32 crypto_int32_x) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n testl %2,%2\n cmovgl %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  ਵਾਪਸ crypto_int32_z;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n cset %w0,gt" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  ਵਾਪਸ crypto_int32_z;
#ਨਹੀਂਤਾਂ
  crypto_int32 crypto_int32_z = -crypto_int32_x;
  crypto_int32_z ^= crypto_int32_x & crypto_int32_z;
  ਵਾਪਸ crypto_int32_unsigned_topbit_01(crypto_int32_z);
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int32 crypto_int32_zero_ਨਕਾਬ(crypto_int32 crypto_int32_x) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n testl %2,%2\n cmovel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  ਵਾਪਸ crypto_int32_z;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n csetm %w0,eq" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  ਵਾਪਸ crypto_int32_z;
#ਨਹੀਂਤਾਂ
  ਵਾਪਸ ~crypto_int32_nonzero_ਨਕਾਬ(crypto_int32_x);
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int32 crypto_int32_zero_01(crypto_int32 crypto_int32_x) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n testl %2,%2\n cmovel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  ਵਾਪਸ crypto_int32_z;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n cset %w0,eq" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  ਵਾਪਸ crypto_int32_z;
#ਨਹੀਂਤਾਂ
  ਵਾਪਸ 1-crypto_int32_nonzero_01(crypto_int32_x);
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int32 crypto_int32_unequal_ਨਕਾਬ(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n cmpl %3,%2\n cmovnel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ਵਾਪਸ crypto_int32_z;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n csetm %w0,ne" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ਵਾਪਸ crypto_int32_z;
#ਨਹੀਂਤਾਂ
  ਵਾਪਸ crypto_int32_nonzero_ਨਕਾਬ(crypto_int32_x ^ crypto_int32_y);
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int32 crypto_int32_unequal_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n cmpl %3,%2\n cmovnel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ਵਾਪਸ crypto_int32_z;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n cset %w0,ne" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ਵਾਪਸ crypto_int32_z;
#ਨਹੀਂਤਾਂ
  ਵਾਪਸ crypto_int32_nonzero_01(crypto_int32_x ^ crypto_int32_y);
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int32 crypto_int32_equal_ਨਕਾਬ(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n cmpl %3,%2\n cmovel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ਵਾਪਸ crypto_int32_z;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n csetm %w0,eq" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ਵਾਪਸ crypto_int32_z;
#ਨਹੀਂਤਾਂ
  ਵਾਪਸ ~crypto_int32_unequal_ਨਕਾਬ(crypto_int32_x,crypto_int32_y);
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int32 crypto_int32_equal_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n cmpl %3,%2\n cmovel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ਵਾਪਸ crypto_int32_z;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n cset %w0,eq" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ਵਾਪਸ crypto_int32_z;
#ਨਹੀਂਤਾਂ
  ਵਾਪਸ 1-crypto_int32_unequal_01(crypto_int32_x,crypto_int32_y);
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int32 crypto_int32_min(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpl %1,%0\n cmovgl %1,%0" : "+r"(crypto_int32_x) : "r"(crypto_int32_y) : "cc");
  ਵਾਪਸ crypto_int32_x;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("cmp %w0,%w1\n csel %w0,%w0,%w1,lt" : "+r"(crypto_int32_x) : "r"(crypto_int32_y) : "cc");
  ਵਾਪਸ crypto_int32_x;
#ਨਹੀਂਤਾਂ
  crypto_int64 crypto_int32_r = (crypto_int64)crypto_int32_y ^ (crypto_int64)crypto_int32_x;
  crypto_int64 crypto_int32_z = (crypto_int64)crypto_int32_y - (crypto_int64)crypto_int32_x;
  crypto_int32_z ^= crypto_int32_r & (crypto_int32_z ^ crypto_int32_y);
  crypto_int32_z = crypto_int32_negative_ਨਕਾਬ(crypto_int32_z);
  crypto_int32_z &= crypto_int32_r;
  ਵਾਪਸ crypto_int32_x ^ crypto_int32_z;
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int32 crypto_int32_max(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpl %1,%0\n cmovll %1,%0" : "+r"(crypto_int32_x) : "r"(crypto_int32_y) : "cc");
  ਵਾਪਸ crypto_int32_x;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("cmp %w0,%w1\n csel %w0,%w1,%w0,lt" : "+r"(crypto_int32_x) : "r"(crypto_int32_y) : "cc");
  ਵਾਪਸ crypto_int32_x;
#ਨਹੀਂਤਾਂ
  crypto_int64 crypto_int32_r = (crypto_int64)crypto_int32_y ^ (crypto_int64)crypto_int32_x;
  crypto_int64 crypto_int32_z = (crypto_int64)crypto_int32_y - (crypto_int64)crypto_int32_x;
  crypto_int32_z ^= crypto_int32_r & (crypto_int32_z ^ crypto_int32_y);
  crypto_int32_z = crypto_int32_negative_ਨਕਾਬ(crypto_int32_z);
  crypto_int32_z &= crypto_int32_r;
  ਵਾਪਸ crypto_int32_y ^ crypto_int32_z;
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
ਖਾਲੀ crypto_int32_minmax(crypto_int32 *crypto_int32_p,crypto_int32 *crypto_int32_q) {
  crypto_int32 crypto_int32_x = *crypto_int32_p;
  crypto_int32 crypto_int32_y = *crypto_int32_q;
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmpl %2,%1\n movl %1,%0\n cmovgl %2,%1\n cmovgl %0,%2" : "=&r"(crypto_int32_z), "+&r"(crypto_int32_x), "+r"(crypto_int32_y) : : "cc");
  *crypto_int32_p = crypto_int32_x;
  *crypto_int32_q = crypto_int32_y;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_r, crypto_int32_s;
  __asm__ ("cmp %w2,%w3\n csel %w0,%w2,%w3,lt\n csel %w1,%w3,%w2,lt" : "=&r"(crypto_int32_r), "=r"(crypto_int32_s) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  *crypto_int32_p = crypto_int32_r;
  *crypto_int32_q = crypto_int32_s;
#ਨਹੀਂਤਾਂ
  crypto_int64 crypto_int32_r = (crypto_int64)crypto_int32_y ^ (crypto_int64)crypto_int32_x;
  crypto_int64 crypto_int32_z = (crypto_int64)crypto_int32_y - (crypto_int64)crypto_int32_x;
  crypto_int32_z ^= crypto_int32_r & (crypto_int32_z ^ crypto_int32_y);
  crypto_int32_z = crypto_int32_negative_ਨਕਾਬ(crypto_int32_z);
  crypto_int32_z &= crypto_int32_r;
  crypto_int32_x ^= crypto_int32_z;
  crypto_int32_y ^= crypto_int32_z;
  *crypto_int32_p = crypto_int32_x;
  *crypto_int32_q = crypto_int32_y;
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int32 crypto_int32_smaller_ਨਕਾਬ(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n cmpl %3,%2\n cmovll %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ਵਾਪਸ crypto_int32_z;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n csetm %w0,lt" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ਵਾਪਸ crypto_int32_z;
#ਨਹੀਂਤਾਂ
  crypto_int32 crypto_int32_r = crypto_int32_x ^ crypto_int32_y;
  crypto_int32 crypto_int32_z = crypto_int32_x - crypto_int32_y;
  crypto_int32_z ^= crypto_int32_r & (crypto_int32_z ^ crypto_int32_x);
  ਵਾਪਸ crypto_int32_negative_ਨਕਾਬ(crypto_int32_z);
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int32 crypto_int32_smaller_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n cmpl %3,%2\n cmovll %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ਵਾਪਸ crypto_int32_z;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n cset %w0,lt" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ਵਾਪਸ crypto_int32_z;
#ਨਹੀਂਤਾਂ
  crypto_int32 crypto_int32_r = crypto_int32_x ^ crypto_int32_y;
  crypto_int32 crypto_int32_z = crypto_int32_x - crypto_int32_y;
  crypto_int32_z ^= crypto_int32_r & (crypto_int32_z ^ crypto_int32_x);
  ਵਾਪਸ crypto_int32_unsigned_topbit_01(crypto_int32_z);
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int32 crypto_int32_leq_ਨਕਾਬ(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n cmpl %3,%2\n cmovlel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ਵਾਪਸ crypto_int32_z;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n csetm %w0,le" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ਵਾਪਸ crypto_int32_z;
#ਨਹੀਂਤਾਂ
  ਵਾਪਸ ~crypto_int32_smaller_ਨਕਾਬ(crypto_int32_y,crypto_int32_x);
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int32 crypto_int32_leq_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n cmpl %3,%2\n cmovlel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ਵਾਪਸ crypto_int32_z;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n cset %w0,le" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ਵਾਪਸ crypto_int32_z;
#ਨਹੀਂਤਾਂ
  ਵਾਪਸ 1-crypto_int32_smaller_01(crypto_int32_y,crypto_int32_x);
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
ਪੂਰਨ crypto_int32_ones_ਅੰਕ(crypto_int32 crypto_int32_x) {
  crypto_int32_unsigned crypto_int32_y = crypto_int32_x;
  ਅਚਲ crypto_int32 C0 = 0x55555555;
  ਅਚਲ crypto_int32 C1 = 0x33333333;
  ਅਚਲ crypto_int32 C2 = 0x0f0f0f0f;
  crypto_int32_y -= ((crypto_int32_y >> 1) & C0);
  crypto_int32_y = (crypto_int32_y & C1) + ((crypto_int32_y >> 2) & C1);
  crypto_int32_y = (crypto_int32_y + (crypto_int32_y >> 4)) & C2;
  crypto_int32_y += crypto_int32_y >> 8;
  crypto_int32_y = (crypto_int32_y + (crypto_int32_y >> 16)) & 0xff;
  ਵਾਪਸ crypto_int32_y;
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
ਪੂਰਨ crypto_int32_bottomzeros_ਅੰਕ(crypto_int32 crypto_int32_x) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 fallback = 32;
  __asm__ ("bsfl %0,%0\n cmovel %1,%0" : "+&r"(crypto_int32_x) : "r"(fallback) : "cc");
  ਵਾਪਸ crypto_int32_x;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  int64_t crypto_int32_y;
  __asm__ ("rbit %w0,%w1\n clz %w0,%w0" : "=r"(crypto_int32_y) : "r"(crypto_int32_x) : );
  ਵਾਪਸ crypto_int32_y;
#ਨਹੀਂਤਾਂ
  crypto_int32 crypto_int32_y = crypto_int32_x ^ (crypto_int32_x-1);
  crypto_int32_y = ((crypto_int32) crypto_int32_y) >> 1;
  crypto_int32_y &= ~(crypto_int32_x & (((crypto_int32) 1) << (32-1)));
  ਵਾਪਸ crypto_int32_ones_ਅੰਕ(crypto_int32_y);
#ਜੇ_ਅੰਤ
}

#ਜੇ_ਅੰਤ

/* from supercop-20240808/cryptoint/crypto_int64.h */
/* auto-generated: cd cryptoint; ./autogen */
/* cryptoint 20240806 */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ crypto_int64_h
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ crypto_int64_h

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ crypto_int64 int64_t
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ crypto_int64_unsigned uint64_t



__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int64 crypto_int64_ਲੱਦੋ(ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *crypto_int64_s) {
  crypto_int64 crypto_int64_z = 0;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 0;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 8;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 16;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 24;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 32;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 40;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 48;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 56;
  ਵਾਪਸ crypto_int64_z;
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
ਖਾਲੀ crypto_int64_store(ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *crypto_int64_s,crypto_int64 crypto_int64_x) {
  *crypto_int64_s++ = crypto_int64_x >> 0;
  *crypto_int64_s++ = crypto_int64_x >> 8;
  *crypto_int64_s++ = crypto_int64_x >> 16;
  *crypto_int64_s++ = crypto_int64_x >> 24;
  *crypto_int64_s++ = crypto_int64_x >> 32;
  *crypto_int64_s++ = crypto_int64_x >> 40;
  *crypto_int64_s++ = crypto_int64_x >> 48;
  *crypto_int64_s++ = crypto_int64_x >> 56;
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int64 crypto_int64_negative_ਨਕਾਬ(crypto_int64 crypto_int64_x) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarq $63,%0" : "+r"(crypto_int64_x) : : "cc");
  ਵਾਪਸ crypto_int64_x;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_y;
  __asm__ ("asr %0,%1,63" : "=r"(crypto_int64_y) : "r"(crypto_int64_x) : );
  ਵਾਪਸ crypto_int64_y;
#ਨਹੀਂਤਾਂ
  crypto_int64_x >>= 64-6;
  crypto_int64_x ^= crypto_int64_optblocker;
  crypto_int64_x >>= 5;
  ਵਾਪਸ crypto_int64_x;
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int64_unsigned crypto_int64_unsigned_topbit_01(crypto_int64_unsigned crypto_int64_x) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("shrq $63,%0" : "+r"(crypto_int64_x) : : "cc");
  ਵਾਪਸ crypto_int64_x;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_y;
  __asm__ ("lsr %0,%1,63" : "=r"(crypto_int64_y) : "r"(crypto_int64_x) : );
  ਵਾਪਸ crypto_int64_y;
#ਨਹੀਂਤਾਂ
  crypto_int64_x >>= 64-6;
  crypto_int64_x ^= crypto_int64_optblocker;
  crypto_int64_x >>= 5;
  ਵਾਪਸ crypto_int64_x;
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int64 crypto_int64_negative_01(crypto_int64 crypto_int64_x) {
  ਵਾਪਸ crypto_int64_unsigned_topbit_01(crypto_int64_x);
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int64 crypto_int64_topbit_ਨਕਾਬ(crypto_int64 crypto_int64_x) {
  ਵਾਪਸ crypto_int64_negative_ਨਕਾਬ(crypto_int64_x);
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int64 crypto_int64_topbit_01(crypto_int64 crypto_int64_x) {
  ਵਾਪਸ crypto_int64_unsigned_topbit_01(crypto_int64_x);
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int64 crypto_int64_bottombit_ਨਕਾਬ(crypto_int64 crypto_int64_x) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andq $1,%0" : "+r"(crypto_int64_x) : : "cc");
  ਵਾਪਸ -crypto_int64_x;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_y;
  __asm__ ("sbfx %0,%1,0,1" : "=r"(crypto_int64_y) : "r"(crypto_int64_x) : );
  ਵਾਪਸ crypto_int64_y;
#ਨਹੀਂਤਾਂ
  crypto_int64_x &= 1 ^ crypto_int64_optblocker;
  ਵਾਪਸ -crypto_int64_x;
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int64 crypto_int64_bottombit_01(crypto_int64 crypto_int64_x) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andq $1,%0" : "+r"(crypto_int64_x) : : "cc");
  ਵਾਪਸ crypto_int64_x;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_y;
  __asm__ ("ubfx %0,%1,0,1" : "=r"(crypto_int64_y) : "r"(crypto_int64_x) : );
  ਵਾਪਸ crypto_int64_y;
#ਨਹੀਂਤਾਂ
  crypto_int64_x &= 1 ^ crypto_int64_optblocker;
  ਵਾਪਸ crypto_int64_x;
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int64 crypto_int64_bitinrangepublicpos_ਨਕਾਬ(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarq %%cl,%0" : "+r"(crypto_int64_x) : "c"(crypto_int64_s) : "cc");
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %0,%0,%1" : "+r"(crypto_int64_x) : "r"(crypto_int64_s) : );
#ਨਹੀਂਤਾਂ
  crypto_int64_x >>= crypto_int64_s ^ crypto_int64_optblocker;
#ਜੇ_ਅੰਤ
  ਵਾਪਸ crypto_int64_bottombit_ਨਕਾਬ(crypto_int64_x);
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int64 crypto_int64_bitinrangepublicpos_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarq %%cl,%0" : "+r"(crypto_int64_x) : "c"(crypto_int64_s) : "cc");
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %0,%0,%1" : "+r"(crypto_int64_x) : "r"(crypto_int64_s) : );
#ਨਹੀਂਤਾਂ
  crypto_int64_x >>= crypto_int64_s ^ crypto_int64_optblocker;
#ਜੇ_ਅੰਤ
  ਵਾਪਸ crypto_int64_bottombit_01(crypto_int64_x);
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int64 crypto_int64_shlmod(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("shlq %%cl,%0" : "+r"(crypto_int64_x) : "c"(crypto_int64_s) : "cc");
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("lsl %0,%0,%1" : "+r"(crypto_int64_x) : "r"(crypto_int64_s) : );
#ਨਹੀਂਤਾਂ
  ਪੂਰਨ crypto_int64_k, crypto_int64_l;
  ਲਈ (crypto_int64_l = 0,crypto_int64_k = 1;crypto_int64_k < 64;++crypto_int64_l,crypto_int64_k *= 2)
    crypto_int64_x ^= (crypto_int64_x ^ (crypto_int64_x << crypto_int64_k)) & crypto_int64_bitinrangepublicpos_ਨਕਾਬ(crypto_int64_s,crypto_int64_l);
#ਜੇ_ਅੰਤ
  ਵਾਪਸ crypto_int64_x;
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int64 crypto_int64_shrmod(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarq %%cl,%0" : "+r"(crypto_int64_x) : "c"(crypto_int64_s) : "cc");
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %0,%0,%1" : "+r"(crypto_int64_x) : "r"(crypto_int64_s) : );
#ਨਹੀਂਤਾਂ
  ਪੂਰਨ crypto_int64_k, crypto_int64_l;
  ਲਈ (crypto_int64_l = 0,crypto_int64_k = 1;crypto_int64_k < 64;++crypto_int64_l,crypto_int64_k *= 2)
    crypto_int64_x ^= (crypto_int64_x ^ (crypto_int64_x >> crypto_int64_k)) & crypto_int64_bitinrangepublicpos_ਨਕਾਬ(crypto_int64_s,crypto_int64_l);
#ਜੇ_ਅੰਤ
  ਵਾਪਸ crypto_int64_x;
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int64 crypto_int64_bitmod_ਨਕਾਬ(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
  crypto_int64_x = crypto_int64_shrmod(crypto_int64_x,crypto_int64_s);
  ਵਾਪਸ crypto_int64_bottombit_ਨਕਾਬ(crypto_int64_x);
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int64 crypto_int64_bitmod_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
  crypto_int64_x = crypto_int64_shrmod(crypto_int64_x,crypto_int64_s);
  ਵਾਪਸ crypto_int64_bottombit_01(crypto_int64_x);
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int64 crypto_int64_nonzero_ਨਕਾਬ(crypto_int64 crypto_int64_x) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n testq %2,%2\n cmovneq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  ਵਾਪਸ crypto_int64_z;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n csetm %0,ne" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  ਵਾਪਸ crypto_int64_z;
#ਨਹੀਂਤਾਂ
  crypto_int64_x |= -crypto_int64_x;
  ਵਾਪਸ crypto_int64_negative_ਨਕਾਬ(crypto_int64_x);
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int64 crypto_int64_nonzero_01(crypto_int64 crypto_int64_x) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n testq %2,%2\n cmovneq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  ਵਾਪਸ crypto_int64_z;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n cset %0,ne" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  ਵਾਪਸ crypto_int64_z;
#ਨਹੀਂਤਾਂ
  crypto_int64_x |= -crypto_int64_x;
  ਵਾਪਸ crypto_int64_unsigned_topbit_01(crypto_int64_x);
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int64 crypto_int64_ਸਕਾਰਾਤਮਕ_ਨਕਾਬ(crypto_int64 crypto_int64_x) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n testq %2,%2\n cmovgq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  ਵਾਪਸ crypto_int64_z;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n csetm %0,gt" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  ਵਾਪਸ crypto_int64_z;
#ਨਹੀਂਤਾਂ
  crypto_int64 crypto_int64_z = -crypto_int64_x;
  crypto_int64_z ^= crypto_int64_x & crypto_int64_z;
  ਵਾਪਸ crypto_int64_negative_ਨਕਾਬ(crypto_int64_z);
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int64 crypto_int64_ਸਕਾਰਾਤਮਕ_01(crypto_int64 crypto_int64_x) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n testq %2,%2\n cmovgq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  ਵਾਪਸ crypto_int64_z;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n cset %0,gt" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  ਵਾਪਸ crypto_int64_z;
#ਨਹੀਂਤਾਂ
  crypto_int64 crypto_int64_z = -crypto_int64_x;
  crypto_int64_z ^= crypto_int64_x & crypto_int64_z;
  ਵਾਪਸ crypto_int64_unsigned_topbit_01(crypto_int64_z);
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int64 crypto_int64_zero_ਨਕਾਬ(crypto_int64 crypto_int64_x) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n testq %2,%2\n cmoveq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  ਵਾਪਸ crypto_int64_z;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n csetm %0,eq" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  ਵਾਪਸ crypto_int64_z;
#ਨਹੀਂਤਾਂ
  ਵਾਪਸ ~crypto_int64_nonzero_ਨਕਾਬ(crypto_int64_x);
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int64 crypto_int64_zero_01(crypto_int64 crypto_int64_x) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n testq %2,%2\n cmoveq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  ਵਾਪਸ crypto_int64_z;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n cset %0,eq" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  ਵਾਪਸ crypto_int64_z;
#ਨਹੀਂਤਾਂ
  ਵਾਪਸ 1-crypto_int64_nonzero_01(crypto_int64_x);
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int64 crypto_int64_unequal_ਨਕਾਬ(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n cmpq %3,%2\n cmovneq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ਵਾਪਸ crypto_int64_z;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n csetm %0,ne" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ਵਾਪਸ crypto_int64_z;
#ਨਹੀਂਤਾਂ
  ਵਾਪਸ crypto_int64_nonzero_ਨਕਾਬ(crypto_int64_x ^ crypto_int64_y);
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int64 crypto_int64_unequal_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n cmpq %3,%2\n cmovneq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ਵਾਪਸ crypto_int64_z;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n cset %0,ne" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ਵਾਪਸ crypto_int64_z;
#ਨਹੀਂਤਾਂ
  ਵਾਪਸ crypto_int64_nonzero_01(crypto_int64_x ^ crypto_int64_y);
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int64 crypto_int64_equal_ਨਕਾਬ(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n cmpq %3,%2\n cmoveq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ਵਾਪਸ crypto_int64_z;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n csetm %0,eq" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ਵਾਪਸ crypto_int64_z;
#ਨਹੀਂਤਾਂ
  ਵਾਪਸ ~crypto_int64_unequal_ਨਕਾਬ(crypto_int64_x,crypto_int64_y);
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int64 crypto_int64_equal_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n cmpq %3,%2\n cmoveq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ਵਾਪਸ crypto_int64_z;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n cset %0,eq" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ਵਾਪਸ crypto_int64_z;
#ਨਹੀਂਤਾਂ
  ਵਾਪਸ 1-crypto_int64_unequal_01(crypto_int64_x,crypto_int64_y);
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int64 crypto_int64_min(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpq %1,%0\n cmovgq %1,%0" : "+r"(crypto_int64_x) : "r"(crypto_int64_y) : "cc");
  ਵਾਪਸ crypto_int64_x;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("cmp %0,%1\n csel %0,%0,%1,lt" : "+r"(crypto_int64_x) : "r"(crypto_int64_y) : "cc");
  ਵਾਪਸ crypto_int64_x;
#ਨਹੀਂਤਾਂ
  crypto_int64 crypto_int64_r = crypto_int64_y ^ crypto_int64_x;
  crypto_int64 crypto_int64_z = crypto_int64_y - crypto_int64_x;
  crypto_int64_z ^= crypto_int64_r & (crypto_int64_z ^ crypto_int64_y);
  crypto_int64_z = crypto_int64_negative_ਨਕਾਬ(crypto_int64_z);
  crypto_int64_z &= crypto_int64_r;
  ਵਾਪਸ crypto_int64_x ^ crypto_int64_z;
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int64 crypto_int64_max(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpq %1,%0\n cmovlq %1,%0" : "+r"(crypto_int64_x) : "r"(crypto_int64_y) : "cc");
  ਵਾਪਸ crypto_int64_x;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("cmp %0,%1\n csel %0,%1,%0,lt" : "+r"(crypto_int64_x) : "r"(crypto_int64_y) : "cc");
  ਵਾਪਸ crypto_int64_x;
#ਨਹੀਂਤਾਂ
  crypto_int64 crypto_int64_r = crypto_int64_y ^ crypto_int64_x;
  crypto_int64 crypto_int64_z = crypto_int64_y - crypto_int64_x;
  crypto_int64_z ^= crypto_int64_r & (crypto_int64_z ^ crypto_int64_y);
  crypto_int64_z = crypto_int64_negative_ਨਕਾਬ(crypto_int64_z);
  crypto_int64_z &= crypto_int64_r;
  ਵਾਪਸ crypto_int64_y ^ crypto_int64_z;
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
ਖਾਲੀ crypto_int64_minmax(crypto_int64 *crypto_int64_p,crypto_int64 *crypto_int64_q) {
  crypto_int64 crypto_int64_x = *crypto_int64_p;
  crypto_int64 crypto_int64_y = *crypto_int64_q;
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmpq %2,%1\n movq %1,%0\n cmovgq %2,%1\n cmovgq %0,%2" : "=&r"(crypto_int64_z), "+&r"(crypto_int64_x), "+r"(crypto_int64_y) : : "cc");
  *crypto_int64_p = crypto_int64_x;
  *crypto_int64_q = crypto_int64_y;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_r, crypto_int64_s;
  __asm__ ("cmp %2,%3\n csel %0,%2,%3,lt\n csel %1,%3,%2,lt" : "=&r"(crypto_int64_r), "=r"(crypto_int64_s) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  *crypto_int64_p = crypto_int64_r;
  *crypto_int64_q = crypto_int64_s;
#ਨਹੀਂਤਾਂ
  crypto_int64 crypto_int64_r = crypto_int64_y ^ crypto_int64_x;
  crypto_int64 crypto_int64_z = crypto_int64_y - crypto_int64_x;
  crypto_int64_z ^= crypto_int64_r & (crypto_int64_z ^ crypto_int64_y);
  crypto_int64_z = crypto_int64_negative_ਨਕਾਬ(crypto_int64_z);
  crypto_int64_z &= crypto_int64_r;
  crypto_int64_x ^= crypto_int64_z;
  crypto_int64_y ^= crypto_int64_z;
  *crypto_int64_p = crypto_int64_x;
  *crypto_int64_q = crypto_int64_y;
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int64 crypto_int64_smaller_ਨਕਾਬ(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n cmpq %3,%2\n cmovlq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ਵਾਪਸ crypto_int64_z;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n csetm %0,lt" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ਵਾਪਸ crypto_int64_z;
#ਨਹੀਂਤਾਂ
  crypto_int64 crypto_int64_r = crypto_int64_x ^ crypto_int64_y;
  crypto_int64 crypto_int64_z = crypto_int64_x - crypto_int64_y;
  crypto_int64_z ^= crypto_int64_r & (crypto_int64_z ^ crypto_int64_x);
  ਵਾਪਸ crypto_int64_negative_ਨਕਾਬ(crypto_int64_z);
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int64 crypto_int64_smaller_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n cmpq %3,%2\n cmovlq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ਵਾਪਸ crypto_int64_z;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n cset %0,lt" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ਵਾਪਸ crypto_int64_z;
#ਨਹੀਂਤਾਂ
  crypto_int64 crypto_int64_r = crypto_int64_x ^ crypto_int64_y;
  crypto_int64 crypto_int64_z = crypto_int64_x - crypto_int64_y;
  crypto_int64_z ^= crypto_int64_r & (crypto_int64_z ^ crypto_int64_x);
  ਵਾਪਸ crypto_int64_unsigned_topbit_01(crypto_int64_z);
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int64 crypto_int64_leq_ਨਕਾਬ(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n cmpq %3,%2\n cmovleq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ਵਾਪਸ crypto_int64_z;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n csetm %0,le" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ਵਾਪਸ crypto_int64_z;
#ਨਹੀਂਤਾਂ
  ਵਾਪਸ ~crypto_int64_smaller_ਨਕਾਬ(crypto_int64_y,crypto_int64_x);
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
crypto_int64 crypto_int64_leq_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n cmpq %3,%2\n cmovleq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ਵਾਪਸ crypto_int64_z;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n cset %0,le" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ਵਾਪਸ crypto_int64_z;
#ਨਹੀਂਤਾਂ
  ਵਾਪਸ 1-crypto_int64_smaller_01(crypto_int64_y,crypto_int64_x);
#ਜੇ_ਅੰਤ
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
ਪੂਰਨ crypto_int64_ones_ਅੰਕ(crypto_int64 crypto_int64_x) {
  crypto_int64_unsigned crypto_int64_y = crypto_int64_x;
  ਅਚਲ crypto_int64 C0 = 0x5555555555555555;
  ਅਚਲ crypto_int64 C1 = 0x3333333333333333;
  ਅਚਲ crypto_int64 C2 = 0x0f0f0f0f0f0f0f0f;
  crypto_int64_y -= ((crypto_int64_y >> 1) & C0);
  crypto_int64_y = (crypto_int64_y & C1) + ((crypto_int64_y >> 2) & C1);
  crypto_int64_y = (crypto_int64_y + (crypto_int64_y >> 4)) & C2;
  crypto_int64_y += crypto_int64_y >> 8;
  crypto_int64_y += crypto_int64_y >> 16;
  crypto_int64_y = (crypto_int64_y + (crypto_int64_y >> 32)) & 0xff;
  ਵਾਪਸ crypto_int64_y;
}

__attribute__((ਅਣਵਰਤਿਆ))
ਸਥਿਰ ਸਤਰਅੰਦਰ
ਪੂਰਨ crypto_int64_bottomzeros_ਅੰਕ(crypto_int64 crypto_int64_x) {
#ਜੇ defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 fallback = 64;
  __asm__ ("bsfq %0,%0\n cmoveq %1,%0" : "+&r"(crypto_int64_x) : "r"(fallback) : "cc");
  ਵਾਪਸ crypto_int64_x;
#ਜਾਂਜੇ defined(__GNUC__) && defined(__aarch64__)
  int64_t crypto_int64_y;
  __asm__ ("rbit %0,%1\n clz %0,%0" : "=r"(crypto_int64_y) : "r"(crypto_int64_x) : );
  ਵਾਪਸ crypto_int64_y;
#ਨਹੀਂਤਾਂ
  crypto_int64 crypto_int64_y = crypto_int64_x ^ (crypto_int64_x-1);
  crypto_int64_y = ((crypto_int64) crypto_int64_y) >> 1;
  crypto_int64_y &= ~(crypto_int64_x & (((crypto_int64) 1) << (64-1)));
  ਵਾਪਸ crypto_int64_ones_ਅੰਕ(crypto_int64_y);
#ਜੇ_ਅੰਤ
}

#ਜੇ_ਅੰਤ

/* from supercop-20240808/crypto_sort/int32/portable4/sort.c */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ int32_MINMAX(a,b) crypto_int32_minmax(&a,&b)

ਸਥਿਰ ਖਾਲੀ crypto_ਛਾਂਟੋ_int32(ਖਾਲੀ *array,ਲੰਮਾ ਲੰਮਾ n)
{
  ਲੰਮਾ ਲੰਮਾ ਸਿਖਰ,p,q,r,i,j;
  int32 *x = array;

  ਜੇ (n < 2) ਵਾਪਸ;
  ਸਿਖਰ = 1;
  ਜਦੋਂ (ਸਿਖਰ < n - ਸਿਖਰ) ਸਿਖਰ += ਸਿਖਰ;

  ਲਈ (p = ਸਿਖਰ;p >= 1;p >>= 1) {
    i = 0;
    ਜਦੋਂ (i + 2 * p <= n) {
      ਲਈ (j = i;j < i + p;++j)
        int32_MINMAX(x[j],x[j+p]);
      i += 2 * p;
    }
    ਲਈ (j = i;j < n - p;++j)
      int32_MINMAX(x[j],x[j+p]);

    i = 0;
    j = 0;
    ਲਈ (q = ਸਿਖਰ;q > p;q >>= 1) {
      ਜੇ (j != i) ਲਈ (;;) {
        ਜੇ (j == n - q) ਜਾਓ ਪੂਰਾ;
        int32 a = x[j + p];
        ਲਈ (r = q;r > p;r >>= 1)
          int32_MINMAX(a,x[j + r]);
        x[j + p] = a;
        ++j;
        ਜੇ (j == i + p) {
          i += 2 * p;
          ਰੋਕੋ;
        }
      }
      ਜਦੋਂ (i + p <= n - q) {
        ਲਈ (j = i;j < i + p;++j) {
          int32 a = x[j + p];
          ਲਈ (r = q;r > p;r >>= 1)
            int32_MINMAX(a,x[j+r]);
          x[j + p] = a;
        }
        i += 2 * p;
      }
      /* now i + p > n - q */
      j = i;
      ਜਦੋਂ (j < n - q) {
        int32 a = x[j + p];
        ਲਈ (r = q;r > p;r >>= 1)
          int32_MINMAX(a,x[j+r]);
        x[j + p] = a;
        ++j;
      }

      ਪੂਰਾ: ;
    }
  }
}

/* from supercop-20240808/crypto_sort/uint32/useint32/sort.c */

/* can save time by vectorizing xor loops */
/* can save time by integrating xor loops with int32_sort */

ਸਥਿਰ ਖਾਲੀ crypto_ਛਾਂਟੋ_uint32(ਖਾਲੀ *array,ਲੰਮਾ ਲੰਮਾ n)
{
  crypto_uint32 *x = array;
  ਲੰਮਾ ਲੰਮਾ j;
  ਲਈ (j = 0;j < n;++j) x[j] ^= 0x80000000;
  crypto_ਛਾਂਟੋ_int32(array,n);
  ਲਈ (j = 0;j < n;++j) x[j] ^= 0x80000000;
}

/* from supercop-20240808/crypto_kem/sntrup761/compact/kem.c */
// 20240806 djb: some automated conversion to cryptoint

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ p 761
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ q 4591
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ w 286
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ q12 ((q - 1) / 2)
ਕਿਸਮਪਰਿਭਾਸ਼ਾ int8_t small;
ਕਿਸਮਪਰਿਭਾਸ਼ਾ int16_t Fq;
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ Hash_ਬਾਈਟਾਂ 32
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ Small_ਬਾਈਟਾਂ ((p + 3) / 4)
ਕਿਸਮਪਰਿਭਾਸ਼ਾ small Inputs[p];
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ Secret_ਕੁੰਜੀਆਂ_ਬਾਈਟਾਂ (2 * Small_ਬਾਈਟਾਂ)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ Confirm_ਬਾਈਟਾਂ 32

ਸਥਿਰ small F3_freeze(int16_t x) { ਵਾਪਸ x - 3 * ((10923 * x + 16384) >> 15); }

ਸਥਿਰ Fq Fq_freeze(int32_t x) {
  ਅਚਲ int32_t q16 = (0x10000 + q / 2) / q;
  ਅਚਲ int32_t q20 = (0x100000 + q / 2) / q;
  ਅਚਲ int32_t q28 = (0x10000000 + q / 2) / q;
  x -= q * ((q16 * x) >> 16);
  x -= q * ((q20 * x) >> 20);
  ਵਾਪਸ x - q * ((q28 * x + 0x8000000) >> 28);
}

ਸਥਿਰ ਪੂਰਨ Weightw_ਨਕਾਬ(small *r) {
  ਪੂਰਨ i, ਭਾਰ = 0;
  ਲਈ (i = 0; i < p; ++i) ਭਾਰ += crypto_int64_bottombit_01(r[i]);
  ਵਾਪਸ crypto_int16_nonzero_ਨਕਾਬ(ਭਾਰ - w);
}

ਸਥਿਰ ਖਾਲੀ uint32_divmod_uint14(uint32_t *Q, uint16_t *r, uint32_t x, uint16_t m) {
  uint32_t qpart, ਨਕਾਬ, v = 0x80000000 / m;
  qpart = (x * (uint64_t)v) >> 31;
  x -= qpart * m;
  *Q = qpart;
  qpart = (x * (uint64_t)v) >> 31;
  x -= qpart * m;
  *Q += qpart;
  x -= m;
  *Q += 1;
  ਨਕਾਬ = crypto_int32_negative_ਨਕਾਬ(x);
  x += ਨਕਾਬ & (uint32_t)m;
  *Q += ਨਕਾਬ;
  *r = x;
}

ਸਥਿਰ uint16_t uint32_mod_uint14(uint32_t x, uint16_t m) {
  uint32_t Q;
  uint16_t r;
  uint32_divmod_uint14(&Q, &r, x, m);
  ਵਾਪਸ r;
}

ਸਥਿਰ ਖਾਲੀ Encode(ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *ਬਾਹਰਲਾ, ਅਚਲ uint16_t *R, ਅਚਲ uint16_t *M, ਲੰਮਾ ਲੰਮਾ len) {
  ਜੇ (len == 1) {
    uint16_t r = R[0], m = M[0];
    ਜਦੋਂ (m > 1) {
      *ਬਾਹਰਲਾ++ = r;
      r >>= 8;
      m = (m + 255) >> 8;
    }
  }
  ਜੇ (len > 1) {
    uint16_t R2[(len + 1) / 2], M2[(len + 1) / 2];
    ਲੰਮਾ ਲੰਮਾ i;
    ਲਈ (i = 0; i < len - 1; i += 2) {
      uint32_t m0 = M[i];
      uint32_t r = R[i] + R[i + 1] * m0;
      uint32_t m = M[i + 1] * m0;
      ਜਦੋਂ (m >= 16384) {
        *ਬਾਹਰਲਾ++ = r;
        r >>= 8;
        m = (m + 255) >> 8;
      }
      R2[i / 2] = r;
      M2[i / 2] = m;
    }
    ਜੇ (i < len) {
      R2[i / 2] = R[i];
      M2[i / 2] = M[i];
    }
    Encode(ਬਾਹਰਲਾ, R2, M2, (len + 1) / 2);
  }
}

ਸਥਿਰ ਖਾਲੀ Decode(uint16_t *ਬਾਹਰਲਾ, ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *S, ਅਚਲ uint16_t *M, ਲੰਮਾ ਲੰਮਾ len) {
  ਜੇ (len == 1) {
    ਜੇ (M[0] == 1)
      *ਬਾਹਰਲਾ = 0;
    ਨਹੀਂਤਾਂ ਜੇ (M[0] <= 256)
      *ਬਾਹਰਲਾ = uint32_mod_uint14(S[0], M[0]);
    ਨਹੀਂਤਾਂ
      *ਬਾਹਰਲਾ = uint32_mod_uint14(S[0] + (((uint16_t)S[1]) << 8), M[0]);
  }
  ਜੇ (len > 1) {
    uint16_t R2[(len + 1) / 2], M2[(len + 1) / 2], bottomr[len / 2];
    uint32_t bottomt[len / 2];
    ਲੰਮਾ ਲੰਮਾ i;
    ਲਈ (i = 0; i < len - 1; i += 2) {
      uint32_t m = M[i] * (uint32_t)M[i + 1];
      ਜੇ (m > 256 * 16383) {
        bottomt[i / 2] = 256 * 256;
        bottomr[i / 2] = S[0] + 256 * S[1];
        S += 2;
        M2[i / 2] = (((m + 255) >> 8) + 255) >> 8;
      } ਨਹੀਂਤਾਂ ਜੇ (m >= 16384) {
        bottomt[i / 2] = 256;
        bottomr[i / 2] = S[0];
        S += 1;
        M2[i / 2] = (m + 255) >> 8;
      } ਨਹੀਂਤਾਂ {
        bottomt[i / 2] = 1;
        bottomr[i / 2] = 0;
        M2[i / 2] = m;
      }
    }
    ਜੇ (i < len) M2[i / 2] = M[i];
    Decode(R2, S, M2, (len + 1) / 2);
    ਲਈ (i = 0; i < len - 1; i += 2) {
      uint32_t r1, r = bottomr[i / 2];
      uint16_t r0;
      r += bottomt[i / 2] * R2[i / 2];
      uint32_divmod_uint14(&r1, &r0, r, M[i]);
      r1 = uint32_mod_uint14(r1, M[i + 1]);
      *ਬਾਹਰਲਾ++ = r0;
      *ਬਾਹਰਲਾ++ = r1;
    }
    ਜੇ (i < len) *ਬਾਹਰਲਾ++ = R2[i / 2];
  }
}

ਸਥਿਰ ਖਾਲੀ R3_fromRq(small *ਬਾਹਰਲਾ, ਅਚਲ Fq *r) {
  ਪੂਰਨ i;
  ਲਈ (i = 0; i < p; ++i) ਬਾਹਰਲਾ[i] = F3_freeze(r[i]);
}

ਸਥਿਰ ਖਾਲੀ R3_mult(small *h, ਅਚਲ small *f, ਅਚਲ small *g) {
  int16_t fg[p + p - 1];
  ਪੂਰਨ i, j;
  ਲਈ (i = 0; i < p + p - 1; ++i) fg[i] = 0;
  ਲਈ (i = 0; i < p; ++i)
    ਲਈ (j = 0; j < p; ++j) fg[i + j] += f[i] * (int16_t)g[j];
  ਲਈ (i = p; i < p + p - 1; ++i) fg[i - p] += fg[i];
  ਲਈ (i = p; i < p + p - 1; ++i) fg[i - p + 1] += fg[i];
  ਲਈ (i = 0; i < p; ++i) h[i] = F3_freeze(fg[i]);
}

ਸਥਿਰ ਪੂਰਨ R3_recip(small *ਬਾਹਰਲਾ, ਅਚਲ small *ਵਿੱਚ) {
  small f[p + 1], g[p + 1], v[p + 1], r[p + 1];
  ਪੂਰਨ sign, ਅਦਲਾ_ਬਦਲੀ, t, i, loop, delta = 1;
  ਲਈ (i = 0; i < p + 1; ++i) v[i] = 0;
  ਲਈ (i = 0; i < p + 1; ++i) r[i] = 0;
  r[0] = 1;
  ਲਈ (i = 0; i < p; ++i) f[i] = 0;
  f[0] = 1;
  f[p - 1] = f[p] = -1;
  ਲਈ (i = 0; i < p; ++i) g[p - 1 - i] = ਵਿੱਚ[i];
  g[p] = 0;
  ਲਈ (loop = 0; loop < 2 * p - 1; ++loop) {
    ਲਈ (i = p; i > 0; --i) v[i] = v[i - 1];
    v[0] = 0;
    sign = -g[0] * f[0];
    ਅਦਲਾ_ਬਦਲੀ = crypto_int16_negative_ਨਕਾਬ(-delta) & crypto_int16_nonzero_ਨਕਾਬ(g[0]);
    delta ^= ਅਦਲਾ_ਬਦਲੀ & (delta ^ -delta);
    delta += 1;
    ਲਈ (i = 0; i < p + 1; ++i) {
      t = ਅਦਲਾ_ਬਦਲੀ & (f[i] ^ g[i]);
      f[i] ^= t;
      g[i] ^= t;
      t = ਅਦਲਾ_ਬਦਲੀ & (v[i] ^ r[i]);
      v[i] ^= t;
      r[i] ^= t;
    }
    ਲਈ (i = 0; i < p + 1; ++i) g[i] = F3_freeze(g[i] + sign * f[i]);
    ਲਈ (i = 0; i < p + 1; ++i) r[i] = F3_freeze(r[i] + sign * v[i]);
    ਲਈ (i = 0; i < p; ++i) g[i] = g[i + 1];
    g[p] = 0;
  }
  sign = f[0];
  ਲਈ (i = 0; i < p; ++i) ਬਾਹਰਲਾ[i] = sign * v[p - 1 - i];
  ਵਾਪਸ crypto_int16_nonzero_ਨਕਾਬ(delta);
}

ਸਥਿਰ ਖਾਲੀ Rq_mult_small(Fq *h, ਅਚਲ Fq *f, ਅਚਲ small *g) {
  int32_t fg[p + p - 1];
  ਪੂਰਨ i, j;
  ਲਈ (i = 0; i < p + p - 1; ++i) fg[i] = 0;
  ਲਈ (i = 0; i < p; ++i)
    ਲਈ (j = 0; j < p; ++j) fg[i + j] += f[i] * (int32_t)g[j];
  ਲਈ (i = p; i < p + p - 1; ++i) fg[i - p] += fg[i];
  ਲਈ (i = p; i < p + p - 1; ++i) fg[i - p + 1] += fg[i];
  ਲਈ (i = 0; i < p; ++i) h[i] = Fq_freeze(fg[i]);
}

ਸਥਿਰ ਖਾਲੀ Rq_mult3(Fq *h, ਅਚਲ Fq *f) {
  ਪੂਰਨ i;
  ਲਈ (i = 0; i < p; ++i) h[i] = Fq_freeze(3 * f[i]);
}

ਸਥਿਰ Fq Fq_recip(Fq a1) {
  ਪੂਰਨ i = 1;
  Fq ai = a1;
  ਜਦੋਂ (i < q - 2) {
    ai = Fq_freeze(a1 * (int32_t)ai);
    i += 1;
  }
  ਵਾਪਸ ai;
}

ਸਥਿਰ ਪੂਰਨ Rq_recip3(Fq *ਬਾਹਰਲਾ, ਅਚਲ small *ਵਿੱਚ) {
  Fq f[p + 1], g[p + 1], v[p + 1], r[p + 1], scale;
  ਪੂਰਨ ਅਦਲਾ_ਬਦਲੀ, t, i, loop, delta = 1;
  int32_t f0, g0;
  ਲਈ (i = 0; i < p + 1; ++i) v[i] = 0;
  ਲਈ (i = 0; i < p + 1; ++i) r[i] = 0;
  r[0] = Fq_recip(3);
  ਲਈ (i = 0; i < p; ++i) f[i] = 0;
  f[0] = 1;
  f[p - 1] = f[p] = -1;
  ਲਈ (i = 0; i < p; ++i) g[p - 1 - i] = ਵਿੱਚ[i];
  g[p] = 0;
  ਲਈ (loop = 0; loop < 2 * p - 1; ++loop) {
    ਲਈ (i = p; i > 0; --i) v[i] = v[i - 1];
    v[0] = 0;
    ਅਦਲਾ_ਬਦਲੀ = crypto_int16_negative_ਨਕਾਬ(-delta) & crypto_int16_nonzero_ਨਕਾਬ(g[0]);
    delta ^= ਅਦਲਾ_ਬਦਲੀ & (delta ^ -delta);
    delta += 1;
    ਲਈ (i = 0; i < p + 1; ++i) {
      t = ਅਦਲਾ_ਬਦਲੀ & (f[i] ^ g[i]);
      f[i] ^= t;
      g[i] ^= t;
      t = ਅਦਲਾ_ਬਦਲੀ & (v[i] ^ r[i]);
      v[i] ^= t;
      r[i] ^= t;
    }
    f0 = f[0];
    g0 = g[0];
    ਲਈ (i = 0; i < p + 1; ++i) g[i] = Fq_freeze(f0 * g[i] - g0 * f[i]);
    ਲਈ (i = 0; i < p + 1; ++i) r[i] = Fq_freeze(f0 * r[i] - g0 * v[i]);
    ਲਈ (i = 0; i < p; ++i) g[i] = g[i + 1];
    g[p] = 0;
  }
  scale = Fq_recip(f[0]);
  ਲਈ (i = 0; i < p; ++i) ਬਾਹਰਲਾ[i] = Fq_freeze(scale * (int32_t)v[p - 1 - i]);
  ਵਾਪਸ crypto_int16_nonzero_ਨਕਾਬ(delta);
}

ਸਥਿਰ ਖਾਲੀ ਗੇੜਾ_3(Fq *ਬਾਹਰਲਾ, ਅਚਲ Fq *a) {
  ਪੂਰਨ i;
  ਲਈ (i = 0; i < p; ++i) ਬਾਹਰਲਾ[i] = a[i] - F3_freeze(a[i]);
}

ਸਥਿਰ ਖਾਲੀ Short_fromlist(small *ਬਾਹਰਲਾ, ਅਚਲ uint32_t *ਵਿੱਚ) {
  uint32_t L[p];
  ਪੂਰਨ i;
  ਲਈ (i = 0; i < w; ++i) L[i] = ਵਿੱਚ[i] & (uint32_t)-2;
  ਲਈ (i = w; i < p; ++i) L[i] = (ਵਿੱਚ[i] & (uint32_t)-3) | 1;
  crypto_ਛਾਂਟੋ_uint32(L, p);
  ਲਈ (i = 0; i < p; ++i) ਬਾਹਰਲਾ[i] = (L[i] & 3) - 1;
}

ਸਥਿਰ ਖਾਲੀ Hash_ਅਗੇਤਰ(ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *ਬਾਹਰਲਾ, ਪੂਰਨ b, ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *ਵਿੱਚ, ਪੂਰਨ inlen) {
  ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ x[inlen + 1], h[64];
  ਪੂਰਨ i;
  x[0] = b;
  ਲਈ (i = 0; i < inlen; ++i) x[i + 1] = ਵਿੱਚ[i];
  crypto_hash_sha512(h, x, inlen + 1);
  ਲਈ (i = 0; i < 32; ++i) ਬਾਹਰਲਾ[i] = h[i];
}


ਸਥਿਰ ਖਾਲੀ Short_random(small *ਬਾਹਰਲਾ) {
  uint32_t L[p];
  randombytes(L, ਆਕਾਰ(L));
  Short_fromlist(ਬਾਹਰਲਾ, L);
  explicit_bzero(L, ਆਕਾਰ(L));
}
ਸਥਿਰ ਖਾਲੀ Small_random(small *ਬਾਹਰਲਾ) {
  ਪੂਰਨ i;
  uint32_t L[p];
  randombytes(L, ਆਕਾਰ(L));
  ਲਈ (i = 0; i < p; ++i) ਬਾਹਰਲਾ[i] = (((L[i] & 0x3fffffff) * 3) >> 30) - 1;
  explicit_bzero(L, ਆਕਾਰ(L));
}
ਸਥਿਰ ਖਾਲੀ ਕੁੰਜੀ_Gen(Fq *h, small *f, small *ginv) {
  small g[p];
  Fq finv[p];
  ਲਈ (;;) {
    ਪੂਰਨ ਨਤੀਜਾ;
    Small_random(g);
    ਨਤੀਜਾ = R3_recip(ginv, g);
    crypto_declassify(&ਨਤੀਜਾ, ਆਕਾਰ ਨਤੀਜਾ);
    ਜੇ (ਨਤੀਜਾ == 0) ਰੋਕੋ;
  }
  Short_random(f);
  Rq_recip3(finv, f);
  Rq_mult_small(h, finv, g);
}

ਸਥਿਰ ਖਾਲੀ Encrypt(Fq *c, ਅਚਲ small *r, ਅਚਲ Fq *h) {
  Fq hr[p];
  Rq_mult_small(hr, h, r);
  ਗੇੜਾ_3(c, hr);
}

ਸਥਿਰ ਖਾਲੀ Decrypt(small *r, ਅਚਲ Fq *c, ਅਚਲ small *f, ਅਚਲ small *ginv) {
  Fq cf[p], cf3[p];
  small e[p], ev[p];
  ਪੂਰਨ ਨਕਾਬ, i;
  Rq_mult_small(cf, c, f);
  Rq_mult3(cf3, cf);
  R3_fromRq(e, cf3);
  R3_mult(ev, e, ginv);
  ਨਕਾਬ = Weightw_ਨਕਾਬ(ev);
  ਲਈ (i = 0; i < w; ++i) r[i] = ((ev[i] ^ 1) & ~ਨਕਾਬ) ^ 1;
  ਲਈ (i = w; i < p; ++i) r[i] = ev[i] & ~ਨਕਾਬ;
}

ਸਥਿਰ ਖਾਲੀ Small_encode(ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *s, ਅਚਲ small *f) {
  ਪੂਰਨ i, j;
  ਲਈ (i = 0; i < p / 4; ++i) {
    small x = 0;
    ਲਈ (j = 0;j < 4;++j) x += (*f++ + 1) << (2 * j);
    *s++ = x;
  }
  *s = *f++ + 1;
}

ਸਥਿਰ ਖਾਲੀ Small_decode(small *f, ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *s) {
  ਪੂਰਨ i, j;
  ਲਈ (i = 0; i < p / 4; ++i) {
    ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ x = *s++;
    ਲਈ (j = 0;j < 4;++j) *f++ = ((small)((x >> (2 * j)) & 3)) - 1;
  }
  *f++ = ((small)(*s & 3)) - 1;
}

ਸਥਿਰ ਖਾਲੀ Rq_encode(ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *s, ਅਚਲ Fq *r) {
  uint16_t R[p], M[p];
  ਪੂਰਨ i;
  ਲਈ (i = 0; i < p; ++i) R[i] = r[i] + q12;
  ਲਈ (i = 0; i < p; ++i) M[i] = q;
  Encode(s, R, M, p);
}

ਸਥਿਰ ਖਾਲੀ Rq_decode(Fq *r, ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *s) {
  uint16_t R[p], M[p];
  ਪੂਰਨ i;
  ਲਈ (i = 0; i < p; ++i) M[i] = q;
  Decode(R, s, M, p);
  ਲਈ (i = 0; i < p; ++i) r[i] = ((Fq)R[i]) - q12;
}

ਸਥਿਰ ਖਾਲੀ Rounded_encode(ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *s, ਅਚਲ Fq *r) {
  uint16_t R[p], M[p];
  ਪੂਰਨ i;
  ਲਈ (i = 0; i < p; ++i) R[i] = ((r[i] + q12) * 10923) >> 15;
  ਲਈ (i = 0; i < p; ++i) M[i] = (q + 2) / 3;
  Encode(s, R, M, p);
}

ਸਥਿਰ ਖਾਲੀ Rounded_decode(Fq *r, ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *s) {
  uint16_t R[p], M[p];
  ਪੂਰਨ i;
  ਲਈ (i = 0; i < p; ++i) M[i] = (q + 2) / 3;
  Decode(R, s, M, p);
  ਲਈ (i = 0; i < p; ++i) r[i] = R[i] * 3 - q12;
}

ਸਥਿਰ ਖਾਲੀ ZKeyGen(ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *pk, ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *sk) {
  Fq h[p];
  small f[p], v[p];
  ਕੁੰਜੀ_Gen(h, f, v);
  Rq_encode(pk, h);
  Small_encode(sk, f);
  Small_encode(sk + Small_ਬਾਈਟਾਂ, v);
}

ਸਥਿਰ ਖਾਲੀ ZEncrypt(ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *C, ਅਚਲ Inputs r, ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *pk) {
  Fq h[p], c[p];
  Rq_decode(h, pk);
  Encrypt(c, r, h);
  Rounded_encode(C, c);
}

ਸਥਿਰ ਖਾਲੀ ZDecrypt(Inputs r, ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *C, ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *sk) {
  small f[p], v[p];
  Fq c[p];
  Small_decode(f, sk);
  Small_decode(v, sk + Small_ਬਾਈਟਾਂ);
  Rounded_decode(c, C);
  Decrypt(r, c, f, v);
}

ਸਥਿਰ ਖਾਲੀ HashConfirm(ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *h, ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *r, ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *cache) {
  ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ x[Hash_ਬਾਈਟਾਂ * 2];
  ਪੂਰਨ i;
  Hash_ਅਗੇਤਰ(x, 3, r, Small_ਬਾਈਟਾਂ);
  ਲਈ (i = 0; i < Hash_ਬਾਈਟਾਂ; ++i) x[Hash_ਬਾਈਟਾਂ + i] = cache[i];
  Hash_ਅਗੇਤਰ(h, 2, x, ਆਕਾਰ x);
}

ਸਥਿਰ ਖਾਲੀ HashSession(ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *k, ਪੂਰਨ b, ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *y, ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *z) {
  ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ x[Hash_ਬਾਈਟਾਂ + crypto_kem_sntrup761_CIPHERTEXTBYTES];
  ਪੂਰਨ i;
  Hash_ਅਗੇਤਰ(x, 3, y, Small_ਬਾਈਟਾਂ);
  ਲਈ (i = 0; i < crypto_kem_sntrup761_CIPHERTEXTBYTES; ++i) x[Hash_ਬਾਈਟਾਂ + i] = z[i];
  Hash_ਅਗੇਤਰ(k, b, x, ਆਕਾਰ x);
}

ਪੂਰਨ crypto_kem_sntrup761_keypair(ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *pk, ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *sk) {
  ਪੂਰਨ i;
  ZKeyGen(pk, sk);
  sk += Secret_ਕੁੰਜੀਆਂ_ਬਾਈਟਾਂ;
  ਲਈ (i = 0; i < crypto_kem_sntrup761_PUBLICKEYBYTES; ++i) *sk++ = pk[i];
  randombytes(sk, Small_ਬਾਈਟਾਂ);
  Hash_ਅਗੇਤਰ(sk + Small_ਬਾਈਟਾਂ, 4, pk, crypto_kem_sntrup761_PUBLICKEYBYTES);
  ਵਾਪਸ 0;
}

ਸਥਿਰ ਖਾਲੀ Hide(ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *c, ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *r_enc, ਅਚਲ Inputs r, ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *pk, ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *cache) {
  Small_encode(r_enc, r);
  ZEncrypt(c, r, pk);
  HashConfirm(c + crypto_kem_sntrup761_CIPHERTEXTBYTES - Confirm_ਬਾਈਟਾਂ, r_enc, cache);
}

ਪੂਰਨ crypto_kem_sntrup761_enc(ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *c, ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *k, ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *pk) {
  Inputs r;
  ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ r_enc[Small_ਬਾਈਟਾਂ], cache[Hash_ਬਾਈਟਾਂ];
  Hash_ਅਗੇਤਰ(cache, 4, pk, crypto_kem_sntrup761_PUBLICKEYBYTES);
  Short_random(r);
  Hide(c, r_enc, r, pk, cache);
  HashSession(k, 1, r_enc, c);
  ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ Ciphertexts_diff_ਨਕਾਬ(ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *c, ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *c2) {
  uint16_t differentbits = 0;
  ਪੂਰਨ len = crypto_kem_sntrup761_CIPHERTEXTBYTES;
  ਜਦੋਂ (len-- > 0) differentbits |= (*c++) ^ (*c2++);
  ਵਾਪਸ (crypto_int64_bitmod_01((differentbits - 1),8)) - 1;
}

ਪੂਰਨ crypto_kem_sntrup761_dec(ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *k, ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *c, ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *sk) {
  ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *pk = sk + Secret_ਕੁੰਜੀਆਂ_ਬਾਈਟਾਂ;
  ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *rho = pk + crypto_kem_sntrup761_PUBLICKEYBYTES;
  ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *cache = rho + Small_ਬਾਈਟਾਂ;
  Inputs r;
  ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ r_enc[Small_ਬਾਈਟਾਂ], cnew[crypto_kem_sntrup761_CIPHERTEXTBYTES];
  ਪੂਰਨ ਨਕਾਬ, i;
  ZDecrypt(r, c, sk);
  Hide(cnew, r_enc, r, pk, cache);
  ਨਕਾਬ = Ciphertexts_diff_ਨਕਾਬ(c, cnew);
  ਲਈ (i = 0; i < Small_ਬਾਈਟਾਂ; ++i) r_enc[i] ^= ਨਕਾਬ & (r_enc[i] ^ rho[i]);
  HashSession(k, 1 + ਨਕਾਬ, r_enc, c);
  ਵਾਪਸ 0;
}

#ਜੇ_ਅੰਤ /* USE_SNTRUP761X25519 */
