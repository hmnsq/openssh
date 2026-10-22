/*  $OpenBSD: sntrup761.c,v 1.9 2026/01/20 22:56:11 dtucker Exp $ */

/*
 * Public Domain, Authors:
 * - Daniel J. Bernstein
 * - Chitchanok Chuengsatiansup
 * - Tanja Lange
 * - Christine van Vredendaal
 */

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ifdef USE_SNTRUP761X25519

#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ "crypto_api.h"

#define crypto_declassify(x, y) କର {} ଯେତେବେଳେ (0)

#define int8 crypto_int8
#define uint8 crypto_uint8
#define int16 crypto_int16
#define uint16 crypto_uint16
#define int32 crypto_int32
#define uint32 crypto_uint32
#define int64 crypto_int64
#define uint64 crypto_uint64
ବାହ୍ୟ ଅସ୍ଥିର crypto_int16 crypto_int16_optblocker;
ବାହ୍ୟ ଅସ୍ଥିର crypto_int32 crypto_int32_optblocker;
ବାହ୍ୟ ଅସ୍ଥିର crypto_int64 crypto_int64_optblocker;

/* from supercop-20240808/cryptoint/crypto_int16.h */
/* auto-generated: cd cryptoint; ./autogen */
/* cryptoint 20240806 */

#ifndef crypto_int16_h
#define crypto_int16_h

#define crypto_int16 int16_t
#define crypto_int16_unsigned uint16_t



__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int16 crypto_int16_load(ଅଚଳ unsigned ଅକ୍ଷର *crypto_int16_s) {
  crypto_int16 crypto_int16_z = 0;
  crypto_int16_z |= ((crypto_int16) (*crypto_int16_s++)) << 0;
  crypto_int16_z |= ((crypto_int16) (*crypto_int16_s++)) << 8;
  ଫେରନ୍ତୁ crypto_int16_z;
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
ଶୂନ୍ୟ crypto_int16_store(unsigned ଅକ୍ଷର *crypto_int16_s,crypto_int16 crypto_int16_x) {
  *crypto_int16_s++ = crypto_int16_x >> 0;
  *crypto_int16_s++ = crypto_int16_x >> 8;
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int16 crypto_int16_negative_mask(crypto_int16 crypto_int16_x) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarw $15,%0" : "+r"(crypto_int16_x) : : "cc");
  ଫେରନ୍ତୁ crypto_int16_x;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_y;
  __asm__ ("sbfx %w0,%w1,15,1" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) : );
  ଫେରନ୍ତୁ crypto_int16_y;
#ଅନ୍ୟଥା
  crypto_int16_x >>= 16-6;
  crypto_int16_x ^= crypto_int16_optblocker;
  crypto_int16_x >>= 5;
  ଫେରନ୍ତୁ crypto_int16_x;
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int16_unsigned crypto_int16_unsigned_topbit_01(crypto_int16_unsigned crypto_int16_x) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("shrw $15,%0" : "+r"(crypto_int16_x) : : "cc");
  ଫେରନ୍ତୁ crypto_int16_x;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_y;
  __asm__ ("ubfx %w0,%w1,15,1" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) : );
  ଫେରନ୍ତୁ crypto_int16_y;
#ଅନ୍ୟଥା
  crypto_int16_x >>= 16-6;
  crypto_int16_x ^= crypto_int16_optblocker;
  crypto_int16_x >>= 5;
  ଫେରନ୍ତୁ crypto_int16_x;
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int16 crypto_int16_negative_01(crypto_int16 crypto_int16_x) {
  ଫେରନ୍ତୁ crypto_int16_unsigned_topbit_01(crypto_int16_x);
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int16 crypto_int16_topbit_mask(crypto_int16 crypto_int16_x) {
  ଫେରନ୍ତୁ crypto_int16_negative_mask(crypto_int16_x);
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int16 crypto_int16_topbit_01(crypto_int16 crypto_int16_x) {
  ଫେରନ୍ତୁ crypto_int16_unsigned_topbit_01(crypto_int16_x);
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int16 crypto_int16_bottombit_mask(crypto_int16 crypto_int16_x) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andw $1,%0" : "+r"(crypto_int16_x) : : "cc");
  ଫେରନ୍ତୁ -crypto_int16_x;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_y;
  __asm__ ("sbfx %w0,%w1,0,1" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) : );
  ଫେରନ୍ତୁ crypto_int16_y;
#ଅନ୍ୟଥା
  crypto_int16_x &= 1 ^ crypto_int16_optblocker;
  ଫେରନ୍ତୁ -crypto_int16_x;
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int16 crypto_int16_bottombit_01(crypto_int16 crypto_int16_x) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andw $1,%0" : "+r"(crypto_int16_x) : : "cc");
  ଫେରନ୍ତୁ crypto_int16_x;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_y;
  __asm__ ("ubfx %w0,%w1,0,1" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) : );
  ଫେରନ୍ତୁ crypto_int16_y;
#ଅନ୍ୟଥା
  crypto_int16_x &= 1 ^ crypto_int16_optblocker;
  ଫେରନ୍ତୁ crypto_int16_x;
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int16 crypto_int16_bitinrangepublicpos_mask(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarw %%cl,%0" : "+r"(crypto_int16_x) : "c"(crypto_int16_s) : "cc");
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("sxth %w0,%w0\n asr %w0,%w0,%w1" : "+&r"(crypto_int16_x) : "r"(crypto_int16_s) : );
#ଅନ୍ୟଥା
  crypto_int16_x >>= crypto_int16_s ^ crypto_int16_optblocker;
#endif
  ଫେରନ୍ତୁ crypto_int16_bottombit_mask(crypto_int16_x);
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int16 crypto_int16_bitinrangepublicpos_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarw %%cl,%0" : "+r"(crypto_int16_x) : "c"(crypto_int16_s) : "cc");
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("sxth %w0,%w0\n asr %w0,%w0,%w1" : "+&r"(crypto_int16_x) : "r"(crypto_int16_s) : );
#ଅନ୍ୟଥା
  crypto_int16_x >>= crypto_int16_s ^ crypto_int16_optblocker;
#endif
  ଫେରନ୍ତୁ crypto_int16_bottombit_01(crypto_int16_x);
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int16 crypto_int16_shlmod(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  crypto_int16_s &= 15;
  __asm__ ("shlw %%cl,%0" : "+r"(crypto_int16_x) : "c"(crypto_int16_s) : "cc");
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("and %w0,%w0,15\n and %w1,%w1,65535\n lsl %w1,%w1,%w0" : "+&r"(crypto_int16_s), "+r"(crypto_int16_x) : : );
#ଅନ୍ୟଥା
  ପୂର୍ଣ୍ଣସଂଖ୍ୟା crypto_int16_k, crypto_int16_l;
  ପାଇଁ (crypto_int16_l = 0,crypto_int16_k = 1;crypto_int16_k < 16;++crypto_int16_l,crypto_int16_k *= 2)
    crypto_int16_x ^= (crypto_int16_x ^ (crypto_int16_x << crypto_int16_k)) & crypto_int16_bitinrangepublicpos_mask(crypto_int16_s,crypto_int16_l);
#endif
  ଫେରନ୍ତୁ crypto_int16_x;
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int16 crypto_int16_shrmod(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  crypto_int16_s &= 15;
  __asm__ ("sarw %%cl,%0" : "+r"(crypto_int16_x) : "c"(crypto_int16_s) : "cc");
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("and %w0,%w0,15\n sxth %w1,%w1\n asr %w1,%w1,%w0" : "+&r"(crypto_int16_s), "+r"(crypto_int16_x) : : );
#ଅନ୍ୟଥା
  ପୂର୍ଣ୍ଣସଂଖ୍ୟା crypto_int16_k, crypto_int16_l;
  ପାଇଁ (crypto_int16_l = 0,crypto_int16_k = 1;crypto_int16_k < 16;++crypto_int16_l,crypto_int16_k *= 2)
    crypto_int16_x ^= (crypto_int16_x ^ (crypto_int16_x >> crypto_int16_k)) & crypto_int16_bitinrangepublicpos_mask(crypto_int16_s,crypto_int16_l);
#endif
  ଫେରନ୍ତୁ crypto_int16_x;
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int16 crypto_int16_bitmod_mask(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
  crypto_int16_x = crypto_int16_shrmod(crypto_int16_x,crypto_int16_s);
  ଫେରନ୍ତୁ crypto_int16_bottombit_mask(crypto_int16_x);
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int16 crypto_int16_bitmod_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
  crypto_int16_x = crypto_int16_shrmod(crypto_int16_x,crypto_int16_s);
  ଫେରନ୍ତୁ crypto_int16_bottombit_01(crypto_int16_x);
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int16 crypto_int16_nonzero_mask(crypto_int16 crypto_int16_x) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n testw %2,%2\n cmovnew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  ଫେରନ୍ତୁ crypto_int16_z;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("tst %w1,65535\n csetm %w0,ne" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  ଫେରନ୍ତୁ crypto_int16_z;
#ଅନ୍ୟଥା
  crypto_int16_x |= -crypto_int16_x;
  ଫେରନ୍ତୁ crypto_int16_negative_mask(crypto_int16_x);
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int16 crypto_int16_nonzero_01(crypto_int16 crypto_int16_x) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n testw %2,%2\n cmovnew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  ଫେରନ୍ତୁ crypto_int16_z;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("tst %w1,65535\n cset %w0,ne" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  ଫେରନ୍ତୁ crypto_int16_z;
#ଅନ୍ୟଥା
  crypto_int16_x |= -crypto_int16_x;
  ଫେରନ୍ତୁ crypto_int16_unsigned_topbit_01(crypto_int16_x);
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int16 crypto_int16_positive_mask(crypto_int16 crypto_int16_x) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n testw %2,%2\n cmovgw %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  ଫେରନ୍ତୁ crypto_int16_z;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,0\n csetm %w0,gt" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  ଫେରନ୍ତୁ crypto_int16_z;
#ଅନ୍ୟଥା
  crypto_int16 crypto_int16_z = -crypto_int16_x;
  crypto_int16_z ^= crypto_int16_x & crypto_int16_z;
  ଫେରନ୍ତୁ crypto_int16_negative_mask(crypto_int16_z);
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int16 crypto_int16_positive_01(crypto_int16 crypto_int16_x) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n testw %2,%2\n cmovgw %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  ଫେରନ୍ତୁ crypto_int16_z;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,0\n cset %w0,gt" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  ଫେରନ୍ତୁ crypto_int16_z;
#ଅନ୍ୟଥା
  crypto_int16 crypto_int16_z = -crypto_int16_x;
  crypto_int16_z ^= crypto_int16_x & crypto_int16_z;
  ଫେରନ୍ତୁ crypto_int16_unsigned_topbit_01(crypto_int16_z);
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int16 crypto_int16_zero_mask(crypto_int16 crypto_int16_x) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n testw %2,%2\n cmovew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  ଫେରନ୍ତୁ crypto_int16_z;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("tst %w1,65535\n csetm %w0,eq" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  ଫେରନ୍ତୁ crypto_int16_z;
#ଅନ୍ୟଥା
  ଫେରନ୍ତୁ ~crypto_int16_nonzero_mask(crypto_int16_x);
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int16 crypto_int16_zero_01(crypto_int16 crypto_int16_x) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n testw %2,%2\n cmovew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  ଫେରନ୍ତୁ crypto_int16_z;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("tst %w1,65535\n cset %w0,eq" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  ଫେରନ୍ତୁ crypto_int16_z;
#ଅନ୍ୟଥା
  ଫେରନ୍ତୁ 1-crypto_int16_nonzero_01(crypto_int16_x);
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int16 crypto_int16_unequal_mask(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n cmpw %3,%2\n cmovnew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ଫେରନ୍ତୁ crypto_int16_z;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("and %w0,%w1,65535\n cmp %w0,%w2,uxth\n csetm %w0,ne" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ଫେରନ୍ତୁ crypto_int16_z;
#ଅନ୍ୟଥା
  ଫେରନ୍ତୁ crypto_int16_nonzero_mask(crypto_int16_x ^ crypto_int16_y);
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int16 crypto_int16_unequal_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n cmpw %3,%2\n cmovnew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ଫେରନ୍ତୁ crypto_int16_z;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("and %w0,%w1,65535\n cmp %w0,%w2,uxth\n cset %w0,ne" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ଫେରନ୍ତୁ crypto_int16_z;
#ଅନ୍ୟଥା
  ଫେରନ୍ତୁ crypto_int16_nonzero_01(crypto_int16_x ^ crypto_int16_y);
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int16 crypto_int16_equal_mask(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n cmpw %3,%2\n cmovew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ଫେରନ୍ତୁ crypto_int16_z;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("and %w0,%w1,65535\n cmp %w0,%w2,uxth\n csetm %w0,eq" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ଫେରନ୍ତୁ crypto_int16_z;
#ଅନ୍ୟଥା
  ଫେରନ୍ତୁ ~crypto_int16_unequal_mask(crypto_int16_x,crypto_int16_y);
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int16 crypto_int16_equal_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n cmpw %3,%2\n cmovew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ଫେରନ୍ତୁ crypto_int16_z;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("and %w0,%w1,65535\n cmp %w0,%w2,uxth\n cset %w0,eq" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ଫେରନ୍ତୁ crypto_int16_z;
#ଅନ୍ୟଥା
  ଫେରନ୍ତୁ 1-crypto_int16_unequal_01(crypto_int16_x,crypto_int16_y);
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int16 crypto_int16_min(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpw %1,%0\n cmovgw %1,%0" : "+r"(crypto_int16_x) : "r"(crypto_int16_y) : "cc");
  ଫେରନ୍ତୁ crypto_int16_x;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("sxth %w0,%w0\n cmp %w0,%w1,sxth\n csel %w0,%w0,%w1,lt" : "+&r"(crypto_int16_x) : "r"(crypto_int16_y) : "cc");
  ଫେରନ୍ତୁ crypto_int16_x;
#ଅନ୍ୟଥା
  crypto_int16 crypto_int16_r = crypto_int16_y ^ crypto_int16_x;
  crypto_int16 crypto_int16_z = crypto_int16_y - crypto_int16_x;
  crypto_int16_z ^= crypto_int16_r & (crypto_int16_z ^ crypto_int16_y);
  crypto_int16_z = crypto_int16_negative_mask(crypto_int16_z);
  crypto_int16_z &= crypto_int16_r;
  ଫେରନ୍ତୁ crypto_int16_x ^ crypto_int16_z;
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int16 crypto_int16_max(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpw %1,%0\n cmovlw %1,%0" : "+r"(crypto_int16_x) : "r"(crypto_int16_y) : "cc");
  ଫେରନ୍ତୁ crypto_int16_x;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("sxth %w0,%w0\n cmp %w0,%w1,sxth\n csel %w0,%w1,%w0,lt" : "+&r"(crypto_int16_x) : "r"(crypto_int16_y) : "cc");
  ଫେରନ୍ତୁ crypto_int16_x;
#ଅନ୍ୟଥା
  crypto_int16 crypto_int16_r = crypto_int16_y ^ crypto_int16_x;
  crypto_int16 crypto_int16_z = crypto_int16_y - crypto_int16_x;
  crypto_int16_z ^= crypto_int16_r & (crypto_int16_z ^ crypto_int16_y);
  crypto_int16_z = crypto_int16_negative_mask(crypto_int16_z);
  crypto_int16_z &= crypto_int16_r;
  ଫେରନ୍ତୁ crypto_int16_y ^ crypto_int16_z;
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
ଶୂନ୍ୟ crypto_int16_minmax(crypto_int16 *crypto_int16_p,crypto_int16 *crypto_int16_q) {
  crypto_int16 crypto_int16_x = *crypto_int16_p;
  crypto_int16 crypto_int16_y = *crypto_int16_q;
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("cmpw %2,%1\n movw %1,%0\n cmovgw %2,%1\n cmovgw %0,%2" : "=&r"(crypto_int16_z), "+&r"(crypto_int16_x), "+r"(crypto_int16_y) : : "cc");
  *crypto_int16_p = crypto_int16_x;
  *crypto_int16_q = crypto_int16_y;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_r, crypto_int16_s;
  __asm__ ("sxth %w0,%w0\n cmp %w0,%w3,sxth\n csel %w1,%w0,%w3,lt\n csel %w2,%w3,%w0,lt" : "+&r"(crypto_int16_x), "=&r"(crypto_int16_r), "=r"(crypto_int16_s) : "r"(crypto_int16_y) : "cc");
  *crypto_int16_p = crypto_int16_r;
  *crypto_int16_q = crypto_int16_s;
#ଅନ୍ୟଥା
  crypto_int16 crypto_int16_r = crypto_int16_y ^ crypto_int16_x;
  crypto_int16 crypto_int16_z = crypto_int16_y - crypto_int16_x;
  crypto_int16_z ^= crypto_int16_r & (crypto_int16_z ^ crypto_int16_y);
  crypto_int16_z = crypto_int16_negative_mask(crypto_int16_z);
  crypto_int16_z &= crypto_int16_r;
  crypto_int16_x ^= crypto_int16_z;
  crypto_int16_y ^= crypto_int16_z;
  *crypto_int16_p = crypto_int16_x;
  *crypto_int16_q = crypto_int16_y;
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int16 crypto_int16_smaller_mask(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n cmpw %3,%2\n cmovlw %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ଫେରନ୍ତୁ crypto_int16_z;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,%w2,sxth\n csetm %w0,lt" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ଫେରନ୍ତୁ crypto_int16_z;
#ଅନ୍ୟଥା
  crypto_int16 crypto_int16_r = crypto_int16_x ^ crypto_int16_y;
  crypto_int16 crypto_int16_z = crypto_int16_x - crypto_int16_y;
  crypto_int16_z ^= crypto_int16_r & (crypto_int16_z ^ crypto_int16_x);
  ଫେରନ୍ତୁ crypto_int16_negative_mask(crypto_int16_z);
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int16 crypto_int16_smaller_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n cmpw %3,%2\n cmovlw %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ଫେରନ୍ତୁ crypto_int16_z;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,%w2,sxth\n cset %w0,lt" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ଫେରନ୍ତୁ crypto_int16_z;
#ଅନ୍ୟଥା
  crypto_int16 crypto_int16_r = crypto_int16_x ^ crypto_int16_y;
  crypto_int16 crypto_int16_z = crypto_int16_x - crypto_int16_y;
  crypto_int16_z ^= crypto_int16_r & (crypto_int16_z ^ crypto_int16_x);
  ଫେରନ୍ତୁ crypto_int16_unsigned_topbit_01(crypto_int16_z);
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int16 crypto_int16_leq_mask(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n cmpw %3,%2\n cmovlew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ଫେରନ୍ତୁ crypto_int16_z;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,%w2,sxth\n csetm %w0,le" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ଫେରନ୍ତୁ crypto_int16_z;
#ଅନ୍ୟଥା
  ଫେରନ୍ତୁ ~crypto_int16_smaller_mask(crypto_int16_y,crypto_int16_x);
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int16 crypto_int16_leq_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n cmpw %3,%2\n cmovlew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ଫେରନ୍ତୁ crypto_int16_z;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,%w2,sxth\n cset %w0,le" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ଫେରନ୍ତୁ crypto_int16_z;
#ଅନ୍ୟଥା
  ଫେରନ୍ତୁ 1-crypto_int16_smaller_01(crypto_int16_y,crypto_int16_x);
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
ପୂର୍ଣ୍ଣସଂଖ୍ୟା crypto_int16_ones_ଅଙ୍କ(crypto_int16 crypto_int16_x) {
  crypto_int16_unsigned crypto_int16_y = crypto_int16_x;
  ଅଚଳ crypto_int16 C0 = 0x5555;
  ଅଚଳ crypto_int16 C1 = 0x3333;
  ଅଚଳ crypto_int16 C2 = 0x0f0f;
  crypto_int16_y -= ((crypto_int16_y >> 1) & C0);
  crypto_int16_y = (crypto_int16_y & C1) + ((crypto_int16_y >> 2) & C1);
  crypto_int16_y = (crypto_int16_y + (crypto_int16_y >> 4)) & C2;
  crypto_int16_y = (crypto_int16_y + (crypto_int16_y >> 8)) & 0xff;
  ଫେରନ୍ତୁ crypto_int16_y;
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
ପୂର୍ଣ୍ଣସଂଖ୍ୟା crypto_int16_bottomzeros_ଅଙ୍କ(crypto_int16 crypto_int16_x) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 fallback = 16;
  __asm__ ("bsfw %0,%0\n cmovew %1,%0" : "+&r"(crypto_int16_x) : "r"(fallback) : "cc");
  ଫେରନ୍ତୁ crypto_int16_x;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  int64_t crypto_int16_y;
  __asm__ ("orr %w0,%w1,-65536\n rbit %w0,%w0\n clz %w0,%w0" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) : );
  ଫେରନ୍ତୁ crypto_int16_y;
#ଅନ୍ୟଥା
  crypto_int16 crypto_int16_y = crypto_int16_x ^ (crypto_int16_x-1);
  crypto_int16_y = ((crypto_int16) crypto_int16_y) >> 1;
  crypto_int16_y &= ~(crypto_int16_x & (((crypto_int16) 1) << (16-1)));
  ଫେରନ୍ତୁ crypto_int16_ones_ଅଙ୍କ(crypto_int16_y);
#endif
}

#endif

/* from supercop-20240808/cryptoint/crypto_int32.h */
/* auto-generated: cd cryptoint; ./autogen */
/* cryptoint 20240806 */

#ifndef crypto_int32_h
#define crypto_int32_h

#define crypto_int32 int32_t
#define crypto_int32_unsigned uint32_t



__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int32 crypto_int32_load(ଅଚଳ unsigned ଅକ୍ଷର *crypto_int32_s) {
  crypto_int32 crypto_int32_z = 0;
  crypto_int32_z |= ((crypto_int32) (*crypto_int32_s++)) << 0;
  crypto_int32_z |= ((crypto_int32) (*crypto_int32_s++)) << 8;
  crypto_int32_z |= ((crypto_int32) (*crypto_int32_s++)) << 16;
  crypto_int32_z |= ((crypto_int32) (*crypto_int32_s++)) << 24;
  ଫେରନ୍ତୁ crypto_int32_z;
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
ଶୂନ୍ୟ crypto_int32_store(unsigned ଅକ୍ଷର *crypto_int32_s,crypto_int32 crypto_int32_x) {
  *crypto_int32_s++ = crypto_int32_x >> 0;
  *crypto_int32_s++ = crypto_int32_x >> 8;
  *crypto_int32_s++ = crypto_int32_x >> 16;
  *crypto_int32_s++ = crypto_int32_x >> 24;
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int32 crypto_int32_negative_mask(crypto_int32 crypto_int32_x) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarl $31,%0" : "+r"(crypto_int32_x) : : "cc");
  ଫେରନ୍ତୁ crypto_int32_x;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_y;
  __asm__ ("asr %w0,%w1,31" : "=r"(crypto_int32_y) : "r"(crypto_int32_x) : );
  ଫେରନ୍ତୁ crypto_int32_y;
#ଅନ୍ୟଥା
  crypto_int32_x >>= 32-6;
  crypto_int32_x ^= crypto_int32_optblocker;
  crypto_int32_x >>= 5;
  ଫେରନ୍ତୁ crypto_int32_x;
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int32_unsigned crypto_int32_unsigned_topbit_01(crypto_int32_unsigned crypto_int32_x) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("shrl $31,%0" : "+r"(crypto_int32_x) : : "cc");
  ଫେରନ୍ତୁ crypto_int32_x;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_y;
  __asm__ ("lsr %w0,%w1,31" : "=r"(crypto_int32_y) : "r"(crypto_int32_x) : );
  ଫେରନ୍ତୁ crypto_int32_y;
#ଅନ୍ୟଥା
  crypto_int32_x >>= 32-6;
  crypto_int32_x ^= crypto_int32_optblocker;
  crypto_int32_x >>= 5;
  ଫେରନ୍ତୁ crypto_int32_x;
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int32 crypto_int32_negative_01(crypto_int32 crypto_int32_x) {
  ଫେରନ୍ତୁ crypto_int32_unsigned_topbit_01(crypto_int32_x);
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int32 crypto_int32_topbit_mask(crypto_int32 crypto_int32_x) {
  ଫେରନ୍ତୁ crypto_int32_negative_mask(crypto_int32_x);
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int32 crypto_int32_topbit_01(crypto_int32 crypto_int32_x) {
  ଫେରନ୍ତୁ crypto_int32_unsigned_topbit_01(crypto_int32_x);
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int32 crypto_int32_bottombit_mask(crypto_int32 crypto_int32_x) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andl $1,%0" : "+r"(crypto_int32_x) : : "cc");
  ଫେରନ୍ତୁ -crypto_int32_x;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_y;
  __asm__ ("sbfx %w0,%w1,0,1" : "=r"(crypto_int32_y) : "r"(crypto_int32_x) : );
  ଫେରନ୍ତୁ crypto_int32_y;
#ଅନ୍ୟଥା
  crypto_int32_x &= 1 ^ crypto_int32_optblocker;
  ଫେରନ୍ତୁ -crypto_int32_x;
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int32 crypto_int32_bottombit_01(crypto_int32 crypto_int32_x) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andl $1,%0" : "+r"(crypto_int32_x) : : "cc");
  ଫେରନ୍ତୁ crypto_int32_x;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_y;
  __asm__ ("ubfx %w0,%w1,0,1" : "=r"(crypto_int32_y) : "r"(crypto_int32_x) : );
  ଫେରନ୍ତୁ crypto_int32_y;
#ଅନ୍ୟଥା
  crypto_int32_x &= 1 ^ crypto_int32_optblocker;
  ଫେରନ୍ତୁ crypto_int32_x;
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int32 crypto_int32_bitinrangepublicpos_mask(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarl %%cl,%0" : "+r"(crypto_int32_x) : "c"(crypto_int32_s) : "cc");
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %w0,%w0,%w1" : "+r"(crypto_int32_x) : "r"(crypto_int32_s) : );
#ଅନ୍ୟଥା
  crypto_int32_x >>= crypto_int32_s ^ crypto_int32_optblocker;
#endif
  ଫେରନ୍ତୁ crypto_int32_bottombit_mask(crypto_int32_x);
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int32 crypto_int32_bitinrangepublicpos_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarl %%cl,%0" : "+r"(crypto_int32_x) : "c"(crypto_int32_s) : "cc");
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %w0,%w0,%w1" : "+r"(crypto_int32_x) : "r"(crypto_int32_s) : );
#ଅନ୍ୟଥା
  crypto_int32_x >>= crypto_int32_s ^ crypto_int32_optblocker;
#endif
  ଫେରନ୍ତୁ crypto_int32_bottombit_01(crypto_int32_x);
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int32 crypto_int32_shlmod(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("shll %%cl,%0" : "+r"(crypto_int32_x) : "c"(crypto_int32_s) : "cc");
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("lsl %w0,%w0,%w1" : "+r"(crypto_int32_x) : "r"(crypto_int32_s) : );
#ଅନ୍ୟଥା
  ପୂର୍ଣ୍ଣସଂଖ୍ୟା crypto_int32_k, crypto_int32_l;
  ପାଇଁ (crypto_int32_l = 0,crypto_int32_k = 1;crypto_int32_k < 32;++crypto_int32_l,crypto_int32_k *= 2)
    crypto_int32_x ^= (crypto_int32_x ^ (crypto_int32_x << crypto_int32_k)) & crypto_int32_bitinrangepublicpos_mask(crypto_int32_s,crypto_int32_l);
#endif
  ଫେରନ୍ତୁ crypto_int32_x;
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int32 crypto_int32_shrmod(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarl %%cl,%0" : "+r"(crypto_int32_x) : "c"(crypto_int32_s) : "cc");
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %w0,%w0,%w1" : "+r"(crypto_int32_x) : "r"(crypto_int32_s) : );
#ଅନ୍ୟଥା
  ପୂର୍ଣ୍ଣସଂଖ୍ୟା crypto_int32_k, crypto_int32_l;
  ପାଇଁ (crypto_int32_l = 0,crypto_int32_k = 1;crypto_int32_k < 32;++crypto_int32_l,crypto_int32_k *= 2)
    crypto_int32_x ^= (crypto_int32_x ^ (crypto_int32_x >> crypto_int32_k)) & crypto_int32_bitinrangepublicpos_mask(crypto_int32_s,crypto_int32_l);
#endif
  ଫେରନ୍ତୁ crypto_int32_x;
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int32 crypto_int32_bitmod_mask(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
  crypto_int32_x = crypto_int32_shrmod(crypto_int32_x,crypto_int32_s);
  ଫେରନ୍ତୁ crypto_int32_bottombit_mask(crypto_int32_x);
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int32 crypto_int32_bitmod_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
  crypto_int32_x = crypto_int32_shrmod(crypto_int32_x,crypto_int32_s);
  ଫେରନ୍ତୁ crypto_int32_bottombit_01(crypto_int32_x);
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int32 crypto_int32_nonzero_mask(crypto_int32 crypto_int32_x) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n testl %2,%2\n cmovnel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  ଫେରନ୍ତୁ crypto_int32_z;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n csetm %w0,ne" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  ଫେରନ୍ତୁ crypto_int32_z;
#ଅନ୍ୟଥା
  crypto_int32_x |= -crypto_int32_x;
  ଫେରନ୍ତୁ crypto_int32_negative_mask(crypto_int32_x);
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int32 crypto_int32_nonzero_01(crypto_int32 crypto_int32_x) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n testl %2,%2\n cmovnel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  ଫେରନ୍ତୁ crypto_int32_z;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n cset %w0,ne" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  ଫେରନ୍ତୁ crypto_int32_z;
#ଅନ୍ୟଥା
  crypto_int32_x |= -crypto_int32_x;
  ଫେରନ୍ତୁ crypto_int32_unsigned_topbit_01(crypto_int32_x);
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int32 crypto_int32_positive_mask(crypto_int32 crypto_int32_x) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n testl %2,%2\n cmovgl %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  ଫେରନ୍ତୁ crypto_int32_z;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n csetm %w0,gt" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  ଫେରନ୍ତୁ crypto_int32_z;
#ଅନ୍ୟଥା
  crypto_int32 crypto_int32_z = -crypto_int32_x;
  crypto_int32_z ^= crypto_int32_x & crypto_int32_z;
  ଫେରନ୍ତୁ crypto_int32_negative_mask(crypto_int32_z);
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int32 crypto_int32_positive_01(crypto_int32 crypto_int32_x) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n testl %2,%2\n cmovgl %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  ଫେରନ୍ତୁ crypto_int32_z;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n cset %w0,gt" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  ଫେରନ୍ତୁ crypto_int32_z;
#ଅନ୍ୟଥା
  crypto_int32 crypto_int32_z = -crypto_int32_x;
  crypto_int32_z ^= crypto_int32_x & crypto_int32_z;
  ଫେରନ୍ତୁ crypto_int32_unsigned_topbit_01(crypto_int32_z);
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int32 crypto_int32_zero_mask(crypto_int32 crypto_int32_x) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n testl %2,%2\n cmovel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  ଫେରନ୍ତୁ crypto_int32_z;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n csetm %w0,eq" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  ଫେରନ୍ତୁ crypto_int32_z;
#ଅନ୍ୟଥା
  ଫେରନ୍ତୁ ~crypto_int32_nonzero_mask(crypto_int32_x);
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int32 crypto_int32_zero_01(crypto_int32 crypto_int32_x) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n testl %2,%2\n cmovel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  ଫେରନ୍ତୁ crypto_int32_z;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n cset %w0,eq" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  ଫେରନ୍ତୁ crypto_int32_z;
#ଅନ୍ୟଥା
  ଫେରନ୍ତୁ 1-crypto_int32_nonzero_01(crypto_int32_x);
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int32 crypto_int32_unequal_mask(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n cmpl %3,%2\n cmovnel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ଫେରନ୍ତୁ crypto_int32_z;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n csetm %w0,ne" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ଫେରନ୍ତୁ crypto_int32_z;
#ଅନ୍ୟଥା
  ଫେରନ୍ତୁ crypto_int32_nonzero_mask(crypto_int32_x ^ crypto_int32_y);
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int32 crypto_int32_unequal_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n cmpl %3,%2\n cmovnel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ଫେରନ୍ତୁ crypto_int32_z;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n cset %w0,ne" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ଫେରନ୍ତୁ crypto_int32_z;
#ଅନ୍ୟଥା
  ଫେରନ୍ତୁ crypto_int32_nonzero_01(crypto_int32_x ^ crypto_int32_y);
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int32 crypto_int32_equal_mask(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n cmpl %3,%2\n cmovel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ଫେରନ୍ତୁ crypto_int32_z;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n csetm %w0,eq" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ଫେରନ୍ତୁ crypto_int32_z;
#ଅନ୍ୟଥା
  ଫେରନ୍ତୁ ~crypto_int32_unequal_mask(crypto_int32_x,crypto_int32_y);
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int32 crypto_int32_equal_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n cmpl %3,%2\n cmovel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ଫେରନ୍ତୁ crypto_int32_z;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n cset %w0,eq" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ଫେରନ୍ତୁ crypto_int32_z;
#ଅନ୍ୟଥା
  ଫେରନ୍ତୁ 1-crypto_int32_unequal_01(crypto_int32_x,crypto_int32_y);
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int32 crypto_int32_min(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpl %1,%0\n cmovgl %1,%0" : "+r"(crypto_int32_x) : "r"(crypto_int32_y) : "cc");
  ଫେରନ୍ତୁ crypto_int32_x;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("cmp %w0,%w1\n csel %w0,%w0,%w1,lt" : "+r"(crypto_int32_x) : "r"(crypto_int32_y) : "cc");
  ଫେରନ୍ତୁ crypto_int32_x;
#ଅନ୍ୟଥା
  crypto_int64 crypto_int32_r = (crypto_int64)crypto_int32_y ^ (crypto_int64)crypto_int32_x;
  crypto_int64 crypto_int32_z = (crypto_int64)crypto_int32_y - (crypto_int64)crypto_int32_x;
  crypto_int32_z ^= crypto_int32_r & (crypto_int32_z ^ crypto_int32_y);
  crypto_int32_z = crypto_int32_negative_mask(crypto_int32_z);
  crypto_int32_z &= crypto_int32_r;
  ଫେରନ୍ତୁ crypto_int32_x ^ crypto_int32_z;
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int32 crypto_int32_max(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpl %1,%0\n cmovll %1,%0" : "+r"(crypto_int32_x) : "r"(crypto_int32_y) : "cc");
  ଫେରନ୍ତୁ crypto_int32_x;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("cmp %w0,%w1\n csel %w0,%w1,%w0,lt" : "+r"(crypto_int32_x) : "r"(crypto_int32_y) : "cc");
  ଫେରନ୍ତୁ crypto_int32_x;
#ଅନ୍ୟଥା
  crypto_int64 crypto_int32_r = (crypto_int64)crypto_int32_y ^ (crypto_int64)crypto_int32_x;
  crypto_int64 crypto_int32_z = (crypto_int64)crypto_int32_y - (crypto_int64)crypto_int32_x;
  crypto_int32_z ^= crypto_int32_r & (crypto_int32_z ^ crypto_int32_y);
  crypto_int32_z = crypto_int32_negative_mask(crypto_int32_z);
  crypto_int32_z &= crypto_int32_r;
  ଫେରନ୍ତୁ crypto_int32_y ^ crypto_int32_z;
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
ଶୂନ୍ୟ crypto_int32_minmax(crypto_int32 *crypto_int32_p,crypto_int32 *crypto_int32_q) {
  crypto_int32 crypto_int32_x = *crypto_int32_p;
  crypto_int32 crypto_int32_y = *crypto_int32_q;
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmpl %2,%1\n movl %1,%0\n cmovgl %2,%1\n cmovgl %0,%2" : "=&r"(crypto_int32_z), "+&r"(crypto_int32_x), "+r"(crypto_int32_y) : : "cc");
  *crypto_int32_p = crypto_int32_x;
  *crypto_int32_q = crypto_int32_y;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_r, crypto_int32_s;
  __asm__ ("cmp %w2,%w3\n csel %w0,%w2,%w3,lt\n csel %w1,%w3,%w2,lt" : "=&r"(crypto_int32_r), "=r"(crypto_int32_s) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  *crypto_int32_p = crypto_int32_r;
  *crypto_int32_q = crypto_int32_s;
#ଅନ୍ୟଥା
  crypto_int64 crypto_int32_r = (crypto_int64)crypto_int32_y ^ (crypto_int64)crypto_int32_x;
  crypto_int64 crypto_int32_z = (crypto_int64)crypto_int32_y - (crypto_int64)crypto_int32_x;
  crypto_int32_z ^= crypto_int32_r & (crypto_int32_z ^ crypto_int32_y);
  crypto_int32_z = crypto_int32_negative_mask(crypto_int32_z);
  crypto_int32_z &= crypto_int32_r;
  crypto_int32_x ^= crypto_int32_z;
  crypto_int32_y ^= crypto_int32_z;
  *crypto_int32_p = crypto_int32_x;
  *crypto_int32_q = crypto_int32_y;
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int32 crypto_int32_smaller_mask(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n cmpl %3,%2\n cmovll %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ଫେରନ୍ତୁ crypto_int32_z;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n csetm %w0,lt" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ଫେରନ୍ତୁ crypto_int32_z;
#ଅନ୍ୟଥା
  crypto_int32 crypto_int32_r = crypto_int32_x ^ crypto_int32_y;
  crypto_int32 crypto_int32_z = crypto_int32_x - crypto_int32_y;
  crypto_int32_z ^= crypto_int32_r & (crypto_int32_z ^ crypto_int32_x);
  ଫେରନ୍ତୁ crypto_int32_negative_mask(crypto_int32_z);
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int32 crypto_int32_smaller_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n cmpl %3,%2\n cmovll %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ଫେରନ୍ତୁ crypto_int32_z;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n cset %w0,lt" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ଫେରନ୍ତୁ crypto_int32_z;
#ଅନ୍ୟଥା
  crypto_int32 crypto_int32_r = crypto_int32_x ^ crypto_int32_y;
  crypto_int32 crypto_int32_z = crypto_int32_x - crypto_int32_y;
  crypto_int32_z ^= crypto_int32_r & (crypto_int32_z ^ crypto_int32_x);
  ଫେରନ୍ତୁ crypto_int32_unsigned_topbit_01(crypto_int32_z);
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int32 crypto_int32_leq_mask(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n cmpl %3,%2\n cmovlel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ଫେରନ୍ତୁ crypto_int32_z;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n csetm %w0,le" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ଫେରନ୍ତୁ crypto_int32_z;
#ଅନ୍ୟଥା
  ଫେରନ୍ତୁ ~crypto_int32_smaller_mask(crypto_int32_y,crypto_int32_x);
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int32 crypto_int32_leq_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n cmpl %3,%2\n cmovlel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ଫେରନ୍ତୁ crypto_int32_z;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n cset %w0,le" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ଫେରନ୍ତୁ crypto_int32_z;
#ଅନ୍ୟଥା
  ଫେରନ୍ତୁ 1-crypto_int32_smaller_01(crypto_int32_y,crypto_int32_x);
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
ପୂର୍ଣ୍ଣସଂଖ୍ୟା crypto_int32_ones_ଅଙ୍କ(crypto_int32 crypto_int32_x) {
  crypto_int32_unsigned crypto_int32_y = crypto_int32_x;
  ଅଚଳ crypto_int32 C0 = 0x55555555;
  ଅଚଳ crypto_int32 C1 = 0x33333333;
  ଅଚଳ crypto_int32 C2 = 0x0f0f0f0f;
  crypto_int32_y -= ((crypto_int32_y >> 1) & C0);
  crypto_int32_y = (crypto_int32_y & C1) + ((crypto_int32_y >> 2) & C1);
  crypto_int32_y = (crypto_int32_y + (crypto_int32_y >> 4)) & C2;
  crypto_int32_y += crypto_int32_y >> 8;
  crypto_int32_y = (crypto_int32_y + (crypto_int32_y >> 16)) & 0xff;
  ଫେରନ୍ତୁ crypto_int32_y;
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
ପୂର୍ଣ୍ଣସଂଖ୍ୟା crypto_int32_bottomzeros_ଅଙ୍କ(crypto_int32 crypto_int32_x) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 fallback = 32;
  __asm__ ("bsfl %0,%0\n cmovel %1,%0" : "+&r"(crypto_int32_x) : "r"(fallback) : "cc");
  ଫେରନ୍ତୁ crypto_int32_x;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  int64_t crypto_int32_y;
  __asm__ ("rbit %w0,%w1\n clz %w0,%w0" : "=r"(crypto_int32_y) : "r"(crypto_int32_x) : );
  ଫେରନ୍ତୁ crypto_int32_y;
#ଅନ୍ୟଥା
  crypto_int32 crypto_int32_y = crypto_int32_x ^ (crypto_int32_x-1);
  crypto_int32_y = ((crypto_int32) crypto_int32_y) >> 1;
  crypto_int32_y &= ~(crypto_int32_x & (((crypto_int32) 1) << (32-1)));
  ଫେରନ୍ତୁ crypto_int32_ones_ଅଙ୍କ(crypto_int32_y);
#endif
}

#endif

/* from supercop-20240808/cryptoint/crypto_int64.h */
/* auto-generated: cd cryptoint; ./autogen */
/* cryptoint 20240806 */

#ifndef crypto_int64_h
#define crypto_int64_h

#define crypto_int64 int64_t
#define crypto_int64_unsigned uint64_t



__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int64 crypto_int64_load(ଅଚଳ unsigned ଅକ୍ଷର *crypto_int64_s) {
  crypto_int64 crypto_int64_z = 0;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 0;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 8;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 16;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 24;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 32;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 40;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 48;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 56;
  ଫେରନ୍ତୁ crypto_int64_z;
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
ଶୂନ୍ୟ crypto_int64_store(unsigned ଅକ୍ଷର *crypto_int64_s,crypto_int64 crypto_int64_x) {
  *crypto_int64_s++ = crypto_int64_x >> 0;
  *crypto_int64_s++ = crypto_int64_x >> 8;
  *crypto_int64_s++ = crypto_int64_x >> 16;
  *crypto_int64_s++ = crypto_int64_x >> 24;
  *crypto_int64_s++ = crypto_int64_x >> 32;
  *crypto_int64_s++ = crypto_int64_x >> 40;
  *crypto_int64_s++ = crypto_int64_x >> 48;
  *crypto_int64_s++ = crypto_int64_x >> 56;
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int64 crypto_int64_negative_mask(crypto_int64 crypto_int64_x) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarq $63,%0" : "+r"(crypto_int64_x) : : "cc");
  ଫେରନ୍ତୁ crypto_int64_x;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_y;
  __asm__ ("asr %0,%1,63" : "=r"(crypto_int64_y) : "r"(crypto_int64_x) : );
  ଫେରନ୍ତୁ crypto_int64_y;
#ଅନ୍ୟଥା
  crypto_int64_x >>= 64-6;
  crypto_int64_x ^= crypto_int64_optblocker;
  crypto_int64_x >>= 5;
  ଫେରନ୍ତୁ crypto_int64_x;
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int64_unsigned crypto_int64_unsigned_topbit_01(crypto_int64_unsigned crypto_int64_x) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("shrq $63,%0" : "+r"(crypto_int64_x) : : "cc");
  ଫେରନ୍ତୁ crypto_int64_x;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_y;
  __asm__ ("lsr %0,%1,63" : "=r"(crypto_int64_y) : "r"(crypto_int64_x) : );
  ଫେରନ୍ତୁ crypto_int64_y;
#ଅନ୍ୟଥା
  crypto_int64_x >>= 64-6;
  crypto_int64_x ^= crypto_int64_optblocker;
  crypto_int64_x >>= 5;
  ଫେରନ୍ତୁ crypto_int64_x;
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int64 crypto_int64_negative_01(crypto_int64 crypto_int64_x) {
  ଫେରନ୍ତୁ crypto_int64_unsigned_topbit_01(crypto_int64_x);
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int64 crypto_int64_topbit_mask(crypto_int64 crypto_int64_x) {
  ଫେରନ୍ତୁ crypto_int64_negative_mask(crypto_int64_x);
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int64 crypto_int64_topbit_01(crypto_int64 crypto_int64_x) {
  ଫେରନ୍ତୁ crypto_int64_unsigned_topbit_01(crypto_int64_x);
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int64 crypto_int64_bottombit_mask(crypto_int64 crypto_int64_x) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andq $1,%0" : "+r"(crypto_int64_x) : : "cc");
  ଫେରନ୍ତୁ -crypto_int64_x;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_y;
  __asm__ ("sbfx %0,%1,0,1" : "=r"(crypto_int64_y) : "r"(crypto_int64_x) : );
  ଫେରନ୍ତୁ crypto_int64_y;
#ଅନ୍ୟଥା
  crypto_int64_x &= 1 ^ crypto_int64_optblocker;
  ଫେରନ୍ତୁ -crypto_int64_x;
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int64 crypto_int64_bottombit_01(crypto_int64 crypto_int64_x) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andq $1,%0" : "+r"(crypto_int64_x) : : "cc");
  ଫେରନ୍ତୁ crypto_int64_x;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_y;
  __asm__ ("ubfx %0,%1,0,1" : "=r"(crypto_int64_y) : "r"(crypto_int64_x) : );
  ଫେରନ୍ତୁ crypto_int64_y;
#ଅନ୍ୟଥା
  crypto_int64_x &= 1 ^ crypto_int64_optblocker;
  ଫେରନ୍ତୁ crypto_int64_x;
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int64 crypto_int64_bitinrangepublicpos_mask(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarq %%cl,%0" : "+r"(crypto_int64_x) : "c"(crypto_int64_s) : "cc");
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %0,%0,%1" : "+r"(crypto_int64_x) : "r"(crypto_int64_s) : );
#ଅନ୍ୟଥା
  crypto_int64_x >>= crypto_int64_s ^ crypto_int64_optblocker;
#endif
  ଫେରନ୍ତୁ crypto_int64_bottombit_mask(crypto_int64_x);
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int64 crypto_int64_bitinrangepublicpos_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarq %%cl,%0" : "+r"(crypto_int64_x) : "c"(crypto_int64_s) : "cc");
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %0,%0,%1" : "+r"(crypto_int64_x) : "r"(crypto_int64_s) : );
#ଅନ୍ୟଥା
  crypto_int64_x >>= crypto_int64_s ^ crypto_int64_optblocker;
#endif
  ଫେରନ୍ତୁ crypto_int64_bottombit_01(crypto_int64_x);
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int64 crypto_int64_shlmod(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("shlq %%cl,%0" : "+r"(crypto_int64_x) : "c"(crypto_int64_s) : "cc");
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("lsl %0,%0,%1" : "+r"(crypto_int64_x) : "r"(crypto_int64_s) : );
#ଅନ୍ୟଥା
  ପୂର୍ଣ୍ଣସଂଖ୍ୟା crypto_int64_k, crypto_int64_l;
  ପାଇଁ (crypto_int64_l = 0,crypto_int64_k = 1;crypto_int64_k < 64;++crypto_int64_l,crypto_int64_k *= 2)
    crypto_int64_x ^= (crypto_int64_x ^ (crypto_int64_x << crypto_int64_k)) & crypto_int64_bitinrangepublicpos_mask(crypto_int64_s,crypto_int64_l);
#endif
  ଫେରନ୍ତୁ crypto_int64_x;
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int64 crypto_int64_shrmod(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarq %%cl,%0" : "+r"(crypto_int64_x) : "c"(crypto_int64_s) : "cc");
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %0,%0,%1" : "+r"(crypto_int64_x) : "r"(crypto_int64_s) : );
#ଅନ୍ୟଥା
  ପୂର୍ଣ୍ଣସଂଖ୍ୟା crypto_int64_k, crypto_int64_l;
  ପାଇଁ (crypto_int64_l = 0,crypto_int64_k = 1;crypto_int64_k < 64;++crypto_int64_l,crypto_int64_k *= 2)
    crypto_int64_x ^= (crypto_int64_x ^ (crypto_int64_x >> crypto_int64_k)) & crypto_int64_bitinrangepublicpos_mask(crypto_int64_s,crypto_int64_l);
#endif
  ଫେରନ୍ତୁ crypto_int64_x;
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int64 crypto_int64_bitmod_mask(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
  crypto_int64_x = crypto_int64_shrmod(crypto_int64_x,crypto_int64_s);
  ଫେରନ୍ତୁ crypto_int64_bottombit_mask(crypto_int64_x);
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int64 crypto_int64_bitmod_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
  crypto_int64_x = crypto_int64_shrmod(crypto_int64_x,crypto_int64_s);
  ଫେରନ୍ତୁ crypto_int64_bottombit_01(crypto_int64_x);
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int64 crypto_int64_nonzero_mask(crypto_int64 crypto_int64_x) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n testq %2,%2\n cmovneq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  ଫେରନ୍ତୁ crypto_int64_z;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n csetm %0,ne" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  ଫେରନ୍ତୁ crypto_int64_z;
#ଅନ୍ୟଥା
  crypto_int64_x |= -crypto_int64_x;
  ଫେରନ୍ତୁ crypto_int64_negative_mask(crypto_int64_x);
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int64 crypto_int64_nonzero_01(crypto_int64 crypto_int64_x) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n testq %2,%2\n cmovneq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  ଫେରନ୍ତୁ crypto_int64_z;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n cset %0,ne" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  ଫେରନ୍ତୁ crypto_int64_z;
#ଅନ୍ୟଥା
  crypto_int64_x |= -crypto_int64_x;
  ଫେରନ୍ତୁ crypto_int64_unsigned_topbit_01(crypto_int64_x);
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int64 crypto_int64_positive_mask(crypto_int64 crypto_int64_x) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n testq %2,%2\n cmovgq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  ଫେରନ୍ତୁ crypto_int64_z;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n csetm %0,gt" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  ଫେରନ୍ତୁ crypto_int64_z;
#ଅନ୍ୟଥା
  crypto_int64 crypto_int64_z = -crypto_int64_x;
  crypto_int64_z ^= crypto_int64_x & crypto_int64_z;
  ଫେରନ୍ତୁ crypto_int64_negative_mask(crypto_int64_z);
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int64 crypto_int64_positive_01(crypto_int64 crypto_int64_x) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n testq %2,%2\n cmovgq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  ଫେରନ୍ତୁ crypto_int64_z;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n cset %0,gt" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  ଫେରନ୍ତୁ crypto_int64_z;
#ଅନ୍ୟଥା
  crypto_int64 crypto_int64_z = -crypto_int64_x;
  crypto_int64_z ^= crypto_int64_x & crypto_int64_z;
  ଫେରନ୍ତୁ crypto_int64_unsigned_topbit_01(crypto_int64_z);
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int64 crypto_int64_zero_mask(crypto_int64 crypto_int64_x) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n testq %2,%2\n cmoveq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  ଫେରନ୍ତୁ crypto_int64_z;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n csetm %0,eq" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  ଫେରନ୍ତୁ crypto_int64_z;
#ଅନ୍ୟଥା
  ଫେରନ୍ତୁ ~crypto_int64_nonzero_mask(crypto_int64_x);
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int64 crypto_int64_zero_01(crypto_int64 crypto_int64_x) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n testq %2,%2\n cmoveq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  ଫେରନ୍ତୁ crypto_int64_z;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n cset %0,eq" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  ଫେରନ୍ତୁ crypto_int64_z;
#ଅନ୍ୟଥା
  ଫେରନ୍ତୁ 1-crypto_int64_nonzero_01(crypto_int64_x);
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int64 crypto_int64_unequal_mask(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n cmpq %3,%2\n cmovneq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ଫେରନ୍ତୁ crypto_int64_z;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n csetm %0,ne" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ଫେରନ୍ତୁ crypto_int64_z;
#ଅନ୍ୟଥା
  ଫେରନ୍ତୁ crypto_int64_nonzero_mask(crypto_int64_x ^ crypto_int64_y);
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int64 crypto_int64_unequal_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n cmpq %3,%2\n cmovneq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ଫେରନ୍ତୁ crypto_int64_z;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n cset %0,ne" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ଫେରନ୍ତୁ crypto_int64_z;
#ଅନ୍ୟଥା
  ଫେରନ୍ତୁ crypto_int64_nonzero_01(crypto_int64_x ^ crypto_int64_y);
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int64 crypto_int64_equal_mask(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n cmpq %3,%2\n cmoveq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ଫେରନ୍ତୁ crypto_int64_z;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n csetm %0,eq" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ଫେରନ୍ତୁ crypto_int64_z;
#ଅନ୍ୟଥା
  ଫେରନ୍ତୁ ~crypto_int64_unequal_mask(crypto_int64_x,crypto_int64_y);
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int64 crypto_int64_equal_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n cmpq %3,%2\n cmoveq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ଫେରନ୍ତୁ crypto_int64_z;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n cset %0,eq" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ଫେରନ୍ତୁ crypto_int64_z;
#ଅନ୍ୟଥା
  ଫେରନ୍ତୁ 1-crypto_int64_unequal_01(crypto_int64_x,crypto_int64_y);
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int64 crypto_int64_min(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpq %1,%0\n cmovgq %1,%0" : "+r"(crypto_int64_x) : "r"(crypto_int64_y) : "cc");
  ଫେରନ୍ତୁ crypto_int64_x;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("cmp %0,%1\n csel %0,%0,%1,lt" : "+r"(crypto_int64_x) : "r"(crypto_int64_y) : "cc");
  ଫେରନ୍ତୁ crypto_int64_x;
#ଅନ୍ୟଥା
  crypto_int64 crypto_int64_r = crypto_int64_y ^ crypto_int64_x;
  crypto_int64 crypto_int64_z = crypto_int64_y - crypto_int64_x;
  crypto_int64_z ^= crypto_int64_r & (crypto_int64_z ^ crypto_int64_y);
  crypto_int64_z = crypto_int64_negative_mask(crypto_int64_z);
  crypto_int64_z &= crypto_int64_r;
  ଫେରନ୍ତୁ crypto_int64_x ^ crypto_int64_z;
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int64 crypto_int64_max(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpq %1,%0\n cmovlq %1,%0" : "+r"(crypto_int64_x) : "r"(crypto_int64_y) : "cc");
  ଫେରନ୍ତୁ crypto_int64_x;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("cmp %0,%1\n csel %0,%1,%0,lt" : "+r"(crypto_int64_x) : "r"(crypto_int64_y) : "cc");
  ଫେରନ୍ତୁ crypto_int64_x;
#ଅନ୍ୟଥା
  crypto_int64 crypto_int64_r = crypto_int64_y ^ crypto_int64_x;
  crypto_int64 crypto_int64_z = crypto_int64_y - crypto_int64_x;
  crypto_int64_z ^= crypto_int64_r & (crypto_int64_z ^ crypto_int64_y);
  crypto_int64_z = crypto_int64_negative_mask(crypto_int64_z);
  crypto_int64_z &= crypto_int64_r;
  ଫେରନ୍ତୁ crypto_int64_y ^ crypto_int64_z;
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
ଶୂନ୍ୟ crypto_int64_minmax(crypto_int64 *crypto_int64_p,crypto_int64 *crypto_int64_q) {
  crypto_int64 crypto_int64_x = *crypto_int64_p;
  crypto_int64 crypto_int64_y = *crypto_int64_q;
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmpq %2,%1\n movq %1,%0\n cmovgq %2,%1\n cmovgq %0,%2" : "=&r"(crypto_int64_z), "+&r"(crypto_int64_x), "+r"(crypto_int64_y) : : "cc");
  *crypto_int64_p = crypto_int64_x;
  *crypto_int64_q = crypto_int64_y;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_r, crypto_int64_s;
  __asm__ ("cmp %2,%3\n csel %0,%2,%3,lt\n csel %1,%3,%2,lt" : "=&r"(crypto_int64_r), "=r"(crypto_int64_s) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  *crypto_int64_p = crypto_int64_r;
  *crypto_int64_q = crypto_int64_s;
#ଅନ୍ୟଥା
  crypto_int64 crypto_int64_r = crypto_int64_y ^ crypto_int64_x;
  crypto_int64 crypto_int64_z = crypto_int64_y - crypto_int64_x;
  crypto_int64_z ^= crypto_int64_r & (crypto_int64_z ^ crypto_int64_y);
  crypto_int64_z = crypto_int64_negative_mask(crypto_int64_z);
  crypto_int64_z &= crypto_int64_r;
  crypto_int64_x ^= crypto_int64_z;
  crypto_int64_y ^= crypto_int64_z;
  *crypto_int64_p = crypto_int64_x;
  *crypto_int64_q = crypto_int64_y;
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int64 crypto_int64_smaller_mask(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n cmpq %3,%2\n cmovlq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ଫେରନ୍ତୁ crypto_int64_z;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n csetm %0,lt" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ଫେରନ୍ତୁ crypto_int64_z;
#ଅନ୍ୟଥା
  crypto_int64 crypto_int64_r = crypto_int64_x ^ crypto_int64_y;
  crypto_int64 crypto_int64_z = crypto_int64_x - crypto_int64_y;
  crypto_int64_z ^= crypto_int64_r & (crypto_int64_z ^ crypto_int64_x);
  ଫେରନ୍ତୁ crypto_int64_negative_mask(crypto_int64_z);
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int64 crypto_int64_smaller_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n cmpq %3,%2\n cmovlq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ଫେରନ୍ତୁ crypto_int64_z;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n cset %0,lt" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ଫେରନ୍ତୁ crypto_int64_z;
#ଅନ୍ୟଥା
  crypto_int64 crypto_int64_r = crypto_int64_x ^ crypto_int64_y;
  crypto_int64 crypto_int64_z = crypto_int64_x - crypto_int64_y;
  crypto_int64_z ^= crypto_int64_r & (crypto_int64_z ^ crypto_int64_x);
  ଫେରନ୍ତୁ crypto_int64_unsigned_topbit_01(crypto_int64_z);
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int64 crypto_int64_leq_mask(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n cmpq %3,%2\n cmovleq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ଫେରନ୍ତୁ crypto_int64_z;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n csetm %0,le" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ଫେରନ୍ତୁ crypto_int64_z;
#ଅନ୍ୟଥା
  ଫେରନ୍ତୁ ~crypto_int64_smaller_mask(crypto_int64_y,crypto_int64_x);
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
crypto_int64 crypto_int64_leq_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n cmpq %3,%2\n cmovleq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ଫେରନ୍ତୁ crypto_int64_z;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n cset %0,le" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ଫେରନ୍ତୁ crypto_int64_z;
#ଅନ୍ୟଥା
  ଫେରନ୍ତୁ 1-crypto_int64_smaller_01(crypto_int64_y,crypto_int64_x);
#endif
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
ପୂର୍ଣ୍ଣସଂଖ୍ୟା crypto_int64_ones_ଅଙ୍କ(crypto_int64 crypto_int64_x) {
  crypto_int64_unsigned crypto_int64_y = crypto_int64_x;
  ଅଚଳ crypto_int64 C0 = 0x5555555555555555;
  ଅଚଳ crypto_int64 C1 = 0x3333333333333333;
  ଅଚଳ crypto_int64 C2 = 0x0f0f0f0f0f0f0f0f;
  crypto_int64_y -= ((crypto_int64_y >> 1) & C0);
  crypto_int64_y = (crypto_int64_y & C1) + ((crypto_int64_y >> 2) & C1);
  crypto_int64_y = (crypto_int64_y + (crypto_int64_y >> 4)) & C2;
  crypto_int64_y += crypto_int64_y >> 8;
  crypto_int64_y += crypto_int64_y >> 16;
  crypto_int64_y = (crypto_int64_y + (crypto_int64_y >> 32)) & 0xff;
  ଫେରନ୍ତୁ crypto_int64_y;
}

__attribute__((unused))
ସ୍ଥିର ଧାଡ଼ିଭିତରେ
ପୂର୍ଣ୍ଣସଂଖ୍ୟା crypto_int64_bottomzeros_ଅଙ୍କ(crypto_int64 crypto_int64_x) {
#ଯଦି defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 fallback = 64;
  __asm__ ("bsfq %0,%0\n cmoveq %1,%0" : "+&r"(crypto_int64_x) : "r"(fallback) : "cc");
  ଫେରନ୍ତୁ crypto_int64_x;
#ନଚେତଯଦି defined(__GNUC__) && defined(__aarch64__)
  int64_t crypto_int64_y;
  __asm__ ("rbit %0,%1\n clz %0,%0" : "=r"(crypto_int64_y) : "r"(crypto_int64_x) : );
  ଫେରନ୍ତୁ crypto_int64_y;
#ଅନ୍ୟଥା
  crypto_int64 crypto_int64_y = crypto_int64_x ^ (crypto_int64_x-1);
  crypto_int64_y = ((crypto_int64) crypto_int64_y) >> 1;
  crypto_int64_y &= ~(crypto_int64_x & (((crypto_int64) 1) << (64-1)));
  ଫେରନ୍ତୁ crypto_int64_ones_ଅଙ୍କ(crypto_int64_y);
#endif
}

#endif

/* from supercop-20240808/crypto_sort/int32/portable4/sort.c */
#define int32_MINMAX(a,b) crypto_int32_minmax(&a,&b)

ସ୍ଥିର ଶୂନ୍ୟ crypto_sort_int32(ଶୂନ୍ୟ *array,long long n)
{
  long long ଶୀର୍ଷ,p,q,r,i,j;
  int32 *x = array;

  ଯଦି (n < 2) ଫେରନ୍ତୁ;
  ଶୀର୍ଷ = 1;
  ଯେତେବେଳେ (ଶୀର୍ଷ < n - ଶୀର୍ଷ) ଶୀର୍ଷ += ଶୀର୍ଷ;

  ପାଇଁ (p = ଶୀର୍ଷ;p >= 1;p >>= 1) {
    i = 0;
    ଯେତେବେଳେ (i + 2 * p <= n) {
      ପାଇଁ (j = i;j < i + p;++j)
        int32_MINMAX(x[j],x[j+p]);
      i += 2 * p;
    }
    ପାଇଁ (j = i;j < n - p;++j)
      int32_MINMAX(x[j],x[j+p]);

    i = 0;
    j = 0;
    ପାଇଁ (q = ଶୀର୍ଷ;q > p;q >>= 1) {
      ଯଦି (j != i) ପାଇଁ (;;) {
        ଯଦି (j == n - q) ଯାଅ done;
        int32 a = x[j + p];
        ପାଇଁ (r = q;r > p;r >>= 1)
          int32_MINMAX(a,x[j + r]);
        x[j + p] = a;
        ++j;
        ଯଦି (j == i + p) {
          i += 2 * p;
          ଭାଙ୍ଗ;
        }
      }
      ଯେତେବେଳେ (i + p <= n - q) {
        ପାଇଁ (j = i;j < i + p;++j) {
          int32 a = x[j + p];
          ପାଇଁ (r = q;r > p;r >>= 1)
            int32_MINMAX(a,x[j+r]);
          x[j + p] = a;
        }
        i += 2 * p;
      }
      /* now i + p > n - q */
      j = i;
      ଯେତେବେଳେ (j < n - q) {
        int32 a = x[j + p];
        ପାଇଁ (r = q;r > p;r >>= 1)
          int32_MINMAX(a,x[j+r]);
        x[j + p] = a;
        ++j;
      }

      done: ;
    }
  }
}

/* from supercop-20240808/crypto_sort/uint32/useint32/sort.c */

/* can save time by vectorizing xor loops */
/* can save time by integrating xor loops with int32_sort */

ସ୍ଥିର ଶୂନ୍ୟ crypto_sort_uint32(ଶୂନ୍ୟ *array,long long n)
{
  crypto_uint32 *x = array;
  long long j;
  ପାଇଁ (j = 0;j < n;++j) x[j] ^= 0x80000000;
  crypto_sort_int32(array,n);
  ପାଇଁ (j = 0;j < n;++j) x[j] ^= 0x80000000;
}

/* from supercop-20240808/crypto_kem/sntrup761/compact/kem.c */
// 20240806 djb: some automated conversion to cryptoint

#define p 761
#define q 4591
#define w 286
#define q12 ((q - 1) / 2)
ପ୍ରକାରବ୍ୟାଖ୍ୟା int8_t small;
ପ୍ରକାରବ୍ୟାଖ୍ୟା int16_t Fq;
#define Hash_bytes 32
#define Small_bytes ((p + 3) / 4)
ପ୍ରକାରବ୍ୟାଖ୍ୟା small Inputs[p];
#define Secret_ଚାବିଗୁଡ଼ିକ_bytes (2 * Small_bytes)
#define Confirm_bytes 32

ସ୍ଥିର small F3_freeze(int16_t x) { ଫେରନ୍ତୁ x - 3 * ((10923 * x + 16384) >> 15); }

ସ୍ଥିର Fq Fq_freeze(int32_t x) {
  ଅଚଳ int32_t q16 = (0x10000 + q / 2) / q;
  ଅଚଳ int32_t q20 = (0x100000 + q / 2) / q;
  ଅଚଳ int32_t q28 = (0x10000000 + q / 2) / q;
  x -= q * ((q16 * x) >> 16);
  x -= q * ((q20 * x) >> 20);
  ଫେରନ୍ତୁ x - q * ((q28 * x + 0x8000000) >> 28);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା Weightw_mask(small *r) {
  ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, weight = 0;
  ପାଇଁ (i = 0; i < p; ++i) weight += crypto_int64_bottombit_01(r[i]);
  ଫେରନ୍ତୁ crypto_int16_nonzero_mask(weight - w);
}

ସ୍ଥିର ଶୂନ୍ୟ uint32_divmod_uint14(uint32_t *Q, uint16_t *r, uint32_t x, uint16_t m) {
  uint32_t qpart, mask, v = 0x80000000 / m;
  qpart = (x * (uint64_t)v) >> 31;
  x -= qpart * m;
  *Q = qpart;
  qpart = (x * (uint64_t)v) >> 31;
  x -= qpart * m;
  *Q += qpart;
  x -= m;
  *Q += 1;
  mask = crypto_int32_negative_mask(x);
  x += mask & (uint32_t)m;
  *Q += mask;
  *r = x;
}

ସ୍ଥିର uint16_t uint32_mod_uint14(uint32_t x, uint16_t m) {
  uint32_t Q;
  uint16_t r;
  uint32_divmod_uint14(&Q, &r, x, m);
  ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ଶୂନ୍ୟ Encode(unsigned ଅକ୍ଷର *out, ଅଚଳ uint16_t *R, ଅଚଳ uint16_t *M, long long len) {
  ଯଦି (len == 1) {
    uint16_t r = R[0], m = M[0];
    ଯେତେବେଳେ (m > 1) {
      *out++ = r;
      r >>= 8;
      m = (m + 255) >> 8;
    }
  }
  ଯଦି (len > 1) {
    uint16_t R2[(len + 1) / 2], M2[(len + 1) / 2];
    long long i;
    ପାଇଁ (i = 0; i < len - 1; i += 2) {
      uint32_t m0 = M[i];
      uint32_t r = R[i] + R[i + 1] * m0;
      uint32_t m = M[i + 1] * m0;
      ଯେତେବେଳେ (m >= 16384) {
        *out++ = r;
        r >>= 8;
        m = (m + 255) >> 8;
      }
      R2[i / 2] = r;
      M2[i / 2] = m;
    }
    ଯଦି (i < len) {
      R2[i / 2] = R[i];
      M2[i / 2] = M[i];
    }
    Encode(out, R2, M2, (len + 1) / 2);
  }
}

ସ୍ଥିର ଶୂନ୍ୟ Decode(uint16_t *out, ଅଚଳ unsigned ଅକ୍ଷର *S, ଅଚଳ uint16_t *M, long long len) {
  ଯଦି (len == 1) {
    ଯଦି (M[0] == 1)
      *out = 0;
    ଅନ୍ୟଥା ଯଦି (M[0] <= 256)
      *out = uint32_mod_uint14(S[0], M[0]);
    ଅନ୍ୟଥା
      *out = uint32_mod_uint14(S[0] + (((uint16_t)S[1]) << 8), M[0]);
  }
  ଯଦି (len > 1) {
    uint16_t R2[(len + 1) / 2], M2[(len + 1) / 2], bottomr[len / 2];
    uint32_t bottomt[len / 2];
    long long i;
    ପାଇଁ (i = 0; i < len - 1; i += 2) {
      uint32_t m = M[i] * (uint32_t)M[i + 1];
      ଯଦି (m > 256 * 16383) {
        bottomt[i / 2] = 256 * 256;
        bottomr[i / 2] = S[0] + 256 * S[1];
        S += 2;
        M2[i / 2] = (((m + 255) >> 8) + 255) >> 8;
      } ଅନ୍ୟଥା ଯଦି (m >= 16384) {
        bottomt[i / 2] = 256;
        bottomr[i / 2] = S[0];
        S += 1;
        M2[i / 2] = (m + 255) >> 8;
      } ଅନ୍ୟଥା {
        bottomt[i / 2] = 1;
        bottomr[i / 2] = 0;
        M2[i / 2] = m;
      }
    }
    ଯଦି (i < len) M2[i / 2] = M[i];
    Decode(R2, S, M2, (len + 1) / 2);
    ପାଇଁ (i = 0; i < len - 1; i += 2) {
      uint32_t r1, r = bottomr[i / 2];
      uint16_t r0;
      r += bottomt[i / 2] * R2[i / 2];
      uint32_divmod_uint14(&r1, &r0, r, M[i]);
      r1 = uint32_mod_uint14(r1, M[i + 1]);
      *out++ = r0;
      *out++ = r1;
    }
    ଯଦି (i < len) *out++ = R2[i / 2];
  }
}

ସ୍ଥିର ଶୂନ୍ୟ R3_fromRq(small *out, ଅଚଳ Fq *r) {
  ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;
  ପାଇଁ (i = 0; i < p; ++i) out[i] = F3_freeze(r[i]);
}

ସ୍ଥିର ଶୂନ୍ୟ R3_mult(small *h, ଅଚଳ small *f, ଅଚଳ small *g) {
  int16_t fg[p + p - 1];
  ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, j;
  ପାଇଁ (i = 0; i < p + p - 1; ++i) fg[i] = 0;
  ପାଇଁ (i = 0; i < p; ++i)
    ପାଇଁ (j = 0; j < p; ++j) fg[i + j] += f[i] * (int16_t)g[j];
  ପାଇଁ (i = p; i < p + p - 1; ++i) fg[i - p] += fg[i];
  ପାଇଁ (i = p; i < p + p - 1; ++i) fg[i - p + 1] += fg[i];
  ପାଇଁ (i = 0; i < p; ++i) h[i] = F3_freeze(fg[i]);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା R3_recip(small *out, ଅଚଳ small *in) {
  small f[p + 1], g[p + 1], v[p + 1], r[p + 1];
  ପୂର୍ଣ୍ଣସଂଖ୍ୟା sign, swap, t, i, loop, delta = 1;
  ପାଇଁ (i = 0; i < p + 1; ++i) v[i] = 0;
  ପାଇଁ (i = 0; i < p + 1; ++i) r[i] = 0;
  r[0] = 1;
  ପାଇଁ (i = 0; i < p; ++i) f[i] = 0;
  f[0] = 1;
  f[p - 1] = f[p] = -1;
  ପାଇଁ (i = 0; i < p; ++i) g[p - 1 - i] = in[i];
  g[p] = 0;
  ପାଇଁ (loop = 0; loop < 2 * p - 1; ++loop) {
    ପାଇଁ (i = p; i > 0; --i) v[i] = v[i - 1];
    v[0] = 0;
    sign = -g[0] * f[0];
    swap = crypto_int16_negative_mask(-delta) & crypto_int16_nonzero_mask(g[0]);
    delta ^= swap & (delta ^ -delta);
    delta += 1;
    ପାଇଁ (i = 0; i < p + 1; ++i) {
      t = swap & (f[i] ^ g[i]);
      f[i] ^= t;
      g[i] ^= t;
      t = swap & (v[i] ^ r[i]);
      v[i] ^= t;
      r[i] ^= t;
    }
    ପାଇଁ (i = 0; i < p + 1; ++i) g[i] = F3_freeze(g[i] + sign * f[i]);
    ପାଇଁ (i = 0; i < p + 1; ++i) r[i] = F3_freeze(r[i] + sign * v[i]);
    ପାଇଁ (i = 0; i < p; ++i) g[i] = g[i + 1];
    g[p] = 0;
  }
  sign = f[0];
  ପାଇଁ (i = 0; i < p; ++i) out[i] = sign * v[p - 1 - i];
  ଫେରନ୍ତୁ crypto_int16_nonzero_mask(delta);
}

ସ୍ଥିର ଶୂନ୍ୟ Rq_mult_small(Fq *h, ଅଚଳ Fq *f, ଅଚଳ small *g) {
  int32_t fg[p + p - 1];
  ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, j;
  ପାଇଁ (i = 0; i < p + p - 1; ++i) fg[i] = 0;
  ପାଇଁ (i = 0; i < p; ++i)
    ପାଇଁ (j = 0; j < p; ++j) fg[i + j] += f[i] * (int32_t)g[j];
  ପାଇଁ (i = p; i < p + p - 1; ++i) fg[i - p] += fg[i];
  ପାଇଁ (i = p; i < p + p - 1; ++i) fg[i - p + 1] += fg[i];
  ପାଇଁ (i = 0; i < p; ++i) h[i] = Fq_freeze(fg[i]);
}

ସ୍ଥିର ଶୂନ୍ୟ Rq_mult3(Fq *h, ଅଚଳ Fq *f) {
  ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;
  ପାଇଁ (i = 0; i < p; ++i) h[i] = Fq_freeze(3 * f[i]);
}

ସ୍ଥିର Fq Fq_recip(Fq a1) {
  ପୂର୍ଣ୍ଣସଂଖ୍ୟା i = 1;
  Fq ai = a1;
  ଯେତେବେଳେ (i < q - 2) {
    ai = Fq_freeze(a1 * (int32_t)ai);
    i += 1;
  }
  ଫେରନ୍ତୁ ai;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା Rq_recip3(Fq *out, ଅଚଳ small *in) {
  Fq f[p + 1], g[p + 1], v[p + 1], r[p + 1], scale;
  ପୂର୍ଣ୍ଣସଂଖ୍ୟା swap, t, i, loop, delta = 1;
  int32_t f0, g0;
  ପାଇଁ (i = 0; i < p + 1; ++i) v[i] = 0;
  ପାଇଁ (i = 0; i < p + 1; ++i) r[i] = 0;
  r[0] = Fq_recip(3);
  ପାଇଁ (i = 0; i < p; ++i) f[i] = 0;
  f[0] = 1;
  f[p - 1] = f[p] = -1;
  ପାଇଁ (i = 0; i < p; ++i) g[p - 1 - i] = in[i];
  g[p] = 0;
  ପାଇଁ (loop = 0; loop < 2 * p - 1; ++loop) {
    ପାଇଁ (i = p; i > 0; --i) v[i] = v[i - 1];
    v[0] = 0;
    swap = crypto_int16_negative_mask(-delta) & crypto_int16_nonzero_mask(g[0]);
    delta ^= swap & (delta ^ -delta);
    delta += 1;
    ପାଇଁ (i = 0; i < p + 1; ++i) {
      t = swap & (f[i] ^ g[i]);
      f[i] ^= t;
      g[i] ^= t;
      t = swap & (v[i] ^ r[i]);
      v[i] ^= t;
      r[i] ^= t;
    }
    f0 = f[0];
    g0 = g[0];
    ପାଇଁ (i = 0; i < p + 1; ++i) g[i] = Fq_freeze(f0 * g[i] - g0 * f[i]);
    ପାଇଁ (i = 0; i < p + 1; ++i) r[i] = Fq_freeze(f0 * r[i] - g0 * v[i]);
    ପାଇଁ (i = 0; i < p; ++i) g[i] = g[i + 1];
    g[p] = 0;
  }
  scale = Fq_recip(f[0]);
  ପାଇଁ (i = 0; i < p; ++i) out[i] = Fq_freeze(scale * (int32_t)v[p - 1 - i]);
  ଫେରନ୍ତୁ crypto_int16_nonzero_mask(delta);
}

ସ୍ଥିର ଶୂନ୍ୟ Round(Fq *out, ଅଚଳ Fq *a) {
  ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;
  ପାଇଁ (i = 0; i < p; ++i) out[i] = a[i] - F3_freeze(a[i]);
}

ସ୍ଥିର ଶୂନ୍ୟ Short_fromlist(small *out, ଅଚଳ uint32_t *in) {
  uint32_t L[p];
  ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;
  ପାଇଁ (i = 0; i < w; ++i) L[i] = in[i] & (uint32_t)-2;
  ପାଇଁ (i = w; i < p; ++i) L[i] = (in[i] & (uint32_t)-3) | 1;
  crypto_sort_uint32(L, p);
  ପାଇଁ (i = 0; i < p; ++i) out[i] = (L[i] & 3) - 1;
}

ସ୍ଥିର ଶୂନ୍ୟ Hash_prefix(unsigned ଅକ୍ଷର *out, ପୂର୍ଣ୍ଣସଂଖ୍ୟା b, ଅଚଳ unsigned ଅକ୍ଷର *in, ପୂର୍ଣ୍ଣସଂଖ୍ୟା inlen) {
  unsigned ଅକ୍ଷର x[inlen + 1], h[64];
  ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;
  x[0] = b;
  ପାଇଁ (i = 0; i < inlen; ++i) x[i + 1] = in[i];
  crypto_hash_sha512(h, x, inlen + 1);
  ପାଇଁ (i = 0; i < 32; ++i) out[i] = h[i];
}


ସ୍ଥିର ଶୂନ୍ୟ Short_random(small *out) {
  uint32_t L[p];
  randombytes(L, ଆକାର(L));
  Short_fromlist(out, L);
  explicit_bzero(L, ଆକାର(L));
}
ସ୍ଥିର ଶୂନ୍ୟ Small_random(small *out) {
  ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;
  uint32_t L[p];
  randombytes(L, ଆକାର(L));
  ପାଇଁ (i = 0; i < p; ++i) out[i] = (((L[i] & 0x3fffffff) * 3) >> 30) - 1;
  explicit_bzero(L, ଆକାର(L));
}
ସ୍ଥିର ଶୂନ୍ୟ ଚାବି_Gen(Fq *h, small *f, small *ginv) {
  small g[p];
  Fq finv[p];
  ପାଇଁ (;;) {
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା result;
    Small_random(g);
    result = R3_recip(ginv, g);
    crypto_declassify(&result, ଆକାର result);
    ଯଦି (result == 0) ଭାଙ୍ଗ;
  }
  Short_random(f);
  Rq_recip3(finv, f);
  Rq_mult_small(h, finv, g);
}

ସ୍ଥିର ଶୂନ୍ୟ Encrypt(Fq *c, ଅଚଳ small *r, ଅଚଳ Fq *h) {
  Fq hr[p];
  Rq_mult_small(hr, h, r);
  Round(c, hr);
}

ସ୍ଥିର ଶୂନ୍ୟ Decrypt(small *r, ଅଚଳ Fq *c, ଅଚଳ small *f, ଅଚଳ small *ginv) {
  Fq cf[p], cf3[p];
  small e[p], ev[p];
  ପୂର୍ଣ୍ଣସଂଖ୍ୟା mask, i;
  Rq_mult_small(cf, c, f);
  Rq_mult3(cf3, cf);
  R3_fromRq(e, cf3);
  R3_mult(ev, e, ginv);
  mask = Weightw_mask(ev);
  ପାଇଁ (i = 0; i < w; ++i) r[i] = ((ev[i] ^ 1) & ~mask) ^ 1;
  ପାଇଁ (i = w; i < p; ++i) r[i] = ev[i] & ~mask;
}

ସ୍ଥିର ଶୂନ୍ୟ Small_encode(unsigned ଅକ୍ଷର *s, ଅଚଳ small *f) {
  ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, j;
  ପାଇଁ (i = 0; i < p / 4; ++i) {
    small x = 0;
    ପାଇଁ (j = 0;j < 4;++j) x += (*f++ + 1) << (2 * j);
    *s++ = x;
  }
  *s = *f++ + 1;
}

ସ୍ଥିର ଶୂନ୍ୟ Small_decode(small *f, ଅଚଳ unsigned ଅକ୍ଷର *s) {
  ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, j;
  ପାଇଁ (i = 0; i < p / 4; ++i) {
    unsigned ଅକ୍ଷର x = *s++;
    ପାଇଁ (j = 0;j < 4;++j) *f++ = ((small)((x >> (2 * j)) & 3)) - 1;
  }
  *f++ = ((small)(*s & 3)) - 1;
}

ସ୍ଥିର ଶୂନ୍ୟ Rq_encode(unsigned ଅକ୍ଷର *s, ଅଚଳ Fq *r) {
  uint16_t R[p], M[p];
  ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;
  ପାଇଁ (i = 0; i < p; ++i) R[i] = r[i] + q12;
  ପାଇଁ (i = 0; i < p; ++i) M[i] = q;
  Encode(s, R, M, p);
}

ସ୍ଥିର ଶୂନ୍ୟ Rq_decode(Fq *r, ଅଚଳ unsigned ଅକ୍ଷର *s) {
  uint16_t R[p], M[p];
  ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;
  ପାଇଁ (i = 0; i < p; ++i) M[i] = q;
  Decode(R, s, M, p);
  ପାଇଁ (i = 0; i < p; ++i) r[i] = ((Fq)R[i]) - q12;
}

ସ୍ଥିର ଶୂନ୍ୟ Rounded_encode(unsigned ଅକ୍ଷର *s, ଅଚଳ Fq *r) {
  uint16_t R[p], M[p];
  ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;
  ପାଇଁ (i = 0; i < p; ++i) R[i] = ((r[i] + q12) * 10923) >> 15;
  ପାଇଁ (i = 0; i < p; ++i) M[i] = (q + 2) / 3;
  Encode(s, R, M, p);
}

ସ୍ଥିର ଶୂନ୍ୟ Rounded_decode(Fq *r, ଅଚଳ unsigned ଅକ୍ଷର *s) {
  uint16_t R[p], M[p];
  ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;
  ପାଇଁ (i = 0; i < p; ++i) M[i] = (q + 2) / 3;
  Decode(R, s, M, p);
  ପାଇଁ (i = 0; i < p; ++i) r[i] = R[i] * 3 - q12;
}

ସ୍ଥିର ଶୂନ୍ୟ ZKeyGen(unsigned ଅକ୍ଷର *pk, unsigned ଅକ୍ଷର *sk) {
  Fq h[p];
  small f[p], v[p];
  ଚାବି_Gen(h, f, v);
  Rq_encode(pk, h);
  Small_encode(sk, f);
  Small_encode(sk + Small_bytes, v);
}

ସ୍ଥିର ଶୂନ୍ୟ ZEncrypt(unsigned ଅକ୍ଷର *C, ଅଚଳ Inputs r, ଅଚଳ unsigned ଅକ୍ଷର *pk) {
  Fq h[p], c[p];
  Rq_decode(h, pk);
  Encrypt(c, r, h);
  Rounded_encode(C, c);
}

ସ୍ଥିର ଶୂନ୍ୟ ZDecrypt(Inputs r, ଅଚଳ unsigned ଅକ୍ଷର *C, ଅଚଳ unsigned ଅକ୍ଷର *sk) {
  small f[p], v[p];
  Fq c[p];
  Small_decode(f, sk);
  Small_decode(v, sk + Small_bytes);
  Rounded_decode(c, C);
  Decrypt(r, c, f, v);
}

ସ୍ଥିର ଶୂନ୍ୟ HashConfirm(unsigned ଅକ୍ଷର *h, ଅଚଳ unsigned ଅକ୍ଷର *r, ଅଚଳ unsigned ଅକ୍ଷର *cache) {
  unsigned ଅକ୍ଷର x[Hash_bytes * 2];
  ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;
  Hash_prefix(x, 3, r, Small_bytes);
  ପାଇଁ (i = 0; i < Hash_bytes; ++i) x[Hash_bytes + i] = cache[i];
  Hash_prefix(h, 2, x, ଆକାର x);
}

ସ୍ଥିର ଶୂନ୍ୟ HashSession(unsigned ଅକ୍ଷର *k, ପୂର୍ଣ୍ଣସଂଖ୍ୟା b, ଅଚଳ unsigned ଅକ୍ଷର *y, ଅଚଳ unsigned ଅକ୍ଷର *z) {
  unsigned ଅକ୍ଷର x[Hash_bytes + crypto_kem_sntrup761_CIPHERTEXTBYTES];
  ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;
  Hash_prefix(x, 3, y, Small_bytes);
  ପାଇଁ (i = 0; i < crypto_kem_sntrup761_CIPHERTEXTBYTES; ++i) x[Hash_bytes + i] = z[i];
  Hash_prefix(k, b, x, ଆକାର x);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା crypto_kem_sntrup761_keypair(unsigned ଅକ୍ଷର *pk, unsigned ଅକ୍ଷର *sk) {
  ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;
  ZKeyGen(pk, sk);
  sk += Secret_ଚାବିଗୁଡ଼ିକ_bytes;
  ପାଇଁ (i = 0; i < crypto_kem_sntrup761_PUBLICKEYBYTES; ++i) *sk++ = pk[i];
  randombytes(sk, Small_bytes);
  Hash_prefix(sk + Small_bytes, 4, pk, crypto_kem_sntrup761_PUBLICKEYBYTES);
  ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ଶୂନ୍ୟ Hide(unsigned ଅକ୍ଷର *c, unsigned ଅକ୍ଷର *r_enc, ଅଚଳ Inputs r, ଅଚଳ unsigned ଅକ୍ଷର *pk, ଅଚଳ unsigned ଅକ୍ଷର *cache) {
  Small_encode(r_enc, r);
  ZEncrypt(c, r, pk);
  HashConfirm(c + crypto_kem_sntrup761_CIPHERTEXTBYTES - Confirm_bytes, r_enc, cache);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା crypto_kem_sntrup761_enc(unsigned ଅକ୍ଷର *c, unsigned ଅକ୍ଷର *k, ଅଚଳ unsigned ଅକ୍ଷର *pk) {
  Inputs r;
  unsigned ଅକ୍ଷର r_enc[Small_bytes], cache[Hash_bytes];
  Hash_prefix(cache, 4, pk, crypto_kem_sntrup761_PUBLICKEYBYTES);
  Short_random(r);
  Hide(c, r_enc, r, pk, cache);
  HashSession(k, 1, r_enc, c);
  ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା Ciphertexts_diff_mask(ଅଚଳ unsigned ଅକ୍ଷର *c, ଅଚଳ unsigned ଅକ୍ଷର *c2) {
  uint16_t differentbits = 0;
  ପୂର୍ଣ୍ଣସଂଖ୍ୟା len = crypto_kem_sntrup761_CIPHERTEXTBYTES;
  ଯେତେବେଳେ (len-- > 0) differentbits |= (*c++) ^ (*c2++);
  ଫେରନ୍ତୁ (crypto_int64_bitmod_01((differentbits - 1),8)) - 1;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା crypto_kem_sntrup761_dec(unsigned ଅକ୍ଷର *k, ଅଚଳ unsigned ଅକ୍ଷର *c, ଅଚଳ unsigned ଅକ୍ଷର *sk) {
  ଅଚଳ unsigned ଅକ୍ଷର *pk = sk + Secret_ଚାବିଗୁଡ଼ିକ_bytes;
  ଅଚଳ unsigned ଅକ୍ଷର *rho = pk + crypto_kem_sntrup761_PUBLICKEYBYTES;
  ଅଚଳ unsigned ଅକ୍ଷର *cache = rho + Small_bytes;
  Inputs r;
  unsigned ଅକ୍ଷର r_enc[Small_bytes], cnew[crypto_kem_sntrup761_CIPHERTEXTBYTES];
  ପୂର୍ଣ୍ଣସଂଖ୍ୟା mask, i;
  ZDecrypt(r, c, sk);
  Hide(cnew, r_enc, r, pk, cache);
  mask = Ciphertexts_diff_mask(c, cnew);
  ପାଇଁ (i = 0; i < Small_bytes; ++i) r_enc[i] ^= mask & (r_enc[i] ^ rho[i]);
  HashSession(k, 1 + mask, r_enc, c);
  ଫେରନ୍ତୁ 0;
}

#endif /* USE_SNTRUP761X25519 */
