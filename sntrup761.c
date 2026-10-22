/*  $OpenBSD: sntrup761.c,v 1.9 2026/01/20 22:56:11 dtucker Exp $ */

/*
 * Public Domain, Authors:
 * - Daniel J. Bernstein
 * - Chitchanok Chuengsatiansup
 * - Tanja Lange
 * - Christine van Vredendaal
 */

#অন্তর্ভাব "includes.h"

#ifdef USE_SNTRUP761X25519

#অন্তর্ভাব <string.h>
#অন্তর্ভাব "crypto_api.h"

#define crypto_declassify(x, y) করো {} যখন (0)

#define int8 crypto_int8
#define uint8 crypto_uint8
#define int16 crypto_int16
#define uint16 crypto_uint16
#define int32 crypto_int32
#define uint32 crypto_uint32
#define int64 crypto_int64
#define uint64 crypto_uint64
বাহ্যিক অস্থির crypto_int16 crypto_int16_optblocker;
বাহ্যিক অস্থির crypto_int32 crypto_int32_optblocker;
বাহ্যিক অস্থির crypto_int64 crypto_int64_optblocker;

/* from supercop-20240808/cryptoint/crypto_int16.h */
/* auto-generated: cd cryptoint; ./autogen */
/* cryptoint 20240806 */

#ifndef crypto_int16_h
#define crypto_int16_h

#define crypto_int16 int16_t
#define crypto_int16_unsigned uint16_t



__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int16 crypto_int16_load(ধ্রুবক unsigned অক্ষর *crypto_int16_s) {
  crypto_int16 crypto_int16_z = 0;
  crypto_int16_z |= ((crypto_int16) (*crypto_int16_s++)) << 0;
  crypto_int16_z |= ((crypto_int16) (*crypto_int16_s++)) << 8;
  ফেরত crypto_int16_z;
}

__attribute__((unused))
স্থির অন্তঃরেখ
শূন্য crypto_int16_store(unsigned অক্ষর *crypto_int16_s,crypto_int16 crypto_int16_x) {
  *crypto_int16_s++ = crypto_int16_x >> 0;
  *crypto_int16_s++ = crypto_int16_x >> 8;
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int16 crypto_int16_negative_mask(crypto_int16 crypto_int16_x) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarw $15,%0" : "+r"(crypto_int16_x) : : "cc");
  ফেরত crypto_int16_x;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_y;
  __asm__ ("sbfx %w0,%w1,15,1" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) : );
  ফেরত crypto_int16_y;
#অন্যথা
  crypto_int16_x >>= 16-6;
  crypto_int16_x ^= crypto_int16_optblocker;
  crypto_int16_x >>= 5;
  ফেরত crypto_int16_x;
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int16_unsigned crypto_int16_unsigned_topbit_01(crypto_int16_unsigned crypto_int16_x) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("shrw $15,%0" : "+r"(crypto_int16_x) : : "cc");
  ফেরত crypto_int16_x;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_y;
  __asm__ ("ubfx %w0,%w1,15,1" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) : );
  ফেরত crypto_int16_y;
#অন্যথা
  crypto_int16_x >>= 16-6;
  crypto_int16_x ^= crypto_int16_optblocker;
  crypto_int16_x >>= 5;
  ফেরত crypto_int16_x;
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int16 crypto_int16_negative_01(crypto_int16 crypto_int16_x) {
  ফেরত crypto_int16_unsigned_topbit_01(crypto_int16_x);
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int16 crypto_int16_topbit_mask(crypto_int16 crypto_int16_x) {
  ফেরত crypto_int16_negative_mask(crypto_int16_x);
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int16 crypto_int16_topbit_01(crypto_int16 crypto_int16_x) {
  ফেরত crypto_int16_unsigned_topbit_01(crypto_int16_x);
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int16 crypto_int16_bottombit_mask(crypto_int16 crypto_int16_x) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andw $1,%0" : "+r"(crypto_int16_x) : : "cc");
  ফেরত -crypto_int16_x;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_y;
  __asm__ ("sbfx %w0,%w1,0,1" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) : );
  ফেরত crypto_int16_y;
#অন্যথা
  crypto_int16_x &= 1 ^ crypto_int16_optblocker;
  ফেরত -crypto_int16_x;
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int16 crypto_int16_bottombit_01(crypto_int16 crypto_int16_x) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andw $1,%0" : "+r"(crypto_int16_x) : : "cc");
  ফেরত crypto_int16_x;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_y;
  __asm__ ("ubfx %w0,%w1,0,1" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) : );
  ফেরত crypto_int16_y;
#অন্যথা
  crypto_int16_x &= 1 ^ crypto_int16_optblocker;
  ফেরত crypto_int16_x;
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int16 crypto_int16_bitinrangepublicpos_mask(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarw %%cl,%0" : "+r"(crypto_int16_x) : "c"(crypto_int16_s) : "cc");
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("sxth %w0,%w0\n asr %w0,%w0,%w1" : "+&r"(crypto_int16_x) : "r"(crypto_int16_s) : );
#অন্যথা
  crypto_int16_x >>= crypto_int16_s ^ crypto_int16_optblocker;
#endif
  ফেরত crypto_int16_bottombit_mask(crypto_int16_x);
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int16 crypto_int16_bitinrangepublicpos_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarw %%cl,%0" : "+r"(crypto_int16_x) : "c"(crypto_int16_s) : "cc");
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("sxth %w0,%w0\n asr %w0,%w0,%w1" : "+&r"(crypto_int16_x) : "r"(crypto_int16_s) : );
#অন্যথা
  crypto_int16_x >>= crypto_int16_s ^ crypto_int16_optblocker;
#endif
  ফেরত crypto_int16_bottombit_01(crypto_int16_x);
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int16 crypto_int16_shlmod(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  crypto_int16_s &= 15;
  __asm__ ("shlw %%cl,%0" : "+r"(crypto_int16_x) : "c"(crypto_int16_s) : "cc");
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("and %w0,%w0,15\n and %w1,%w1,65535\n lsl %w1,%w1,%w0" : "+&r"(crypto_int16_s), "+r"(crypto_int16_x) : : );
#অন্যথা
  পূর্ণসংখ্যা crypto_int16_k, crypto_int16_l;
  জন্য (crypto_int16_l = 0,crypto_int16_k = 1;crypto_int16_k < 16;++crypto_int16_l,crypto_int16_k *= 2)
    crypto_int16_x ^= (crypto_int16_x ^ (crypto_int16_x << crypto_int16_k)) & crypto_int16_bitinrangepublicpos_mask(crypto_int16_s,crypto_int16_l);
#endif
  ফেরত crypto_int16_x;
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int16 crypto_int16_shrmod(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  crypto_int16_s &= 15;
  __asm__ ("sarw %%cl,%0" : "+r"(crypto_int16_x) : "c"(crypto_int16_s) : "cc");
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("and %w0,%w0,15\n sxth %w1,%w1\n asr %w1,%w1,%w0" : "+&r"(crypto_int16_s), "+r"(crypto_int16_x) : : );
#অন্যথা
  পূর্ণসংখ্যা crypto_int16_k, crypto_int16_l;
  জন্য (crypto_int16_l = 0,crypto_int16_k = 1;crypto_int16_k < 16;++crypto_int16_l,crypto_int16_k *= 2)
    crypto_int16_x ^= (crypto_int16_x ^ (crypto_int16_x >> crypto_int16_k)) & crypto_int16_bitinrangepublicpos_mask(crypto_int16_s,crypto_int16_l);
#endif
  ফেরত crypto_int16_x;
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int16 crypto_int16_bitmod_mask(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
  crypto_int16_x = crypto_int16_shrmod(crypto_int16_x,crypto_int16_s);
  ফেরত crypto_int16_bottombit_mask(crypto_int16_x);
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int16 crypto_int16_bitmod_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
  crypto_int16_x = crypto_int16_shrmod(crypto_int16_x,crypto_int16_s);
  ফেরত crypto_int16_bottombit_01(crypto_int16_x);
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int16 crypto_int16_nonzero_mask(crypto_int16 crypto_int16_x) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n testw %2,%2\n cmovnew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  ফেরত crypto_int16_z;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("tst %w1,65535\n csetm %w0,ne" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  ফেরত crypto_int16_z;
#অন্যথা
  crypto_int16_x |= -crypto_int16_x;
  ফেরত crypto_int16_negative_mask(crypto_int16_x);
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int16 crypto_int16_nonzero_01(crypto_int16 crypto_int16_x) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n testw %2,%2\n cmovnew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  ফেরত crypto_int16_z;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("tst %w1,65535\n cset %w0,ne" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  ফেরত crypto_int16_z;
#অন্যথা
  crypto_int16_x |= -crypto_int16_x;
  ফেরত crypto_int16_unsigned_topbit_01(crypto_int16_x);
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int16 crypto_int16_positive_mask(crypto_int16 crypto_int16_x) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n testw %2,%2\n cmovgw %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  ফেরত crypto_int16_z;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,0\n csetm %w0,gt" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  ফেরত crypto_int16_z;
#অন্যথা
  crypto_int16 crypto_int16_z = -crypto_int16_x;
  crypto_int16_z ^= crypto_int16_x & crypto_int16_z;
  ফেরত crypto_int16_negative_mask(crypto_int16_z);
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int16 crypto_int16_positive_01(crypto_int16 crypto_int16_x) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n testw %2,%2\n cmovgw %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  ফেরত crypto_int16_z;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,0\n cset %w0,gt" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  ফেরত crypto_int16_z;
#অন্যথা
  crypto_int16 crypto_int16_z = -crypto_int16_x;
  crypto_int16_z ^= crypto_int16_x & crypto_int16_z;
  ফেরত crypto_int16_unsigned_topbit_01(crypto_int16_z);
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int16 crypto_int16_zero_mask(crypto_int16 crypto_int16_x) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n testw %2,%2\n cmovew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  ফেরত crypto_int16_z;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("tst %w1,65535\n csetm %w0,eq" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  ফেরত crypto_int16_z;
#অন্যথা
  ফেরত ~crypto_int16_nonzero_mask(crypto_int16_x);
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int16 crypto_int16_zero_01(crypto_int16 crypto_int16_x) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n testw %2,%2\n cmovew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  ফেরত crypto_int16_z;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("tst %w1,65535\n cset %w0,eq" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  ফেরত crypto_int16_z;
#অন্যথা
  ফেরত 1-crypto_int16_nonzero_01(crypto_int16_x);
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int16 crypto_int16_unequal_mask(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n cmpw %3,%2\n cmovnew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ফেরত crypto_int16_z;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("and %w0,%w1,65535\n cmp %w0,%w2,uxth\n csetm %w0,ne" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ফেরত crypto_int16_z;
#অন্যথা
  ফেরত crypto_int16_nonzero_mask(crypto_int16_x ^ crypto_int16_y);
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int16 crypto_int16_unequal_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n cmpw %3,%2\n cmovnew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ফেরত crypto_int16_z;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("and %w0,%w1,65535\n cmp %w0,%w2,uxth\n cset %w0,ne" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ফেরত crypto_int16_z;
#অন্যথা
  ফেরত crypto_int16_nonzero_01(crypto_int16_x ^ crypto_int16_y);
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int16 crypto_int16_equal_mask(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n cmpw %3,%2\n cmovew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ফেরত crypto_int16_z;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("and %w0,%w1,65535\n cmp %w0,%w2,uxth\n csetm %w0,eq" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ফেরত crypto_int16_z;
#অন্যথা
  ফেরত ~crypto_int16_unequal_mask(crypto_int16_x,crypto_int16_y);
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int16 crypto_int16_equal_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n cmpw %3,%2\n cmovew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ফেরত crypto_int16_z;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("and %w0,%w1,65535\n cmp %w0,%w2,uxth\n cset %w0,eq" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ফেরত crypto_int16_z;
#অন্যথা
  ফেরত 1-crypto_int16_unequal_01(crypto_int16_x,crypto_int16_y);
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int16 crypto_int16_min(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpw %1,%0\n cmovgw %1,%0" : "+r"(crypto_int16_x) : "r"(crypto_int16_y) : "cc");
  ফেরত crypto_int16_x;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("sxth %w0,%w0\n cmp %w0,%w1,sxth\n csel %w0,%w0,%w1,lt" : "+&r"(crypto_int16_x) : "r"(crypto_int16_y) : "cc");
  ফেরত crypto_int16_x;
#অন্যথা
  crypto_int16 crypto_int16_r = crypto_int16_y ^ crypto_int16_x;
  crypto_int16 crypto_int16_z = crypto_int16_y - crypto_int16_x;
  crypto_int16_z ^= crypto_int16_r & (crypto_int16_z ^ crypto_int16_y);
  crypto_int16_z = crypto_int16_negative_mask(crypto_int16_z);
  crypto_int16_z &= crypto_int16_r;
  ফেরত crypto_int16_x ^ crypto_int16_z;
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int16 crypto_int16_max(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpw %1,%0\n cmovlw %1,%0" : "+r"(crypto_int16_x) : "r"(crypto_int16_y) : "cc");
  ফেরত crypto_int16_x;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("sxth %w0,%w0\n cmp %w0,%w1,sxth\n csel %w0,%w1,%w0,lt" : "+&r"(crypto_int16_x) : "r"(crypto_int16_y) : "cc");
  ফেরত crypto_int16_x;
#অন্যথা
  crypto_int16 crypto_int16_r = crypto_int16_y ^ crypto_int16_x;
  crypto_int16 crypto_int16_z = crypto_int16_y - crypto_int16_x;
  crypto_int16_z ^= crypto_int16_r & (crypto_int16_z ^ crypto_int16_y);
  crypto_int16_z = crypto_int16_negative_mask(crypto_int16_z);
  crypto_int16_z &= crypto_int16_r;
  ফেরত crypto_int16_y ^ crypto_int16_z;
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
শূন্য crypto_int16_minmax(crypto_int16 *crypto_int16_p,crypto_int16 *crypto_int16_q) {
  crypto_int16 crypto_int16_x = *crypto_int16_p;
  crypto_int16 crypto_int16_y = *crypto_int16_q;
#যদি defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("cmpw %2,%1\n movw %1,%0\n cmovgw %2,%1\n cmovgw %0,%2" : "=&r"(crypto_int16_z), "+&r"(crypto_int16_x), "+r"(crypto_int16_y) : : "cc");
  *crypto_int16_p = crypto_int16_x;
  *crypto_int16_q = crypto_int16_y;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_r, crypto_int16_s;
  __asm__ ("sxth %w0,%w0\n cmp %w0,%w3,sxth\n csel %w1,%w0,%w3,lt\n csel %w2,%w3,%w0,lt" : "+&r"(crypto_int16_x), "=&r"(crypto_int16_r), "=r"(crypto_int16_s) : "r"(crypto_int16_y) : "cc");
  *crypto_int16_p = crypto_int16_r;
  *crypto_int16_q = crypto_int16_s;
#অন্যথা
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
স্থির অন্তঃরেখ
crypto_int16 crypto_int16_smaller_mask(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n cmpw %3,%2\n cmovlw %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ফেরত crypto_int16_z;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,%w2,sxth\n csetm %w0,lt" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ফেরত crypto_int16_z;
#অন্যথা
  crypto_int16 crypto_int16_r = crypto_int16_x ^ crypto_int16_y;
  crypto_int16 crypto_int16_z = crypto_int16_x - crypto_int16_y;
  crypto_int16_z ^= crypto_int16_r & (crypto_int16_z ^ crypto_int16_x);
  ফেরত crypto_int16_negative_mask(crypto_int16_z);
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int16 crypto_int16_smaller_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n cmpw %3,%2\n cmovlw %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ফেরত crypto_int16_z;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,%w2,sxth\n cset %w0,lt" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ফেরত crypto_int16_z;
#অন্যথা
  crypto_int16 crypto_int16_r = crypto_int16_x ^ crypto_int16_y;
  crypto_int16 crypto_int16_z = crypto_int16_x - crypto_int16_y;
  crypto_int16_z ^= crypto_int16_r & (crypto_int16_z ^ crypto_int16_x);
  ফেরত crypto_int16_unsigned_topbit_01(crypto_int16_z);
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int16 crypto_int16_leq_mask(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n cmpw %3,%2\n cmovlew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ফেরত crypto_int16_z;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,%w2,sxth\n csetm %w0,le" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ফেরত crypto_int16_z;
#অন্যথা
  ফেরত ~crypto_int16_smaller_mask(crypto_int16_y,crypto_int16_x);
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int16 crypto_int16_leq_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n cmpw %3,%2\n cmovlew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ফেরত crypto_int16_z;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,%w2,sxth\n cset %w0,le" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ফেরত crypto_int16_z;
#অন্যথা
  ফেরত 1-crypto_int16_smaller_01(crypto_int16_y,crypto_int16_x);
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
পূর্ণসংখ্যা crypto_int16_ones_অঙ্ক(crypto_int16 crypto_int16_x) {
  crypto_int16_unsigned crypto_int16_y = crypto_int16_x;
  ধ্রুবক crypto_int16 C0 = 0x5555;
  ধ্রুবক crypto_int16 C1 = 0x3333;
  ধ্রুবক crypto_int16 C2 = 0x0f0f;
  crypto_int16_y -= ((crypto_int16_y >> 1) & C0);
  crypto_int16_y = (crypto_int16_y & C1) + ((crypto_int16_y >> 2) & C1);
  crypto_int16_y = (crypto_int16_y + (crypto_int16_y >> 4)) & C2;
  crypto_int16_y = (crypto_int16_y + (crypto_int16_y >> 8)) & 0xff;
  ফেরত crypto_int16_y;
}

__attribute__((unused))
স্থির অন্তঃরেখ
পূর্ণসংখ্যা crypto_int16_bottomzeros_অঙ্ক(crypto_int16 crypto_int16_x) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 fallback = 16;
  __asm__ ("bsfw %0,%0\n cmovew %1,%0" : "+&r"(crypto_int16_x) : "r"(fallback) : "cc");
  ফেরত crypto_int16_x;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  int64_t crypto_int16_y;
  __asm__ ("orr %w0,%w1,-65536\n rbit %w0,%w0\n clz %w0,%w0" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) : );
  ফেরত crypto_int16_y;
#অন্যথা
  crypto_int16 crypto_int16_y = crypto_int16_x ^ (crypto_int16_x-1);
  crypto_int16_y = ((crypto_int16) crypto_int16_y) >> 1;
  crypto_int16_y &= ~(crypto_int16_x & (((crypto_int16) 1) << (16-1)));
  ফেরত crypto_int16_ones_অঙ্ক(crypto_int16_y);
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
স্থির অন্তঃরেখ
crypto_int32 crypto_int32_load(ধ্রুবক unsigned অক্ষর *crypto_int32_s) {
  crypto_int32 crypto_int32_z = 0;
  crypto_int32_z |= ((crypto_int32) (*crypto_int32_s++)) << 0;
  crypto_int32_z |= ((crypto_int32) (*crypto_int32_s++)) << 8;
  crypto_int32_z |= ((crypto_int32) (*crypto_int32_s++)) << 16;
  crypto_int32_z |= ((crypto_int32) (*crypto_int32_s++)) << 24;
  ফেরত crypto_int32_z;
}

__attribute__((unused))
স্থির অন্তঃরেখ
শূন্য crypto_int32_store(unsigned অক্ষর *crypto_int32_s,crypto_int32 crypto_int32_x) {
  *crypto_int32_s++ = crypto_int32_x >> 0;
  *crypto_int32_s++ = crypto_int32_x >> 8;
  *crypto_int32_s++ = crypto_int32_x >> 16;
  *crypto_int32_s++ = crypto_int32_x >> 24;
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int32 crypto_int32_negative_mask(crypto_int32 crypto_int32_x) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarl $31,%0" : "+r"(crypto_int32_x) : : "cc");
  ফেরত crypto_int32_x;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_y;
  __asm__ ("asr %w0,%w1,31" : "=r"(crypto_int32_y) : "r"(crypto_int32_x) : );
  ফেরত crypto_int32_y;
#অন্যথা
  crypto_int32_x >>= 32-6;
  crypto_int32_x ^= crypto_int32_optblocker;
  crypto_int32_x >>= 5;
  ফেরত crypto_int32_x;
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int32_unsigned crypto_int32_unsigned_topbit_01(crypto_int32_unsigned crypto_int32_x) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("shrl $31,%0" : "+r"(crypto_int32_x) : : "cc");
  ফেরত crypto_int32_x;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_y;
  __asm__ ("lsr %w0,%w1,31" : "=r"(crypto_int32_y) : "r"(crypto_int32_x) : );
  ফেরত crypto_int32_y;
#অন্যথা
  crypto_int32_x >>= 32-6;
  crypto_int32_x ^= crypto_int32_optblocker;
  crypto_int32_x >>= 5;
  ফেরত crypto_int32_x;
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int32 crypto_int32_negative_01(crypto_int32 crypto_int32_x) {
  ফেরত crypto_int32_unsigned_topbit_01(crypto_int32_x);
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int32 crypto_int32_topbit_mask(crypto_int32 crypto_int32_x) {
  ফেরত crypto_int32_negative_mask(crypto_int32_x);
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int32 crypto_int32_topbit_01(crypto_int32 crypto_int32_x) {
  ফেরত crypto_int32_unsigned_topbit_01(crypto_int32_x);
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int32 crypto_int32_bottombit_mask(crypto_int32 crypto_int32_x) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andl $1,%0" : "+r"(crypto_int32_x) : : "cc");
  ফেরত -crypto_int32_x;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_y;
  __asm__ ("sbfx %w0,%w1,0,1" : "=r"(crypto_int32_y) : "r"(crypto_int32_x) : );
  ফেরত crypto_int32_y;
#অন্যথা
  crypto_int32_x &= 1 ^ crypto_int32_optblocker;
  ফেরত -crypto_int32_x;
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int32 crypto_int32_bottombit_01(crypto_int32 crypto_int32_x) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andl $1,%0" : "+r"(crypto_int32_x) : : "cc");
  ফেরত crypto_int32_x;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_y;
  __asm__ ("ubfx %w0,%w1,0,1" : "=r"(crypto_int32_y) : "r"(crypto_int32_x) : );
  ফেরত crypto_int32_y;
#অন্যথা
  crypto_int32_x &= 1 ^ crypto_int32_optblocker;
  ফেরত crypto_int32_x;
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int32 crypto_int32_bitinrangepublicpos_mask(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarl %%cl,%0" : "+r"(crypto_int32_x) : "c"(crypto_int32_s) : "cc");
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %w0,%w0,%w1" : "+r"(crypto_int32_x) : "r"(crypto_int32_s) : );
#অন্যথা
  crypto_int32_x >>= crypto_int32_s ^ crypto_int32_optblocker;
#endif
  ফেরত crypto_int32_bottombit_mask(crypto_int32_x);
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int32 crypto_int32_bitinrangepublicpos_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarl %%cl,%0" : "+r"(crypto_int32_x) : "c"(crypto_int32_s) : "cc");
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %w0,%w0,%w1" : "+r"(crypto_int32_x) : "r"(crypto_int32_s) : );
#অন্যথা
  crypto_int32_x >>= crypto_int32_s ^ crypto_int32_optblocker;
#endif
  ফেরত crypto_int32_bottombit_01(crypto_int32_x);
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int32 crypto_int32_shlmod(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("shll %%cl,%0" : "+r"(crypto_int32_x) : "c"(crypto_int32_s) : "cc");
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("lsl %w0,%w0,%w1" : "+r"(crypto_int32_x) : "r"(crypto_int32_s) : );
#অন্যথা
  পূর্ণসংখ্যা crypto_int32_k, crypto_int32_l;
  জন্য (crypto_int32_l = 0,crypto_int32_k = 1;crypto_int32_k < 32;++crypto_int32_l,crypto_int32_k *= 2)
    crypto_int32_x ^= (crypto_int32_x ^ (crypto_int32_x << crypto_int32_k)) & crypto_int32_bitinrangepublicpos_mask(crypto_int32_s,crypto_int32_l);
#endif
  ফেরত crypto_int32_x;
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int32 crypto_int32_shrmod(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarl %%cl,%0" : "+r"(crypto_int32_x) : "c"(crypto_int32_s) : "cc");
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %w0,%w0,%w1" : "+r"(crypto_int32_x) : "r"(crypto_int32_s) : );
#অন্যথা
  পূর্ণসংখ্যা crypto_int32_k, crypto_int32_l;
  জন্য (crypto_int32_l = 0,crypto_int32_k = 1;crypto_int32_k < 32;++crypto_int32_l,crypto_int32_k *= 2)
    crypto_int32_x ^= (crypto_int32_x ^ (crypto_int32_x >> crypto_int32_k)) & crypto_int32_bitinrangepublicpos_mask(crypto_int32_s,crypto_int32_l);
#endif
  ফেরত crypto_int32_x;
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int32 crypto_int32_bitmod_mask(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
  crypto_int32_x = crypto_int32_shrmod(crypto_int32_x,crypto_int32_s);
  ফেরত crypto_int32_bottombit_mask(crypto_int32_x);
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int32 crypto_int32_bitmod_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
  crypto_int32_x = crypto_int32_shrmod(crypto_int32_x,crypto_int32_s);
  ফেরত crypto_int32_bottombit_01(crypto_int32_x);
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int32 crypto_int32_nonzero_mask(crypto_int32 crypto_int32_x) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n testl %2,%2\n cmovnel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  ফেরত crypto_int32_z;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n csetm %w0,ne" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  ফেরত crypto_int32_z;
#অন্যথা
  crypto_int32_x |= -crypto_int32_x;
  ফেরত crypto_int32_negative_mask(crypto_int32_x);
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int32 crypto_int32_nonzero_01(crypto_int32 crypto_int32_x) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n testl %2,%2\n cmovnel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  ফেরত crypto_int32_z;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n cset %w0,ne" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  ফেরত crypto_int32_z;
#অন্যথা
  crypto_int32_x |= -crypto_int32_x;
  ফেরত crypto_int32_unsigned_topbit_01(crypto_int32_x);
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int32 crypto_int32_positive_mask(crypto_int32 crypto_int32_x) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n testl %2,%2\n cmovgl %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  ফেরত crypto_int32_z;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n csetm %w0,gt" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  ফেরত crypto_int32_z;
#অন্যথা
  crypto_int32 crypto_int32_z = -crypto_int32_x;
  crypto_int32_z ^= crypto_int32_x & crypto_int32_z;
  ফেরত crypto_int32_negative_mask(crypto_int32_z);
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int32 crypto_int32_positive_01(crypto_int32 crypto_int32_x) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n testl %2,%2\n cmovgl %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  ফেরত crypto_int32_z;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n cset %w0,gt" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  ফেরত crypto_int32_z;
#অন্যথা
  crypto_int32 crypto_int32_z = -crypto_int32_x;
  crypto_int32_z ^= crypto_int32_x & crypto_int32_z;
  ফেরত crypto_int32_unsigned_topbit_01(crypto_int32_z);
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int32 crypto_int32_zero_mask(crypto_int32 crypto_int32_x) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n testl %2,%2\n cmovel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  ফেরত crypto_int32_z;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n csetm %w0,eq" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  ফেরত crypto_int32_z;
#অন্যথা
  ফেরত ~crypto_int32_nonzero_mask(crypto_int32_x);
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int32 crypto_int32_zero_01(crypto_int32 crypto_int32_x) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n testl %2,%2\n cmovel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  ফেরত crypto_int32_z;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n cset %w0,eq" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  ফেরত crypto_int32_z;
#অন্যথা
  ফেরত 1-crypto_int32_nonzero_01(crypto_int32_x);
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int32 crypto_int32_unequal_mask(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n cmpl %3,%2\n cmovnel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ফেরত crypto_int32_z;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n csetm %w0,ne" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ফেরত crypto_int32_z;
#অন্যথা
  ফেরত crypto_int32_nonzero_mask(crypto_int32_x ^ crypto_int32_y);
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int32 crypto_int32_unequal_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n cmpl %3,%2\n cmovnel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ফেরত crypto_int32_z;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n cset %w0,ne" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ফেরত crypto_int32_z;
#অন্যথা
  ফেরত crypto_int32_nonzero_01(crypto_int32_x ^ crypto_int32_y);
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int32 crypto_int32_equal_mask(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n cmpl %3,%2\n cmovel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ফেরত crypto_int32_z;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n csetm %w0,eq" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ফেরত crypto_int32_z;
#অন্যথা
  ফেরত ~crypto_int32_unequal_mask(crypto_int32_x,crypto_int32_y);
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int32 crypto_int32_equal_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n cmpl %3,%2\n cmovel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ফেরত crypto_int32_z;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n cset %w0,eq" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ফেরত crypto_int32_z;
#অন্যথা
  ফেরত 1-crypto_int32_unequal_01(crypto_int32_x,crypto_int32_y);
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int32 crypto_int32_min(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpl %1,%0\n cmovgl %1,%0" : "+r"(crypto_int32_x) : "r"(crypto_int32_y) : "cc");
  ফেরত crypto_int32_x;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("cmp %w0,%w1\n csel %w0,%w0,%w1,lt" : "+r"(crypto_int32_x) : "r"(crypto_int32_y) : "cc");
  ফেরত crypto_int32_x;
#অন্যথা
  crypto_int64 crypto_int32_r = (crypto_int64)crypto_int32_y ^ (crypto_int64)crypto_int32_x;
  crypto_int64 crypto_int32_z = (crypto_int64)crypto_int32_y - (crypto_int64)crypto_int32_x;
  crypto_int32_z ^= crypto_int32_r & (crypto_int32_z ^ crypto_int32_y);
  crypto_int32_z = crypto_int32_negative_mask(crypto_int32_z);
  crypto_int32_z &= crypto_int32_r;
  ফেরত crypto_int32_x ^ crypto_int32_z;
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int32 crypto_int32_max(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpl %1,%0\n cmovll %1,%0" : "+r"(crypto_int32_x) : "r"(crypto_int32_y) : "cc");
  ফেরত crypto_int32_x;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("cmp %w0,%w1\n csel %w0,%w1,%w0,lt" : "+r"(crypto_int32_x) : "r"(crypto_int32_y) : "cc");
  ফেরত crypto_int32_x;
#অন্যথা
  crypto_int64 crypto_int32_r = (crypto_int64)crypto_int32_y ^ (crypto_int64)crypto_int32_x;
  crypto_int64 crypto_int32_z = (crypto_int64)crypto_int32_y - (crypto_int64)crypto_int32_x;
  crypto_int32_z ^= crypto_int32_r & (crypto_int32_z ^ crypto_int32_y);
  crypto_int32_z = crypto_int32_negative_mask(crypto_int32_z);
  crypto_int32_z &= crypto_int32_r;
  ফেরত crypto_int32_y ^ crypto_int32_z;
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
শূন্য crypto_int32_minmax(crypto_int32 *crypto_int32_p,crypto_int32 *crypto_int32_q) {
  crypto_int32 crypto_int32_x = *crypto_int32_p;
  crypto_int32 crypto_int32_y = *crypto_int32_q;
#যদি defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmpl %2,%1\n movl %1,%0\n cmovgl %2,%1\n cmovgl %0,%2" : "=&r"(crypto_int32_z), "+&r"(crypto_int32_x), "+r"(crypto_int32_y) : : "cc");
  *crypto_int32_p = crypto_int32_x;
  *crypto_int32_q = crypto_int32_y;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_r, crypto_int32_s;
  __asm__ ("cmp %w2,%w3\n csel %w0,%w2,%w3,lt\n csel %w1,%w3,%w2,lt" : "=&r"(crypto_int32_r), "=r"(crypto_int32_s) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  *crypto_int32_p = crypto_int32_r;
  *crypto_int32_q = crypto_int32_s;
#অন্যথা
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
স্থির অন্তঃরেখ
crypto_int32 crypto_int32_smaller_mask(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n cmpl %3,%2\n cmovll %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ফেরত crypto_int32_z;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n csetm %w0,lt" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ফেরত crypto_int32_z;
#অন্যথা
  crypto_int32 crypto_int32_r = crypto_int32_x ^ crypto_int32_y;
  crypto_int32 crypto_int32_z = crypto_int32_x - crypto_int32_y;
  crypto_int32_z ^= crypto_int32_r & (crypto_int32_z ^ crypto_int32_x);
  ফেরত crypto_int32_negative_mask(crypto_int32_z);
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int32 crypto_int32_smaller_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n cmpl %3,%2\n cmovll %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ফেরত crypto_int32_z;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n cset %w0,lt" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ফেরত crypto_int32_z;
#অন্যথা
  crypto_int32 crypto_int32_r = crypto_int32_x ^ crypto_int32_y;
  crypto_int32 crypto_int32_z = crypto_int32_x - crypto_int32_y;
  crypto_int32_z ^= crypto_int32_r & (crypto_int32_z ^ crypto_int32_x);
  ফেরত crypto_int32_unsigned_topbit_01(crypto_int32_z);
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int32 crypto_int32_leq_mask(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n cmpl %3,%2\n cmovlel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ফেরত crypto_int32_z;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n csetm %w0,le" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ফেরত crypto_int32_z;
#অন্যথা
  ফেরত ~crypto_int32_smaller_mask(crypto_int32_y,crypto_int32_x);
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int32 crypto_int32_leq_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n cmpl %3,%2\n cmovlel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ফেরত crypto_int32_z;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n cset %w0,le" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ফেরত crypto_int32_z;
#অন্যথা
  ফেরত 1-crypto_int32_smaller_01(crypto_int32_y,crypto_int32_x);
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
পূর্ণসংখ্যা crypto_int32_ones_অঙ্ক(crypto_int32 crypto_int32_x) {
  crypto_int32_unsigned crypto_int32_y = crypto_int32_x;
  ধ্রুবক crypto_int32 C0 = 0x55555555;
  ধ্রুবক crypto_int32 C1 = 0x33333333;
  ধ্রুবক crypto_int32 C2 = 0x0f0f0f0f;
  crypto_int32_y -= ((crypto_int32_y >> 1) & C0);
  crypto_int32_y = (crypto_int32_y & C1) + ((crypto_int32_y >> 2) & C1);
  crypto_int32_y = (crypto_int32_y + (crypto_int32_y >> 4)) & C2;
  crypto_int32_y += crypto_int32_y >> 8;
  crypto_int32_y = (crypto_int32_y + (crypto_int32_y >> 16)) & 0xff;
  ফেরত crypto_int32_y;
}

__attribute__((unused))
স্থির অন্তঃরেখ
পূর্ণসংখ্যা crypto_int32_bottomzeros_অঙ্ক(crypto_int32 crypto_int32_x) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 fallback = 32;
  __asm__ ("bsfl %0,%0\n cmovel %1,%0" : "+&r"(crypto_int32_x) : "r"(fallback) : "cc");
  ফেরত crypto_int32_x;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  int64_t crypto_int32_y;
  __asm__ ("rbit %w0,%w1\n clz %w0,%w0" : "=r"(crypto_int32_y) : "r"(crypto_int32_x) : );
  ফেরত crypto_int32_y;
#অন্যথা
  crypto_int32 crypto_int32_y = crypto_int32_x ^ (crypto_int32_x-1);
  crypto_int32_y = ((crypto_int32) crypto_int32_y) >> 1;
  crypto_int32_y &= ~(crypto_int32_x & (((crypto_int32) 1) << (32-1)));
  ফেরত crypto_int32_ones_অঙ্ক(crypto_int32_y);
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
স্থির অন্তঃরেখ
crypto_int64 crypto_int64_load(ধ্রুবক unsigned অক্ষর *crypto_int64_s) {
  crypto_int64 crypto_int64_z = 0;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 0;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 8;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 16;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 24;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 32;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 40;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 48;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 56;
  ফেরত crypto_int64_z;
}

__attribute__((unused))
স্থির অন্তঃরেখ
শূন্য crypto_int64_store(unsigned অক্ষর *crypto_int64_s,crypto_int64 crypto_int64_x) {
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
স্থির অন্তঃরেখ
crypto_int64 crypto_int64_negative_mask(crypto_int64 crypto_int64_x) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarq $63,%0" : "+r"(crypto_int64_x) : : "cc");
  ফেরত crypto_int64_x;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_y;
  __asm__ ("asr %0,%1,63" : "=r"(crypto_int64_y) : "r"(crypto_int64_x) : );
  ফেরত crypto_int64_y;
#অন্যথা
  crypto_int64_x >>= 64-6;
  crypto_int64_x ^= crypto_int64_optblocker;
  crypto_int64_x >>= 5;
  ফেরত crypto_int64_x;
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int64_unsigned crypto_int64_unsigned_topbit_01(crypto_int64_unsigned crypto_int64_x) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("shrq $63,%0" : "+r"(crypto_int64_x) : : "cc");
  ফেরত crypto_int64_x;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_y;
  __asm__ ("lsr %0,%1,63" : "=r"(crypto_int64_y) : "r"(crypto_int64_x) : );
  ফেরত crypto_int64_y;
#অন্যথা
  crypto_int64_x >>= 64-6;
  crypto_int64_x ^= crypto_int64_optblocker;
  crypto_int64_x >>= 5;
  ফেরত crypto_int64_x;
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int64 crypto_int64_negative_01(crypto_int64 crypto_int64_x) {
  ফেরত crypto_int64_unsigned_topbit_01(crypto_int64_x);
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int64 crypto_int64_topbit_mask(crypto_int64 crypto_int64_x) {
  ফেরত crypto_int64_negative_mask(crypto_int64_x);
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int64 crypto_int64_topbit_01(crypto_int64 crypto_int64_x) {
  ফেরত crypto_int64_unsigned_topbit_01(crypto_int64_x);
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int64 crypto_int64_bottombit_mask(crypto_int64 crypto_int64_x) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andq $1,%0" : "+r"(crypto_int64_x) : : "cc");
  ফেরত -crypto_int64_x;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_y;
  __asm__ ("sbfx %0,%1,0,1" : "=r"(crypto_int64_y) : "r"(crypto_int64_x) : );
  ফেরত crypto_int64_y;
#অন্যথা
  crypto_int64_x &= 1 ^ crypto_int64_optblocker;
  ফেরত -crypto_int64_x;
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int64 crypto_int64_bottombit_01(crypto_int64 crypto_int64_x) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andq $1,%0" : "+r"(crypto_int64_x) : : "cc");
  ফেরত crypto_int64_x;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_y;
  __asm__ ("ubfx %0,%1,0,1" : "=r"(crypto_int64_y) : "r"(crypto_int64_x) : );
  ফেরত crypto_int64_y;
#অন্যথা
  crypto_int64_x &= 1 ^ crypto_int64_optblocker;
  ফেরত crypto_int64_x;
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int64 crypto_int64_bitinrangepublicpos_mask(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarq %%cl,%0" : "+r"(crypto_int64_x) : "c"(crypto_int64_s) : "cc");
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %0,%0,%1" : "+r"(crypto_int64_x) : "r"(crypto_int64_s) : );
#অন্যথা
  crypto_int64_x >>= crypto_int64_s ^ crypto_int64_optblocker;
#endif
  ফেরত crypto_int64_bottombit_mask(crypto_int64_x);
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int64 crypto_int64_bitinrangepublicpos_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarq %%cl,%0" : "+r"(crypto_int64_x) : "c"(crypto_int64_s) : "cc");
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %0,%0,%1" : "+r"(crypto_int64_x) : "r"(crypto_int64_s) : );
#অন্যথা
  crypto_int64_x >>= crypto_int64_s ^ crypto_int64_optblocker;
#endif
  ফেরত crypto_int64_bottombit_01(crypto_int64_x);
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int64 crypto_int64_shlmod(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("shlq %%cl,%0" : "+r"(crypto_int64_x) : "c"(crypto_int64_s) : "cc");
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("lsl %0,%0,%1" : "+r"(crypto_int64_x) : "r"(crypto_int64_s) : );
#অন্যথা
  পূর্ণসংখ্যা crypto_int64_k, crypto_int64_l;
  জন্য (crypto_int64_l = 0,crypto_int64_k = 1;crypto_int64_k < 64;++crypto_int64_l,crypto_int64_k *= 2)
    crypto_int64_x ^= (crypto_int64_x ^ (crypto_int64_x << crypto_int64_k)) & crypto_int64_bitinrangepublicpos_mask(crypto_int64_s,crypto_int64_l);
#endif
  ফেরত crypto_int64_x;
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int64 crypto_int64_shrmod(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarq %%cl,%0" : "+r"(crypto_int64_x) : "c"(crypto_int64_s) : "cc");
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %0,%0,%1" : "+r"(crypto_int64_x) : "r"(crypto_int64_s) : );
#অন্যথা
  পূর্ণসংখ্যা crypto_int64_k, crypto_int64_l;
  জন্য (crypto_int64_l = 0,crypto_int64_k = 1;crypto_int64_k < 64;++crypto_int64_l,crypto_int64_k *= 2)
    crypto_int64_x ^= (crypto_int64_x ^ (crypto_int64_x >> crypto_int64_k)) & crypto_int64_bitinrangepublicpos_mask(crypto_int64_s,crypto_int64_l);
#endif
  ফেরত crypto_int64_x;
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int64 crypto_int64_bitmod_mask(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
  crypto_int64_x = crypto_int64_shrmod(crypto_int64_x,crypto_int64_s);
  ফেরত crypto_int64_bottombit_mask(crypto_int64_x);
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int64 crypto_int64_bitmod_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
  crypto_int64_x = crypto_int64_shrmod(crypto_int64_x,crypto_int64_s);
  ফেরত crypto_int64_bottombit_01(crypto_int64_x);
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int64 crypto_int64_nonzero_mask(crypto_int64 crypto_int64_x) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n testq %2,%2\n cmovneq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  ফেরত crypto_int64_z;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n csetm %0,ne" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  ফেরত crypto_int64_z;
#অন্যথা
  crypto_int64_x |= -crypto_int64_x;
  ফেরত crypto_int64_negative_mask(crypto_int64_x);
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int64 crypto_int64_nonzero_01(crypto_int64 crypto_int64_x) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n testq %2,%2\n cmovneq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  ফেরত crypto_int64_z;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n cset %0,ne" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  ফেরত crypto_int64_z;
#অন্যথা
  crypto_int64_x |= -crypto_int64_x;
  ফেরত crypto_int64_unsigned_topbit_01(crypto_int64_x);
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int64 crypto_int64_positive_mask(crypto_int64 crypto_int64_x) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n testq %2,%2\n cmovgq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  ফেরত crypto_int64_z;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n csetm %0,gt" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  ফেরত crypto_int64_z;
#অন্যথা
  crypto_int64 crypto_int64_z = -crypto_int64_x;
  crypto_int64_z ^= crypto_int64_x & crypto_int64_z;
  ফেরত crypto_int64_negative_mask(crypto_int64_z);
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int64 crypto_int64_positive_01(crypto_int64 crypto_int64_x) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n testq %2,%2\n cmovgq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  ফেরত crypto_int64_z;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n cset %0,gt" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  ফেরত crypto_int64_z;
#অন্যথা
  crypto_int64 crypto_int64_z = -crypto_int64_x;
  crypto_int64_z ^= crypto_int64_x & crypto_int64_z;
  ফেরত crypto_int64_unsigned_topbit_01(crypto_int64_z);
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int64 crypto_int64_zero_mask(crypto_int64 crypto_int64_x) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n testq %2,%2\n cmoveq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  ফেরত crypto_int64_z;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n csetm %0,eq" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  ফেরত crypto_int64_z;
#অন্যথা
  ফেরত ~crypto_int64_nonzero_mask(crypto_int64_x);
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int64 crypto_int64_zero_01(crypto_int64 crypto_int64_x) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n testq %2,%2\n cmoveq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  ফেরত crypto_int64_z;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n cset %0,eq" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  ফেরত crypto_int64_z;
#অন্যথা
  ফেরত 1-crypto_int64_nonzero_01(crypto_int64_x);
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int64 crypto_int64_unequal_mask(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n cmpq %3,%2\n cmovneq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ফেরত crypto_int64_z;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n csetm %0,ne" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ফেরত crypto_int64_z;
#অন্যথা
  ফেরত crypto_int64_nonzero_mask(crypto_int64_x ^ crypto_int64_y);
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int64 crypto_int64_unequal_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n cmpq %3,%2\n cmovneq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ফেরত crypto_int64_z;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n cset %0,ne" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ফেরত crypto_int64_z;
#অন্যথা
  ফেরত crypto_int64_nonzero_01(crypto_int64_x ^ crypto_int64_y);
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int64 crypto_int64_equal_mask(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n cmpq %3,%2\n cmoveq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ফেরত crypto_int64_z;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n csetm %0,eq" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ফেরত crypto_int64_z;
#অন্যথা
  ফেরত ~crypto_int64_unequal_mask(crypto_int64_x,crypto_int64_y);
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int64 crypto_int64_equal_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n cmpq %3,%2\n cmoveq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ফেরত crypto_int64_z;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n cset %0,eq" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ফেরত crypto_int64_z;
#অন্যথা
  ফেরত 1-crypto_int64_unequal_01(crypto_int64_x,crypto_int64_y);
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int64 crypto_int64_min(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpq %1,%0\n cmovgq %1,%0" : "+r"(crypto_int64_x) : "r"(crypto_int64_y) : "cc");
  ফেরত crypto_int64_x;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("cmp %0,%1\n csel %0,%0,%1,lt" : "+r"(crypto_int64_x) : "r"(crypto_int64_y) : "cc");
  ফেরত crypto_int64_x;
#অন্যথা
  crypto_int64 crypto_int64_r = crypto_int64_y ^ crypto_int64_x;
  crypto_int64 crypto_int64_z = crypto_int64_y - crypto_int64_x;
  crypto_int64_z ^= crypto_int64_r & (crypto_int64_z ^ crypto_int64_y);
  crypto_int64_z = crypto_int64_negative_mask(crypto_int64_z);
  crypto_int64_z &= crypto_int64_r;
  ফেরত crypto_int64_x ^ crypto_int64_z;
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int64 crypto_int64_max(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpq %1,%0\n cmovlq %1,%0" : "+r"(crypto_int64_x) : "r"(crypto_int64_y) : "cc");
  ফেরত crypto_int64_x;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("cmp %0,%1\n csel %0,%1,%0,lt" : "+r"(crypto_int64_x) : "r"(crypto_int64_y) : "cc");
  ফেরত crypto_int64_x;
#অন্যথা
  crypto_int64 crypto_int64_r = crypto_int64_y ^ crypto_int64_x;
  crypto_int64 crypto_int64_z = crypto_int64_y - crypto_int64_x;
  crypto_int64_z ^= crypto_int64_r & (crypto_int64_z ^ crypto_int64_y);
  crypto_int64_z = crypto_int64_negative_mask(crypto_int64_z);
  crypto_int64_z &= crypto_int64_r;
  ফেরত crypto_int64_y ^ crypto_int64_z;
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
শূন্য crypto_int64_minmax(crypto_int64 *crypto_int64_p,crypto_int64 *crypto_int64_q) {
  crypto_int64 crypto_int64_x = *crypto_int64_p;
  crypto_int64 crypto_int64_y = *crypto_int64_q;
#যদি defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmpq %2,%1\n movq %1,%0\n cmovgq %2,%1\n cmovgq %0,%2" : "=&r"(crypto_int64_z), "+&r"(crypto_int64_x), "+r"(crypto_int64_y) : : "cc");
  *crypto_int64_p = crypto_int64_x;
  *crypto_int64_q = crypto_int64_y;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_r, crypto_int64_s;
  __asm__ ("cmp %2,%3\n csel %0,%2,%3,lt\n csel %1,%3,%2,lt" : "=&r"(crypto_int64_r), "=r"(crypto_int64_s) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  *crypto_int64_p = crypto_int64_r;
  *crypto_int64_q = crypto_int64_s;
#অন্যথা
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
স্থির অন্তঃরেখ
crypto_int64 crypto_int64_smaller_mask(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n cmpq %3,%2\n cmovlq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ফেরত crypto_int64_z;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n csetm %0,lt" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ফেরত crypto_int64_z;
#অন্যথা
  crypto_int64 crypto_int64_r = crypto_int64_x ^ crypto_int64_y;
  crypto_int64 crypto_int64_z = crypto_int64_x - crypto_int64_y;
  crypto_int64_z ^= crypto_int64_r & (crypto_int64_z ^ crypto_int64_x);
  ফেরত crypto_int64_negative_mask(crypto_int64_z);
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int64 crypto_int64_smaller_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n cmpq %3,%2\n cmovlq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ফেরত crypto_int64_z;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n cset %0,lt" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ফেরত crypto_int64_z;
#অন্যথা
  crypto_int64 crypto_int64_r = crypto_int64_x ^ crypto_int64_y;
  crypto_int64 crypto_int64_z = crypto_int64_x - crypto_int64_y;
  crypto_int64_z ^= crypto_int64_r & (crypto_int64_z ^ crypto_int64_x);
  ফেরত crypto_int64_unsigned_topbit_01(crypto_int64_z);
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int64 crypto_int64_leq_mask(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n cmpq %3,%2\n cmovleq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ফেরত crypto_int64_z;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n csetm %0,le" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ফেরত crypto_int64_z;
#অন্যথা
  ফেরত ~crypto_int64_smaller_mask(crypto_int64_y,crypto_int64_x);
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
crypto_int64 crypto_int64_leq_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n cmpq %3,%2\n cmovleq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ফেরত crypto_int64_z;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n cset %0,le" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ফেরত crypto_int64_z;
#অন্যথা
  ফেরত 1-crypto_int64_smaller_01(crypto_int64_y,crypto_int64_x);
#endif
}

__attribute__((unused))
স্থির অন্তঃরেখ
পূর্ণসংখ্যা crypto_int64_ones_অঙ্ক(crypto_int64 crypto_int64_x) {
  crypto_int64_unsigned crypto_int64_y = crypto_int64_x;
  ধ্রুবক crypto_int64 C0 = 0x5555555555555555;
  ধ্রুবক crypto_int64 C1 = 0x3333333333333333;
  ধ্রুবক crypto_int64 C2 = 0x0f0f0f0f0f0f0f0f;
  crypto_int64_y -= ((crypto_int64_y >> 1) & C0);
  crypto_int64_y = (crypto_int64_y & C1) + ((crypto_int64_y >> 2) & C1);
  crypto_int64_y = (crypto_int64_y + (crypto_int64_y >> 4)) & C2;
  crypto_int64_y += crypto_int64_y >> 8;
  crypto_int64_y += crypto_int64_y >> 16;
  crypto_int64_y = (crypto_int64_y + (crypto_int64_y >> 32)) & 0xff;
  ফেরত crypto_int64_y;
}

__attribute__((unused))
স্থির অন্তঃরেখ
পূর্ণসংখ্যা crypto_int64_bottomzeros_অঙ্ক(crypto_int64 crypto_int64_x) {
#যদি defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 fallback = 64;
  __asm__ ("bsfq %0,%0\n cmoveq %1,%0" : "+&r"(crypto_int64_x) : "r"(fallback) : "cc");
  ফেরত crypto_int64_x;
#নতুবা_যদি defined(__GNUC__) && defined(__aarch64__)
  int64_t crypto_int64_y;
  __asm__ ("rbit %0,%1\n clz %0,%0" : "=r"(crypto_int64_y) : "r"(crypto_int64_x) : );
  ফেরত crypto_int64_y;
#অন্যথা
  crypto_int64 crypto_int64_y = crypto_int64_x ^ (crypto_int64_x-1);
  crypto_int64_y = ((crypto_int64) crypto_int64_y) >> 1;
  crypto_int64_y &= ~(crypto_int64_x & (((crypto_int64) 1) << (64-1)));
  ফেরত crypto_int64_ones_অঙ্ক(crypto_int64_y);
#endif
}

#endif

/* from supercop-20240808/crypto_sort/int32/portable4/sort.c */
#define int32_MINMAX(a,b) crypto_int32_minmax(&a,&b)

স্থির শূন্য crypto_sort_int32(শূন্য *array,long long n)
{
  long long শীর্ষ,p,q,r,i,j;
  int32 *x = array;

  যদি (n < 2) ফেরত;
  শীর্ষ = 1;
  যখন (শীর্ষ < n - শীর্ষ) শীর্ষ += শীর্ষ;

  জন্য (p = শীর্ষ;p >= 1;p >>= 1) {
    i = 0;
    যখন (i + 2 * p <= n) {
      জন্য (j = i;j < i + p;++j)
        int32_MINMAX(x[j],x[j+p]);
      i += 2 * p;
    }
    জন্য (j = i;j < n - p;++j)
      int32_MINMAX(x[j],x[j+p]);

    i = 0;
    j = 0;
    জন্য (q = শীর্ষ;q > p;q >>= 1) {
      যদি (j != i) জন্য (;;) {
        যদি (j == n - q) যাও done;
        int32 a = x[j + p];
        জন্য (r = q;r > p;r >>= 1)
          int32_MINMAX(a,x[j + r]);
        x[j + p] = a;
        ++j;
        যদি (j == i + p) {
          i += 2 * p;
          বিরতি;
        }
      }
      যখন (i + p <= n - q) {
        জন্য (j = i;j < i + p;++j) {
          int32 a = x[j + p];
          জন্য (r = q;r > p;r >>= 1)
            int32_MINMAX(a,x[j+r]);
          x[j + p] = a;
        }
        i += 2 * p;
      }
      /* now i + p > n - q */
      j = i;
      যখন (j < n - q) {
        int32 a = x[j + p];
        জন্য (r = q;r > p;r >>= 1)
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

স্থির শূন্য crypto_sort_uint32(শূন্য *array,long long n)
{
  crypto_uint32 *x = array;
  long long j;
  জন্য (j = 0;j < n;++j) x[j] ^= 0x80000000;
  crypto_sort_int32(array,n);
  জন্য (j = 0;j < n;++j) x[j] ^= 0x80000000;
}

/* from supercop-20240808/crypto_kem/sntrup761/compact/kem.c */
// 20240806 djb: some automated conversion to cryptoint

#define p 761
#define q 4591
#define w 286
#define q12 ((q - 1) / 2)
প্রকারলেখ int8_t small;
প্রকারলেখ int16_t Fq;
#define Hash_bytes 32
#define Small_bytes ((p + 3) / 4)
প্রকারলেখ small Inputs[p];
#define Secret_চাবিগুলি_bytes (2 * Small_bytes)
#define Confirm_bytes 32

স্থির small F3_freeze(int16_t x) { ফেরত x - 3 * ((10923 * x + 16384) >> 15); }

স্থির Fq Fq_freeze(int32_t x) {
  ধ্রুবক int32_t q16 = (0x10000 + q / 2) / q;
  ধ্রুবক int32_t q20 = (0x100000 + q / 2) / q;
  ধ্রুবক int32_t q28 = (0x10000000 + q / 2) / q;
  x -= q * ((q16 * x) >> 16);
  x -= q * ((q20 * x) >> 20);
  ফেরত x - q * ((q28 * x + 0x8000000) >> 28);
}

স্থির পূর্ণসংখ্যা Weightw_mask(small *r) {
  পূর্ণসংখ্যা i, weight = 0;
  জন্য (i = 0; i < p; ++i) weight += crypto_int64_bottombit_01(r[i]);
  ফেরত crypto_int16_nonzero_mask(weight - w);
}

স্থির শূন্য uint32_divmod_uint14(uint32_t *Q, uint16_t *r, uint32_t x, uint16_t m) {
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

স্থির uint16_t uint32_mod_uint14(uint32_t x, uint16_t m) {
  uint32_t Q;
  uint16_t r;
  uint32_divmod_uint14(&Q, &r, x, m);
  ফেরত r;
}

স্থির শূন্য Encode(unsigned অক্ষর *out, ধ্রুবক uint16_t *R, ধ্রুবক uint16_t *M, long long len) {
  যদি (len == 1) {
    uint16_t r = R[0], m = M[0];
    যখন (m > 1) {
      *out++ = r;
      r >>= 8;
      m = (m + 255) >> 8;
    }
  }
  যদি (len > 1) {
    uint16_t R2[(len + 1) / 2], M2[(len + 1) / 2];
    long long i;
    জন্য (i = 0; i < len - 1; i += 2) {
      uint32_t m0 = M[i];
      uint32_t r = R[i] + R[i + 1] * m0;
      uint32_t m = M[i + 1] * m0;
      যখন (m >= 16384) {
        *out++ = r;
        r >>= 8;
        m = (m + 255) >> 8;
      }
      R2[i / 2] = r;
      M2[i / 2] = m;
    }
    যদি (i < len) {
      R2[i / 2] = R[i];
      M2[i / 2] = M[i];
    }
    Encode(out, R2, M2, (len + 1) / 2);
  }
}

স্থির শূন্য Decode(uint16_t *out, ধ্রুবক unsigned অক্ষর *S, ধ্রুবক uint16_t *M, long long len) {
  যদি (len == 1) {
    যদি (M[0] == 1)
      *out = 0;
    অন্যথা যদি (M[0] <= 256)
      *out = uint32_mod_uint14(S[0], M[0]);
    অন্যথা
      *out = uint32_mod_uint14(S[0] + (((uint16_t)S[1]) << 8), M[0]);
  }
  যদি (len > 1) {
    uint16_t R2[(len + 1) / 2], M2[(len + 1) / 2], bottomr[len / 2];
    uint32_t bottomt[len / 2];
    long long i;
    জন্য (i = 0; i < len - 1; i += 2) {
      uint32_t m = M[i] * (uint32_t)M[i + 1];
      যদি (m > 256 * 16383) {
        bottomt[i / 2] = 256 * 256;
        bottomr[i / 2] = S[0] + 256 * S[1];
        S += 2;
        M2[i / 2] = (((m + 255) >> 8) + 255) >> 8;
      } অন্যথা যদি (m >= 16384) {
        bottomt[i / 2] = 256;
        bottomr[i / 2] = S[0];
        S += 1;
        M2[i / 2] = (m + 255) >> 8;
      } অন্যথা {
        bottomt[i / 2] = 1;
        bottomr[i / 2] = 0;
        M2[i / 2] = m;
      }
    }
    যদি (i < len) M2[i / 2] = M[i];
    Decode(R2, S, M2, (len + 1) / 2);
    জন্য (i = 0; i < len - 1; i += 2) {
      uint32_t r1, r = bottomr[i / 2];
      uint16_t r0;
      r += bottomt[i / 2] * R2[i / 2];
      uint32_divmod_uint14(&r1, &r0, r, M[i]);
      r1 = uint32_mod_uint14(r1, M[i + 1]);
      *out++ = r0;
      *out++ = r1;
    }
    যদি (i < len) *out++ = R2[i / 2];
  }
}

স্থির শূন্য R3_fromRq(small *out, ধ্রুবক Fq *r) {
  পূর্ণসংখ্যা i;
  জন্য (i = 0; i < p; ++i) out[i] = F3_freeze(r[i]);
}

স্থির শূন্য R3_mult(small *h, ধ্রুবক small *f, ধ্রুবক small *g) {
  int16_t fg[p + p - 1];
  পূর্ণসংখ্যা i, j;
  জন্য (i = 0; i < p + p - 1; ++i) fg[i] = 0;
  জন্য (i = 0; i < p; ++i)
    জন্য (j = 0; j < p; ++j) fg[i + j] += f[i] * (int16_t)g[j];
  জন্য (i = p; i < p + p - 1; ++i) fg[i - p] += fg[i];
  জন্য (i = p; i < p + p - 1; ++i) fg[i - p + 1] += fg[i];
  জন্য (i = 0; i < p; ++i) h[i] = F3_freeze(fg[i]);
}

স্থির পূর্ণসংখ্যা R3_recip(small *out, ধ্রুবক small *in) {
  small f[p + 1], g[p + 1], v[p + 1], r[p + 1];
  পূর্ণসংখ্যা sign, swap, t, i, loop, delta = 1;
  জন্য (i = 0; i < p + 1; ++i) v[i] = 0;
  জন্য (i = 0; i < p + 1; ++i) r[i] = 0;
  r[0] = 1;
  জন্য (i = 0; i < p; ++i) f[i] = 0;
  f[0] = 1;
  f[p - 1] = f[p] = -1;
  জন্য (i = 0; i < p; ++i) g[p - 1 - i] = in[i];
  g[p] = 0;
  জন্য (loop = 0; loop < 2 * p - 1; ++loop) {
    জন্য (i = p; i > 0; --i) v[i] = v[i - 1];
    v[0] = 0;
    sign = -g[0] * f[0];
    swap = crypto_int16_negative_mask(-delta) & crypto_int16_nonzero_mask(g[0]);
    delta ^= swap & (delta ^ -delta);
    delta += 1;
    জন্য (i = 0; i < p + 1; ++i) {
      t = swap & (f[i] ^ g[i]);
      f[i] ^= t;
      g[i] ^= t;
      t = swap & (v[i] ^ r[i]);
      v[i] ^= t;
      r[i] ^= t;
    }
    জন্য (i = 0; i < p + 1; ++i) g[i] = F3_freeze(g[i] + sign * f[i]);
    জন্য (i = 0; i < p + 1; ++i) r[i] = F3_freeze(r[i] + sign * v[i]);
    জন্য (i = 0; i < p; ++i) g[i] = g[i + 1];
    g[p] = 0;
  }
  sign = f[0];
  জন্য (i = 0; i < p; ++i) out[i] = sign * v[p - 1 - i];
  ফেরত crypto_int16_nonzero_mask(delta);
}

স্থির শূন্য Rq_mult_small(Fq *h, ধ্রুবক Fq *f, ধ্রুবক small *g) {
  int32_t fg[p + p - 1];
  পূর্ণসংখ্যা i, j;
  জন্য (i = 0; i < p + p - 1; ++i) fg[i] = 0;
  জন্য (i = 0; i < p; ++i)
    জন্য (j = 0; j < p; ++j) fg[i + j] += f[i] * (int32_t)g[j];
  জন্য (i = p; i < p + p - 1; ++i) fg[i - p] += fg[i];
  জন্য (i = p; i < p + p - 1; ++i) fg[i - p + 1] += fg[i];
  জন্য (i = 0; i < p; ++i) h[i] = Fq_freeze(fg[i]);
}

স্থির শূন্য Rq_mult3(Fq *h, ধ্রুবক Fq *f) {
  পূর্ণসংখ্যা i;
  জন্য (i = 0; i < p; ++i) h[i] = Fq_freeze(3 * f[i]);
}

স্থির Fq Fq_recip(Fq a1) {
  পূর্ণসংখ্যা i = 1;
  Fq ai = a1;
  যখন (i < q - 2) {
    ai = Fq_freeze(a1 * (int32_t)ai);
    i += 1;
  }
  ফেরত ai;
}

স্থির পূর্ণসংখ্যা Rq_recip3(Fq *out, ধ্রুবক small *in) {
  Fq f[p + 1], g[p + 1], v[p + 1], r[p + 1], scale;
  পূর্ণসংখ্যা swap, t, i, loop, delta = 1;
  int32_t f0, g0;
  জন্য (i = 0; i < p + 1; ++i) v[i] = 0;
  জন্য (i = 0; i < p + 1; ++i) r[i] = 0;
  r[0] = Fq_recip(3);
  জন্য (i = 0; i < p; ++i) f[i] = 0;
  f[0] = 1;
  f[p - 1] = f[p] = -1;
  জন্য (i = 0; i < p; ++i) g[p - 1 - i] = in[i];
  g[p] = 0;
  জন্য (loop = 0; loop < 2 * p - 1; ++loop) {
    জন্য (i = p; i > 0; --i) v[i] = v[i - 1];
    v[0] = 0;
    swap = crypto_int16_negative_mask(-delta) & crypto_int16_nonzero_mask(g[0]);
    delta ^= swap & (delta ^ -delta);
    delta += 1;
    জন্য (i = 0; i < p + 1; ++i) {
      t = swap & (f[i] ^ g[i]);
      f[i] ^= t;
      g[i] ^= t;
      t = swap & (v[i] ^ r[i]);
      v[i] ^= t;
      r[i] ^= t;
    }
    f0 = f[0];
    g0 = g[0];
    জন্য (i = 0; i < p + 1; ++i) g[i] = Fq_freeze(f0 * g[i] - g0 * f[i]);
    জন্য (i = 0; i < p + 1; ++i) r[i] = Fq_freeze(f0 * r[i] - g0 * v[i]);
    জন্য (i = 0; i < p; ++i) g[i] = g[i + 1];
    g[p] = 0;
  }
  scale = Fq_recip(f[0]);
  জন্য (i = 0; i < p; ++i) out[i] = Fq_freeze(scale * (int32_t)v[p - 1 - i]);
  ফেরত crypto_int16_nonzero_mask(delta);
}

স্থির শূন্য Round(Fq *out, ধ্রুবক Fq *a) {
  পূর্ণসংখ্যা i;
  জন্য (i = 0; i < p; ++i) out[i] = a[i] - F3_freeze(a[i]);
}

স্থির শূন্য Short_fromlist(small *out, ধ্রুবক uint32_t *in) {
  uint32_t L[p];
  পূর্ণসংখ্যা i;
  জন্য (i = 0; i < w; ++i) L[i] = in[i] & (uint32_t)-2;
  জন্য (i = w; i < p; ++i) L[i] = (in[i] & (uint32_t)-3) | 1;
  crypto_sort_uint32(L, p);
  জন্য (i = 0; i < p; ++i) out[i] = (L[i] & 3) - 1;
}

স্থির শূন্য Hash_prefix(unsigned অক্ষর *out, পূর্ণসংখ্যা b, ধ্রুবক unsigned অক্ষর *in, পূর্ণসংখ্যা inlen) {
  unsigned অক্ষর x[inlen + 1], h[64];
  পূর্ণসংখ্যা i;
  x[0] = b;
  জন্য (i = 0; i < inlen; ++i) x[i + 1] = in[i];
  crypto_hash_sha512(h, x, inlen + 1);
  জন্য (i = 0; i < 32; ++i) out[i] = h[i];
}


স্থির শূন্য Short_random(small *out) {
  uint32_t L[p];
  randombytes(L, আকার(L));
  Short_fromlist(out, L);
  explicit_bzero(L, আকার(L));
}
স্থির শূন্য Small_random(small *out) {
  পূর্ণসংখ্যা i;
  uint32_t L[p];
  randombytes(L, আকার(L));
  জন্য (i = 0; i < p; ++i) out[i] = (((L[i] & 0x3fffffff) * 3) >> 30) - 1;
  explicit_bzero(L, আকার(L));
}
স্থির শূন্য চাবি_Gen(Fq *h, small *f, small *ginv) {
  small g[p];
  Fq finv[p];
  জন্য (;;) {
    পূর্ণসংখ্যা ফলাফল;
    Small_random(g);
    ফলাফল = R3_recip(ginv, g);
    crypto_declassify(&ফলাফল, আকার ফলাফল);
    যদি (ফলাফল == 0) বিরতি;
  }
  Short_random(f);
  Rq_recip3(finv, f);
  Rq_mult_small(h, finv, g);
}

স্থির শূন্য Encrypt(Fq *c, ধ্রুবক small *r, ধ্রুবক Fq *h) {
  Fq hr[p];
  Rq_mult_small(hr, h, r);
  Round(c, hr);
}

স্থির শূন্য Decrypt(small *r, ধ্রুবক Fq *c, ধ্রুবক small *f, ধ্রুবক small *ginv) {
  Fq cf[p], cf3[p];
  small e[p], ev[p];
  পূর্ণসংখ্যা mask, i;
  Rq_mult_small(cf, c, f);
  Rq_mult3(cf3, cf);
  R3_fromRq(e, cf3);
  R3_mult(ev, e, ginv);
  mask = Weightw_mask(ev);
  জন্য (i = 0; i < w; ++i) r[i] = ((ev[i] ^ 1) & ~mask) ^ 1;
  জন্য (i = w; i < p; ++i) r[i] = ev[i] & ~mask;
}

স্থির শূন্য Small_encode(unsigned অক্ষর *s, ধ্রুবক small *f) {
  পূর্ণসংখ্যা i, j;
  জন্য (i = 0; i < p / 4; ++i) {
    small x = 0;
    জন্য (j = 0;j < 4;++j) x += (*f++ + 1) << (2 * j);
    *s++ = x;
  }
  *s = *f++ + 1;
}

স্থির শূন্য Small_decode(small *f, ধ্রুবক unsigned অক্ষর *s) {
  পূর্ণসংখ্যা i, j;
  জন্য (i = 0; i < p / 4; ++i) {
    unsigned অক্ষর x = *s++;
    জন্য (j = 0;j < 4;++j) *f++ = ((small)((x >> (2 * j)) & 3)) - 1;
  }
  *f++ = ((small)(*s & 3)) - 1;
}

স্থির শূন্য Rq_encode(unsigned অক্ষর *s, ধ্রুবক Fq *r) {
  uint16_t R[p], M[p];
  পূর্ণসংখ্যা i;
  জন্য (i = 0; i < p; ++i) R[i] = r[i] + q12;
  জন্য (i = 0; i < p; ++i) M[i] = q;
  Encode(s, R, M, p);
}

স্থির শূন্য Rq_decode(Fq *r, ধ্রুবক unsigned অক্ষর *s) {
  uint16_t R[p], M[p];
  পূর্ণসংখ্যা i;
  জন্য (i = 0; i < p; ++i) M[i] = q;
  Decode(R, s, M, p);
  জন্য (i = 0; i < p; ++i) r[i] = ((Fq)R[i]) - q12;
}

স্থির শূন্য Rounded_encode(unsigned অক্ষর *s, ধ্রুবক Fq *r) {
  uint16_t R[p], M[p];
  পূর্ণসংখ্যা i;
  জন্য (i = 0; i < p; ++i) R[i] = ((r[i] + q12) * 10923) >> 15;
  জন্য (i = 0; i < p; ++i) M[i] = (q + 2) / 3;
  Encode(s, R, M, p);
}

স্থির শূন্য Rounded_decode(Fq *r, ধ্রুবক unsigned অক্ষর *s) {
  uint16_t R[p], M[p];
  পূর্ণসংখ্যা i;
  জন্য (i = 0; i < p; ++i) M[i] = (q + 2) / 3;
  Decode(R, s, M, p);
  জন্য (i = 0; i < p; ++i) r[i] = R[i] * 3 - q12;
}

স্থির শূন্য ZKeyGen(unsigned অক্ষর *pk, unsigned অক্ষর *sk) {
  Fq h[p];
  small f[p], v[p];
  চাবি_Gen(h, f, v);
  Rq_encode(pk, h);
  Small_encode(sk, f);
  Small_encode(sk + Small_bytes, v);
}

স্থির শূন্য ZEncrypt(unsigned অক্ষর *C, ধ্রুবক Inputs r, ধ্রুবক unsigned অক্ষর *pk) {
  Fq h[p], c[p];
  Rq_decode(h, pk);
  Encrypt(c, r, h);
  Rounded_encode(C, c);
}

স্থির শূন্য ZDecrypt(Inputs r, ধ্রুবক unsigned অক্ষর *C, ধ্রুবক unsigned অক্ষর *sk) {
  small f[p], v[p];
  Fq c[p];
  Small_decode(f, sk);
  Small_decode(v, sk + Small_bytes);
  Rounded_decode(c, C);
  Decrypt(r, c, f, v);
}

স্থির শূন্য HashConfirm(unsigned অক্ষর *h, ধ্রুবক unsigned অক্ষর *r, ধ্রুবক unsigned অক্ষর *cache) {
  unsigned অক্ষর x[Hash_bytes * 2];
  পূর্ণসংখ্যা i;
  Hash_prefix(x, 3, r, Small_bytes);
  জন্য (i = 0; i < Hash_bytes; ++i) x[Hash_bytes + i] = cache[i];
  Hash_prefix(h, 2, x, আকার x);
}

স্থির শূন্য HashSession(unsigned অক্ষর *k, পূর্ণসংখ্যা b, ধ্রুবক unsigned অক্ষর *y, ধ্রুবক unsigned অক্ষর *z) {
  unsigned অক্ষর x[Hash_bytes + crypto_kem_sntrup761_CIPHERTEXTBYTES];
  পূর্ণসংখ্যা i;
  Hash_prefix(x, 3, y, Small_bytes);
  জন্য (i = 0; i < crypto_kem_sntrup761_CIPHERTEXTBYTES; ++i) x[Hash_bytes + i] = z[i];
  Hash_prefix(k, b, x, আকার x);
}

পূর্ণসংখ্যা crypto_kem_sntrup761_keypair(unsigned অক্ষর *pk, unsigned অক্ষর *sk) {
  পূর্ণসংখ্যা i;
  ZKeyGen(pk, sk);
  sk += Secret_চাবিগুলি_bytes;
  জন্য (i = 0; i < crypto_kem_sntrup761_PUBLICKEYBYTES; ++i) *sk++ = pk[i];
  randombytes(sk, Small_bytes);
  Hash_prefix(sk + Small_bytes, 4, pk, crypto_kem_sntrup761_PUBLICKEYBYTES);
  ফেরত 0;
}

স্থির শূন্য Hide(unsigned অক্ষর *c, unsigned অক্ষর *r_enc, ধ্রুবক Inputs r, ধ্রুবক unsigned অক্ষর *pk, ধ্রুবক unsigned অক্ষর *cache) {
  Small_encode(r_enc, r);
  ZEncrypt(c, r, pk);
  HashConfirm(c + crypto_kem_sntrup761_CIPHERTEXTBYTES - Confirm_bytes, r_enc, cache);
}

পূর্ণসংখ্যা crypto_kem_sntrup761_enc(unsigned অক্ষর *c, unsigned অক্ষর *k, ধ্রুবক unsigned অক্ষর *pk) {
  Inputs r;
  unsigned অক্ষর r_enc[Small_bytes], cache[Hash_bytes];
  Hash_prefix(cache, 4, pk, crypto_kem_sntrup761_PUBLICKEYBYTES);
  Short_random(r);
  Hide(c, r_enc, r, pk, cache);
  HashSession(k, 1, r_enc, c);
  ফেরত 0;
}

স্থির পূর্ণসংখ্যা Ciphertexts_diff_mask(ধ্রুবক unsigned অক্ষর *c, ধ্রুবক unsigned অক্ষর *c2) {
  uint16_t differentbits = 0;
  পূর্ণসংখ্যা len = crypto_kem_sntrup761_CIPHERTEXTBYTES;
  যখন (len-- > 0) differentbits |= (*c++) ^ (*c2++);
  ফেরত (crypto_int64_bitmod_01((differentbits - 1),8)) - 1;
}

পূর্ণসংখ্যা crypto_kem_sntrup761_dec(unsigned অক্ষর *k, ধ্রুবক unsigned অক্ষর *c, ধ্রুবক unsigned অক্ষর *sk) {
  ধ্রুবক unsigned অক্ষর *pk = sk + Secret_চাবিগুলি_bytes;
  ধ্রুবক unsigned অক্ষর *rho = pk + crypto_kem_sntrup761_PUBLICKEYBYTES;
  ধ্রুবক unsigned অক্ষর *cache = rho + Small_bytes;
  Inputs r;
  unsigned অক্ষর r_enc[Small_bytes], cnew[crypto_kem_sntrup761_CIPHERTEXTBYTES];
  পূর্ণসংখ্যা mask, i;
  ZDecrypt(r, c, sk);
  Hide(cnew, r_enc, r, pk, cache);
  mask = Ciphertexts_diff_mask(c, cnew);
  জন্য (i = 0; i < Small_bytes; ++i) r_enc[i] ^= mask & (r_enc[i] ^ rho[i]);
  HashSession(k, 1 + mask, r_enc, c);
  ফেরত 0;
}

#endif /* USE_SNTRUP761X25519 */
