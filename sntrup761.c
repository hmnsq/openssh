/*  $OpenBSD: sntrup761.c,v 1.9 2026/01/20 22:56:11 dtucker Exp $ */

/*
 * Public Domain, Authors:
 * - Daniel J. Bernstein
 * - Chitchanok Chuengsatiansup
 * - Tanja Lange
 * - Christine van Vredendaal
 */

#అన్తర్భావ "includes.h"

#నిర్వచితమైతే USE_SNTRUP761X25519

#అన్తర్భావ <string.h>
#అన్తర్భావ "crypto_api.h"

#నిర్వచించు crypto_declassify(x, y) చేయి {} అయితే (0)

#నిర్వచించు int8 crypto_int8
#నిర్వచించు uint8 crypto_uint8
#నిర్వచించు int16 crypto_int16
#నిర్వచించు uint16 crypto_uint16
#నిర్వచించు int32 crypto_int32
#నిర్వచించు uint32 crypto_uint32
#నిర్వచించు int64 crypto_int64
#నిర్వచించు uint64 crypto_uint64
బాహ్య అస్థిర crypto_int16 crypto_int16_optblocker;
బాహ్య అస్థిర crypto_int32 crypto_int32_optblocker;
బాహ్య అస్థిర crypto_int64 crypto_int64_optblocker;

/* from supercop-20240808/cryptoint/crypto_int16.h */
/* auto-generated: cd cryptoint; ./autogen */
/* cryptoint 20240806 */

#నిర్వచితం_కాకపోతే crypto_int16_h
#నిర్వచించు crypto_int16_h

#నిర్వచించు crypto_int16 int16_t
#నిర్వచించు crypto_int16_unsigned uint16_t



__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int16 crypto_int16_ఎక్కించు(స్థిరరాశి గుర్తులేని అక్షరం *crypto_int16_s) {
  crypto_int16 crypto_int16_z = 0;
  crypto_int16_z |= ((crypto_int16) (*crypto_int16_s++)) << 0;
  crypto_int16_z |= ((crypto_int16) (*crypto_int16_s++)) << 8;
  తిరిగి crypto_int16_z;
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
శూన్య crypto_int16_store(గుర్తులేని అక్షరం *crypto_int16_s,crypto_int16 crypto_int16_x) {
  *crypto_int16_s++ = crypto_int16_x >> 0;
  *crypto_int16_s++ = crypto_int16_x >> 8;
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int16 crypto_int16_negative_ముసుగు(crypto_int16 crypto_int16_x) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarw $15,%0" : "+r"(crypto_int16_x) : : "cc");
  తిరిగి crypto_int16_x;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_y;
  __asm__ ("sbfx %w0,%w1,15,1" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) : );
  తిరిగి crypto_int16_y;
#లేకపోతే
  crypto_int16_x >>= 16-6;
  crypto_int16_x ^= crypto_int16_optblocker;
  crypto_int16_x >>= 5;
  తిరిగి crypto_int16_x;
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int16_unsigned crypto_int16_unsigned_topbit_01(crypto_int16_unsigned crypto_int16_x) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("shrw $15,%0" : "+r"(crypto_int16_x) : : "cc");
  తిరిగి crypto_int16_x;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_y;
  __asm__ ("ubfx %w0,%w1,15,1" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) : );
  తిరిగి crypto_int16_y;
#లేకపోతే
  crypto_int16_x >>= 16-6;
  crypto_int16_x ^= crypto_int16_optblocker;
  crypto_int16_x >>= 5;
  తిరిగి crypto_int16_x;
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int16 crypto_int16_negative_01(crypto_int16 crypto_int16_x) {
  తిరిగి crypto_int16_unsigned_topbit_01(crypto_int16_x);
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int16 crypto_int16_topbit_ముసుగు(crypto_int16 crypto_int16_x) {
  తిరిగి crypto_int16_negative_ముసుగు(crypto_int16_x);
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int16 crypto_int16_topbit_01(crypto_int16 crypto_int16_x) {
  తిరిగి crypto_int16_unsigned_topbit_01(crypto_int16_x);
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int16 crypto_int16_bottombit_ముసుగు(crypto_int16 crypto_int16_x) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andw $1,%0" : "+r"(crypto_int16_x) : : "cc");
  తిరిగి -crypto_int16_x;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_y;
  __asm__ ("sbfx %w0,%w1,0,1" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) : );
  తిరిగి crypto_int16_y;
#లేకపోతే
  crypto_int16_x &= 1 ^ crypto_int16_optblocker;
  తిరిగి -crypto_int16_x;
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int16 crypto_int16_bottombit_01(crypto_int16 crypto_int16_x) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andw $1,%0" : "+r"(crypto_int16_x) : : "cc");
  తిరిగి crypto_int16_x;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_y;
  __asm__ ("ubfx %w0,%w1,0,1" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) : );
  తిరిగి crypto_int16_y;
#లేకపోతే
  crypto_int16_x &= 1 ^ crypto_int16_optblocker;
  తిరిగి crypto_int16_x;
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int16 crypto_int16_bitinrangepublicpos_ముసుగు(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarw %%cl,%0" : "+r"(crypto_int16_x) : "c"(crypto_int16_s) : "cc");
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("sxth %w0,%w0\n asr %w0,%w0,%w1" : "+&r"(crypto_int16_x) : "r"(crypto_int16_s) : );
#లేకపోతే
  crypto_int16_x >>= crypto_int16_s ^ crypto_int16_optblocker;
#అయితే_ముగింపు
  తిరిగి crypto_int16_bottombit_ముసుగు(crypto_int16_x);
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int16 crypto_int16_bitinrangepublicpos_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarw %%cl,%0" : "+r"(crypto_int16_x) : "c"(crypto_int16_s) : "cc");
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("sxth %w0,%w0\n asr %w0,%w0,%w1" : "+&r"(crypto_int16_x) : "r"(crypto_int16_s) : );
#లేకపోతే
  crypto_int16_x >>= crypto_int16_s ^ crypto_int16_optblocker;
#అయితే_ముగింపు
  తిరిగి crypto_int16_bottombit_01(crypto_int16_x);
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int16 crypto_int16_shlmod(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16_s &= 15;
  __asm__ ("shlw %%cl,%0" : "+r"(crypto_int16_x) : "c"(crypto_int16_s) : "cc");
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("and %w0,%w0,15\n and %w1,%w1,65535\n lsl %w1,%w1,%w0" : "+&r"(crypto_int16_s), "+r"(crypto_int16_x) : : );
#లేకపోతే
  పూర్ణాంకం crypto_int16_k, crypto_int16_l;
  కొరకు (crypto_int16_l = 0,crypto_int16_k = 1;crypto_int16_k < 16;++crypto_int16_l,crypto_int16_k *= 2)
    crypto_int16_x ^= (crypto_int16_x ^ (crypto_int16_x << crypto_int16_k)) & crypto_int16_bitinrangepublicpos_ముసుగు(crypto_int16_s,crypto_int16_l);
#అయితే_ముగింపు
  తిరిగి crypto_int16_x;
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int16 crypto_int16_shrmod(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16_s &= 15;
  __asm__ ("sarw %%cl,%0" : "+r"(crypto_int16_x) : "c"(crypto_int16_s) : "cc");
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("and %w0,%w0,15\n sxth %w1,%w1\n asr %w1,%w1,%w0" : "+&r"(crypto_int16_s), "+r"(crypto_int16_x) : : );
#లేకపోతే
  పూర్ణాంకం crypto_int16_k, crypto_int16_l;
  కొరకు (crypto_int16_l = 0,crypto_int16_k = 1;crypto_int16_k < 16;++crypto_int16_l,crypto_int16_k *= 2)
    crypto_int16_x ^= (crypto_int16_x ^ (crypto_int16_x >> crypto_int16_k)) & crypto_int16_bitinrangepublicpos_ముసుగు(crypto_int16_s,crypto_int16_l);
#అయితే_ముగింపు
  తిరిగి crypto_int16_x;
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int16 crypto_int16_bitmod_ముసుగు(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
  crypto_int16_x = crypto_int16_shrmod(crypto_int16_x,crypto_int16_s);
  తిరిగి crypto_int16_bottombit_ముసుగు(crypto_int16_x);
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int16 crypto_int16_bitmod_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
  crypto_int16_x = crypto_int16_shrmod(crypto_int16_x,crypto_int16_s);
  తిరిగి crypto_int16_bottombit_01(crypto_int16_x);
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int16 crypto_int16_nonzero_ముసుగు(crypto_int16 crypto_int16_x) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n testw %2,%2\n cmovnew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  తిరిగి crypto_int16_z;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("tst %w1,65535\n csetm %w0,ne" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  తిరిగి crypto_int16_z;
#లేకపోతే
  crypto_int16_x |= -crypto_int16_x;
  తిరిగి crypto_int16_negative_ముసుగు(crypto_int16_x);
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int16 crypto_int16_nonzero_01(crypto_int16 crypto_int16_x) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n testw %2,%2\n cmovnew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  తిరిగి crypto_int16_z;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("tst %w1,65535\n cset %w0,ne" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  తిరిగి crypto_int16_z;
#లేకపోతే
  crypto_int16_x |= -crypto_int16_x;
  తిరిగి crypto_int16_unsigned_topbit_01(crypto_int16_x);
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int16 crypto_int16_ధనాత్మక_ముసుగు(crypto_int16 crypto_int16_x) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n testw %2,%2\n cmovgw %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  తిరిగి crypto_int16_z;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,0\n csetm %w0,gt" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  తిరిగి crypto_int16_z;
#లేకపోతే
  crypto_int16 crypto_int16_z = -crypto_int16_x;
  crypto_int16_z ^= crypto_int16_x & crypto_int16_z;
  తిరిగి crypto_int16_negative_ముసుగు(crypto_int16_z);
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int16 crypto_int16_ధనాత్మక_01(crypto_int16 crypto_int16_x) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n testw %2,%2\n cmovgw %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  తిరిగి crypto_int16_z;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,0\n cset %w0,gt" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  తిరిగి crypto_int16_z;
#లేకపోతే
  crypto_int16 crypto_int16_z = -crypto_int16_x;
  crypto_int16_z ^= crypto_int16_x & crypto_int16_z;
  తిరిగి crypto_int16_unsigned_topbit_01(crypto_int16_z);
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int16 crypto_int16_zero_ముసుగు(crypto_int16 crypto_int16_x) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n testw %2,%2\n cmovew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  తిరిగి crypto_int16_z;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("tst %w1,65535\n csetm %w0,eq" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  తిరిగి crypto_int16_z;
#లేకపోతే
  తిరిగి ~crypto_int16_nonzero_ముసుగు(crypto_int16_x);
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int16 crypto_int16_zero_01(crypto_int16 crypto_int16_x) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n testw %2,%2\n cmovew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  తిరిగి crypto_int16_z;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("tst %w1,65535\n cset %w0,eq" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  తిరిగి crypto_int16_z;
#లేకపోతే
  తిరిగి 1-crypto_int16_nonzero_01(crypto_int16_x);
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int16 crypto_int16_unequal_ముసుగు(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n cmpw %3,%2\n cmovnew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  తిరిగి crypto_int16_z;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("and %w0,%w1,65535\n cmp %w0,%w2,uxth\n csetm %w0,ne" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  తిరిగి crypto_int16_z;
#లేకపోతే
  తిరిగి crypto_int16_nonzero_ముసుగు(crypto_int16_x ^ crypto_int16_y);
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int16 crypto_int16_unequal_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n cmpw %3,%2\n cmovnew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  తిరిగి crypto_int16_z;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("and %w0,%w1,65535\n cmp %w0,%w2,uxth\n cset %w0,ne" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  తిరిగి crypto_int16_z;
#లేకపోతే
  తిరిగి crypto_int16_nonzero_01(crypto_int16_x ^ crypto_int16_y);
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int16 crypto_int16_equal_ముసుగు(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n cmpw %3,%2\n cmovew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  తిరిగి crypto_int16_z;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("and %w0,%w1,65535\n cmp %w0,%w2,uxth\n csetm %w0,eq" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  తిరిగి crypto_int16_z;
#లేకపోతే
  తిరిగి ~crypto_int16_unequal_ముసుగు(crypto_int16_x,crypto_int16_y);
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int16 crypto_int16_equal_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n cmpw %3,%2\n cmovew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  తిరిగి crypto_int16_z;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("and %w0,%w1,65535\n cmp %w0,%w2,uxth\n cset %w0,eq" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  తిరిగి crypto_int16_z;
#లేకపోతే
  తిరిగి 1-crypto_int16_unequal_01(crypto_int16_x,crypto_int16_y);
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int16 crypto_int16_min(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpw %1,%0\n cmovgw %1,%0" : "+r"(crypto_int16_x) : "r"(crypto_int16_y) : "cc");
  తిరిగి crypto_int16_x;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("sxth %w0,%w0\n cmp %w0,%w1,sxth\n csel %w0,%w0,%w1,lt" : "+&r"(crypto_int16_x) : "r"(crypto_int16_y) : "cc");
  తిరిగి crypto_int16_x;
#లేకపోతే
  crypto_int16 crypto_int16_r = crypto_int16_y ^ crypto_int16_x;
  crypto_int16 crypto_int16_z = crypto_int16_y - crypto_int16_x;
  crypto_int16_z ^= crypto_int16_r & (crypto_int16_z ^ crypto_int16_y);
  crypto_int16_z = crypto_int16_negative_ముసుగు(crypto_int16_z);
  crypto_int16_z &= crypto_int16_r;
  తిరిగి crypto_int16_x ^ crypto_int16_z;
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int16 crypto_int16_max(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpw %1,%0\n cmovlw %1,%0" : "+r"(crypto_int16_x) : "r"(crypto_int16_y) : "cc");
  తిరిగి crypto_int16_x;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("sxth %w0,%w0\n cmp %w0,%w1,sxth\n csel %w0,%w1,%w0,lt" : "+&r"(crypto_int16_x) : "r"(crypto_int16_y) : "cc");
  తిరిగి crypto_int16_x;
#లేకపోతే
  crypto_int16 crypto_int16_r = crypto_int16_y ^ crypto_int16_x;
  crypto_int16 crypto_int16_z = crypto_int16_y - crypto_int16_x;
  crypto_int16_z ^= crypto_int16_r & (crypto_int16_z ^ crypto_int16_y);
  crypto_int16_z = crypto_int16_negative_ముసుగు(crypto_int16_z);
  crypto_int16_z &= crypto_int16_r;
  తిరిగి crypto_int16_y ^ crypto_int16_z;
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
శూన్య crypto_int16_minmax(crypto_int16 *crypto_int16_p,crypto_int16 *crypto_int16_q) {
  crypto_int16 crypto_int16_x = *crypto_int16_p;
  crypto_int16 crypto_int16_y = *crypto_int16_q;
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("cmpw %2,%1\n movw %1,%0\n cmovgw %2,%1\n cmovgw %0,%2" : "=&r"(crypto_int16_z), "+&r"(crypto_int16_x), "+r"(crypto_int16_y) : : "cc");
  *crypto_int16_p = crypto_int16_x;
  *crypto_int16_q = crypto_int16_y;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_r, crypto_int16_s;
  __asm__ ("sxth %w0,%w0\n cmp %w0,%w3,sxth\n csel %w1,%w0,%w3,lt\n csel %w2,%w3,%w0,lt" : "+&r"(crypto_int16_x), "=&r"(crypto_int16_r), "=r"(crypto_int16_s) : "r"(crypto_int16_y) : "cc");
  *crypto_int16_p = crypto_int16_r;
  *crypto_int16_q = crypto_int16_s;
#లేకపోతే
  crypto_int16 crypto_int16_r = crypto_int16_y ^ crypto_int16_x;
  crypto_int16 crypto_int16_z = crypto_int16_y - crypto_int16_x;
  crypto_int16_z ^= crypto_int16_r & (crypto_int16_z ^ crypto_int16_y);
  crypto_int16_z = crypto_int16_negative_ముసుగు(crypto_int16_z);
  crypto_int16_z &= crypto_int16_r;
  crypto_int16_x ^= crypto_int16_z;
  crypto_int16_y ^= crypto_int16_z;
  *crypto_int16_p = crypto_int16_x;
  *crypto_int16_q = crypto_int16_y;
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int16 crypto_int16_smaller_ముసుగు(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n cmpw %3,%2\n cmovlw %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  తిరిగి crypto_int16_z;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,%w2,sxth\n csetm %w0,lt" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  తిరిగి crypto_int16_z;
#లేకపోతే
  crypto_int16 crypto_int16_r = crypto_int16_x ^ crypto_int16_y;
  crypto_int16 crypto_int16_z = crypto_int16_x - crypto_int16_y;
  crypto_int16_z ^= crypto_int16_r & (crypto_int16_z ^ crypto_int16_x);
  తిరిగి crypto_int16_negative_ముసుగు(crypto_int16_z);
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int16 crypto_int16_smaller_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n cmpw %3,%2\n cmovlw %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  తిరిగి crypto_int16_z;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,%w2,sxth\n cset %w0,lt" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  తిరిగి crypto_int16_z;
#లేకపోతే
  crypto_int16 crypto_int16_r = crypto_int16_x ^ crypto_int16_y;
  crypto_int16 crypto_int16_z = crypto_int16_x - crypto_int16_y;
  crypto_int16_z ^= crypto_int16_r & (crypto_int16_z ^ crypto_int16_x);
  తిరిగి crypto_int16_unsigned_topbit_01(crypto_int16_z);
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int16 crypto_int16_leq_ముసుగు(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n cmpw %3,%2\n cmovlew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  తిరిగి crypto_int16_z;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,%w2,sxth\n csetm %w0,le" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  తిరిగి crypto_int16_z;
#లేకపోతే
  తిరిగి ~crypto_int16_smaller_ముసుగు(crypto_int16_y,crypto_int16_x);
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int16 crypto_int16_leq_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n cmpw %3,%2\n cmovlew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  తిరిగి crypto_int16_z;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,%w2,sxth\n cset %w0,le" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  తిరిగి crypto_int16_z;
#లేకపోతే
  తిరిగి 1-crypto_int16_smaller_01(crypto_int16_y,crypto_int16_x);
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
పూర్ణాంకం crypto_int16_ones_అంకె(crypto_int16 crypto_int16_x) {
  crypto_int16_unsigned crypto_int16_y = crypto_int16_x;
  స్థిరరాశి crypto_int16 C0 = 0x5555;
  స్థిరరాశి crypto_int16 C1 = 0x3333;
  స్థిరరాశి crypto_int16 C2 = 0x0f0f;
  crypto_int16_y -= ((crypto_int16_y >> 1) & C0);
  crypto_int16_y = (crypto_int16_y & C1) + ((crypto_int16_y >> 2) & C1);
  crypto_int16_y = (crypto_int16_y + (crypto_int16_y >> 4)) & C2;
  crypto_int16_y = (crypto_int16_y + (crypto_int16_y >> 8)) & 0xff;
  తిరిగి crypto_int16_y;
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
పూర్ణాంకం crypto_int16_bottomzeros_అంకె(crypto_int16 crypto_int16_x) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 fallback = 16;
  __asm__ ("bsfw %0,%0\n cmovew %1,%0" : "+&r"(crypto_int16_x) : "r"(fallback) : "cc");
  తిరిగి crypto_int16_x;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  int64_t crypto_int16_y;
  __asm__ ("orr %w0,%w1,-65536\n rbit %w0,%w0\n clz %w0,%w0" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) : );
  తిరిగి crypto_int16_y;
#లేకపోతే
  crypto_int16 crypto_int16_y = crypto_int16_x ^ (crypto_int16_x-1);
  crypto_int16_y = ((crypto_int16) crypto_int16_y) >> 1;
  crypto_int16_y &= ~(crypto_int16_x & (((crypto_int16) 1) << (16-1)));
  తిరిగి crypto_int16_ones_అంకె(crypto_int16_y);
#అయితే_ముగింపు
}

#అయితే_ముగింపు

/* from supercop-20240808/cryptoint/crypto_int32.h */
/* auto-generated: cd cryptoint; ./autogen */
/* cryptoint 20240806 */

#నిర్వచితం_కాకపోతే crypto_int32_h
#నిర్వచించు crypto_int32_h

#నిర్వచించు crypto_int32 int32_t
#నిర్వచించు crypto_int32_unsigned uint32_t



__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int32 crypto_int32_ఎక్కించు(స్థిరరాశి గుర్తులేని అక్షరం *crypto_int32_s) {
  crypto_int32 crypto_int32_z = 0;
  crypto_int32_z |= ((crypto_int32) (*crypto_int32_s++)) << 0;
  crypto_int32_z |= ((crypto_int32) (*crypto_int32_s++)) << 8;
  crypto_int32_z |= ((crypto_int32) (*crypto_int32_s++)) << 16;
  crypto_int32_z |= ((crypto_int32) (*crypto_int32_s++)) << 24;
  తిరిగి crypto_int32_z;
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
శూన్య crypto_int32_store(గుర్తులేని అక్షరం *crypto_int32_s,crypto_int32 crypto_int32_x) {
  *crypto_int32_s++ = crypto_int32_x >> 0;
  *crypto_int32_s++ = crypto_int32_x >> 8;
  *crypto_int32_s++ = crypto_int32_x >> 16;
  *crypto_int32_s++ = crypto_int32_x >> 24;
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int32 crypto_int32_negative_ముసుగు(crypto_int32 crypto_int32_x) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarl $31,%0" : "+r"(crypto_int32_x) : : "cc");
  తిరిగి crypto_int32_x;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_y;
  __asm__ ("asr %w0,%w1,31" : "=r"(crypto_int32_y) : "r"(crypto_int32_x) : );
  తిరిగి crypto_int32_y;
#లేకపోతే
  crypto_int32_x >>= 32-6;
  crypto_int32_x ^= crypto_int32_optblocker;
  crypto_int32_x >>= 5;
  తిరిగి crypto_int32_x;
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int32_unsigned crypto_int32_unsigned_topbit_01(crypto_int32_unsigned crypto_int32_x) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("shrl $31,%0" : "+r"(crypto_int32_x) : : "cc");
  తిరిగి crypto_int32_x;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_y;
  __asm__ ("lsr %w0,%w1,31" : "=r"(crypto_int32_y) : "r"(crypto_int32_x) : );
  తిరిగి crypto_int32_y;
#లేకపోతే
  crypto_int32_x >>= 32-6;
  crypto_int32_x ^= crypto_int32_optblocker;
  crypto_int32_x >>= 5;
  తిరిగి crypto_int32_x;
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int32 crypto_int32_negative_01(crypto_int32 crypto_int32_x) {
  తిరిగి crypto_int32_unsigned_topbit_01(crypto_int32_x);
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int32 crypto_int32_topbit_ముసుగు(crypto_int32 crypto_int32_x) {
  తిరిగి crypto_int32_negative_ముసుగు(crypto_int32_x);
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int32 crypto_int32_topbit_01(crypto_int32 crypto_int32_x) {
  తిరిగి crypto_int32_unsigned_topbit_01(crypto_int32_x);
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int32 crypto_int32_bottombit_ముసుగు(crypto_int32 crypto_int32_x) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andl $1,%0" : "+r"(crypto_int32_x) : : "cc");
  తిరిగి -crypto_int32_x;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_y;
  __asm__ ("sbfx %w0,%w1,0,1" : "=r"(crypto_int32_y) : "r"(crypto_int32_x) : );
  తిరిగి crypto_int32_y;
#లేకపోతే
  crypto_int32_x &= 1 ^ crypto_int32_optblocker;
  తిరిగి -crypto_int32_x;
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int32 crypto_int32_bottombit_01(crypto_int32 crypto_int32_x) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andl $1,%0" : "+r"(crypto_int32_x) : : "cc");
  తిరిగి crypto_int32_x;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_y;
  __asm__ ("ubfx %w0,%w1,0,1" : "=r"(crypto_int32_y) : "r"(crypto_int32_x) : );
  తిరిగి crypto_int32_y;
#లేకపోతే
  crypto_int32_x &= 1 ^ crypto_int32_optblocker;
  తిరిగి crypto_int32_x;
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int32 crypto_int32_bitinrangepublicpos_ముసుగు(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarl %%cl,%0" : "+r"(crypto_int32_x) : "c"(crypto_int32_s) : "cc");
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %w0,%w0,%w1" : "+r"(crypto_int32_x) : "r"(crypto_int32_s) : );
#లేకపోతే
  crypto_int32_x >>= crypto_int32_s ^ crypto_int32_optblocker;
#అయితే_ముగింపు
  తిరిగి crypto_int32_bottombit_ముసుగు(crypto_int32_x);
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int32 crypto_int32_bitinrangepublicpos_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarl %%cl,%0" : "+r"(crypto_int32_x) : "c"(crypto_int32_s) : "cc");
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %w0,%w0,%w1" : "+r"(crypto_int32_x) : "r"(crypto_int32_s) : );
#లేకపోతే
  crypto_int32_x >>= crypto_int32_s ^ crypto_int32_optblocker;
#అయితే_ముగింపు
  తిరిగి crypto_int32_bottombit_01(crypto_int32_x);
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int32 crypto_int32_shlmod(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("shll %%cl,%0" : "+r"(crypto_int32_x) : "c"(crypto_int32_s) : "cc");
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("lsl %w0,%w0,%w1" : "+r"(crypto_int32_x) : "r"(crypto_int32_s) : );
#లేకపోతే
  పూర్ణాంకం crypto_int32_k, crypto_int32_l;
  కొరకు (crypto_int32_l = 0,crypto_int32_k = 1;crypto_int32_k < 32;++crypto_int32_l,crypto_int32_k *= 2)
    crypto_int32_x ^= (crypto_int32_x ^ (crypto_int32_x << crypto_int32_k)) & crypto_int32_bitinrangepublicpos_ముసుగు(crypto_int32_s,crypto_int32_l);
#అయితే_ముగింపు
  తిరిగి crypto_int32_x;
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int32 crypto_int32_shrmod(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarl %%cl,%0" : "+r"(crypto_int32_x) : "c"(crypto_int32_s) : "cc");
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %w0,%w0,%w1" : "+r"(crypto_int32_x) : "r"(crypto_int32_s) : );
#లేకపోతే
  పూర్ణాంకం crypto_int32_k, crypto_int32_l;
  కొరకు (crypto_int32_l = 0,crypto_int32_k = 1;crypto_int32_k < 32;++crypto_int32_l,crypto_int32_k *= 2)
    crypto_int32_x ^= (crypto_int32_x ^ (crypto_int32_x >> crypto_int32_k)) & crypto_int32_bitinrangepublicpos_ముసుగు(crypto_int32_s,crypto_int32_l);
#అయితే_ముగింపు
  తిరిగి crypto_int32_x;
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int32 crypto_int32_bitmod_ముసుగు(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
  crypto_int32_x = crypto_int32_shrmod(crypto_int32_x,crypto_int32_s);
  తిరిగి crypto_int32_bottombit_ముసుగు(crypto_int32_x);
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int32 crypto_int32_bitmod_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
  crypto_int32_x = crypto_int32_shrmod(crypto_int32_x,crypto_int32_s);
  తిరిగి crypto_int32_bottombit_01(crypto_int32_x);
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int32 crypto_int32_nonzero_ముసుగు(crypto_int32 crypto_int32_x) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n testl %2,%2\n cmovnel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  తిరిగి crypto_int32_z;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n csetm %w0,ne" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  తిరిగి crypto_int32_z;
#లేకపోతే
  crypto_int32_x |= -crypto_int32_x;
  తిరిగి crypto_int32_negative_ముసుగు(crypto_int32_x);
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int32 crypto_int32_nonzero_01(crypto_int32 crypto_int32_x) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n testl %2,%2\n cmovnel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  తిరిగి crypto_int32_z;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n cset %w0,ne" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  తిరిగి crypto_int32_z;
#లేకపోతే
  crypto_int32_x |= -crypto_int32_x;
  తిరిగి crypto_int32_unsigned_topbit_01(crypto_int32_x);
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int32 crypto_int32_ధనాత్మక_ముసుగు(crypto_int32 crypto_int32_x) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n testl %2,%2\n cmovgl %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  తిరిగి crypto_int32_z;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n csetm %w0,gt" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  తిరిగి crypto_int32_z;
#లేకపోతే
  crypto_int32 crypto_int32_z = -crypto_int32_x;
  crypto_int32_z ^= crypto_int32_x & crypto_int32_z;
  తిరిగి crypto_int32_negative_ముసుగు(crypto_int32_z);
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int32 crypto_int32_ధనాత్మక_01(crypto_int32 crypto_int32_x) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n testl %2,%2\n cmovgl %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  తిరిగి crypto_int32_z;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n cset %w0,gt" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  తిరిగి crypto_int32_z;
#లేకపోతే
  crypto_int32 crypto_int32_z = -crypto_int32_x;
  crypto_int32_z ^= crypto_int32_x & crypto_int32_z;
  తిరిగి crypto_int32_unsigned_topbit_01(crypto_int32_z);
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int32 crypto_int32_zero_ముసుగు(crypto_int32 crypto_int32_x) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n testl %2,%2\n cmovel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  తిరిగి crypto_int32_z;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n csetm %w0,eq" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  తిరిగి crypto_int32_z;
#లేకపోతే
  తిరిగి ~crypto_int32_nonzero_ముసుగు(crypto_int32_x);
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int32 crypto_int32_zero_01(crypto_int32 crypto_int32_x) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n testl %2,%2\n cmovel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  తిరిగి crypto_int32_z;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n cset %w0,eq" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  తిరిగి crypto_int32_z;
#లేకపోతే
  తిరిగి 1-crypto_int32_nonzero_01(crypto_int32_x);
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int32 crypto_int32_unequal_ముసుగు(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n cmpl %3,%2\n cmovnel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  తిరిగి crypto_int32_z;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n csetm %w0,ne" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  తిరిగి crypto_int32_z;
#లేకపోతే
  తిరిగి crypto_int32_nonzero_ముసుగు(crypto_int32_x ^ crypto_int32_y);
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int32 crypto_int32_unequal_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n cmpl %3,%2\n cmovnel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  తిరిగి crypto_int32_z;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n cset %w0,ne" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  తిరిగి crypto_int32_z;
#లేకపోతే
  తిరిగి crypto_int32_nonzero_01(crypto_int32_x ^ crypto_int32_y);
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int32 crypto_int32_equal_ముసుగు(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n cmpl %3,%2\n cmovel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  తిరిగి crypto_int32_z;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n csetm %w0,eq" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  తిరిగి crypto_int32_z;
#లేకపోతే
  తిరిగి ~crypto_int32_unequal_ముసుగు(crypto_int32_x,crypto_int32_y);
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int32 crypto_int32_equal_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n cmpl %3,%2\n cmovel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  తిరిగి crypto_int32_z;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n cset %w0,eq" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  తిరిగి crypto_int32_z;
#లేకపోతే
  తిరిగి 1-crypto_int32_unequal_01(crypto_int32_x,crypto_int32_y);
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int32 crypto_int32_min(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpl %1,%0\n cmovgl %1,%0" : "+r"(crypto_int32_x) : "r"(crypto_int32_y) : "cc");
  తిరిగి crypto_int32_x;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("cmp %w0,%w1\n csel %w0,%w0,%w1,lt" : "+r"(crypto_int32_x) : "r"(crypto_int32_y) : "cc");
  తిరిగి crypto_int32_x;
#లేకపోతే
  crypto_int64 crypto_int32_r = (crypto_int64)crypto_int32_y ^ (crypto_int64)crypto_int32_x;
  crypto_int64 crypto_int32_z = (crypto_int64)crypto_int32_y - (crypto_int64)crypto_int32_x;
  crypto_int32_z ^= crypto_int32_r & (crypto_int32_z ^ crypto_int32_y);
  crypto_int32_z = crypto_int32_negative_ముసుగు(crypto_int32_z);
  crypto_int32_z &= crypto_int32_r;
  తిరిగి crypto_int32_x ^ crypto_int32_z;
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int32 crypto_int32_max(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpl %1,%0\n cmovll %1,%0" : "+r"(crypto_int32_x) : "r"(crypto_int32_y) : "cc");
  తిరిగి crypto_int32_x;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("cmp %w0,%w1\n csel %w0,%w1,%w0,lt" : "+r"(crypto_int32_x) : "r"(crypto_int32_y) : "cc");
  తిరిగి crypto_int32_x;
#లేకపోతే
  crypto_int64 crypto_int32_r = (crypto_int64)crypto_int32_y ^ (crypto_int64)crypto_int32_x;
  crypto_int64 crypto_int32_z = (crypto_int64)crypto_int32_y - (crypto_int64)crypto_int32_x;
  crypto_int32_z ^= crypto_int32_r & (crypto_int32_z ^ crypto_int32_y);
  crypto_int32_z = crypto_int32_negative_ముసుగు(crypto_int32_z);
  crypto_int32_z &= crypto_int32_r;
  తిరిగి crypto_int32_y ^ crypto_int32_z;
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
శూన్య crypto_int32_minmax(crypto_int32 *crypto_int32_p,crypto_int32 *crypto_int32_q) {
  crypto_int32 crypto_int32_x = *crypto_int32_p;
  crypto_int32 crypto_int32_y = *crypto_int32_q;
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmpl %2,%1\n movl %1,%0\n cmovgl %2,%1\n cmovgl %0,%2" : "=&r"(crypto_int32_z), "+&r"(crypto_int32_x), "+r"(crypto_int32_y) : : "cc");
  *crypto_int32_p = crypto_int32_x;
  *crypto_int32_q = crypto_int32_y;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_r, crypto_int32_s;
  __asm__ ("cmp %w2,%w3\n csel %w0,%w2,%w3,lt\n csel %w1,%w3,%w2,lt" : "=&r"(crypto_int32_r), "=r"(crypto_int32_s) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  *crypto_int32_p = crypto_int32_r;
  *crypto_int32_q = crypto_int32_s;
#లేకపోతే
  crypto_int64 crypto_int32_r = (crypto_int64)crypto_int32_y ^ (crypto_int64)crypto_int32_x;
  crypto_int64 crypto_int32_z = (crypto_int64)crypto_int32_y - (crypto_int64)crypto_int32_x;
  crypto_int32_z ^= crypto_int32_r & (crypto_int32_z ^ crypto_int32_y);
  crypto_int32_z = crypto_int32_negative_ముసుగు(crypto_int32_z);
  crypto_int32_z &= crypto_int32_r;
  crypto_int32_x ^= crypto_int32_z;
  crypto_int32_y ^= crypto_int32_z;
  *crypto_int32_p = crypto_int32_x;
  *crypto_int32_q = crypto_int32_y;
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int32 crypto_int32_smaller_ముసుగు(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n cmpl %3,%2\n cmovll %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  తిరిగి crypto_int32_z;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n csetm %w0,lt" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  తిరిగి crypto_int32_z;
#లేకపోతే
  crypto_int32 crypto_int32_r = crypto_int32_x ^ crypto_int32_y;
  crypto_int32 crypto_int32_z = crypto_int32_x - crypto_int32_y;
  crypto_int32_z ^= crypto_int32_r & (crypto_int32_z ^ crypto_int32_x);
  తిరిగి crypto_int32_negative_ముసుగు(crypto_int32_z);
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int32 crypto_int32_smaller_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n cmpl %3,%2\n cmovll %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  తిరిగి crypto_int32_z;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n cset %w0,lt" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  తిరిగి crypto_int32_z;
#లేకపోతే
  crypto_int32 crypto_int32_r = crypto_int32_x ^ crypto_int32_y;
  crypto_int32 crypto_int32_z = crypto_int32_x - crypto_int32_y;
  crypto_int32_z ^= crypto_int32_r & (crypto_int32_z ^ crypto_int32_x);
  తిరిగి crypto_int32_unsigned_topbit_01(crypto_int32_z);
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int32 crypto_int32_leq_ముసుగు(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n cmpl %3,%2\n cmovlel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  తిరిగి crypto_int32_z;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n csetm %w0,le" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  తిరిగి crypto_int32_z;
#లేకపోతే
  తిరిగి ~crypto_int32_smaller_ముసుగు(crypto_int32_y,crypto_int32_x);
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int32 crypto_int32_leq_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n cmpl %3,%2\n cmovlel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  తిరిగి crypto_int32_z;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n cset %w0,le" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  తిరిగి crypto_int32_z;
#లేకపోతే
  తిరిగి 1-crypto_int32_smaller_01(crypto_int32_y,crypto_int32_x);
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
పూర్ణాంకం crypto_int32_ones_అంకె(crypto_int32 crypto_int32_x) {
  crypto_int32_unsigned crypto_int32_y = crypto_int32_x;
  స్థిరరాశి crypto_int32 C0 = 0x55555555;
  స్థిరరాశి crypto_int32 C1 = 0x33333333;
  స్థిరరాశి crypto_int32 C2 = 0x0f0f0f0f;
  crypto_int32_y -= ((crypto_int32_y >> 1) & C0);
  crypto_int32_y = (crypto_int32_y & C1) + ((crypto_int32_y >> 2) & C1);
  crypto_int32_y = (crypto_int32_y + (crypto_int32_y >> 4)) & C2;
  crypto_int32_y += crypto_int32_y >> 8;
  crypto_int32_y = (crypto_int32_y + (crypto_int32_y >> 16)) & 0xff;
  తిరిగి crypto_int32_y;
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
పూర్ణాంకం crypto_int32_bottomzeros_అంకె(crypto_int32 crypto_int32_x) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 fallback = 32;
  __asm__ ("bsfl %0,%0\n cmovel %1,%0" : "+&r"(crypto_int32_x) : "r"(fallback) : "cc");
  తిరిగి crypto_int32_x;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  int64_t crypto_int32_y;
  __asm__ ("rbit %w0,%w1\n clz %w0,%w0" : "=r"(crypto_int32_y) : "r"(crypto_int32_x) : );
  తిరిగి crypto_int32_y;
#లేకపోతే
  crypto_int32 crypto_int32_y = crypto_int32_x ^ (crypto_int32_x-1);
  crypto_int32_y = ((crypto_int32) crypto_int32_y) >> 1;
  crypto_int32_y &= ~(crypto_int32_x & (((crypto_int32) 1) << (32-1)));
  తిరిగి crypto_int32_ones_అంకె(crypto_int32_y);
#అయితే_ముగింపు
}

#అయితే_ముగింపు

/* from supercop-20240808/cryptoint/crypto_int64.h */
/* auto-generated: cd cryptoint; ./autogen */
/* cryptoint 20240806 */

#నిర్వచితం_కాకపోతే crypto_int64_h
#నిర్వచించు crypto_int64_h

#నిర్వచించు crypto_int64 int64_t
#నిర్వచించు crypto_int64_unsigned uint64_t



__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int64 crypto_int64_ఎక్కించు(స్థిరరాశి గుర్తులేని అక్షరం *crypto_int64_s) {
  crypto_int64 crypto_int64_z = 0;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 0;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 8;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 16;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 24;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 32;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 40;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 48;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 56;
  తిరిగి crypto_int64_z;
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
శూన్య crypto_int64_store(గుర్తులేని అక్షరం *crypto_int64_s,crypto_int64 crypto_int64_x) {
  *crypto_int64_s++ = crypto_int64_x >> 0;
  *crypto_int64_s++ = crypto_int64_x >> 8;
  *crypto_int64_s++ = crypto_int64_x >> 16;
  *crypto_int64_s++ = crypto_int64_x >> 24;
  *crypto_int64_s++ = crypto_int64_x >> 32;
  *crypto_int64_s++ = crypto_int64_x >> 40;
  *crypto_int64_s++ = crypto_int64_x >> 48;
  *crypto_int64_s++ = crypto_int64_x >> 56;
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int64 crypto_int64_negative_ముసుగు(crypto_int64 crypto_int64_x) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarq $63,%0" : "+r"(crypto_int64_x) : : "cc");
  తిరిగి crypto_int64_x;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_y;
  __asm__ ("asr %0,%1,63" : "=r"(crypto_int64_y) : "r"(crypto_int64_x) : );
  తిరిగి crypto_int64_y;
#లేకపోతే
  crypto_int64_x >>= 64-6;
  crypto_int64_x ^= crypto_int64_optblocker;
  crypto_int64_x >>= 5;
  తిరిగి crypto_int64_x;
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int64_unsigned crypto_int64_unsigned_topbit_01(crypto_int64_unsigned crypto_int64_x) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("shrq $63,%0" : "+r"(crypto_int64_x) : : "cc");
  తిరిగి crypto_int64_x;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_y;
  __asm__ ("lsr %0,%1,63" : "=r"(crypto_int64_y) : "r"(crypto_int64_x) : );
  తిరిగి crypto_int64_y;
#లేకపోతే
  crypto_int64_x >>= 64-6;
  crypto_int64_x ^= crypto_int64_optblocker;
  crypto_int64_x >>= 5;
  తిరిగి crypto_int64_x;
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int64 crypto_int64_negative_01(crypto_int64 crypto_int64_x) {
  తిరిగి crypto_int64_unsigned_topbit_01(crypto_int64_x);
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int64 crypto_int64_topbit_ముసుగు(crypto_int64 crypto_int64_x) {
  తిరిగి crypto_int64_negative_ముసుగు(crypto_int64_x);
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int64 crypto_int64_topbit_01(crypto_int64 crypto_int64_x) {
  తిరిగి crypto_int64_unsigned_topbit_01(crypto_int64_x);
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int64 crypto_int64_bottombit_ముసుగు(crypto_int64 crypto_int64_x) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andq $1,%0" : "+r"(crypto_int64_x) : : "cc");
  తిరిగి -crypto_int64_x;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_y;
  __asm__ ("sbfx %0,%1,0,1" : "=r"(crypto_int64_y) : "r"(crypto_int64_x) : );
  తిరిగి crypto_int64_y;
#లేకపోతే
  crypto_int64_x &= 1 ^ crypto_int64_optblocker;
  తిరిగి -crypto_int64_x;
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int64 crypto_int64_bottombit_01(crypto_int64 crypto_int64_x) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andq $1,%0" : "+r"(crypto_int64_x) : : "cc");
  తిరిగి crypto_int64_x;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_y;
  __asm__ ("ubfx %0,%1,0,1" : "=r"(crypto_int64_y) : "r"(crypto_int64_x) : );
  తిరిగి crypto_int64_y;
#లేకపోతే
  crypto_int64_x &= 1 ^ crypto_int64_optblocker;
  తిరిగి crypto_int64_x;
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int64 crypto_int64_bitinrangepublicpos_ముసుగు(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarq %%cl,%0" : "+r"(crypto_int64_x) : "c"(crypto_int64_s) : "cc");
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %0,%0,%1" : "+r"(crypto_int64_x) : "r"(crypto_int64_s) : );
#లేకపోతే
  crypto_int64_x >>= crypto_int64_s ^ crypto_int64_optblocker;
#అయితే_ముగింపు
  తిరిగి crypto_int64_bottombit_ముసుగు(crypto_int64_x);
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int64 crypto_int64_bitinrangepublicpos_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarq %%cl,%0" : "+r"(crypto_int64_x) : "c"(crypto_int64_s) : "cc");
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %0,%0,%1" : "+r"(crypto_int64_x) : "r"(crypto_int64_s) : );
#లేకపోతే
  crypto_int64_x >>= crypto_int64_s ^ crypto_int64_optblocker;
#అయితే_ముగింపు
  తిరిగి crypto_int64_bottombit_01(crypto_int64_x);
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int64 crypto_int64_shlmod(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("shlq %%cl,%0" : "+r"(crypto_int64_x) : "c"(crypto_int64_s) : "cc");
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("lsl %0,%0,%1" : "+r"(crypto_int64_x) : "r"(crypto_int64_s) : );
#లేకపోతే
  పూర్ణాంకం crypto_int64_k, crypto_int64_l;
  కొరకు (crypto_int64_l = 0,crypto_int64_k = 1;crypto_int64_k < 64;++crypto_int64_l,crypto_int64_k *= 2)
    crypto_int64_x ^= (crypto_int64_x ^ (crypto_int64_x << crypto_int64_k)) & crypto_int64_bitinrangepublicpos_ముసుగు(crypto_int64_s,crypto_int64_l);
#అయితే_ముగింపు
  తిరిగి crypto_int64_x;
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int64 crypto_int64_shrmod(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarq %%cl,%0" : "+r"(crypto_int64_x) : "c"(crypto_int64_s) : "cc");
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %0,%0,%1" : "+r"(crypto_int64_x) : "r"(crypto_int64_s) : );
#లేకపోతే
  పూర్ణాంకం crypto_int64_k, crypto_int64_l;
  కొరకు (crypto_int64_l = 0,crypto_int64_k = 1;crypto_int64_k < 64;++crypto_int64_l,crypto_int64_k *= 2)
    crypto_int64_x ^= (crypto_int64_x ^ (crypto_int64_x >> crypto_int64_k)) & crypto_int64_bitinrangepublicpos_ముసుగు(crypto_int64_s,crypto_int64_l);
#అయితే_ముగింపు
  తిరిగి crypto_int64_x;
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int64 crypto_int64_bitmod_ముసుగు(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
  crypto_int64_x = crypto_int64_shrmod(crypto_int64_x,crypto_int64_s);
  తిరిగి crypto_int64_bottombit_ముసుగు(crypto_int64_x);
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int64 crypto_int64_bitmod_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
  crypto_int64_x = crypto_int64_shrmod(crypto_int64_x,crypto_int64_s);
  తిరిగి crypto_int64_bottombit_01(crypto_int64_x);
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int64 crypto_int64_nonzero_ముసుగు(crypto_int64 crypto_int64_x) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n testq %2,%2\n cmovneq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  తిరిగి crypto_int64_z;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n csetm %0,ne" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  తిరిగి crypto_int64_z;
#లేకపోతే
  crypto_int64_x |= -crypto_int64_x;
  తిరిగి crypto_int64_negative_ముసుగు(crypto_int64_x);
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int64 crypto_int64_nonzero_01(crypto_int64 crypto_int64_x) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n testq %2,%2\n cmovneq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  తిరిగి crypto_int64_z;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n cset %0,ne" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  తిరిగి crypto_int64_z;
#లేకపోతే
  crypto_int64_x |= -crypto_int64_x;
  తిరిగి crypto_int64_unsigned_topbit_01(crypto_int64_x);
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int64 crypto_int64_ధనాత్మక_ముసుగు(crypto_int64 crypto_int64_x) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n testq %2,%2\n cmovgq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  తిరిగి crypto_int64_z;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n csetm %0,gt" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  తిరిగి crypto_int64_z;
#లేకపోతే
  crypto_int64 crypto_int64_z = -crypto_int64_x;
  crypto_int64_z ^= crypto_int64_x & crypto_int64_z;
  తిరిగి crypto_int64_negative_ముసుగు(crypto_int64_z);
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int64 crypto_int64_ధనాత్మక_01(crypto_int64 crypto_int64_x) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n testq %2,%2\n cmovgq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  తిరిగి crypto_int64_z;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n cset %0,gt" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  తిరిగి crypto_int64_z;
#లేకపోతే
  crypto_int64 crypto_int64_z = -crypto_int64_x;
  crypto_int64_z ^= crypto_int64_x & crypto_int64_z;
  తిరిగి crypto_int64_unsigned_topbit_01(crypto_int64_z);
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int64 crypto_int64_zero_ముసుగు(crypto_int64 crypto_int64_x) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n testq %2,%2\n cmoveq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  తిరిగి crypto_int64_z;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n csetm %0,eq" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  తిరిగి crypto_int64_z;
#లేకపోతే
  తిరిగి ~crypto_int64_nonzero_ముసుగు(crypto_int64_x);
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int64 crypto_int64_zero_01(crypto_int64 crypto_int64_x) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n testq %2,%2\n cmoveq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  తిరిగి crypto_int64_z;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n cset %0,eq" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  తిరిగి crypto_int64_z;
#లేకపోతే
  తిరిగి 1-crypto_int64_nonzero_01(crypto_int64_x);
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int64 crypto_int64_unequal_ముసుగు(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n cmpq %3,%2\n cmovneq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  తిరిగి crypto_int64_z;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n csetm %0,ne" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  తిరిగి crypto_int64_z;
#లేకపోతే
  తిరిగి crypto_int64_nonzero_ముసుగు(crypto_int64_x ^ crypto_int64_y);
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int64 crypto_int64_unequal_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n cmpq %3,%2\n cmovneq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  తిరిగి crypto_int64_z;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n cset %0,ne" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  తిరిగి crypto_int64_z;
#లేకపోతే
  తిరిగి crypto_int64_nonzero_01(crypto_int64_x ^ crypto_int64_y);
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int64 crypto_int64_equal_ముసుగు(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n cmpq %3,%2\n cmoveq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  తిరిగి crypto_int64_z;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n csetm %0,eq" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  తిరిగి crypto_int64_z;
#లేకపోతే
  తిరిగి ~crypto_int64_unequal_ముసుగు(crypto_int64_x,crypto_int64_y);
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int64 crypto_int64_equal_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n cmpq %3,%2\n cmoveq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  తిరిగి crypto_int64_z;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n cset %0,eq" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  తిరిగి crypto_int64_z;
#లేకపోతే
  తిరిగి 1-crypto_int64_unequal_01(crypto_int64_x,crypto_int64_y);
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int64 crypto_int64_min(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpq %1,%0\n cmovgq %1,%0" : "+r"(crypto_int64_x) : "r"(crypto_int64_y) : "cc");
  తిరిగి crypto_int64_x;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("cmp %0,%1\n csel %0,%0,%1,lt" : "+r"(crypto_int64_x) : "r"(crypto_int64_y) : "cc");
  తిరిగి crypto_int64_x;
#లేకపోతే
  crypto_int64 crypto_int64_r = crypto_int64_y ^ crypto_int64_x;
  crypto_int64 crypto_int64_z = crypto_int64_y - crypto_int64_x;
  crypto_int64_z ^= crypto_int64_r & (crypto_int64_z ^ crypto_int64_y);
  crypto_int64_z = crypto_int64_negative_ముసుగు(crypto_int64_z);
  crypto_int64_z &= crypto_int64_r;
  తిరిగి crypto_int64_x ^ crypto_int64_z;
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int64 crypto_int64_max(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpq %1,%0\n cmovlq %1,%0" : "+r"(crypto_int64_x) : "r"(crypto_int64_y) : "cc");
  తిరిగి crypto_int64_x;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("cmp %0,%1\n csel %0,%1,%0,lt" : "+r"(crypto_int64_x) : "r"(crypto_int64_y) : "cc");
  తిరిగి crypto_int64_x;
#లేకపోతే
  crypto_int64 crypto_int64_r = crypto_int64_y ^ crypto_int64_x;
  crypto_int64 crypto_int64_z = crypto_int64_y - crypto_int64_x;
  crypto_int64_z ^= crypto_int64_r & (crypto_int64_z ^ crypto_int64_y);
  crypto_int64_z = crypto_int64_negative_ముసుగు(crypto_int64_z);
  crypto_int64_z &= crypto_int64_r;
  తిరిగి crypto_int64_y ^ crypto_int64_z;
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
శూన్య crypto_int64_minmax(crypto_int64 *crypto_int64_p,crypto_int64 *crypto_int64_q) {
  crypto_int64 crypto_int64_x = *crypto_int64_p;
  crypto_int64 crypto_int64_y = *crypto_int64_q;
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmpq %2,%1\n movq %1,%0\n cmovgq %2,%1\n cmovgq %0,%2" : "=&r"(crypto_int64_z), "+&r"(crypto_int64_x), "+r"(crypto_int64_y) : : "cc");
  *crypto_int64_p = crypto_int64_x;
  *crypto_int64_q = crypto_int64_y;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_r, crypto_int64_s;
  __asm__ ("cmp %2,%3\n csel %0,%2,%3,lt\n csel %1,%3,%2,lt" : "=&r"(crypto_int64_r), "=r"(crypto_int64_s) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  *crypto_int64_p = crypto_int64_r;
  *crypto_int64_q = crypto_int64_s;
#లేకపోతే
  crypto_int64 crypto_int64_r = crypto_int64_y ^ crypto_int64_x;
  crypto_int64 crypto_int64_z = crypto_int64_y - crypto_int64_x;
  crypto_int64_z ^= crypto_int64_r & (crypto_int64_z ^ crypto_int64_y);
  crypto_int64_z = crypto_int64_negative_ముసుగు(crypto_int64_z);
  crypto_int64_z &= crypto_int64_r;
  crypto_int64_x ^= crypto_int64_z;
  crypto_int64_y ^= crypto_int64_z;
  *crypto_int64_p = crypto_int64_x;
  *crypto_int64_q = crypto_int64_y;
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int64 crypto_int64_smaller_ముసుగు(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n cmpq %3,%2\n cmovlq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  తిరిగి crypto_int64_z;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n csetm %0,lt" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  తిరిగి crypto_int64_z;
#లేకపోతే
  crypto_int64 crypto_int64_r = crypto_int64_x ^ crypto_int64_y;
  crypto_int64 crypto_int64_z = crypto_int64_x - crypto_int64_y;
  crypto_int64_z ^= crypto_int64_r & (crypto_int64_z ^ crypto_int64_x);
  తిరిగి crypto_int64_negative_ముసుగు(crypto_int64_z);
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int64 crypto_int64_smaller_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n cmpq %3,%2\n cmovlq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  తిరిగి crypto_int64_z;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n cset %0,lt" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  తిరిగి crypto_int64_z;
#లేకపోతే
  crypto_int64 crypto_int64_r = crypto_int64_x ^ crypto_int64_y;
  crypto_int64 crypto_int64_z = crypto_int64_x - crypto_int64_y;
  crypto_int64_z ^= crypto_int64_r & (crypto_int64_z ^ crypto_int64_x);
  తిరిగి crypto_int64_unsigned_topbit_01(crypto_int64_z);
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int64 crypto_int64_leq_ముసుగు(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n cmpq %3,%2\n cmovleq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  తిరిగి crypto_int64_z;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n csetm %0,le" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  తిరిగి crypto_int64_z;
#లేకపోతే
  తిరిగి ~crypto_int64_smaller_ముసుగు(crypto_int64_y,crypto_int64_x);
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
crypto_int64 crypto_int64_leq_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n cmpq %3,%2\n cmovleq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  తిరిగి crypto_int64_z;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n cset %0,le" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  తిరిగి crypto_int64_z;
#లేకపోతే
  తిరిగి 1-crypto_int64_smaller_01(crypto_int64_y,crypto_int64_x);
#అయితే_ముగింపు
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
పూర్ణాంకం crypto_int64_ones_అంకె(crypto_int64 crypto_int64_x) {
  crypto_int64_unsigned crypto_int64_y = crypto_int64_x;
  స్థిరరాశి crypto_int64 C0 = 0x5555555555555555;
  స్థిరరాశి crypto_int64 C1 = 0x3333333333333333;
  స్థిరరాశి crypto_int64 C2 = 0x0f0f0f0f0f0f0f0f;
  crypto_int64_y -= ((crypto_int64_y >> 1) & C0);
  crypto_int64_y = (crypto_int64_y & C1) + ((crypto_int64_y >> 2) & C1);
  crypto_int64_y = (crypto_int64_y + (crypto_int64_y >> 4)) & C2;
  crypto_int64_y += crypto_int64_y >> 8;
  crypto_int64_y += crypto_int64_y >> 16;
  crypto_int64_y = (crypto_int64_y + (crypto_int64_y >> 32)) & 0xff;
  తిరిగి crypto_int64_y;
}

__attribute__((వాడని))
స్థిర అంతఃవరుస
పూర్ణాంకం crypto_int64_bottomzeros_అంకె(crypto_int64 crypto_int64_x) {
#ఒకవేళ defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 fallback = 64;
  __asm__ ("bsfq %0,%0\n cmoveq %1,%0" : "+&r"(crypto_int64_x) : "r"(fallback) : "cc");
  తిరిగి crypto_int64_x;
#లేదావేళ defined(__GNUC__) && defined(__aarch64__)
  int64_t crypto_int64_y;
  __asm__ ("rbit %0,%1\n clz %0,%0" : "=r"(crypto_int64_y) : "r"(crypto_int64_x) : );
  తిరిగి crypto_int64_y;
#లేకపోతే
  crypto_int64 crypto_int64_y = crypto_int64_x ^ (crypto_int64_x-1);
  crypto_int64_y = ((crypto_int64) crypto_int64_y) >> 1;
  crypto_int64_y &= ~(crypto_int64_x & (((crypto_int64) 1) << (64-1)));
  తిరిగి crypto_int64_ones_అంకె(crypto_int64_y);
#అయితే_ముగింపు
}

#అయితే_ముగింపు

/* from supercop-20240808/crypto_sort/int32/portable4/sort.c */
#నిర్వచించు int32_MINMAX(a,b) crypto_int32_minmax(&a,&b)

స్థిర శూన్య crypto_క్రమీకరించు_int32(శూన్య *array,దీర్ఘ దీర్ఘ n)
{
  దీర్ఘ దీర్ఘ శిఖరం,p,q,r,i,j;
  int32 *x = array;

  ఒకవేళ (n < 2) తిరిగి;
  శిఖరం = 1;
  అయితే (శిఖరం < n - శిఖరం) శిఖరం += శిఖరం;

  కొరకు (p = శిఖరం;p >= 1;p >>= 1) {
    i = 0;
    అయితే (i + 2 * p <= n) {
      కొరకు (j = i;j < i + p;++j)
        int32_MINMAX(x[j],x[j+p]);
      i += 2 * p;
    }
    కొరకు (j = i;j < n - p;++j)
      int32_MINMAX(x[j],x[j+p]);

    i = 0;
    j = 0;
    కొరకు (q = శిఖరం;q > p;q >>= 1) {
      ఒకవేళ (j != i) కొరకు (;;) {
        ఒకవేళ (j == n - q) వెళ్ళు పూర్తి;
        int32 a = x[j + p];
        కొరకు (r = q;r > p;r >>= 1)
          int32_MINMAX(a,x[j + r]);
        x[j + p] = a;
        ++j;
        ఒకవేళ (j == i + p) {
          i += 2 * p;
          ఆపు;
        }
      }
      అయితే (i + p <= n - q) {
        కొరకు (j = i;j < i + p;++j) {
          int32 a = x[j + p];
          కొరకు (r = q;r > p;r >>= 1)
            int32_MINMAX(a,x[j+r]);
          x[j + p] = a;
        }
        i += 2 * p;
      }
      /* now i + p > n - q */
      j = i;
      అయితే (j < n - q) {
        int32 a = x[j + p];
        కొరకు (r = q;r > p;r >>= 1)
          int32_MINMAX(a,x[j+r]);
        x[j + p] = a;
        ++j;
      }

      పూర్తి: ;
    }
  }
}

/* from supercop-20240808/crypto_sort/uint32/useint32/sort.c */

/* can save time by vectorizing xor loops */
/* can save time by integrating xor loops with int32_sort */

స్థిర శూన్య crypto_క్రమీకరించు_uint32(శూన్య *array,దీర్ఘ దీర్ఘ n)
{
  crypto_uint32 *x = array;
  దీర్ఘ దీర్ఘ j;
  కొరకు (j = 0;j < n;++j) x[j] ^= 0x80000000;
  crypto_క్రమీకరించు_int32(array,n);
  కొరకు (j = 0;j < n;++j) x[j] ^= 0x80000000;
}

/* from supercop-20240808/crypto_kem/sntrup761/compact/kem.c */
// 20240806 djb: some automated conversion to cryptoint

#నిర్వచించు p 761
#నిర్వచించు q 4591
#నిర్వచించు w 286
#నిర్వచించు q12 ((q - 1) / 2)
రకనిర్వచనం int8_t small;
రకనిర్వచనం int16_t Fq;
#నిర్వచించు Hash_బైట్లు 32
#నిర్వచించు Small_బైట్లు ((p + 3) / 4)
రకనిర్వచనం small Inputs[p];
#నిర్వచించు Secret_కీలకాలు_బైట్లు (2 * Small_బైట్లు)
#నిర్వచించు Confirm_బైట్లు 32

స్థిర small F3_freeze(int16_t x) { తిరిగి x - 3 * ((10923 * x + 16384) >> 15); }

స్థిర Fq Fq_freeze(int32_t x) {
  స్థిరరాశి int32_t q16 = (0x10000 + q / 2) / q;
  స్థిరరాశి int32_t q20 = (0x100000 + q / 2) / q;
  స్థిరరాశి int32_t q28 = (0x10000000 + q / 2) / q;
  x -= q * ((q16 * x) >> 16);
  x -= q * ((q20 * x) >> 20);
  తిరిగి x - q * ((q28 * x + 0x8000000) >> 28);
}

స్థిర పూర్ణాంకం Weightw_ముసుగు(small *r) {
  పూర్ణాంకం i, బరువు = 0;
  కొరకు (i = 0; i < p; ++i) బరువు += crypto_int64_bottombit_01(r[i]);
  తిరిగి crypto_int16_nonzero_ముసుగు(బరువు - w);
}

స్థిర శూన్య uint32_divmod_uint14(uint32_t *Q, uint16_t *r, uint32_t x, uint16_t m) {
  uint32_t qpart, ముసుగు, v = 0x80000000 / m;
  qpart = (x * (uint64_t)v) >> 31;
  x -= qpart * m;
  *Q = qpart;
  qpart = (x * (uint64_t)v) >> 31;
  x -= qpart * m;
  *Q += qpart;
  x -= m;
  *Q += 1;
  ముసుగు = crypto_int32_negative_ముసుగు(x);
  x += ముసుగు & (uint32_t)m;
  *Q += ముసుగు;
  *r = x;
}

స్థిర uint16_t uint32_mod_uint14(uint32_t x, uint16_t m) {
  uint32_t Q;
  uint16_t r;
  uint32_divmod_uint14(&Q, &r, x, m);
  తిరిగి r;
}

స్థిర శూన్య Encode(గుర్తులేని అక్షరం *బహిర్గతం, స్థిరరాశి uint16_t *R, స్థిరరాశి uint16_t *M, దీర్ఘ దీర్ఘ len) {
  ఒకవేళ (len == 1) {
    uint16_t r = R[0], m = M[0];
    అయితే (m > 1) {
      *బహిర్గతం++ = r;
      r >>= 8;
      m = (m + 255) >> 8;
    }
  }
  ఒకవేళ (len > 1) {
    uint16_t R2[(len + 1) / 2], M2[(len + 1) / 2];
    దీర్ఘ దీర్ఘ i;
    కొరకు (i = 0; i < len - 1; i += 2) {
      uint32_t m0 = M[i];
      uint32_t r = R[i] + R[i + 1] * m0;
      uint32_t m = M[i + 1] * m0;
      అయితే (m >= 16384) {
        *బహిర్గతం++ = r;
        r >>= 8;
        m = (m + 255) >> 8;
      }
      R2[i / 2] = r;
      M2[i / 2] = m;
    }
    ఒకవేళ (i < len) {
      R2[i / 2] = R[i];
      M2[i / 2] = M[i];
    }
    Encode(బహిర్గతం, R2, M2, (len + 1) / 2);
  }
}

స్థిర శూన్య Decode(uint16_t *బహిర్గతం, స్థిరరాశి గుర్తులేని అక్షరం *S, స్థిరరాశి uint16_t *M, దీర్ఘ దీర్ఘ len) {
  ఒకవేళ (len == 1) {
    ఒకవేళ (M[0] == 1)
      *బహిర్గతం = 0;
    లేకపోతే ఒకవేళ (M[0] <= 256)
      *బహిర్గతం = uint32_mod_uint14(S[0], M[0]);
    లేకపోతే
      *బహిర్గతం = uint32_mod_uint14(S[0] + (((uint16_t)S[1]) << 8), M[0]);
  }
  ఒకవేళ (len > 1) {
    uint16_t R2[(len + 1) / 2], M2[(len + 1) / 2], bottomr[len / 2];
    uint32_t bottomt[len / 2];
    దీర్ఘ దీర్ఘ i;
    కొరకు (i = 0; i < len - 1; i += 2) {
      uint32_t m = M[i] * (uint32_t)M[i + 1];
      ఒకవేళ (m > 256 * 16383) {
        bottomt[i / 2] = 256 * 256;
        bottomr[i / 2] = S[0] + 256 * S[1];
        S += 2;
        M2[i / 2] = (((m + 255) >> 8) + 255) >> 8;
      } లేకపోతే ఒకవేళ (m >= 16384) {
        bottomt[i / 2] = 256;
        bottomr[i / 2] = S[0];
        S += 1;
        M2[i / 2] = (m + 255) >> 8;
      } లేకపోతే {
        bottomt[i / 2] = 1;
        bottomr[i / 2] = 0;
        M2[i / 2] = m;
      }
    }
    ఒకవేళ (i < len) M2[i / 2] = M[i];
    Decode(R2, S, M2, (len + 1) / 2);
    కొరకు (i = 0; i < len - 1; i += 2) {
      uint32_t r1, r = bottomr[i / 2];
      uint16_t r0;
      r += bottomt[i / 2] * R2[i / 2];
      uint32_divmod_uint14(&r1, &r0, r, M[i]);
      r1 = uint32_mod_uint14(r1, M[i + 1]);
      *బహిర్గతం++ = r0;
      *బహిర్గతం++ = r1;
    }
    ఒకవేళ (i < len) *బహిర్గతం++ = R2[i / 2];
  }
}

స్థిర శూన్య R3_fromRq(small *బహిర్గతం, స్థిరరాశి Fq *r) {
  పూర్ణాంకం i;
  కొరకు (i = 0; i < p; ++i) బహిర్గతం[i] = F3_freeze(r[i]);
}

స్థిర శూన్య R3_mult(small *h, స్థిరరాశి small *f, స్థిరరాశి small *g) {
  int16_t fg[p + p - 1];
  పూర్ణాంకం i, j;
  కొరకు (i = 0; i < p + p - 1; ++i) fg[i] = 0;
  కొరకు (i = 0; i < p; ++i)
    కొరకు (j = 0; j < p; ++j) fg[i + j] += f[i] * (int16_t)g[j];
  కొరకు (i = p; i < p + p - 1; ++i) fg[i - p] += fg[i];
  కొరకు (i = p; i < p + p - 1; ++i) fg[i - p + 1] += fg[i];
  కొరకు (i = 0; i < p; ++i) h[i] = F3_freeze(fg[i]);
}

స్థిర పూర్ణాంకం R3_recip(small *బహిర్గతం, స్థిరరాశి small *లోపల) {
  small f[p + 1], g[p + 1], v[p + 1], r[p + 1];
  పూర్ణాంకం sign, మార్పిడి, t, i, loop, delta = 1;
  కొరకు (i = 0; i < p + 1; ++i) v[i] = 0;
  కొరకు (i = 0; i < p + 1; ++i) r[i] = 0;
  r[0] = 1;
  కొరకు (i = 0; i < p; ++i) f[i] = 0;
  f[0] = 1;
  f[p - 1] = f[p] = -1;
  కొరకు (i = 0; i < p; ++i) g[p - 1 - i] = లోపల[i];
  g[p] = 0;
  కొరకు (loop = 0; loop < 2 * p - 1; ++loop) {
    కొరకు (i = p; i > 0; --i) v[i] = v[i - 1];
    v[0] = 0;
    sign = -g[0] * f[0];
    మార్పిడి = crypto_int16_negative_ముసుగు(-delta) & crypto_int16_nonzero_ముసుగు(g[0]);
    delta ^= మార్పిడి & (delta ^ -delta);
    delta += 1;
    కొరకు (i = 0; i < p + 1; ++i) {
      t = మార్పిడి & (f[i] ^ g[i]);
      f[i] ^= t;
      g[i] ^= t;
      t = మార్పిడి & (v[i] ^ r[i]);
      v[i] ^= t;
      r[i] ^= t;
    }
    కొరకు (i = 0; i < p + 1; ++i) g[i] = F3_freeze(g[i] + sign * f[i]);
    కొరకు (i = 0; i < p + 1; ++i) r[i] = F3_freeze(r[i] + sign * v[i]);
    కొరకు (i = 0; i < p; ++i) g[i] = g[i + 1];
    g[p] = 0;
  }
  sign = f[0];
  కొరకు (i = 0; i < p; ++i) బహిర్గతం[i] = sign * v[p - 1 - i];
  తిరిగి crypto_int16_nonzero_ముసుగు(delta);
}

స్థిర శూన్య Rq_mult_small(Fq *h, స్థిరరాశి Fq *f, స్థిరరాశి small *g) {
  int32_t fg[p + p - 1];
  పూర్ణాంకం i, j;
  కొరకు (i = 0; i < p + p - 1; ++i) fg[i] = 0;
  కొరకు (i = 0; i < p; ++i)
    కొరకు (j = 0; j < p; ++j) fg[i + j] += f[i] * (int32_t)g[j];
  కొరకు (i = p; i < p + p - 1; ++i) fg[i - p] += fg[i];
  కొరకు (i = p; i < p + p - 1; ++i) fg[i - p + 1] += fg[i];
  కొరకు (i = 0; i < p; ++i) h[i] = Fq_freeze(fg[i]);
}

స్థిర శూన్య Rq_mult3(Fq *h, స్థిరరాశి Fq *f) {
  పూర్ణాంకం i;
  కొరకు (i = 0; i < p; ++i) h[i] = Fq_freeze(3 * f[i]);
}

స్థిర Fq Fq_recip(Fq a1) {
  పూర్ణాంకం i = 1;
  Fq ai = a1;
  అయితే (i < q - 2) {
    ai = Fq_freeze(a1 * (int32_t)ai);
    i += 1;
  }
  తిరిగి ai;
}

స్థిర పూర్ణాంకం Rq_recip3(Fq *బహిర్గతం, స్థిరరాశి small *లోపల) {
  Fq f[p + 1], g[p + 1], v[p + 1], r[p + 1], scale;
  పూర్ణాంకం మార్పిడి, t, i, loop, delta = 1;
  int32_t f0, g0;
  కొరకు (i = 0; i < p + 1; ++i) v[i] = 0;
  కొరకు (i = 0; i < p + 1; ++i) r[i] = 0;
  r[0] = Fq_recip(3);
  కొరకు (i = 0; i < p; ++i) f[i] = 0;
  f[0] = 1;
  f[p - 1] = f[p] = -1;
  కొరకు (i = 0; i < p; ++i) g[p - 1 - i] = లోపల[i];
  g[p] = 0;
  కొరకు (loop = 0; loop < 2 * p - 1; ++loop) {
    కొరకు (i = p; i > 0; --i) v[i] = v[i - 1];
    v[0] = 0;
    మార్పిడి = crypto_int16_negative_ముసుగు(-delta) & crypto_int16_nonzero_ముసుగు(g[0]);
    delta ^= మార్పిడి & (delta ^ -delta);
    delta += 1;
    కొరకు (i = 0; i < p + 1; ++i) {
      t = మార్పిడి & (f[i] ^ g[i]);
      f[i] ^= t;
      g[i] ^= t;
      t = మార్పిడి & (v[i] ^ r[i]);
      v[i] ^= t;
      r[i] ^= t;
    }
    f0 = f[0];
    g0 = g[0];
    కొరకు (i = 0; i < p + 1; ++i) g[i] = Fq_freeze(f0 * g[i] - g0 * f[i]);
    కొరకు (i = 0; i < p + 1; ++i) r[i] = Fq_freeze(f0 * r[i] - g0 * v[i]);
    కొరకు (i = 0; i < p; ++i) g[i] = g[i + 1];
    g[p] = 0;
  }
  scale = Fq_recip(f[0]);
  కొరకు (i = 0; i < p; ++i) బహిర్గతం[i] = Fq_freeze(scale * (int32_t)v[p - 1 - i]);
  తిరిగి crypto_int16_nonzero_ముసుగు(delta);
}

స్థిర శూన్య విడత_3(Fq *బహిర్గతం, స్థిరరాశి Fq *a) {
  పూర్ణాంకం i;
  కొరకు (i = 0; i < p; ++i) బహిర్గతం[i] = a[i] - F3_freeze(a[i]);
}

స్థిర శూన్య Short_fromlist(small *బహిర్గతం, స్థిరరాశి uint32_t *లోపల) {
  uint32_t L[p];
  పూర్ణాంకం i;
  కొరకు (i = 0; i < w; ++i) L[i] = లోపల[i] & (uint32_t)-2;
  కొరకు (i = w; i < p; ++i) L[i] = (లోపల[i] & (uint32_t)-3) | 1;
  crypto_క్రమీకరించు_uint32(L, p);
  కొరకు (i = 0; i < p; ++i) బహిర్గతం[i] = (L[i] & 3) - 1;
}

స్థిర శూన్య Hash_ఉపసర్గ(గుర్తులేని అక్షరం *బహిర్గతం, పూర్ణాంకం b, స్థిరరాశి గుర్తులేని అక్షరం *లోపల, పూర్ణాంకం inlen) {
  గుర్తులేని అక్షరం x[inlen + 1], h[64];
  పూర్ణాంకం i;
  x[0] = b;
  కొరకు (i = 0; i < inlen; ++i) x[i + 1] = లోపల[i];
  crypto_hash_sha512(h, x, inlen + 1);
  కొరకు (i = 0; i < 32; ++i) బహిర్గతం[i] = h[i];
}


స్థిర శూన్య Short_random(small *బహిర్గతం) {
  uint32_t L[p];
  randombytes(L, పరిమాణం(L));
  Short_fromlist(బహిర్గతం, L);
  explicit_bzero(L, పరిమాణం(L));
}
స్థిర శూన్య Small_random(small *బహిర్గతం) {
  పూర్ణాంకం i;
  uint32_t L[p];
  randombytes(L, పరిమాణం(L));
  కొరకు (i = 0; i < p; ++i) బహిర్గతం[i] = (((L[i] & 0x3fffffff) * 3) >> 30) - 1;
  explicit_bzero(L, పరిమాణం(L));
}
స్థిర శూన్య కీలకం_Gen(Fq *h, small *f, small *ginv) {
  small g[p];
  Fq finv[p];
  కొరకు (;;) {
    పూర్ణాంకం ఫలితం;
    Small_random(g);
    ఫలితం = R3_recip(ginv, g);
    crypto_declassify(&ఫలితం, పరిమాణం ఫలితం);
    ఒకవేళ (ఫలితం == 0) ఆపు;
  }
  Short_random(f);
  Rq_recip3(finv, f);
  Rq_mult_small(h, finv, g);
}

స్థిర శూన్య Encrypt(Fq *c, స్థిరరాశి small *r, స్థిరరాశి Fq *h) {
  Fq hr[p];
  Rq_mult_small(hr, h, r);
  విడత_3(c, hr);
}

స్థిర శూన్య Decrypt(small *r, స్థిరరాశి Fq *c, స్థిరరాశి small *f, స్థిరరాశి small *ginv) {
  Fq cf[p], cf3[p];
  small e[p], ev[p];
  పూర్ణాంకం ముసుగు, i;
  Rq_mult_small(cf, c, f);
  Rq_mult3(cf3, cf);
  R3_fromRq(e, cf3);
  R3_mult(ev, e, ginv);
  ముసుగు = Weightw_ముసుగు(ev);
  కొరకు (i = 0; i < w; ++i) r[i] = ((ev[i] ^ 1) & ~ముసుగు) ^ 1;
  కొరకు (i = w; i < p; ++i) r[i] = ev[i] & ~ముసుగు;
}

స్థిర శూన్య Small_encode(గుర్తులేని అక్షరం *s, స్థిరరాశి small *f) {
  పూర్ణాంకం i, j;
  కొరకు (i = 0; i < p / 4; ++i) {
    small x = 0;
    కొరకు (j = 0;j < 4;++j) x += (*f++ + 1) << (2 * j);
    *s++ = x;
  }
  *s = *f++ + 1;
}

స్థిర శూన్య Small_decode(small *f, స్థిరరాశి గుర్తులేని అక్షరం *s) {
  పూర్ణాంకం i, j;
  కొరకు (i = 0; i < p / 4; ++i) {
    గుర్తులేని అక్షరం x = *s++;
    కొరకు (j = 0;j < 4;++j) *f++ = ((small)((x >> (2 * j)) & 3)) - 1;
  }
  *f++ = ((small)(*s & 3)) - 1;
}

స్థిర శూన్య Rq_encode(గుర్తులేని అక్షరం *s, స్థిరరాశి Fq *r) {
  uint16_t R[p], M[p];
  పూర్ణాంకం i;
  కొరకు (i = 0; i < p; ++i) R[i] = r[i] + q12;
  కొరకు (i = 0; i < p; ++i) M[i] = q;
  Encode(s, R, M, p);
}

స్థిర శూన్య Rq_decode(Fq *r, స్థిరరాశి గుర్తులేని అక్షరం *s) {
  uint16_t R[p], M[p];
  పూర్ణాంకం i;
  కొరకు (i = 0; i < p; ++i) M[i] = q;
  Decode(R, s, M, p);
  కొరకు (i = 0; i < p; ++i) r[i] = ((Fq)R[i]) - q12;
}

స్థిర శూన్య Rounded_encode(గుర్తులేని అక్షరం *s, స్థిరరాశి Fq *r) {
  uint16_t R[p], M[p];
  పూర్ణాంకం i;
  కొరకు (i = 0; i < p; ++i) R[i] = ((r[i] + q12) * 10923) >> 15;
  కొరకు (i = 0; i < p; ++i) M[i] = (q + 2) / 3;
  Encode(s, R, M, p);
}

స్థిర శూన్య Rounded_decode(Fq *r, స్థిరరాశి గుర్తులేని అక్షరం *s) {
  uint16_t R[p], M[p];
  పూర్ణాంకం i;
  కొరకు (i = 0; i < p; ++i) M[i] = (q + 2) / 3;
  Decode(R, s, M, p);
  కొరకు (i = 0; i < p; ++i) r[i] = R[i] * 3 - q12;
}

స్థిర శూన్య ZKeyGen(గుర్తులేని అక్షరం *pk, గుర్తులేని అక్షరం *sk) {
  Fq h[p];
  small f[p], v[p];
  కీలకం_Gen(h, f, v);
  Rq_encode(pk, h);
  Small_encode(sk, f);
  Small_encode(sk + Small_బైట్లు, v);
}

స్థిర శూన్య ZEncrypt(గుర్తులేని అక్షరం *C, స్థిరరాశి Inputs r, స్థిరరాశి గుర్తులేని అక్షరం *pk) {
  Fq h[p], c[p];
  Rq_decode(h, pk);
  Encrypt(c, r, h);
  Rounded_encode(C, c);
}

స్థిర శూన్య ZDecrypt(Inputs r, స్థిరరాశి గుర్తులేని అక్షరం *C, స్థిరరాశి గుర్తులేని అక్షరం *sk) {
  small f[p], v[p];
  Fq c[p];
  Small_decode(f, sk);
  Small_decode(v, sk + Small_బైట్లు);
  Rounded_decode(c, C);
  Decrypt(r, c, f, v);
}

స్థిర శూన్య HashConfirm(గుర్తులేని అక్షరం *h, స్థిరరాశి గుర్తులేని అక్షరం *r, స్థిరరాశి గుర్తులేని అక్షరం *cache) {
  గుర్తులేని అక్షరం x[Hash_బైట్లు * 2];
  పూర్ణాంకం i;
  Hash_ఉపసర్గ(x, 3, r, Small_బైట్లు);
  కొరకు (i = 0; i < Hash_బైట్లు; ++i) x[Hash_బైట్లు + i] = cache[i];
  Hash_ఉపసర్గ(h, 2, x, పరిమాణం x);
}

స్థిర శూన్య HashSession(గుర్తులేని అక్షరం *k, పూర్ణాంకం b, స్థిరరాశి గుర్తులేని అక్షరం *y, స్థిరరాశి గుర్తులేని అక్షరం *z) {
  గుర్తులేని అక్షరం x[Hash_బైట్లు + crypto_kem_sntrup761_CIPHERTEXTBYTES];
  పూర్ణాంకం i;
  Hash_ఉపసర్గ(x, 3, y, Small_బైట్లు);
  కొరకు (i = 0; i < crypto_kem_sntrup761_CIPHERTEXTBYTES; ++i) x[Hash_బైట్లు + i] = z[i];
  Hash_ఉపసర్గ(k, b, x, పరిమాణం x);
}

పూర్ణాంకం crypto_kem_sntrup761_keypair(గుర్తులేని అక్షరం *pk, గుర్తులేని అక్షరం *sk) {
  పూర్ణాంకం i;
  ZKeyGen(pk, sk);
  sk += Secret_కీలకాలు_బైట్లు;
  కొరకు (i = 0; i < crypto_kem_sntrup761_PUBLICKEYBYTES; ++i) *sk++ = pk[i];
  randombytes(sk, Small_బైట్లు);
  Hash_ఉపసర్గ(sk + Small_బైట్లు, 4, pk, crypto_kem_sntrup761_PUBLICKEYBYTES);
  తిరిగి 0;
}

స్థిర శూన్య Hide(గుర్తులేని అక్షరం *c, గుర్తులేని అక్షరం *r_enc, స్థిరరాశి Inputs r, స్థిరరాశి గుర్తులేని అక్షరం *pk, స్థిరరాశి గుర్తులేని అక్షరం *cache) {
  Small_encode(r_enc, r);
  ZEncrypt(c, r, pk);
  HashConfirm(c + crypto_kem_sntrup761_CIPHERTEXTBYTES - Confirm_బైట్లు, r_enc, cache);
}

పూర్ణాంకం crypto_kem_sntrup761_enc(గుర్తులేని అక్షరం *c, గుర్తులేని అక్షరం *k, స్థిరరాశి గుర్తులేని అక్షరం *pk) {
  Inputs r;
  గుర్తులేని అక్షరం r_enc[Small_బైట్లు], cache[Hash_బైట్లు];
  Hash_ఉపసర్గ(cache, 4, pk, crypto_kem_sntrup761_PUBLICKEYBYTES);
  Short_random(r);
  Hide(c, r_enc, r, pk, cache);
  HashSession(k, 1, r_enc, c);
  తిరిగి 0;
}

స్థిర పూర్ణాంకం Ciphertexts_diff_ముసుగు(స్థిరరాశి గుర్తులేని అక్షరం *c, స్థిరరాశి గుర్తులేని అక్షరం *c2) {
  uint16_t differentbits = 0;
  పూర్ణాంకం len = crypto_kem_sntrup761_CIPHERTEXTBYTES;
  అయితే (len-- > 0) differentbits |= (*c++) ^ (*c2++);
  తిరిగి (crypto_int64_bitmod_01((differentbits - 1),8)) - 1;
}

పూర్ణాంకం crypto_kem_sntrup761_dec(గుర్తులేని అక్షరం *k, స్థిరరాశి గుర్తులేని అక్షరం *c, స్థిరరాశి గుర్తులేని అక్షరం *sk) {
  స్థిరరాశి గుర్తులేని అక్షరం *pk = sk + Secret_కీలకాలు_బైట్లు;
  స్థిరరాశి గుర్తులేని అక్షరం *rho = pk + crypto_kem_sntrup761_PUBLICKEYBYTES;
  స్థిరరాశి గుర్తులేని అక్షరం *cache = rho + Small_బైట్లు;
  Inputs r;
  గుర్తులేని అక్షరం r_enc[Small_బైట్లు], cnew[crypto_kem_sntrup761_CIPHERTEXTBYTES];
  పూర్ణాంకం ముసుగు, i;
  ZDecrypt(r, c, sk);
  Hide(cnew, r_enc, r, pk, cache);
  ముసుగు = Ciphertexts_diff_ముసుగు(c, cnew);
  కొరకు (i = 0; i < Small_బైట్లు; ++i) r_enc[i] ^= ముసుగు & (r_enc[i] ^ rho[i]);
  HashSession(k, 1 + ముసుగు, r_enc, c);
  తిరిగి 0;
}

#అయితే_ముగింపు /* USE_SNTRUP761X25519 */
