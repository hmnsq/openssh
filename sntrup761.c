/*  $OpenBSD: sntrup761.c,v 1.9 2026/01/20 22:56:11 dtucker Exp $ */

/*
 * Public Domain, Authors:
 * - Daniel J. Bernstein
 * - Chitchanok Chuengsatiansup
 * - Tanja Lange
 * - Christine van Vredendaal
 */

#شامل "includes.h"

#اگر_تعریف_شدہ USE_SNTRUP761X25519

#شامل <string.h>
#شامل "crypto_api.h"

#تعریف_کرو crypto_declassify(x, y) کرو {} جب (0)

#تعریف_کرو int8 crypto_int8
#تعریف_کرو uint8 crypto_uint8
#تعریف_کرو int16 crypto_int16
#تعریف_کرو uint16 crypto_uint16
#تعریف_کرو int32 crypto_int32
#تعریف_کرو uint32 crypto_uint32
#تعریف_کرو int64 crypto_int64
#تعریف_کرو uint64 crypto_uint64
خارجی متلون crypto_int16 crypto_int16_optblocker;
خارجی متلون crypto_int32 crypto_int32_optblocker;
خارجی متلون crypto_int64 crypto_int64_optblocker;

/* from supercop-20240808/cryptoint/crypto_int16.h */
/* auto-generated: cd cryptoint; ./autogen */
/* cryptoint 20240806 */

#اگر_غیر_تعریف_شدہ crypto_int16_h
#تعریف_کرو crypto_int16_h

#تعریف_کرو crypto_int16 int16_t
#تعریف_کرو crypto_int16_unsigned uint16_t



__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int16 crypto_int16_بھرو(ثابت غیرعلامتی حرف *crypto_int16_s) {
  crypto_int16 crypto_int16_z = 0;
  crypto_int16_z |= ((crypto_int16) (*crypto_int16_s++)) << 0;
  crypto_int16_z |= ((crypto_int16) (*crypto_int16_s++)) << 8;
  واپس crypto_int16_z;
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
خالی crypto_int16_store(غیرعلامتی حرف *crypto_int16_s,crypto_int16 crypto_int16_x) {
  *crypto_int16_s++ = crypto_int16_x >> 0;
  *crypto_int16_s++ = crypto_int16_x >> 8;
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int16 crypto_int16_negative_نقاب(crypto_int16 crypto_int16_x) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarw $15,%0" : "+r"(crypto_int16_x) : : "cc");
  واپس crypto_int16_x;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_y;
  __asm__ ("sbfx %w0,%w1,15,1" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) : );
  واپس crypto_int16_y;
#ورنہ
  crypto_int16_x >>= 16-6;
  crypto_int16_x ^= crypto_int16_optblocker;
  crypto_int16_x >>= 5;
  واپس crypto_int16_x;
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int16_unsigned crypto_int16_unsigned_topbit_01(crypto_int16_unsigned crypto_int16_x) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("shrw $15,%0" : "+r"(crypto_int16_x) : : "cc");
  واپس crypto_int16_x;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_y;
  __asm__ ("ubfx %w0,%w1,15,1" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) : );
  واپس crypto_int16_y;
#ورنہ
  crypto_int16_x >>= 16-6;
  crypto_int16_x ^= crypto_int16_optblocker;
  crypto_int16_x >>= 5;
  واپس crypto_int16_x;
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int16 crypto_int16_negative_01(crypto_int16 crypto_int16_x) {
  واپس crypto_int16_unsigned_topbit_01(crypto_int16_x);
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int16 crypto_int16_topbit_نقاب(crypto_int16 crypto_int16_x) {
  واپس crypto_int16_negative_نقاب(crypto_int16_x);
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int16 crypto_int16_topbit_01(crypto_int16 crypto_int16_x) {
  واپس crypto_int16_unsigned_topbit_01(crypto_int16_x);
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int16 crypto_int16_bottombit_نقاب(crypto_int16 crypto_int16_x) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andw $1,%0" : "+r"(crypto_int16_x) : : "cc");
  واپس -crypto_int16_x;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_y;
  __asm__ ("sbfx %w0,%w1,0,1" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) : );
  واپس crypto_int16_y;
#ورنہ
  crypto_int16_x &= 1 ^ crypto_int16_optblocker;
  واپس -crypto_int16_x;
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int16 crypto_int16_bottombit_01(crypto_int16 crypto_int16_x) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andw $1,%0" : "+r"(crypto_int16_x) : : "cc");
  واپس crypto_int16_x;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_y;
  __asm__ ("ubfx %w0,%w1,0,1" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) : );
  واپس crypto_int16_y;
#ورنہ
  crypto_int16_x &= 1 ^ crypto_int16_optblocker;
  واپس crypto_int16_x;
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int16 crypto_int16_bitinrangepublicpos_نقاب(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarw %%cl,%0" : "+r"(crypto_int16_x) : "c"(crypto_int16_s) : "cc");
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("sxth %w0,%w0\n asr %w0,%w0,%w1" : "+&r"(crypto_int16_x) : "r"(crypto_int16_s) : );
#ورنہ
  crypto_int16_x >>= crypto_int16_s ^ crypto_int16_optblocker;
#اگر_ختم
  واپس crypto_int16_bottombit_نقاب(crypto_int16_x);
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int16 crypto_int16_bitinrangepublicpos_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarw %%cl,%0" : "+r"(crypto_int16_x) : "c"(crypto_int16_s) : "cc");
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("sxth %w0,%w0\n asr %w0,%w0,%w1" : "+&r"(crypto_int16_x) : "r"(crypto_int16_s) : );
#ورنہ
  crypto_int16_x >>= crypto_int16_s ^ crypto_int16_optblocker;
#اگر_ختم
  واپس crypto_int16_bottombit_01(crypto_int16_x);
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int16 crypto_int16_shlmod(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  crypto_int16_s &= 15;
  __asm__ ("shlw %%cl,%0" : "+r"(crypto_int16_x) : "c"(crypto_int16_s) : "cc");
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("and %w0,%w0,15\n and %w1,%w1,65535\n lsl %w1,%w1,%w0" : "+&r"(crypto_int16_s), "+r"(crypto_int16_x) : : );
#ورنہ
  صحیح crypto_int16_k, crypto_int16_l;
  برائے (crypto_int16_l = 0,crypto_int16_k = 1;crypto_int16_k < 16;++crypto_int16_l,crypto_int16_k *= 2)
    crypto_int16_x ^= (crypto_int16_x ^ (crypto_int16_x << crypto_int16_k)) & crypto_int16_bitinrangepublicpos_نقاب(crypto_int16_s,crypto_int16_l);
#اگر_ختم
  واپس crypto_int16_x;
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int16 crypto_int16_shrmod(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  crypto_int16_s &= 15;
  __asm__ ("sarw %%cl,%0" : "+r"(crypto_int16_x) : "c"(crypto_int16_s) : "cc");
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("and %w0,%w0,15\n sxth %w1,%w1\n asr %w1,%w1,%w0" : "+&r"(crypto_int16_s), "+r"(crypto_int16_x) : : );
#ورنہ
  صحیح crypto_int16_k, crypto_int16_l;
  برائے (crypto_int16_l = 0,crypto_int16_k = 1;crypto_int16_k < 16;++crypto_int16_l,crypto_int16_k *= 2)
    crypto_int16_x ^= (crypto_int16_x ^ (crypto_int16_x >> crypto_int16_k)) & crypto_int16_bitinrangepublicpos_نقاب(crypto_int16_s,crypto_int16_l);
#اگر_ختم
  واپس crypto_int16_x;
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int16 crypto_int16_bitmod_نقاب(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
  crypto_int16_x = crypto_int16_shrmod(crypto_int16_x,crypto_int16_s);
  واپس crypto_int16_bottombit_نقاب(crypto_int16_x);
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int16 crypto_int16_bitmod_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
  crypto_int16_x = crypto_int16_shrmod(crypto_int16_x,crypto_int16_s);
  واپس crypto_int16_bottombit_01(crypto_int16_x);
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int16 crypto_int16_nonzero_نقاب(crypto_int16 crypto_int16_x) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n testw %2,%2\n cmovnew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  واپس crypto_int16_z;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("tst %w1,65535\n csetm %w0,ne" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  واپس crypto_int16_z;
#ورنہ
  crypto_int16_x |= -crypto_int16_x;
  واپس crypto_int16_negative_نقاب(crypto_int16_x);
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int16 crypto_int16_nonzero_01(crypto_int16 crypto_int16_x) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n testw %2,%2\n cmovnew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  واپس crypto_int16_z;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("tst %w1,65535\n cset %w0,ne" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  واپس crypto_int16_z;
#ورنہ
  crypto_int16_x |= -crypto_int16_x;
  واپس crypto_int16_unsigned_topbit_01(crypto_int16_x);
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int16 crypto_int16_مثبت_نقاب(crypto_int16 crypto_int16_x) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n testw %2,%2\n cmovgw %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  واپس crypto_int16_z;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,0\n csetm %w0,gt" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  واپس crypto_int16_z;
#ورنہ
  crypto_int16 crypto_int16_z = -crypto_int16_x;
  crypto_int16_z ^= crypto_int16_x & crypto_int16_z;
  واپس crypto_int16_negative_نقاب(crypto_int16_z);
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int16 crypto_int16_مثبت_01(crypto_int16 crypto_int16_x) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n testw %2,%2\n cmovgw %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  واپس crypto_int16_z;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,0\n cset %w0,gt" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  واپس crypto_int16_z;
#ورنہ
  crypto_int16 crypto_int16_z = -crypto_int16_x;
  crypto_int16_z ^= crypto_int16_x & crypto_int16_z;
  واپس crypto_int16_unsigned_topbit_01(crypto_int16_z);
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int16 crypto_int16_zero_نقاب(crypto_int16 crypto_int16_x) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n testw %2,%2\n cmovew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  واپس crypto_int16_z;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("tst %w1,65535\n csetm %w0,eq" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  واپس crypto_int16_z;
#ورنہ
  واپس ~crypto_int16_nonzero_نقاب(crypto_int16_x);
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int16 crypto_int16_zero_01(crypto_int16 crypto_int16_x) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n testw %2,%2\n cmovew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  واپس crypto_int16_z;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("tst %w1,65535\n cset %w0,eq" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  واپس crypto_int16_z;
#ورنہ
  واپس 1-crypto_int16_nonzero_01(crypto_int16_x);
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int16 crypto_int16_unequal_نقاب(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n cmpw %3,%2\n cmovnew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  واپس crypto_int16_z;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("and %w0,%w1,65535\n cmp %w0,%w2,uxth\n csetm %w0,ne" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  واپس crypto_int16_z;
#ورنہ
  واپس crypto_int16_nonzero_نقاب(crypto_int16_x ^ crypto_int16_y);
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int16 crypto_int16_unequal_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n cmpw %3,%2\n cmovnew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  واپس crypto_int16_z;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("and %w0,%w1,65535\n cmp %w0,%w2,uxth\n cset %w0,ne" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  واپس crypto_int16_z;
#ورنہ
  واپس crypto_int16_nonzero_01(crypto_int16_x ^ crypto_int16_y);
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int16 crypto_int16_equal_نقاب(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n cmpw %3,%2\n cmovew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  واپس crypto_int16_z;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("and %w0,%w1,65535\n cmp %w0,%w2,uxth\n csetm %w0,eq" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  واپس crypto_int16_z;
#ورنہ
  واپس ~crypto_int16_unequal_نقاب(crypto_int16_x,crypto_int16_y);
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int16 crypto_int16_equal_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n cmpw %3,%2\n cmovew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  واپس crypto_int16_z;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("and %w0,%w1,65535\n cmp %w0,%w2,uxth\n cset %w0,eq" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  واپس crypto_int16_z;
#ورنہ
  واپس 1-crypto_int16_unequal_01(crypto_int16_x,crypto_int16_y);
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int16 crypto_int16_min(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpw %1,%0\n cmovgw %1,%0" : "+r"(crypto_int16_x) : "r"(crypto_int16_y) : "cc");
  واپس crypto_int16_x;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("sxth %w0,%w0\n cmp %w0,%w1,sxth\n csel %w0,%w0,%w1,lt" : "+&r"(crypto_int16_x) : "r"(crypto_int16_y) : "cc");
  واپس crypto_int16_x;
#ورنہ
  crypto_int16 crypto_int16_r = crypto_int16_y ^ crypto_int16_x;
  crypto_int16 crypto_int16_z = crypto_int16_y - crypto_int16_x;
  crypto_int16_z ^= crypto_int16_r & (crypto_int16_z ^ crypto_int16_y);
  crypto_int16_z = crypto_int16_negative_نقاب(crypto_int16_z);
  crypto_int16_z &= crypto_int16_r;
  واپس crypto_int16_x ^ crypto_int16_z;
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int16 crypto_int16_max(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpw %1,%0\n cmovlw %1,%0" : "+r"(crypto_int16_x) : "r"(crypto_int16_y) : "cc");
  واپس crypto_int16_x;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("sxth %w0,%w0\n cmp %w0,%w1,sxth\n csel %w0,%w1,%w0,lt" : "+&r"(crypto_int16_x) : "r"(crypto_int16_y) : "cc");
  واپس crypto_int16_x;
#ورنہ
  crypto_int16 crypto_int16_r = crypto_int16_y ^ crypto_int16_x;
  crypto_int16 crypto_int16_z = crypto_int16_y - crypto_int16_x;
  crypto_int16_z ^= crypto_int16_r & (crypto_int16_z ^ crypto_int16_y);
  crypto_int16_z = crypto_int16_negative_نقاب(crypto_int16_z);
  crypto_int16_z &= crypto_int16_r;
  واپس crypto_int16_y ^ crypto_int16_z;
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
خالی crypto_int16_minmax(crypto_int16 *crypto_int16_p,crypto_int16 *crypto_int16_q) {
  crypto_int16 crypto_int16_x = *crypto_int16_p;
  crypto_int16 crypto_int16_y = *crypto_int16_q;
#اگر defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("cmpw %2,%1\n movw %1,%0\n cmovgw %2,%1\n cmovgw %0,%2" : "=&r"(crypto_int16_z), "+&r"(crypto_int16_x), "+r"(crypto_int16_y) : : "cc");
  *crypto_int16_p = crypto_int16_x;
  *crypto_int16_q = crypto_int16_y;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_r, crypto_int16_s;
  __asm__ ("sxth %w0,%w0\n cmp %w0,%w3,sxth\n csel %w1,%w0,%w3,lt\n csel %w2,%w3,%w0,lt" : "+&r"(crypto_int16_x), "=&r"(crypto_int16_r), "=r"(crypto_int16_s) : "r"(crypto_int16_y) : "cc");
  *crypto_int16_p = crypto_int16_r;
  *crypto_int16_q = crypto_int16_s;
#ورنہ
  crypto_int16 crypto_int16_r = crypto_int16_y ^ crypto_int16_x;
  crypto_int16 crypto_int16_z = crypto_int16_y - crypto_int16_x;
  crypto_int16_z ^= crypto_int16_r & (crypto_int16_z ^ crypto_int16_y);
  crypto_int16_z = crypto_int16_negative_نقاب(crypto_int16_z);
  crypto_int16_z &= crypto_int16_r;
  crypto_int16_x ^= crypto_int16_z;
  crypto_int16_y ^= crypto_int16_z;
  *crypto_int16_p = crypto_int16_x;
  *crypto_int16_q = crypto_int16_y;
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int16 crypto_int16_smaller_نقاب(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n cmpw %3,%2\n cmovlw %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  واپس crypto_int16_z;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,%w2,sxth\n csetm %w0,lt" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  واپس crypto_int16_z;
#ورنہ
  crypto_int16 crypto_int16_r = crypto_int16_x ^ crypto_int16_y;
  crypto_int16 crypto_int16_z = crypto_int16_x - crypto_int16_y;
  crypto_int16_z ^= crypto_int16_r & (crypto_int16_z ^ crypto_int16_x);
  واپس crypto_int16_negative_نقاب(crypto_int16_z);
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int16 crypto_int16_smaller_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n cmpw %3,%2\n cmovlw %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  واپس crypto_int16_z;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,%w2,sxth\n cset %w0,lt" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  واپس crypto_int16_z;
#ورنہ
  crypto_int16 crypto_int16_r = crypto_int16_x ^ crypto_int16_y;
  crypto_int16 crypto_int16_z = crypto_int16_x - crypto_int16_y;
  crypto_int16_z ^= crypto_int16_r & (crypto_int16_z ^ crypto_int16_x);
  واپس crypto_int16_unsigned_topbit_01(crypto_int16_z);
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int16 crypto_int16_leq_نقاب(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n cmpw %3,%2\n cmovlew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  واپس crypto_int16_z;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,%w2,sxth\n csetm %w0,le" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  واپس crypto_int16_z;
#ورنہ
  واپس ~crypto_int16_smaller_نقاب(crypto_int16_y,crypto_int16_x);
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int16 crypto_int16_leq_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n cmpw %3,%2\n cmovlew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  واپس crypto_int16_z;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,%w2,sxth\n cset %w0,le" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  واپس crypto_int16_z;
#ورنہ
  واپس 1-crypto_int16_smaller_01(crypto_int16_y,crypto_int16_x);
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
صحیح crypto_int16_ones_عدد(crypto_int16 crypto_int16_x) {
  crypto_int16_unsigned crypto_int16_y = crypto_int16_x;
  ثابت crypto_int16 C0 = 0x5555;
  ثابت crypto_int16 C1 = 0x3333;
  ثابت crypto_int16 C2 = 0x0f0f;
  crypto_int16_y -= ((crypto_int16_y >> 1) & C0);
  crypto_int16_y = (crypto_int16_y & C1) + ((crypto_int16_y >> 2) & C1);
  crypto_int16_y = (crypto_int16_y + (crypto_int16_y >> 4)) & C2;
  crypto_int16_y = (crypto_int16_y + (crypto_int16_y >> 8)) & 0xff;
  واپس crypto_int16_y;
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
صحیح crypto_int16_bottomzeros_عدد(crypto_int16 crypto_int16_x) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 fallback = 16;
  __asm__ ("bsfw %0,%0\n cmovew %1,%0" : "+&r"(crypto_int16_x) : "r"(fallback) : "cc");
  واپس crypto_int16_x;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  int64_t crypto_int16_y;
  __asm__ ("orr %w0,%w1,-65536\n rbit %w0,%w0\n clz %w0,%w0" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) : );
  واپس crypto_int16_y;
#ورنہ
  crypto_int16 crypto_int16_y = crypto_int16_x ^ (crypto_int16_x-1);
  crypto_int16_y = ((crypto_int16) crypto_int16_y) >> 1;
  crypto_int16_y &= ~(crypto_int16_x & (((crypto_int16) 1) << (16-1)));
  واپس crypto_int16_ones_عدد(crypto_int16_y);
#اگر_ختم
}

#اگر_ختم

/* from supercop-20240808/cryptoint/crypto_int32.h */
/* auto-generated: cd cryptoint; ./autogen */
/* cryptoint 20240806 */

#اگر_غیر_تعریف_شدہ crypto_int32_h
#تعریف_کرو crypto_int32_h

#تعریف_کرو crypto_int32 int32_t
#تعریف_کرو crypto_int32_unsigned uint32_t



__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int32 crypto_int32_بھرو(ثابت غیرعلامتی حرف *crypto_int32_s) {
  crypto_int32 crypto_int32_z = 0;
  crypto_int32_z |= ((crypto_int32) (*crypto_int32_s++)) << 0;
  crypto_int32_z |= ((crypto_int32) (*crypto_int32_s++)) << 8;
  crypto_int32_z |= ((crypto_int32) (*crypto_int32_s++)) << 16;
  crypto_int32_z |= ((crypto_int32) (*crypto_int32_s++)) << 24;
  واپس crypto_int32_z;
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
خالی crypto_int32_store(غیرعلامتی حرف *crypto_int32_s,crypto_int32 crypto_int32_x) {
  *crypto_int32_s++ = crypto_int32_x >> 0;
  *crypto_int32_s++ = crypto_int32_x >> 8;
  *crypto_int32_s++ = crypto_int32_x >> 16;
  *crypto_int32_s++ = crypto_int32_x >> 24;
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int32 crypto_int32_negative_نقاب(crypto_int32 crypto_int32_x) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarl $31,%0" : "+r"(crypto_int32_x) : : "cc");
  واپس crypto_int32_x;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_y;
  __asm__ ("asr %w0,%w1,31" : "=r"(crypto_int32_y) : "r"(crypto_int32_x) : );
  واپس crypto_int32_y;
#ورنہ
  crypto_int32_x >>= 32-6;
  crypto_int32_x ^= crypto_int32_optblocker;
  crypto_int32_x >>= 5;
  واپس crypto_int32_x;
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int32_unsigned crypto_int32_unsigned_topbit_01(crypto_int32_unsigned crypto_int32_x) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("shrl $31,%0" : "+r"(crypto_int32_x) : : "cc");
  واپس crypto_int32_x;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_y;
  __asm__ ("lsr %w0,%w1,31" : "=r"(crypto_int32_y) : "r"(crypto_int32_x) : );
  واپس crypto_int32_y;
#ورنہ
  crypto_int32_x >>= 32-6;
  crypto_int32_x ^= crypto_int32_optblocker;
  crypto_int32_x >>= 5;
  واپس crypto_int32_x;
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int32 crypto_int32_negative_01(crypto_int32 crypto_int32_x) {
  واپس crypto_int32_unsigned_topbit_01(crypto_int32_x);
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int32 crypto_int32_topbit_نقاب(crypto_int32 crypto_int32_x) {
  واپس crypto_int32_negative_نقاب(crypto_int32_x);
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int32 crypto_int32_topbit_01(crypto_int32 crypto_int32_x) {
  واپس crypto_int32_unsigned_topbit_01(crypto_int32_x);
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int32 crypto_int32_bottombit_نقاب(crypto_int32 crypto_int32_x) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andl $1,%0" : "+r"(crypto_int32_x) : : "cc");
  واپس -crypto_int32_x;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_y;
  __asm__ ("sbfx %w0,%w1,0,1" : "=r"(crypto_int32_y) : "r"(crypto_int32_x) : );
  واپس crypto_int32_y;
#ورنہ
  crypto_int32_x &= 1 ^ crypto_int32_optblocker;
  واپس -crypto_int32_x;
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int32 crypto_int32_bottombit_01(crypto_int32 crypto_int32_x) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andl $1,%0" : "+r"(crypto_int32_x) : : "cc");
  واپس crypto_int32_x;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_y;
  __asm__ ("ubfx %w0,%w1,0,1" : "=r"(crypto_int32_y) : "r"(crypto_int32_x) : );
  واپس crypto_int32_y;
#ورنہ
  crypto_int32_x &= 1 ^ crypto_int32_optblocker;
  واپس crypto_int32_x;
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int32 crypto_int32_bitinrangepublicpos_نقاب(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarl %%cl,%0" : "+r"(crypto_int32_x) : "c"(crypto_int32_s) : "cc");
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %w0,%w0,%w1" : "+r"(crypto_int32_x) : "r"(crypto_int32_s) : );
#ورنہ
  crypto_int32_x >>= crypto_int32_s ^ crypto_int32_optblocker;
#اگر_ختم
  واپس crypto_int32_bottombit_نقاب(crypto_int32_x);
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int32 crypto_int32_bitinrangepublicpos_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarl %%cl,%0" : "+r"(crypto_int32_x) : "c"(crypto_int32_s) : "cc");
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %w0,%w0,%w1" : "+r"(crypto_int32_x) : "r"(crypto_int32_s) : );
#ورنہ
  crypto_int32_x >>= crypto_int32_s ^ crypto_int32_optblocker;
#اگر_ختم
  واپس crypto_int32_bottombit_01(crypto_int32_x);
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int32 crypto_int32_shlmod(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("shll %%cl,%0" : "+r"(crypto_int32_x) : "c"(crypto_int32_s) : "cc");
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("lsl %w0,%w0,%w1" : "+r"(crypto_int32_x) : "r"(crypto_int32_s) : );
#ورنہ
  صحیح crypto_int32_k, crypto_int32_l;
  برائے (crypto_int32_l = 0,crypto_int32_k = 1;crypto_int32_k < 32;++crypto_int32_l,crypto_int32_k *= 2)
    crypto_int32_x ^= (crypto_int32_x ^ (crypto_int32_x << crypto_int32_k)) & crypto_int32_bitinrangepublicpos_نقاب(crypto_int32_s,crypto_int32_l);
#اگر_ختم
  واپس crypto_int32_x;
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int32 crypto_int32_shrmod(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarl %%cl,%0" : "+r"(crypto_int32_x) : "c"(crypto_int32_s) : "cc");
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %w0,%w0,%w1" : "+r"(crypto_int32_x) : "r"(crypto_int32_s) : );
#ورنہ
  صحیح crypto_int32_k, crypto_int32_l;
  برائے (crypto_int32_l = 0,crypto_int32_k = 1;crypto_int32_k < 32;++crypto_int32_l,crypto_int32_k *= 2)
    crypto_int32_x ^= (crypto_int32_x ^ (crypto_int32_x >> crypto_int32_k)) & crypto_int32_bitinrangepublicpos_نقاب(crypto_int32_s,crypto_int32_l);
#اگر_ختم
  واپس crypto_int32_x;
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int32 crypto_int32_bitmod_نقاب(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
  crypto_int32_x = crypto_int32_shrmod(crypto_int32_x,crypto_int32_s);
  واپس crypto_int32_bottombit_نقاب(crypto_int32_x);
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int32 crypto_int32_bitmod_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
  crypto_int32_x = crypto_int32_shrmod(crypto_int32_x,crypto_int32_s);
  واپس crypto_int32_bottombit_01(crypto_int32_x);
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int32 crypto_int32_nonzero_نقاب(crypto_int32 crypto_int32_x) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n testl %2,%2\n cmovnel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  واپس crypto_int32_z;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n csetm %w0,ne" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  واپس crypto_int32_z;
#ورنہ
  crypto_int32_x |= -crypto_int32_x;
  واپس crypto_int32_negative_نقاب(crypto_int32_x);
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int32 crypto_int32_nonzero_01(crypto_int32 crypto_int32_x) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n testl %2,%2\n cmovnel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  واپس crypto_int32_z;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n cset %w0,ne" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  واپس crypto_int32_z;
#ورنہ
  crypto_int32_x |= -crypto_int32_x;
  واپس crypto_int32_unsigned_topbit_01(crypto_int32_x);
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int32 crypto_int32_مثبت_نقاب(crypto_int32 crypto_int32_x) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n testl %2,%2\n cmovgl %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  واپس crypto_int32_z;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n csetm %w0,gt" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  واپس crypto_int32_z;
#ورنہ
  crypto_int32 crypto_int32_z = -crypto_int32_x;
  crypto_int32_z ^= crypto_int32_x & crypto_int32_z;
  واپس crypto_int32_negative_نقاب(crypto_int32_z);
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int32 crypto_int32_مثبت_01(crypto_int32 crypto_int32_x) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n testl %2,%2\n cmovgl %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  واپس crypto_int32_z;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n cset %w0,gt" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  واپس crypto_int32_z;
#ورنہ
  crypto_int32 crypto_int32_z = -crypto_int32_x;
  crypto_int32_z ^= crypto_int32_x & crypto_int32_z;
  واپس crypto_int32_unsigned_topbit_01(crypto_int32_z);
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int32 crypto_int32_zero_نقاب(crypto_int32 crypto_int32_x) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n testl %2,%2\n cmovel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  واپس crypto_int32_z;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n csetm %w0,eq" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  واپس crypto_int32_z;
#ورنہ
  واپس ~crypto_int32_nonzero_نقاب(crypto_int32_x);
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int32 crypto_int32_zero_01(crypto_int32 crypto_int32_x) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n testl %2,%2\n cmovel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  واپس crypto_int32_z;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n cset %w0,eq" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  واپس crypto_int32_z;
#ورنہ
  واپس 1-crypto_int32_nonzero_01(crypto_int32_x);
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int32 crypto_int32_unequal_نقاب(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n cmpl %3,%2\n cmovnel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  واپس crypto_int32_z;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n csetm %w0,ne" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  واپس crypto_int32_z;
#ورنہ
  واپس crypto_int32_nonzero_نقاب(crypto_int32_x ^ crypto_int32_y);
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int32 crypto_int32_unequal_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n cmpl %3,%2\n cmovnel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  واپس crypto_int32_z;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n cset %w0,ne" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  واپس crypto_int32_z;
#ورنہ
  واپس crypto_int32_nonzero_01(crypto_int32_x ^ crypto_int32_y);
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int32 crypto_int32_equal_نقاب(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n cmpl %3,%2\n cmovel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  واپس crypto_int32_z;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n csetm %w0,eq" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  واپس crypto_int32_z;
#ورنہ
  واپس ~crypto_int32_unequal_نقاب(crypto_int32_x,crypto_int32_y);
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int32 crypto_int32_equal_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n cmpl %3,%2\n cmovel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  واپس crypto_int32_z;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n cset %w0,eq" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  واپس crypto_int32_z;
#ورنہ
  واپس 1-crypto_int32_unequal_01(crypto_int32_x,crypto_int32_y);
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int32 crypto_int32_min(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpl %1,%0\n cmovgl %1,%0" : "+r"(crypto_int32_x) : "r"(crypto_int32_y) : "cc");
  واپس crypto_int32_x;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("cmp %w0,%w1\n csel %w0,%w0,%w1,lt" : "+r"(crypto_int32_x) : "r"(crypto_int32_y) : "cc");
  واپس crypto_int32_x;
#ورنہ
  crypto_int64 crypto_int32_r = (crypto_int64)crypto_int32_y ^ (crypto_int64)crypto_int32_x;
  crypto_int64 crypto_int32_z = (crypto_int64)crypto_int32_y - (crypto_int64)crypto_int32_x;
  crypto_int32_z ^= crypto_int32_r & (crypto_int32_z ^ crypto_int32_y);
  crypto_int32_z = crypto_int32_negative_نقاب(crypto_int32_z);
  crypto_int32_z &= crypto_int32_r;
  واپس crypto_int32_x ^ crypto_int32_z;
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int32 crypto_int32_max(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpl %1,%0\n cmovll %1,%0" : "+r"(crypto_int32_x) : "r"(crypto_int32_y) : "cc");
  واپس crypto_int32_x;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("cmp %w0,%w1\n csel %w0,%w1,%w0,lt" : "+r"(crypto_int32_x) : "r"(crypto_int32_y) : "cc");
  واپس crypto_int32_x;
#ورنہ
  crypto_int64 crypto_int32_r = (crypto_int64)crypto_int32_y ^ (crypto_int64)crypto_int32_x;
  crypto_int64 crypto_int32_z = (crypto_int64)crypto_int32_y - (crypto_int64)crypto_int32_x;
  crypto_int32_z ^= crypto_int32_r & (crypto_int32_z ^ crypto_int32_y);
  crypto_int32_z = crypto_int32_negative_نقاب(crypto_int32_z);
  crypto_int32_z &= crypto_int32_r;
  واپس crypto_int32_y ^ crypto_int32_z;
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
خالی crypto_int32_minmax(crypto_int32 *crypto_int32_p,crypto_int32 *crypto_int32_q) {
  crypto_int32 crypto_int32_x = *crypto_int32_p;
  crypto_int32 crypto_int32_y = *crypto_int32_q;
#اگر defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmpl %2,%1\n movl %1,%0\n cmovgl %2,%1\n cmovgl %0,%2" : "=&r"(crypto_int32_z), "+&r"(crypto_int32_x), "+r"(crypto_int32_y) : : "cc");
  *crypto_int32_p = crypto_int32_x;
  *crypto_int32_q = crypto_int32_y;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_r, crypto_int32_s;
  __asm__ ("cmp %w2,%w3\n csel %w0,%w2,%w3,lt\n csel %w1,%w3,%w2,lt" : "=&r"(crypto_int32_r), "=r"(crypto_int32_s) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  *crypto_int32_p = crypto_int32_r;
  *crypto_int32_q = crypto_int32_s;
#ورنہ
  crypto_int64 crypto_int32_r = (crypto_int64)crypto_int32_y ^ (crypto_int64)crypto_int32_x;
  crypto_int64 crypto_int32_z = (crypto_int64)crypto_int32_y - (crypto_int64)crypto_int32_x;
  crypto_int32_z ^= crypto_int32_r & (crypto_int32_z ^ crypto_int32_y);
  crypto_int32_z = crypto_int32_negative_نقاب(crypto_int32_z);
  crypto_int32_z &= crypto_int32_r;
  crypto_int32_x ^= crypto_int32_z;
  crypto_int32_y ^= crypto_int32_z;
  *crypto_int32_p = crypto_int32_x;
  *crypto_int32_q = crypto_int32_y;
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int32 crypto_int32_smaller_نقاب(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n cmpl %3,%2\n cmovll %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  واپس crypto_int32_z;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n csetm %w0,lt" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  واپس crypto_int32_z;
#ورنہ
  crypto_int32 crypto_int32_r = crypto_int32_x ^ crypto_int32_y;
  crypto_int32 crypto_int32_z = crypto_int32_x - crypto_int32_y;
  crypto_int32_z ^= crypto_int32_r & (crypto_int32_z ^ crypto_int32_x);
  واپس crypto_int32_negative_نقاب(crypto_int32_z);
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int32 crypto_int32_smaller_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n cmpl %3,%2\n cmovll %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  واپس crypto_int32_z;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n cset %w0,lt" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  واپس crypto_int32_z;
#ورنہ
  crypto_int32 crypto_int32_r = crypto_int32_x ^ crypto_int32_y;
  crypto_int32 crypto_int32_z = crypto_int32_x - crypto_int32_y;
  crypto_int32_z ^= crypto_int32_r & (crypto_int32_z ^ crypto_int32_x);
  واپس crypto_int32_unsigned_topbit_01(crypto_int32_z);
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int32 crypto_int32_leq_نقاب(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n cmpl %3,%2\n cmovlel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  واپس crypto_int32_z;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n csetm %w0,le" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  واپس crypto_int32_z;
#ورنہ
  واپس ~crypto_int32_smaller_نقاب(crypto_int32_y,crypto_int32_x);
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int32 crypto_int32_leq_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n cmpl %3,%2\n cmovlel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  واپس crypto_int32_z;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n cset %w0,le" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  واپس crypto_int32_z;
#ورنہ
  واپس 1-crypto_int32_smaller_01(crypto_int32_y,crypto_int32_x);
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
صحیح crypto_int32_ones_عدد(crypto_int32 crypto_int32_x) {
  crypto_int32_unsigned crypto_int32_y = crypto_int32_x;
  ثابت crypto_int32 C0 = 0x55555555;
  ثابت crypto_int32 C1 = 0x33333333;
  ثابت crypto_int32 C2 = 0x0f0f0f0f;
  crypto_int32_y -= ((crypto_int32_y >> 1) & C0);
  crypto_int32_y = (crypto_int32_y & C1) + ((crypto_int32_y >> 2) & C1);
  crypto_int32_y = (crypto_int32_y + (crypto_int32_y >> 4)) & C2;
  crypto_int32_y += crypto_int32_y >> 8;
  crypto_int32_y = (crypto_int32_y + (crypto_int32_y >> 16)) & 0xff;
  واپس crypto_int32_y;
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
صحیح crypto_int32_bottomzeros_عدد(crypto_int32 crypto_int32_x) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 fallback = 32;
  __asm__ ("bsfl %0,%0\n cmovel %1,%0" : "+&r"(crypto_int32_x) : "r"(fallback) : "cc");
  واپس crypto_int32_x;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  int64_t crypto_int32_y;
  __asm__ ("rbit %w0,%w1\n clz %w0,%w0" : "=r"(crypto_int32_y) : "r"(crypto_int32_x) : );
  واپس crypto_int32_y;
#ورنہ
  crypto_int32 crypto_int32_y = crypto_int32_x ^ (crypto_int32_x-1);
  crypto_int32_y = ((crypto_int32) crypto_int32_y) >> 1;
  crypto_int32_y &= ~(crypto_int32_x & (((crypto_int32) 1) << (32-1)));
  واپس crypto_int32_ones_عدد(crypto_int32_y);
#اگر_ختم
}

#اگر_ختم

/* from supercop-20240808/cryptoint/crypto_int64.h */
/* auto-generated: cd cryptoint; ./autogen */
/* cryptoint 20240806 */

#اگر_غیر_تعریف_شدہ crypto_int64_h
#تعریف_کرو crypto_int64_h

#تعریف_کرو crypto_int64 int64_t
#تعریف_کرو crypto_int64_unsigned uint64_t



__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int64 crypto_int64_بھرو(ثابت غیرعلامتی حرف *crypto_int64_s) {
  crypto_int64 crypto_int64_z = 0;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 0;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 8;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 16;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 24;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 32;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 40;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 48;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 56;
  واپس crypto_int64_z;
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
خالی crypto_int64_store(غیرعلامتی حرف *crypto_int64_s,crypto_int64 crypto_int64_x) {
  *crypto_int64_s++ = crypto_int64_x >> 0;
  *crypto_int64_s++ = crypto_int64_x >> 8;
  *crypto_int64_s++ = crypto_int64_x >> 16;
  *crypto_int64_s++ = crypto_int64_x >> 24;
  *crypto_int64_s++ = crypto_int64_x >> 32;
  *crypto_int64_s++ = crypto_int64_x >> 40;
  *crypto_int64_s++ = crypto_int64_x >> 48;
  *crypto_int64_s++ = crypto_int64_x >> 56;
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int64 crypto_int64_negative_نقاب(crypto_int64 crypto_int64_x) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarq $63,%0" : "+r"(crypto_int64_x) : : "cc");
  واپس crypto_int64_x;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_y;
  __asm__ ("asr %0,%1,63" : "=r"(crypto_int64_y) : "r"(crypto_int64_x) : );
  واپس crypto_int64_y;
#ورنہ
  crypto_int64_x >>= 64-6;
  crypto_int64_x ^= crypto_int64_optblocker;
  crypto_int64_x >>= 5;
  واپس crypto_int64_x;
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int64_unsigned crypto_int64_unsigned_topbit_01(crypto_int64_unsigned crypto_int64_x) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("shrq $63,%0" : "+r"(crypto_int64_x) : : "cc");
  واپس crypto_int64_x;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_y;
  __asm__ ("lsr %0,%1,63" : "=r"(crypto_int64_y) : "r"(crypto_int64_x) : );
  واپس crypto_int64_y;
#ورنہ
  crypto_int64_x >>= 64-6;
  crypto_int64_x ^= crypto_int64_optblocker;
  crypto_int64_x >>= 5;
  واپس crypto_int64_x;
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int64 crypto_int64_negative_01(crypto_int64 crypto_int64_x) {
  واپس crypto_int64_unsigned_topbit_01(crypto_int64_x);
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int64 crypto_int64_topbit_نقاب(crypto_int64 crypto_int64_x) {
  واپس crypto_int64_negative_نقاب(crypto_int64_x);
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int64 crypto_int64_topbit_01(crypto_int64 crypto_int64_x) {
  واپس crypto_int64_unsigned_topbit_01(crypto_int64_x);
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int64 crypto_int64_bottombit_نقاب(crypto_int64 crypto_int64_x) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andq $1,%0" : "+r"(crypto_int64_x) : : "cc");
  واپس -crypto_int64_x;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_y;
  __asm__ ("sbfx %0,%1,0,1" : "=r"(crypto_int64_y) : "r"(crypto_int64_x) : );
  واپس crypto_int64_y;
#ورنہ
  crypto_int64_x &= 1 ^ crypto_int64_optblocker;
  واپس -crypto_int64_x;
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int64 crypto_int64_bottombit_01(crypto_int64 crypto_int64_x) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andq $1,%0" : "+r"(crypto_int64_x) : : "cc");
  واپس crypto_int64_x;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_y;
  __asm__ ("ubfx %0,%1,0,1" : "=r"(crypto_int64_y) : "r"(crypto_int64_x) : );
  واپس crypto_int64_y;
#ورنہ
  crypto_int64_x &= 1 ^ crypto_int64_optblocker;
  واپس crypto_int64_x;
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int64 crypto_int64_bitinrangepublicpos_نقاب(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarq %%cl,%0" : "+r"(crypto_int64_x) : "c"(crypto_int64_s) : "cc");
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %0,%0,%1" : "+r"(crypto_int64_x) : "r"(crypto_int64_s) : );
#ورنہ
  crypto_int64_x >>= crypto_int64_s ^ crypto_int64_optblocker;
#اگر_ختم
  واپس crypto_int64_bottombit_نقاب(crypto_int64_x);
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int64 crypto_int64_bitinrangepublicpos_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarq %%cl,%0" : "+r"(crypto_int64_x) : "c"(crypto_int64_s) : "cc");
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %0,%0,%1" : "+r"(crypto_int64_x) : "r"(crypto_int64_s) : );
#ورنہ
  crypto_int64_x >>= crypto_int64_s ^ crypto_int64_optblocker;
#اگر_ختم
  واپس crypto_int64_bottombit_01(crypto_int64_x);
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int64 crypto_int64_shlmod(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("shlq %%cl,%0" : "+r"(crypto_int64_x) : "c"(crypto_int64_s) : "cc");
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("lsl %0,%0,%1" : "+r"(crypto_int64_x) : "r"(crypto_int64_s) : );
#ورنہ
  صحیح crypto_int64_k, crypto_int64_l;
  برائے (crypto_int64_l = 0,crypto_int64_k = 1;crypto_int64_k < 64;++crypto_int64_l,crypto_int64_k *= 2)
    crypto_int64_x ^= (crypto_int64_x ^ (crypto_int64_x << crypto_int64_k)) & crypto_int64_bitinrangepublicpos_نقاب(crypto_int64_s,crypto_int64_l);
#اگر_ختم
  واپس crypto_int64_x;
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int64 crypto_int64_shrmod(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarq %%cl,%0" : "+r"(crypto_int64_x) : "c"(crypto_int64_s) : "cc");
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %0,%0,%1" : "+r"(crypto_int64_x) : "r"(crypto_int64_s) : );
#ورنہ
  صحیح crypto_int64_k, crypto_int64_l;
  برائے (crypto_int64_l = 0,crypto_int64_k = 1;crypto_int64_k < 64;++crypto_int64_l,crypto_int64_k *= 2)
    crypto_int64_x ^= (crypto_int64_x ^ (crypto_int64_x >> crypto_int64_k)) & crypto_int64_bitinrangepublicpos_نقاب(crypto_int64_s,crypto_int64_l);
#اگر_ختم
  واپس crypto_int64_x;
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int64 crypto_int64_bitmod_نقاب(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
  crypto_int64_x = crypto_int64_shrmod(crypto_int64_x,crypto_int64_s);
  واپس crypto_int64_bottombit_نقاب(crypto_int64_x);
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int64 crypto_int64_bitmod_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
  crypto_int64_x = crypto_int64_shrmod(crypto_int64_x,crypto_int64_s);
  واپس crypto_int64_bottombit_01(crypto_int64_x);
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int64 crypto_int64_nonzero_نقاب(crypto_int64 crypto_int64_x) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n testq %2,%2\n cmovneq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  واپس crypto_int64_z;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n csetm %0,ne" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  واپس crypto_int64_z;
#ورنہ
  crypto_int64_x |= -crypto_int64_x;
  واپس crypto_int64_negative_نقاب(crypto_int64_x);
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int64 crypto_int64_nonzero_01(crypto_int64 crypto_int64_x) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n testq %2,%2\n cmovneq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  واپس crypto_int64_z;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n cset %0,ne" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  واپس crypto_int64_z;
#ورنہ
  crypto_int64_x |= -crypto_int64_x;
  واپس crypto_int64_unsigned_topbit_01(crypto_int64_x);
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int64 crypto_int64_مثبت_نقاب(crypto_int64 crypto_int64_x) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n testq %2,%2\n cmovgq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  واپس crypto_int64_z;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n csetm %0,gt" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  واپس crypto_int64_z;
#ورنہ
  crypto_int64 crypto_int64_z = -crypto_int64_x;
  crypto_int64_z ^= crypto_int64_x & crypto_int64_z;
  واپس crypto_int64_negative_نقاب(crypto_int64_z);
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int64 crypto_int64_مثبت_01(crypto_int64 crypto_int64_x) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n testq %2,%2\n cmovgq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  واپس crypto_int64_z;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n cset %0,gt" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  واپس crypto_int64_z;
#ورنہ
  crypto_int64 crypto_int64_z = -crypto_int64_x;
  crypto_int64_z ^= crypto_int64_x & crypto_int64_z;
  واپس crypto_int64_unsigned_topbit_01(crypto_int64_z);
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int64 crypto_int64_zero_نقاب(crypto_int64 crypto_int64_x) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n testq %2,%2\n cmoveq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  واپس crypto_int64_z;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n csetm %0,eq" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  واپس crypto_int64_z;
#ورنہ
  واپس ~crypto_int64_nonzero_نقاب(crypto_int64_x);
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int64 crypto_int64_zero_01(crypto_int64 crypto_int64_x) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n testq %2,%2\n cmoveq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  واپس crypto_int64_z;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n cset %0,eq" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  واپس crypto_int64_z;
#ورنہ
  واپس 1-crypto_int64_nonzero_01(crypto_int64_x);
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int64 crypto_int64_unequal_نقاب(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n cmpq %3,%2\n cmovneq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  واپس crypto_int64_z;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n csetm %0,ne" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  واپس crypto_int64_z;
#ورنہ
  واپس crypto_int64_nonzero_نقاب(crypto_int64_x ^ crypto_int64_y);
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int64 crypto_int64_unequal_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n cmpq %3,%2\n cmovneq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  واپس crypto_int64_z;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n cset %0,ne" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  واپس crypto_int64_z;
#ورنہ
  واپس crypto_int64_nonzero_01(crypto_int64_x ^ crypto_int64_y);
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int64 crypto_int64_equal_نقاب(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n cmpq %3,%2\n cmoveq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  واپس crypto_int64_z;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n csetm %0,eq" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  واپس crypto_int64_z;
#ورنہ
  واپس ~crypto_int64_unequal_نقاب(crypto_int64_x,crypto_int64_y);
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int64 crypto_int64_equal_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n cmpq %3,%2\n cmoveq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  واپس crypto_int64_z;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n cset %0,eq" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  واپس crypto_int64_z;
#ورنہ
  واپس 1-crypto_int64_unequal_01(crypto_int64_x,crypto_int64_y);
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int64 crypto_int64_min(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpq %1,%0\n cmovgq %1,%0" : "+r"(crypto_int64_x) : "r"(crypto_int64_y) : "cc");
  واپس crypto_int64_x;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("cmp %0,%1\n csel %0,%0,%1,lt" : "+r"(crypto_int64_x) : "r"(crypto_int64_y) : "cc");
  واپس crypto_int64_x;
#ورنہ
  crypto_int64 crypto_int64_r = crypto_int64_y ^ crypto_int64_x;
  crypto_int64 crypto_int64_z = crypto_int64_y - crypto_int64_x;
  crypto_int64_z ^= crypto_int64_r & (crypto_int64_z ^ crypto_int64_y);
  crypto_int64_z = crypto_int64_negative_نقاب(crypto_int64_z);
  crypto_int64_z &= crypto_int64_r;
  واپس crypto_int64_x ^ crypto_int64_z;
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int64 crypto_int64_max(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpq %1,%0\n cmovlq %1,%0" : "+r"(crypto_int64_x) : "r"(crypto_int64_y) : "cc");
  واپس crypto_int64_x;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("cmp %0,%1\n csel %0,%1,%0,lt" : "+r"(crypto_int64_x) : "r"(crypto_int64_y) : "cc");
  واپس crypto_int64_x;
#ورنہ
  crypto_int64 crypto_int64_r = crypto_int64_y ^ crypto_int64_x;
  crypto_int64 crypto_int64_z = crypto_int64_y - crypto_int64_x;
  crypto_int64_z ^= crypto_int64_r & (crypto_int64_z ^ crypto_int64_y);
  crypto_int64_z = crypto_int64_negative_نقاب(crypto_int64_z);
  crypto_int64_z &= crypto_int64_r;
  واپس crypto_int64_y ^ crypto_int64_z;
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
خالی crypto_int64_minmax(crypto_int64 *crypto_int64_p,crypto_int64 *crypto_int64_q) {
  crypto_int64 crypto_int64_x = *crypto_int64_p;
  crypto_int64 crypto_int64_y = *crypto_int64_q;
#اگر defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmpq %2,%1\n movq %1,%0\n cmovgq %2,%1\n cmovgq %0,%2" : "=&r"(crypto_int64_z), "+&r"(crypto_int64_x), "+r"(crypto_int64_y) : : "cc");
  *crypto_int64_p = crypto_int64_x;
  *crypto_int64_q = crypto_int64_y;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_r, crypto_int64_s;
  __asm__ ("cmp %2,%3\n csel %0,%2,%3,lt\n csel %1,%3,%2,lt" : "=&r"(crypto_int64_r), "=r"(crypto_int64_s) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  *crypto_int64_p = crypto_int64_r;
  *crypto_int64_q = crypto_int64_s;
#ورنہ
  crypto_int64 crypto_int64_r = crypto_int64_y ^ crypto_int64_x;
  crypto_int64 crypto_int64_z = crypto_int64_y - crypto_int64_x;
  crypto_int64_z ^= crypto_int64_r & (crypto_int64_z ^ crypto_int64_y);
  crypto_int64_z = crypto_int64_negative_نقاب(crypto_int64_z);
  crypto_int64_z &= crypto_int64_r;
  crypto_int64_x ^= crypto_int64_z;
  crypto_int64_y ^= crypto_int64_z;
  *crypto_int64_p = crypto_int64_x;
  *crypto_int64_q = crypto_int64_y;
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int64 crypto_int64_smaller_نقاب(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n cmpq %3,%2\n cmovlq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  واپس crypto_int64_z;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n csetm %0,lt" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  واپس crypto_int64_z;
#ورنہ
  crypto_int64 crypto_int64_r = crypto_int64_x ^ crypto_int64_y;
  crypto_int64 crypto_int64_z = crypto_int64_x - crypto_int64_y;
  crypto_int64_z ^= crypto_int64_r & (crypto_int64_z ^ crypto_int64_x);
  واپس crypto_int64_negative_نقاب(crypto_int64_z);
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int64 crypto_int64_smaller_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n cmpq %3,%2\n cmovlq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  واپس crypto_int64_z;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n cset %0,lt" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  واپس crypto_int64_z;
#ورنہ
  crypto_int64 crypto_int64_r = crypto_int64_x ^ crypto_int64_y;
  crypto_int64 crypto_int64_z = crypto_int64_x - crypto_int64_y;
  crypto_int64_z ^= crypto_int64_r & (crypto_int64_z ^ crypto_int64_x);
  واپس crypto_int64_unsigned_topbit_01(crypto_int64_z);
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int64 crypto_int64_leq_نقاب(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n cmpq %3,%2\n cmovleq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  واپس crypto_int64_z;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n csetm %0,le" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  واپس crypto_int64_z;
#ورنہ
  واپس ~crypto_int64_smaller_نقاب(crypto_int64_y,crypto_int64_x);
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
crypto_int64 crypto_int64_leq_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n cmpq %3,%2\n cmovleq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  واپس crypto_int64_z;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n cset %0,le" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  واپس crypto_int64_z;
#ورنہ
  واپس 1-crypto_int64_smaller_01(crypto_int64_y,crypto_int64_x);
#اگر_ختم
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
صحیح crypto_int64_ones_عدد(crypto_int64 crypto_int64_x) {
  crypto_int64_unsigned crypto_int64_y = crypto_int64_x;
  ثابت crypto_int64 C0 = 0x5555555555555555;
  ثابت crypto_int64 C1 = 0x3333333333333333;
  ثابت crypto_int64 C2 = 0x0f0f0f0f0f0f0f0f;
  crypto_int64_y -= ((crypto_int64_y >> 1) & C0);
  crypto_int64_y = (crypto_int64_y & C1) + ((crypto_int64_y >> 2) & C1);
  crypto_int64_y = (crypto_int64_y + (crypto_int64_y >> 4)) & C2;
  crypto_int64_y += crypto_int64_y >> 8;
  crypto_int64_y += crypto_int64_y >> 16;
  crypto_int64_y = (crypto_int64_y + (crypto_int64_y >> 32)) & 0xff;
  واپس crypto_int64_y;
}

__attribute__((غیر_مستعمل))
ساکن اندرونی
صحیح crypto_int64_bottomzeros_عدد(crypto_int64 crypto_int64_x) {
#اگر defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 fallback = 64;
  __asm__ ("bsfq %0,%0\n cmoveq %1,%0" : "+&r"(crypto_int64_x) : "r"(fallback) : "cc");
  واپس crypto_int64_x;
#وگرنہ_اگر defined(__GNUC__) && defined(__aarch64__)
  int64_t crypto_int64_y;
  __asm__ ("rbit %0,%1\n clz %0,%0" : "=r"(crypto_int64_y) : "r"(crypto_int64_x) : );
  واپس crypto_int64_y;
#ورنہ
  crypto_int64 crypto_int64_y = crypto_int64_x ^ (crypto_int64_x-1);
  crypto_int64_y = ((crypto_int64) crypto_int64_y) >> 1;
  crypto_int64_y &= ~(crypto_int64_x & (((crypto_int64) 1) << (64-1)));
  واپس crypto_int64_ones_عدد(crypto_int64_y);
#اگر_ختم
}

#اگر_ختم

/* from supercop-20240808/crypto_sort/int32/portable4/sort.c */
#تعریف_کرو int32_MINMAX(a,b) crypto_int32_minmax(&a,&b)

ساکن خالی crypto_ترتیب_دو_int32(خالی *array,طویل طویل n)
{
  طویل طویل چوٹی,p,q,r,i,j;
  int32 *x = array;

  اگر (n < 2) واپس;
  چوٹی = 1;
  جب (چوٹی < n - چوٹی) چوٹی += چوٹی;

  برائے (p = چوٹی;p >= 1;p >>= 1) {
    i = 0;
    جب (i + 2 * p <= n) {
      برائے (j = i;j < i + p;++j)
        int32_MINMAX(x[j],x[j+p]);
      i += 2 * p;
    }
    برائے (j = i;j < n - p;++j)
      int32_MINMAX(x[j],x[j+p]);

    i = 0;
    j = 0;
    برائے (q = چوٹی;q > p;q >>= 1) {
      اگر (j != i) برائے (;;) {
        اگر (j == n - q) جاؤ مکمل;
        int32 a = x[j + p];
        برائے (r = q;r > p;r >>= 1)
          int32_MINMAX(a,x[j + r]);
        x[j + p] = a;
        ++j;
        اگر (j == i + p) {
          i += 2 * p;
          توڑو;
        }
      }
      جب (i + p <= n - q) {
        برائے (j = i;j < i + p;++j) {
          int32 a = x[j + p];
          برائے (r = q;r > p;r >>= 1)
            int32_MINMAX(a,x[j+r]);
          x[j + p] = a;
        }
        i += 2 * p;
      }
      /* now i + p > n - q */
      j = i;
      جب (j < n - q) {
        int32 a = x[j + p];
        برائے (r = q;r > p;r >>= 1)
          int32_MINMAX(a,x[j+r]);
        x[j + p] = a;
        ++j;
      }

      مکمل: ;
    }
  }
}

/* from supercop-20240808/crypto_sort/uint32/useint32/sort.c */

/* can save time by vectorizing xor loops */
/* can save time by integrating xor loops with int32_sort */

ساکن خالی crypto_ترتیب_دو_uint32(خالی *array,طویل طویل n)
{
  crypto_uint32 *x = array;
  طویل طویل j;
  برائے (j = 0;j < n;++j) x[j] ^= 0x80000000;
  crypto_ترتیب_دو_int32(array,n);
  برائے (j = 0;j < n;++j) x[j] ^= 0x80000000;
}

/* from supercop-20240808/crypto_kem/sntrup761/compact/kem.c */
// 20240806 djb: some automated conversion to cryptoint

#تعریف_کرو p 761
#تعریف_کرو q 4591
#تعریف_کرو w 286
#تعریف_کرو q12 ((q - 1) / 2)
قسمتعریف int8_t small;
قسمتعریف int16_t Fq;
#تعریف_کرو Hash_بائٹیں 32
#تعریف_کرو Small_بائٹیں ((p + 3) / 4)
قسمتعریف small Inputs[p];
#تعریف_کرو Secret_کلیدیں_بائٹیں (2 * Small_بائٹیں)
#تعریف_کرو Confirm_بائٹیں 32

ساکن small F3_freeze(int16_t x) { واپس x - 3 * ((10923 * x + 16384) >> 15); }

ساکن Fq Fq_freeze(int32_t x) {
  ثابت int32_t q16 = (0x10000 + q / 2) / q;
  ثابت int32_t q20 = (0x100000 + q / 2) / q;
  ثابت int32_t q28 = (0x10000000 + q / 2) / q;
  x -= q * ((q16 * x) >> 16);
  x -= q * ((q20 * x) >> 20);
  واپس x - q * ((q28 * x + 0x8000000) >> 28);
}

ساکن صحیح Weightw_نقاب(small *r) {
  صحیح i, وزن = 0;
  برائے (i = 0; i < p; ++i) وزن += crypto_int64_bottombit_01(r[i]);
  واپس crypto_int16_nonzero_نقاب(وزن - w);
}

ساکن خالی uint32_divmod_uint14(uint32_t *Q, uint16_t *r, uint32_t x, uint16_t m) {
  uint32_t qpart, نقاب, v = 0x80000000 / m;
  qpart = (x * (uint64_t)v) >> 31;
  x -= qpart * m;
  *Q = qpart;
  qpart = (x * (uint64_t)v) >> 31;
  x -= qpart * m;
  *Q += qpart;
  x -= m;
  *Q += 1;
  نقاب = crypto_int32_negative_نقاب(x);
  x += نقاب & (uint32_t)m;
  *Q += نقاب;
  *r = x;
}

ساکن uint16_t uint32_mod_uint14(uint32_t x, uint16_t m) {
  uint32_t Q;
  uint16_t r;
  uint32_divmod_uint14(&Q, &r, x, m);
  واپس r;
}

ساکن خالی Encode(غیرعلامتی حرف *برآمد, ثابت uint16_t *R, ثابت uint16_t *M, طویل طویل len) {
  اگر (len == 1) {
    uint16_t r = R[0], m = M[0];
    جب (m > 1) {
      *برآمد++ = r;
      r >>= 8;
      m = (m + 255) >> 8;
    }
  }
  اگر (len > 1) {
    uint16_t R2[(len + 1) / 2], M2[(len + 1) / 2];
    طویل طویل i;
    برائے (i = 0; i < len - 1; i += 2) {
      uint32_t m0 = M[i];
      uint32_t r = R[i] + R[i + 1] * m0;
      uint32_t m = M[i + 1] * m0;
      جب (m >= 16384) {
        *برآمد++ = r;
        r >>= 8;
        m = (m + 255) >> 8;
      }
      R2[i / 2] = r;
      M2[i / 2] = m;
    }
    اگر (i < len) {
      R2[i / 2] = R[i];
      M2[i / 2] = M[i];
    }
    Encode(برآمد, R2, M2, (len + 1) / 2);
  }
}

ساکن خالی Decode(uint16_t *برآمد, ثابت غیرعلامتی حرف *S, ثابت uint16_t *M, طویل طویل len) {
  اگر (len == 1) {
    اگر (M[0] == 1)
      *برآمد = 0;
    ورنہ اگر (M[0] <= 256)
      *برآمد = uint32_mod_uint14(S[0], M[0]);
    ورنہ
      *برآمد = uint32_mod_uint14(S[0] + (((uint16_t)S[1]) << 8), M[0]);
  }
  اگر (len > 1) {
    uint16_t R2[(len + 1) / 2], M2[(len + 1) / 2], bottomr[len / 2];
    uint32_t bottomt[len / 2];
    طویل طویل i;
    برائے (i = 0; i < len - 1; i += 2) {
      uint32_t m = M[i] * (uint32_t)M[i + 1];
      اگر (m > 256 * 16383) {
        bottomt[i / 2] = 256 * 256;
        bottomr[i / 2] = S[0] + 256 * S[1];
        S += 2;
        M2[i / 2] = (((m + 255) >> 8) + 255) >> 8;
      } ورنہ اگر (m >= 16384) {
        bottomt[i / 2] = 256;
        bottomr[i / 2] = S[0];
        S += 1;
        M2[i / 2] = (m + 255) >> 8;
      } ورنہ {
        bottomt[i / 2] = 1;
        bottomr[i / 2] = 0;
        M2[i / 2] = m;
      }
    }
    اگر (i < len) M2[i / 2] = M[i];
    Decode(R2, S, M2, (len + 1) / 2);
    برائے (i = 0; i < len - 1; i += 2) {
      uint32_t r1, r = bottomr[i / 2];
      uint16_t r0;
      r += bottomt[i / 2] * R2[i / 2];
      uint32_divmod_uint14(&r1, &r0, r, M[i]);
      r1 = uint32_mod_uint14(r1, M[i + 1]);
      *برآمد++ = r0;
      *برآمد++ = r1;
    }
    اگر (i < len) *برآمد++ = R2[i / 2];
  }
}

ساکن خالی R3_fromRq(small *برآمد, ثابت Fq *r) {
  صحیح i;
  برائے (i = 0; i < p; ++i) برآمد[i] = F3_freeze(r[i]);
}

ساکن خالی R3_mult(small *h, ثابت small *f, ثابت small *g) {
  int16_t fg[p + p - 1];
  صحیح i, j;
  برائے (i = 0; i < p + p - 1; ++i) fg[i] = 0;
  برائے (i = 0; i < p; ++i)
    برائے (j = 0; j < p; ++j) fg[i + j] += f[i] * (int16_t)g[j];
  برائے (i = p; i < p + p - 1; ++i) fg[i - p] += fg[i];
  برائے (i = p; i < p + p - 1; ++i) fg[i - p + 1] += fg[i];
  برائے (i = 0; i < p; ++i) h[i] = F3_freeze(fg[i]);
}

ساکن صحیح R3_recip(small *برآمد, ثابت small *اندر) {
  small f[p + 1], g[p + 1], v[p + 1], r[p + 1];
  صحیح sign, تبادلہ, t, i, loop, delta = 1;
  برائے (i = 0; i < p + 1; ++i) v[i] = 0;
  برائے (i = 0; i < p + 1; ++i) r[i] = 0;
  r[0] = 1;
  برائے (i = 0; i < p; ++i) f[i] = 0;
  f[0] = 1;
  f[p - 1] = f[p] = -1;
  برائے (i = 0; i < p; ++i) g[p - 1 - i] = اندر[i];
  g[p] = 0;
  برائے (loop = 0; loop < 2 * p - 1; ++loop) {
    برائے (i = p; i > 0; --i) v[i] = v[i - 1];
    v[0] = 0;
    sign = -g[0] * f[0];
    تبادلہ = crypto_int16_negative_نقاب(-delta) & crypto_int16_nonzero_نقاب(g[0]);
    delta ^= تبادلہ & (delta ^ -delta);
    delta += 1;
    برائے (i = 0; i < p + 1; ++i) {
      t = تبادلہ & (f[i] ^ g[i]);
      f[i] ^= t;
      g[i] ^= t;
      t = تبادلہ & (v[i] ^ r[i]);
      v[i] ^= t;
      r[i] ^= t;
    }
    برائے (i = 0; i < p + 1; ++i) g[i] = F3_freeze(g[i] + sign * f[i]);
    برائے (i = 0; i < p + 1; ++i) r[i] = F3_freeze(r[i] + sign * v[i]);
    برائے (i = 0; i < p; ++i) g[i] = g[i + 1];
    g[p] = 0;
  }
  sign = f[0];
  برائے (i = 0; i < p; ++i) برآمد[i] = sign * v[p - 1 - i];
  واپس crypto_int16_nonzero_نقاب(delta);
}

ساکن خالی Rq_mult_small(Fq *h, ثابت Fq *f, ثابت small *g) {
  int32_t fg[p + p - 1];
  صحیح i, j;
  برائے (i = 0; i < p + p - 1; ++i) fg[i] = 0;
  برائے (i = 0; i < p; ++i)
    برائے (j = 0; j < p; ++j) fg[i + j] += f[i] * (int32_t)g[j];
  برائے (i = p; i < p + p - 1; ++i) fg[i - p] += fg[i];
  برائے (i = p; i < p + p - 1; ++i) fg[i - p + 1] += fg[i];
  برائے (i = 0; i < p; ++i) h[i] = Fq_freeze(fg[i]);
}

ساکن خالی Rq_mult3(Fq *h, ثابت Fq *f) {
  صحیح i;
  برائے (i = 0; i < p; ++i) h[i] = Fq_freeze(3 * f[i]);
}

ساکن Fq Fq_recip(Fq a1) {
  صحیح i = 1;
  Fq ai = a1;
  جب (i < q - 2) {
    ai = Fq_freeze(a1 * (int32_t)ai);
    i += 1;
  }
  واپس ai;
}

ساکن صحیح Rq_recip3(Fq *برآمد, ثابت small *اندر) {
  Fq f[p + 1], g[p + 1], v[p + 1], r[p + 1], scale;
  صحیح تبادلہ, t, i, loop, delta = 1;
  int32_t f0, g0;
  برائے (i = 0; i < p + 1; ++i) v[i] = 0;
  برائے (i = 0; i < p + 1; ++i) r[i] = 0;
  r[0] = Fq_recip(3);
  برائے (i = 0; i < p; ++i) f[i] = 0;
  f[0] = 1;
  f[p - 1] = f[p] = -1;
  برائے (i = 0; i < p; ++i) g[p - 1 - i] = اندر[i];
  g[p] = 0;
  برائے (loop = 0; loop < 2 * p - 1; ++loop) {
    برائے (i = p; i > 0; --i) v[i] = v[i - 1];
    v[0] = 0;
    تبادلہ = crypto_int16_negative_نقاب(-delta) & crypto_int16_nonzero_نقاب(g[0]);
    delta ^= تبادلہ & (delta ^ -delta);
    delta += 1;
    برائے (i = 0; i < p + 1; ++i) {
      t = تبادلہ & (f[i] ^ g[i]);
      f[i] ^= t;
      g[i] ^= t;
      t = تبادلہ & (v[i] ^ r[i]);
      v[i] ^= t;
      r[i] ^= t;
    }
    f0 = f[0];
    g0 = g[0];
    برائے (i = 0; i < p + 1; ++i) g[i] = Fq_freeze(f0 * g[i] - g0 * f[i]);
    برائے (i = 0; i < p + 1; ++i) r[i] = Fq_freeze(f0 * r[i] - g0 * v[i]);
    برائے (i = 0; i < p; ++i) g[i] = g[i + 1];
    g[p] = 0;
  }
  scale = Fq_recip(f[0]);
  برائے (i = 0; i < p; ++i) برآمد[i] = Fq_freeze(scale * (int32_t)v[p - 1 - i]);
  واپس crypto_int16_nonzero_نقاب(delta);
}

ساکن خالی باری_3(Fq *برآمد, ثابت Fq *a) {
  صحیح i;
  برائے (i = 0; i < p; ++i) برآمد[i] = a[i] - F3_freeze(a[i]);
}

ساکن خالی Short_fromlist(small *برآمد, ثابت uint32_t *اندر) {
  uint32_t L[p];
  صحیح i;
  برائے (i = 0; i < w; ++i) L[i] = اندر[i] & (uint32_t)-2;
  برائے (i = w; i < p; ++i) L[i] = (اندر[i] & (uint32_t)-3) | 1;
  crypto_ترتیب_دو_uint32(L, p);
  برائے (i = 0; i < p; ++i) برآمد[i] = (L[i] & 3) - 1;
}

ساکن خالی Hash_سابقہ(غیرعلامتی حرف *برآمد, صحیح b, ثابت غیرعلامتی حرف *اندر, صحیح inlen) {
  غیرعلامتی حرف x[inlen + 1], h[64];
  صحیح i;
  x[0] = b;
  برائے (i = 0; i < inlen; ++i) x[i + 1] = اندر[i];
  crypto_hash_sha512(h, x, inlen + 1);
  برائے (i = 0; i < 32; ++i) برآمد[i] = h[i];
}


ساکن خالی Short_random(small *برآمد) {
  uint32_t L[p];
  randombytes(L, حجم(L));
  Short_fromlist(برآمد, L);
  explicit_bzero(L, حجم(L));
}
ساکن خالی Small_random(small *برآمد) {
  صحیح i;
  uint32_t L[p];
  randombytes(L, حجم(L));
  برائے (i = 0; i < p; ++i) برآمد[i] = (((L[i] & 0x3fffffff) * 3) >> 30) - 1;
  explicit_bzero(L, حجم(L));
}
ساکن خالی کلید_Gen(Fq *h, small *f, small *ginv) {
  small g[p];
  Fq finv[p];
  برائے (;;) {
    صحیح نتیجہ;
    Small_random(g);
    نتیجہ = R3_recip(ginv, g);
    crypto_declassify(&نتیجہ, حجم نتیجہ);
    اگر (نتیجہ == 0) توڑو;
  }
  Short_random(f);
  Rq_recip3(finv, f);
  Rq_mult_small(h, finv, g);
}

ساکن خالی Encrypt(Fq *c, ثابت small *r, ثابت Fq *h) {
  Fq hr[p];
  Rq_mult_small(hr, h, r);
  باری_3(c, hr);
}

ساکن خالی Decrypt(small *r, ثابت Fq *c, ثابت small *f, ثابت small *ginv) {
  Fq cf[p], cf3[p];
  small e[p], ev[p];
  صحیح نقاب, i;
  Rq_mult_small(cf, c, f);
  Rq_mult3(cf3, cf);
  R3_fromRq(e, cf3);
  R3_mult(ev, e, ginv);
  نقاب = Weightw_نقاب(ev);
  برائے (i = 0; i < w; ++i) r[i] = ((ev[i] ^ 1) & ~نقاب) ^ 1;
  برائے (i = w; i < p; ++i) r[i] = ev[i] & ~نقاب;
}

ساکن خالی Small_encode(غیرعلامتی حرف *s, ثابت small *f) {
  صحیح i, j;
  برائے (i = 0; i < p / 4; ++i) {
    small x = 0;
    برائے (j = 0;j < 4;++j) x += (*f++ + 1) << (2 * j);
    *s++ = x;
  }
  *s = *f++ + 1;
}

ساکن خالی Small_decode(small *f, ثابت غیرعلامتی حرف *s) {
  صحیح i, j;
  برائے (i = 0; i < p / 4; ++i) {
    غیرعلامتی حرف x = *s++;
    برائے (j = 0;j < 4;++j) *f++ = ((small)((x >> (2 * j)) & 3)) - 1;
  }
  *f++ = ((small)(*s & 3)) - 1;
}

ساکن خالی Rq_encode(غیرعلامتی حرف *s, ثابت Fq *r) {
  uint16_t R[p], M[p];
  صحیح i;
  برائے (i = 0; i < p; ++i) R[i] = r[i] + q12;
  برائے (i = 0; i < p; ++i) M[i] = q;
  Encode(s, R, M, p);
}

ساکن خالی Rq_decode(Fq *r, ثابت غیرعلامتی حرف *s) {
  uint16_t R[p], M[p];
  صحیح i;
  برائے (i = 0; i < p; ++i) M[i] = q;
  Decode(R, s, M, p);
  برائے (i = 0; i < p; ++i) r[i] = ((Fq)R[i]) - q12;
}

ساکن خالی Rounded_encode(غیرعلامتی حرف *s, ثابت Fq *r) {
  uint16_t R[p], M[p];
  صحیح i;
  برائے (i = 0; i < p; ++i) R[i] = ((r[i] + q12) * 10923) >> 15;
  برائے (i = 0; i < p; ++i) M[i] = (q + 2) / 3;
  Encode(s, R, M, p);
}

ساکن خالی Rounded_decode(Fq *r, ثابت غیرعلامتی حرف *s) {
  uint16_t R[p], M[p];
  صحیح i;
  برائے (i = 0; i < p; ++i) M[i] = (q + 2) / 3;
  Decode(R, s, M, p);
  برائے (i = 0; i < p; ++i) r[i] = R[i] * 3 - q12;
}

ساکن خالی ZKeyGen(غیرعلامتی حرف *pk, غیرعلامتی حرف *sk) {
  Fq h[p];
  small f[p], v[p];
  کلید_Gen(h, f, v);
  Rq_encode(pk, h);
  Small_encode(sk, f);
  Small_encode(sk + Small_بائٹیں, v);
}

ساکن خالی ZEncrypt(غیرعلامتی حرف *C, ثابت Inputs r, ثابت غیرعلامتی حرف *pk) {
  Fq h[p], c[p];
  Rq_decode(h, pk);
  Encrypt(c, r, h);
  Rounded_encode(C, c);
}

ساکن خالی ZDecrypt(Inputs r, ثابت غیرعلامتی حرف *C, ثابت غیرعلامتی حرف *sk) {
  small f[p], v[p];
  Fq c[p];
  Small_decode(f, sk);
  Small_decode(v, sk + Small_بائٹیں);
  Rounded_decode(c, C);
  Decrypt(r, c, f, v);
}

ساکن خالی HashConfirm(غیرعلامتی حرف *h, ثابت غیرعلامتی حرف *r, ثابت غیرعلامتی حرف *cache) {
  غیرعلامتی حرف x[Hash_بائٹیں * 2];
  صحیح i;
  Hash_سابقہ(x, 3, r, Small_بائٹیں);
  برائے (i = 0; i < Hash_بائٹیں; ++i) x[Hash_بائٹیں + i] = cache[i];
  Hash_سابقہ(h, 2, x, حجم x);
}

ساکن خالی HashSession(غیرعلامتی حرف *k, صحیح b, ثابت غیرعلامتی حرف *y, ثابت غیرعلامتی حرف *z) {
  غیرعلامتی حرف x[Hash_بائٹیں + crypto_kem_sntrup761_CIPHERTEXTBYTES];
  صحیح i;
  Hash_سابقہ(x, 3, y, Small_بائٹیں);
  برائے (i = 0; i < crypto_kem_sntrup761_CIPHERTEXTBYTES; ++i) x[Hash_بائٹیں + i] = z[i];
  Hash_سابقہ(k, b, x, حجم x);
}

صحیح crypto_kem_sntrup761_keypair(غیرعلامتی حرف *pk, غیرعلامتی حرف *sk) {
  صحیح i;
  ZKeyGen(pk, sk);
  sk += Secret_کلیدیں_بائٹیں;
  برائے (i = 0; i < crypto_kem_sntrup761_PUBLICKEYBYTES; ++i) *sk++ = pk[i];
  randombytes(sk, Small_بائٹیں);
  Hash_سابقہ(sk + Small_بائٹیں, 4, pk, crypto_kem_sntrup761_PUBLICKEYBYTES);
  واپس 0;
}

ساکن خالی Hide(غیرعلامتی حرف *c, غیرعلامتی حرف *r_enc, ثابت Inputs r, ثابت غیرعلامتی حرف *pk, ثابت غیرعلامتی حرف *cache) {
  Small_encode(r_enc, r);
  ZEncrypt(c, r, pk);
  HashConfirm(c + crypto_kem_sntrup761_CIPHERTEXTBYTES - Confirm_بائٹیں, r_enc, cache);
}

صحیح crypto_kem_sntrup761_enc(غیرعلامتی حرف *c, غیرعلامتی حرف *k, ثابت غیرعلامتی حرف *pk) {
  Inputs r;
  غیرعلامتی حرف r_enc[Small_بائٹیں], cache[Hash_بائٹیں];
  Hash_سابقہ(cache, 4, pk, crypto_kem_sntrup761_PUBLICKEYBYTES);
  Short_random(r);
  Hide(c, r_enc, r, pk, cache);
  HashSession(k, 1, r_enc, c);
  واپس 0;
}

ساکن صحیح Ciphertexts_diff_نقاب(ثابت غیرعلامتی حرف *c, ثابت غیرعلامتی حرف *c2) {
  uint16_t differentbits = 0;
  صحیح len = crypto_kem_sntrup761_CIPHERTEXTBYTES;
  جب (len-- > 0) differentbits |= (*c++) ^ (*c2++);
  واپس (crypto_int64_bitmod_01((differentbits - 1),8)) - 1;
}

صحیح crypto_kem_sntrup761_dec(غیرعلامتی حرف *k, ثابت غیرعلامتی حرف *c, ثابت غیرعلامتی حرف *sk) {
  ثابت غیرعلامتی حرف *pk = sk + Secret_کلیدیں_بائٹیں;
  ثابت غیرعلامتی حرف *rho = pk + crypto_kem_sntrup761_PUBLICKEYBYTES;
  ثابت غیرعلامتی حرف *cache = rho + Small_بائٹیں;
  Inputs r;
  غیرعلامتی حرف r_enc[Small_بائٹیں], cnew[crypto_kem_sntrup761_CIPHERTEXTBYTES];
  صحیح نقاب, i;
  ZDecrypt(r, c, sk);
  Hide(cnew, r_enc, r, pk, cache);
  نقاب = Ciphertexts_diff_نقاب(c, cnew);
  برائے (i = 0; i < Small_بائٹیں; ++i) r_enc[i] ^= نقاب & (r_enc[i] ^ rho[i]);
  HashSession(k, 1 + نقاب, r_enc, c);
  واپس 0;
}

#اگر_ختم /* USE_SNTRUP761X25519 */
