/*  $OpenBSD: sntrup761.c,v 1.9 2026/01/20 22:56:11 dtucker Exp $ */

/*
 * Public Domain, Authors:
 * - Daniel J. Bernstein
 * - Chitchanok Chuengsatiansup
 * - Tanja Lange
 * - Christine van Vredendaal
 */

#ضمن "includes.h"

#جے_تعریف_شدہ USE_SNTRUP761X25519

#ضمن <string.h>
#ضمن "crypto_api.h"

#تعریف_کرو crypto_declassify(x, y) افعل {} طالما (0)

#تعریف_کرو int8 crypto_int8
#تعریف_کرو uint8 crypto_uint8
#تعریف_کرو int16 crypto_int16
#تعریف_کرو uint16 crypto_uint16
#تعریف_کرو int32 crypto_int32
#تعریف_کرو uint32 crypto_uint32
#تعریف_کرو int64 crypto_int64
#تعریف_کرو uint64 crypto_uint64
خارجي متطاير crypto_int16 crypto_int16_optblocker;
خارجي متطاير crypto_int32 crypto_int32_optblocker;
خارجي متطاير crypto_int64 crypto_int64_optblocker;

/* from supercop-20240808/cryptoint/crypto_int16.h */
/* auto-generated: cd cryptoint; ./autogen */
/* cryptoint 20240806 */

#جے_بنا_تعریف crypto_int16_h
#تعریف_کرو crypto_int16_h

#تعریف_کرو crypto_int16 int16_t
#تعریف_کرو crypto_int16_unsigned uint16_t



__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int16 crypto_int16_لدو(ثابت بنانشانی حرف *crypto_int16_s) {
  crypto_int16 crypto_int16_z = 0;
  crypto_int16_z |= ((crypto_int16) (*crypto_int16_s++)) << 0;
  crypto_int16_z |= ((crypto_int16) (*crypto_int16_s++)) << 8;
  أرجع crypto_int16_z;
}

__attribute__((بن_ورتیا))
ساكن مضمن
فراغ crypto_int16_store(بنانشانی حرف *crypto_int16_s,crypto_int16 crypto_int16_x) {
  *crypto_int16_s++ = crypto_int16_x >> 0;
  *crypto_int16_s++ = crypto_int16_x >> 8;
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int16 crypto_int16_negative_نقاب(crypto_int16 crypto_int16_x) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarw $15,%0" : "+r"(crypto_int16_x) : : "cc");
  أرجع crypto_int16_x;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_y;
  __asm__ ("sbfx %w0,%w1,15,1" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) : );
  أرجع crypto_int16_y;
#وإلا
  crypto_int16_x >>= 16-6;
  crypto_int16_x ^= crypto_int16_optblocker;
  crypto_int16_x >>= 5;
  أرجع crypto_int16_x;
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int16_unsigned crypto_int16_unsigned_topbit_01(crypto_int16_unsigned crypto_int16_x) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("shrw $15,%0" : "+r"(crypto_int16_x) : : "cc");
  أرجع crypto_int16_x;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_y;
  __asm__ ("ubfx %w0,%w1,15,1" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) : );
  أرجع crypto_int16_y;
#وإلا
  crypto_int16_x >>= 16-6;
  crypto_int16_x ^= crypto_int16_optblocker;
  crypto_int16_x >>= 5;
  أرجع crypto_int16_x;
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int16 crypto_int16_negative_01(crypto_int16 crypto_int16_x) {
  أرجع crypto_int16_unsigned_topbit_01(crypto_int16_x);
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int16 crypto_int16_topbit_نقاب(crypto_int16 crypto_int16_x) {
  أرجع crypto_int16_negative_نقاب(crypto_int16_x);
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int16 crypto_int16_topbit_01(crypto_int16 crypto_int16_x) {
  أرجع crypto_int16_unsigned_topbit_01(crypto_int16_x);
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int16 crypto_int16_bottombit_نقاب(crypto_int16 crypto_int16_x) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andw $1,%0" : "+r"(crypto_int16_x) : : "cc");
  أرجع -crypto_int16_x;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_y;
  __asm__ ("sbfx %w0,%w1,0,1" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) : );
  أرجع crypto_int16_y;
#وإلا
  crypto_int16_x &= 1 ^ crypto_int16_optblocker;
  أرجع -crypto_int16_x;
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int16 crypto_int16_bottombit_01(crypto_int16 crypto_int16_x) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andw $1,%0" : "+r"(crypto_int16_x) : : "cc");
  أرجع crypto_int16_x;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_y;
  __asm__ ("ubfx %w0,%w1,0,1" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) : );
  أرجع crypto_int16_y;
#وإلا
  crypto_int16_x &= 1 ^ crypto_int16_optblocker;
  أرجع crypto_int16_x;
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int16 crypto_int16_bitinrangepublicpos_نقاب(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarw %%cl,%0" : "+r"(crypto_int16_x) : "c"(crypto_int16_s) : "cc");
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("sxth %w0,%w0\n asr %w0,%w0,%w1" : "+&r"(crypto_int16_x) : "r"(crypto_int16_s) : );
#وإلا
  crypto_int16_x >>= crypto_int16_s ^ crypto_int16_optblocker;
#جے_انت
  أرجع crypto_int16_bottombit_نقاب(crypto_int16_x);
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int16 crypto_int16_bitinrangepublicpos_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarw %%cl,%0" : "+r"(crypto_int16_x) : "c"(crypto_int16_s) : "cc");
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("sxth %w0,%w0\n asr %w0,%w0,%w1" : "+&r"(crypto_int16_x) : "r"(crypto_int16_s) : );
#وإلا
  crypto_int16_x >>= crypto_int16_s ^ crypto_int16_optblocker;
#جے_انت
  أرجع crypto_int16_bottombit_01(crypto_int16_x);
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int16 crypto_int16_shlmod(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  crypto_int16_s &= 15;
  __asm__ ("shlw %%cl,%0" : "+r"(crypto_int16_x) : "c"(crypto_int16_s) : "cc");
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("and %w0,%w0,15\n and %w1,%w1,65535\n lsl %w1,%w1,%w0" : "+&r"(crypto_int16_s), "+r"(crypto_int16_x) : : );
#وإلا
  صحيح crypto_int16_k, crypto_int16_l;
  لكل (crypto_int16_l = 0,crypto_int16_k = 1;crypto_int16_k < 16;++crypto_int16_l,crypto_int16_k *= 2)
    crypto_int16_x ^= (crypto_int16_x ^ (crypto_int16_x << crypto_int16_k)) & crypto_int16_bitinrangepublicpos_نقاب(crypto_int16_s,crypto_int16_l);
#جے_انت
  أرجع crypto_int16_x;
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int16 crypto_int16_shrmod(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  crypto_int16_s &= 15;
  __asm__ ("sarw %%cl,%0" : "+r"(crypto_int16_x) : "c"(crypto_int16_s) : "cc");
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("and %w0,%w0,15\n sxth %w1,%w1\n asr %w1,%w1,%w0" : "+&r"(crypto_int16_s), "+r"(crypto_int16_x) : : );
#وإلا
  صحيح crypto_int16_k, crypto_int16_l;
  لكل (crypto_int16_l = 0,crypto_int16_k = 1;crypto_int16_k < 16;++crypto_int16_l,crypto_int16_k *= 2)
    crypto_int16_x ^= (crypto_int16_x ^ (crypto_int16_x >> crypto_int16_k)) & crypto_int16_bitinrangepublicpos_نقاب(crypto_int16_s,crypto_int16_l);
#جے_انت
  أرجع crypto_int16_x;
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int16 crypto_int16_bitmod_نقاب(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
  crypto_int16_x = crypto_int16_shrmod(crypto_int16_x,crypto_int16_s);
  أرجع crypto_int16_bottombit_نقاب(crypto_int16_x);
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int16 crypto_int16_bitmod_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
  crypto_int16_x = crypto_int16_shrmod(crypto_int16_x,crypto_int16_s);
  أرجع crypto_int16_bottombit_01(crypto_int16_x);
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int16 crypto_int16_nonzero_نقاب(crypto_int16 crypto_int16_x) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n testw %2,%2\n cmovnew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  أرجع crypto_int16_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("tst %w1,65535\n csetm %w0,ne" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  أرجع crypto_int16_z;
#وإلا
  crypto_int16_x |= -crypto_int16_x;
  أرجع crypto_int16_negative_نقاب(crypto_int16_x);
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int16 crypto_int16_nonzero_01(crypto_int16 crypto_int16_x) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n testw %2,%2\n cmovnew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  أرجع crypto_int16_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("tst %w1,65535\n cset %w0,ne" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  أرجع crypto_int16_z;
#وإلا
  crypto_int16_x |= -crypto_int16_x;
  أرجع crypto_int16_unsigned_topbit_01(crypto_int16_x);
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int16 crypto_int16_مثبت_نقاب(crypto_int16 crypto_int16_x) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n testw %2,%2\n cmovgw %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  أرجع crypto_int16_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,0\n csetm %w0,gt" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  أرجع crypto_int16_z;
#وإلا
  crypto_int16 crypto_int16_z = -crypto_int16_x;
  crypto_int16_z ^= crypto_int16_x & crypto_int16_z;
  أرجع crypto_int16_negative_نقاب(crypto_int16_z);
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int16 crypto_int16_مثبت_01(crypto_int16 crypto_int16_x) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n testw %2,%2\n cmovgw %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  أرجع crypto_int16_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,0\n cset %w0,gt" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  أرجع crypto_int16_z;
#وإلا
  crypto_int16 crypto_int16_z = -crypto_int16_x;
  crypto_int16_z ^= crypto_int16_x & crypto_int16_z;
  أرجع crypto_int16_unsigned_topbit_01(crypto_int16_z);
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int16 crypto_int16_zero_نقاب(crypto_int16 crypto_int16_x) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n testw %2,%2\n cmovew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  أرجع crypto_int16_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("tst %w1,65535\n csetm %w0,eq" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  أرجع crypto_int16_z;
#وإلا
  أرجع ~crypto_int16_nonzero_نقاب(crypto_int16_x);
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int16 crypto_int16_zero_01(crypto_int16 crypto_int16_x) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n testw %2,%2\n cmovew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  أرجع crypto_int16_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("tst %w1,65535\n cset %w0,eq" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  أرجع crypto_int16_z;
#وإلا
  أرجع 1-crypto_int16_nonzero_01(crypto_int16_x);
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int16 crypto_int16_unequal_نقاب(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n cmpw %3,%2\n cmovnew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  أرجع crypto_int16_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("and %w0,%w1,65535\n cmp %w0,%w2,uxth\n csetm %w0,ne" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  أرجع crypto_int16_z;
#وإلا
  أرجع crypto_int16_nonzero_نقاب(crypto_int16_x ^ crypto_int16_y);
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int16 crypto_int16_unequal_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n cmpw %3,%2\n cmovnew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  أرجع crypto_int16_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("and %w0,%w1,65535\n cmp %w0,%w2,uxth\n cset %w0,ne" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  أرجع crypto_int16_z;
#وإلا
  أرجع crypto_int16_nonzero_01(crypto_int16_x ^ crypto_int16_y);
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int16 crypto_int16_equal_نقاب(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n cmpw %3,%2\n cmovew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  أرجع crypto_int16_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("and %w0,%w1,65535\n cmp %w0,%w2,uxth\n csetm %w0,eq" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  أرجع crypto_int16_z;
#وإلا
  أرجع ~crypto_int16_unequal_نقاب(crypto_int16_x,crypto_int16_y);
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int16 crypto_int16_equal_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n cmpw %3,%2\n cmovew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  أرجع crypto_int16_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("and %w0,%w1,65535\n cmp %w0,%w2,uxth\n cset %w0,eq" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  أرجع crypto_int16_z;
#وإلا
  أرجع 1-crypto_int16_unequal_01(crypto_int16_x,crypto_int16_y);
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int16 crypto_int16_min(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpw %1,%0\n cmovgw %1,%0" : "+r"(crypto_int16_x) : "r"(crypto_int16_y) : "cc");
  أرجع crypto_int16_x;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("sxth %w0,%w0\n cmp %w0,%w1,sxth\n csel %w0,%w0,%w1,lt" : "+&r"(crypto_int16_x) : "r"(crypto_int16_y) : "cc");
  أرجع crypto_int16_x;
#وإلا
  crypto_int16 crypto_int16_r = crypto_int16_y ^ crypto_int16_x;
  crypto_int16 crypto_int16_z = crypto_int16_y - crypto_int16_x;
  crypto_int16_z ^= crypto_int16_r & (crypto_int16_z ^ crypto_int16_y);
  crypto_int16_z = crypto_int16_negative_نقاب(crypto_int16_z);
  crypto_int16_z &= crypto_int16_r;
  أرجع crypto_int16_x ^ crypto_int16_z;
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int16 crypto_int16_max(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpw %1,%0\n cmovlw %1,%0" : "+r"(crypto_int16_x) : "r"(crypto_int16_y) : "cc");
  أرجع crypto_int16_x;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("sxth %w0,%w0\n cmp %w0,%w1,sxth\n csel %w0,%w1,%w0,lt" : "+&r"(crypto_int16_x) : "r"(crypto_int16_y) : "cc");
  أرجع crypto_int16_x;
#وإلا
  crypto_int16 crypto_int16_r = crypto_int16_y ^ crypto_int16_x;
  crypto_int16 crypto_int16_z = crypto_int16_y - crypto_int16_x;
  crypto_int16_z ^= crypto_int16_r & (crypto_int16_z ^ crypto_int16_y);
  crypto_int16_z = crypto_int16_negative_نقاب(crypto_int16_z);
  crypto_int16_z &= crypto_int16_r;
  أرجع crypto_int16_y ^ crypto_int16_z;
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
فراغ crypto_int16_minmax(crypto_int16 *crypto_int16_p,crypto_int16 *crypto_int16_q) {
  crypto_int16 crypto_int16_x = *crypto_int16_p;
  crypto_int16 crypto_int16_y = *crypto_int16_q;
#إذا defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("cmpw %2,%1\n movw %1,%0\n cmovgw %2,%1\n cmovgw %0,%2" : "=&r"(crypto_int16_z), "+&r"(crypto_int16_x), "+r"(crypto_int16_y) : : "cc");
  *crypto_int16_p = crypto_int16_x;
  *crypto_int16_q = crypto_int16_y;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_r, crypto_int16_s;
  __asm__ ("sxth %w0,%w0\n cmp %w0,%w3,sxth\n csel %w1,%w0,%w3,lt\n csel %w2,%w3,%w0,lt" : "+&r"(crypto_int16_x), "=&r"(crypto_int16_r), "=r"(crypto_int16_s) : "r"(crypto_int16_y) : "cc");
  *crypto_int16_p = crypto_int16_r;
  *crypto_int16_q = crypto_int16_s;
#وإلا
  crypto_int16 crypto_int16_r = crypto_int16_y ^ crypto_int16_x;
  crypto_int16 crypto_int16_z = crypto_int16_y - crypto_int16_x;
  crypto_int16_z ^= crypto_int16_r & (crypto_int16_z ^ crypto_int16_y);
  crypto_int16_z = crypto_int16_negative_نقاب(crypto_int16_z);
  crypto_int16_z &= crypto_int16_r;
  crypto_int16_x ^= crypto_int16_z;
  crypto_int16_y ^= crypto_int16_z;
  *crypto_int16_p = crypto_int16_x;
  *crypto_int16_q = crypto_int16_y;
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int16 crypto_int16_smaller_نقاب(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n cmpw %3,%2\n cmovlw %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  أرجع crypto_int16_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,%w2,sxth\n csetm %w0,lt" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  أرجع crypto_int16_z;
#وإلا
  crypto_int16 crypto_int16_r = crypto_int16_x ^ crypto_int16_y;
  crypto_int16 crypto_int16_z = crypto_int16_x - crypto_int16_y;
  crypto_int16_z ^= crypto_int16_r & (crypto_int16_z ^ crypto_int16_x);
  أرجع crypto_int16_negative_نقاب(crypto_int16_z);
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int16 crypto_int16_smaller_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n cmpw %3,%2\n cmovlw %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  أرجع crypto_int16_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,%w2,sxth\n cset %w0,lt" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  أرجع crypto_int16_z;
#وإلا
  crypto_int16 crypto_int16_r = crypto_int16_x ^ crypto_int16_y;
  crypto_int16 crypto_int16_z = crypto_int16_x - crypto_int16_y;
  crypto_int16_z ^= crypto_int16_r & (crypto_int16_z ^ crypto_int16_x);
  أرجع crypto_int16_unsigned_topbit_01(crypto_int16_z);
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int16 crypto_int16_leq_نقاب(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n cmpw %3,%2\n cmovlew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  أرجع crypto_int16_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,%w2,sxth\n csetm %w0,le" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  أرجع crypto_int16_z;
#وإلا
  أرجع ~crypto_int16_smaller_نقاب(crypto_int16_y,crypto_int16_x);
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int16 crypto_int16_leq_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n cmpw %3,%2\n cmovlew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  أرجع crypto_int16_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,%w2,sxth\n cset %w0,le" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  أرجع crypto_int16_z;
#وإلا
  أرجع 1-crypto_int16_smaller_01(crypto_int16_y,crypto_int16_x);
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
صحيح crypto_int16_ones_عدد(crypto_int16 crypto_int16_x) {
  crypto_int16_unsigned crypto_int16_y = crypto_int16_x;
  ثابت crypto_int16 C0 = 0x5555;
  ثابت crypto_int16 C1 = 0x3333;
  ثابت crypto_int16 C2 = 0x0f0f;
  crypto_int16_y -= ((crypto_int16_y >> 1) & C0);
  crypto_int16_y = (crypto_int16_y & C1) + ((crypto_int16_y >> 2) & C1);
  crypto_int16_y = (crypto_int16_y + (crypto_int16_y >> 4)) & C2;
  crypto_int16_y = (crypto_int16_y + (crypto_int16_y >> 8)) & 0xff;
  أرجع crypto_int16_y;
}

__attribute__((بن_ورتیا))
ساكن مضمن
صحيح crypto_int16_bottomzeros_عدد(crypto_int16 crypto_int16_x) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 fallback = 16;
  __asm__ ("bsfw %0,%0\n cmovew %1,%0" : "+&r"(crypto_int16_x) : "r"(fallback) : "cc");
  أرجع crypto_int16_x;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  int64_t crypto_int16_y;
  __asm__ ("orr %w0,%w1,-65536\n rbit %w0,%w0\n clz %w0,%w0" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) : );
  أرجع crypto_int16_y;
#وإلا
  crypto_int16 crypto_int16_y = crypto_int16_x ^ (crypto_int16_x-1);
  crypto_int16_y = ((crypto_int16) crypto_int16_y) >> 1;
  crypto_int16_y &= ~(crypto_int16_x & (((crypto_int16) 1) << (16-1)));
  أرجع crypto_int16_ones_عدد(crypto_int16_y);
#جے_انت
}

#جے_انت

/* from supercop-20240808/cryptoint/crypto_int32.h */
/* auto-generated: cd cryptoint; ./autogen */
/* cryptoint 20240806 */

#جے_بنا_تعریف crypto_int32_h
#تعریف_کرو crypto_int32_h

#تعریف_کرو crypto_int32 int32_t
#تعریف_کرو crypto_int32_unsigned uint32_t



__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int32 crypto_int32_لدو(ثابت بنانشانی حرف *crypto_int32_s) {
  crypto_int32 crypto_int32_z = 0;
  crypto_int32_z |= ((crypto_int32) (*crypto_int32_s++)) << 0;
  crypto_int32_z |= ((crypto_int32) (*crypto_int32_s++)) << 8;
  crypto_int32_z |= ((crypto_int32) (*crypto_int32_s++)) << 16;
  crypto_int32_z |= ((crypto_int32) (*crypto_int32_s++)) << 24;
  أرجع crypto_int32_z;
}

__attribute__((بن_ورتیا))
ساكن مضمن
فراغ crypto_int32_store(بنانشانی حرف *crypto_int32_s,crypto_int32 crypto_int32_x) {
  *crypto_int32_s++ = crypto_int32_x >> 0;
  *crypto_int32_s++ = crypto_int32_x >> 8;
  *crypto_int32_s++ = crypto_int32_x >> 16;
  *crypto_int32_s++ = crypto_int32_x >> 24;
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int32 crypto_int32_negative_نقاب(crypto_int32 crypto_int32_x) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarl $31,%0" : "+r"(crypto_int32_x) : : "cc");
  أرجع crypto_int32_x;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_y;
  __asm__ ("asr %w0,%w1,31" : "=r"(crypto_int32_y) : "r"(crypto_int32_x) : );
  أرجع crypto_int32_y;
#وإلا
  crypto_int32_x >>= 32-6;
  crypto_int32_x ^= crypto_int32_optblocker;
  crypto_int32_x >>= 5;
  أرجع crypto_int32_x;
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int32_unsigned crypto_int32_unsigned_topbit_01(crypto_int32_unsigned crypto_int32_x) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("shrl $31,%0" : "+r"(crypto_int32_x) : : "cc");
  أرجع crypto_int32_x;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_y;
  __asm__ ("lsr %w0,%w1,31" : "=r"(crypto_int32_y) : "r"(crypto_int32_x) : );
  أرجع crypto_int32_y;
#وإلا
  crypto_int32_x >>= 32-6;
  crypto_int32_x ^= crypto_int32_optblocker;
  crypto_int32_x >>= 5;
  أرجع crypto_int32_x;
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int32 crypto_int32_negative_01(crypto_int32 crypto_int32_x) {
  أرجع crypto_int32_unsigned_topbit_01(crypto_int32_x);
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int32 crypto_int32_topbit_نقاب(crypto_int32 crypto_int32_x) {
  أرجع crypto_int32_negative_نقاب(crypto_int32_x);
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int32 crypto_int32_topbit_01(crypto_int32 crypto_int32_x) {
  أرجع crypto_int32_unsigned_topbit_01(crypto_int32_x);
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int32 crypto_int32_bottombit_نقاب(crypto_int32 crypto_int32_x) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andl $1,%0" : "+r"(crypto_int32_x) : : "cc");
  أرجع -crypto_int32_x;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_y;
  __asm__ ("sbfx %w0,%w1,0,1" : "=r"(crypto_int32_y) : "r"(crypto_int32_x) : );
  أرجع crypto_int32_y;
#وإلا
  crypto_int32_x &= 1 ^ crypto_int32_optblocker;
  أرجع -crypto_int32_x;
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int32 crypto_int32_bottombit_01(crypto_int32 crypto_int32_x) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andl $1,%0" : "+r"(crypto_int32_x) : : "cc");
  أرجع crypto_int32_x;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_y;
  __asm__ ("ubfx %w0,%w1,0,1" : "=r"(crypto_int32_y) : "r"(crypto_int32_x) : );
  أرجع crypto_int32_y;
#وإلا
  crypto_int32_x &= 1 ^ crypto_int32_optblocker;
  أرجع crypto_int32_x;
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int32 crypto_int32_bitinrangepublicpos_نقاب(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarl %%cl,%0" : "+r"(crypto_int32_x) : "c"(crypto_int32_s) : "cc");
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %w0,%w0,%w1" : "+r"(crypto_int32_x) : "r"(crypto_int32_s) : );
#وإلا
  crypto_int32_x >>= crypto_int32_s ^ crypto_int32_optblocker;
#جے_انت
  أرجع crypto_int32_bottombit_نقاب(crypto_int32_x);
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int32 crypto_int32_bitinrangepublicpos_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarl %%cl,%0" : "+r"(crypto_int32_x) : "c"(crypto_int32_s) : "cc");
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %w0,%w0,%w1" : "+r"(crypto_int32_x) : "r"(crypto_int32_s) : );
#وإلا
  crypto_int32_x >>= crypto_int32_s ^ crypto_int32_optblocker;
#جے_انت
  أرجع crypto_int32_bottombit_01(crypto_int32_x);
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int32 crypto_int32_shlmod(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("shll %%cl,%0" : "+r"(crypto_int32_x) : "c"(crypto_int32_s) : "cc");
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("lsl %w0,%w0,%w1" : "+r"(crypto_int32_x) : "r"(crypto_int32_s) : );
#وإلا
  صحيح crypto_int32_k, crypto_int32_l;
  لكل (crypto_int32_l = 0,crypto_int32_k = 1;crypto_int32_k < 32;++crypto_int32_l,crypto_int32_k *= 2)
    crypto_int32_x ^= (crypto_int32_x ^ (crypto_int32_x << crypto_int32_k)) & crypto_int32_bitinrangepublicpos_نقاب(crypto_int32_s,crypto_int32_l);
#جے_انت
  أرجع crypto_int32_x;
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int32 crypto_int32_shrmod(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarl %%cl,%0" : "+r"(crypto_int32_x) : "c"(crypto_int32_s) : "cc");
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %w0,%w0,%w1" : "+r"(crypto_int32_x) : "r"(crypto_int32_s) : );
#وإلا
  صحيح crypto_int32_k, crypto_int32_l;
  لكل (crypto_int32_l = 0,crypto_int32_k = 1;crypto_int32_k < 32;++crypto_int32_l,crypto_int32_k *= 2)
    crypto_int32_x ^= (crypto_int32_x ^ (crypto_int32_x >> crypto_int32_k)) & crypto_int32_bitinrangepublicpos_نقاب(crypto_int32_s,crypto_int32_l);
#جے_انت
  أرجع crypto_int32_x;
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int32 crypto_int32_bitmod_نقاب(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
  crypto_int32_x = crypto_int32_shrmod(crypto_int32_x,crypto_int32_s);
  أرجع crypto_int32_bottombit_نقاب(crypto_int32_x);
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int32 crypto_int32_bitmod_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
  crypto_int32_x = crypto_int32_shrmod(crypto_int32_x,crypto_int32_s);
  أرجع crypto_int32_bottombit_01(crypto_int32_x);
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int32 crypto_int32_nonzero_نقاب(crypto_int32 crypto_int32_x) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n testl %2,%2\n cmovnel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  أرجع crypto_int32_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n csetm %w0,ne" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  أرجع crypto_int32_z;
#وإلا
  crypto_int32_x |= -crypto_int32_x;
  أرجع crypto_int32_negative_نقاب(crypto_int32_x);
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int32 crypto_int32_nonzero_01(crypto_int32 crypto_int32_x) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n testl %2,%2\n cmovnel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  أرجع crypto_int32_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n cset %w0,ne" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  أرجع crypto_int32_z;
#وإلا
  crypto_int32_x |= -crypto_int32_x;
  أرجع crypto_int32_unsigned_topbit_01(crypto_int32_x);
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int32 crypto_int32_مثبت_نقاب(crypto_int32 crypto_int32_x) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n testl %2,%2\n cmovgl %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  أرجع crypto_int32_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n csetm %w0,gt" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  أرجع crypto_int32_z;
#وإلا
  crypto_int32 crypto_int32_z = -crypto_int32_x;
  crypto_int32_z ^= crypto_int32_x & crypto_int32_z;
  أرجع crypto_int32_negative_نقاب(crypto_int32_z);
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int32 crypto_int32_مثبت_01(crypto_int32 crypto_int32_x) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n testl %2,%2\n cmovgl %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  أرجع crypto_int32_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n cset %w0,gt" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  أرجع crypto_int32_z;
#وإلا
  crypto_int32 crypto_int32_z = -crypto_int32_x;
  crypto_int32_z ^= crypto_int32_x & crypto_int32_z;
  أرجع crypto_int32_unsigned_topbit_01(crypto_int32_z);
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int32 crypto_int32_zero_نقاب(crypto_int32 crypto_int32_x) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n testl %2,%2\n cmovel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  أرجع crypto_int32_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n csetm %w0,eq" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  أرجع crypto_int32_z;
#وإلا
  أرجع ~crypto_int32_nonzero_نقاب(crypto_int32_x);
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int32 crypto_int32_zero_01(crypto_int32 crypto_int32_x) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n testl %2,%2\n cmovel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  أرجع crypto_int32_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n cset %w0,eq" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  أرجع crypto_int32_z;
#وإلا
  أرجع 1-crypto_int32_nonzero_01(crypto_int32_x);
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int32 crypto_int32_unequal_نقاب(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n cmpl %3,%2\n cmovnel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  أرجع crypto_int32_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n csetm %w0,ne" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  أرجع crypto_int32_z;
#وإلا
  أرجع crypto_int32_nonzero_نقاب(crypto_int32_x ^ crypto_int32_y);
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int32 crypto_int32_unequal_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n cmpl %3,%2\n cmovnel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  أرجع crypto_int32_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n cset %w0,ne" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  أرجع crypto_int32_z;
#وإلا
  أرجع crypto_int32_nonzero_01(crypto_int32_x ^ crypto_int32_y);
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int32 crypto_int32_equal_نقاب(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n cmpl %3,%2\n cmovel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  أرجع crypto_int32_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n csetm %w0,eq" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  أرجع crypto_int32_z;
#وإلا
  أرجع ~crypto_int32_unequal_نقاب(crypto_int32_x,crypto_int32_y);
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int32 crypto_int32_equal_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n cmpl %3,%2\n cmovel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  أرجع crypto_int32_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n cset %w0,eq" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  أرجع crypto_int32_z;
#وإلا
  أرجع 1-crypto_int32_unequal_01(crypto_int32_x,crypto_int32_y);
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int32 crypto_int32_min(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpl %1,%0\n cmovgl %1,%0" : "+r"(crypto_int32_x) : "r"(crypto_int32_y) : "cc");
  أرجع crypto_int32_x;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("cmp %w0,%w1\n csel %w0,%w0,%w1,lt" : "+r"(crypto_int32_x) : "r"(crypto_int32_y) : "cc");
  أرجع crypto_int32_x;
#وإلا
  crypto_int64 crypto_int32_r = (crypto_int64)crypto_int32_y ^ (crypto_int64)crypto_int32_x;
  crypto_int64 crypto_int32_z = (crypto_int64)crypto_int32_y - (crypto_int64)crypto_int32_x;
  crypto_int32_z ^= crypto_int32_r & (crypto_int32_z ^ crypto_int32_y);
  crypto_int32_z = crypto_int32_negative_نقاب(crypto_int32_z);
  crypto_int32_z &= crypto_int32_r;
  أرجع crypto_int32_x ^ crypto_int32_z;
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int32 crypto_int32_max(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpl %1,%0\n cmovll %1,%0" : "+r"(crypto_int32_x) : "r"(crypto_int32_y) : "cc");
  أرجع crypto_int32_x;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("cmp %w0,%w1\n csel %w0,%w1,%w0,lt" : "+r"(crypto_int32_x) : "r"(crypto_int32_y) : "cc");
  أرجع crypto_int32_x;
#وإلا
  crypto_int64 crypto_int32_r = (crypto_int64)crypto_int32_y ^ (crypto_int64)crypto_int32_x;
  crypto_int64 crypto_int32_z = (crypto_int64)crypto_int32_y - (crypto_int64)crypto_int32_x;
  crypto_int32_z ^= crypto_int32_r & (crypto_int32_z ^ crypto_int32_y);
  crypto_int32_z = crypto_int32_negative_نقاب(crypto_int32_z);
  crypto_int32_z &= crypto_int32_r;
  أرجع crypto_int32_y ^ crypto_int32_z;
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
فراغ crypto_int32_minmax(crypto_int32 *crypto_int32_p,crypto_int32 *crypto_int32_q) {
  crypto_int32 crypto_int32_x = *crypto_int32_p;
  crypto_int32 crypto_int32_y = *crypto_int32_q;
#إذا defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmpl %2,%1\n movl %1,%0\n cmovgl %2,%1\n cmovgl %0,%2" : "=&r"(crypto_int32_z), "+&r"(crypto_int32_x), "+r"(crypto_int32_y) : : "cc");
  *crypto_int32_p = crypto_int32_x;
  *crypto_int32_q = crypto_int32_y;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_r, crypto_int32_s;
  __asm__ ("cmp %w2,%w3\n csel %w0,%w2,%w3,lt\n csel %w1,%w3,%w2,lt" : "=&r"(crypto_int32_r), "=r"(crypto_int32_s) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  *crypto_int32_p = crypto_int32_r;
  *crypto_int32_q = crypto_int32_s;
#وإلا
  crypto_int64 crypto_int32_r = (crypto_int64)crypto_int32_y ^ (crypto_int64)crypto_int32_x;
  crypto_int64 crypto_int32_z = (crypto_int64)crypto_int32_y - (crypto_int64)crypto_int32_x;
  crypto_int32_z ^= crypto_int32_r & (crypto_int32_z ^ crypto_int32_y);
  crypto_int32_z = crypto_int32_negative_نقاب(crypto_int32_z);
  crypto_int32_z &= crypto_int32_r;
  crypto_int32_x ^= crypto_int32_z;
  crypto_int32_y ^= crypto_int32_z;
  *crypto_int32_p = crypto_int32_x;
  *crypto_int32_q = crypto_int32_y;
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int32 crypto_int32_smaller_نقاب(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n cmpl %3,%2\n cmovll %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  أرجع crypto_int32_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n csetm %w0,lt" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  أرجع crypto_int32_z;
#وإلا
  crypto_int32 crypto_int32_r = crypto_int32_x ^ crypto_int32_y;
  crypto_int32 crypto_int32_z = crypto_int32_x - crypto_int32_y;
  crypto_int32_z ^= crypto_int32_r & (crypto_int32_z ^ crypto_int32_x);
  أرجع crypto_int32_negative_نقاب(crypto_int32_z);
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int32 crypto_int32_smaller_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n cmpl %3,%2\n cmovll %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  أرجع crypto_int32_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n cset %w0,lt" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  أرجع crypto_int32_z;
#وإلا
  crypto_int32 crypto_int32_r = crypto_int32_x ^ crypto_int32_y;
  crypto_int32 crypto_int32_z = crypto_int32_x - crypto_int32_y;
  crypto_int32_z ^= crypto_int32_r & (crypto_int32_z ^ crypto_int32_x);
  أرجع crypto_int32_unsigned_topbit_01(crypto_int32_z);
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int32 crypto_int32_leq_نقاب(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n cmpl %3,%2\n cmovlel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  أرجع crypto_int32_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n csetm %w0,le" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  أرجع crypto_int32_z;
#وإلا
  أرجع ~crypto_int32_smaller_نقاب(crypto_int32_y,crypto_int32_x);
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int32 crypto_int32_leq_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n cmpl %3,%2\n cmovlel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  أرجع crypto_int32_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n cset %w0,le" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  أرجع crypto_int32_z;
#وإلا
  أرجع 1-crypto_int32_smaller_01(crypto_int32_y,crypto_int32_x);
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
صحيح crypto_int32_ones_عدد(crypto_int32 crypto_int32_x) {
  crypto_int32_unsigned crypto_int32_y = crypto_int32_x;
  ثابت crypto_int32 C0 = 0x55555555;
  ثابت crypto_int32 C1 = 0x33333333;
  ثابت crypto_int32 C2 = 0x0f0f0f0f;
  crypto_int32_y -= ((crypto_int32_y >> 1) & C0);
  crypto_int32_y = (crypto_int32_y & C1) + ((crypto_int32_y >> 2) & C1);
  crypto_int32_y = (crypto_int32_y + (crypto_int32_y >> 4)) & C2;
  crypto_int32_y += crypto_int32_y >> 8;
  crypto_int32_y = (crypto_int32_y + (crypto_int32_y >> 16)) & 0xff;
  أرجع crypto_int32_y;
}

__attribute__((بن_ورتیا))
ساكن مضمن
صحيح crypto_int32_bottomzeros_عدد(crypto_int32 crypto_int32_x) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 fallback = 32;
  __asm__ ("bsfl %0,%0\n cmovel %1,%0" : "+&r"(crypto_int32_x) : "r"(fallback) : "cc");
  أرجع crypto_int32_x;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  int64_t crypto_int32_y;
  __asm__ ("rbit %w0,%w1\n clz %w0,%w0" : "=r"(crypto_int32_y) : "r"(crypto_int32_x) : );
  أرجع crypto_int32_y;
#وإلا
  crypto_int32 crypto_int32_y = crypto_int32_x ^ (crypto_int32_x-1);
  crypto_int32_y = ((crypto_int32) crypto_int32_y) >> 1;
  crypto_int32_y &= ~(crypto_int32_x & (((crypto_int32) 1) << (32-1)));
  أرجع crypto_int32_ones_عدد(crypto_int32_y);
#جے_انت
}

#جے_انت

/* from supercop-20240808/cryptoint/crypto_int64.h */
/* auto-generated: cd cryptoint; ./autogen */
/* cryptoint 20240806 */

#جے_بنا_تعریف crypto_int64_h
#تعریف_کرو crypto_int64_h

#تعریف_کرو crypto_int64 int64_t
#تعریف_کرو crypto_int64_unsigned uint64_t



__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int64 crypto_int64_لدو(ثابت بنانشانی حرف *crypto_int64_s) {
  crypto_int64 crypto_int64_z = 0;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 0;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 8;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 16;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 24;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 32;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 40;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 48;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 56;
  أرجع crypto_int64_z;
}

__attribute__((بن_ورتیا))
ساكن مضمن
فراغ crypto_int64_store(بنانشانی حرف *crypto_int64_s,crypto_int64 crypto_int64_x) {
  *crypto_int64_s++ = crypto_int64_x >> 0;
  *crypto_int64_s++ = crypto_int64_x >> 8;
  *crypto_int64_s++ = crypto_int64_x >> 16;
  *crypto_int64_s++ = crypto_int64_x >> 24;
  *crypto_int64_s++ = crypto_int64_x >> 32;
  *crypto_int64_s++ = crypto_int64_x >> 40;
  *crypto_int64_s++ = crypto_int64_x >> 48;
  *crypto_int64_s++ = crypto_int64_x >> 56;
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int64 crypto_int64_negative_نقاب(crypto_int64 crypto_int64_x) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarq $63,%0" : "+r"(crypto_int64_x) : : "cc");
  أرجع crypto_int64_x;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_y;
  __asm__ ("asr %0,%1,63" : "=r"(crypto_int64_y) : "r"(crypto_int64_x) : );
  أرجع crypto_int64_y;
#وإلا
  crypto_int64_x >>= 64-6;
  crypto_int64_x ^= crypto_int64_optblocker;
  crypto_int64_x >>= 5;
  أرجع crypto_int64_x;
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int64_unsigned crypto_int64_unsigned_topbit_01(crypto_int64_unsigned crypto_int64_x) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("shrq $63,%0" : "+r"(crypto_int64_x) : : "cc");
  أرجع crypto_int64_x;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_y;
  __asm__ ("lsr %0,%1,63" : "=r"(crypto_int64_y) : "r"(crypto_int64_x) : );
  أرجع crypto_int64_y;
#وإلا
  crypto_int64_x >>= 64-6;
  crypto_int64_x ^= crypto_int64_optblocker;
  crypto_int64_x >>= 5;
  أرجع crypto_int64_x;
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int64 crypto_int64_negative_01(crypto_int64 crypto_int64_x) {
  أرجع crypto_int64_unsigned_topbit_01(crypto_int64_x);
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int64 crypto_int64_topbit_نقاب(crypto_int64 crypto_int64_x) {
  أرجع crypto_int64_negative_نقاب(crypto_int64_x);
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int64 crypto_int64_topbit_01(crypto_int64 crypto_int64_x) {
  أرجع crypto_int64_unsigned_topbit_01(crypto_int64_x);
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int64 crypto_int64_bottombit_نقاب(crypto_int64 crypto_int64_x) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andq $1,%0" : "+r"(crypto_int64_x) : : "cc");
  أرجع -crypto_int64_x;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_y;
  __asm__ ("sbfx %0,%1,0,1" : "=r"(crypto_int64_y) : "r"(crypto_int64_x) : );
  أرجع crypto_int64_y;
#وإلا
  crypto_int64_x &= 1 ^ crypto_int64_optblocker;
  أرجع -crypto_int64_x;
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int64 crypto_int64_bottombit_01(crypto_int64 crypto_int64_x) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andq $1,%0" : "+r"(crypto_int64_x) : : "cc");
  أرجع crypto_int64_x;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_y;
  __asm__ ("ubfx %0,%1,0,1" : "=r"(crypto_int64_y) : "r"(crypto_int64_x) : );
  أرجع crypto_int64_y;
#وإلا
  crypto_int64_x &= 1 ^ crypto_int64_optblocker;
  أرجع crypto_int64_x;
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int64 crypto_int64_bitinrangepublicpos_نقاب(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarq %%cl,%0" : "+r"(crypto_int64_x) : "c"(crypto_int64_s) : "cc");
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %0,%0,%1" : "+r"(crypto_int64_x) : "r"(crypto_int64_s) : );
#وإلا
  crypto_int64_x >>= crypto_int64_s ^ crypto_int64_optblocker;
#جے_انت
  أرجع crypto_int64_bottombit_نقاب(crypto_int64_x);
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int64 crypto_int64_bitinrangepublicpos_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarq %%cl,%0" : "+r"(crypto_int64_x) : "c"(crypto_int64_s) : "cc");
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %0,%0,%1" : "+r"(crypto_int64_x) : "r"(crypto_int64_s) : );
#وإلا
  crypto_int64_x >>= crypto_int64_s ^ crypto_int64_optblocker;
#جے_انت
  أرجع crypto_int64_bottombit_01(crypto_int64_x);
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int64 crypto_int64_shlmod(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("shlq %%cl,%0" : "+r"(crypto_int64_x) : "c"(crypto_int64_s) : "cc");
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("lsl %0,%0,%1" : "+r"(crypto_int64_x) : "r"(crypto_int64_s) : );
#وإلا
  صحيح crypto_int64_k, crypto_int64_l;
  لكل (crypto_int64_l = 0,crypto_int64_k = 1;crypto_int64_k < 64;++crypto_int64_l,crypto_int64_k *= 2)
    crypto_int64_x ^= (crypto_int64_x ^ (crypto_int64_x << crypto_int64_k)) & crypto_int64_bitinrangepublicpos_نقاب(crypto_int64_s,crypto_int64_l);
#جے_انت
  أرجع crypto_int64_x;
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int64 crypto_int64_shrmod(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarq %%cl,%0" : "+r"(crypto_int64_x) : "c"(crypto_int64_s) : "cc");
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %0,%0,%1" : "+r"(crypto_int64_x) : "r"(crypto_int64_s) : );
#وإلا
  صحيح crypto_int64_k, crypto_int64_l;
  لكل (crypto_int64_l = 0,crypto_int64_k = 1;crypto_int64_k < 64;++crypto_int64_l,crypto_int64_k *= 2)
    crypto_int64_x ^= (crypto_int64_x ^ (crypto_int64_x >> crypto_int64_k)) & crypto_int64_bitinrangepublicpos_نقاب(crypto_int64_s,crypto_int64_l);
#جے_انت
  أرجع crypto_int64_x;
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int64 crypto_int64_bitmod_نقاب(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
  crypto_int64_x = crypto_int64_shrmod(crypto_int64_x,crypto_int64_s);
  أرجع crypto_int64_bottombit_نقاب(crypto_int64_x);
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int64 crypto_int64_bitmod_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
  crypto_int64_x = crypto_int64_shrmod(crypto_int64_x,crypto_int64_s);
  أرجع crypto_int64_bottombit_01(crypto_int64_x);
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int64 crypto_int64_nonzero_نقاب(crypto_int64 crypto_int64_x) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n testq %2,%2\n cmovneq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  أرجع crypto_int64_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n csetm %0,ne" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  أرجع crypto_int64_z;
#وإلا
  crypto_int64_x |= -crypto_int64_x;
  أرجع crypto_int64_negative_نقاب(crypto_int64_x);
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int64 crypto_int64_nonzero_01(crypto_int64 crypto_int64_x) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n testq %2,%2\n cmovneq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  أرجع crypto_int64_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n cset %0,ne" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  أرجع crypto_int64_z;
#وإلا
  crypto_int64_x |= -crypto_int64_x;
  أرجع crypto_int64_unsigned_topbit_01(crypto_int64_x);
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int64 crypto_int64_مثبت_نقاب(crypto_int64 crypto_int64_x) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n testq %2,%2\n cmovgq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  أرجع crypto_int64_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n csetm %0,gt" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  أرجع crypto_int64_z;
#وإلا
  crypto_int64 crypto_int64_z = -crypto_int64_x;
  crypto_int64_z ^= crypto_int64_x & crypto_int64_z;
  أرجع crypto_int64_negative_نقاب(crypto_int64_z);
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int64 crypto_int64_مثبت_01(crypto_int64 crypto_int64_x) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n testq %2,%2\n cmovgq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  أرجع crypto_int64_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n cset %0,gt" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  أرجع crypto_int64_z;
#وإلا
  crypto_int64 crypto_int64_z = -crypto_int64_x;
  crypto_int64_z ^= crypto_int64_x & crypto_int64_z;
  أرجع crypto_int64_unsigned_topbit_01(crypto_int64_z);
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int64 crypto_int64_zero_نقاب(crypto_int64 crypto_int64_x) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n testq %2,%2\n cmoveq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  أرجع crypto_int64_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n csetm %0,eq" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  أرجع crypto_int64_z;
#وإلا
  أرجع ~crypto_int64_nonzero_نقاب(crypto_int64_x);
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int64 crypto_int64_zero_01(crypto_int64 crypto_int64_x) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n testq %2,%2\n cmoveq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  أرجع crypto_int64_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n cset %0,eq" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  أرجع crypto_int64_z;
#وإلا
  أرجع 1-crypto_int64_nonzero_01(crypto_int64_x);
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int64 crypto_int64_unequal_نقاب(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n cmpq %3,%2\n cmovneq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  أرجع crypto_int64_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n csetm %0,ne" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  أرجع crypto_int64_z;
#وإلا
  أرجع crypto_int64_nonzero_نقاب(crypto_int64_x ^ crypto_int64_y);
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int64 crypto_int64_unequal_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n cmpq %3,%2\n cmovneq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  أرجع crypto_int64_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n cset %0,ne" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  أرجع crypto_int64_z;
#وإلا
  أرجع crypto_int64_nonzero_01(crypto_int64_x ^ crypto_int64_y);
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int64 crypto_int64_equal_نقاب(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n cmpq %3,%2\n cmoveq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  أرجع crypto_int64_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n csetm %0,eq" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  أرجع crypto_int64_z;
#وإلا
  أرجع ~crypto_int64_unequal_نقاب(crypto_int64_x,crypto_int64_y);
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int64 crypto_int64_equal_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n cmpq %3,%2\n cmoveq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  أرجع crypto_int64_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n cset %0,eq" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  أرجع crypto_int64_z;
#وإلا
  أرجع 1-crypto_int64_unequal_01(crypto_int64_x,crypto_int64_y);
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int64 crypto_int64_min(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpq %1,%0\n cmovgq %1,%0" : "+r"(crypto_int64_x) : "r"(crypto_int64_y) : "cc");
  أرجع crypto_int64_x;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("cmp %0,%1\n csel %0,%0,%1,lt" : "+r"(crypto_int64_x) : "r"(crypto_int64_y) : "cc");
  أرجع crypto_int64_x;
#وإلا
  crypto_int64 crypto_int64_r = crypto_int64_y ^ crypto_int64_x;
  crypto_int64 crypto_int64_z = crypto_int64_y - crypto_int64_x;
  crypto_int64_z ^= crypto_int64_r & (crypto_int64_z ^ crypto_int64_y);
  crypto_int64_z = crypto_int64_negative_نقاب(crypto_int64_z);
  crypto_int64_z &= crypto_int64_r;
  أرجع crypto_int64_x ^ crypto_int64_z;
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int64 crypto_int64_max(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpq %1,%0\n cmovlq %1,%0" : "+r"(crypto_int64_x) : "r"(crypto_int64_y) : "cc");
  أرجع crypto_int64_x;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("cmp %0,%1\n csel %0,%1,%0,lt" : "+r"(crypto_int64_x) : "r"(crypto_int64_y) : "cc");
  أرجع crypto_int64_x;
#وإلا
  crypto_int64 crypto_int64_r = crypto_int64_y ^ crypto_int64_x;
  crypto_int64 crypto_int64_z = crypto_int64_y - crypto_int64_x;
  crypto_int64_z ^= crypto_int64_r & (crypto_int64_z ^ crypto_int64_y);
  crypto_int64_z = crypto_int64_negative_نقاب(crypto_int64_z);
  crypto_int64_z &= crypto_int64_r;
  أرجع crypto_int64_y ^ crypto_int64_z;
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
فراغ crypto_int64_minmax(crypto_int64 *crypto_int64_p,crypto_int64 *crypto_int64_q) {
  crypto_int64 crypto_int64_x = *crypto_int64_p;
  crypto_int64 crypto_int64_y = *crypto_int64_q;
#إذا defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmpq %2,%1\n movq %1,%0\n cmovgq %2,%1\n cmovgq %0,%2" : "=&r"(crypto_int64_z), "+&r"(crypto_int64_x), "+r"(crypto_int64_y) : : "cc");
  *crypto_int64_p = crypto_int64_x;
  *crypto_int64_q = crypto_int64_y;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_r, crypto_int64_s;
  __asm__ ("cmp %2,%3\n csel %0,%2,%3,lt\n csel %1,%3,%2,lt" : "=&r"(crypto_int64_r), "=r"(crypto_int64_s) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  *crypto_int64_p = crypto_int64_r;
  *crypto_int64_q = crypto_int64_s;
#وإلا
  crypto_int64 crypto_int64_r = crypto_int64_y ^ crypto_int64_x;
  crypto_int64 crypto_int64_z = crypto_int64_y - crypto_int64_x;
  crypto_int64_z ^= crypto_int64_r & (crypto_int64_z ^ crypto_int64_y);
  crypto_int64_z = crypto_int64_negative_نقاب(crypto_int64_z);
  crypto_int64_z &= crypto_int64_r;
  crypto_int64_x ^= crypto_int64_z;
  crypto_int64_y ^= crypto_int64_z;
  *crypto_int64_p = crypto_int64_x;
  *crypto_int64_q = crypto_int64_y;
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int64 crypto_int64_smaller_نقاب(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n cmpq %3,%2\n cmovlq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  أرجع crypto_int64_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n csetm %0,lt" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  أرجع crypto_int64_z;
#وإلا
  crypto_int64 crypto_int64_r = crypto_int64_x ^ crypto_int64_y;
  crypto_int64 crypto_int64_z = crypto_int64_x - crypto_int64_y;
  crypto_int64_z ^= crypto_int64_r & (crypto_int64_z ^ crypto_int64_x);
  أرجع crypto_int64_negative_نقاب(crypto_int64_z);
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int64 crypto_int64_smaller_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n cmpq %3,%2\n cmovlq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  أرجع crypto_int64_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n cset %0,lt" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  أرجع crypto_int64_z;
#وإلا
  crypto_int64 crypto_int64_r = crypto_int64_x ^ crypto_int64_y;
  crypto_int64 crypto_int64_z = crypto_int64_x - crypto_int64_y;
  crypto_int64_z ^= crypto_int64_r & (crypto_int64_z ^ crypto_int64_x);
  أرجع crypto_int64_unsigned_topbit_01(crypto_int64_z);
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int64 crypto_int64_leq_نقاب(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n cmpq %3,%2\n cmovleq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  أرجع crypto_int64_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n csetm %0,le" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  أرجع crypto_int64_z;
#وإلا
  أرجع ~crypto_int64_smaller_نقاب(crypto_int64_y,crypto_int64_x);
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
crypto_int64 crypto_int64_leq_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n cmpq %3,%2\n cmovleq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  أرجع crypto_int64_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n cset %0,le" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  أرجع crypto_int64_z;
#وإلا
  أرجع 1-crypto_int64_smaller_01(crypto_int64_y,crypto_int64_x);
#جے_انت
}

__attribute__((بن_ورتیا))
ساكن مضمن
صحيح crypto_int64_ones_عدد(crypto_int64 crypto_int64_x) {
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
  أرجع crypto_int64_y;
}

__attribute__((بن_ورتیا))
ساكن مضمن
صحيح crypto_int64_bottomzeros_عدد(crypto_int64 crypto_int64_x) {
#إذا defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 fallback = 64;
  __asm__ ("bsfq %0,%0\n cmoveq %1,%0" : "+&r"(crypto_int64_x) : "r"(fallback) : "cc");
  أرجع crypto_int64_x;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  int64_t crypto_int64_y;
  __asm__ ("rbit %0,%1\n clz %0,%0" : "=r"(crypto_int64_y) : "r"(crypto_int64_x) : );
  أرجع crypto_int64_y;
#وإلا
  crypto_int64 crypto_int64_y = crypto_int64_x ^ (crypto_int64_x-1);
  crypto_int64_y = ((crypto_int64) crypto_int64_y) >> 1;
  crypto_int64_y &= ~(crypto_int64_x & (((crypto_int64) 1) << (64-1)));
  أرجع crypto_int64_ones_عدد(crypto_int64_y);
#جے_انت
}

#جے_انت

/* from supercop-20240808/crypto_sort/int32/portable4/sort.c */
#تعریف_کرو int32_MINMAX(a,b) crypto_int32_minmax(&a,&b)

ساكن فراغ crypto_ترتیب_دیو_int32(فراغ *array,لما لما n)
{
  لما لما چوٹی,p,q,r,i,j;
  int32 *x = array;

  إذا (n < 2) أرجع;
  چوٹی = 1;
  طالما (چوٹی < n - چوٹی) چوٹی += چوٹی;

  لكل (p = چوٹی;p >= 1;p >>= 1) {
    i = 0;
    طالما (i + 2 * p <= n) {
      لكل (j = i;j < i + p;++j)
        int32_MINMAX(x[j],x[j+p]);
      i += 2 * p;
    }
    لكل (j = i;j < n - p;++j)
      int32_MINMAX(x[j],x[j+p]);

    i = 0;
    j = 0;
    لكل (q = چوٹی;q > p;q >>= 1) {
      إذا (j != i) لكل (;;) {
        إذا (j == n - q) اذهب پورا;
        int32 a = x[j + p];
        لكل (r = q;r > p;r >>= 1)
          int32_MINMAX(a,x[j + r]);
        x[j + p] = a;
        ++j;
        إذا (j == i + p) {
          i += 2 * p;
          اكسر;
        }
      }
      طالما (i + p <= n - q) {
        لكل (j = i;j < i + p;++j) {
          int32 a = x[j + p];
          لكل (r = q;r > p;r >>= 1)
            int32_MINMAX(a,x[j+r]);
          x[j + p] = a;
        }
        i += 2 * p;
      }
      /* now i + p > n - q */
      j = i;
      طالما (j < n - q) {
        int32 a = x[j + p];
        لكل (r = q;r > p;r >>= 1)
          int32_MINMAX(a,x[j+r]);
        x[j + p] = a;
        ++j;
      }

      پورا: ;
    }
  }
}

/* from supercop-20240808/crypto_sort/uint32/useint32/sort.c */

/* can save time by vectorizing xor loops */
/* can save time by integrating xor loops with int32_sort */

ساكن فراغ crypto_ترتیب_دیو_uint32(فراغ *array,لما لما n)
{
  crypto_uint32 *x = array;
  لما لما j;
  لكل (j = 0;j < n;++j) x[j] ^= 0x80000000;
  crypto_ترتیب_دیو_int32(array,n);
  لكل (j = 0;j < n;++j) x[j] ^= 0x80000000;
}

/* from supercop-20240808/crypto_kem/sntrup761/compact/kem.c */
// 20240806 djb: some automated conversion to cryptoint

#تعریف_کرو p 761
#تعریف_کرو q 4591
#تعریف_کرو w 286
#تعریف_کرو q12 ((q - 1) / 2)
تعريفنوع int8_t small;
تعريفنوع int16_t Fq;
#تعریف_کرو Hash_بائٹاں 32
#تعریف_کرو Small_بائٹاں ((p + 3) / 4)
تعريفنوع small Inputs[p];
#تعریف_کرو Secret_کلیدیں_بائٹاں (2 * Small_بائٹاں)
#تعریف_کرو Confirm_بائٹاں 32

ساكن small F3_freeze(int16_t x) { أرجع x - 3 * ((10923 * x + 16384) >> 15); }

ساكن Fq Fq_freeze(int32_t x) {
  ثابت int32_t q16 = (0x10000 + q / 2) / q;
  ثابت int32_t q20 = (0x100000 + q / 2) / q;
  ثابت int32_t q28 = (0x10000000 + q / 2) / q;
  x -= q * ((q16 * x) >> 16);
  x -= q * ((q20 * x) >> 20);
  أرجع x - q * ((q28 * x + 0x8000000) >> 28);
}

ساكن صحيح Weightw_نقاب(small *r) {
  صحيح i, بھار = 0;
  لكل (i = 0; i < p; ++i) بھار += crypto_int64_bottombit_01(r[i]);
  أرجع crypto_int16_nonzero_نقاب(بھار - w);
}

ساكن فراغ uint32_divmod_uint14(uint32_t *Q, uint16_t *r, uint32_t x, uint16_t m) {
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

ساكن uint16_t uint32_mod_uint14(uint32_t x, uint16_t m) {
  uint32_t Q;
  uint16_t r;
  uint32_divmod_uint14(&Q, &r, x, m);
  أرجع r;
}

ساكن فراغ Encode(بنانشانی حرف *باہرلا, ثابت uint16_t *R, ثابت uint16_t *M, لما لما len) {
  إذا (len == 1) {
    uint16_t r = R[0], m = M[0];
    طالما (m > 1) {
      *باہرلا++ = r;
      r >>= 8;
      m = (m + 255) >> 8;
    }
  }
  إذا (len > 1) {
    uint16_t R2[(len + 1) / 2], M2[(len + 1) / 2];
    لما لما i;
    لكل (i = 0; i < len - 1; i += 2) {
      uint32_t m0 = M[i];
      uint32_t r = R[i] + R[i + 1] * m0;
      uint32_t m = M[i + 1] * m0;
      طالما (m >= 16384) {
        *باہرلا++ = r;
        r >>= 8;
        m = (m + 255) >> 8;
      }
      R2[i / 2] = r;
      M2[i / 2] = m;
    }
    إذا (i < len) {
      R2[i / 2] = R[i];
      M2[i / 2] = M[i];
    }
    Encode(باہرلا, R2, M2, (len + 1) / 2);
  }
}

ساكن فراغ Decode(uint16_t *باہرلا, ثابت بنانشانی حرف *S, ثابت uint16_t *M, لما لما len) {
  إذا (len == 1) {
    إذا (M[0] == 1)
      *باہرلا = 0;
    وإلا إذا (M[0] <= 256)
      *باہرلا = uint32_mod_uint14(S[0], M[0]);
    وإلا
      *باہرلا = uint32_mod_uint14(S[0] + (((uint16_t)S[1]) << 8), M[0]);
  }
  إذا (len > 1) {
    uint16_t R2[(len + 1) / 2], M2[(len + 1) / 2], bottomr[len / 2];
    uint32_t bottomt[len / 2];
    لما لما i;
    لكل (i = 0; i < len - 1; i += 2) {
      uint32_t m = M[i] * (uint32_t)M[i + 1];
      إذا (m > 256 * 16383) {
        bottomt[i / 2] = 256 * 256;
        bottomr[i / 2] = S[0] + 256 * S[1];
        S += 2;
        M2[i / 2] = (((m + 255) >> 8) + 255) >> 8;
      } وإلا إذا (m >= 16384) {
        bottomt[i / 2] = 256;
        bottomr[i / 2] = S[0];
        S += 1;
        M2[i / 2] = (m + 255) >> 8;
      } وإلا {
        bottomt[i / 2] = 1;
        bottomr[i / 2] = 0;
        M2[i / 2] = m;
      }
    }
    إذا (i < len) M2[i / 2] = M[i];
    Decode(R2, S, M2, (len + 1) / 2);
    لكل (i = 0; i < len - 1; i += 2) {
      uint32_t r1, r = bottomr[i / 2];
      uint16_t r0;
      r += bottomt[i / 2] * R2[i / 2];
      uint32_divmod_uint14(&r1, &r0, r, M[i]);
      r1 = uint32_mod_uint14(r1, M[i + 1]);
      *باہرلا++ = r0;
      *باہرلا++ = r1;
    }
    إذا (i < len) *باہرلا++ = R2[i / 2];
  }
}

ساكن فراغ R3_fromRq(small *باہرلا, ثابت Fq *r) {
  صحيح i;
  لكل (i = 0; i < p; ++i) باہرلا[i] = F3_freeze(r[i]);
}

ساكن فراغ R3_mult(small *h, ثابت small *f, ثابت small *g) {
  int16_t fg[p + p - 1];
  صحيح i, j;
  لكل (i = 0; i < p + p - 1; ++i) fg[i] = 0;
  لكل (i = 0; i < p; ++i)
    لكل (j = 0; j < p; ++j) fg[i + j] += f[i] * (int16_t)g[j];
  لكل (i = p; i < p + p - 1; ++i) fg[i - p] += fg[i];
  لكل (i = p; i < p + p - 1; ++i) fg[i - p + 1] += fg[i];
  لكل (i = 0; i < p; ++i) h[i] = F3_freeze(fg[i]);
}

ساكن صحيح R3_recip(small *باہرلا, ثابت small *وچ) {
  small f[p + 1], g[p + 1], v[p + 1], r[p + 1];
  صحيح sign, وٹاندرا, t, i, loop, delta = 1;
  لكل (i = 0; i < p + 1; ++i) v[i] = 0;
  لكل (i = 0; i < p + 1; ++i) r[i] = 0;
  r[0] = 1;
  لكل (i = 0; i < p; ++i) f[i] = 0;
  f[0] = 1;
  f[p - 1] = f[p] = -1;
  لكل (i = 0; i < p; ++i) g[p - 1 - i] = وچ[i];
  g[p] = 0;
  لكل (loop = 0; loop < 2 * p - 1; ++loop) {
    لكل (i = p; i > 0; --i) v[i] = v[i - 1];
    v[0] = 0;
    sign = -g[0] * f[0];
    وٹاندرا = crypto_int16_negative_نقاب(-delta) & crypto_int16_nonzero_نقاب(g[0]);
    delta ^= وٹاندرا & (delta ^ -delta);
    delta += 1;
    لكل (i = 0; i < p + 1; ++i) {
      t = وٹاندرا & (f[i] ^ g[i]);
      f[i] ^= t;
      g[i] ^= t;
      t = وٹاندرا & (v[i] ^ r[i]);
      v[i] ^= t;
      r[i] ^= t;
    }
    لكل (i = 0; i < p + 1; ++i) g[i] = F3_freeze(g[i] + sign * f[i]);
    لكل (i = 0; i < p + 1; ++i) r[i] = F3_freeze(r[i] + sign * v[i]);
    لكل (i = 0; i < p; ++i) g[i] = g[i + 1];
    g[p] = 0;
  }
  sign = f[0];
  لكل (i = 0; i < p; ++i) باہرلا[i] = sign * v[p - 1 - i];
  أرجع crypto_int16_nonzero_نقاب(delta);
}

ساكن فراغ Rq_mult_small(Fq *h, ثابت Fq *f, ثابت small *g) {
  int32_t fg[p + p - 1];
  صحيح i, j;
  لكل (i = 0; i < p + p - 1; ++i) fg[i] = 0;
  لكل (i = 0; i < p; ++i)
    لكل (j = 0; j < p; ++j) fg[i + j] += f[i] * (int32_t)g[j];
  لكل (i = p; i < p + p - 1; ++i) fg[i - p] += fg[i];
  لكل (i = p; i < p + p - 1; ++i) fg[i - p + 1] += fg[i];
  لكل (i = 0; i < p; ++i) h[i] = Fq_freeze(fg[i]);
}

ساكن فراغ Rq_mult3(Fq *h, ثابت Fq *f) {
  صحيح i;
  لكل (i = 0; i < p; ++i) h[i] = Fq_freeze(3 * f[i]);
}

ساكن Fq Fq_recip(Fq a1) {
  صحيح i = 1;
  Fq ai = a1;
  طالما (i < q - 2) {
    ai = Fq_freeze(a1 * (int32_t)ai);
    i += 1;
  }
  أرجع ai;
}

ساكن صحيح Rq_recip3(Fq *باہرلا, ثابت small *وچ) {
  Fq f[p + 1], g[p + 1], v[p + 1], r[p + 1], scale;
  صحيح وٹاندرا, t, i, loop, delta = 1;
  int32_t f0, g0;
  لكل (i = 0; i < p + 1; ++i) v[i] = 0;
  لكل (i = 0; i < p + 1; ++i) r[i] = 0;
  r[0] = Fq_recip(3);
  لكل (i = 0; i < p; ++i) f[i] = 0;
  f[0] = 1;
  f[p - 1] = f[p] = -1;
  لكل (i = 0; i < p; ++i) g[p - 1 - i] = وچ[i];
  g[p] = 0;
  لكل (loop = 0; loop < 2 * p - 1; ++loop) {
    لكل (i = p; i > 0; --i) v[i] = v[i - 1];
    v[0] = 0;
    وٹاندرا = crypto_int16_negative_نقاب(-delta) & crypto_int16_nonzero_نقاب(g[0]);
    delta ^= وٹاندرا & (delta ^ -delta);
    delta += 1;
    لكل (i = 0; i < p + 1; ++i) {
      t = وٹاندرا & (f[i] ^ g[i]);
      f[i] ^= t;
      g[i] ^= t;
      t = وٹاندرا & (v[i] ^ r[i]);
      v[i] ^= t;
      r[i] ^= t;
    }
    f0 = f[0];
    g0 = g[0];
    لكل (i = 0; i < p + 1; ++i) g[i] = Fq_freeze(f0 * g[i] - g0 * f[i]);
    لكل (i = 0; i < p + 1; ++i) r[i] = Fq_freeze(f0 * r[i] - g0 * v[i]);
    لكل (i = 0; i < p; ++i) g[i] = g[i + 1];
    g[p] = 0;
  }
  scale = Fq_recip(f[0]);
  لكل (i = 0; i < p; ++i) باہرلا[i] = Fq_freeze(scale * (int32_t)v[p - 1 - i]);
  أرجع crypto_int16_nonzero_نقاب(delta);
}

ساكن فراغ گیڑا_3(Fq *باہرلا, ثابت Fq *a) {
  صحيح i;
  لكل (i = 0; i < p; ++i) باہرلا[i] = a[i] - F3_freeze(a[i]);
}

ساكن فراغ Short_fromlist(small *باہرلا, ثابت uint32_t *وچ) {
  uint32_t L[p];
  صحيح i;
  لكل (i = 0; i < w; ++i) L[i] = وچ[i] & (uint32_t)-2;
  لكل (i = w; i < p; ++i) L[i] = (وچ[i] & (uint32_t)-3) | 1;
  crypto_ترتیب_دیو_uint32(L, p);
  لكل (i = 0; i < p; ++i) باہرلا[i] = (L[i] & 3) - 1;
}

ساكن فراغ Hash_اگیتر(بنانشانی حرف *باہرلا, صحيح b, ثابت بنانشانی حرف *وچ, صحيح inlen) {
  بنانشانی حرف x[inlen + 1], h[64];
  صحيح i;
  x[0] = b;
  لكل (i = 0; i < inlen; ++i) x[i + 1] = وچ[i];
  crypto_hash_sha512(h, x, inlen + 1);
  لكل (i = 0; i < 32; ++i) باہرلا[i] = h[i];
}


ساكن فراغ Short_random(small *باہرلا) {
  uint32_t L[p];
  randombytes(L, حجم(L));
  Short_fromlist(باہرلا, L);
  explicit_bzero(L, حجم(L));
}
ساكن فراغ Small_random(small *باہرلا) {
  صحيح i;
  uint32_t L[p];
  randombytes(L, حجم(L));
  لكل (i = 0; i < p; ++i) باہرلا[i] = (((L[i] & 0x3fffffff) * 3) >> 30) - 1;
  explicit_bzero(L, حجم(L));
}
ساكن فراغ کلید_Gen(Fq *h, small *f, small *ginv) {
  small g[p];
  Fq finv[p];
  لكل (;;) {
    صحيح نتیجہ;
    Small_random(g);
    نتیجہ = R3_recip(ginv, g);
    crypto_declassify(&نتیجہ, حجم نتیجہ);
    إذا (نتیجہ == 0) اكسر;
  }
  Short_random(f);
  Rq_recip3(finv, f);
  Rq_mult_small(h, finv, g);
}

ساكن فراغ Encrypt(Fq *c, ثابت small *r, ثابت Fq *h) {
  Fq hr[p];
  Rq_mult_small(hr, h, r);
  گیڑا_3(c, hr);
}

ساكن فراغ Decrypt(small *r, ثابت Fq *c, ثابت small *f, ثابت small *ginv) {
  Fq cf[p], cf3[p];
  small e[p], ev[p];
  صحيح نقاب, i;
  Rq_mult_small(cf, c, f);
  Rq_mult3(cf3, cf);
  R3_fromRq(e, cf3);
  R3_mult(ev, e, ginv);
  نقاب = Weightw_نقاب(ev);
  لكل (i = 0; i < w; ++i) r[i] = ((ev[i] ^ 1) & ~نقاب) ^ 1;
  لكل (i = w; i < p; ++i) r[i] = ev[i] & ~نقاب;
}

ساكن فراغ Small_encode(بنانشانی حرف *s, ثابت small *f) {
  صحيح i, j;
  لكل (i = 0; i < p / 4; ++i) {
    small x = 0;
    لكل (j = 0;j < 4;++j) x += (*f++ + 1) << (2 * j);
    *s++ = x;
  }
  *s = *f++ + 1;
}

ساكن فراغ Small_decode(small *f, ثابت بنانشانی حرف *s) {
  صحيح i, j;
  لكل (i = 0; i < p / 4; ++i) {
    بنانشانی حرف x = *s++;
    لكل (j = 0;j < 4;++j) *f++ = ((small)((x >> (2 * j)) & 3)) - 1;
  }
  *f++ = ((small)(*s & 3)) - 1;
}

ساكن فراغ Rq_encode(بنانشانی حرف *s, ثابت Fq *r) {
  uint16_t R[p], M[p];
  صحيح i;
  لكل (i = 0; i < p; ++i) R[i] = r[i] + q12;
  لكل (i = 0; i < p; ++i) M[i] = q;
  Encode(s, R, M, p);
}

ساكن فراغ Rq_decode(Fq *r, ثابت بنانشانی حرف *s) {
  uint16_t R[p], M[p];
  صحيح i;
  لكل (i = 0; i < p; ++i) M[i] = q;
  Decode(R, s, M, p);
  لكل (i = 0; i < p; ++i) r[i] = ((Fq)R[i]) - q12;
}

ساكن فراغ Rounded_encode(بنانشانی حرف *s, ثابت Fq *r) {
  uint16_t R[p], M[p];
  صحيح i;
  لكل (i = 0; i < p; ++i) R[i] = ((r[i] + q12) * 10923) >> 15;
  لكل (i = 0; i < p; ++i) M[i] = (q + 2) / 3;
  Encode(s, R, M, p);
}

ساكن فراغ Rounded_decode(Fq *r, ثابت بنانشانی حرف *s) {
  uint16_t R[p], M[p];
  صحيح i;
  لكل (i = 0; i < p; ++i) M[i] = (q + 2) / 3;
  Decode(R, s, M, p);
  لكل (i = 0; i < p; ++i) r[i] = R[i] * 3 - q12;
}

ساكن فراغ ZKeyGen(بنانشانی حرف *pk, بنانشانی حرف *sk) {
  Fq h[p];
  small f[p], v[p];
  کلید_Gen(h, f, v);
  Rq_encode(pk, h);
  Small_encode(sk, f);
  Small_encode(sk + Small_بائٹاں, v);
}

ساكن فراغ ZEncrypt(بنانشانی حرف *C, ثابت Inputs r, ثابت بنانشانی حرف *pk) {
  Fq h[p], c[p];
  Rq_decode(h, pk);
  Encrypt(c, r, h);
  Rounded_encode(C, c);
}

ساكن فراغ ZDecrypt(Inputs r, ثابت بنانشانی حرف *C, ثابت بنانشانی حرف *sk) {
  small f[p], v[p];
  Fq c[p];
  Small_decode(f, sk);
  Small_decode(v, sk + Small_بائٹاں);
  Rounded_decode(c, C);
  Decrypt(r, c, f, v);
}

ساكن فراغ HashConfirm(بنانشانی حرف *h, ثابت بنانشانی حرف *r, ثابت بنانشانی حرف *cache) {
  بنانشانی حرف x[Hash_بائٹاں * 2];
  صحيح i;
  Hash_اگیتر(x, 3, r, Small_بائٹاں);
  لكل (i = 0; i < Hash_بائٹاں; ++i) x[Hash_بائٹاں + i] = cache[i];
  Hash_اگیتر(h, 2, x, حجم x);
}

ساكن فراغ HashSession(بنانشانی حرف *k, صحيح b, ثابت بنانشانی حرف *y, ثابت بنانشانی حرف *z) {
  بنانشانی حرف x[Hash_بائٹاں + crypto_kem_sntrup761_CIPHERTEXTBYTES];
  صحيح i;
  Hash_اگیتر(x, 3, y, Small_بائٹاں);
  لكل (i = 0; i < crypto_kem_sntrup761_CIPHERTEXTBYTES; ++i) x[Hash_بائٹاں + i] = z[i];
  Hash_اگیتر(k, b, x, حجم x);
}

صحيح crypto_kem_sntrup761_keypair(بنانشانی حرف *pk, بنانشانی حرف *sk) {
  صحيح i;
  ZKeyGen(pk, sk);
  sk += Secret_کلیدیں_بائٹاں;
  لكل (i = 0; i < crypto_kem_sntrup761_PUBLICKEYBYTES; ++i) *sk++ = pk[i];
  randombytes(sk, Small_بائٹاں);
  Hash_اگیتر(sk + Small_بائٹاں, 4, pk, crypto_kem_sntrup761_PUBLICKEYBYTES);
  أرجع 0;
}

ساكن فراغ Hide(بنانشانی حرف *c, بنانشانی حرف *r_enc, ثابت Inputs r, ثابت بنانشانی حرف *pk, ثابت بنانشانی حرف *cache) {
  Small_encode(r_enc, r);
  ZEncrypt(c, r, pk);
  HashConfirm(c + crypto_kem_sntrup761_CIPHERTEXTBYTES - Confirm_بائٹاں, r_enc, cache);
}

صحيح crypto_kem_sntrup761_enc(بنانشانی حرف *c, بنانشانی حرف *k, ثابت بنانشانی حرف *pk) {
  Inputs r;
  بنانشانی حرف r_enc[Small_بائٹاں], cache[Hash_بائٹاں];
  Hash_اگیتر(cache, 4, pk, crypto_kem_sntrup761_PUBLICKEYBYTES);
  Short_random(r);
  Hide(c, r_enc, r, pk, cache);
  HashSession(k, 1, r_enc, c);
  أرجع 0;
}

ساكن صحيح Ciphertexts_diff_نقاب(ثابت بنانشانی حرف *c, ثابت بنانشانی حرف *c2) {
  uint16_t differentbits = 0;
  صحيح len = crypto_kem_sntrup761_CIPHERTEXTBYTES;
  طالما (len-- > 0) differentbits |= (*c++) ^ (*c2++);
  أرجع (crypto_int64_bitmod_01((differentbits - 1),8)) - 1;
}

صحيح crypto_kem_sntrup761_dec(بنانشانی حرف *k, ثابت بنانشانی حرف *c, ثابت بنانشانی حرف *sk) {
  ثابت بنانشانی حرف *pk = sk + Secret_کلیدیں_بائٹاں;
  ثابت بنانشانی حرف *rho = pk + crypto_kem_sntrup761_PUBLICKEYBYTES;
  ثابت بنانشانی حرف *cache = rho + Small_بائٹاں;
  Inputs r;
  بنانشانی حرف r_enc[Small_بائٹاں], cnew[crypto_kem_sntrup761_CIPHERTEXTBYTES];
  صحيح نقاب, i;
  ZDecrypt(r, c, sk);
  Hide(cnew, r_enc, r, pk, cache);
  نقاب = Ciphertexts_diff_نقاب(c, cnew);
  لكل (i = 0; i < Small_بائٹاں; ++i) r_enc[i] ^= نقاب & (r_enc[i] ^ rho[i]);
  HashSession(k, 1 + نقاب, r_enc, c);
  أرجع 0;
}

#جے_انت /* USE_SNTRUP761X25519 */
