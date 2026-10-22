/*  $OpenBSD: sntrup761.c,v 1.9 2026/01/20 22:56:11 dtucker Exp $ */

/*
 * Public Domain, Authors:
 * - Daniel J. Bernstein
 * - Chitchanok Chuengsatiansup
 * - Tanja Lange
 * - Christine van Vredendaal
 */

#ضمن "includes.h"

#ifdef USE_SNTRUP761X25519

#ضمن <string.h>
#ضمن "crypto_api.h"

#define crypto_declassify(x, y) עשה {} כלעוד (0)

#define int8 crypto_int8
#define uint8 crypto_uint8
#define int16 crypto_int16
#define uint16 crypto_uint16
#define int32 crypto_int32
#define uint32 crypto_uint32
#define int64 crypto_int64
#define uint64 crypto_uint64
خارجي متطاير crypto_int16 crypto_int16_optblocker;
خارجي متطاير crypto_int32 crypto_int32_optblocker;
خارجي متطاير crypto_int64 crypto_int64_optblocker;

/* from supercop-20240808/cryptoint/crypto_int16.h */
/* auto-generated: cd cryptoint; ./autogen */
/* cryptoint 20240806 */

#ifndef crypto_int16_h
#define crypto_int16_h

#define crypto_int16 int16_t
#define crypto_int16_unsigned uint16_t



__attribute__((unused))
ساكن مضمن
crypto_int16 crypto_int16_load(ثابت unsigned حرف *crypto_int16_s) {
  crypto_int16 crypto_int16_z = 0;
  crypto_int16_z |= ((crypto_int16) (*crypto_int16_s++)) << 0;
  crypto_int16_z |= ((crypto_int16) (*crypto_int16_s++)) << 8;
  החזר crypto_int16_z;
}

__attribute__((unused))
ساكن مضمن
فراغ crypto_int16_store(unsigned حرف *crypto_int16_s,crypto_int16 crypto_int16_x) {
  *crypto_int16_s++ = crypto_int16_x >> 0;
  *crypto_int16_s++ = crypto_int16_x >> 8;
}

__attribute__((unused))
ساكن مضمن
crypto_int16 crypto_int16_negative_mask(crypto_int16 crypto_int16_x) {
#אם defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarw $15,%0" : "+r"(crypto_int16_x) : : "cc");
  החזר crypto_int16_x;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_y;
  __asm__ ("sbfx %w0,%w1,15,1" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) : );
  החזר crypto_int16_y;
#אחרת
  crypto_int16_x >>= 16-6;
  crypto_int16_x ^= crypto_int16_optblocker;
  crypto_int16_x >>= 5;
  החזר crypto_int16_x;
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int16_unsigned crypto_int16_unsigned_topbit_01(crypto_int16_unsigned crypto_int16_x) {
#אם defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("shrw $15,%0" : "+r"(crypto_int16_x) : : "cc");
  החזר crypto_int16_x;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_y;
  __asm__ ("ubfx %w0,%w1,15,1" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) : );
  החזר crypto_int16_y;
#אחרת
  crypto_int16_x >>= 16-6;
  crypto_int16_x ^= crypto_int16_optblocker;
  crypto_int16_x >>= 5;
  החזר crypto_int16_x;
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int16 crypto_int16_negative_01(crypto_int16 crypto_int16_x) {
  החזר crypto_int16_unsigned_topbit_01(crypto_int16_x);
}

__attribute__((unused))
ساكن مضمن
crypto_int16 crypto_int16_topbit_mask(crypto_int16 crypto_int16_x) {
  החזר crypto_int16_negative_mask(crypto_int16_x);
}

__attribute__((unused))
ساكن مضمن
crypto_int16 crypto_int16_topbit_01(crypto_int16 crypto_int16_x) {
  החזר crypto_int16_unsigned_topbit_01(crypto_int16_x);
}

__attribute__((unused))
ساكن مضمن
crypto_int16 crypto_int16_bottombit_mask(crypto_int16 crypto_int16_x) {
#אם defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andw $1,%0" : "+r"(crypto_int16_x) : : "cc");
  החזר -crypto_int16_x;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_y;
  __asm__ ("sbfx %w0,%w1,0,1" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) : );
  החזר crypto_int16_y;
#אחרת
  crypto_int16_x &= 1 ^ crypto_int16_optblocker;
  החזר -crypto_int16_x;
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int16 crypto_int16_bottombit_01(crypto_int16 crypto_int16_x) {
#אם defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andw $1,%0" : "+r"(crypto_int16_x) : : "cc");
  החזר crypto_int16_x;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_y;
  __asm__ ("ubfx %w0,%w1,0,1" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) : );
  החזר crypto_int16_y;
#אחרת
  crypto_int16_x &= 1 ^ crypto_int16_optblocker;
  החזר crypto_int16_x;
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int16 crypto_int16_bitinrangepublicpos_mask(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
#אם defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarw %%cl,%0" : "+r"(crypto_int16_x) : "c"(crypto_int16_s) : "cc");
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("sxth %w0,%w0\n asr %w0,%w0,%w1" : "+&r"(crypto_int16_x) : "r"(crypto_int16_s) : );
#אחרת
  crypto_int16_x >>= crypto_int16_s ^ crypto_int16_optblocker;
#endif
  החזר crypto_int16_bottombit_mask(crypto_int16_x);
}

__attribute__((unused))
ساكن مضمن
crypto_int16 crypto_int16_bitinrangepublicpos_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
#אם defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarw %%cl,%0" : "+r"(crypto_int16_x) : "c"(crypto_int16_s) : "cc");
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("sxth %w0,%w0\n asr %w0,%w0,%w1" : "+&r"(crypto_int16_x) : "r"(crypto_int16_s) : );
#אחרת
  crypto_int16_x >>= crypto_int16_s ^ crypto_int16_optblocker;
#endif
  החזר crypto_int16_bottombit_01(crypto_int16_x);
}

__attribute__((unused))
ساكن مضمن
crypto_int16 crypto_int16_shlmod(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
#אם defined(__GNUC__) && defined(__x86_64__)
  crypto_int16_s &= 15;
  __asm__ ("shlw %%cl,%0" : "+r"(crypto_int16_x) : "c"(crypto_int16_s) : "cc");
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("and %w0,%w0,15\n and %w1,%w1,65535\n lsl %w1,%w1,%w0" : "+&r"(crypto_int16_s), "+r"(crypto_int16_x) : : );
#אחרת
  صحيح crypto_int16_k, crypto_int16_l;
  עבור (crypto_int16_l = 0,crypto_int16_k = 1;crypto_int16_k < 16;++crypto_int16_l,crypto_int16_k *= 2)
    crypto_int16_x ^= (crypto_int16_x ^ (crypto_int16_x << crypto_int16_k)) & crypto_int16_bitinrangepublicpos_mask(crypto_int16_s,crypto_int16_l);
#endif
  החזר crypto_int16_x;
}

__attribute__((unused))
ساكن مضمن
crypto_int16 crypto_int16_shrmod(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
#אם defined(__GNUC__) && defined(__x86_64__)
  crypto_int16_s &= 15;
  __asm__ ("sarw %%cl,%0" : "+r"(crypto_int16_x) : "c"(crypto_int16_s) : "cc");
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("and %w0,%w0,15\n sxth %w1,%w1\n asr %w1,%w1,%w0" : "+&r"(crypto_int16_s), "+r"(crypto_int16_x) : : );
#אחרת
  صحيح crypto_int16_k, crypto_int16_l;
  עבור (crypto_int16_l = 0,crypto_int16_k = 1;crypto_int16_k < 16;++crypto_int16_l,crypto_int16_k *= 2)
    crypto_int16_x ^= (crypto_int16_x ^ (crypto_int16_x >> crypto_int16_k)) & crypto_int16_bitinrangepublicpos_mask(crypto_int16_s,crypto_int16_l);
#endif
  החזר crypto_int16_x;
}

__attribute__((unused))
ساكن مضمن
crypto_int16 crypto_int16_bitmod_mask(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
  crypto_int16_x = crypto_int16_shrmod(crypto_int16_x,crypto_int16_s);
  החזר crypto_int16_bottombit_mask(crypto_int16_x);
}

__attribute__((unused))
ساكن مضمن
crypto_int16 crypto_int16_bitmod_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
  crypto_int16_x = crypto_int16_shrmod(crypto_int16_x,crypto_int16_s);
  החזר crypto_int16_bottombit_01(crypto_int16_x);
}

__attribute__((unused))
ساكن مضمن
crypto_int16 crypto_int16_nonzero_mask(crypto_int16 crypto_int16_x) {
#אם defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n testw %2,%2\n cmovnew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  החזר crypto_int16_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("tst %w1,65535\n csetm %w0,ne" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  החזר crypto_int16_z;
#אחרת
  crypto_int16_x |= -crypto_int16_x;
  החזר crypto_int16_negative_mask(crypto_int16_x);
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int16 crypto_int16_nonzero_01(crypto_int16 crypto_int16_x) {
#אם defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n testw %2,%2\n cmovnew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  החזר crypto_int16_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("tst %w1,65535\n cset %w0,ne" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  החזר crypto_int16_z;
#אחרת
  crypto_int16_x |= -crypto_int16_x;
  החזר crypto_int16_unsigned_topbit_01(crypto_int16_x);
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int16 crypto_int16_positive_mask(crypto_int16 crypto_int16_x) {
#אם defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n testw %2,%2\n cmovgw %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  החזר crypto_int16_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,0\n csetm %w0,gt" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  החזר crypto_int16_z;
#אחרת
  crypto_int16 crypto_int16_z = -crypto_int16_x;
  crypto_int16_z ^= crypto_int16_x & crypto_int16_z;
  החזר crypto_int16_negative_mask(crypto_int16_z);
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int16 crypto_int16_positive_01(crypto_int16 crypto_int16_x) {
#אם defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n testw %2,%2\n cmovgw %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  החזר crypto_int16_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,0\n cset %w0,gt" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  החזר crypto_int16_z;
#אחרת
  crypto_int16 crypto_int16_z = -crypto_int16_x;
  crypto_int16_z ^= crypto_int16_x & crypto_int16_z;
  החזר crypto_int16_unsigned_topbit_01(crypto_int16_z);
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int16 crypto_int16_zero_mask(crypto_int16 crypto_int16_x) {
#אם defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n testw %2,%2\n cmovew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  החזר crypto_int16_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("tst %w1,65535\n csetm %w0,eq" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  החזר crypto_int16_z;
#אחרת
  החזר ~crypto_int16_nonzero_mask(crypto_int16_x);
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int16 crypto_int16_zero_01(crypto_int16 crypto_int16_x) {
#אם defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n testw %2,%2\n cmovew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  החזר crypto_int16_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("tst %w1,65535\n cset %w0,eq" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  החזר crypto_int16_z;
#אחרת
  החזר 1-crypto_int16_nonzero_01(crypto_int16_x);
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int16 crypto_int16_unequal_mask(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#אם defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n cmpw %3,%2\n cmovnew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  החזר crypto_int16_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("and %w0,%w1,65535\n cmp %w0,%w2,uxth\n csetm %w0,ne" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  החזר crypto_int16_z;
#אחרת
  החזר crypto_int16_nonzero_mask(crypto_int16_x ^ crypto_int16_y);
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int16 crypto_int16_unequal_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#אם defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n cmpw %3,%2\n cmovnew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  החזר crypto_int16_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("and %w0,%w1,65535\n cmp %w0,%w2,uxth\n cset %w0,ne" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  החזר crypto_int16_z;
#אחרת
  החזר crypto_int16_nonzero_01(crypto_int16_x ^ crypto_int16_y);
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int16 crypto_int16_equal_mask(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#אם defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n cmpw %3,%2\n cmovew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  החזר crypto_int16_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("and %w0,%w1,65535\n cmp %w0,%w2,uxth\n csetm %w0,eq" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  החזר crypto_int16_z;
#אחרת
  החזר ~crypto_int16_unequal_mask(crypto_int16_x,crypto_int16_y);
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int16 crypto_int16_equal_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#אם defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n cmpw %3,%2\n cmovew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  החזר crypto_int16_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("and %w0,%w1,65535\n cmp %w0,%w2,uxth\n cset %w0,eq" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  החזר crypto_int16_z;
#אחרת
  החזר 1-crypto_int16_unequal_01(crypto_int16_x,crypto_int16_y);
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int16 crypto_int16_min(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#אם defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpw %1,%0\n cmovgw %1,%0" : "+r"(crypto_int16_x) : "r"(crypto_int16_y) : "cc");
  החזר crypto_int16_x;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("sxth %w0,%w0\n cmp %w0,%w1,sxth\n csel %w0,%w0,%w1,lt" : "+&r"(crypto_int16_x) : "r"(crypto_int16_y) : "cc");
  החזר crypto_int16_x;
#אחרת
  crypto_int16 crypto_int16_r = crypto_int16_y ^ crypto_int16_x;
  crypto_int16 crypto_int16_z = crypto_int16_y - crypto_int16_x;
  crypto_int16_z ^= crypto_int16_r & (crypto_int16_z ^ crypto_int16_y);
  crypto_int16_z = crypto_int16_negative_mask(crypto_int16_z);
  crypto_int16_z &= crypto_int16_r;
  החזר crypto_int16_x ^ crypto_int16_z;
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int16 crypto_int16_max(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#אם defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpw %1,%0\n cmovlw %1,%0" : "+r"(crypto_int16_x) : "r"(crypto_int16_y) : "cc");
  החזר crypto_int16_x;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("sxth %w0,%w0\n cmp %w0,%w1,sxth\n csel %w0,%w1,%w0,lt" : "+&r"(crypto_int16_x) : "r"(crypto_int16_y) : "cc");
  החזר crypto_int16_x;
#אחרת
  crypto_int16 crypto_int16_r = crypto_int16_y ^ crypto_int16_x;
  crypto_int16 crypto_int16_z = crypto_int16_y - crypto_int16_x;
  crypto_int16_z ^= crypto_int16_r & (crypto_int16_z ^ crypto_int16_y);
  crypto_int16_z = crypto_int16_negative_mask(crypto_int16_z);
  crypto_int16_z &= crypto_int16_r;
  החזר crypto_int16_y ^ crypto_int16_z;
#endif
}

__attribute__((unused))
ساكن مضمن
فراغ crypto_int16_minmax(crypto_int16 *crypto_int16_p,crypto_int16 *crypto_int16_q) {
  crypto_int16 crypto_int16_x = *crypto_int16_p;
  crypto_int16 crypto_int16_y = *crypto_int16_q;
#אם defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("cmpw %2,%1\n movw %1,%0\n cmovgw %2,%1\n cmovgw %0,%2" : "=&r"(crypto_int16_z), "+&r"(crypto_int16_x), "+r"(crypto_int16_y) : : "cc");
  *crypto_int16_p = crypto_int16_x;
  *crypto_int16_q = crypto_int16_y;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_r, crypto_int16_s;
  __asm__ ("sxth %w0,%w0\n cmp %w0,%w3,sxth\n csel %w1,%w0,%w3,lt\n csel %w2,%w3,%w0,lt" : "+&r"(crypto_int16_x), "=&r"(crypto_int16_r), "=r"(crypto_int16_s) : "r"(crypto_int16_y) : "cc");
  *crypto_int16_p = crypto_int16_r;
  *crypto_int16_q = crypto_int16_s;
#אחרת
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
ساكن مضمن
crypto_int16 crypto_int16_smaller_mask(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#אם defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n cmpw %3,%2\n cmovlw %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  החזר crypto_int16_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,%w2,sxth\n csetm %w0,lt" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  החזר crypto_int16_z;
#אחרת
  crypto_int16 crypto_int16_r = crypto_int16_x ^ crypto_int16_y;
  crypto_int16 crypto_int16_z = crypto_int16_x - crypto_int16_y;
  crypto_int16_z ^= crypto_int16_r & (crypto_int16_z ^ crypto_int16_x);
  החזר crypto_int16_negative_mask(crypto_int16_z);
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int16 crypto_int16_smaller_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#אם defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n cmpw %3,%2\n cmovlw %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  החזר crypto_int16_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,%w2,sxth\n cset %w0,lt" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  החזר crypto_int16_z;
#אחרת
  crypto_int16 crypto_int16_r = crypto_int16_x ^ crypto_int16_y;
  crypto_int16 crypto_int16_z = crypto_int16_x - crypto_int16_y;
  crypto_int16_z ^= crypto_int16_r & (crypto_int16_z ^ crypto_int16_x);
  החזר crypto_int16_unsigned_topbit_01(crypto_int16_z);
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int16 crypto_int16_leq_mask(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#אם defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n cmpw %3,%2\n cmovlew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  החזר crypto_int16_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,%w2,sxth\n csetm %w0,le" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  החזר crypto_int16_z;
#אחרת
  החזר ~crypto_int16_smaller_mask(crypto_int16_y,crypto_int16_x);
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int16 crypto_int16_leq_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#אם defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n cmpw %3,%2\n cmovlew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  החזר crypto_int16_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,%w2,sxth\n cset %w0,le" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  החזר crypto_int16_z;
#אחרת
  החזר 1-crypto_int16_smaller_01(crypto_int16_y,crypto_int16_x);
#endif
}

__attribute__((unused))
ساكن مضمن
صحيح crypto_int16_ones_num(crypto_int16 crypto_int16_x) {
  crypto_int16_unsigned crypto_int16_y = crypto_int16_x;
  ثابت crypto_int16 C0 = 0x5555;
  ثابت crypto_int16 C1 = 0x3333;
  ثابت crypto_int16 C2 = 0x0f0f;
  crypto_int16_y -= ((crypto_int16_y >> 1) & C0);
  crypto_int16_y = (crypto_int16_y & C1) + ((crypto_int16_y >> 2) & C1);
  crypto_int16_y = (crypto_int16_y + (crypto_int16_y >> 4)) & C2;
  crypto_int16_y = (crypto_int16_y + (crypto_int16_y >> 8)) & 0xff;
  החזר crypto_int16_y;
}

__attribute__((unused))
ساكن مضمن
صحيح crypto_int16_bottomzeros_num(crypto_int16 crypto_int16_x) {
#אם defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 fallback = 16;
  __asm__ ("bsfw %0,%0\n cmovew %1,%0" : "+&r"(crypto_int16_x) : "r"(fallback) : "cc");
  החזר crypto_int16_x;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  int64_t crypto_int16_y;
  __asm__ ("orr %w0,%w1,-65536\n rbit %w0,%w0\n clz %w0,%w0" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) : );
  החזר crypto_int16_y;
#אחרת
  crypto_int16 crypto_int16_y = crypto_int16_x ^ (crypto_int16_x-1);
  crypto_int16_y = ((crypto_int16) crypto_int16_y) >> 1;
  crypto_int16_y &= ~(crypto_int16_x & (((crypto_int16) 1) << (16-1)));
  החזר crypto_int16_ones_num(crypto_int16_y);
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
ساكن مضمن
crypto_int32 crypto_int32_load(ثابت unsigned حرف *crypto_int32_s) {
  crypto_int32 crypto_int32_z = 0;
  crypto_int32_z |= ((crypto_int32) (*crypto_int32_s++)) << 0;
  crypto_int32_z |= ((crypto_int32) (*crypto_int32_s++)) << 8;
  crypto_int32_z |= ((crypto_int32) (*crypto_int32_s++)) << 16;
  crypto_int32_z |= ((crypto_int32) (*crypto_int32_s++)) << 24;
  החזר crypto_int32_z;
}

__attribute__((unused))
ساكن مضمن
فراغ crypto_int32_store(unsigned حرف *crypto_int32_s,crypto_int32 crypto_int32_x) {
  *crypto_int32_s++ = crypto_int32_x >> 0;
  *crypto_int32_s++ = crypto_int32_x >> 8;
  *crypto_int32_s++ = crypto_int32_x >> 16;
  *crypto_int32_s++ = crypto_int32_x >> 24;
}

__attribute__((unused))
ساكن مضمن
crypto_int32 crypto_int32_negative_mask(crypto_int32 crypto_int32_x) {
#אם defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarl $31,%0" : "+r"(crypto_int32_x) : : "cc");
  החזר crypto_int32_x;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_y;
  __asm__ ("asr %w0,%w1,31" : "=r"(crypto_int32_y) : "r"(crypto_int32_x) : );
  החזר crypto_int32_y;
#אחרת
  crypto_int32_x >>= 32-6;
  crypto_int32_x ^= crypto_int32_optblocker;
  crypto_int32_x >>= 5;
  החזר crypto_int32_x;
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int32_unsigned crypto_int32_unsigned_topbit_01(crypto_int32_unsigned crypto_int32_x) {
#אם defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("shrl $31,%0" : "+r"(crypto_int32_x) : : "cc");
  החזר crypto_int32_x;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_y;
  __asm__ ("lsr %w0,%w1,31" : "=r"(crypto_int32_y) : "r"(crypto_int32_x) : );
  החזר crypto_int32_y;
#אחרת
  crypto_int32_x >>= 32-6;
  crypto_int32_x ^= crypto_int32_optblocker;
  crypto_int32_x >>= 5;
  החזר crypto_int32_x;
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int32 crypto_int32_negative_01(crypto_int32 crypto_int32_x) {
  החזר crypto_int32_unsigned_topbit_01(crypto_int32_x);
}

__attribute__((unused))
ساكن مضمن
crypto_int32 crypto_int32_topbit_mask(crypto_int32 crypto_int32_x) {
  החזר crypto_int32_negative_mask(crypto_int32_x);
}

__attribute__((unused))
ساكن مضمن
crypto_int32 crypto_int32_topbit_01(crypto_int32 crypto_int32_x) {
  החזר crypto_int32_unsigned_topbit_01(crypto_int32_x);
}

__attribute__((unused))
ساكن مضمن
crypto_int32 crypto_int32_bottombit_mask(crypto_int32 crypto_int32_x) {
#אם defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andl $1,%0" : "+r"(crypto_int32_x) : : "cc");
  החזר -crypto_int32_x;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_y;
  __asm__ ("sbfx %w0,%w1,0,1" : "=r"(crypto_int32_y) : "r"(crypto_int32_x) : );
  החזר crypto_int32_y;
#אחרת
  crypto_int32_x &= 1 ^ crypto_int32_optblocker;
  החזר -crypto_int32_x;
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int32 crypto_int32_bottombit_01(crypto_int32 crypto_int32_x) {
#אם defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andl $1,%0" : "+r"(crypto_int32_x) : : "cc");
  החזר crypto_int32_x;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_y;
  __asm__ ("ubfx %w0,%w1,0,1" : "=r"(crypto_int32_y) : "r"(crypto_int32_x) : );
  החזר crypto_int32_y;
#אחרת
  crypto_int32_x &= 1 ^ crypto_int32_optblocker;
  החזר crypto_int32_x;
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int32 crypto_int32_bitinrangepublicpos_mask(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
#אם defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarl %%cl,%0" : "+r"(crypto_int32_x) : "c"(crypto_int32_s) : "cc");
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %w0,%w0,%w1" : "+r"(crypto_int32_x) : "r"(crypto_int32_s) : );
#אחרת
  crypto_int32_x >>= crypto_int32_s ^ crypto_int32_optblocker;
#endif
  החזר crypto_int32_bottombit_mask(crypto_int32_x);
}

__attribute__((unused))
ساكن مضمن
crypto_int32 crypto_int32_bitinrangepublicpos_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
#אם defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarl %%cl,%0" : "+r"(crypto_int32_x) : "c"(crypto_int32_s) : "cc");
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %w0,%w0,%w1" : "+r"(crypto_int32_x) : "r"(crypto_int32_s) : );
#אחרת
  crypto_int32_x >>= crypto_int32_s ^ crypto_int32_optblocker;
#endif
  החזר crypto_int32_bottombit_01(crypto_int32_x);
}

__attribute__((unused))
ساكن مضمن
crypto_int32 crypto_int32_shlmod(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
#אם defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("shll %%cl,%0" : "+r"(crypto_int32_x) : "c"(crypto_int32_s) : "cc");
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("lsl %w0,%w0,%w1" : "+r"(crypto_int32_x) : "r"(crypto_int32_s) : );
#אחרת
  صحيح crypto_int32_k, crypto_int32_l;
  עבור (crypto_int32_l = 0,crypto_int32_k = 1;crypto_int32_k < 32;++crypto_int32_l,crypto_int32_k *= 2)
    crypto_int32_x ^= (crypto_int32_x ^ (crypto_int32_x << crypto_int32_k)) & crypto_int32_bitinrangepublicpos_mask(crypto_int32_s,crypto_int32_l);
#endif
  החזר crypto_int32_x;
}

__attribute__((unused))
ساكن مضمن
crypto_int32 crypto_int32_shrmod(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
#אם defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarl %%cl,%0" : "+r"(crypto_int32_x) : "c"(crypto_int32_s) : "cc");
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %w0,%w0,%w1" : "+r"(crypto_int32_x) : "r"(crypto_int32_s) : );
#אחרת
  صحيح crypto_int32_k, crypto_int32_l;
  עבור (crypto_int32_l = 0,crypto_int32_k = 1;crypto_int32_k < 32;++crypto_int32_l,crypto_int32_k *= 2)
    crypto_int32_x ^= (crypto_int32_x ^ (crypto_int32_x >> crypto_int32_k)) & crypto_int32_bitinrangepublicpos_mask(crypto_int32_s,crypto_int32_l);
#endif
  החזר crypto_int32_x;
}

__attribute__((unused))
ساكن مضمن
crypto_int32 crypto_int32_bitmod_mask(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
  crypto_int32_x = crypto_int32_shrmod(crypto_int32_x,crypto_int32_s);
  החזר crypto_int32_bottombit_mask(crypto_int32_x);
}

__attribute__((unused))
ساكن مضمن
crypto_int32 crypto_int32_bitmod_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
  crypto_int32_x = crypto_int32_shrmod(crypto_int32_x,crypto_int32_s);
  החזר crypto_int32_bottombit_01(crypto_int32_x);
}

__attribute__((unused))
ساكن مضمن
crypto_int32 crypto_int32_nonzero_mask(crypto_int32 crypto_int32_x) {
#אם defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n testl %2,%2\n cmovnel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  החזר crypto_int32_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n csetm %w0,ne" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  החזר crypto_int32_z;
#אחרת
  crypto_int32_x |= -crypto_int32_x;
  החזר crypto_int32_negative_mask(crypto_int32_x);
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int32 crypto_int32_nonzero_01(crypto_int32 crypto_int32_x) {
#אם defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n testl %2,%2\n cmovnel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  החזר crypto_int32_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n cset %w0,ne" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  החזר crypto_int32_z;
#אחרת
  crypto_int32_x |= -crypto_int32_x;
  החזר crypto_int32_unsigned_topbit_01(crypto_int32_x);
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int32 crypto_int32_positive_mask(crypto_int32 crypto_int32_x) {
#אם defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n testl %2,%2\n cmovgl %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  החזר crypto_int32_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n csetm %w0,gt" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  החזר crypto_int32_z;
#אחרת
  crypto_int32 crypto_int32_z = -crypto_int32_x;
  crypto_int32_z ^= crypto_int32_x & crypto_int32_z;
  החזר crypto_int32_negative_mask(crypto_int32_z);
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int32 crypto_int32_positive_01(crypto_int32 crypto_int32_x) {
#אם defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n testl %2,%2\n cmovgl %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  החזר crypto_int32_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n cset %w0,gt" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  החזר crypto_int32_z;
#אחרת
  crypto_int32 crypto_int32_z = -crypto_int32_x;
  crypto_int32_z ^= crypto_int32_x & crypto_int32_z;
  החזר crypto_int32_unsigned_topbit_01(crypto_int32_z);
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int32 crypto_int32_zero_mask(crypto_int32 crypto_int32_x) {
#אם defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n testl %2,%2\n cmovel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  החזר crypto_int32_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n csetm %w0,eq" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  החזר crypto_int32_z;
#אחרת
  החזר ~crypto_int32_nonzero_mask(crypto_int32_x);
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int32 crypto_int32_zero_01(crypto_int32 crypto_int32_x) {
#אם defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n testl %2,%2\n cmovel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  החזר crypto_int32_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n cset %w0,eq" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  החזר crypto_int32_z;
#אחרת
  החזר 1-crypto_int32_nonzero_01(crypto_int32_x);
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int32 crypto_int32_unequal_mask(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#אם defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n cmpl %3,%2\n cmovnel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  החזר crypto_int32_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n csetm %w0,ne" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  החזר crypto_int32_z;
#אחרת
  החזר crypto_int32_nonzero_mask(crypto_int32_x ^ crypto_int32_y);
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int32 crypto_int32_unequal_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#אם defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n cmpl %3,%2\n cmovnel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  החזר crypto_int32_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n cset %w0,ne" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  החזר crypto_int32_z;
#אחרת
  החזר crypto_int32_nonzero_01(crypto_int32_x ^ crypto_int32_y);
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int32 crypto_int32_equal_mask(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#אם defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n cmpl %3,%2\n cmovel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  החזר crypto_int32_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n csetm %w0,eq" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  החזר crypto_int32_z;
#אחרת
  החזר ~crypto_int32_unequal_mask(crypto_int32_x,crypto_int32_y);
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int32 crypto_int32_equal_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#אם defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n cmpl %3,%2\n cmovel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  החזר crypto_int32_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n cset %w0,eq" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  החזר crypto_int32_z;
#אחרת
  החזר 1-crypto_int32_unequal_01(crypto_int32_x,crypto_int32_y);
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int32 crypto_int32_min(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#אם defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpl %1,%0\n cmovgl %1,%0" : "+r"(crypto_int32_x) : "r"(crypto_int32_y) : "cc");
  החזר crypto_int32_x;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("cmp %w0,%w1\n csel %w0,%w0,%w1,lt" : "+r"(crypto_int32_x) : "r"(crypto_int32_y) : "cc");
  החזר crypto_int32_x;
#אחרת
  crypto_int64 crypto_int32_r = (crypto_int64)crypto_int32_y ^ (crypto_int64)crypto_int32_x;
  crypto_int64 crypto_int32_z = (crypto_int64)crypto_int32_y - (crypto_int64)crypto_int32_x;
  crypto_int32_z ^= crypto_int32_r & (crypto_int32_z ^ crypto_int32_y);
  crypto_int32_z = crypto_int32_negative_mask(crypto_int32_z);
  crypto_int32_z &= crypto_int32_r;
  החזר crypto_int32_x ^ crypto_int32_z;
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int32 crypto_int32_max(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#אם defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpl %1,%0\n cmovll %1,%0" : "+r"(crypto_int32_x) : "r"(crypto_int32_y) : "cc");
  החזר crypto_int32_x;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("cmp %w0,%w1\n csel %w0,%w1,%w0,lt" : "+r"(crypto_int32_x) : "r"(crypto_int32_y) : "cc");
  החזר crypto_int32_x;
#אחרת
  crypto_int64 crypto_int32_r = (crypto_int64)crypto_int32_y ^ (crypto_int64)crypto_int32_x;
  crypto_int64 crypto_int32_z = (crypto_int64)crypto_int32_y - (crypto_int64)crypto_int32_x;
  crypto_int32_z ^= crypto_int32_r & (crypto_int32_z ^ crypto_int32_y);
  crypto_int32_z = crypto_int32_negative_mask(crypto_int32_z);
  crypto_int32_z &= crypto_int32_r;
  החזר crypto_int32_y ^ crypto_int32_z;
#endif
}

__attribute__((unused))
ساكن مضمن
فراغ crypto_int32_minmax(crypto_int32 *crypto_int32_p,crypto_int32 *crypto_int32_q) {
  crypto_int32 crypto_int32_x = *crypto_int32_p;
  crypto_int32 crypto_int32_y = *crypto_int32_q;
#אם defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmpl %2,%1\n movl %1,%0\n cmovgl %2,%1\n cmovgl %0,%2" : "=&r"(crypto_int32_z), "+&r"(crypto_int32_x), "+r"(crypto_int32_y) : : "cc");
  *crypto_int32_p = crypto_int32_x;
  *crypto_int32_q = crypto_int32_y;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_r, crypto_int32_s;
  __asm__ ("cmp %w2,%w3\n csel %w0,%w2,%w3,lt\n csel %w1,%w3,%w2,lt" : "=&r"(crypto_int32_r), "=r"(crypto_int32_s) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  *crypto_int32_p = crypto_int32_r;
  *crypto_int32_q = crypto_int32_s;
#אחרת
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
ساكن مضمن
crypto_int32 crypto_int32_smaller_mask(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#אם defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n cmpl %3,%2\n cmovll %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  החזר crypto_int32_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n csetm %w0,lt" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  החזר crypto_int32_z;
#אחרת
  crypto_int32 crypto_int32_r = crypto_int32_x ^ crypto_int32_y;
  crypto_int32 crypto_int32_z = crypto_int32_x - crypto_int32_y;
  crypto_int32_z ^= crypto_int32_r & (crypto_int32_z ^ crypto_int32_x);
  החזר crypto_int32_negative_mask(crypto_int32_z);
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int32 crypto_int32_smaller_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#אם defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n cmpl %3,%2\n cmovll %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  החזר crypto_int32_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n cset %w0,lt" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  החזר crypto_int32_z;
#אחרת
  crypto_int32 crypto_int32_r = crypto_int32_x ^ crypto_int32_y;
  crypto_int32 crypto_int32_z = crypto_int32_x - crypto_int32_y;
  crypto_int32_z ^= crypto_int32_r & (crypto_int32_z ^ crypto_int32_x);
  החזר crypto_int32_unsigned_topbit_01(crypto_int32_z);
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int32 crypto_int32_leq_mask(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#אם defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n cmpl %3,%2\n cmovlel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  החזר crypto_int32_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n csetm %w0,le" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  החזר crypto_int32_z;
#אחרת
  החזר ~crypto_int32_smaller_mask(crypto_int32_y,crypto_int32_x);
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int32 crypto_int32_leq_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#אם defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n cmpl %3,%2\n cmovlel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  החזר crypto_int32_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n cset %w0,le" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  החזר crypto_int32_z;
#אחרת
  החזר 1-crypto_int32_smaller_01(crypto_int32_y,crypto_int32_x);
#endif
}

__attribute__((unused))
ساكن مضمن
صحيح crypto_int32_ones_num(crypto_int32 crypto_int32_x) {
  crypto_int32_unsigned crypto_int32_y = crypto_int32_x;
  ثابت crypto_int32 C0 = 0x55555555;
  ثابت crypto_int32 C1 = 0x33333333;
  ثابت crypto_int32 C2 = 0x0f0f0f0f;
  crypto_int32_y -= ((crypto_int32_y >> 1) & C0);
  crypto_int32_y = (crypto_int32_y & C1) + ((crypto_int32_y >> 2) & C1);
  crypto_int32_y = (crypto_int32_y + (crypto_int32_y >> 4)) & C2;
  crypto_int32_y += crypto_int32_y >> 8;
  crypto_int32_y = (crypto_int32_y + (crypto_int32_y >> 16)) & 0xff;
  החזר crypto_int32_y;
}

__attribute__((unused))
ساكن مضمن
صحيح crypto_int32_bottomzeros_num(crypto_int32 crypto_int32_x) {
#אם defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 fallback = 32;
  __asm__ ("bsfl %0,%0\n cmovel %1,%0" : "+&r"(crypto_int32_x) : "r"(fallback) : "cc");
  החזר crypto_int32_x;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  int64_t crypto_int32_y;
  __asm__ ("rbit %w0,%w1\n clz %w0,%w0" : "=r"(crypto_int32_y) : "r"(crypto_int32_x) : );
  החזר crypto_int32_y;
#אחרת
  crypto_int32 crypto_int32_y = crypto_int32_x ^ (crypto_int32_x-1);
  crypto_int32_y = ((crypto_int32) crypto_int32_y) >> 1;
  crypto_int32_y &= ~(crypto_int32_x & (((crypto_int32) 1) << (32-1)));
  החזר crypto_int32_ones_num(crypto_int32_y);
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
ساكن مضمن
crypto_int64 crypto_int64_load(ثابت unsigned حرف *crypto_int64_s) {
  crypto_int64 crypto_int64_z = 0;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 0;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 8;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 16;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 24;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 32;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 40;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 48;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 56;
  החזר crypto_int64_z;
}

__attribute__((unused))
ساكن مضمن
فراغ crypto_int64_store(unsigned حرف *crypto_int64_s,crypto_int64 crypto_int64_x) {
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
ساكن مضمن
crypto_int64 crypto_int64_negative_mask(crypto_int64 crypto_int64_x) {
#אם defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarq $63,%0" : "+r"(crypto_int64_x) : : "cc");
  החזר crypto_int64_x;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_y;
  __asm__ ("asr %0,%1,63" : "=r"(crypto_int64_y) : "r"(crypto_int64_x) : );
  החזר crypto_int64_y;
#אחרת
  crypto_int64_x >>= 64-6;
  crypto_int64_x ^= crypto_int64_optblocker;
  crypto_int64_x >>= 5;
  החזר crypto_int64_x;
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int64_unsigned crypto_int64_unsigned_topbit_01(crypto_int64_unsigned crypto_int64_x) {
#אם defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("shrq $63,%0" : "+r"(crypto_int64_x) : : "cc");
  החזר crypto_int64_x;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_y;
  __asm__ ("lsr %0,%1,63" : "=r"(crypto_int64_y) : "r"(crypto_int64_x) : );
  החזר crypto_int64_y;
#אחרת
  crypto_int64_x >>= 64-6;
  crypto_int64_x ^= crypto_int64_optblocker;
  crypto_int64_x >>= 5;
  החזר crypto_int64_x;
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int64 crypto_int64_negative_01(crypto_int64 crypto_int64_x) {
  החזר crypto_int64_unsigned_topbit_01(crypto_int64_x);
}

__attribute__((unused))
ساكن مضمن
crypto_int64 crypto_int64_topbit_mask(crypto_int64 crypto_int64_x) {
  החזר crypto_int64_negative_mask(crypto_int64_x);
}

__attribute__((unused))
ساكن مضمن
crypto_int64 crypto_int64_topbit_01(crypto_int64 crypto_int64_x) {
  החזר crypto_int64_unsigned_topbit_01(crypto_int64_x);
}

__attribute__((unused))
ساكن مضمن
crypto_int64 crypto_int64_bottombit_mask(crypto_int64 crypto_int64_x) {
#אם defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andq $1,%0" : "+r"(crypto_int64_x) : : "cc");
  החזר -crypto_int64_x;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_y;
  __asm__ ("sbfx %0,%1,0,1" : "=r"(crypto_int64_y) : "r"(crypto_int64_x) : );
  החזר crypto_int64_y;
#אחרת
  crypto_int64_x &= 1 ^ crypto_int64_optblocker;
  החזר -crypto_int64_x;
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int64 crypto_int64_bottombit_01(crypto_int64 crypto_int64_x) {
#אם defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andq $1,%0" : "+r"(crypto_int64_x) : : "cc");
  החזר crypto_int64_x;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_y;
  __asm__ ("ubfx %0,%1,0,1" : "=r"(crypto_int64_y) : "r"(crypto_int64_x) : );
  החזר crypto_int64_y;
#אחרת
  crypto_int64_x &= 1 ^ crypto_int64_optblocker;
  החזר crypto_int64_x;
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int64 crypto_int64_bitinrangepublicpos_mask(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
#אם defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarq %%cl,%0" : "+r"(crypto_int64_x) : "c"(crypto_int64_s) : "cc");
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %0,%0,%1" : "+r"(crypto_int64_x) : "r"(crypto_int64_s) : );
#אחרת
  crypto_int64_x >>= crypto_int64_s ^ crypto_int64_optblocker;
#endif
  החזר crypto_int64_bottombit_mask(crypto_int64_x);
}

__attribute__((unused))
ساكن مضمن
crypto_int64 crypto_int64_bitinrangepublicpos_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
#אם defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarq %%cl,%0" : "+r"(crypto_int64_x) : "c"(crypto_int64_s) : "cc");
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %0,%0,%1" : "+r"(crypto_int64_x) : "r"(crypto_int64_s) : );
#אחרת
  crypto_int64_x >>= crypto_int64_s ^ crypto_int64_optblocker;
#endif
  החזר crypto_int64_bottombit_01(crypto_int64_x);
}

__attribute__((unused))
ساكن مضمن
crypto_int64 crypto_int64_shlmod(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
#אם defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("shlq %%cl,%0" : "+r"(crypto_int64_x) : "c"(crypto_int64_s) : "cc");
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("lsl %0,%0,%1" : "+r"(crypto_int64_x) : "r"(crypto_int64_s) : );
#אחרת
  صحيح crypto_int64_k, crypto_int64_l;
  עבור (crypto_int64_l = 0,crypto_int64_k = 1;crypto_int64_k < 64;++crypto_int64_l,crypto_int64_k *= 2)
    crypto_int64_x ^= (crypto_int64_x ^ (crypto_int64_x << crypto_int64_k)) & crypto_int64_bitinrangepublicpos_mask(crypto_int64_s,crypto_int64_l);
#endif
  החזר crypto_int64_x;
}

__attribute__((unused))
ساكن مضمن
crypto_int64 crypto_int64_shrmod(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
#אם defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarq %%cl,%0" : "+r"(crypto_int64_x) : "c"(crypto_int64_s) : "cc");
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %0,%0,%1" : "+r"(crypto_int64_x) : "r"(crypto_int64_s) : );
#אחרת
  صحيح crypto_int64_k, crypto_int64_l;
  עבור (crypto_int64_l = 0,crypto_int64_k = 1;crypto_int64_k < 64;++crypto_int64_l,crypto_int64_k *= 2)
    crypto_int64_x ^= (crypto_int64_x ^ (crypto_int64_x >> crypto_int64_k)) & crypto_int64_bitinrangepublicpos_mask(crypto_int64_s,crypto_int64_l);
#endif
  החזר crypto_int64_x;
}

__attribute__((unused))
ساكن مضمن
crypto_int64 crypto_int64_bitmod_mask(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
  crypto_int64_x = crypto_int64_shrmod(crypto_int64_x,crypto_int64_s);
  החזר crypto_int64_bottombit_mask(crypto_int64_x);
}

__attribute__((unused))
ساكن مضمن
crypto_int64 crypto_int64_bitmod_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
  crypto_int64_x = crypto_int64_shrmod(crypto_int64_x,crypto_int64_s);
  החזר crypto_int64_bottombit_01(crypto_int64_x);
}

__attribute__((unused))
ساكن مضمن
crypto_int64 crypto_int64_nonzero_mask(crypto_int64 crypto_int64_x) {
#אם defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n testq %2,%2\n cmovneq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  החזר crypto_int64_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n csetm %0,ne" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  החזר crypto_int64_z;
#אחרת
  crypto_int64_x |= -crypto_int64_x;
  החזר crypto_int64_negative_mask(crypto_int64_x);
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int64 crypto_int64_nonzero_01(crypto_int64 crypto_int64_x) {
#אם defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n testq %2,%2\n cmovneq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  החזר crypto_int64_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n cset %0,ne" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  החזר crypto_int64_z;
#אחרת
  crypto_int64_x |= -crypto_int64_x;
  החזר crypto_int64_unsigned_topbit_01(crypto_int64_x);
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int64 crypto_int64_positive_mask(crypto_int64 crypto_int64_x) {
#אם defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n testq %2,%2\n cmovgq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  החזר crypto_int64_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n csetm %0,gt" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  החזר crypto_int64_z;
#אחרת
  crypto_int64 crypto_int64_z = -crypto_int64_x;
  crypto_int64_z ^= crypto_int64_x & crypto_int64_z;
  החזר crypto_int64_negative_mask(crypto_int64_z);
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int64 crypto_int64_positive_01(crypto_int64 crypto_int64_x) {
#אם defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n testq %2,%2\n cmovgq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  החזר crypto_int64_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n cset %0,gt" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  החזר crypto_int64_z;
#אחרת
  crypto_int64 crypto_int64_z = -crypto_int64_x;
  crypto_int64_z ^= crypto_int64_x & crypto_int64_z;
  החזר crypto_int64_unsigned_topbit_01(crypto_int64_z);
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int64 crypto_int64_zero_mask(crypto_int64 crypto_int64_x) {
#אם defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n testq %2,%2\n cmoveq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  החזר crypto_int64_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n csetm %0,eq" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  החזר crypto_int64_z;
#אחרת
  החזר ~crypto_int64_nonzero_mask(crypto_int64_x);
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int64 crypto_int64_zero_01(crypto_int64 crypto_int64_x) {
#אם defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n testq %2,%2\n cmoveq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  החזר crypto_int64_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n cset %0,eq" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  החזר crypto_int64_z;
#אחרת
  החזר 1-crypto_int64_nonzero_01(crypto_int64_x);
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int64 crypto_int64_unequal_mask(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#אם defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n cmpq %3,%2\n cmovneq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  החזר crypto_int64_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n csetm %0,ne" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  החזר crypto_int64_z;
#אחרת
  החזר crypto_int64_nonzero_mask(crypto_int64_x ^ crypto_int64_y);
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int64 crypto_int64_unequal_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#אם defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n cmpq %3,%2\n cmovneq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  החזר crypto_int64_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n cset %0,ne" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  החזר crypto_int64_z;
#אחרת
  החזר crypto_int64_nonzero_01(crypto_int64_x ^ crypto_int64_y);
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int64 crypto_int64_equal_mask(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#אם defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n cmpq %3,%2\n cmoveq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  החזר crypto_int64_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n csetm %0,eq" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  החזר crypto_int64_z;
#אחרת
  החזר ~crypto_int64_unequal_mask(crypto_int64_x,crypto_int64_y);
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int64 crypto_int64_equal_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#אם defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n cmpq %3,%2\n cmoveq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  החזר crypto_int64_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n cset %0,eq" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  החזר crypto_int64_z;
#אחרת
  החזר 1-crypto_int64_unequal_01(crypto_int64_x,crypto_int64_y);
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int64 crypto_int64_min(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#אם defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpq %1,%0\n cmovgq %1,%0" : "+r"(crypto_int64_x) : "r"(crypto_int64_y) : "cc");
  החזר crypto_int64_x;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("cmp %0,%1\n csel %0,%0,%1,lt" : "+r"(crypto_int64_x) : "r"(crypto_int64_y) : "cc");
  החזר crypto_int64_x;
#אחרת
  crypto_int64 crypto_int64_r = crypto_int64_y ^ crypto_int64_x;
  crypto_int64 crypto_int64_z = crypto_int64_y - crypto_int64_x;
  crypto_int64_z ^= crypto_int64_r & (crypto_int64_z ^ crypto_int64_y);
  crypto_int64_z = crypto_int64_negative_mask(crypto_int64_z);
  crypto_int64_z &= crypto_int64_r;
  החזר crypto_int64_x ^ crypto_int64_z;
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int64 crypto_int64_max(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#אם defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpq %1,%0\n cmovlq %1,%0" : "+r"(crypto_int64_x) : "r"(crypto_int64_y) : "cc");
  החזר crypto_int64_x;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("cmp %0,%1\n csel %0,%1,%0,lt" : "+r"(crypto_int64_x) : "r"(crypto_int64_y) : "cc");
  החזר crypto_int64_x;
#אחרת
  crypto_int64 crypto_int64_r = crypto_int64_y ^ crypto_int64_x;
  crypto_int64 crypto_int64_z = crypto_int64_y - crypto_int64_x;
  crypto_int64_z ^= crypto_int64_r & (crypto_int64_z ^ crypto_int64_y);
  crypto_int64_z = crypto_int64_negative_mask(crypto_int64_z);
  crypto_int64_z &= crypto_int64_r;
  החזר crypto_int64_y ^ crypto_int64_z;
#endif
}

__attribute__((unused))
ساكن مضمن
فراغ crypto_int64_minmax(crypto_int64 *crypto_int64_p,crypto_int64 *crypto_int64_q) {
  crypto_int64 crypto_int64_x = *crypto_int64_p;
  crypto_int64 crypto_int64_y = *crypto_int64_q;
#אם defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmpq %2,%1\n movq %1,%0\n cmovgq %2,%1\n cmovgq %0,%2" : "=&r"(crypto_int64_z), "+&r"(crypto_int64_x), "+r"(crypto_int64_y) : : "cc");
  *crypto_int64_p = crypto_int64_x;
  *crypto_int64_q = crypto_int64_y;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_r, crypto_int64_s;
  __asm__ ("cmp %2,%3\n csel %0,%2,%3,lt\n csel %1,%3,%2,lt" : "=&r"(crypto_int64_r), "=r"(crypto_int64_s) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  *crypto_int64_p = crypto_int64_r;
  *crypto_int64_q = crypto_int64_s;
#אחרת
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
ساكن مضمن
crypto_int64 crypto_int64_smaller_mask(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#אם defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n cmpq %3,%2\n cmovlq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  החזר crypto_int64_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n csetm %0,lt" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  החזר crypto_int64_z;
#אחרת
  crypto_int64 crypto_int64_r = crypto_int64_x ^ crypto_int64_y;
  crypto_int64 crypto_int64_z = crypto_int64_x - crypto_int64_y;
  crypto_int64_z ^= crypto_int64_r & (crypto_int64_z ^ crypto_int64_x);
  החזר crypto_int64_negative_mask(crypto_int64_z);
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int64 crypto_int64_smaller_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#אם defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n cmpq %3,%2\n cmovlq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  החזר crypto_int64_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n cset %0,lt" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  החזר crypto_int64_z;
#אחרת
  crypto_int64 crypto_int64_r = crypto_int64_x ^ crypto_int64_y;
  crypto_int64 crypto_int64_z = crypto_int64_x - crypto_int64_y;
  crypto_int64_z ^= crypto_int64_r & (crypto_int64_z ^ crypto_int64_x);
  החזר crypto_int64_unsigned_topbit_01(crypto_int64_z);
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int64 crypto_int64_leq_mask(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#אם defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n cmpq %3,%2\n cmovleq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  החזר crypto_int64_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n csetm %0,le" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  החזר crypto_int64_z;
#אחרת
  החזר ~crypto_int64_smaller_mask(crypto_int64_y,crypto_int64_x);
#endif
}

__attribute__((unused))
ساكن مضمن
crypto_int64 crypto_int64_leq_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#אם defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n cmpq %3,%2\n cmovleq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  החזר crypto_int64_z;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n cset %0,le" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  החזר crypto_int64_z;
#אחרת
  החזר 1-crypto_int64_smaller_01(crypto_int64_y,crypto_int64_x);
#endif
}

__attribute__((unused))
ساكن مضمن
صحيح crypto_int64_ones_num(crypto_int64 crypto_int64_x) {
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
  החזר crypto_int64_y;
}

__attribute__((unused))
ساكن مضمن
صحيح crypto_int64_bottomzeros_num(crypto_int64 crypto_int64_x) {
#אם defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 fallback = 64;
  __asm__ ("bsfq %0,%0\n cmoveq %1,%0" : "+&r"(crypto_int64_x) : "r"(fallback) : "cc");
  החזר crypto_int64_x;
#وإلاإذا defined(__GNUC__) && defined(__aarch64__)
  int64_t crypto_int64_y;
  __asm__ ("rbit %0,%1\n clz %0,%0" : "=r"(crypto_int64_y) : "r"(crypto_int64_x) : );
  החזר crypto_int64_y;
#אחרת
  crypto_int64 crypto_int64_y = crypto_int64_x ^ (crypto_int64_x-1);
  crypto_int64_y = ((crypto_int64) crypto_int64_y) >> 1;
  crypto_int64_y &= ~(crypto_int64_x & (((crypto_int64) 1) << (64-1)));
  החזר crypto_int64_ones_num(crypto_int64_y);
#endif
}

#endif

/* from supercop-20240808/crypto_sort/int32/portable4/sort.c */
#define int32_MINMAX(a,b) crypto_int32_minmax(&a,&b)

ساكن فراغ crypto_sort_int32(فراغ *array,long long n)
{
  long long top,p,q,r,i,j;
  int32 *x = array;

  אם (n < 2) החזר;
  top = 1;
  כלעוד (top < n - top) top += top;

  עבור (p = top;p >= 1;p >>= 1) {
    i = 0;
    כלעוד (i + 2 * p <= n) {
      עבור (j = i;j < i + p;++j)
        int32_MINMAX(x[j],x[j+p]);
      i += 2 * p;
    }
    עבור (j = i;j < n - p;++j)
      int32_MINMAX(x[j],x[j+p]);

    i = 0;
    j = 0;
    עבור (q = top;q > p;q >>= 1) {
      אם (j != i) עבור (;;) {
        אם (j == n - q) اذهب done;
        int32 a = x[j + p];
        עבור (r = q;r > p;r >>= 1)
          int32_MINMAX(a,x[j + r]);
        x[j + p] = a;
        ++j;
        אם (j == i + p) {
          i += 2 * p;
          اكسر;
        }
      }
      כלעוד (i + p <= n - q) {
        עבור (j = i;j < i + p;++j) {
          int32 a = x[j + p];
          עבור (r = q;r > p;r >>= 1)
            int32_MINMAX(a,x[j+r]);
          x[j + p] = a;
        }
        i += 2 * p;
      }
      /* now i + p > n - q */
      j = i;
      כלעוד (j < n - q) {
        int32 a = x[j + p];
        עבור (r = q;r > p;r >>= 1)
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

ساكن فراغ crypto_sort_uint32(فراغ *array,long long n)
{
  crypto_uint32 *x = array;
  long long j;
  עבור (j = 0;j < n;++j) x[j] ^= 0x80000000;
  crypto_sort_int32(array,n);
  עבור (j = 0;j < n;++j) x[j] ^= 0x80000000;
}

/* from supercop-20240808/crypto_kem/sntrup761/compact/kem.c */
// 20240806 djb: some automated conversion to cryptoint

#define p 761
#define q 4591
#define w 286
#define q12 ((q - 1) / 2)
تعريفنوع int8_t small;
تعريفنوع int16_t Fq;
#define Hash_bytes 32
#define Small_bytes ((p + 3) / 4)
تعريفنوع small Inputs[p];
#define SecretKeys_bytes (2 * Small_bytes)
#define Confirm_bytes 32

ساكن small F3_freeze(int16_t x) { החזר x - 3 * ((10923 * x + 16384) >> 15); }

ساكن Fq Fq_freeze(int32_t x) {
  ثابت int32_t q16 = (0x10000 + q / 2) / q;
  ثابت int32_t q20 = (0x100000 + q / 2) / q;
  ثابت int32_t q28 = (0x10000000 + q / 2) / q;
  x -= q * ((q16 * x) >> 16);
  x -= q * ((q20 * x) >> 20);
  החזר x - q * ((q28 * x + 0x8000000) >> 28);
}

ساكن صحيح Weightw_mask(small *r) {
  صحيح i, weight = 0;
  עבור (i = 0; i < p; ++i) weight += crypto_int64_bottombit_01(r[i]);
  החזר crypto_int16_nonzero_mask(weight - w);
}

ساكن فراغ uint32_divmod_uint14(uint32_t *Q, uint16_t *r, uint32_t x, uint16_t m) {
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

ساكن uint16_t uint32_mod_uint14(uint32_t x, uint16_t m) {
  uint32_t Q;
  uint16_t r;
  uint32_divmod_uint14(&Q, &r, x, m);
  החזר r;
}

ساكن فراغ Encode(unsigned حرف *out, ثابت uint16_t *R, ثابت uint16_t *M, long long len) {
  אם (len == 1) {
    uint16_t r = R[0], m = M[0];
    כלעוד (m > 1) {
      *out++ = r;
      r >>= 8;
      m = (m + 255) >> 8;
    }
  }
  אם (len > 1) {
    uint16_t R2[(len + 1) / 2], M2[(len + 1) / 2];
    long long i;
    עבור (i = 0; i < len - 1; i += 2) {
      uint32_t m0 = M[i];
      uint32_t r = R[i] + R[i + 1] * m0;
      uint32_t m = M[i + 1] * m0;
      כלעוד (m >= 16384) {
        *out++ = r;
        r >>= 8;
        m = (m + 255) >> 8;
      }
      R2[i / 2] = r;
      M2[i / 2] = m;
    }
    אם (i < len) {
      R2[i / 2] = R[i];
      M2[i / 2] = M[i];
    }
    Encode(out, R2, M2, (len + 1) / 2);
  }
}

ساكن فراغ Decode(uint16_t *out, ثابت unsigned حرف *S, ثابت uint16_t *M, long long len) {
  אם (len == 1) {
    אם (M[0] == 1)
      *out = 0;
    אחרת אם (M[0] <= 256)
      *out = uint32_mod_uint14(S[0], M[0]);
    אחרת
      *out = uint32_mod_uint14(S[0] + (((uint16_t)S[1]) << 8), M[0]);
  }
  אם (len > 1) {
    uint16_t R2[(len + 1) / 2], M2[(len + 1) / 2], bottomr[len / 2];
    uint32_t bottomt[len / 2];
    long long i;
    עבור (i = 0; i < len - 1; i += 2) {
      uint32_t m = M[i] * (uint32_t)M[i + 1];
      אם (m > 256 * 16383) {
        bottomt[i / 2] = 256 * 256;
        bottomr[i / 2] = S[0] + 256 * S[1];
        S += 2;
        M2[i / 2] = (((m + 255) >> 8) + 255) >> 8;
      } אחרת אם (m >= 16384) {
        bottomt[i / 2] = 256;
        bottomr[i / 2] = S[0];
        S += 1;
        M2[i / 2] = (m + 255) >> 8;
      } אחרת {
        bottomt[i / 2] = 1;
        bottomr[i / 2] = 0;
        M2[i / 2] = m;
      }
    }
    אם (i < len) M2[i / 2] = M[i];
    Decode(R2, S, M2, (len + 1) / 2);
    עבור (i = 0; i < len - 1; i += 2) {
      uint32_t r1, r = bottomr[i / 2];
      uint16_t r0;
      r += bottomt[i / 2] * R2[i / 2];
      uint32_divmod_uint14(&r1, &r0, r, M[i]);
      r1 = uint32_mod_uint14(r1, M[i + 1]);
      *out++ = r0;
      *out++ = r1;
    }
    אם (i < len) *out++ = R2[i / 2];
  }
}

ساكن فراغ R3_fromRq(small *out, ثابت Fq *r) {
  صحيح i;
  עבור (i = 0; i < p; ++i) out[i] = F3_freeze(r[i]);
}

ساكن فراغ R3_mult(small *h, ثابت small *f, ثابت small *g) {
  int16_t fg[p + p - 1];
  صحيح i, j;
  עבור (i = 0; i < p + p - 1; ++i) fg[i] = 0;
  עבור (i = 0; i < p; ++i)
    עבור (j = 0; j < p; ++j) fg[i + j] += f[i] * (int16_t)g[j];
  עבור (i = p; i < p + p - 1; ++i) fg[i - p] += fg[i];
  עבור (i = p; i < p + p - 1; ++i) fg[i - p + 1] += fg[i];
  עבור (i = 0; i < p; ++i) h[i] = F3_freeze(fg[i]);
}

ساكن صحيح R3_recip(small *out, ثابت small *in) {
  small f[p + 1], g[p + 1], v[p + 1], r[p + 1];
  صحيح sign, swap, t, i, loop, delta = 1;
  עבור (i = 0; i < p + 1; ++i) v[i] = 0;
  עבור (i = 0; i < p + 1; ++i) r[i] = 0;
  r[0] = 1;
  עבור (i = 0; i < p; ++i) f[i] = 0;
  f[0] = 1;
  f[p - 1] = f[p] = -1;
  עבור (i = 0; i < p; ++i) g[p - 1 - i] = in[i];
  g[p] = 0;
  עבור (loop = 0; loop < 2 * p - 1; ++loop) {
    עבור (i = p; i > 0; --i) v[i] = v[i - 1];
    v[0] = 0;
    sign = -g[0] * f[0];
    swap = crypto_int16_negative_mask(-delta) & crypto_int16_nonzero_mask(g[0]);
    delta ^= swap & (delta ^ -delta);
    delta += 1;
    עבור (i = 0; i < p + 1; ++i) {
      t = swap & (f[i] ^ g[i]);
      f[i] ^= t;
      g[i] ^= t;
      t = swap & (v[i] ^ r[i]);
      v[i] ^= t;
      r[i] ^= t;
    }
    עבור (i = 0; i < p + 1; ++i) g[i] = F3_freeze(g[i] + sign * f[i]);
    עבור (i = 0; i < p + 1; ++i) r[i] = F3_freeze(r[i] + sign * v[i]);
    עבור (i = 0; i < p; ++i) g[i] = g[i + 1];
    g[p] = 0;
  }
  sign = f[0];
  עבור (i = 0; i < p; ++i) out[i] = sign * v[p - 1 - i];
  החזר crypto_int16_nonzero_mask(delta);
}

ساكن فراغ Rq_mult_small(Fq *h, ثابت Fq *f, ثابت small *g) {
  int32_t fg[p + p - 1];
  صحيح i, j;
  עבור (i = 0; i < p + p - 1; ++i) fg[i] = 0;
  עבור (i = 0; i < p; ++i)
    עבור (j = 0; j < p; ++j) fg[i + j] += f[i] * (int32_t)g[j];
  עבור (i = p; i < p + p - 1; ++i) fg[i - p] += fg[i];
  עבור (i = p; i < p + p - 1; ++i) fg[i - p + 1] += fg[i];
  עבור (i = 0; i < p; ++i) h[i] = Fq_freeze(fg[i]);
}

ساكن فراغ Rq_mult3(Fq *h, ثابت Fq *f) {
  صحيح i;
  עבור (i = 0; i < p; ++i) h[i] = Fq_freeze(3 * f[i]);
}

ساكن Fq Fq_recip(Fq a1) {
  صحيح i = 1;
  Fq ai = a1;
  כלעוד (i < q - 2) {
    ai = Fq_freeze(a1 * (int32_t)ai);
    i += 1;
  }
  החזר ai;
}

ساكن صحيح Rq_recip3(Fq *out, ثابت small *in) {
  Fq f[p + 1], g[p + 1], v[p + 1], r[p + 1], scale;
  صحيح swap, t, i, loop, delta = 1;
  int32_t f0, g0;
  עבור (i = 0; i < p + 1; ++i) v[i] = 0;
  עבור (i = 0; i < p + 1; ++i) r[i] = 0;
  r[0] = Fq_recip(3);
  עבור (i = 0; i < p; ++i) f[i] = 0;
  f[0] = 1;
  f[p - 1] = f[p] = -1;
  עבור (i = 0; i < p; ++i) g[p - 1 - i] = in[i];
  g[p] = 0;
  עבור (loop = 0; loop < 2 * p - 1; ++loop) {
    עבור (i = p; i > 0; --i) v[i] = v[i - 1];
    v[0] = 0;
    swap = crypto_int16_negative_mask(-delta) & crypto_int16_nonzero_mask(g[0]);
    delta ^= swap & (delta ^ -delta);
    delta += 1;
    עבור (i = 0; i < p + 1; ++i) {
      t = swap & (f[i] ^ g[i]);
      f[i] ^= t;
      g[i] ^= t;
      t = swap & (v[i] ^ r[i]);
      v[i] ^= t;
      r[i] ^= t;
    }
    f0 = f[0];
    g0 = g[0];
    עבור (i = 0; i < p + 1; ++i) g[i] = Fq_freeze(f0 * g[i] - g0 * f[i]);
    עבור (i = 0; i < p + 1; ++i) r[i] = Fq_freeze(f0 * r[i] - g0 * v[i]);
    עבור (i = 0; i < p; ++i) g[i] = g[i + 1];
    g[p] = 0;
  }
  scale = Fq_recip(f[0]);
  עבור (i = 0; i < p; ++i) out[i] = Fq_freeze(scale * (int32_t)v[p - 1 - i]);
  החזר crypto_int16_nonzero_mask(delta);
}

ساكن فراغ Round(Fq *out, ثابت Fq *a) {
  صحيح i;
  עבור (i = 0; i < p; ++i) out[i] = a[i] - F3_freeze(a[i]);
}

ساكن فراغ Short_fromlist(small *out, ثابت uint32_t *in) {
  uint32_t L[p];
  صحيح i;
  עבור (i = 0; i < w; ++i) L[i] = in[i] & (uint32_t)-2;
  עבור (i = w; i < p; ++i) L[i] = (in[i] & (uint32_t)-3) | 1;
  crypto_sort_uint32(L, p);
  עבור (i = 0; i < p; ++i) out[i] = (L[i] & 3) - 1;
}

ساكن فراغ Hash_prefix(unsigned حرف *out, صحيح b, ثابت unsigned حرف *in, صحيح inlen) {
  unsigned حرف x[inlen + 1], h[64];
  صحيح i;
  x[0] = b;
  עבור (i = 0; i < inlen; ++i) x[i + 1] = in[i];
  crypto_hash_sha512(h, x, inlen + 1);
  עבור (i = 0; i < 32; ++i) out[i] = h[i];
}


ساكن فراغ Short_random(small *out) {
  uint32_t L[p];
  randombytes(L, حجم(L));
  Short_fromlist(out, L);
  explicit_bzero(L, حجم(L));
}
ساكن فراغ Small_random(small *out) {
  صحيح i;
  uint32_t L[p];
  randombytes(L, حجم(L));
  עבור (i = 0; i < p; ++i) out[i] = (((L[i] & 0x3fffffff) * 3) >> 30) - 1;
  explicit_bzero(L, حجم(L));
}
ساكن فراغ KeyGen(Fq *h, small *f, small *ginv) {
  small g[p];
  Fq finv[p];
  עבור (;;) {
    صحيح result;
    Small_random(g);
    result = R3_recip(ginv, g);
    crypto_declassify(&result, حجم result);
    אם (result == 0) اكسر;
  }
  Short_random(f);
  Rq_recip3(finv, f);
  Rq_mult_small(h, finv, g);
}

ساكن فراغ Encrypt(Fq *c, ثابت small *r, ثابت Fq *h) {
  Fq hr[p];
  Rq_mult_small(hr, h, r);
  Round(c, hr);
}

ساكن فراغ Decrypt(small *r, ثابت Fq *c, ثابت small *f, ثابت small *ginv) {
  Fq cf[p], cf3[p];
  small e[p], ev[p];
  صحيح mask, i;
  Rq_mult_small(cf, c, f);
  Rq_mult3(cf3, cf);
  R3_fromRq(e, cf3);
  R3_mult(ev, e, ginv);
  mask = Weightw_mask(ev);
  עבור (i = 0; i < w; ++i) r[i] = ((ev[i] ^ 1) & ~mask) ^ 1;
  עבור (i = w; i < p; ++i) r[i] = ev[i] & ~mask;
}

ساكن فراغ Small_encode(unsigned حرف *s, ثابت small *f) {
  صحيح i, j;
  עבור (i = 0; i < p / 4; ++i) {
    small x = 0;
    עבור (j = 0;j < 4;++j) x += (*f++ + 1) << (2 * j);
    *s++ = x;
  }
  *s = *f++ + 1;
}

ساكن فراغ Small_decode(small *f, ثابت unsigned حرف *s) {
  صحيح i, j;
  עבור (i = 0; i < p / 4; ++i) {
    unsigned حرف x = *s++;
    עבור (j = 0;j < 4;++j) *f++ = ((small)((x >> (2 * j)) & 3)) - 1;
  }
  *f++ = ((small)(*s & 3)) - 1;
}

ساكن فراغ Rq_encode(unsigned حرف *s, ثابت Fq *r) {
  uint16_t R[p], M[p];
  صحيح i;
  עבור (i = 0; i < p; ++i) R[i] = r[i] + q12;
  עבור (i = 0; i < p; ++i) M[i] = q;
  Encode(s, R, M, p);
}

ساكن فراغ Rq_decode(Fq *r, ثابت unsigned حرف *s) {
  uint16_t R[p], M[p];
  صحيح i;
  עבור (i = 0; i < p; ++i) M[i] = q;
  Decode(R, s, M, p);
  עבור (i = 0; i < p; ++i) r[i] = ((Fq)R[i]) - q12;
}

ساكن فراغ Rounded_encode(unsigned حرف *s, ثابت Fq *r) {
  uint16_t R[p], M[p];
  صحيح i;
  עבור (i = 0; i < p; ++i) R[i] = ((r[i] + q12) * 10923) >> 15;
  עבור (i = 0; i < p; ++i) M[i] = (q + 2) / 3;
  Encode(s, R, M, p);
}

ساكن فراغ Rounded_decode(Fq *r, ثابت unsigned حرف *s) {
  uint16_t R[p], M[p];
  صحيح i;
  עבור (i = 0; i < p; ++i) M[i] = (q + 2) / 3;
  Decode(R, s, M, p);
  עבור (i = 0; i < p; ++i) r[i] = R[i] * 3 - q12;
}

ساكن فراغ ZKeyGen(unsigned حرف *pk, unsigned حرف *sk) {
  Fq h[p];
  small f[p], v[p];
  KeyGen(h, f, v);
  Rq_encode(pk, h);
  Small_encode(sk, f);
  Small_encode(sk + Small_bytes, v);
}

ساكن فراغ ZEncrypt(unsigned حرف *C, ثابت Inputs r, ثابت unsigned حرف *pk) {
  Fq h[p], c[p];
  Rq_decode(h, pk);
  Encrypt(c, r, h);
  Rounded_encode(C, c);
}

ساكن فراغ ZDecrypt(Inputs r, ثابت unsigned حرف *C, ثابت unsigned حرف *sk) {
  small f[p], v[p];
  Fq c[p];
  Small_decode(f, sk);
  Small_decode(v, sk + Small_bytes);
  Rounded_decode(c, C);
  Decrypt(r, c, f, v);
}

ساكن فراغ HashConfirm(unsigned حرف *h, ثابت unsigned حرف *r, ثابت unsigned حرف *cache) {
  unsigned حرف x[Hash_bytes * 2];
  صحيح i;
  Hash_prefix(x, 3, r, Small_bytes);
  עבור (i = 0; i < Hash_bytes; ++i) x[Hash_bytes + i] = cache[i];
  Hash_prefix(h, 2, x, حجم x);
}

ساكن فراغ HashSession(unsigned حرف *k, صحيح b, ثابت unsigned حرف *y, ثابت unsigned حرف *z) {
  unsigned حرف x[Hash_bytes + crypto_kem_sntrup761_CIPHERTEXTBYTES];
  صحيح i;
  Hash_prefix(x, 3, y, Small_bytes);
  עבור (i = 0; i < crypto_kem_sntrup761_CIPHERTEXTBYTES; ++i) x[Hash_bytes + i] = z[i];
  Hash_prefix(k, b, x, حجم x);
}

صحيح crypto_kem_sntrup761_keypair(unsigned حرف *pk, unsigned حرف *sk) {
  صحيح i;
  ZKeyGen(pk, sk);
  sk += SecretKeys_bytes;
  עבור (i = 0; i < crypto_kem_sntrup761_PUBLICKEYBYTES; ++i) *sk++ = pk[i];
  randombytes(sk, Small_bytes);
  Hash_prefix(sk + Small_bytes, 4, pk, crypto_kem_sntrup761_PUBLICKEYBYTES);
  החזר 0;
}

ساكن فراغ Hide(unsigned حرف *c, unsigned حرف *r_enc, ثابت Inputs r, ثابت unsigned حرف *pk, ثابت unsigned حرف *cache) {
  Small_encode(r_enc, r);
  ZEncrypt(c, r, pk);
  HashConfirm(c + crypto_kem_sntrup761_CIPHERTEXTBYTES - Confirm_bytes, r_enc, cache);
}

صحيح crypto_kem_sntrup761_enc(unsigned حرف *c, unsigned حرف *k, ثابت unsigned حرف *pk) {
  Inputs r;
  unsigned حرف r_enc[Small_bytes], cache[Hash_bytes];
  Hash_prefix(cache, 4, pk, crypto_kem_sntrup761_PUBLICKEYBYTES);
  Short_random(r);
  Hide(c, r_enc, r, pk, cache);
  HashSession(k, 1, r_enc, c);
  החזר 0;
}

ساكن صحيح Ciphertexts_diff_mask(ثابت unsigned حرف *c, ثابت unsigned حرف *c2) {
  uint16_t differentbits = 0;
  صحيح len = crypto_kem_sntrup761_CIPHERTEXTBYTES;
  כלעוד (len-- > 0) differentbits |= (*c++) ^ (*c2++);
  החזר (crypto_int64_bitmod_01((differentbits - 1),8)) - 1;
}

صحيح crypto_kem_sntrup761_dec(unsigned حرف *k, ثابت unsigned حرف *c, ثابت unsigned حرف *sk) {
  ثابت unsigned حرف *pk = sk + SecretKeys_bytes;
  ثابت unsigned حرف *rho = pk + crypto_kem_sntrup761_PUBLICKEYBYTES;
  ثابت unsigned حرف *cache = rho + Small_bytes;
  Inputs r;
  unsigned حرف r_enc[Small_bytes], cnew[crypto_kem_sntrup761_CIPHERTEXTBYTES];
  صحيح mask, i;
  ZDecrypt(r, c, sk);
  Hide(cnew, r_enc, r, pk, cache);
  mask = Ciphertexts_diff_mask(c, cnew);
  עבור (i = 0; i < Small_bytes; ++i) r_enc[i] ^= mask & (r_enc[i] ^ rho[i]);
  HashSession(k, 1 + mask, r_enc, c);
  החזר 0;
}

#endif /* USE_SNTRUP761X25519 */
