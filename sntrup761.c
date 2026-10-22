/*  $OpenBSD: sntrup761.c,v 1.9 2026/01/20 22:56:11 dtucker Exp $ */

/*
 * Public Domain, Authors:
 * - Daniel J. Bernstein
 * - Chitchanok Chuengsatiansup
 * - Tanja Lange
 * - Christine van Vredendaal
 */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_SNTRUP761X25519

#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ "crypto_api.h"

#ವ್ಯಾಖ್ಯಾನಿಸು crypto_declassify(x, y) ಮಾಡು {} ಆಗ (0)

#ವ್ಯಾಖ್ಯಾನಿಸು int8 crypto_int8
#ವ್ಯಾಖ್ಯಾನಿಸು uint8 crypto_uint8
#ವ್ಯಾಖ್ಯಾನಿಸು int16 crypto_int16
#ವ್ಯಾಖ್ಯಾನಿಸು uint16 crypto_uint16
#ವ್ಯಾಖ್ಯಾನಿಸು int32 crypto_int32
#ವ್ಯಾಖ್ಯಾನಿಸು uint32 crypto_uint32
#ವ್ಯಾಖ್ಯಾನಿಸು int64 crypto_int64
#ವ್ಯಾಖ್ಯಾನಿಸು uint64 crypto_uint64
ಬಾಹ್ಯ ಅಸ್ಥಿರ crypto_int16 crypto_int16_optblocker;
ಬಾಹ್ಯ ಅಸ್ಥಿರ crypto_int32 crypto_int32_optblocker;
ಬಾಹ್ಯ ಅಸ್ಥಿರ crypto_int64 crypto_int64_optblocker;

/* from supercop-20240808/cryptoint/crypto_int16.h */
/* auto-generated: cd cryptoint; ./autogen */
/* cryptoint 20240806 */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ crypto_int16_h
#ವ್ಯಾಖ್ಯಾನಿಸು crypto_int16_h

#ವ್ಯಾಖ್ಯಾನಿಸು crypto_int16 int16_t
#ವ್ಯಾಖ್ಯಾನಿಸು crypto_int16_unsigned uint16_t



__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int16 crypto_int16_ತುಂಬು(ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *crypto_int16_s) {
  crypto_int16 crypto_int16_z = 0;
  crypto_int16_z |= ((crypto_int16) (*crypto_int16_s++)) << 0;
  crypto_int16_z |= ((crypto_int16) (*crypto_int16_s++)) << 8;
  ಹಿಂತಿರುಗಿ crypto_int16_z;
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
ಶೂನ್ಯ crypto_int16_store(ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *crypto_int16_s,crypto_int16 crypto_int16_x) {
  *crypto_int16_s++ = crypto_int16_x >> 0;
  *crypto_int16_s++ = crypto_int16_x >> 8;
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int16 crypto_int16_negative_ಮುಖವಾಡ(crypto_int16 crypto_int16_x) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarw $15,%0" : "+r"(crypto_int16_x) : : "cc");
  ಹಿಂತಿರುಗಿ crypto_int16_x;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_y;
  __asm__ ("sbfx %w0,%w1,15,1" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) : );
  ಹಿಂತಿರುಗಿ crypto_int16_y;
#ಇಲ್ಲದಿದ್ದರೆ
  crypto_int16_x >>= 16-6;
  crypto_int16_x ^= crypto_int16_optblocker;
  crypto_int16_x >>= 5;
  ಹಿಂತಿರುಗಿ crypto_int16_x;
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int16_unsigned crypto_int16_unsigned_topbit_01(crypto_int16_unsigned crypto_int16_x) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("shrw $15,%0" : "+r"(crypto_int16_x) : : "cc");
  ಹಿಂತಿರುಗಿ crypto_int16_x;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_y;
  __asm__ ("ubfx %w0,%w1,15,1" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) : );
  ಹಿಂತಿರುಗಿ crypto_int16_y;
#ಇಲ್ಲದಿದ್ದರೆ
  crypto_int16_x >>= 16-6;
  crypto_int16_x ^= crypto_int16_optblocker;
  crypto_int16_x >>= 5;
  ಹಿಂತಿರುಗಿ crypto_int16_x;
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int16 crypto_int16_negative_01(crypto_int16 crypto_int16_x) {
  ಹಿಂತಿರುಗಿ crypto_int16_unsigned_topbit_01(crypto_int16_x);
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int16 crypto_int16_topbit_ಮುಖವಾಡ(crypto_int16 crypto_int16_x) {
  ಹಿಂತಿರುಗಿ crypto_int16_negative_ಮುಖವಾಡ(crypto_int16_x);
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int16 crypto_int16_topbit_01(crypto_int16 crypto_int16_x) {
  ಹಿಂತಿರುಗಿ crypto_int16_unsigned_topbit_01(crypto_int16_x);
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int16 crypto_int16_bottombit_ಮುಖವಾಡ(crypto_int16 crypto_int16_x) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andw $1,%0" : "+r"(crypto_int16_x) : : "cc");
  ಹಿಂತಿರುಗಿ -crypto_int16_x;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_y;
  __asm__ ("sbfx %w0,%w1,0,1" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) : );
  ಹಿಂತಿರುಗಿ crypto_int16_y;
#ಇಲ್ಲದಿದ್ದರೆ
  crypto_int16_x &= 1 ^ crypto_int16_optblocker;
  ಹಿಂತಿರುಗಿ -crypto_int16_x;
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int16 crypto_int16_bottombit_01(crypto_int16 crypto_int16_x) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andw $1,%0" : "+r"(crypto_int16_x) : : "cc");
  ಹಿಂತಿರುಗಿ crypto_int16_x;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_y;
  __asm__ ("ubfx %w0,%w1,0,1" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) : );
  ಹಿಂತಿರುಗಿ crypto_int16_y;
#ಇಲ್ಲದಿದ್ದರೆ
  crypto_int16_x &= 1 ^ crypto_int16_optblocker;
  ಹಿಂತಿರುಗಿ crypto_int16_x;
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int16 crypto_int16_bitinrangepublicpos_ಮುಖವಾಡ(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarw %%cl,%0" : "+r"(crypto_int16_x) : "c"(crypto_int16_s) : "cc");
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("sxth %w0,%w0\n asr %w0,%w0,%w1" : "+&r"(crypto_int16_x) : "r"(crypto_int16_s) : );
#ಇಲ್ಲದಿದ್ದರೆ
  crypto_int16_x >>= crypto_int16_s ^ crypto_int16_optblocker;
#ಆದರೆ_ಅಂತ್ಯ
  ಹಿಂತಿರುಗಿ crypto_int16_bottombit_ಮುಖವಾಡ(crypto_int16_x);
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int16 crypto_int16_bitinrangepublicpos_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarw %%cl,%0" : "+r"(crypto_int16_x) : "c"(crypto_int16_s) : "cc");
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("sxth %w0,%w0\n asr %w0,%w0,%w1" : "+&r"(crypto_int16_x) : "r"(crypto_int16_s) : );
#ಇಲ್ಲದಿದ್ದರೆ
  crypto_int16_x >>= crypto_int16_s ^ crypto_int16_optblocker;
#ಆದರೆ_ಅಂತ್ಯ
  ಹಿಂತಿರುಗಿ crypto_int16_bottombit_01(crypto_int16_x);
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int16 crypto_int16_shlmod(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16_s &= 15;
  __asm__ ("shlw %%cl,%0" : "+r"(crypto_int16_x) : "c"(crypto_int16_s) : "cc");
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("and %w0,%w0,15\n and %w1,%w1,65535\n lsl %w1,%w1,%w0" : "+&r"(crypto_int16_s), "+r"(crypto_int16_x) : : );
#ಇಲ್ಲದಿದ್ದರೆ
  ಪೂರ್ಣಾಂಕ crypto_int16_k, crypto_int16_l;
  ಗಾಗಿ (crypto_int16_l = 0,crypto_int16_k = 1;crypto_int16_k < 16;++crypto_int16_l,crypto_int16_k *= 2)
    crypto_int16_x ^= (crypto_int16_x ^ (crypto_int16_x << crypto_int16_k)) & crypto_int16_bitinrangepublicpos_ಮುಖವಾಡ(crypto_int16_s,crypto_int16_l);
#ಆದರೆ_ಅಂತ್ಯ
  ಹಿಂತಿರುಗಿ crypto_int16_x;
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int16 crypto_int16_shrmod(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16_s &= 15;
  __asm__ ("sarw %%cl,%0" : "+r"(crypto_int16_x) : "c"(crypto_int16_s) : "cc");
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("and %w0,%w0,15\n sxth %w1,%w1\n asr %w1,%w1,%w0" : "+&r"(crypto_int16_s), "+r"(crypto_int16_x) : : );
#ಇಲ್ಲದಿದ್ದರೆ
  ಪೂರ್ಣಾಂಕ crypto_int16_k, crypto_int16_l;
  ಗಾಗಿ (crypto_int16_l = 0,crypto_int16_k = 1;crypto_int16_k < 16;++crypto_int16_l,crypto_int16_k *= 2)
    crypto_int16_x ^= (crypto_int16_x ^ (crypto_int16_x >> crypto_int16_k)) & crypto_int16_bitinrangepublicpos_ಮುಖವಾಡ(crypto_int16_s,crypto_int16_l);
#ಆದರೆ_ಅಂತ್ಯ
  ಹಿಂತಿರುಗಿ crypto_int16_x;
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int16 crypto_int16_bitmod_ಮುಖವಾಡ(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
  crypto_int16_x = crypto_int16_shrmod(crypto_int16_x,crypto_int16_s);
  ಹಿಂತಿರುಗಿ crypto_int16_bottombit_ಮುಖವಾಡ(crypto_int16_x);
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int16 crypto_int16_bitmod_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
  crypto_int16_x = crypto_int16_shrmod(crypto_int16_x,crypto_int16_s);
  ಹಿಂತಿರುಗಿ crypto_int16_bottombit_01(crypto_int16_x);
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int16 crypto_int16_nonzero_ಮುಖವಾಡ(crypto_int16 crypto_int16_x) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n testw %2,%2\n cmovnew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int16_z;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("tst %w1,65535\n csetm %w0,ne" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int16_z;
#ಇಲ್ಲದಿದ್ದರೆ
  crypto_int16_x |= -crypto_int16_x;
  ಹಿಂತಿರುಗಿ crypto_int16_negative_ಮುಖವಾಡ(crypto_int16_x);
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int16 crypto_int16_nonzero_01(crypto_int16 crypto_int16_x) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n testw %2,%2\n cmovnew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int16_z;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("tst %w1,65535\n cset %w0,ne" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int16_z;
#ಇಲ್ಲದಿದ್ದರೆ
  crypto_int16_x |= -crypto_int16_x;
  ಹಿಂತಿರುಗಿ crypto_int16_unsigned_topbit_01(crypto_int16_x);
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int16 crypto_int16_ಧನಾತ್ಮಕ_ಮುಖವಾಡ(crypto_int16 crypto_int16_x) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n testw %2,%2\n cmovgw %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int16_z;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,0\n csetm %w0,gt" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int16_z;
#ಇಲ್ಲದಿದ್ದರೆ
  crypto_int16 crypto_int16_z = -crypto_int16_x;
  crypto_int16_z ^= crypto_int16_x & crypto_int16_z;
  ಹಿಂತಿರುಗಿ crypto_int16_negative_ಮುಖವಾಡ(crypto_int16_z);
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int16 crypto_int16_ಧನಾತ್ಮಕ_01(crypto_int16 crypto_int16_x) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n testw %2,%2\n cmovgw %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int16_z;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,0\n cset %w0,gt" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int16_z;
#ಇಲ್ಲದಿದ್ದರೆ
  crypto_int16 crypto_int16_z = -crypto_int16_x;
  crypto_int16_z ^= crypto_int16_x & crypto_int16_z;
  ಹಿಂತಿರುಗಿ crypto_int16_unsigned_topbit_01(crypto_int16_z);
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int16 crypto_int16_zero_ಮುಖವಾಡ(crypto_int16 crypto_int16_x) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n testw %2,%2\n cmovew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int16_z;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("tst %w1,65535\n csetm %w0,eq" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int16_z;
#ಇಲ್ಲದಿದ್ದರೆ
  ಹಿಂತಿರುಗಿ ~crypto_int16_nonzero_ಮುಖವಾಡ(crypto_int16_x);
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int16 crypto_int16_zero_01(crypto_int16 crypto_int16_x) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n testw %2,%2\n cmovew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int16_z;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("tst %w1,65535\n cset %w0,eq" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int16_z;
#ಇಲ್ಲದಿದ್ದರೆ
  ಹಿಂತಿರುಗಿ 1-crypto_int16_nonzero_01(crypto_int16_x);
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int16 crypto_int16_unequal_ಮುಖವಾಡ(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n cmpw %3,%2\n cmovnew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int16_z;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("and %w0,%w1,65535\n cmp %w0,%w2,uxth\n csetm %w0,ne" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int16_z;
#ಇಲ್ಲದಿದ್ದರೆ
  ಹಿಂತಿರುಗಿ crypto_int16_nonzero_ಮುಖವಾಡ(crypto_int16_x ^ crypto_int16_y);
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int16 crypto_int16_unequal_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n cmpw %3,%2\n cmovnew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int16_z;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("and %w0,%w1,65535\n cmp %w0,%w2,uxth\n cset %w0,ne" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int16_z;
#ಇಲ್ಲದಿದ್ದರೆ
  ಹಿಂತಿರುಗಿ crypto_int16_nonzero_01(crypto_int16_x ^ crypto_int16_y);
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int16 crypto_int16_equal_ಮುಖವಾಡ(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n cmpw %3,%2\n cmovew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int16_z;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("and %w0,%w1,65535\n cmp %w0,%w2,uxth\n csetm %w0,eq" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int16_z;
#ಇಲ್ಲದಿದ್ದರೆ
  ಹಿಂತಿರುಗಿ ~crypto_int16_unequal_ಮುಖವಾಡ(crypto_int16_x,crypto_int16_y);
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int16 crypto_int16_equal_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n cmpw %3,%2\n cmovew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int16_z;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("and %w0,%w1,65535\n cmp %w0,%w2,uxth\n cset %w0,eq" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int16_z;
#ಇಲ್ಲದಿದ್ದರೆ
  ಹಿಂತಿರುಗಿ 1-crypto_int16_unequal_01(crypto_int16_x,crypto_int16_y);
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int16 crypto_int16_min(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpw %1,%0\n cmovgw %1,%0" : "+r"(crypto_int16_x) : "r"(crypto_int16_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int16_x;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("sxth %w0,%w0\n cmp %w0,%w1,sxth\n csel %w0,%w0,%w1,lt" : "+&r"(crypto_int16_x) : "r"(crypto_int16_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int16_x;
#ಇಲ್ಲದಿದ್ದರೆ
  crypto_int16 crypto_int16_r = crypto_int16_y ^ crypto_int16_x;
  crypto_int16 crypto_int16_z = crypto_int16_y - crypto_int16_x;
  crypto_int16_z ^= crypto_int16_r & (crypto_int16_z ^ crypto_int16_y);
  crypto_int16_z = crypto_int16_negative_ಮುಖವಾಡ(crypto_int16_z);
  crypto_int16_z &= crypto_int16_r;
  ಹಿಂತಿರುಗಿ crypto_int16_x ^ crypto_int16_z;
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int16 crypto_int16_max(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpw %1,%0\n cmovlw %1,%0" : "+r"(crypto_int16_x) : "r"(crypto_int16_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int16_x;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("sxth %w0,%w0\n cmp %w0,%w1,sxth\n csel %w0,%w1,%w0,lt" : "+&r"(crypto_int16_x) : "r"(crypto_int16_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int16_x;
#ಇಲ್ಲದಿದ್ದರೆ
  crypto_int16 crypto_int16_r = crypto_int16_y ^ crypto_int16_x;
  crypto_int16 crypto_int16_z = crypto_int16_y - crypto_int16_x;
  crypto_int16_z ^= crypto_int16_r & (crypto_int16_z ^ crypto_int16_y);
  crypto_int16_z = crypto_int16_negative_ಮುಖವಾಡ(crypto_int16_z);
  crypto_int16_z &= crypto_int16_r;
  ಹಿಂತಿರುಗಿ crypto_int16_y ^ crypto_int16_z;
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
ಶೂನ್ಯ crypto_int16_minmax(crypto_int16 *crypto_int16_p,crypto_int16 *crypto_int16_q) {
  crypto_int16 crypto_int16_x = *crypto_int16_p;
  crypto_int16 crypto_int16_y = *crypto_int16_q;
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("cmpw %2,%1\n movw %1,%0\n cmovgw %2,%1\n cmovgw %0,%2" : "=&r"(crypto_int16_z), "+&r"(crypto_int16_x), "+r"(crypto_int16_y) : : "cc");
  *crypto_int16_p = crypto_int16_x;
  *crypto_int16_q = crypto_int16_y;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_r, crypto_int16_s;
  __asm__ ("sxth %w0,%w0\n cmp %w0,%w3,sxth\n csel %w1,%w0,%w3,lt\n csel %w2,%w3,%w0,lt" : "+&r"(crypto_int16_x), "=&r"(crypto_int16_r), "=r"(crypto_int16_s) : "r"(crypto_int16_y) : "cc");
  *crypto_int16_p = crypto_int16_r;
  *crypto_int16_q = crypto_int16_s;
#ಇಲ್ಲದಿದ್ದರೆ
  crypto_int16 crypto_int16_r = crypto_int16_y ^ crypto_int16_x;
  crypto_int16 crypto_int16_z = crypto_int16_y - crypto_int16_x;
  crypto_int16_z ^= crypto_int16_r & (crypto_int16_z ^ crypto_int16_y);
  crypto_int16_z = crypto_int16_negative_ಮುಖವಾಡ(crypto_int16_z);
  crypto_int16_z &= crypto_int16_r;
  crypto_int16_x ^= crypto_int16_z;
  crypto_int16_y ^= crypto_int16_z;
  *crypto_int16_p = crypto_int16_x;
  *crypto_int16_q = crypto_int16_y;
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int16 crypto_int16_smaller_ಮುಖವಾಡ(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n cmpw %3,%2\n cmovlw %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int16_z;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,%w2,sxth\n csetm %w0,lt" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int16_z;
#ಇಲ್ಲದಿದ್ದರೆ
  crypto_int16 crypto_int16_r = crypto_int16_x ^ crypto_int16_y;
  crypto_int16 crypto_int16_z = crypto_int16_x - crypto_int16_y;
  crypto_int16_z ^= crypto_int16_r & (crypto_int16_z ^ crypto_int16_x);
  ಹಿಂತಿರುಗಿ crypto_int16_negative_ಮುಖವಾಡ(crypto_int16_z);
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int16 crypto_int16_smaller_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n cmpw %3,%2\n cmovlw %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int16_z;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,%w2,sxth\n cset %w0,lt" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int16_z;
#ಇಲ್ಲದಿದ್ದರೆ
  crypto_int16 crypto_int16_r = crypto_int16_x ^ crypto_int16_y;
  crypto_int16 crypto_int16_z = crypto_int16_x - crypto_int16_y;
  crypto_int16_z ^= crypto_int16_r & (crypto_int16_z ^ crypto_int16_x);
  ಹಿಂತಿರುಗಿ crypto_int16_unsigned_topbit_01(crypto_int16_z);
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int16 crypto_int16_leq_ಮುಖವಾಡ(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n cmpw %3,%2\n cmovlew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int16_z;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,%w2,sxth\n csetm %w0,le" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int16_z;
#ಇಲ್ಲದಿದ್ದರೆ
  ಹಿಂತಿರುಗಿ ~crypto_int16_smaller_ಮುಖವಾಡ(crypto_int16_y,crypto_int16_x);
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int16 crypto_int16_leq_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n cmpw %3,%2\n cmovlew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int16_z;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,%w2,sxth\n cset %w0,le" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int16_z;
#ಇಲ್ಲದಿದ್ದರೆ
  ಹಿಂತಿರುಗಿ 1-crypto_int16_smaller_01(crypto_int16_y,crypto_int16_x);
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
ಪೂರ್ಣಾಂಕ crypto_int16_ones_ಅಂಕೆ(crypto_int16 crypto_int16_x) {
  crypto_int16_unsigned crypto_int16_y = crypto_int16_x;
  ಸ್ಥಿರಾಂಕ crypto_int16 C0 = 0x5555;
  ಸ್ಥಿರಾಂಕ crypto_int16 C1 = 0x3333;
  ಸ್ಥಿರಾಂಕ crypto_int16 C2 = 0x0f0f;
  crypto_int16_y -= ((crypto_int16_y >> 1) & C0);
  crypto_int16_y = (crypto_int16_y & C1) + ((crypto_int16_y >> 2) & C1);
  crypto_int16_y = (crypto_int16_y + (crypto_int16_y >> 4)) & C2;
  crypto_int16_y = (crypto_int16_y + (crypto_int16_y >> 8)) & 0xff;
  ಹಿಂತಿರುಗಿ crypto_int16_y;
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
ಪೂರ್ಣಾಂಕ crypto_int16_bottomzeros_ಅಂಕೆ(crypto_int16 crypto_int16_x) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 fallback = 16;
  __asm__ ("bsfw %0,%0\n cmovew %1,%0" : "+&r"(crypto_int16_x) : "r"(fallback) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int16_x;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  int64_t crypto_int16_y;
  __asm__ ("orr %w0,%w1,-65536\n rbit %w0,%w0\n clz %w0,%w0" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) : );
  ಹಿಂತಿರುಗಿ crypto_int16_y;
#ಇಲ್ಲದಿದ್ದರೆ
  crypto_int16 crypto_int16_y = crypto_int16_x ^ (crypto_int16_x-1);
  crypto_int16_y = ((crypto_int16) crypto_int16_y) >> 1;
  crypto_int16_y &= ~(crypto_int16_x & (((crypto_int16) 1) << (16-1)));
  ಹಿಂತಿರುಗಿ crypto_int16_ones_ಅಂಕೆ(crypto_int16_y);
#ಆದರೆ_ಅಂತ್ಯ
}

#ಆದರೆ_ಅಂತ್ಯ

/* from supercop-20240808/cryptoint/crypto_int32.h */
/* auto-generated: cd cryptoint; ./autogen */
/* cryptoint 20240806 */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ crypto_int32_h
#ವ್ಯಾಖ್ಯಾನಿಸು crypto_int32_h

#ವ್ಯಾಖ್ಯಾನಿಸು crypto_int32 int32_t
#ವ್ಯಾಖ್ಯಾನಿಸು crypto_int32_unsigned uint32_t



__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int32 crypto_int32_ತುಂಬು(ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *crypto_int32_s) {
  crypto_int32 crypto_int32_z = 0;
  crypto_int32_z |= ((crypto_int32) (*crypto_int32_s++)) << 0;
  crypto_int32_z |= ((crypto_int32) (*crypto_int32_s++)) << 8;
  crypto_int32_z |= ((crypto_int32) (*crypto_int32_s++)) << 16;
  crypto_int32_z |= ((crypto_int32) (*crypto_int32_s++)) << 24;
  ಹಿಂತಿರುಗಿ crypto_int32_z;
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
ಶೂನ್ಯ crypto_int32_store(ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *crypto_int32_s,crypto_int32 crypto_int32_x) {
  *crypto_int32_s++ = crypto_int32_x >> 0;
  *crypto_int32_s++ = crypto_int32_x >> 8;
  *crypto_int32_s++ = crypto_int32_x >> 16;
  *crypto_int32_s++ = crypto_int32_x >> 24;
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int32 crypto_int32_negative_ಮುಖವಾಡ(crypto_int32 crypto_int32_x) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarl $31,%0" : "+r"(crypto_int32_x) : : "cc");
  ಹಿಂತಿರುಗಿ crypto_int32_x;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_y;
  __asm__ ("asr %w0,%w1,31" : "=r"(crypto_int32_y) : "r"(crypto_int32_x) : );
  ಹಿಂತಿರುಗಿ crypto_int32_y;
#ಇಲ್ಲದಿದ್ದರೆ
  crypto_int32_x >>= 32-6;
  crypto_int32_x ^= crypto_int32_optblocker;
  crypto_int32_x >>= 5;
  ಹಿಂತಿರುಗಿ crypto_int32_x;
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int32_unsigned crypto_int32_unsigned_topbit_01(crypto_int32_unsigned crypto_int32_x) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("shrl $31,%0" : "+r"(crypto_int32_x) : : "cc");
  ಹಿಂತಿರುಗಿ crypto_int32_x;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_y;
  __asm__ ("lsr %w0,%w1,31" : "=r"(crypto_int32_y) : "r"(crypto_int32_x) : );
  ಹಿಂತಿರುಗಿ crypto_int32_y;
#ಇಲ್ಲದಿದ್ದರೆ
  crypto_int32_x >>= 32-6;
  crypto_int32_x ^= crypto_int32_optblocker;
  crypto_int32_x >>= 5;
  ಹಿಂತಿರುಗಿ crypto_int32_x;
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int32 crypto_int32_negative_01(crypto_int32 crypto_int32_x) {
  ಹಿಂತಿರುಗಿ crypto_int32_unsigned_topbit_01(crypto_int32_x);
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int32 crypto_int32_topbit_ಮುಖವಾಡ(crypto_int32 crypto_int32_x) {
  ಹಿಂತಿರುಗಿ crypto_int32_negative_ಮುಖವಾಡ(crypto_int32_x);
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int32 crypto_int32_topbit_01(crypto_int32 crypto_int32_x) {
  ಹಿಂತಿರುಗಿ crypto_int32_unsigned_topbit_01(crypto_int32_x);
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int32 crypto_int32_bottombit_ಮುಖವಾಡ(crypto_int32 crypto_int32_x) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andl $1,%0" : "+r"(crypto_int32_x) : : "cc");
  ಹಿಂತಿರುಗಿ -crypto_int32_x;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_y;
  __asm__ ("sbfx %w0,%w1,0,1" : "=r"(crypto_int32_y) : "r"(crypto_int32_x) : );
  ಹಿಂತಿರುಗಿ crypto_int32_y;
#ಇಲ್ಲದಿದ್ದರೆ
  crypto_int32_x &= 1 ^ crypto_int32_optblocker;
  ಹಿಂತಿರುಗಿ -crypto_int32_x;
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int32 crypto_int32_bottombit_01(crypto_int32 crypto_int32_x) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andl $1,%0" : "+r"(crypto_int32_x) : : "cc");
  ಹಿಂತಿರುಗಿ crypto_int32_x;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_y;
  __asm__ ("ubfx %w0,%w1,0,1" : "=r"(crypto_int32_y) : "r"(crypto_int32_x) : );
  ಹಿಂತಿರುಗಿ crypto_int32_y;
#ಇಲ್ಲದಿದ್ದರೆ
  crypto_int32_x &= 1 ^ crypto_int32_optblocker;
  ಹಿಂತಿರುಗಿ crypto_int32_x;
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int32 crypto_int32_bitinrangepublicpos_ಮುಖವಾಡ(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarl %%cl,%0" : "+r"(crypto_int32_x) : "c"(crypto_int32_s) : "cc");
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %w0,%w0,%w1" : "+r"(crypto_int32_x) : "r"(crypto_int32_s) : );
#ಇಲ್ಲದಿದ್ದರೆ
  crypto_int32_x >>= crypto_int32_s ^ crypto_int32_optblocker;
#ಆದರೆ_ಅಂತ್ಯ
  ಹಿಂತಿರುಗಿ crypto_int32_bottombit_ಮುಖವಾಡ(crypto_int32_x);
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int32 crypto_int32_bitinrangepublicpos_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarl %%cl,%0" : "+r"(crypto_int32_x) : "c"(crypto_int32_s) : "cc");
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %w0,%w0,%w1" : "+r"(crypto_int32_x) : "r"(crypto_int32_s) : );
#ಇಲ್ಲದಿದ್ದರೆ
  crypto_int32_x >>= crypto_int32_s ^ crypto_int32_optblocker;
#ಆದರೆ_ಅಂತ್ಯ
  ಹಿಂತಿರುಗಿ crypto_int32_bottombit_01(crypto_int32_x);
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int32 crypto_int32_shlmod(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("shll %%cl,%0" : "+r"(crypto_int32_x) : "c"(crypto_int32_s) : "cc");
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("lsl %w0,%w0,%w1" : "+r"(crypto_int32_x) : "r"(crypto_int32_s) : );
#ಇಲ್ಲದಿದ್ದರೆ
  ಪೂರ್ಣಾಂಕ crypto_int32_k, crypto_int32_l;
  ಗಾಗಿ (crypto_int32_l = 0,crypto_int32_k = 1;crypto_int32_k < 32;++crypto_int32_l,crypto_int32_k *= 2)
    crypto_int32_x ^= (crypto_int32_x ^ (crypto_int32_x << crypto_int32_k)) & crypto_int32_bitinrangepublicpos_ಮುಖವಾಡ(crypto_int32_s,crypto_int32_l);
#ಆದರೆ_ಅಂತ್ಯ
  ಹಿಂತಿರುಗಿ crypto_int32_x;
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int32 crypto_int32_shrmod(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarl %%cl,%0" : "+r"(crypto_int32_x) : "c"(crypto_int32_s) : "cc");
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %w0,%w0,%w1" : "+r"(crypto_int32_x) : "r"(crypto_int32_s) : );
#ಇಲ್ಲದಿದ್ದರೆ
  ಪೂರ್ಣಾಂಕ crypto_int32_k, crypto_int32_l;
  ಗಾಗಿ (crypto_int32_l = 0,crypto_int32_k = 1;crypto_int32_k < 32;++crypto_int32_l,crypto_int32_k *= 2)
    crypto_int32_x ^= (crypto_int32_x ^ (crypto_int32_x >> crypto_int32_k)) & crypto_int32_bitinrangepublicpos_ಮುಖವಾಡ(crypto_int32_s,crypto_int32_l);
#ಆದರೆ_ಅಂತ್ಯ
  ಹಿಂತಿರುಗಿ crypto_int32_x;
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int32 crypto_int32_bitmod_ಮುಖವಾಡ(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
  crypto_int32_x = crypto_int32_shrmod(crypto_int32_x,crypto_int32_s);
  ಹಿಂತಿರುಗಿ crypto_int32_bottombit_ಮುಖವಾಡ(crypto_int32_x);
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int32 crypto_int32_bitmod_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
  crypto_int32_x = crypto_int32_shrmod(crypto_int32_x,crypto_int32_s);
  ಹಿಂತಿರುಗಿ crypto_int32_bottombit_01(crypto_int32_x);
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int32 crypto_int32_nonzero_ಮುಖವಾಡ(crypto_int32 crypto_int32_x) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n testl %2,%2\n cmovnel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int32_z;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n csetm %w0,ne" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int32_z;
#ಇಲ್ಲದಿದ್ದರೆ
  crypto_int32_x |= -crypto_int32_x;
  ಹಿಂತಿರುಗಿ crypto_int32_negative_ಮುಖವಾಡ(crypto_int32_x);
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int32 crypto_int32_nonzero_01(crypto_int32 crypto_int32_x) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n testl %2,%2\n cmovnel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int32_z;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n cset %w0,ne" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int32_z;
#ಇಲ್ಲದಿದ್ದರೆ
  crypto_int32_x |= -crypto_int32_x;
  ಹಿಂತಿರುಗಿ crypto_int32_unsigned_topbit_01(crypto_int32_x);
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int32 crypto_int32_ಧನಾತ್ಮಕ_ಮುಖವಾಡ(crypto_int32 crypto_int32_x) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n testl %2,%2\n cmovgl %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int32_z;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n csetm %w0,gt" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int32_z;
#ಇಲ್ಲದಿದ್ದರೆ
  crypto_int32 crypto_int32_z = -crypto_int32_x;
  crypto_int32_z ^= crypto_int32_x & crypto_int32_z;
  ಹಿಂತಿರುಗಿ crypto_int32_negative_ಮುಖವಾಡ(crypto_int32_z);
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int32 crypto_int32_ಧನಾತ್ಮಕ_01(crypto_int32 crypto_int32_x) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n testl %2,%2\n cmovgl %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int32_z;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n cset %w0,gt" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int32_z;
#ಇಲ್ಲದಿದ್ದರೆ
  crypto_int32 crypto_int32_z = -crypto_int32_x;
  crypto_int32_z ^= crypto_int32_x & crypto_int32_z;
  ಹಿಂತಿರುಗಿ crypto_int32_unsigned_topbit_01(crypto_int32_z);
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int32 crypto_int32_zero_ಮುಖವಾಡ(crypto_int32 crypto_int32_x) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n testl %2,%2\n cmovel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int32_z;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n csetm %w0,eq" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int32_z;
#ಇಲ್ಲದಿದ್ದರೆ
  ಹಿಂತಿರುಗಿ ~crypto_int32_nonzero_ಮುಖವಾಡ(crypto_int32_x);
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int32 crypto_int32_zero_01(crypto_int32 crypto_int32_x) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n testl %2,%2\n cmovel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int32_z;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n cset %w0,eq" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int32_z;
#ಇಲ್ಲದಿದ್ದರೆ
  ಹಿಂತಿರುಗಿ 1-crypto_int32_nonzero_01(crypto_int32_x);
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int32 crypto_int32_unequal_ಮುಖವಾಡ(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n cmpl %3,%2\n cmovnel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int32_z;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n csetm %w0,ne" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int32_z;
#ಇಲ್ಲದಿದ್ದರೆ
  ಹಿಂತಿರುಗಿ crypto_int32_nonzero_ಮುಖವಾಡ(crypto_int32_x ^ crypto_int32_y);
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int32 crypto_int32_unequal_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n cmpl %3,%2\n cmovnel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int32_z;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n cset %w0,ne" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int32_z;
#ಇಲ್ಲದಿದ್ದರೆ
  ಹಿಂತಿರುಗಿ crypto_int32_nonzero_01(crypto_int32_x ^ crypto_int32_y);
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int32 crypto_int32_equal_ಮುಖವಾಡ(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n cmpl %3,%2\n cmovel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int32_z;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n csetm %w0,eq" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int32_z;
#ಇಲ್ಲದಿದ್ದರೆ
  ಹಿಂತಿರುಗಿ ~crypto_int32_unequal_ಮುಖವಾಡ(crypto_int32_x,crypto_int32_y);
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int32 crypto_int32_equal_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n cmpl %3,%2\n cmovel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int32_z;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n cset %w0,eq" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int32_z;
#ಇಲ್ಲದಿದ್ದರೆ
  ಹಿಂತಿರುಗಿ 1-crypto_int32_unequal_01(crypto_int32_x,crypto_int32_y);
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int32 crypto_int32_min(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpl %1,%0\n cmovgl %1,%0" : "+r"(crypto_int32_x) : "r"(crypto_int32_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int32_x;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("cmp %w0,%w1\n csel %w0,%w0,%w1,lt" : "+r"(crypto_int32_x) : "r"(crypto_int32_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int32_x;
#ಇಲ್ಲದಿದ್ದರೆ
  crypto_int64 crypto_int32_r = (crypto_int64)crypto_int32_y ^ (crypto_int64)crypto_int32_x;
  crypto_int64 crypto_int32_z = (crypto_int64)crypto_int32_y - (crypto_int64)crypto_int32_x;
  crypto_int32_z ^= crypto_int32_r & (crypto_int32_z ^ crypto_int32_y);
  crypto_int32_z = crypto_int32_negative_ಮುಖವಾಡ(crypto_int32_z);
  crypto_int32_z &= crypto_int32_r;
  ಹಿಂತಿರುಗಿ crypto_int32_x ^ crypto_int32_z;
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int32 crypto_int32_max(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpl %1,%0\n cmovll %1,%0" : "+r"(crypto_int32_x) : "r"(crypto_int32_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int32_x;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("cmp %w0,%w1\n csel %w0,%w1,%w0,lt" : "+r"(crypto_int32_x) : "r"(crypto_int32_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int32_x;
#ಇಲ್ಲದಿದ್ದರೆ
  crypto_int64 crypto_int32_r = (crypto_int64)crypto_int32_y ^ (crypto_int64)crypto_int32_x;
  crypto_int64 crypto_int32_z = (crypto_int64)crypto_int32_y - (crypto_int64)crypto_int32_x;
  crypto_int32_z ^= crypto_int32_r & (crypto_int32_z ^ crypto_int32_y);
  crypto_int32_z = crypto_int32_negative_ಮುಖವಾಡ(crypto_int32_z);
  crypto_int32_z &= crypto_int32_r;
  ಹಿಂತಿರುಗಿ crypto_int32_y ^ crypto_int32_z;
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
ಶೂನ್ಯ crypto_int32_minmax(crypto_int32 *crypto_int32_p,crypto_int32 *crypto_int32_q) {
  crypto_int32 crypto_int32_x = *crypto_int32_p;
  crypto_int32 crypto_int32_y = *crypto_int32_q;
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmpl %2,%1\n movl %1,%0\n cmovgl %2,%1\n cmovgl %0,%2" : "=&r"(crypto_int32_z), "+&r"(crypto_int32_x), "+r"(crypto_int32_y) : : "cc");
  *crypto_int32_p = crypto_int32_x;
  *crypto_int32_q = crypto_int32_y;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_r, crypto_int32_s;
  __asm__ ("cmp %w2,%w3\n csel %w0,%w2,%w3,lt\n csel %w1,%w3,%w2,lt" : "=&r"(crypto_int32_r), "=r"(crypto_int32_s) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  *crypto_int32_p = crypto_int32_r;
  *crypto_int32_q = crypto_int32_s;
#ಇಲ್ಲದಿದ್ದರೆ
  crypto_int64 crypto_int32_r = (crypto_int64)crypto_int32_y ^ (crypto_int64)crypto_int32_x;
  crypto_int64 crypto_int32_z = (crypto_int64)crypto_int32_y - (crypto_int64)crypto_int32_x;
  crypto_int32_z ^= crypto_int32_r & (crypto_int32_z ^ crypto_int32_y);
  crypto_int32_z = crypto_int32_negative_ಮುಖವಾಡ(crypto_int32_z);
  crypto_int32_z &= crypto_int32_r;
  crypto_int32_x ^= crypto_int32_z;
  crypto_int32_y ^= crypto_int32_z;
  *crypto_int32_p = crypto_int32_x;
  *crypto_int32_q = crypto_int32_y;
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int32 crypto_int32_smaller_ಮುಖವಾಡ(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n cmpl %3,%2\n cmovll %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int32_z;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n csetm %w0,lt" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int32_z;
#ಇಲ್ಲದಿದ್ದರೆ
  crypto_int32 crypto_int32_r = crypto_int32_x ^ crypto_int32_y;
  crypto_int32 crypto_int32_z = crypto_int32_x - crypto_int32_y;
  crypto_int32_z ^= crypto_int32_r & (crypto_int32_z ^ crypto_int32_x);
  ಹಿಂತಿರುಗಿ crypto_int32_negative_ಮುಖವಾಡ(crypto_int32_z);
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int32 crypto_int32_smaller_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n cmpl %3,%2\n cmovll %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int32_z;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n cset %w0,lt" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int32_z;
#ಇಲ್ಲದಿದ್ದರೆ
  crypto_int32 crypto_int32_r = crypto_int32_x ^ crypto_int32_y;
  crypto_int32 crypto_int32_z = crypto_int32_x - crypto_int32_y;
  crypto_int32_z ^= crypto_int32_r & (crypto_int32_z ^ crypto_int32_x);
  ಹಿಂತಿರುಗಿ crypto_int32_unsigned_topbit_01(crypto_int32_z);
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int32 crypto_int32_leq_ಮುಖವಾಡ(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n cmpl %3,%2\n cmovlel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int32_z;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n csetm %w0,le" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int32_z;
#ಇಲ್ಲದಿದ್ದರೆ
  ಹಿಂತಿರುಗಿ ~crypto_int32_smaller_ಮುಖವಾಡ(crypto_int32_y,crypto_int32_x);
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int32 crypto_int32_leq_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n cmpl %3,%2\n cmovlel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int32_z;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n cset %w0,le" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int32_z;
#ಇಲ್ಲದಿದ್ದರೆ
  ಹಿಂತಿರುಗಿ 1-crypto_int32_smaller_01(crypto_int32_y,crypto_int32_x);
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
ಪೂರ್ಣಾಂಕ crypto_int32_ones_ಅಂಕೆ(crypto_int32 crypto_int32_x) {
  crypto_int32_unsigned crypto_int32_y = crypto_int32_x;
  ಸ್ಥಿರಾಂಕ crypto_int32 C0 = 0x55555555;
  ಸ್ಥಿರಾಂಕ crypto_int32 C1 = 0x33333333;
  ಸ್ಥಿರಾಂಕ crypto_int32 C2 = 0x0f0f0f0f;
  crypto_int32_y -= ((crypto_int32_y >> 1) & C0);
  crypto_int32_y = (crypto_int32_y & C1) + ((crypto_int32_y >> 2) & C1);
  crypto_int32_y = (crypto_int32_y + (crypto_int32_y >> 4)) & C2;
  crypto_int32_y += crypto_int32_y >> 8;
  crypto_int32_y = (crypto_int32_y + (crypto_int32_y >> 16)) & 0xff;
  ಹಿಂತಿರುಗಿ crypto_int32_y;
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
ಪೂರ್ಣಾಂಕ crypto_int32_bottomzeros_ಅಂಕೆ(crypto_int32 crypto_int32_x) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 fallback = 32;
  __asm__ ("bsfl %0,%0\n cmovel %1,%0" : "+&r"(crypto_int32_x) : "r"(fallback) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int32_x;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  int64_t crypto_int32_y;
  __asm__ ("rbit %w0,%w1\n clz %w0,%w0" : "=r"(crypto_int32_y) : "r"(crypto_int32_x) : );
  ಹಿಂತಿರುಗಿ crypto_int32_y;
#ಇಲ್ಲದಿದ್ದರೆ
  crypto_int32 crypto_int32_y = crypto_int32_x ^ (crypto_int32_x-1);
  crypto_int32_y = ((crypto_int32) crypto_int32_y) >> 1;
  crypto_int32_y &= ~(crypto_int32_x & (((crypto_int32) 1) << (32-1)));
  ಹಿಂತಿರುಗಿ crypto_int32_ones_ಅಂಕೆ(crypto_int32_y);
#ಆದರೆ_ಅಂತ್ಯ
}

#ಆದರೆ_ಅಂತ್ಯ

/* from supercop-20240808/cryptoint/crypto_int64.h */
/* auto-generated: cd cryptoint; ./autogen */
/* cryptoint 20240806 */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ crypto_int64_h
#ವ್ಯಾಖ್ಯಾನಿಸು crypto_int64_h

#ವ್ಯಾಖ್ಯಾನಿಸು crypto_int64 int64_t
#ವ್ಯಾಖ್ಯಾನಿಸು crypto_int64_unsigned uint64_t



__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int64 crypto_int64_ತುಂಬು(ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *crypto_int64_s) {
  crypto_int64 crypto_int64_z = 0;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 0;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 8;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 16;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 24;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 32;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 40;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 48;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 56;
  ಹಿಂತಿರುಗಿ crypto_int64_z;
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
ಶೂನ್ಯ crypto_int64_store(ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *crypto_int64_s,crypto_int64 crypto_int64_x) {
  *crypto_int64_s++ = crypto_int64_x >> 0;
  *crypto_int64_s++ = crypto_int64_x >> 8;
  *crypto_int64_s++ = crypto_int64_x >> 16;
  *crypto_int64_s++ = crypto_int64_x >> 24;
  *crypto_int64_s++ = crypto_int64_x >> 32;
  *crypto_int64_s++ = crypto_int64_x >> 40;
  *crypto_int64_s++ = crypto_int64_x >> 48;
  *crypto_int64_s++ = crypto_int64_x >> 56;
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int64 crypto_int64_negative_ಮುಖವಾಡ(crypto_int64 crypto_int64_x) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarq $63,%0" : "+r"(crypto_int64_x) : : "cc");
  ಹಿಂತಿರುಗಿ crypto_int64_x;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_y;
  __asm__ ("asr %0,%1,63" : "=r"(crypto_int64_y) : "r"(crypto_int64_x) : );
  ಹಿಂತಿರುಗಿ crypto_int64_y;
#ಇಲ್ಲದಿದ್ದರೆ
  crypto_int64_x >>= 64-6;
  crypto_int64_x ^= crypto_int64_optblocker;
  crypto_int64_x >>= 5;
  ಹಿಂತಿರುಗಿ crypto_int64_x;
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int64_unsigned crypto_int64_unsigned_topbit_01(crypto_int64_unsigned crypto_int64_x) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("shrq $63,%0" : "+r"(crypto_int64_x) : : "cc");
  ಹಿಂತಿರುಗಿ crypto_int64_x;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_y;
  __asm__ ("lsr %0,%1,63" : "=r"(crypto_int64_y) : "r"(crypto_int64_x) : );
  ಹಿಂತಿರುಗಿ crypto_int64_y;
#ಇಲ್ಲದಿದ್ದರೆ
  crypto_int64_x >>= 64-6;
  crypto_int64_x ^= crypto_int64_optblocker;
  crypto_int64_x >>= 5;
  ಹಿಂತಿರುಗಿ crypto_int64_x;
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int64 crypto_int64_negative_01(crypto_int64 crypto_int64_x) {
  ಹಿಂತಿರುಗಿ crypto_int64_unsigned_topbit_01(crypto_int64_x);
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int64 crypto_int64_topbit_ಮುಖವಾಡ(crypto_int64 crypto_int64_x) {
  ಹಿಂತಿರುಗಿ crypto_int64_negative_ಮುಖವಾಡ(crypto_int64_x);
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int64 crypto_int64_topbit_01(crypto_int64 crypto_int64_x) {
  ಹಿಂತಿರುಗಿ crypto_int64_unsigned_topbit_01(crypto_int64_x);
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int64 crypto_int64_bottombit_ಮುಖವಾಡ(crypto_int64 crypto_int64_x) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andq $1,%0" : "+r"(crypto_int64_x) : : "cc");
  ಹಿಂತಿರುಗಿ -crypto_int64_x;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_y;
  __asm__ ("sbfx %0,%1,0,1" : "=r"(crypto_int64_y) : "r"(crypto_int64_x) : );
  ಹಿಂತಿರುಗಿ crypto_int64_y;
#ಇಲ್ಲದಿದ್ದರೆ
  crypto_int64_x &= 1 ^ crypto_int64_optblocker;
  ಹಿಂತಿರುಗಿ -crypto_int64_x;
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int64 crypto_int64_bottombit_01(crypto_int64 crypto_int64_x) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andq $1,%0" : "+r"(crypto_int64_x) : : "cc");
  ಹಿಂತಿರುಗಿ crypto_int64_x;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_y;
  __asm__ ("ubfx %0,%1,0,1" : "=r"(crypto_int64_y) : "r"(crypto_int64_x) : );
  ಹಿಂತಿರುಗಿ crypto_int64_y;
#ಇಲ್ಲದಿದ್ದರೆ
  crypto_int64_x &= 1 ^ crypto_int64_optblocker;
  ಹಿಂತಿರುಗಿ crypto_int64_x;
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int64 crypto_int64_bitinrangepublicpos_ಮುಖವಾಡ(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarq %%cl,%0" : "+r"(crypto_int64_x) : "c"(crypto_int64_s) : "cc");
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %0,%0,%1" : "+r"(crypto_int64_x) : "r"(crypto_int64_s) : );
#ಇಲ್ಲದಿದ್ದರೆ
  crypto_int64_x >>= crypto_int64_s ^ crypto_int64_optblocker;
#ಆದರೆ_ಅಂತ್ಯ
  ಹಿಂತಿರುಗಿ crypto_int64_bottombit_ಮುಖವಾಡ(crypto_int64_x);
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int64 crypto_int64_bitinrangepublicpos_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarq %%cl,%0" : "+r"(crypto_int64_x) : "c"(crypto_int64_s) : "cc");
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %0,%0,%1" : "+r"(crypto_int64_x) : "r"(crypto_int64_s) : );
#ಇಲ್ಲದಿದ್ದರೆ
  crypto_int64_x >>= crypto_int64_s ^ crypto_int64_optblocker;
#ಆದರೆ_ಅಂತ್ಯ
  ಹಿಂತಿರುಗಿ crypto_int64_bottombit_01(crypto_int64_x);
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int64 crypto_int64_shlmod(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("shlq %%cl,%0" : "+r"(crypto_int64_x) : "c"(crypto_int64_s) : "cc");
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("lsl %0,%0,%1" : "+r"(crypto_int64_x) : "r"(crypto_int64_s) : );
#ಇಲ್ಲದಿದ್ದರೆ
  ಪೂರ್ಣಾಂಕ crypto_int64_k, crypto_int64_l;
  ಗಾಗಿ (crypto_int64_l = 0,crypto_int64_k = 1;crypto_int64_k < 64;++crypto_int64_l,crypto_int64_k *= 2)
    crypto_int64_x ^= (crypto_int64_x ^ (crypto_int64_x << crypto_int64_k)) & crypto_int64_bitinrangepublicpos_ಮುಖವಾಡ(crypto_int64_s,crypto_int64_l);
#ಆದರೆ_ಅಂತ್ಯ
  ಹಿಂತಿರುಗಿ crypto_int64_x;
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int64 crypto_int64_shrmod(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarq %%cl,%0" : "+r"(crypto_int64_x) : "c"(crypto_int64_s) : "cc");
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %0,%0,%1" : "+r"(crypto_int64_x) : "r"(crypto_int64_s) : );
#ಇಲ್ಲದಿದ್ದರೆ
  ಪೂರ್ಣಾಂಕ crypto_int64_k, crypto_int64_l;
  ಗಾಗಿ (crypto_int64_l = 0,crypto_int64_k = 1;crypto_int64_k < 64;++crypto_int64_l,crypto_int64_k *= 2)
    crypto_int64_x ^= (crypto_int64_x ^ (crypto_int64_x >> crypto_int64_k)) & crypto_int64_bitinrangepublicpos_ಮುಖವಾಡ(crypto_int64_s,crypto_int64_l);
#ಆದರೆ_ಅಂತ್ಯ
  ಹಿಂತಿರುಗಿ crypto_int64_x;
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int64 crypto_int64_bitmod_ಮುಖವಾಡ(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
  crypto_int64_x = crypto_int64_shrmod(crypto_int64_x,crypto_int64_s);
  ಹಿಂತಿರುಗಿ crypto_int64_bottombit_ಮುಖವಾಡ(crypto_int64_x);
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int64 crypto_int64_bitmod_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
  crypto_int64_x = crypto_int64_shrmod(crypto_int64_x,crypto_int64_s);
  ಹಿಂತಿರುಗಿ crypto_int64_bottombit_01(crypto_int64_x);
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int64 crypto_int64_nonzero_ಮುಖವಾಡ(crypto_int64 crypto_int64_x) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n testq %2,%2\n cmovneq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int64_z;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n csetm %0,ne" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int64_z;
#ಇಲ್ಲದಿದ್ದರೆ
  crypto_int64_x |= -crypto_int64_x;
  ಹಿಂತಿರುಗಿ crypto_int64_negative_ಮುಖವಾಡ(crypto_int64_x);
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int64 crypto_int64_nonzero_01(crypto_int64 crypto_int64_x) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n testq %2,%2\n cmovneq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int64_z;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n cset %0,ne" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int64_z;
#ಇಲ್ಲದಿದ್ದರೆ
  crypto_int64_x |= -crypto_int64_x;
  ಹಿಂತಿರುಗಿ crypto_int64_unsigned_topbit_01(crypto_int64_x);
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int64 crypto_int64_ಧನಾತ್ಮಕ_ಮುಖವಾಡ(crypto_int64 crypto_int64_x) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n testq %2,%2\n cmovgq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int64_z;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n csetm %0,gt" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int64_z;
#ಇಲ್ಲದಿದ್ದರೆ
  crypto_int64 crypto_int64_z = -crypto_int64_x;
  crypto_int64_z ^= crypto_int64_x & crypto_int64_z;
  ಹಿಂತಿರುಗಿ crypto_int64_negative_ಮುಖವಾಡ(crypto_int64_z);
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int64 crypto_int64_ಧನಾತ್ಮಕ_01(crypto_int64 crypto_int64_x) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n testq %2,%2\n cmovgq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int64_z;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n cset %0,gt" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int64_z;
#ಇಲ್ಲದಿದ್ದರೆ
  crypto_int64 crypto_int64_z = -crypto_int64_x;
  crypto_int64_z ^= crypto_int64_x & crypto_int64_z;
  ಹಿಂತಿರುಗಿ crypto_int64_unsigned_topbit_01(crypto_int64_z);
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int64 crypto_int64_zero_ಮುಖವಾಡ(crypto_int64 crypto_int64_x) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n testq %2,%2\n cmoveq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int64_z;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n csetm %0,eq" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int64_z;
#ಇಲ್ಲದಿದ್ದರೆ
  ಹಿಂತಿರುಗಿ ~crypto_int64_nonzero_ಮುಖವಾಡ(crypto_int64_x);
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int64 crypto_int64_zero_01(crypto_int64 crypto_int64_x) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n testq %2,%2\n cmoveq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int64_z;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n cset %0,eq" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int64_z;
#ಇಲ್ಲದಿದ್ದರೆ
  ಹಿಂತಿರುಗಿ 1-crypto_int64_nonzero_01(crypto_int64_x);
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int64 crypto_int64_unequal_ಮುಖವಾಡ(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n cmpq %3,%2\n cmovneq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int64_z;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n csetm %0,ne" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int64_z;
#ಇಲ್ಲದಿದ್ದರೆ
  ಹಿಂತಿರುಗಿ crypto_int64_nonzero_ಮುಖವಾಡ(crypto_int64_x ^ crypto_int64_y);
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int64 crypto_int64_unequal_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n cmpq %3,%2\n cmovneq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int64_z;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n cset %0,ne" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int64_z;
#ಇಲ್ಲದಿದ್ದರೆ
  ಹಿಂತಿರುಗಿ crypto_int64_nonzero_01(crypto_int64_x ^ crypto_int64_y);
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int64 crypto_int64_equal_ಮುಖವಾಡ(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n cmpq %3,%2\n cmoveq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int64_z;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n csetm %0,eq" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int64_z;
#ಇಲ್ಲದಿದ್ದರೆ
  ಹಿಂತಿರುಗಿ ~crypto_int64_unequal_ಮುಖವಾಡ(crypto_int64_x,crypto_int64_y);
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int64 crypto_int64_equal_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n cmpq %3,%2\n cmoveq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int64_z;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n cset %0,eq" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int64_z;
#ಇಲ್ಲದಿದ್ದರೆ
  ಹಿಂತಿರುಗಿ 1-crypto_int64_unequal_01(crypto_int64_x,crypto_int64_y);
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int64 crypto_int64_min(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpq %1,%0\n cmovgq %1,%0" : "+r"(crypto_int64_x) : "r"(crypto_int64_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int64_x;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("cmp %0,%1\n csel %0,%0,%1,lt" : "+r"(crypto_int64_x) : "r"(crypto_int64_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int64_x;
#ಇಲ್ಲದಿದ್ದರೆ
  crypto_int64 crypto_int64_r = crypto_int64_y ^ crypto_int64_x;
  crypto_int64 crypto_int64_z = crypto_int64_y - crypto_int64_x;
  crypto_int64_z ^= crypto_int64_r & (crypto_int64_z ^ crypto_int64_y);
  crypto_int64_z = crypto_int64_negative_ಮುಖವಾಡ(crypto_int64_z);
  crypto_int64_z &= crypto_int64_r;
  ಹಿಂತಿರುಗಿ crypto_int64_x ^ crypto_int64_z;
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int64 crypto_int64_max(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpq %1,%0\n cmovlq %1,%0" : "+r"(crypto_int64_x) : "r"(crypto_int64_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int64_x;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("cmp %0,%1\n csel %0,%1,%0,lt" : "+r"(crypto_int64_x) : "r"(crypto_int64_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int64_x;
#ಇಲ್ಲದಿದ್ದರೆ
  crypto_int64 crypto_int64_r = crypto_int64_y ^ crypto_int64_x;
  crypto_int64 crypto_int64_z = crypto_int64_y - crypto_int64_x;
  crypto_int64_z ^= crypto_int64_r & (crypto_int64_z ^ crypto_int64_y);
  crypto_int64_z = crypto_int64_negative_ಮುಖವಾಡ(crypto_int64_z);
  crypto_int64_z &= crypto_int64_r;
  ಹಿಂತಿರುಗಿ crypto_int64_y ^ crypto_int64_z;
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
ಶೂನ್ಯ crypto_int64_minmax(crypto_int64 *crypto_int64_p,crypto_int64 *crypto_int64_q) {
  crypto_int64 crypto_int64_x = *crypto_int64_p;
  crypto_int64 crypto_int64_y = *crypto_int64_q;
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmpq %2,%1\n movq %1,%0\n cmovgq %2,%1\n cmovgq %0,%2" : "=&r"(crypto_int64_z), "+&r"(crypto_int64_x), "+r"(crypto_int64_y) : : "cc");
  *crypto_int64_p = crypto_int64_x;
  *crypto_int64_q = crypto_int64_y;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_r, crypto_int64_s;
  __asm__ ("cmp %2,%3\n csel %0,%2,%3,lt\n csel %1,%3,%2,lt" : "=&r"(crypto_int64_r), "=r"(crypto_int64_s) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  *crypto_int64_p = crypto_int64_r;
  *crypto_int64_q = crypto_int64_s;
#ಇಲ್ಲದಿದ್ದರೆ
  crypto_int64 crypto_int64_r = crypto_int64_y ^ crypto_int64_x;
  crypto_int64 crypto_int64_z = crypto_int64_y - crypto_int64_x;
  crypto_int64_z ^= crypto_int64_r & (crypto_int64_z ^ crypto_int64_y);
  crypto_int64_z = crypto_int64_negative_ಮುಖವಾಡ(crypto_int64_z);
  crypto_int64_z &= crypto_int64_r;
  crypto_int64_x ^= crypto_int64_z;
  crypto_int64_y ^= crypto_int64_z;
  *crypto_int64_p = crypto_int64_x;
  *crypto_int64_q = crypto_int64_y;
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int64 crypto_int64_smaller_ಮುಖವಾಡ(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n cmpq %3,%2\n cmovlq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int64_z;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n csetm %0,lt" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int64_z;
#ಇಲ್ಲದಿದ್ದರೆ
  crypto_int64 crypto_int64_r = crypto_int64_x ^ crypto_int64_y;
  crypto_int64 crypto_int64_z = crypto_int64_x - crypto_int64_y;
  crypto_int64_z ^= crypto_int64_r & (crypto_int64_z ^ crypto_int64_x);
  ಹಿಂತಿರುಗಿ crypto_int64_negative_ಮುಖವಾಡ(crypto_int64_z);
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int64 crypto_int64_smaller_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n cmpq %3,%2\n cmovlq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int64_z;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n cset %0,lt" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int64_z;
#ಇಲ್ಲದಿದ್ದರೆ
  crypto_int64 crypto_int64_r = crypto_int64_x ^ crypto_int64_y;
  crypto_int64 crypto_int64_z = crypto_int64_x - crypto_int64_y;
  crypto_int64_z ^= crypto_int64_r & (crypto_int64_z ^ crypto_int64_x);
  ಹಿಂತಿರುಗಿ crypto_int64_unsigned_topbit_01(crypto_int64_z);
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int64 crypto_int64_leq_ಮುಖವಾಡ(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n cmpq %3,%2\n cmovleq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int64_z;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n csetm %0,le" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int64_z;
#ಇಲ್ಲದಿದ್ದರೆ
  ಹಿಂತಿರುಗಿ ~crypto_int64_smaller_ಮುಖವಾಡ(crypto_int64_y,crypto_int64_x);
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
crypto_int64 crypto_int64_leq_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n cmpq %3,%2\n cmovleq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int64_z;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n cset %0,le" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int64_z;
#ಇಲ್ಲದಿದ್ದರೆ
  ಹಿಂತಿರುಗಿ 1-crypto_int64_smaller_01(crypto_int64_y,crypto_int64_x);
#ಆದರೆ_ಅಂತ್ಯ
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
ಪೂರ್ಣಾಂಕ crypto_int64_ones_ಅಂಕೆ(crypto_int64 crypto_int64_x) {
  crypto_int64_unsigned crypto_int64_y = crypto_int64_x;
  ಸ್ಥಿರಾಂಕ crypto_int64 C0 = 0x5555555555555555;
  ಸ್ಥಿರಾಂಕ crypto_int64 C1 = 0x3333333333333333;
  ಸ್ಥಿರಾಂಕ crypto_int64 C2 = 0x0f0f0f0f0f0f0f0f;
  crypto_int64_y -= ((crypto_int64_y >> 1) & C0);
  crypto_int64_y = (crypto_int64_y & C1) + ((crypto_int64_y >> 2) & C1);
  crypto_int64_y = (crypto_int64_y + (crypto_int64_y >> 4)) & C2;
  crypto_int64_y += crypto_int64_y >> 8;
  crypto_int64_y += crypto_int64_y >> 16;
  crypto_int64_y = (crypto_int64_y + (crypto_int64_y >> 32)) & 0xff;
  ಹಿಂತಿರುಗಿ crypto_int64_y;
}

__attribute__((ಬಳಸದ))
ಸ್ಥಿರ ಸಾಲೊಳಗೆ
ಪೂರ್ಣಾಂಕ crypto_int64_bottomzeros_ಅಂಕೆ(crypto_int64 crypto_int64_x) {
#ಆದರೆ defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 fallback = 64;
  __asm__ ("bsfq %0,%0\n cmoveq %1,%0" : "+&r"(crypto_int64_x) : "r"(fallback) : "cc");
  ಹಿಂತಿರುಗಿ crypto_int64_x;
#ಅಥವಾಆದರೆ defined(__GNUC__) && defined(__aarch64__)
  int64_t crypto_int64_y;
  __asm__ ("rbit %0,%1\n clz %0,%0" : "=r"(crypto_int64_y) : "r"(crypto_int64_x) : );
  ಹಿಂತಿರುಗಿ crypto_int64_y;
#ಇಲ್ಲದಿದ್ದರೆ
  crypto_int64 crypto_int64_y = crypto_int64_x ^ (crypto_int64_x-1);
  crypto_int64_y = ((crypto_int64) crypto_int64_y) >> 1;
  crypto_int64_y &= ~(crypto_int64_x & (((crypto_int64) 1) << (64-1)));
  ಹಿಂತಿರುಗಿ crypto_int64_ones_ಅಂಕೆ(crypto_int64_y);
#ಆದರೆ_ಅಂತ್ಯ
}

#ಆದರೆ_ಅಂತ್ಯ

/* from supercop-20240808/crypto_sort/int32/portable4/sort.c */
#ವ್ಯಾಖ್ಯಾನಿಸು int32_MINMAX(a,b) crypto_int32_minmax(&a,&b)

ಸ್ಥಿರ ಶೂನ್ಯ crypto_ವಿಂಗಡಿಸು_int32(ಶೂನ್ಯ *array,ದೀರ್ಘ ದೀರ್ಘ n)
{
  ದೀರ್ಘ ದೀರ್ಘ ತುದಿ,p,q,r,i,j;
  int32 *x = array;

  ಆದರೆ (n < 2) ಹಿಂತಿರುಗಿ;
  ತುದಿ = 1;
  ಆಗ (ತುದಿ < n - ತುದಿ) ತುದಿ += ತುದಿ;

  ಗಾಗಿ (p = ತುದಿ;p >= 1;p >>= 1) {
    i = 0;
    ಆಗ (i + 2 * p <= n) {
      ಗಾಗಿ (j = i;j < i + p;++j)
        int32_MINMAX(x[j],x[j+p]);
      i += 2 * p;
    }
    ಗಾಗಿ (j = i;j < n - p;++j)
      int32_MINMAX(x[j],x[j+p]);

    i = 0;
    j = 0;
    ಗಾಗಿ (q = ತುದಿ;q > p;q >>= 1) {
      ಆದರೆ (j != i) ಗಾಗಿ (;;) {
        ಆದರೆ (j == n - q) ಹೋಗು ಮುಗಿದ;
        int32 a = x[j + p];
        ಗಾಗಿ (r = q;r > p;r >>= 1)
          int32_MINMAX(a,x[j + r]);
        x[j + p] = a;
        ++j;
        ಆದರೆ (j == i + p) {
          i += 2 * p;
          ನಿಲ್ಲಿಸು;
        }
      }
      ಆಗ (i + p <= n - q) {
        ಗಾಗಿ (j = i;j < i + p;++j) {
          int32 a = x[j + p];
          ಗಾಗಿ (r = q;r > p;r >>= 1)
            int32_MINMAX(a,x[j+r]);
          x[j + p] = a;
        }
        i += 2 * p;
      }
      /* now i + p > n - q */
      j = i;
      ಆಗ (j < n - q) {
        int32 a = x[j + p];
        ಗಾಗಿ (r = q;r > p;r >>= 1)
          int32_MINMAX(a,x[j+r]);
        x[j + p] = a;
        ++j;
      }

      ಮುಗಿದ: ;
    }
  }
}

/* from supercop-20240808/crypto_sort/uint32/useint32/sort.c */

/* can save time by vectorizing xor loops */
/* can save time by integrating xor loops with int32_sort */

ಸ್ಥಿರ ಶೂನ್ಯ crypto_ವಿಂಗಡಿಸು_uint32(ಶೂನ್ಯ *array,ದೀರ್ಘ ದೀರ್ಘ n)
{
  crypto_uint32 *x = array;
  ದೀರ್ಘ ದೀರ್ಘ j;
  ಗಾಗಿ (j = 0;j < n;++j) x[j] ^= 0x80000000;
  crypto_ವಿಂಗಡಿಸು_int32(array,n);
  ಗಾಗಿ (j = 0;j < n;++j) x[j] ^= 0x80000000;
}

/* from supercop-20240808/crypto_kem/sntrup761/compact/kem.c */
// 20240806 djb: some automated conversion to cryptoint

#ವ್ಯಾಖ್ಯಾನಿಸು p 761
#ವ್ಯಾಖ್ಯಾನಿಸು q 4591
#ವ್ಯಾಖ್ಯಾನಿಸು w 286
#ವ್ಯಾಖ್ಯಾನಿಸು q12 ((q - 1) / 2)
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ int8_t small;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ int16_t Fq;
#ವ್ಯಾಖ್ಯಾನಿಸು Hash_ಬೈಟುಗಳು 32
#ವ್ಯಾಖ್ಯಾನಿಸು Small_ಬೈಟುಗಳು ((p + 3) / 4)
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ small Inputs[p];
#ವ್ಯಾಖ್ಯಾನಿಸು Secret_ಕೀಲಿಗಳು_ಬೈಟುಗಳು (2 * Small_ಬೈಟುಗಳು)
#ವ್ಯಾಖ್ಯಾನಿಸು Confirm_ಬೈಟುಗಳು 32

ಸ್ಥಿರ small F3_freeze(int16_t x) { ಹಿಂತಿರುಗಿ x - 3 * ((10923 * x + 16384) >> 15); }

ಸ್ಥಿರ Fq Fq_freeze(int32_t x) {
  ಸ್ಥಿರಾಂಕ int32_t q16 = (0x10000 + q / 2) / q;
  ಸ್ಥಿರಾಂಕ int32_t q20 = (0x100000 + q / 2) / q;
  ಸ್ಥಿರಾಂಕ int32_t q28 = (0x10000000 + q / 2) / q;
  x -= q * ((q16 * x) >> 16);
  x -= q * ((q20 * x) >> 20);
  ಹಿಂತಿರುಗಿ x - q * ((q28 * x + 0x8000000) >> 28);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ Weightw_ಮುಖವಾಡ(small *r) {
  ಪೂರ್ಣಾಂಕ i, ತೂಕ = 0;
  ಗಾಗಿ (i = 0; i < p; ++i) ತೂಕ += crypto_int64_bottombit_01(r[i]);
  ಹಿಂತಿರುಗಿ crypto_int16_nonzero_ಮುಖವಾಡ(ತೂಕ - w);
}

ಸ್ಥಿರ ಶೂನ್ಯ uint32_divmod_uint14(uint32_t *Q, uint16_t *r, uint32_t x, uint16_t m) {
  uint32_t qpart, ಮುಖವಾಡ, v = 0x80000000 / m;
  qpart = (x * (uint64_t)v) >> 31;
  x -= qpart * m;
  *Q = qpart;
  qpart = (x * (uint64_t)v) >> 31;
  x -= qpart * m;
  *Q += qpart;
  x -= m;
  *Q += 1;
  ಮುಖವಾಡ = crypto_int32_negative_ಮುಖವಾಡ(x);
  x += ಮುಖವಾಡ & (uint32_t)m;
  *Q += ಮುಖವಾಡ;
  *r = x;
}

ಸ್ಥಿರ uint16_t uint32_mod_uint14(uint32_t x, uint16_t m) {
  uint32_t Q;
  uint16_t r;
  uint32_divmod_uint14(&Q, &r, x, m);
  ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಶೂನ್ಯ Encode(ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *ಹೊರಹೋಗು, ಸ್ಥಿರಾಂಕ uint16_t *R, ಸ್ಥಿರಾಂಕ uint16_t *M, ದೀರ್ಘ ದೀರ್ಘ len) {
  ಆದರೆ (len == 1) {
    uint16_t r = R[0], m = M[0];
    ಆಗ (m > 1) {
      *ಹೊರಹೋಗು++ = r;
      r >>= 8;
      m = (m + 255) >> 8;
    }
  }
  ಆದರೆ (len > 1) {
    uint16_t R2[(len + 1) / 2], M2[(len + 1) / 2];
    ದೀರ್ಘ ದೀರ್ಘ i;
    ಗಾಗಿ (i = 0; i < len - 1; i += 2) {
      uint32_t m0 = M[i];
      uint32_t r = R[i] + R[i + 1] * m0;
      uint32_t m = M[i + 1] * m0;
      ಆಗ (m >= 16384) {
        *ಹೊರಹೋಗು++ = r;
        r >>= 8;
        m = (m + 255) >> 8;
      }
      R2[i / 2] = r;
      M2[i / 2] = m;
    }
    ಆದರೆ (i < len) {
      R2[i / 2] = R[i];
      M2[i / 2] = M[i];
    }
    Encode(ಹೊರಹೋಗು, R2, M2, (len + 1) / 2);
  }
}

ಸ್ಥಿರ ಶೂನ್ಯ Decode(uint16_t *ಹೊರಹೋಗು, ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *S, ಸ್ಥಿರಾಂಕ uint16_t *M, ದೀರ್ಘ ದೀರ್ಘ len) {
  ಆದರೆ (len == 1) {
    ಆದರೆ (M[0] == 1)
      *ಹೊರಹೋಗು = 0;
    ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (M[0] <= 256)
      *ಹೊರಹೋಗು = uint32_mod_uint14(S[0], M[0]);
    ಇಲ್ಲದಿದ್ದರೆ
      *ಹೊರಹೋಗು = uint32_mod_uint14(S[0] + (((uint16_t)S[1]) << 8), M[0]);
  }
  ಆದರೆ (len > 1) {
    uint16_t R2[(len + 1) / 2], M2[(len + 1) / 2], bottomr[len / 2];
    uint32_t bottomt[len / 2];
    ದೀರ್ಘ ದೀರ್ಘ i;
    ಗಾಗಿ (i = 0; i < len - 1; i += 2) {
      uint32_t m = M[i] * (uint32_t)M[i + 1];
      ಆದರೆ (m > 256 * 16383) {
        bottomt[i / 2] = 256 * 256;
        bottomr[i / 2] = S[0] + 256 * S[1];
        S += 2;
        M2[i / 2] = (((m + 255) >> 8) + 255) >> 8;
      } ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (m >= 16384) {
        bottomt[i / 2] = 256;
        bottomr[i / 2] = S[0];
        S += 1;
        M2[i / 2] = (m + 255) >> 8;
      } ಇಲ್ಲದಿದ್ದರೆ {
        bottomt[i / 2] = 1;
        bottomr[i / 2] = 0;
        M2[i / 2] = m;
      }
    }
    ಆದರೆ (i < len) M2[i / 2] = M[i];
    Decode(R2, S, M2, (len + 1) / 2);
    ಗಾಗಿ (i = 0; i < len - 1; i += 2) {
      uint32_t r1, r = bottomr[i / 2];
      uint16_t r0;
      r += bottomt[i / 2] * R2[i / 2];
      uint32_divmod_uint14(&r1, &r0, r, M[i]);
      r1 = uint32_mod_uint14(r1, M[i + 1]);
      *ಹೊರಹೋಗು++ = r0;
      *ಹೊರಹೋಗು++ = r1;
    }
    ಆದರೆ (i < len) *ಹೊರಹೋಗು++ = R2[i / 2];
  }
}

ಸ್ಥಿರ ಶೂನ್ಯ R3_fromRq(small *ಹೊರಹೋಗು, ಸ್ಥಿರಾಂಕ Fq *r) {
  ಪೂರ್ಣಾಂಕ i;
  ಗಾಗಿ (i = 0; i < p; ++i) ಹೊರಹೋಗು[i] = F3_freeze(r[i]);
}

ಸ್ಥಿರ ಶೂನ್ಯ R3_mult(small *h, ಸ್ಥಿರಾಂಕ small *f, ಸ್ಥಿರಾಂಕ small *g) {
  int16_t fg[p + p - 1];
  ಪೂರ್ಣಾಂಕ i, j;
  ಗಾಗಿ (i = 0; i < p + p - 1; ++i) fg[i] = 0;
  ಗಾಗಿ (i = 0; i < p; ++i)
    ಗಾಗಿ (j = 0; j < p; ++j) fg[i + j] += f[i] * (int16_t)g[j];
  ಗಾಗಿ (i = p; i < p + p - 1; ++i) fg[i - p] += fg[i];
  ಗಾಗಿ (i = p; i < p + p - 1; ++i) fg[i - p + 1] += fg[i];
  ಗಾಗಿ (i = 0; i < p; ++i) h[i] = F3_freeze(fg[i]);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ R3_recip(small *ಹೊರಹೋಗು, ಸ್ಥಿರಾಂಕ small *ಒಳ) {
  small f[p + 1], g[p + 1], v[p + 1], r[p + 1];
  ಪೂರ್ಣಾಂಕ sign, ಅದಲುಬದಲು, t, i, loop, delta = 1;
  ಗಾಗಿ (i = 0; i < p + 1; ++i) v[i] = 0;
  ಗಾಗಿ (i = 0; i < p + 1; ++i) r[i] = 0;
  r[0] = 1;
  ಗಾಗಿ (i = 0; i < p; ++i) f[i] = 0;
  f[0] = 1;
  f[p - 1] = f[p] = -1;
  ಗಾಗಿ (i = 0; i < p; ++i) g[p - 1 - i] = ಒಳ[i];
  g[p] = 0;
  ಗಾಗಿ (loop = 0; loop < 2 * p - 1; ++loop) {
    ಗಾಗಿ (i = p; i > 0; --i) v[i] = v[i - 1];
    v[0] = 0;
    sign = -g[0] * f[0];
    ಅದಲುಬದಲು = crypto_int16_negative_ಮುಖವಾಡ(-delta) & crypto_int16_nonzero_ಮುಖವಾಡ(g[0]);
    delta ^= ಅದಲುಬದಲು & (delta ^ -delta);
    delta += 1;
    ಗಾಗಿ (i = 0; i < p + 1; ++i) {
      t = ಅದಲುಬದಲು & (f[i] ^ g[i]);
      f[i] ^= t;
      g[i] ^= t;
      t = ಅದಲುಬದಲು & (v[i] ^ r[i]);
      v[i] ^= t;
      r[i] ^= t;
    }
    ಗಾಗಿ (i = 0; i < p + 1; ++i) g[i] = F3_freeze(g[i] + sign * f[i]);
    ಗಾಗಿ (i = 0; i < p + 1; ++i) r[i] = F3_freeze(r[i] + sign * v[i]);
    ಗಾಗಿ (i = 0; i < p; ++i) g[i] = g[i + 1];
    g[p] = 0;
  }
  sign = f[0];
  ಗಾಗಿ (i = 0; i < p; ++i) ಹೊರಹೋಗು[i] = sign * v[p - 1 - i];
  ಹಿಂತಿರುಗಿ crypto_int16_nonzero_ಮುಖವಾಡ(delta);
}

ಸ್ಥಿರ ಶೂನ್ಯ Rq_mult_small(Fq *h, ಸ್ಥಿರಾಂಕ Fq *f, ಸ್ಥಿರಾಂಕ small *g) {
  int32_t fg[p + p - 1];
  ಪೂರ್ಣಾಂಕ i, j;
  ಗಾಗಿ (i = 0; i < p + p - 1; ++i) fg[i] = 0;
  ಗಾಗಿ (i = 0; i < p; ++i)
    ಗಾಗಿ (j = 0; j < p; ++j) fg[i + j] += f[i] * (int32_t)g[j];
  ಗಾಗಿ (i = p; i < p + p - 1; ++i) fg[i - p] += fg[i];
  ಗಾಗಿ (i = p; i < p + p - 1; ++i) fg[i - p + 1] += fg[i];
  ಗಾಗಿ (i = 0; i < p; ++i) h[i] = Fq_freeze(fg[i]);
}

ಸ್ಥಿರ ಶೂನ್ಯ Rq_mult3(Fq *h, ಸ್ಥಿರಾಂಕ Fq *f) {
  ಪೂರ್ಣಾಂಕ i;
  ಗಾಗಿ (i = 0; i < p; ++i) h[i] = Fq_freeze(3 * f[i]);
}

ಸ್ಥಿರ Fq Fq_recip(Fq a1) {
  ಪೂರ್ಣಾಂಕ i = 1;
  Fq ai = a1;
  ಆಗ (i < q - 2) {
    ai = Fq_freeze(a1 * (int32_t)ai);
    i += 1;
  }
  ಹಿಂತಿರುಗಿ ai;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ Rq_recip3(Fq *ಹೊರಹೋಗು, ಸ್ಥಿರಾಂಕ small *ಒಳ) {
  Fq f[p + 1], g[p + 1], v[p + 1], r[p + 1], scale;
  ಪೂರ್ಣಾಂಕ ಅದಲುಬದಲು, t, i, loop, delta = 1;
  int32_t f0, g0;
  ಗಾಗಿ (i = 0; i < p + 1; ++i) v[i] = 0;
  ಗಾಗಿ (i = 0; i < p + 1; ++i) r[i] = 0;
  r[0] = Fq_recip(3);
  ಗಾಗಿ (i = 0; i < p; ++i) f[i] = 0;
  f[0] = 1;
  f[p - 1] = f[p] = -1;
  ಗಾಗಿ (i = 0; i < p; ++i) g[p - 1 - i] = ಒಳ[i];
  g[p] = 0;
  ಗಾಗಿ (loop = 0; loop < 2 * p - 1; ++loop) {
    ಗಾಗಿ (i = p; i > 0; --i) v[i] = v[i - 1];
    v[0] = 0;
    ಅದಲುಬದಲು = crypto_int16_negative_ಮುಖವಾಡ(-delta) & crypto_int16_nonzero_ಮುಖವಾಡ(g[0]);
    delta ^= ಅದಲುಬದಲು & (delta ^ -delta);
    delta += 1;
    ಗಾಗಿ (i = 0; i < p + 1; ++i) {
      t = ಅದಲುಬದಲು & (f[i] ^ g[i]);
      f[i] ^= t;
      g[i] ^= t;
      t = ಅದಲುಬದಲು & (v[i] ^ r[i]);
      v[i] ^= t;
      r[i] ^= t;
    }
    f0 = f[0];
    g0 = g[0];
    ಗಾಗಿ (i = 0; i < p + 1; ++i) g[i] = Fq_freeze(f0 * g[i] - g0 * f[i]);
    ಗಾಗಿ (i = 0; i < p + 1; ++i) r[i] = Fq_freeze(f0 * r[i] - g0 * v[i]);
    ಗಾಗಿ (i = 0; i < p; ++i) g[i] = g[i + 1];
    g[p] = 0;
  }
  scale = Fq_recip(f[0]);
  ಗಾಗಿ (i = 0; i < p; ++i) ಹೊರಹೋಗು[i] = Fq_freeze(scale * (int32_t)v[p - 1 - i]);
  ಹಿಂತಿರುಗಿ crypto_int16_nonzero_ಮುಖವಾಡ(delta);
}

ಸ್ಥಿರ ಶೂನ್ಯ ಸುತ್ತು_3(Fq *ಹೊರಹೋಗು, ಸ್ಥಿರಾಂಕ Fq *a) {
  ಪೂರ್ಣಾಂಕ i;
  ಗಾಗಿ (i = 0; i < p; ++i) ಹೊರಹೋಗು[i] = a[i] - F3_freeze(a[i]);
}

ಸ್ಥಿರ ಶೂನ್ಯ Short_fromlist(small *ಹೊರಹೋಗು, ಸ್ಥಿರಾಂಕ uint32_t *ಒಳ) {
  uint32_t L[p];
  ಪೂರ್ಣಾಂಕ i;
  ಗಾಗಿ (i = 0; i < w; ++i) L[i] = ಒಳ[i] & (uint32_t)-2;
  ಗಾಗಿ (i = w; i < p; ++i) L[i] = (ಒಳ[i] & (uint32_t)-3) | 1;
  crypto_ವಿಂಗಡಿಸು_uint32(L, p);
  ಗಾಗಿ (i = 0; i < p; ++i) ಹೊರಹೋಗು[i] = (L[i] & 3) - 1;
}

ಸ್ಥಿರ ಶೂನ್ಯ Hash_ಪೂರ್ವಪ್ರತ್ಯಯ(ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *ಹೊರಹೋಗು, ಪೂರ್ಣಾಂಕ b, ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *ಒಳ, ಪೂರ್ಣಾಂಕ inlen) {
  ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ x[inlen + 1], h[64];
  ಪೂರ್ಣಾಂಕ i;
  x[0] = b;
  ಗಾಗಿ (i = 0; i < inlen; ++i) x[i + 1] = ಒಳ[i];
  crypto_hash_sha512(h, x, inlen + 1);
  ಗಾಗಿ (i = 0; i < 32; ++i) ಹೊರಹೋಗು[i] = h[i];
}


ಸ್ಥಿರ ಶೂನ್ಯ Short_random(small *ಹೊರಹೋಗು) {
  uint32_t L[p];
  randombytes(L, ಗಾತ್ರ(L));
  Short_fromlist(ಹೊರಹೋಗು, L);
  explicit_bzero(L, ಗಾತ್ರ(L));
}
ಸ್ಥಿರ ಶೂನ್ಯ Small_random(small *ಹೊರಹೋಗು) {
  ಪೂರ್ಣಾಂಕ i;
  uint32_t L[p];
  randombytes(L, ಗಾತ್ರ(L));
  ಗಾಗಿ (i = 0; i < p; ++i) ಹೊರಹೋಗು[i] = (((L[i] & 0x3fffffff) * 3) >> 30) - 1;
  explicit_bzero(L, ಗಾತ್ರ(L));
}
ಸ್ಥಿರ ಶೂನ್ಯ ಕೀಲಿ_Gen(Fq *h, small *f, small *ginv) {
  small g[p];
  Fq finv[p];
  ಗಾಗಿ (;;) {
    ಪೂರ್ಣಾಂಕ ಫಲಿತಾಂಶ;
    Small_random(g);
    ಫಲಿತಾಂಶ = R3_recip(ginv, g);
    crypto_declassify(&ಫಲಿತಾಂಶ, ಗಾತ್ರ ಫಲಿತಾಂಶ);
    ಆದರೆ (ಫಲಿತಾಂಶ == 0) ನಿಲ್ಲಿಸು;
  }
  Short_random(f);
  Rq_recip3(finv, f);
  Rq_mult_small(h, finv, g);
}

ಸ್ಥಿರ ಶೂನ್ಯ Encrypt(Fq *c, ಸ್ಥಿರಾಂಕ small *r, ಸ್ಥಿರಾಂಕ Fq *h) {
  Fq hr[p];
  Rq_mult_small(hr, h, r);
  ಸುತ್ತು_3(c, hr);
}

ಸ್ಥಿರ ಶೂನ್ಯ Decrypt(small *r, ಸ್ಥಿರಾಂಕ Fq *c, ಸ್ಥಿರಾಂಕ small *f, ಸ್ಥಿರಾಂಕ small *ginv) {
  Fq cf[p], cf3[p];
  small e[p], ev[p];
  ಪೂರ್ಣಾಂಕ ಮುಖವಾಡ, i;
  Rq_mult_small(cf, c, f);
  Rq_mult3(cf3, cf);
  R3_fromRq(e, cf3);
  R3_mult(ev, e, ginv);
  ಮುಖವಾಡ = Weightw_ಮುಖವಾಡ(ev);
  ಗಾಗಿ (i = 0; i < w; ++i) r[i] = ((ev[i] ^ 1) & ~ಮುಖವಾಡ) ^ 1;
  ಗಾಗಿ (i = w; i < p; ++i) r[i] = ev[i] & ~ಮುಖವಾಡ;
}

ಸ್ಥಿರ ಶೂನ್ಯ Small_encode(ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *s, ಸ್ಥಿರಾಂಕ small *f) {
  ಪೂರ್ಣಾಂಕ i, j;
  ಗಾಗಿ (i = 0; i < p / 4; ++i) {
    small x = 0;
    ಗಾಗಿ (j = 0;j < 4;++j) x += (*f++ + 1) << (2 * j);
    *s++ = x;
  }
  *s = *f++ + 1;
}

ಸ್ಥಿರ ಶೂನ್ಯ Small_decode(small *f, ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *s) {
  ಪೂರ್ಣಾಂಕ i, j;
  ಗಾಗಿ (i = 0; i < p / 4; ++i) {
    ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ x = *s++;
    ಗಾಗಿ (j = 0;j < 4;++j) *f++ = ((small)((x >> (2 * j)) & 3)) - 1;
  }
  *f++ = ((small)(*s & 3)) - 1;
}

ಸ್ಥಿರ ಶೂನ್ಯ Rq_encode(ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *s, ಸ್ಥಿರಾಂಕ Fq *r) {
  uint16_t R[p], M[p];
  ಪೂರ್ಣಾಂಕ i;
  ಗಾಗಿ (i = 0; i < p; ++i) R[i] = r[i] + q12;
  ಗಾಗಿ (i = 0; i < p; ++i) M[i] = q;
  Encode(s, R, M, p);
}

ಸ್ಥಿರ ಶೂನ್ಯ Rq_decode(Fq *r, ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *s) {
  uint16_t R[p], M[p];
  ಪೂರ್ಣಾಂಕ i;
  ಗಾಗಿ (i = 0; i < p; ++i) M[i] = q;
  Decode(R, s, M, p);
  ಗಾಗಿ (i = 0; i < p; ++i) r[i] = ((Fq)R[i]) - q12;
}

ಸ್ಥಿರ ಶೂನ್ಯ Rounded_encode(ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *s, ಸ್ಥಿರಾಂಕ Fq *r) {
  uint16_t R[p], M[p];
  ಪೂರ್ಣಾಂಕ i;
  ಗಾಗಿ (i = 0; i < p; ++i) R[i] = ((r[i] + q12) * 10923) >> 15;
  ಗಾಗಿ (i = 0; i < p; ++i) M[i] = (q + 2) / 3;
  Encode(s, R, M, p);
}

ಸ್ಥಿರ ಶೂನ್ಯ Rounded_decode(Fq *r, ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *s) {
  uint16_t R[p], M[p];
  ಪೂರ್ಣಾಂಕ i;
  ಗಾಗಿ (i = 0; i < p; ++i) M[i] = (q + 2) / 3;
  Decode(R, s, M, p);
  ಗಾಗಿ (i = 0; i < p; ++i) r[i] = R[i] * 3 - q12;
}

ಸ್ಥಿರ ಶೂನ್ಯ ZKeyGen(ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *pk, ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *sk) {
  Fq h[p];
  small f[p], v[p];
  ಕೀಲಿ_Gen(h, f, v);
  Rq_encode(pk, h);
  Small_encode(sk, f);
  Small_encode(sk + Small_ಬೈಟುಗಳು, v);
}

ಸ್ಥಿರ ಶೂನ್ಯ ZEncrypt(ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *C, ಸ್ಥಿರಾಂಕ Inputs r, ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *pk) {
  Fq h[p], c[p];
  Rq_decode(h, pk);
  Encrypt(c, r, h);
  Rounded_encode(C, c);
}

ಸ್ಥಿರ ಶೂನ್ಯ ZDecrypt(Inputs r, ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *C, ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *sk) {
  small f[p], v[p];
  Fq c[p];
  Small_decode(f, sk);
  Small_decode(v, sk + Small_ಬೈಟುಗಳು);
  Rounded_decode(c, C);
  Decrypt(r, c, f, v);
}

ಸ್ಥಿರ ಶೂನ್ಯ HashConfirm(ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *h, ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *r, ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *cache) {
  ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ x[Hash_ಬೈಟುಗಳು * 2];
  ಪೂರ್ಣಾಂಕ i;
  Hash_ಪೂರ್ವಪ್ರತ್ಯಯ(x, 3, r, Small_ಬೈಟುಗಳು);
  ಗಾಗಿ (i = 0; i < Hash_ಬೈಟುಗಳು; ++i) x[Hash_ಬೈಟುಗಳು + i] = cache[i];
  Hash_ಪೂರ್ವಪ್ರತ್ಯಯ(h, 2, x, ಗಾತ್ರ x);
}

ಸ್ಥಿರ ಶೂನ್ಯ HashSession(ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *k, ಪೂರ್ಣಾಂಕ b, ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *y, ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *z) {
  ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ x[Hash_ಬೈಟುಗಳು + crypto_kem_sntrup761_CIPHERTEXTBYTES];
  ಪೂರ್ಣಾಂಕ i;
  Hash_ಪೂರ್ವಪ್ರತ್ಯಯ(x, 3, y, Small_ಬೈಟುಗಳು);
  ಗಾಗಿ (i = 0; i < crypto_kem_sntrup761_CIPHERTEXTBYTES; ++i) x[Hash_ಬೈಟುಗಳು + i] = z[i];
  Hash_ಪೂರ್ವಪ್ರತ್ಯಯ(k, b, x, ಗಾತ್ರ x);
}

ಪೂರ್ಣಾಂಕ crypto_kem_sntrup761_keypair(ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *pk, ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *sk) {
  ಪೂರ್ಣಾಂಕ i;
  ZKeyGen(pk, sk);
  sk += Secret_ಕೀಲಿಗಳು_ಬೈಟುಗಳು;
  ಗಾಗಿ (i = 0; i < crypto_kem_sntrup761_PUBLICKEYBYTES; ++i) *sk++ = pk[i];
  randombytes(sk, Small_ಬೈಟುಗಳು);
  Hash_ಪೂರ್ವಪ್ರತ್ಯಯ(sk + Small_ಬೈಟುಗಳು, 4, pk, crypto_kem_sntrup761_PUBLICKEYBYTES);
  ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ Hide(ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *c, ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *r_enc, ಸ್ಥಿರಾಂಕ Inputs r, ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *pk, ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *cache) {
  Small_encode(r_enc, r);
  ZEncrypt(c, r, pk);
  HashConfirm(c + crypto_kem_sntrup761_CIPHERTEXTBYTES - Confirm_ಬೈಟುಗಳು, r_enc, cache);
}

ಪೂರ್ಣಾಂಕ crypto_kem_sntrup761_enc(ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *c, ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *k, ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *pk) {
  Inputs r;
  ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ r_enc[Small_ಬೈಟುಗಳು], cache[Hash_ಬೈಟುಗಳು];
  Hash_ಪೂರ್ವಪ್ರತ್ಯಯ(cache, 4, pk, crypto_kem_sntrup761_PUBLICKEYBYTES);
  Short_random(r);
  Hide(c, r_enc, r, pk, cache);
  HashSession(k, 1, r_enc, c);
  ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ Ciphertexts_diff_ಮುಖವಾಡ(ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *c, ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *c2) {
  uint16_t differentbits = 0;
  ಪೂರ್ಣಾಂಕ len = crypto_kem_sntrup761_CIPHERTEXTBYTES;
  ಆಗ (len-- > 0) differentbits |= (*c++) ^ (*c2++);
  ಹಿಂತಿರುಗಿ (crypto_int64_bitmod_01((differentbits - 1),8)) - 1;
}

ಪೂರ್ಣಾಂಕ crypto_kem_sntrup761_dec(ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *k, ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *c, ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *sk) {
  ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *pk = sk + Secret_ಕೀಲಿಗಳು_ಬೈಟುಗಳು;
  ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *rho = pk + crypto_kem_sntrup761_PUBLICKEYBYTES;
  ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ *cache = rho + Small_ಬೈಟುಗಳು;
  Inputs r;
  ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ r_enc[Small_ಬೈಟುಗಳು], cnew[crypto_kem_sntrup761_CIPHERTEXTBYTES];
  ಪೂರ್ಣಾಂಕ ಮುಖವಾಡ, i;
  ZDecrypt(r, c, sk);
  Hide(cnew, r_enc, r, pk, cache);
  ಮುಖವಾಡ = Ciphertexts_diff_ಮುಖವಾಡ(c, cnew);
  ಗಾಗಿ (i = 0; i < Small_ಬೈಟುಗಳು; ++i) r_enc[i] ^= ಮುಖವಾಡ & (r_enc[i] ^ rho[i]);
  HashSession(k, 1 + ಮುಖವಾಡ, r_enc, c);
  ಹಿಂತಿರುಗಿ 0;
}

#ಆದರೆ_ಅಂತ್ಯ /* USE_SNTRUP761X25519 */
