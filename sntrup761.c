/*  $OpenBSD: sntrup761.c,v 1.9 2026/01/20 22:56:11 dtucker Exp $ */

/*
 * Public Domain, Authors:
 * - Daniel J. Bernstein
 * - Chitchanok Chuengsatiansup
 * - Tanja Lange
 * - Christine van Vredendaal
 */

#समावेश "includes.h"

#अगर_घोषित USE_SNTRUP761X25519

#समावेश <string.h>
#समावेश "crypto_api.h"

#घोषणा crypto_declassify(x, y) करो {} जबतक (0)

#घोषणा int8 crypto_int8
#घोषणा uint8 crypto_uint8
#घोषणा int16 crypto_int16
#घोषणा uint16 crypto_uint16
#घोषणा int32 crypto_int32
#घोषणा uint32 crypto_uint32
#घोषणा int64 crypto_int64
#घोषणा uint64 crypto_uint64
बाह्य अस्थिर crypto_int16 crypto_int16_optblocker;
बाह्य अस्थिर crypto_int32 crypto_int32_optblocker;
बाह्य अस्थिर crypto_int64 crypto_int64_optblocker;

/* from supercop-20240808/cryptoint/crypto_int16.h */
/* auto-generated: cd cryptoint; ./autogen */
/* cryptoint 20240806 */

#अगर_अघोषित crypto_int16_h
#घोषणा crypto_int16_h

#घोषणा crypto_int16 int16_t
#घोषणा crypto_int16_unsigned uint16_t



__attribute__((unused))
अटल अंतरभूत
crypto_int16 crypto_int16_load(स्थिर अचिन्हित अक्षर *crypto_int16_s) {
  crypto_int16 crypto_int16_z = 0;
  crypto_int16_z |= ((crypto_int16) (*crypto_int16_s++)) << 0;
  crypto_int16_z |= ((crypto_int16) (*crypto_int16_s++)) << 8;
  वापस crypto_int16_z;
}

__attribute__((unused))
अटल अंतरभूत
व्योम crypto_int16_store(अचिन्हित अक्षर *crypto_int16_s,crypto_int16 crypto_int16_x) {
  *crypto_int16_s++ = crypto_int16_x >> 0;
  *crypto_int16_s++ = crypto_int16_x >> 8;
}

__attribute__((unused))
अटल अंतरभूत
crypto_int16 crypto_int16_negative_mask(crypto_int16 crypto_int16_x) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarw $15,%0" : "+r"(crypto_int16_x) : : "cc");
  वापस crypto_int16_x;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_y;
  __asm__ ("sbfx %w0,%w1,15,1" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) : );
  वापस crypto_int16_y;
#अन्यथा
  crypto_int16_x >>= 16-6;
  crypto_int16_x ^= crypto_int16_optblocker;
  crypto_int16_x >>= 5;
  वापस crypto_int16_x;
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int16_unsigned crypto_int16_unsigned_topbit_01(crypto_int16_unsigned crypto_int16_x) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("shrw $15,%0" : "+r"(crypto_int16_x) : : "cc");
  वापस crypto_int16_x;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_y;
  __asm__ ("ubfx %w0,%w1,15,1" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) : );
  वापस crypto_int16_y;
#अन्यथा
  crypto_int16_x >>= 16-6;
  crypto_int16_x ^= crypto_int16_optblocker;
  crypto_int16_x >>= 5;
  वापस crypto_int16_x;
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int16 crypto_int16_negative_01(crypto_int16 crypto_int16_x) {
  वापस crypto_int16_unsigned_topbit_01(crypto_int16_x);
}

__attribute__((unused))
अटल अंतरभूत
crypto_int16 crypto_int16_topbit_mask(crypto_int16 crypto_int16_x) {
  वापस crypto_int16_negative_mask(crypto_int16_x);
}

__attribute__((unused))
अटल अंतरभूत
crypto_int16 crypto_int16_topbit_01(crypto_int16 crypto_int16_x) {
  वापस crypto_int16_unsigned_topbit_01(crypto_int16_x);
}

__attribute__((unused))
अटल अंतरभूत
crypto_int16 crypto_int16_bottombit_mask(crypto_int16 crypto_int16_x) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andw $1,%0" : "+r"(crypto_int16_x) : : "cc");
  वापस -crypto_int16_x;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_y;
  __asm__ ("sbfx %w0,%w1,0,1" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) : );
  वापस crypto_int16_y;
#अन्यथा
  crypto_int16_x &= 1 ^ crypto_int16_optblocker;
  वापस -crypto_int16_x;
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int16 crypto_int16_bottombit_01(crypto_int16 crypto_int16_x) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andw $1,%0" : "+r"(crypto_int16_x) : : "cc");
  वापस crypto_int16_x;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_y;
  __asm__ ("ubfx %w0,%w1,0,1" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) : );
  वापस crypto_int16_y;
#अन्यथा
  crypto_int16_x &= 1 ^ crypto_int16_optblocker;
  वापस crypto_int16_x;
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int16 crypto_int16_bitinrangepublicpos_mask(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarw %%cl,%0" : "+r"(crypto_int16_x) : "c"(crypto_int16_s) : "cc");
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("sxth %w0,%w0\n asr %w0,%w0,%w1" : "+&r"(crypto_int16_x) : "r"(crypto_int16_s) : );
#अन्यथा
  crypto_int16_x >>= crypto_int16_s ^ crypto_int16_optblocker;
#पूर्ण_अगर
  वापस crypto_int16_bottombit_mask(crypto_int16_x);
}

__attribute__((unused))
अटल अंतरभूत
crypto_int16 crypto_int16_bitinrangepublicpos_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarw %%cl,%0" : "+r"(crypto_int16_x) : "c"(crypto_int16_s) : "cc");
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("sxth %w0,%w0\n asr %w0,%w0,%w1" : "+&r"(crypto_int16_x) : "r"(crypto_int16_s) : );
#अन्यथा
  crypto_int16_x >>= crypto_int16_s ^ crypto_int16_optblocker;
#पूर्ण_अगर
  वापस crypto_int16_bottombit_01(crypto_int16_x);
}

__attribute__((unused))
अटल अंतरभूत
crypto_int16 crypto_int16_shlmod(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  crypto_int16_s &= 15;
  __asm__ ("shlw %%cl,%0" : "+r"(crypto_int16_x) : "c"(crypto_int16_s) : "cc");
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("and %w0,%w0,15\n and %w1,%w1,65535\n lsl %w1,%w1,%w0" : "+&r"(crypto_int16_s), "+r"(crypto_int16_x) : : );
#अन्यथा
  पूर्णांक crypto_int16_k, crypto_int16_l;
  क्रम (crypto_int16_l = 0,crypto_int16_k = 1;crypto_int16_k < 16;++crypto_int16_l,crypto_int16_k *= 2)
    crypto_int16_x ^= (crypto_int16_x ^ (crypto_int16_x << crypto_int16_k)) & crypto_int16_bitinrangepublicpos_mask(crypto_int16_s,crypto_int16_l);
#पूर्ण_अगर
  वापस crypto_int16_x;
}

__attribute__((unused))
अटल अंतरभूत
crypto_int16 crypto_int16_shrmod(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  crypto_int16_s &= 15;
  __asm__ ("sarw %%cl,%0" : "+r"(crypto_int16_x) : "c"(crypto_int16_s) : "cc");
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("and %w0,%w0,15\n sxth %w1,%w1\n asr %w1,%w1,%w0" : "+&r"(crypto_int16_s), "+r"(crypto_int16_x) : : );
#अन्यथा
  पूर्णांक crypto_int16_k, crypto_int16_l;
  क्रम (crypto_int16_l = 0,crypto_int16_k = 1;crypto_int16_k < 16;++crypto_int16_l,crypto_int16_k *= 2)
    crypto_int16_x ^= (crypto_int16_x ^ (crypto_int16_x >> crypto_int16_k)) & crypto_int16_bitinrangepublicpos_mask(crypto_int16_s,crypto_int16_l);
#पूर्ण_अगर
  वापस crypto_int16_x;
}

__attribute__((unused))
अटल अंतरभूत
crypto_int16 crypto_int16_bitmod_mask(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
  crypto_int16_x = crypto_int16_shrmod(crypto_int16_x,crypto_int16_s);
  वापस crypto_int16_bottombit_mask(crypto_int16_x);
}

__attribute__((unused))
अटल अंतरभूत
crypto_int16 crypto_int16_bitmod_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_s) {
  crypto_int16_x = crypto_int16_shrmod(crypto_int16_x,crypto_int16_s);
  वापस crypto_int16_bottombit_01(crypto_int16_x);
}

__attribute__((unused))
अटल अंतरभूत
crypto_int16 crypto_int16_nonzero_mask(crypto_int16 crypto_int16_x) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n testw %2,%2\n cmovnew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  वापस crypto_int16_z;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("tst %w1,65535\n csetm %w0,ne" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  वापस crypto_int16_z;
#अन्यथा
  crypto_int16_x |= -crypto_int16_x;
  वापस crypto_int16_negative_mask(crypto_int16_x);
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int16 crypto_int16_nonzero_01(crypto_int16 crypto_int16_x) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n testw %2,%2\n cmovnew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  वापस crypto_int16_z;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("tst %w1,65535\n cset %w0,ne" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  वापस crypto_int16_z;
#अन्यथा
  crypto_int16_x |= -crypto_int16_x;
  वापस crypto_int16_unsigned_topbit_01(crypto_int16_x);
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int16 crypto_int16_positive_mask(crypto_int16 crypto_int16_x) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n testw %2,%2\n cmovgw %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  वापस crypto_int16_z;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,0\n csetm %w0,gt" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  वापस crypto_int16_z;
#अन्यथा
  crypto_int16 crypto_int16_z = -crypto_int16_x;
  crypto_int16_z ^= crypto_int16_x & crypto_int16_z;
  वापस crypto_int16_negative_mask(crypto_int16_z);
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int16 crypto_int16_positive_01(crypto_int16 crypto_int16_x) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n testw %2,%2\n cmovgw %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  वापस crypto_int16_z;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,0\n cset %w0,gt" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  वापस crypto_int16_z;
#अन्यथा
  crypto_int16 crypto_int16_z = -crypto_int16_x;
  crypto_int16_z ^= crypto_int16_x & crypto_int16_z;
  वापस crypto_int16_unsigned_topbit_01(crypto_int16_z);
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int16 crypto_int16_zero_mask(crypto_int16 crypto_int16_x) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n testw %2,%2\n cmovew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  वापस crypto_int16_z;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("tst %w1,65535\n csetm %w0,eq" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  वापस crypto_int16_z;
#अन्यथा
  वापस ~crypto_int16_nonzero_mask(crypto_int16_x);
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int16 crypto_int16_zero_01(crypto_int16 crypto_int16_x) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n testw %2,%2\n cmovew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x) : "cc");
  वापस crypto_int16_z;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("tst %w1,65535\n cset %w0,eq" : "=r"(crypto_int16_z) : "r"(crypto_int16_x) : "cc");
  वापस crypto_int16_z;
#अन्यथा
  वापस 1-crypto_int16_nonzero_01(crypto_int16_x);
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int16 crypto_int16_unequal_mask(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n cmpw %3,%2\n cmovnew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  वापस crypto_int16_z;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("and %w0,%w1,65535\n cmp %w0,%w2,uxth\n csetm %w0,ne" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  वापस crypto_int16_z;
#अन्यथा
  वापस crypto_int16_nonzero_mask(crypto_int16_x ^ crypto_int16_y);
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int16 crypto_int16_unequal_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n cmpw %3,%2\n cmovnew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  वापस crypto_int16_z;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("and %w0,%w1,65535\n cmp %w0,%w2,uxth\n cset %w0,ne" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  वापस crypto_int16_z;
#अन्यथा
  वापस crypto_int16_nonzero_01(crypto_int16_x ^ crypto_int16_y);
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int16 crypto_int16_equal_mask(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n cmpw %3,%2\n cmovew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  वापस crypto_int16_z;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("and %w0,%w1,65535\n cmp %w0,%w2,uxth\n csetm %w0,eq" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  वापस crypto_int16_z;
#अन्यथा
  वापस ~crypto_int16_unequal_mask(crypto_int16_x,crypto_int16_y);
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int16 crypto_int16_equal_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n cmpw %3,%2\n cmovew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  वापस crypto_int16_z;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("and %w0,%w1,65535\n cmp %w0,%w2,uxth\n cset %w0,eq" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  वापस crypto_int16_z;
#अन्यथा
  वापस 1-crypto_int16_unequal_01(crypto_int16_x,crypto_int16_y);
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int16 crypto_int16_min(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpw %1,%0\n cmovgw %1,%0" : "+r"(crypto_int16_x) : "r"(crypto_int16_y) : "cc");
  वापस crypto_int16_x;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("sxth %w0,%w0\n cmp %w0,%w1,sxth\n csel %w0,%w0,%w1,lt" : "+&r"(crypto_int16_x) : "r"(crypto_int16_y) : "cc");
  वापस crypto_int16_x;
#अन्यथा
  crypto_int16 crypto_int16_r = crypto_int16_y ^ crypto_int16_x;
  crypto_int16 crypto_int16_z = crypto_int16_y - crypto_int16_x;
  crypto_int16_z ^= crypto_int16_r & (crypto_int16_z ^ crypto_int16_y);
  crypto_int16_z = crypto_int16_negative_mask(crypto_int16_z);
  crypto_int16_z &= crypto_int16_r;
  वापस crypto_int16_x ^ crypto_int16_z;
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int16 crypto_int16_max(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpw %1,%0\n cmovlw %1,%0" : "+r"(crypto_int16_x) : "r"(crypto_int16_y) : "cc");
  वापस crypto_int16_x;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("sxth %w0,%w0\n cmp %w0,%w1,sxth\n csel %w0,%w1,%w0,lt" : "+&r"(crypto_int16_x) : "r"(crypto_int16_y) : "cc");
  वापस crypto_int16_x;
#अन्यथा
  crypto_int16 crypto_int16_r = crypto_int16_y ^ crypto_int16_x;
  crypto_int16 crypto_int16_z = crypto_int16_y - crypto_int16_x;
  crypto_int16_z ^= crypto_int16_r & (crypto_int16_z ^ crypto_int16_y);
  crypto_int16_z = crypto_int16_negative_mask(crypto_int16_z);
  crypto_int16_z &= crypto_int16_r;
  वापस crypto_int16_y ^ crypto_int16_z;
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
व्योम crypto_int16_minmax(crypto_int16 *crypto_int16_p,crypto_int16 *crypto_int16_q) {
  crypto_int16 crypto_int16_x = *crypto_int16_p;
  crypto_int16 crypto_int16_y = *crypto_int16_q;
#अगर defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("cmpw %2,%1\n movw %1,%0\n cmovgw %2,%1\n cmovgw %0,%2" : "=&r"(crypto_int16_z), "+&r"(crypto_int16_x), "+r"(crypto_int16_y) : : "cc");
  *crypto_int16_p = crypto_int16_x;
  *crypto_int16_q = crypto_int16_y;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_r, crypto_int16_s;
  __asm__ ("sxth %w0,%w0\n cmp %w0,%w3,sxth\n csel %w1,%w0,%w3,lt\n csel %w2,%w3,%w0,lt" : "+&r"(crypto_int16_x), "=&r"(crypto_int16_r), "=r"(crypto_int16_s) : "r"(crypto_int16_y) : "cc");
  *crypto_int16_p = crypto_int16_r;
  *crypto_int16_q = crypto_int16_s;
#अन्यथा
  crypto_int16 crypto_int16_r = crypto_int16_y ^ crypto_int16_x;
  crypto_int16 crypto_int16_z = crypto_int16_y - crypto_int16_x;
  crypto_int16_z ^= crypto_int16_r & (crypto_int16_z ^ crypto_int16_y);
  crypto_int16_z = crypto_int16_negative_mask(crypto_int16_z);
  crypto_int16_z &= crypto_int16_r;
  crypto_int16_x ^= crypto_int16_z;
  crypto_int16_y ^= crypto_int16_z;
  *crypto_int16_p = crypto_int16_x;
  *crypto_int16_q = crypto_int16_y;
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int16 crypto_int16_smaller_mask(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n cmpw %3,%2\n cmovlw %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  वापस crypto_int16_z;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,%w2,sxth\n csetm %w0,lt" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  वापस crypto_int16_z;
#अन्यथा
  crypto_int16 crypto_int16_r = crypto_int16_x ^ crypto_int16_y;
  crypto_int16 crypto_int16_z = crypto_int16_x - crypto_int16_y;
  crypto_int16_z ^= crypto_int16_r & (crypto_int16_z ^ crypto_int16_x);
  वापस crypto_int16_negative_mask(crypto_int16_z);
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int16 crypto_int16_smaller_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n cmpw %3,%2\n cmovlw %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  वापस crypto_int16_z;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,%w2,sxth\n cset %w0,lt" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  वापस crypto_int16_z;
#अन्यथा
  crypto_int16 crypto_int16_r = crypto_int16_x ^ crypto_int16_y;
  crypto_int16 crypto_int16_z = crypto_int16_x - crypto_int16_y;
  crypto_int16_z ^= crypto_int16_r & (crypto_int16_z ^ crypto_int16_x);
  वापस crypto_int16_unsigned_topbit_01(crypto_int16_z);
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int16 crypto_int16_leq_mask(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $-1,%1\n cmpw %3,%2\n cmovlew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  वापस crypto_int16_z;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,%w2,sxth\n csetm %w0,le" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  वापस crypto_int16_z;
#अन्यथा
  वापस ~crypto_int16_smaller_mask(crypto_int16_y,crypto_int16_x);
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int16 crypto_int16_leq_01(crypto_int16 crypto_int16_x,crypto_int16 crypto_int16_y) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 crypto_int16_q,crypto_int16_z;
  __asm__ ("xorw %0,%0\n movw $1,%1\n cmpw %3,%2\n cmovlew %1,%0" : "=&r"(crypto_int16_z), "=&r"(crypto_int16_q) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  वापस crypto_int16_z;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int16 crypto_int16_z;
  __asm__ ("sxth %w0,%w1\n cmp %w0,%w2,sxth\n cset %w0,le" : "=&r"(crypto_int16_z) : "r"(crypto_int16_x), "r"(crypto_int16_y) : "cc");
  वापस crypto_int16_z;
#अन्यथा
  वापस 1-crypto_int16_smaller_01(crypto_int16_y,crypto_int16_x);
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
पूर्णांक crypto_int16_ones_अंक(crypto_int16 crypto_int16_x) {
  crypto_int16_unsigned crypto_int16_y = crypto_int16_x;
  स्थिर crypto_int16 C0 = 0x5555;
  स्थिर crypto_int16 C1 = 0x3333;
  स्थिर crypto_int16 C2 = 0x0f0f;
  crypto_int16_y -= ((crypto_int16_y >> 1) & C0);
  crypto_int16_y = (crypto_int16_y & C1) + ((crypto_int16_y >> 2) & C1);
  crypto_int16_y = (crypto_int16_y + (crypto_int16_y >> 4)) & C2;
  crypto_int16_y = (crypto_int16_y + (crypto_int16_y >> 8)) & 0xff;
  वापस crypto_int16_y;
}

__attribute__((unused))
अटल अंतरभूत
पूर्णांक crypto_int16_bottomzeros_अंक(crypto_int16 crypto_int16_x) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  crypto_int16 fallback = 16;
  __asm__ ("bsfw %0,%0\n cmovew %1,%0" : "+&r"(crypto_int16_x) : "r"(fallback) : "cc");
  वापस crypto_int16_x;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  int64_t crypto_int16_y;
  __asm__ ("orr %w0,%w1,-65536\n rbit %w0,%w0\n clz %w0,%w0" : "=r"(crypto_int16_y) : "r"(crypto_int16_x) : );
  वापस crypto_int16_y;
#अन्यथा
  crypto_int16 crypto_int16_y = crypto_int16_x ^ (crypto_int16_x-1);
  crypto_int16_y = ((crypto_int16) crypto_int16_y) >> 1;
  crypto_int16_y &= ~(crypto_int16_x & (((crypto_int16) 1) << (16-1)));
  वापस crypto_int16_ones_अंक(crypto_int16_y);
#पूर्ण_अगर
}

#पूर्ण_अगर

/* from supercop-20240808/cryptoint/crypto_int32.h */
/* auto-generated: cd cryptoint; ./autogen */
/* cryptoint 20240806 */

#अगर_अघोषित crypto_int32_h
#घोषणा crypto_int32_h

#घोषणा crypto_int32 int32_t
#घोषणा crypto_int32_unsigned uint32_t



__attribute__((unused))
अटल अंतरभूत
crypto_int32 crypto_int32_load(स्थिर अचिन्हित अक्षर *crypto_int32_s) {
  crypto_int32 crypto_int32_z = 0;
  crypto_int32_z |= ((crypto_int32) (*crypto_int32_s++)) << 0;
  crypto_int32_z |= ((crypto_int32) (*crypto_int32_s++)) << 8;
  crypto_int32_z |= ((crypto_int32) (*crypto_int32_s++)) << 16;
  crypto_int32_z |= ((crypto_int32) (*crypto_int32_s++)) << 24;
  वापस crypto_int32_z;
}

__attribute__((unused))
अटल अंतरभूत
व्योम crypto_int32_store(अचिन्हित अक्षर *crypto_int32_s,crypto_int32 crypto_int32_x) {
  *crypto_int32_s++ = crypto_int32_x >> 0;
  *crypto_int32_s++ = crypto_int32_x >> 8;
  *crypto_int32_s++ = crypto_int32_x >> 16;
  *crypto_int32_s++ = crypto_int32_x >> 24;
}

__attribute__((unused))
अटल अंतरभूत
crypto_int32 crypto_int32_negative_mask(crypto_int32 crypto_int32_x) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarl $31,%0" : "+r"(crypto_int32_x) : : "cc");
  वापस crypto_int32_x;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_y;
  __asm__ ("asr %w0,%w1,31" : "=r"(crypto_int32_y) : "r"(crypto_int32_x) : );
  वापस crypto_int32_y;
#अन्यथा
  crypto_int32_x >>= 32-6;
  crypto_int32_x ^= crypto_int32_optblocker;
  crypto_int32_x >>= 5;
  वापस crypto_int32_x;
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int32_unsigned crypto_int32_unsigned_topbit_01(crypto_int32_unsigned crypto_int32_x) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("shrl $31,%0" : "+r"(crypto_int32_x) : : "cc");
  वापस crypto_int32_x;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_y;
  __asm__ ("lsr %w0,%w1,31" : "=r"(crypto_int32_y) : "r"(crypto_int32_x) : );
  वापस crypto_int32_y;
#अन्यथा
  crypto_int32_x >>= 32-6;
  crypto_int32_x ^= crypto_int32_optblocker;
  crypto_int32_x >>= 5;
  वापस crypto_int32_x;
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int32 crypto_int32_negative_01(crypto_int32 crypto_int32_x) {
  वापस crypto_int32_unsigned_topbit_01(crypto_int32_x);
}

__attribute__((unused))
अटल अंतरभूत
crypto_int32 crypto_int32_topbit_mask(crypto_int32 crypto_int32_x) {
  वापस crypto_int32_negative_mask(crypto_int32_x);
}

__attribute__((unused))
अटल अंतरभूत
crypto_int32 crypto_int32_topbit_01(crypto_int32 crypto_int32_x) {
  वापस crypto_int32_unsigned_topbit_01(crypto_int32_x);
}

__attribute__((unused))
अटल अंतरभूत
crypto_int32 crypto_int32_bottombit_mask(crypto_int32 crypto_int32_x) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andl $1,%0" : "+r"(crypto_int32_x) : : "cc");
  वापस -crypto_int32_x;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_y;
  __asm__ ("sbfx %w0,%w1,0,1" : "=r"(crypto_int32_y) : "r"(crypto_int32_x) : );
  वापस crypto_int32_y;
#अन्यथा
  crypto_int32_x &= 1 ^ crypto_int32_optblocker;
  वापस -crypto_int32_x;
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int32 crypto_int32_bottombit_01(crypto_int32 crypto_int32_x) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andl $1,%0" : "+r"(crypto_int32_x) : : "cc");
  वापस crypto_int32_x;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_y;
  __asm__ ("ubfx %w0,%w1,0,1" : "=r"(crypto_int32_y) : "r"(crypto_int32_x) : );
  वापस crypto_int32_y;
#अन्यथा
  crypto_int32_x &= 1 ^ crypto_int32_optblocker;
  वापस crypto_int32_x;
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int32 crypto_int32_bitinrangepublicpos_mask(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarl %%cl,%0" : "+r"(crypto_int32_x) : "c"(crypto_int32_s) : "cc");
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %w0,%w0,%w1" : "+r"(crypto_int32_x) : "r"(crypto_int32_s) : );
#अन्यथा
  crypto_int32_x >>= crypto_int32_s ^ crypto_int32_optblocker;
#पूर्ण_अगर
  वापस crypto_int32_bottombit_mask(crypto_int32_x);
}

__attribute__((unused))
अटल अंतरभूत
crypto_int32 crypto_int32_bitinrangepublicpos_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarl %%cl,%0" : "+r"(crypto_int32_x) : "c"(crypto_int32_s) : "cc");
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %w0,%w0,%w1" : "+r"(crypto_int32_x) : "r"(crypto_int32_s) : );
#अन्यथा
  crypto_int32_x >>= crypto_int32_s ^ crypto_int32_optblocker;
#पूर्ण_अगर
  वापस crypto_int32_bottombit_01(crypto_int32_x);
}

__attribute__((unused))
अटल अंतरभूत
crypto_int32 crypto_int32_shlmod(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("shll %%cl,%0" : "+r"(crypto_int32_x) : "c"(crypto_int32_s) : "cc");
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("lsl %w0,%w0,%w1" : "+r"(crypto_int32_x) : "r"(crypto_int32_s) : );
#अन्यथा
  पूर्णांक crypto_int32_k, crypto_int32_l;
  क्रम (crypto_int32_l = 0,crypto_int32_k = 1;crypto_int32_k < 32;++crypto_int32_l,crypto_int32_k *= 2)
    crypto_int32_x ^= (crypto_int32_x ^ (crypto_int32_x << crypto_int32_k)) & crypto_int32_bitinrangepublicpos_mask(crypto_int32_s,crypto_int32_l);
#पूर्ण_अगर
  वापस crypto_int32_x;
}

__attribute__((unused))
अटल अंतरभूत
crypto_int32 crypto_int32_shrmod(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarl %%cl,%0" : "+r"(crypto_int32_x) : "c"(crypto_int32_s) : "cc");
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %w0,%w0,%w1" : "+r"(crypto_int32_x) : "r"(crypto_int32_s) : );
#अन्यथा
  पूर्णांक crypto_int32_k, crypto_int32_l;
  क्रम (crypto_int32_l = 0,crypto_int32_k = 1;crypto_int32_k < 32;++crypto_int32_l,crypto_int32_k *= 2)
    crypto_int32_x ^= (crypto_int32_x ^ (crypto_int32_x >> crypto_int32_k)) & crypto_int32_bitinrangepublicpos_mask(crypto_int32_s,crypto_int32_l);
#पूर्ण_अगर
  वापस crypto_int32_x;
}

__attribute__((unused))
अटल अंतरभूत
crypto_int32 crypto_int32_bitmod_mask(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
  crypto_int32_x = crypto_int32_shrmod(crypto_int32_x,crypto_int32_s);
  वापस crypto_int32_bottombit_mask(crypto_int32_x);
}

__attribute__((unused))
अटल अंतरभूत
crypto_int32 crypto_int32_bitmod_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_s) {
  crypto_int32_x = crypto_int32_shrmod(crypto_int32_x,crypto_int32_s);
  वापस crypto_int32_bottombit_01(crypto_int32_x);
}

__attribute__((unused))
अटल अंतरभूत
crypto_int32 crypto_int32_nonzero_mask(crypto_int32 crypto_int32_x) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n testl %2,%2\n cmovnel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  वापस crypto_int32_z;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n csetm %w0,ne" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  वापस crypto_int32_z;
#अन्यथा
  crypto_int32_x |= -crypto_int32_x;
  वापस crypto_int32_negative_mask(crypto_int32_x);
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int32 crypto_int32_nonzero_01(crypto_int32 crypto_int32_x) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n testl %2,%2\n cmovnel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  वापस crypto_int32_z;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n cset %w0,ne" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  वापस crypto_int32_z;
#अन्यथा
  crypto_int32_x |= -crypto_int32_x;
  वापस crypto_int32_unsigned_topbit_01(crypto_int32_x);
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int32 crypto_int32_positive_mask(crypto_int32 crypto_int32_x) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n testl %2,%2\n cmovgl %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  वापस crypto_int32_z;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n csetm %w0,gt" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  वापस crypto_int32_z;
#अन्यथा
  crypto_int32 crypto_int32_z = -crypto_int32_x;
  crypto_int32_z ^= crypto_int32_x & crypto_int32_z;
  वापस crypto_int32_negative_mask(crypto_int32_z);
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int32 crypto_int32_positive_01(crypto_int32 crypto_int32_x) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n testl %2,%2\n cmovgl %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  वापस crypto_int32_z;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n cset %w0,gt" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  वापस crypto_int32_z;
#अन्यथा
  crypto_int32 crypto_int32_z = -crypto_int32_x;
  crypto_int32_z ^= crypto_int32_x & crypto_int32_z;
  वापस crypto_int32_unsigned_topbit_01(crypto_int32_z);
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int32 crypto_int32_zero_mask(crypto_int32 crypto_int32_x) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n testl %2,%2\n cmovel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  वापस crypto_int32_z;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n csetm %w0,eq" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  वापस crypto_int32_z;
#अन्यथा
  वापस ~crypto_int32_nonzero_mask(crypto_int32_x);
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int32 crypto_int32_zero_01(crypto_int32 crypto_int32_x) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n testl %2,%2\n cmovel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x) : "cc");
  वापस crypto_int32_z;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,0\n cset %w0,eq" : "=r"(crypto_int32_z) : "r"(crypto_int32_x) : "cc");
  वापस crypto_int32_z;
#अन्यथा
  वापस 1-crypto_int32_nonzero_01(crypto_int32_x);
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int32 crypto_int32_unequal_mask(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n cmpl %3,%2\n cmovnel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  वापस crypto_int32_z;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n csetm %w0,ne" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  वापस crypto_int32_z;
#अन्यथा
  वापस crypto_int32_nonzero_mask(crypto_int32_x ^ crypto_int32_y);
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int32 crypto_int32_unequal_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n cmpl %3,%2\n cmovnel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  वापस crypto_int32_z;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n cset %w0,ne" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  वापस crypto_int32_z;
#अन्यथा
  वापस crypto_int32_nonzero_01(crypto_int32_x ^ crypto_int32_y);
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int32 crypto_int32_equal_mask(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n cmpl %3,%2\n cmovel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  वापस crypto_int32_z;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n csetm %w0,eq" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  वापस crypto_int32_z;
#अन्यथा
  वापस ~crypto_int32_unequal_mask(crypto_int32_x,crypto_int32_y);
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int32 crypto_int32_equal_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n cmpl %3,%2\n cmovel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  वापस crypto_int32_z;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n cset %w0,eq" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  वापस crypto_int32_z;
#अन्यथा
  वापस 1-crypto_int32_unequal_01(crypto_int32_x,crypto_int32_y);
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int32 crypto_int32_min(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpl %1,%0\n cmovgl %1,%0" : "+r"(crypto_int32_x) : "r"(crypto_int32_y) : "cc");
  वापस crypto_int32_x;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("cmp %w0,%w1\n csel %w0,%w0,%w1,lt" : "+r"(crypto_int32_x) : "r"(crypto_int32_y) : "cc");
  वापस crypto_int32_x;
#अन्यथा
  crypto_int64 crypto_int32_r = (crypto_int64)crypto_int32_y ^ (crypto_int64)crypto_int32_x;
  crypto_int64 crypto_int32_z = (crypto_int64)crypto_int32_y - (crypto_int64)crypto_int32_x;
  crypto_int32_z ^= crypto_int32_r & (crypto_int32_z ^ crypto_int32_y);
  crypto_int32_z = crypto_int32_negative_mask(crypto_int32_z);
  crypto_int32_z &= crypto_int32_r;
  वापस crypto_int32_x ^ crypto_int32_z;
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int32 crypto_int32_max(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpl %1,%0\n cmovll %1,%0" : "+r"(crypto_int32_x) : "r"(crypto_int32_y) : "cc");
  वापस crypto_int32_x;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("cmp %w0,%w1\n csel %w0,%w1,%w0,lt" : "+r"(crypto_int32_x) : "r"(crypto_int32_y) : "cc");
  वापस crypto_int32_x;
#अन्यथा
  crypto_int64 crypto_int32_r = (crypto_int64)crypto_int32_y ^ (crypto_int64)crypto_int32_x;
  crypto_int64 crypto_int32_z = (crypto_int64)crypto_int32_y - (crypto_int64)crypto_int32_x;
  crypto_int32_z ^= crypto_int32_r & (crypto_int32_z ^ crypto_int32_y);
  crypto_int32_z = crypto_int32_negative_mask(crypto_int32_z);
  crypto_int32_z &= crypto_int32_r;
  वापस crypto_int32_y ^ crypto_int32_z;
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
व्योम crypto_int32_minmax(crypto_int32 *crypto_int32_p,crypto_int32 *crypto_int32_q) {
  crypto_int32 crypto_int32_x = *crypto_int32_p;
  crypto_int32 crypto_int32_y = *crypto_int32_q;
#अगर defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmpl %2,%1\n movl %1,%0\n cmovgl %2,%1\n cmovgl %0,%2" : "=&r"(crypto_int32_z), "+&r"(crypto_int32_x), "+r"(crypto_int32_y) : : "cc");
  *crypto_int32_p = crypto_int32_x;
  *crypto_int32_q = crypto_int32_y;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_r, crypto_int32_s;
  __asm__ ("cmp %w2,%w3\n csel %w0,%w2,%w3,lt\n csel %w1,%w3,%w2,lt" : "=&r"(crypto_int32_r), "=r"(crypto_int32_s) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  *crypto_int32_p = crypto_int32_r;
  *crypto_int32_q = crypto_int32_s;
#अन्यथा
  crypto_int64 crypto_int32_r = (crypto_int64)crypto_int32_y ^ (crypto_int64)crypto_int32_x;
  crypto_int64 crypto_int32_z = (crypto_int64)crypto_int32_y - (crypto_int64)crypto_int32_x;
  crypto_int32_z ^= crypto_int32_r & (crypto_int32_z ^ crypto_int32_y);
  crypto_int32_z = crypto_int32_negative_mask(crypto_int32_z);
  crypto_int32_z &= crypto_int32_r;
  crypto_int32_x ^= crypto_int32_z;
  crypto_int32_y ^= crypto_int32_z;
  *crypto_int32_p = crypto_int32_x;
  *crypto_int32_q = crypto_int32_y;
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int32 crypto_int32_smaller_mask(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n cmpl %3,%2\n cmovll %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  वापस crypto_int32_z;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n csetm %w0,lt" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  वापस crypto_int32_z;
#अन्यथा
  crypto_int32 crypto_int32_r = crypto_int32_x ^ crypto_int32_y;
  crypto_int32 crypto_int32_z = crypto_int32_x - crypto_int32_y;
  crypto_int32_z ^= crypto_int32_r & (crypto_int32_z ^ crypto_int32_x);
  वापस crypto_int32_negative_mask(crypto_int32_z);
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int32 crypto_int32_smaller_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n cmpl %3,%2\n cmovll %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  वापस crypto_int32_z;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n cset %w0,lt" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  वापस crypto_int32_z;
#अन्यथा
  crypto_int32 crypto_int32_r = crypto_int32_x ^ crypto_int32_y;
  crypto_int32 crypto_int32_z = crypto_int32_x - crypto_int32_y;
  crypto_int32_z ^= crypto_int32_r & (crypto_int32_z ^ crypto_int32_x);
  वापस crypto_int32_unsigned_topbit_01(crypto_int32_z);
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int32 crypto_int32_leq_mask(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $-1,%1\n cmpl %3,%2\n cmovlel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  वापस crypto_int32_z;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n csetm %w0,le" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  वापस crypto_int32_z;
#अन्यथा
  वापस ~crypto_int32_smaller_mask(crypto_int32_y,crypto_int32_x);
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int32 crypto_int32_leq_01(crypto_int32 crypto_int32_x,crypto_int32 crypto_int32_y) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 crypto_int32_q,crypto_int32_z;
  __asm__ ("xorl %0,%0\n movl $1,%1\n cmpl %3,%2\n cmovlel %1,%0" : "=&r"(crypto_int32_z), "=&r"(crypto_int32_q) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  वापस crypto_int32_z;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int32 crypto_int32_z;
  __asm__ ("cmp %w1,%w2\n cset %w0,le" : "=r"(crypto_int32_z) : "r"(crypto_int32_x), "r"(crypto_int32_y) : "cc");
  वापस crypto_int32_z;
#अन्यथा
  वापस 1-crypto_int32_smaller_01(crypto_int32_y,crypto_int32_x);
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
पूर्णांक crypto_int32_ones_अंक(crypto_int32 crypto_int32_x) {
  crypto_int32_unsigned crypto_int32_y = crypto_int32_x;
  स्थिर crypto_int32 C0 = 0x55555555;
  स्थिर crypto_int32 C1 = 0x33333333;
  स्थिर crypto_int32 C2 = 0x0f0f0f0f;
  crypto_int32_y -= ((crypto_int32_y >> 1) & C0);
  crypto_int32_y = (crypto_int32_y & C1) + ((crypto_int32_y >> 2) & C1);
  crypto_int32_y = (crypto_int32_y + (crypto_int32_y >> 4)) & C2;
  crypto_int32_y += crypto_int32_y >> 8;
  crypto_int32_y = (crypto_int32_y + (crypto_int32_y >> 16)) & 0xff;
  वापस crypto_int32_y;
}

__attribute__((unused))
अटल अंतरभूत
पूर्णांक crypto_int32_bottomzeros_अंक(crypto_int32 crypto_int32_x) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  crypto_int32 fallback = 32;
  __asm__ ("bsfl %0,%0\n cmovel %1,%0" : "+&r"(crypto_int32_x) : "r"(fallback) : "cc");
  वापस crypto_int32_x;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  int64_t crypto_int32_y;
  __asm__ ("rbit %w0,%w1\n clz %w0,%w0" : "=r"(crypto_int32_y) : "r"(crypto_int32_x) : );
  वापस crypto_int32_y;
#अन्यथा
  crypto_int32 crypto_int32_y = crypto_int32_x ^ (crypto_int32_x-1);
  crypto_int32_y = ((crypto_int32) crypto_int32_y) >> 1;
  crypto_int32_y &= ~(crypto_int32_x & (((crypto_int32) 1) << (32-1)));
  वापस crypto_int32_ones_अंक(crypto_int32_y);
#पूर्ण_अगर
}

#पूर्ण_अगर

/* from supercop-20240808/cryptoint/crypto_int64.h */
/* auto-generated: cd cryptoint; ./autogen */
/* cryptoint 20240806 */

#अगर_अघोषित crypto_int64_h
#घोषणा crypto_int64_h

#घोषणा crypto_int64 int64_t
#घोषणा crypto_int64_unsigned uint64_t



__attribute__((unused))
अटल अंतरभूत
crypto_int64 crypto_int64_load(स्थिर अचिन्हित अक्षर *crypto_int64_s) {
  crypto_int64 crypto_int64_z = 0;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 0;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 8;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 16;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 24;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 32;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 40;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 48;
  crypto_int64_z |= ((crypto_int64) (*crypto_int64_s++)) << 56;
  वापस crypto_int64_z;
}

__attribute__((unused))
अटल अंतरभूत
व्योम crypto_int64_store(अचिन्हित अक्षर *crypto_int64_s,crypto_int64 crypto_int64_x) {
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
अटल अंतरभूत
crypto_int64 crypto_int64_negative_mask(crypto_int64 crypto_int64_x) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarq $63,%0" : "+r"(crypto_int64_x) : : "cc");
  वापस crypto_int64_x;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_y;
  __asm__ ("asr %0,%1,63" : "=r"(crypto_int64_y) : "r"(crypto_int64_x) : );
  वापस crypto_int64_y;
#अन्यथा
  crypto_int64_x >>= 64-6;
  crypto_int64_x ^= crypto_int64_optblocker;
  crypto_int64_x >>= 5;
  वापस crypto_int64_x;
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int64_unsigned crypto_int64_unsigned_topbit_01(crypto_int64_unsigned crypto_int64_x) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("shrq $63,%0" : "+r"(crypto_int64_x) : : "cc");
  वापस crypto_int64_x;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_y;
  __asm__ ("lsr %0,%1,63" : "=r"(crypto_int64_y) : "r"(crypto_int64_x) : );
  वापस crypto_int64_y;
#अन्यथा
  crypto_int64_x >>= 64-6;
  crypto_int64_x ^= crypto_int64_optblocker;
  crypto_int64_x >>= 5;
  वापस crypto_int64_x;
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int64 crypto_int64_negative_01(crypto_int64 crypto_int64_x) {
  वापस crypto_int64_unsigned_topbit_01(crypto_int64_x);
}

__attribute__((unused))
अटल अंतरभूत
crypto_int64 crypto_int64_topbit_mask(crypto_int64 crypto_int64_x) {
  वापस crypto_int64_negative_mask(crypto_int64_x);
}

__attribute__((unused))
अटल अंतरभूत
crypto_int64 crypto_int64_topbit_01(crypto_int64 crypto_int64_x) {
  वापस crypto_int64_unsigned_topbit_01(crypto_int64_x);
}

__attribute__((unused))
अटल अंतरभूत
crypto_int64 crypto_int64_bottombit_mask(crypto_int64 crypto_int64_x) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andq $1,%0" : "+r"(crypto_int64_x) : : "cc");
  वापस -crypto_int64_x;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_y;
  __asm__ ("sbfx %0,%1,0,1" : "=r"(crypto_int64_y) : "r"(crypto_int64_x) : );
  वापस crypto_int64_y;
#अन्यथा
  crypto_int64_x &= 1 ^ crypto_int64_optblocker;
  वापस -crypto_int64_x;
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int64 crypto_int64_bottombit_01(crypto_int64 crypto_int64_x) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("andq $1,%0" : "+r"(crypto_int64_x) : : "cc");
  वापस crypto_int64_x;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_y;
  __asm__ ("ubfx %0,%1,0,1" : "=r"(crypto_int64_y) : "r"(crypto_int64_x) : );
  वापस crypto_int64_y;
#अन्यथा
  crypto_int64_x &= 1 ^ crypto_int64_optblocker;
  वापस crypto_int64_x;
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int64 crypto_int64_bitinrangepublicpos_mask(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarq %%cl,%0" : "+r"(crypto_int64_x) : "c"(crypto_int64_s) : "cc");
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %0,%0,%1" : "+r"(crypto_int64_x) : "r"(crypto_int64_s) : );
#अन्यथा
  crypto_int64_x >>= crypto_int64_s ^ crypto_int64_optblocker;
#पूर्ण_अगर
  वापस crypto_int64_bottombit_mask(crypto_int64_x);
}

__attribute__((unused))
अटल अंतरभूत
crypto_int64 crypto_int64_bitinrangepublicpos_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarq %%cl,%0" : "+r"(crypto_int64_x) : "c"(crypto_int64_s) : "cc");
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %0,%0,%1" : "+r"(crypto_int64_x) : "r"(crypto_int64_s) : );
#अन्यथा
  crypto_int64_x >>= crypto_int64_s ^ crypto_int64_optblocker;
#पूर्ण_अगर
  वापस crypto_int64_bottombit_01(crypto_int64_x);
}

__attribute__((unused))
अटल अंतरभूत
crypto_int64 crypto_int64_shlmod(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("shlq %%cl,%0" : "+r"(crypto_int64_x) : "c"(crypto_int64_s) : "cc");
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("lsl %0,%0,%1" : "+r"(crypto_int64_x) : "r"(crypto_int64_s) : );
#अन्यथा
  पूर्णांक crypto_int64_k, crypto_int64_l;
  क्रम (crypto_int64_l = 0,crypto_int64_k = 1;crypto_int64_k < 64;++crypto_int64_l,crypto_int64_k *= 2)
    crypto_int64_x ^= (crypto_int64_x ^ (crypto_int64_x << crypto_int64_k)) & crypto_int64_bitinrangepublicpos_mask(crypto_int64_s,crypto_int64_l);
#पूर्ण_अगर
  वापस crypto_int64_x;
}

__attribute__((unused))
अटल अंतरभूत
crypto_int64 crypto_int64_shrmod(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("sarq %%cl,%0" : "+r"(crypto_int64_x) : "c"(crypto_int64_s) : "cc");
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("asr %0,%0,%1" : "+r"(crypto_int64_x) : "r"(crypto_int64_s) : );
#अन्यथा
  पूर्णांक crypto_int64_k, crypto_int64_l;
  क्रम (crypto_int64_l = 0,crypto_int64_k = 1;crypto_int64_k < 64;++crypto_int64_l,crypto_int64_k *= 2)
    crypto_int64_x ^= (crypto_int64_x ^ (crypto_int64_x >> crypto_int64_k)) & crypto_int64_bitinrangepublicpos_mask(crypto_int64_s,crypto_int64_l);
#पूर्ण_अगर
  वापस crypto_int64_x;
}

__attribute__((unused))
अटल अंतरभूत
crypto_int64 crypto_int64_bitmod_mask(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
  crypto_int64_x = crypto_int64_shrmod(crypto_int64_x,crypto_int64_s);
  वापस crypto_int64_bottombit_mask(crypto_int64_x);
}

__attribute__((unused))
अटल अंतरभूत
crypto_int64 crypto_int64_bitmod_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_s) {
  crypto_int64_x = crypto_int64_shrmod(crypto_int64_x,crypto_int64_s);
  वापस crypto_int64_bottombit_01(crypto_int64_x);
}

__attribute__((unused))
अटल अंतरभूत
crypto_int64 crypto_int64_nonzero_mask(crypto_int64 crypto_int64_x) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n testq %2,%2\n cmovneq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  वापस crypto_int64_z;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n csetm %0,ne" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  वापस crypto_int64_z;
#अन्यथा
  crypto_int64_x |= -crypto_int64_x;
  वापस crypto_int64_negative_mask(crypto_int64_x);
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int64 crypto_int64_nonzero_01(crypto_int64 crypto_int64_x) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n testq %2,%2\n cmovneq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  वापस crypto_int64_z;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n cset %0,ne" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  वापस crypto_int64_z;
#अन्यथा
  crypto_int64_x |= -crypto_int64_x;
  वापस crypto_int64_unsigned_topbit_01(crypto_int64_x);
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int64 crypto_int64_positive_mask(crypto_int64 crypto_int64_x) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n testq %2,%2\n cmovgq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  वापस crypto_int64_z;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n csetm %0,gt" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  वापस crypto_int64_z;
#अन्यथा
  crypto_int64 crypto_int64_z = -crypto_int64_x;
  crypto_int64_z ^= crypto_int64_x & crypto_int64_z;
  वापस crypto_int64_negative_mask(crypto_int64_z);
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int64 crypto_int64_positive_01(crypto_int64 crypto_int64_x) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n testq %2,%2\n cmovgq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  वापस crypto_int64_z;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n cset %0,gt" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  वापस crypto_int64_z;
#अन्यथा
  crypto_int64 crypto_int64_z = -crypto_int64_x;
  crypto_int64_z ^= crypto_int64_x & crypto_int64_z;
  वापस crypto_int64_unsigned_topbit_01(crypto_int64_z);
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int64 crypto_int64_zero_mask(crypto_int64 crypto_int64_x) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n testq %2,%2\n cmoveq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  वापस crypto_int64_z;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n csetm %0,eq" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  वापस crypto_int64_z;
#अन्यथा
  वापस ~crypto_int64_nonzero_mask(crypto_int64_x);
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int64 crypto_int64_zero_01(crypto_int64 crypto_int64_x) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n testq %2,%2\n cmoveq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x) : "cc");
  वापस crypto_int64_z;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,0\n cset %0,eq" : "=r"(crypto_int64_z) : "r"(crypto_int64_x) : "cc");
  वापस crypto_int64_z;
#अन्यथा
  वापस 1-crypto_int64_nonzero_01(crypto_int64_x);
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int64 crypto_int64_unequal_mask(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n cmpq %3,%2\n cmovneq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  वापस crypto_int64_z;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n csetm %0,ne" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  वापस crypto_int64_z;
#अन्यथा
  वापस crypto_int64_nonzero_mask(crypto_int64_x ^ crypto_int64_y);
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int64 crypto_int64_unequal_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n cmpq %3,%2\n cmovneq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  वापस crypto_int64_z;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n cset %0,ne" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  वापस crypto_int64_z;
#अन्यथा
  वापस crypto_int64_nonzero_01(crypto_int64_x ^ crypto_int64_y);
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int64 crypto_int64_equal_mask(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n cmpq %3,%2\n cmoveq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  वापस crypto_int64_z;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n csetm %0,eq" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  वापस crypto_int64_z;
#अन्यथा
  वापस ~crypto_int64_unequal_mask(crypto_int64_x,crypto_int64_y);
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int64 crypto_int64_equal_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n cmpq %3,%2\n cmoveq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  वापस crypto_int64_z;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n cset %0,eq" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  वापस crypto_int64_z;
#अन्यथा
  वापस 1-crypto_int64_unequal_01(crypto_int64_x,crypto_int64_y);
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int64 crypto_int64_min(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpq %1,%0\n cmovgq %1,%0" : "+r"(crypto_int64_x) : "r"(crypto_int64_y) : "cc");
  वापस crypto_int64_x;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("cmp %0,%1\n csel %0,%0,%1,lt" : "+r"(crypto_int64_x) : "r"(crypto_int64_y) : "cc");
  वापस crypto_int64_x;
#अन्यथा
  crypto_int64 crypto_int64_r = crypto_int64_y ^ crypto_int64_x;
  crypto_int64 crypto_int64_z = crypto_int64_y - crypto_int64_x;
  crypto_int64_z ^= crypto_int64_r & (crypto_int64_z ^ crypto_int64_y);
  crypto_int64_z = crypto_int64_negative_mask(crypto_int64_z);
  crypto_int64_z &= crypto_int64_r;
  वापस crypto_int64_x ^ crypto_int64_z;
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int64 crypto_int64_max(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  __asm__ ("cmpq %1,%0\n cmovlq %1,%0" : "+r"(crypto_int64_x) : "r"(crypto_int64_y) : "cc");
  वापस crypto_int64_x;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  __asm__ ("cmp %0,%1\n csel %0,%1,%0,lt" : "+r"(crypto_int64_x) : "r"(crypto_int64_y) : "cc");
  वापस crypto_int64_x;
#अन्यथा
  crypto_int64 crypto_int64_r = crypto_int64_y ^ crypto_int64_x;
  crypto_int64 crypto_int64_z = crypto_int64_y - crypto_int64_x;
  crypto_int64_z ^= crypto_int64_r & (crypto_int64_z ^ crypto_int64_y);
  crypto_int64_z = crypto_int64_negative_mask(crypto_int64_z);
  crypto_int64_z &= crypto_int64_r;
  वापस crypto_int64_y ^ crypto_int64_z;
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
व्योम crypto_int64_minmax(crypto_int64 *crypto_int64_p,crypto_int64 *crypto_int64_q) {
  crypto_int64 crypto_int64_x = *crypto_int64_p;
  crypto_int64 crypto_int64_y = *crypto_int64_q;
#अगर defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmpq %2,%1\n movq %1,%0\n cmovgq %2,%1\n cmovgq %0,%2" : "=&r"(crypto_int64_z), "+&r"(crypto_int64_x), "+r"(crypto_int64_y) : : "cc");
  *crypto_int64_p = crypto_int64_x;
  *crypto_int64_q = crypto_int64_y;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_r, crypto_int64_s;
  __asm__ ("cmp %2,%3\n csel %0,%2,%3,lt\n csel %1,%3,%2,lt" : "=&r"(crypto_int64_r), "=r"(crypto_int64_s) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  *crypto_int64_p = crypto_int64_r;
  *crypto_int64_q = crypto_int64_s;
#अन्यथा
  crypto_int64 crypto_int64_r = crypto_int64_y ^ crypto_int64_x;
  crypto_int64 crypto_int64_z = crypto_int64_y - crypto_int64_x;
  crypto_int64_z ^= crypto_int64_r & (crypto_int64_z ^ crypto_int64_y);
  crypto_int64_z = crypto_int64_negative_mask(crypto_int64_z);
  crypto_int64_z &= crypto_int64_r;
  crypto_int64_x ^= crypto_int64_z;
  crypto_int64_y ^= crypto_int64_z;
  *crypto_int64_p = crypto_int64_x;
  *crypto_int64_q = crypto_int64_y;
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int64 crypto_int64_smaller_mask(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n cmpq %3,%2\n cmovlq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  वापस crypto_int64_z;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n csetm %0,lt" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  वापस crypto_int64_z;
#अन्यथा
  crypto_int64 crypto_int64_r = crypto_int64_x ^ crypto_int64_y;
  crypto_int64 crypto_int64_z = crypto_int64_x - crypto_int64_y;
  crypto_int64_z ^= crypto_int64_r & (crypto_int64_z ^ crypto_int64_x);
  वापस crypto_int64_negative_mask(crypto_int64_z);
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int64 crypto_int64_smaller_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n cmpq %3,%2\n cmovlq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  वापस crypto_int64_z;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n cset %0,lt" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  वापस crypto_int64_z;
#अन्यथा
  crypto_int64 crypto_int64_r = crypto_int64_x ^ crypto_int64_y;
  crypto_int64 crypto_int64_z = crypto_int64_x - crypto_int64_y;
  crypto_int64_z ^= crypto_int64_r & (crypto_int64_z ^ crypto_int64_x);
  वापस crypto_int64_unsigned_topbit_01(crypto_int64_z);
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int64 crypto_int64_leq_mask(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $-1,%1\n cmpq %3,%2\n cmovleq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  वापस crypto_int64_z;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n csetm %0,le" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  वापस crypto_int64_z;
#अन्यथा
  वापस ~crypto_int64_smaller_mask(crypto_int64_y,crypto_int64_x);
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
crypto_int64 crypto_int64_leq_01(crypto_int64 crypto_int64_x,crypto_int64 crypto_int64_y) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 crypto_int64_q,crypto_int64_z;
  __asm__ ("xorq %0,%0\n movq $1,%1\n cmpq %3,%2\n cmovleq %1,%0" : "=&r"(crypto_int64_z), "=&r"(crypto_int64_q) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  वापस crypto_int64_z;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  crypto_int64 crypto_int64_z;
  __asm__ ("cmp %1,%2\n cset %0,le" : "=r"(crypto_int64_z) : "r"(crypto_int64_x), "r"(crypto_int64_y) : "cc");
  वापस crypto_int64_z;
#अन्यथा
  वापस 1-crypto_int64_smaller_01(crypto_int64_y,crypto_int64_x);
#पूर्ण_अगर
}

__attribute__((unused))
अटल अंतरभूत
पूर्णांक crypto_int64_ones_अंक(crypto_int64 crypto_int64_x) {
  crypto_int64_unsigned crypto_int64_y = crypto_int64_x;
  स्थिर crypto_int64 C0 = 0x5555555555555555;
  स्थिर crypto_int64 C1 = 0x3333333333333333;
  स्थिर crypto_int64 C2 = 0x0f0f0f0f0f0f0f0f;
  crypto_int64_y -= ((crypto_int64_y >> 1) & C0);
  crypto_int64_y = (crypto_int64_y & C1) + ((crypto_int64_y >> 2) & C1);
  crypto_int64_y = (crypto_int64_y + (crypto_int64_y >> 4)) & C2;
  crypto_int64_y += crypto_int64_y >> 8;
  crypto_int64_y += crypto_int64_y >> 16;
  crypto_int64_y = (crypto_int64_y + (crypto_int64_y >> 32)) & 0xff;
  वापस crypto_int64_y;
}

__attribute__((unused))
अटल अंतरभूत
पूर्णांक crypto_int64_bottomzeros_अंक(crypto_int64 crypto_int64_x) {
#अगर defined(__GNUC__) && defined(__x86_64__)
  crypto_int64 fallback = 64;
  __asm__ ("bsfq %0,%0\n cmoveq %1,%0" : "+&r"(crypto_int64_x) : "r"(fallback) : "cc");
  वापस crypto_int64_x;
#या_अगर defined(__GNUC__) && defined(__aarch64__)
  int64_t crypto_int64_y;
  __asm__ ("rbit %0,%1\n clz %0,%0" : "=r"(crypto_int64_y) : "r"(crypto_int64_x) : );
  वापस crypto_int64_y;
#अन्यथा
  crypto_int64 crypto_int64_y = crypto_int64_x ^ (crypto_int64_x-1);
  crypto_int64_y = ((crypto_int64) crypto_int64_y) >> 1;
  crypto_int64_y &= ~(crypto_int64_x & (((crypto_int64) 1) << (64-1)));
  वापस crypto_int64_ones_अंक(crypto_int64_y);
#पूर्ण_अगर
}

#पूर्ण_अगर

/* from supercop-20240808/crypto_sort/int32/portable4/sort.c */
#घोषणा int32_MINMAX(a,b) crypto_int32_minmax(&a,&b)

अटल व्योम crypto_sort_int32(व्योम *array,दीर्घ दीर्घ n)
{
  दीर्घ दीर्घ शीर्ष,p,q,r,i,j;
  int32 *x = array;

  अगर (n < 2) वापस;
  शीर्ष = 1;
  जबतक (शीर्ष < n - शीर्ष) शीर्ष += शीर्ष;

  क्रम (p = शीर्ष;p >= 1;p >>= 1) {
    i = 0;
    जबतक (i + 2 * p <= n) {
      क्रम (j = i;j < i + p;++j)
        int32_MINMAX(x[j],x[j+p]);
      i += 2 * p;
    }
    क्रम (j = i;j < n - p;++j)
      int32_MINMAX(x[j],x[j+p]);

    i = 0;
    j = 0;
    क्रम (q = शीर्ष;q > p;q >>= 1) {
      अगर (j != i) क्रम (;;) {
        अगर (j == n - q) जाओ done;
        int32 a = x[j + p];
        क्रम (r = q;r > p;r >>= 1)
          int32_MINMAX(a,x[j + r]);
        x[j + p] = a;
        ++j;
        अगर (j == i + p) {
          i += 2 * p;
          अवरोध;
        }
      }
      जबतक (i + p <= n - q) {
        क्रम (j = i;j < i + p;++j) {
          int32 a = x[j + p];
          क्रम (r = q;r > p;r >>= 1)
            int32_MINMAX(a,x[j+r]);
          x[j + p] = a;
        }
        i += 2 * p;
      }
      /* now i + p > n - q */
      j = i;
      जबतक (j < n - q) {
        int32 a = x[j + p];
        क्रम (r = q;r > p;r >>= 1)
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

अटल व्योम crypto_sort_uint32(व्योम *array,दीर्घ दीर्घ n)
{
  crypto_uint32 *x = array;
  दीर्घ दीर्घ j;
  क्रम (j = 0;j < n;++j) x[j] ^= 0x80000000;
  crypto_sort_int32(array,n);
  क्रम (j = 0;j < n;++j) x[j] ^= 0x80000000;
}

/* from supercop-20240808/crypto_kem/sntrup761/compact/kem.c */
// 20240806 djb: some automated conversion to cryptoint

#घोषणा p 761
#घोषणा q 4591
#घोषणा w 286
#घोषणा q12 ((q - 1) / 2)
प्रकार int8_t small;
प्रकार int16_t Fq;
#घोषणा Hash_bytes 32
#घोषणा Small_bytes ((p + 3) / 4)
प्रकार small Inputs[p];
#घोषणा Secret_कुंजियाँ_bytes (2 * Small_bytes)
#घोषणा Confirm_bytes 32

अटल small F3_freeze(int16_t x) { वापस x - 3 * ((10923 * x + 16384) >> 15); }

अटल Fq Fq_freeze(int32_t x) {
  स्थिर int32_t q16 = (0x10000 + q / 2) / q;
  स्थिर int32_t q20 = (0x100000 + q / 2) / q;
  स्थिर int32_t q28 = (0x10000000 + q / 2) / q;
  x -= q * ((q16 * x) >> 16);
  x -= q * ((q20 * x) >> 20);
  वापस x - q * ((q28 * x + 0x8000000) >> 28);
}

अटल पूर्णांक Weightw_mask(small *r) {
  पूर्णांक i, weight = 0;
  क्रम (i = 0; i < p; ++i) weight += crypto_int64_bottombit_01(r[i]);
  वापस crypto_int16_nonzero_mask(weight - w);
}

अटल व्योम uint32_divmod_uint14(uint32_t *Q, uint16_t *r, uint32_t x, uint16_t m) {
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

अटल uint16_t uint32_mod_uint14(uint32_t x, uint16_t m) {
  uint32_t Q;
  uint16_t r;
  uint32_divmod_uint14(&Q, &r, x, m);
  वापस r;
}

अटल व्योम Encode(अचिन्हित अक्षर *out, स्थिर uint16_t *R, स्थिर uint16_t *M, दीर्घ दीर्घ len) {
  अगर (len == 1) {
    uint16_t r = R[0], m = M[0];
    जबतक (m > 1) {
      *out++ = r;
      r >>= 8;
      m = (m + 255) >> 8;
    }
  }
  अगर (len > 1) {
    uint16_t R2[(len + 1) / 2], M2[(len + 1) / 2];
    दीर्घ दीर्घ i;
    क्रम (i = 0; i < len - 1; i += 2) {
      uint32_t m0 = M[i];
      uint32_t r = R[i] + R[i + 1] * m0;
      uint32_t m = M[i + 1] * m0;
      जबतक (m >= 16384) {
        *out++ = r;
        r >>= 8;
        m = (m + 255) >> 8;
      }
      R2[i / 2] = r;
      M2[i / 2] = m;
    }
    अगर (i < len) {
      R2[i / 2] = R[i];
      M2[i / 2] = M[i];
    }
    Encode(out, R2, M2, (len + 1) / 2);
  }
}

अटल व्योम Decode(uint16_t *out, स्थिर अचिन्हित अक्षर *S, स्थिर uint16_t *M, दीर्घ दीर्घ len) {
  अगर (len == 1) {
    अगर (M[0] == 1)
      *out = 0;
    अन्यथा अगर (M[0] <= 256)
      *out = uint32_mod_uint14(S[0], M[0]);
    अन्यथा
      *out = uint32_mod_uint14(S[0] + (((uint16_t)S[1]) << 8), M[0]);
  }
  अगर (len > 1) {
    uint16_t R2[(len + 1) / 2], M2[(len + 1) / 2], bottomr[len / 2];
    uint32_t bottomt[len / 2];
    दीर्घ दीर्घ i;
    क्रम (i = 0; i < len - 1; i += 2) {
      uint32_t m = M[i] * (uint32_t)M[i + 1];
      अगर (m > 256 * 16383) {
        bottomt[i / 2] = 256 * 256;
        bottomr[i / 2] = S[0] + 256 * S[1];
        S += 2;
        M2[i / 2] = (((m + 255) >> 8) + 255) >> 8;
      } अन्यथा अगर (m >= 16384) {
        bottomt[i / 2] = 256;
        bottomr[i / 2] = S[0];
        S += 1;
        M2[i / 2] = (m + 255) >> 8;
      } अन्यथा {
        bottomt[i / 2] = 1;
        bottomr[i / 2] = 0;
        M2[i / 2] = m;
      }
    }
    अगर (i < len) M2[i / 2] = M[i];
    Decode(R2, S, M2, (len + 1) / 2);
    क्रम (i = 0; i < len - 1; i += 2) {
      uint32_t r1, r = bottomr[i / 2];
      uint16_t r0;
      r += bottomt[i / 2] * R2[i / 2];
      uint32_divmod_uint14(&r1, &r0, r, M[i]);
      r1 = uint32_mod_uint14(r1, M[i + 1]);
      *out++ = r0;
      *out++ = r1;
    }
    अगर (i < len) *out++ = R2[i / 2];
  }
}

अटल व्योम R3_fromRq(small *out, स्थिर Fq *r) {
  पूर्णांक i;
  क्रम (i = 0; i < p; ++i) out[i] = F3_freeze(r[i]);
}

अटल व्योम R3_mult(small *h, स्थिर small *f, स्थिर small *g) {
  int16_t fg[p + p - 1];
  पूर्णांक i, j;
  क्रम (i = 0; i < p + p - 1; ++i) fg[i] = 0;
  क्रम (i = 0; i < p; ++i)
    क्रम (j = 0; j < p; ++j) fg[i + j] += f[i] * (int16_t)g[j];
  क्रम (i = p; i < p + p - 1; ++i) fg[i - p] += fg[i];
  क्रम (i = p; i < p + p - 1; ++i) fg[i - p + 1] += fg[i];
  क्रम (i = 0; i < p; ++i) h[i] = F3_freeze(fg[i]);
}

अटल पूर्णांक R3_recip(small *out, स्थिर small *in) {
  small f[p + 1], g[p + 1], v[p + 1], r[p + 1];
  पूर्णांक sign, swap, t, i, loop, delta = 1;
  क्रम (i = 0; i < p + 1; ++i) v[i] = 0;
  क्रम (i = 0; i < p + 1; ++i) r[i] = 0;
  r[0] = 1;
  क्रम (i = 0; i < p; ++i) f[i] = 0;
  f[0] = 1;
  f[p - 1] = f[p] = -1;
  क्रम (i = 0; i < p; ++i) g[p - 1 - i] = in[i];
  g[p] = 0;
  क्रम (loop = 0; loop < 2 * p - 1; ++loop) {
    क्रम (i = p; i > 0; --i) v[i] = v[i - 1];
    v[0] = 0;
    sign = -g[0] * f[0];
    swap = crypto_int16_negative_mask(-delta) & crypto_int16_nonzero_mask(g[0]);
    delta ^= swap & (delta ^ -delta);
    delta += 1;
    क्रम (i = 0; i < p + 1; ++i) {
      t = swap & (f[i] ^ g[i]);
      f[i] ^= t;
      g[i] ^= t;
      t = swap & (v[i] ^ r[i]);
      v[i] ^= t;
      r[i] ^= t;
    }
    क्रम (i = 0; i < p + 1; ++i) g[i] = F3_freeze(g[i] + sign * f[i]);
    क्रम (i = 0; i < p + 1; ++i) r[i] = F3_freeze(r[i] + sign * v[i]);
    क्रम (i = 0; i < p; ++i) g[i] = g[i + 1];
    g[p] = 0;
  }
  sign = f[0];
  क्रम (i = 0; i < p; ++i) out[i] = sign * v[p - 1 - i];
  वापस crypto_int16_nonzero_mask(delta);
}

अटल व्योम Rq_mult_small(Fq *h, स्थिर Fq *f, स्थिर small *g) {
  int32_t fg[p + p - 1];
  पूर्णांक i, j;
  क्रम (i = 0; i < p + p - 1; ++i) fg[i] = 0;
  क्रम (i = 0; i < p; ++i)
    क्रम (j = 0; j < p; ++j) fg[i + j] += f[i] * (int32_t)g[j];
  क्रम (i = p; i < p + p - 1; ++i) fg[i - p] += fg[i];
  क्रम (i = p; i < p + p - 1; ++i) fg[i - p + 1] += fg[i];
  क्रम (i = 0; i < p; ++i) h[i] = Fq_freeze(fg[i]);
}

अटल व्योम Rq_mult3(Fq *h, स्थिर Fq *f) {
  पूर्णांक i;
  क्रम (i = 0; i < p; ++i) h[i] = Fq_freeze(3 * f[i]);
}

अटल Fq Fq_recip(Fq a1) {
  पूर्णांक i = 1;
  Fq ai = a1;
  जबतक (i < q - 2) {
    ai = Fq_freeze(a1 * (int32_t)ai);
    i += 1;
  }
  वापस ai;
}

अटल पूर्णांक Rq_recip3(Fq *out, स्थिर small *in) {
  Fq f[p + 1], g[p + 1], v[p + 1], r[p + 1], scale;
  पूर्णांक swap, t, i, loop, delta = 1;
  int32_t f0, g0;
  क्रम (i = 0; i < p + 1; ++i) v[i] = 0;
  क्रम (i = 0; i < p + 1; ++i) r[i] = 0;
  r[0] = Fq_recip(3);
  क्रम (i = 0; i < p; ++i) f[i] = 0;
  f[0] = 1;
  f[p - 1] = f[p] = -1;
  क्रम (i = 0; i < p; ++i) g[p - 1 - i] = in[i];
  g[p] = 0;
  क्रम (loop = 0; loop < 2 * p - 1; ++loop) {
    क्रम (i = p; i > 0; --i) v[i] = v[i - 1];
    v[0] = 0;
    swap = crypto_int16_negative_mask(-delta) & crypto_int16_nonzero_mask(g[0]);
    delta ^= swap & (delta ^ -delta);
    delta += 1;
    क्रम (i = 0; i < p + 1; ++i) {
      t = swap & (f[i] ^ g[i]);
      f[i] ^= t;
      g[i] ^= t;
      t = swap & (v[i] ^ r[i]);
      v[i] ^= t;
      r[i] ^= t;
    }
    f0 = f[0];
    g0 = g[0];
    क्रम (i = 0; i < p + 1; ++i) g[i] = Fq_freeze(f0 * g[i] - g0 * f[i]);
    क्रम (i = 0; i < p + 1; ++i) r[i] = Fq_freeze(f0 * r[i] - g0 * v[i]);
    क्रम (i = 0; i < p; ++i) g[i] = g[i + 1];
    g[p] = 0;
  }
  scale = Fq_recip(f[0]);
  क्रम (i = 0; i < p; ++i) out[i] = Fq_freeze(scale * (int32_t)v[p - 1 - i]);
  वापस crypto_int16_nonzero_mask(delta);
}

अटल व्योम Round(Fq *out, स्थिर Fq *a) {
  पूर्णांक i;
  क्रम (i = 0; i < p; ++i) out[i] = a[i] - F3_freeze(a[i]);
}

अटल व्योम Short_fromlist(small *out, स्थिर uint32_t *in) {
  uint32_t L[p];
  पूर्णांक i;
  क्रम (i = 0; i < w; ++i) L[i] = in[i] & (uint32_t)-2;
  क्रम (i = w; i < p; ++i) L[i] = (in[i] & (uint32_t)-3) | 1;
  crypto_sort_uint32(L, p);
  क्रम (i = 0; i < p; ++i) out[i] = (L[i] & 3) - 1;
}

अटल व्योम Hash_prefix(अचिन्हित अक्षर *out, पूर्णांक b, स्थिर अचिन्हित अक्षर *in, पूर्णांक inlen) {
  अचिन्हित अक्षर x[inlen + 1], h[64];
  पूर्णांक i;
  x[0] = b;
  क्रम (i = 0; i < inlen; ++i) x[i + 1] = in[i];
  crypto_hash_sha512(h, x, inlen + 1);
  क्रम (i = 0; i < 32; ++i) out[i] = h[i];
}


अटल व्योम Short_random(small *out) {
  uint32_t L[p];
  randombytes(L, माप(L));
  Short_fromlist(out, L);
  explicit_bzero(L, माप(L));
}
अटल व्योम Small_random(small *out) {
  पूर्णांक i;
  uint32_t L[p];
  randombytes(L, माप(L));
  क्रम (i = 0; i < p; ++i) out[i] = (((L[i] & 0x3fffffff) * 3) >> 30) - 1;
  explicit_bzero(L, माप(L));
}
अटल व्योम कुंजी_Gen(Fq *h, small *f, small *ginv) {
  small g[p];
  Fq finv[p];
  क्रम (;;) {
    पूर्णांक परिणाम;
    Small_random(g);
    परिणाम = R3_recip(ginv, g);
    crypto_declassify(&परिणाम, माप परिणाम);
    अगर (परिणाम == 0) अवरोध;
  }
  Short_random(f);
  Rq_recip3(finv, f);
  Rq_mult_small(h, finv, g);
}

अटल व्योम Encrypt(Fq *c, स्थिर small *r, स्थिर Fq *h) {
  Fq hr[p];
  Rq_mult_small(hr, h, r);
  Round(c, hr);
}

अटल व्योम Decrypt(small *r, स्थिर Fq *c, स्थिर small *f, स्थिर small *ginv) {
  Fq cf[p], cf3[p];
  small e[p], ev[p];
  पूर्णांक mask, i;
  Rq_mult_small(cf, c, f);
  Rq_mult3(cf3, cf);
  R3_fromRq(e, cf3);
  R3_mult(ev, e, ginv);
  mask = Weightw_mask(ev);
  क्रम (i = 0; i < w; ++i) r[i] = ((ev[i] ^ 1) & ~mask) ^ 1;
  क्रम (i = w; i < p; ++i) r[i] = ev[i] & ~mask;
}

अटल व्योम Small_encode(अचिन्हित अक्षर *s, स्थिर small *f) {
  पूर्णांक i, j;
  क्रम (i = 0; i < p / 4; ++i) {
    small x = 0;
    क्रम (j = 0;j < 4;++j) x += (*f++ + 1) << (2 * j);
    *s++ = x;
  }
  *s = *f++ + 1;
}

अटल व्योम Small_decode(small *f, स्थिर अचिन्हित अक्षर *s) {
  पूर्णांक i, j;
  क्रम (i = 0; i < p / 4; ++i) {
    अचिन्हित अक्षर x = *s++;
    क्रम (j = 0;j < 4;++j) *f++ = ((small)((x >> (2 * j)) & 3)) - 1;
  }
  *f++ = ((small)(*s & 3)) - 1;
}

अटल व्योम Rq_encode(अचिन्हित अक्षर *s, स्थिर Fq *r) {
  uint16_t R[p], M[p];
  पूर्णांक i;
  क्रम (i = 0; i < p; ++i) R[i] = r[i] + q12;
  क्रम (i = 0; i < p; ++i) M[i] = q;
  Encode(s, R, M, p);
}

अटल व्योम Rq_decode(Fq *r, स्थिर अचिन्हित अक्षर *s) {
  uint16_t R[p], M[p];
  पूर्णांक i;
  क्रम (i = 0; i < p; ++i) M[i] = q;
  Decode(R, s, M, p);
  क्रम (i = 0; i < p; ++i) r[i] = ((Fq)R[i]) - q12;
}

अटल व्योम Rounded_encode(अचिन्हित अक्षर *s, स्थिर Fq *r) {
  uint16_t R[p], M[p];
  पूर्णांक i;
  क्रम (i = 0; i < p; ++i) R[i] = ((r[i] + q12) * 10923) >> 15;
  क्रम (i = 0; i < p; ++i) M[i] = (q + 2) / 3;
  Encode(s, R, M, p);
}

अटल व्योम Rounded_decode(Fq *r, स्थिर अचिन्हित अक्षर *s) {
  uint16_t R[p], M[p];
  पूर्णांक i;
  क्रम (i = 0; i < p; ++i) M[i] = (q + 2) / 3;
  Decode(R, s, M, p);
  क्रम (i = 0; i < p; ++i) r[i] = R[i] * 3 - q12;
}

अटल व्योम ZKeyGen(अचिन्हित अक्षर *pk, अचिन्हित अक्षर *sk) {
  Fq h[p];
  small f[p], v[p];
  कुंजी_Gen(h, f, v);
  Rq_encode(pk, h);
  Small_encode(sk, f);
  Small_encode(sk + Small_bytes, v);
}

अटल व्योम ZEncrypt(अचिन्हित अक्षर *C, स्थिर Inputs r, स्थिर अचिन्हित अक्षर *pk) {
  Fq h[p], c[p];
  Rq_decode(h, pk);
  Encrypt(c, r, h);
  Rounded_encode(C, c);
}

अटल व्योम ZDecrypt(Inputs r, स्थिर अचिन्हित अक्षर *C, स्थिर अचिन्हित अक्षर *sk) {
  small f[p], v[p];
  Fq c[p];
  Small_decode(f, sk);
  Small_decode(v, sk + Small_bytes);
  Rounded_decode(c, C);
  Decrypt(r, c, f, v);
}

अटल व्योम HashConfirm(अचिन्हित अक्षर *h, स्थिर अचिन्हित अक्षर *r, स्थिर अचिन्हित अक्षर *cache) {
  अचिन्हित अक्षर x[Hash_bytes * 2];
  पूर्णांक i;
  Hash_prefix(x, 3, r, Small_bytes);
  क्रम (i = 0; i < Hash_bytes; ++i) x[Hash_bytes + i] = cache[i];
  Hash_prefix(h, 2, x, माप x);
}

अटल व्योम HashSession(अचिन्हित अक्षर *k, पूर्णांक b, स्थिर अचिन्हित अक्षर *y, स्थिर अचिन्हित अक्षर *z) {
  अचिन्हित अक्षर x[Hash_bytes + crypto_kem_sntrup761_CIPHERTEXTBYTES];
  पूर्णांक i;
  Hash_prefix(x, 3, y, Small_bytes);
  क्रम (i = 0; i < crypto_kem_sntrup761_CIPHERTEXTBYTES; ++i) x[Hash_bytes + i] = z[i];
  Hash_prefix(k, b, x, माप x);
}

पूर्णांक crypto_kem_sntrup761_keypair(अचिन्हित अक्षर *pk, अचिन्हित अक्षर *sk) {
  पूर्णांक i;
  ZKeyGen(pk, sk);
  sk += Secret_कुंजियाँ_bytes;
  क्रम (i = 0; i < crypto_kem_sntrup761_PUBLICKEYBYTES; ++i) *sk++ = pk[i];
  randombytes(sk, Small_bytes);
  Hash_prefix(sk + Small_bytes, 4, pk, crypto_kem_sntrup761_PUBLICKEYBYTES);
  वापस 0;
}

अटल व्योम Hide(अचिन्हित अक्षर *c, अचिन्हित अक्षर *r_enc, स्थिर Inputs r, स्थिर अचिन्हित अक्षर *pk, स्थिर अचिन्हित अक्षर *cache) {
  Small_encode(r_enc, r);
  ZEncrypt(c, r, pk);
  HashConfirm(c + crypto_kem_sntrup761_CIPHERTEXTBYTES - Confirm_bytes, r_enc, cache);
}

पूर्णांक crypto_kem_sntrup761_enc(अचिन्हित अक्षर *c, अचिन्हित अक्षर *k, स्थिर अचिन्हित अक्षर *pk) {
  Inputs r;
  अचिन्हित अक्षर r_enc[Small_bytes], cache[Hash_bytes];
  Hash_prefix(cache, 4, pk, crypto_kem_sntrup761_PUBLICKEYBYTES);
  Short_random(r);
  Hide(c, r_enc, r, pk, cache);
  HashSession(k, 1, r_enc, c);
  वापस 0;
}

अटल पूर्णांक Ciphertexts_diff_mask(स्थिर अचिन्हित अक्षर *c, स्थिर अचिन्हित अक्षर *c2) {
  uint16_t differentbits = 0;
  पूर्णांक len = crypto_kem_sntrup761_CIPHERTEXTBYTES;
  जबतक (len-- > 0) differentbits |= (*c++) ^ (*c2++);
  वापस (crypto_int64_bitmod_01((differentbits - 1),8)) - 1;
}

पूर्णांक crypto_kem_sntrup761_dec(अचिन्हित अक्षर *k, स्थिर अचिन्हित अक्षर *c, स्थिर अचिन्हित अक्षर *sk) {
  स्थिर अचिन्हित अक्षर *pk = sk + Secret_कुंजियाँ_bytes;
  स्थिर अचिन्हित अक्षर *rho = pk + crypto_kem_sntrup761_PUBLICKEYBYTES;
  स्थिर अचिन्हित अक्षर *cache = rho + Small_bytes;
  Inputs r;
  अचिन्हित अक्षर r_enc[Small_bytes], cnew[crypto_kem_sntrup761_CIPHERTEXTBYTES];
  पूर्णांक mask, i;
  ZDecrypt(r, c, sk);
  Hide(cnew, r_enc, r, pk, cache);
  mask = Ciphertexts_diff_mask(c, cnew);
  क्रम (i = 0; i < Small_bytes; ++i) r_enc[i] ^= mask & (r_enc[i] ^ rho[i]);
  HashSession(k, 1 + mask, r_enc, c);
  वापस 0;
}

#पूर्ण_अगर /* USE_SNTRUP761X25519 */
