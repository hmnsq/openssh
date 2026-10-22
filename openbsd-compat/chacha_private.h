/* OPENBSD ORIGINAL: lib/libc/crypt/chacha_private.h */

/*
chacha-merged.c version 20080118
D. J. Bernstein
Public domain.
*/

/* $OpenBSD: chacha_private.h,v 1.3 2022/02/28 21:56:29 dtucker Exp $ */

تعريفنوع بنانشان حرف u8;
تعريفنوع بنانشان صحيح u32;

تعريفنوع بنية
{
  u32 داخلا_2[16]; /* could be compressed */
} chacha_ctx;

#وصف_ڪريو U8C(v) (v##U)
#وصف_ڪريو U32C(v) (v##U)

#وصف_ڪريو U8V(v) ((u8)(v) & U8C(0xFF))
#وصف_ڪريو U32V(v) ((u32)(v) & U32C(0xFFFFFFFF))

#وصف_ڪريو ROTL32(v, n) \
  (U32V((v) << (n)) | ((v) >> (32 - (n))))

#وصف_ڪريو U8TO32_LITTLE(p) \
  (((u32)((p)[0])      ) | \
   ((u32)((p)[1]) <<  8) | \
   ((u32)((p)[2]) << 16) | \
   ((u32)((p)[3]) << 24))

#وصف_ڪريو U32TO8_LITTLE(p, v) \
  افعل { \
    (p)[0] = U8V((v)      ); \
    (p)[1] = U8V((v) >>  8); \
    (p)[2] = U8V((v) >> 16); \
    (p)[3] = U8V((v) >> 24); \
  } طالما (0)

#وصف_ڪريو ROTATE(v,c) (ROTL32(v,c))
#وصف_ڪريو XOR(v,w) ((v) ^ (w))
#وصف_ڪريو PLUS(v,w) (U32V((v) + (w)))
#وصف_ڪريو PLUSONE(v) (PLUS((v),1))

#وصف_ڪريو QUARTERROUND(a,b,c,d) \
  a = PLUS(a,b); d = ROTATE(XOR(d,a),16); \
  c = PLUS(c,d); b = ROTATE(XOR(b,c),12); \
  a = PLUS(a,b); d = ROTATE(XOR(d,a), 8); \
  c = PLUS(c,d); b = ROTATE(XOR(b,c), 7);

ساكن ثابت حرف sigma[16] = "expand 32-byte k";
ساكن ثابت حرف tau[16] = "expand 16-byte k";

ساكن فراغ
chacha_keysetup(chacha_ctx *x,ثابت u8 *k,u32 kbits)
{
  ثابت حرف *constants;

  x->داخلا_2[4] = U8TO32_LITTLE(k + 0);
  x->داخلا_2[5] = U8TO32_LITTLE(k + 4);
  x->داخلا_2[6] = U8TO32_LITTLE(k + 8);
  x->داخلا_2[7] = U8TO32_LITTLE(k + 12);
  إذا (kbits == 256) { /* recommended */
    k += 16;
    constants = sigma;
  } وإلا { /* kbits == 128 */
    constants = tau;
  }
  x->داخلا_2[8] = U8TO32_LITTLE(k + 0);
  x->داخلا_2[9] = U8TO32_LITTLE(k + 4);
  x->داخلا_2[10] = U8TO32_LITTLE(k + 8);
  x->داخلا_2[11] = U8TO32_LITTLE(k + 12);
  x->داخلا_2[0] = U8TO32_LITTLE(constants + 0);
  x->داخلا_2[1] = U8TO32_LITTLE(constants + 4);
  x->داخلا_2[2] = U8TO32_LITTLE(constants + 8);
  x->داخلا_2[3] = U8TO32_LITTLE(constants + 12);
}

ساكن فراغ
chacha_ivsetup(chacha_ctx *x,ثابت u8 *iv)
{
  x->داخلا_2[12] = 0;
  x->داخلا_2[13] = 0;
  x->داخلا_2[14] = U8TO32_LITTLE(iv + 0);
  x->داخلا_2[15] = U8TO32_LITTLE(iv + 4);
}

ساكن فراغ
chacha_encrypt_بائيٽون(chacha_ctx *x,ثابت u8 *m,u8 *c,u32 بائيٽون)
{
  u32 x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;
  u32 j0, j1, j2, j3, j4, j5, j6, j7, j8, j9, j10, j11, j12, j13, j14, j15;
  u8 *ctarget = عدم;
  u8 tmp[64];
  u_int i;

  إذا (!بائيٽون) أرجع;

  j0 = x->داخلا_2[0];
  j1 = x->داخلا_2[1];
  j2 = x->داخلا_2[2];
  j3 = x->داخلا_2[3];
  j4 = x->داخلا_2[4];
  j5 = x->داخلا_2[5];
  j6 = x->داخلا_2[6];
  j7 = x->داخلا_2[7];
  j8 = x->داخلا_2[8];
  j9 = x->داخلا_2[9];
  j10 = x->داخلا_2[10];
  j11 = x->داخلا_2[11];
  j12 = x->داخلا_2[12];
  j13 = x->داخلا_2[13];
  j14 = x->داخلا_2[14];
  j15 = x->داخلا_2[15];

  لكل (;;) {
    إذا (بائيٽون < 64) {
      لكل (i = 0;i < بائيٽون;++i) tmp[i] = m[i];
      m = tmp;
      ctarget = c;
      c = tmp;
    }
    x0 = j0;
    x1 = j1;
    x2 = j2;
    x3 = j3;
    x4 = j4;
    x5 = j5;
    x6 = j6;
    x7 = j7;
    x8 = j8;
    x9 = j9;
    x10 = j10;
    x11 = j11;
    x12 = j12;
    x13 = j13;
    x14 = j14;
    x15 = j15;
    لكل (i = 20;i > 0;i -= 2) {
      QUARTERROUND( x0, x4, x8,x12)
      QUARTERROUND( x1, x5, x9,x13)
      QUARTERROUND( x2, x6,x10,x14)
      QUARTERROUND( x3, x7,x11,x15)
      QUARTERROUND( x0, x5,x10,x15)
      QUARTERROUND( x1, x6,x11,x12)
      QUARTERROUND( x2, x7, x8,x13)
      QUARTERROUND( x3, x4, x9,x14)
    }
    x0 = PLUS(x0,j0);
    x1 = PLUS(x1,j1);
    x2 = PLUS(x2,j2);
    x3 = PLUS(x3,j3);
    x4 = PLUS(x4,j4);
    x5 = PLUS(x5,j5);
    x6 = PLUS(x6,j6);
    x7 = PLUS(x7,j7);
    x8 = PLUS(x8,j8);
    x9 = PLUS(x9,j9);
    x10 = PLUS(x10,j10);
    x11 = PLUS(x11,j11);
    x12 = PLUS(x12,j12);
    x13 = PLUS(x13,j13);
    x14 = PLUS(x14,j14);
    x15 = PLUS(x15,j15);

#جيڪڏهن_وصف_نه_ٿيل KEYSTREAM_ONLY
    x0 = XOR(x0,U8TO32_LITTLE(m + 0));
    x1 = XOR(x1,U8TO32_LITTLE(m + 4));
    x2 = XOR(x2,U8TO32_LITTLE(m + 8));
    x3 = XOR(x3,U8TO32_LITTLE(m + 12));
    x4 = XOR(x4,U8TO32_LITTLE(m + 16));
    x5 = XOR(x5,U8TO32_LITTLE(m + 20));
    x6 = XOR(x6,U8TO32_LITTLE(m + 24));
    x7 = XOR(x7,U8TO32_LITTLE(m + 28));
    x8 = XOR(x8,U8TO32_LITTLE(m + 32));
    x9 = XOR(x9,U8TO32_LITTLE(m + 36));
    x10 = XOR(x10,U8TO32_LITTLE(m + 40));
    x11 = XOR(x11,U8TO32_LITTLE(m + 44));
    x12 = XOR(x12,U8TO32_LITTLE(m + 48));
    x13 = XOR(x13,U8TO32_LITTLE(m + 52));
    x14 = XOR(x14,U8TO32_LITTLE(m + 56));
    x15 = XOR(x15,U8TO32_LITTLE(m + 60));
#جيڪڏهن_پورو

    j12 = PLUSONE(j12);
    إذا (!j12) {
      j13 = PLUSONE(j13);
      /* stopping at 2^70 bytes per nonce is user's responsibility */
    }

    U32TO8_LITTLE(c + 0,x0);
    U32TO8_LITTLE(c + 4,x1);
    U32TO8_LITTLE(c + 8,x2);
    U32TO8_LITTLE(c + 12,x3);
    U32TO8_LITTLE(c + 16,x4);
    U32TO8_LITTLE(c + 20,x5);
    U32TO8_LITTLE(c + 24,x6);
    U32TO8_LITTLE(c + 28,x7);
    U32TO8_LITTLE(c + 32,x8);
    U32TO8_LITTLE(c + 36,x9);
    U32TO8_LITTLE(c + 40,x10);
    U32TO8_LITTLE(c + 44,x11);
    U32TO8_LITTLE(c + 48,x12);
    U32TO8_LITTLE(c + 52,x13);
    U32TO8_LITTLE(c + 56,x14);
    U32TO8_LITTLE(c + 60,x15);

    إذا (بائيٽون <= 64) {
      إذا (بائيٽون < 64) {
        لكل (i = 0;i < بائيٽون;++i) ctarget[i] = c[i];
      }
      x->داخلا_2[12] = j12;
      x->داخلا_2[13] = j13;
      أرجع;
    }
    بائيٽون -= 64;
    c += 64;
#جيڪڏهن_وصف_نه_ٿيل KEYSTREAM_ONLY
    m += 64;
#جيڪڏهن_پورو
  }
}
