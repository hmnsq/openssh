/* OPENBSD ORIGINAL: lib/libc/crypt/chacha_private.h */

/*
chacha-merged.c version 20080118
D. J. Bernstein
Public domain.
*/

/* $OpenBSD: chacha_private.h,v 1.3 2022/02/28 21:56:29 dtucker Exp $ */

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ u8;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ u32;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ
{
  u32 ಒಳಹರಿವು[16]; /* could be compressed */
} chacha_ctx;

#ವ್ಯಾಖ್ಯಾನಿಸು U8C(v) (v##U)
#ವ್ಯಾಖ್ಯಾನಿಸು U32C(v) (v##U)

#ವ್ಯಾಖ್ಯಾನಿಸು U8V(v) ((u8)(v) & U8C(0xFF))
#ವ್ಯಾಖ್ಯಾನಿಸು U32V(v) ((u32)(v) & U32C(0xFFFFFFFF))

#ವ್ಯಾಖ್ಯಾನಿಸು ROTL32(v, n) \
  (U32V((v) << (n)) | ((v) >> (32 - (n))))

#ವ್ಯಾಖ್ಯಾನಿಸು U8TO32_LITTLE(p) \
  (((u32)((p)[0])      ) | \
   ((u32)((p)[1]) <<  8) | \
   ((u32)((p)[2]) << 16) | \
   ((u32)((p)[3]) << 24))

#ವ್ಯಾಖ್ಯಾನಿಸು U32TO8_LITTLE(p, v) \
  ಮಾಡು { \
    (p)[0] = U8V((v)      ); \
    (p)[1] = U8V((v) >>  8); \
    (p)[2] = U8V((v) >> 16); \
    (p)[3] = U8V((v) >> 24); \
  } ಆಗ (0)

#ವ್ಯಾಖ್ಯಾನಿಸು ROTATE(v,c) (ROTL32(v,c))
#ವ್ಯಾಖ್ಯಾನಿಸು XOR(v,w) ((v) ^ (w))
#ವ್ಯಾಖ್ಯಾನಿಸು PLUS(v,w) (U32V((v) + (w)))
#ವ್ಯಾಖ್ಯಾನಿಸು PLUSONE(v) (PLUS((v),1))

#ವ್ಯಾಖ್ಯಾನಿಸು QUARTERROUND(a,b,c,d) \
  a = PLUS(a,b); d = ROTATE(XOR(d,a),16); \
  c = PLUS(c,d); b = ROTATE(XOR(b,c),12); \
  a = PLUS(a,b); d = ROTATE(XOR(d,a), 8); \
  c = PLUS(c,d); b = ROTATE(XOR(b,c), 7);

ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ sigma[16] = "expand 32-byte k";
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ tau[16] = "expand 16-byte k";

ಸ್ಥಿರ ಶೂನ್ಯ
chacha_keysetup(chacha_ctx *x,ಸ್ಥಿರಾಂಕ u8 *k,u32 kbits)
{
  ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *constants;

  x->ಒಳಹರಿವು[4] = U8TO32_LITTLE(k + 0);
  x->ಒಳಹರಿವು[5] = U8TO32_LITTLE(k + 4);
  x->ಒಳಹರಿವು[6] = U8TO32_LITTLE(k + 8);
  x->ಒಳಹರಿವು[7] = U8TO32_LITTLE(k + 12);
  ಆದರೆ (kbits == 256) { /* recommended */
    k += 16;
    constants = sigma;
  } ಇಲ್ಲದಿದ್ದರೆ { /* kbits == 128 */
    constants = tau;
  }
  x->ಒಳಹರಿವು[8] = U8TO32_LITTLE(k + 0);
  x->ಒಳಹರಿವು[9] = U8TO32_LITTLE(k + 4);
  x->ಒಳಹರಿವು[10] = U8TO32_LITTLE(k + 8);
  x->ಒಳಹರಿವು[11] = U8TO32_LITTLE(k + 12);
  x->ಒಳಹರಿವು[0] = U8TO32_LITTLE(constants + 0);
  x->ಒಳಹರಿವು[1] = U8TO32_LITTLE(constants + 4);
  x->ಒಳಹರಿವು[2] = U8TO32_LITTLE(constants + 8);
  x->ಒಳಹರಿವು[3] = U8TO32_LITTLE(constants + 12);
}

ಸ್ಥಿರ ಶೂನ್ಯ
chacha_ivsetup(chacha_ctx *x,ಸ್ಥಿರಾಂಕ u8 *iv)
{
  x->ಒಳಹರಿವು[12] = 0;
  x->ಒಳಹರಿವು[13] = 0;
  x->ಒಳಹರಿವು[14] = U8TO32_LITTLE(iv + 0);
  x->ಒಳಹರಿವು[15] = U8TO32_LITTLE(iv + 4);
}

ಸ್ಥಿರ ಶೂನ್ಯ
chacha_encrypt_ಬೈಟುಗಳು(chacha_ctx *x,ಸ್ಥಿರಾಂಕ u8 *m,u8 *c,u32 ಬೈಟುಗಳು)
{
  u32 x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;
  u32 j0, j1, j2, j3, j4, j5, j6, j7, j8, j9, j10, j11, j12, j13, j14, j15;
  u8 *ctarget = ಖಾಲಿ;
  u8 tmp[64];
  u_int i;

  ಆದರೆ (!ಬೈಟುಗಳು) ಹಿಂತಿರುಗಿ;

  j0 = x->ಒಳಹರಿವು[0];
  j1 = x->ಒಳಹರಿವು[1];
  j2 = x->ಒಳಹರಿವು[2];
  j3 = x->ಒಳಹರಿವು[3];
  j4 = x->ಒಳಹರಿವು[4];
  j5 = x->ಒಳಹರಿವು[5];
  j6 = x->ಒಳಹರಿವು[6];
  j7 = x->ಒಳಹರಿವು[7];
  j8 = x->ಒಳಹರಿವು[8];
  j9 = x->ಒಳಹರಿವು[9];
  j10 = x->ಒಳಹರಿವು[10];
  j11 = x->ಒಳಹರಿವು[11];
  j12 = x->ಒಳಹರಿವು[12];
  j13 = x->ಒಳಹರಿವು[13];
  j14 = x->ಒಳಹರಿವು[14];
  j15 = x->ಒಳಹರಿವು[15];

  ಗಾಗಿ (;;) {
    ಆದರೆ (ಬೈಟುಗಳು < 64) {
      ಗಾಗಿ (i = 0;i < ಬೈಟುಗಳು;++i) tmp[i] = m[i];
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
    ಗಾಗಿ (i = 20;i > 0;i -= 2) {
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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ KEYSTREAM_ONLY
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
#ಆದರೆ_ಅಂತ್ಯ

    j12 = PLUSONE(j12);
    ಆದರೆ (!j12) {
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

    ಆದರೆ (ಬೈಟುಗಳು <= 64) {
      ಆದರೆ (ಬೈಟುಗಳು < 64) {
        ಗಾಗಿ (i = 0;i < ಬೈಟುಗಳು;++i) ctarget[i] = c[i];
      }
      x->ಒಳಹರಿವು[12] = j12;
      x->ಒಳಹರಿವು[13] = j13;
      ಹಿಂತಿರುಗಿ;
    }
    ಬೈಟುಗಳು -= 64;
    c += 64;
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ KEYSTREAM_ONLY
    m += 64;
#ಆದರೆ_ಅಂತ್ಯ
  }
}
