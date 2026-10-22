/* $OpenBSD: chacha.c,v 1.3 2026/05/18 04:14:57 tb Exp $ */
/*
chacha-merged.c version 20080118
D. J. Bernstein
Public domain.
*/

#شامل "includes.h"

#شامل "chacha.h"

قسمتعریف غیرعلامتی حرف u8;
قسمتعریف غیرعلامتی صحیح u32;

قسمتعریف ساخت chacha_ctx chacha_ctx;

#تعریف_کرو U8C(v) (v##U)
#تعریف_کرو U32C(v) (v##U)

#تعریف_کرو U8V(v) ((u8)(v) & U8C(0xFF))
#تعریف_کرو U32V(v) ((u32)(v) & U32C(0xFFFFFFFF))

#تعریف_کرو ROTL32(v, n) \
  (U32V((v) << (n)) | ((v) >> (32 - (n))))

#تعریف_کرو U8TO32_LITTLE(p) \
  (((u32)((p)[0])      ) | \
   ((u32)((p)[1]) <<  8) | \
   ((u32)((p)[2]) << 16) | \
   ((u32)((p)[3]) << 24))

#تعریف_کرو U32TO8_LITTLE(p, v) \
  کرو { \
    (p)[0] = U8V((v)      ); \
    (p)[1] = U8V((v) >>  8); \
    (p)[2] = U8V((v) >> 16); \
    (p)[3] = U8V((v) >> 24); \
  } جب (0)

#تعریف_کرو ROTATE(v,c) (ROTL32(v,c))
#تعریف_کرو XOR(v,w) ((v) ^ (w))
#تعریف_کرو PLUS(v,w) (U32V((v) + (w)))
#تعریف_کرو PLUSONE(v) (PLUS((v),1))

#تعریف_کرو QUARTERROUND(a,b,c,d) \
  a = PLUS(a,b); d = ROTATE(XOR(d,a),16); \
  c = PLUS(c,d); b = ROTATE(XOR(b,c),12); \
  a = PLUS(a,b); d = ROTATE(XOR(d,a), 8); \
  c = PLUS(c,d); b = ROTATE(XOR(b,c), 7);

ساکن ثابت حرف sigma[] = "expand 32-byte k";
ساکن ثابت حرف tau[] = "expand 16-byte k";

خالی
chacha_keysetup(chacha_ctx *x,ثابت u8 *k,u32 kbits)
{
  ثابت حرف *constants;

  x->داخلہ[4] = U8TO32_LITTLE(k + 0);
  x->داخلہ[5] = U8TO32_LITTLE(k + 4);
  x->داخلہ[6] = U8TO32_LITTLE(k + 8);
  x->داخلہ[7] = U8TO32_LITTLE(k + 12);
  اگر (kbits == 256) { /* recommended */
    k += 16;
    constants = sigma;
  } ورنہ { /* kbits == 128 */
    constants = tau;
  }
  x->داخلہ[8] = U8TO32_LITTLE(k + 0);
  x->داخلہ[9] = U8TO32_LITTLE(k + 4);
  x->داخلہ[10] = U8TO32_LITTLE(k + 8);
  x->داخلہ[11] = U8TO32_LITTLE(k + 12);
  x->داخلہ[0] = U8TO32_LITTLE(constants + 0);
  x->داخلہ[1] = U8TO32_LITTLE(constants + 4);
  x->داخلہ[2] = U8TO32_LITTLE(constants + 8);
  x->داخلہ[3] = U8TO32_LITTLE(constants + 12);
}

خالی
chacha_ivsetup(chacha_ctx *x, ثابت u8 *iv, ثابت u8 *شمار_2)
{
  x->داخلہ[12] = شمار_2 == تہی ? 0 : U8TO32_LITTLE(شمار_2 + 0);
  x->داخلہ[13] = شمار_2 == تہی ? 0 : U8TO32_LITTLE(شمار_2 + 4);
  x->داخلہ[14] = U8TO32_LITTLE(iv + 0);
  x->داخلہ[15] = U8TO32_LITTLE(iv + 4);
}

خالی
chacha_encrypt_بائٹیں(chacha_ctx *x,ثابت u8 *m,u8 *c,u32 بائٹیں)
{
  u32 x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;
  u32 j0, j1, j2, j3, j4, j5, j6, j7, j8, j9, j10, j11, j12, j13, j14, j15;
  u8 *ctarget = تہی;
  u8 tmp[64];
  u_int i;

  اگر (!بائٹیں) واپس;

  j0 = x->داخلہ[0];
  j1 = x->داخلہ[1];
  j2 = x->داخلہ[2];
  j3 = x->داخلہ[3];
  j4 = x->داخلہ[4];
  j5 = x->داخلہ[5];
  j6 = x->داخلہ[6];
  j7 = x->داخلہ[7];
  j8 = x->داخلہ[8];
  j9 = x->داخلہ[9];
  j10 = x->داخلہ[10];
  j11 = x->داخلہ[11];
  j12 = x->داخلہ[12];
  j13 = x->داخلہ[13];
  j14 = x->داخلہ[14];
  j15 = x->داخلہ[15];

  برائے (;;) {
    اگر (بائٹیں < 64) {
      برائے (i = 0;i < بائٹیں;++i) tmp[i] = m[i];
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
    برائے (i = 20;i > 0;i -= 2) {
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

    j12 = PLUSONE(j12);
    اگر (!j12) {
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

    اگر (بائٹیں <= 64) {
      اگر (بائٹیں < 64) {
        برائے (i = 0;i < بائٹیں;++i) ctarget[i] = c[i];
      }
      x->داخلہ[12] = j12;
      x->داخلہ[13] = j13;
      واپس;
    }
    بائٹیں -= 64;
    c += 64;
    m += 64;
  }
}
