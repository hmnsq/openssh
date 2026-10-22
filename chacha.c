/* $OpenBSD: chacha.c,v 1.3 2026/05/18 04:14:57 tb Exp $ */
/*
chacha-merged.c version 20080118
D. J. Bernstein
Public domain.
*/

#అన్తర్భావ "includes.h"

#అన్తర్భావ "chacha.h"

రకనిర్వచనం గుర్తులేని అక్షరం u8;
రకనిర్వచనం గుర్తులేని పూర్ణాంకం u32;

రకనిర్వచనం నిర్మాణం chacha_ctx chacha_ctx;

#నిర్వచించు U8C(v) (v##U)
#నిర్వచించు U32C(v) (v##U)

#నిర్వచించు U8V(v) ((u8)(v) & U8C(0xFF))
#నిర్వచించు U32V(v) ((u32)(v) & U32C(0xFFFFFFFF))

#నిర్వచించు ROTL32(v, n) \
  (U32V((v) << (n)) | ((v) >> (32 - (n))))

#నిర్వచించు U8TO32_LITTLE(p) \
  (((u32)((p)[0])      ) | \
   ((u32)((p)[1]) <<  8) | \
   ((u32)((p)[2]) << 16) | \
   ((u32)((p)[3]) << 24))

#నిర్వచించు U32TO8_LITTLE(p, v) \
  చేయి { \
    (p)[0] = U8V((v)      ); \
    (p)[1] = U8V((v) >>  8); \
    (p)[2] = U8V((v) >> 16); \
    (p)[3] = U8V((v) >> 24); \
  } అయితే (0)

#నిర్వచించు ROTATE(v,c) (ROTL32(v,c))
#నిర్వచించు XOR(v,w) ((v) ^ (w))
#నిర్వచించు PLUS(v,w) (U32V((v) + (w)))
#నిర్వచించు PLUSONE(v) (PLUS((v),1))

#నిర్వచించు QUARTERROUND(a,b,c,d) \
  a = PLUS(a,b); d = ROTATE(XOR(d,a),16); \
  c = PLUS(c,d); b = ROTATE(XOR(b,c),12); \
  a = PLUS(a,b); d = ROTATE(XOR(d,a), 8); \
  c = PLUS(c,d); b = ROTATE(XOR(b,c), 7);

స్థిర స్థిరరాశి అక్షరం sigma[] = "expand 32-byte k";
స్థిర స్థిరరాశి అక్షరం tau[] = "expand 16-byte k";

శూన్య
chacha_keysetup(chacha_ctx *x,స్థిరరాశి u8 *k,u32 kbits)
{
  స్థిరరాశి అక్షరం *constants;

  x->ఆదానం[4] = U8TO32_LITTLE(k + 0);
  x->ఆదానం[5] = U8TO32_LITTLE(k + 4);
  x->ఆదానం[6] = U8TO32_LITTLE(k + 8);
  x->ఆదానం[7] = U8TO32_LITTLE(k + 12);
  ఒకవేళ (kbits == 256) { /* recommended */
    k += 16;
    constants = sigma;
  } లేకపోతే { /* kbits == 128 */
    constants = tau;
  }
  x->ఆదానం[8] = U8TO32_LITTLE(k + 0);
  x->ఆదానం[9] = U8TO32_LITTLE(k + 4);
  x->ఆదానం[10] = U8TO32_LITTLE(k + 8);
  x->ఆదానం[11] = U8TO32_LITTLE(k + 12);
  x->ఆదానం[0] = U8TO32_LITTLE(constants + 0);
  x->ఆదానం[1] = U8TO32_LITTLE(constants + 4);
  x->ఆదానం[2] = U8TO32_LITTLE(constants + 8);
  x->ఆదానం[3] = U8TO32_LITTLE(constants + 12);
}

శూన్య
chacha_ivsetup(chacha_ctx *x, స్థిరరాశి u8 *iv, స్థిరరాశి u8 *counter)
{
  x->ఆదానం[12] = counter == ఖాళీ ? 0 : U8TO32_LITTLE(counter + 0);
  x->ఆదానం[13] = counter == ఖాళీ ? 0 : U8TO32_LITTLE(counter + 4);
  x->ఆదానం[14] = U8TO32_LITTLE(iv + 0);
  x->ఆదానం[15] = U8TO32_LITTLE(iv + 4);
}

శూన్య
chacha_encrypt_బైట్లు(chacha_ctx *x,స్థిరరాశి u8 *m,u8 *c,u32 బైట్లు)
{
  u32 x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;
  u32 j0, j1, j2, j3, j4, j5, j6, j7, j8, j9, j10, j11, j12, j13, j14, j15;
  u8 *ctarget = ఖాళీ;
  u8 tmp[64];
  u_int i;

  ఒకవేళ (!బైట్లు) తిరిగి;

  j0 = x->ఆదానం[0];
  j1 = x->ఆదానం[1];
  j2 = x->ఆదానం[2];
  j3 = x->ఆదానం[3];
  j4 = x->ఆదానం[4];
  j5 = x->ఆదానం[5];
  j6 = x->ఆదానం[6];
  j7 = x->ఆదానం[7];
  j8 = x->ఆదానం[8];
  j9 = x->ఆదానం[9];
  j10 = x->ఆదానం[10];
  j11 = x->ఆదానం[11];
  j12 = x->ఆదానం[12];
  j13 = x->ఆదానం[13];
  j14 = x->ఆదానం[14];
  j15 = x->ఆదానం[15];

  కొరకు (;;) {
    ఒకవేళ (బైట్లు < 64) {
      కొరకు (i = 0;i < బైట్లు;++i) tmp[i] = m[i];
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
    కొరకు (i = 20;i > 0;i -= 2) {
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
    ఒకవేళ (!j12) {
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

    ఒకవేళ (బైట్లు <= 64) {
      ఒకవేళ (బైట్లు < 64) {
        కొరకు (i = 0;i < బైట్లు;++i) ctarget[i] = c[i];
      }
      x->ఆదానం[12] = j12;
      x->ఆదానం[13] = j13;
      తిరిగి;
    }
    బైట్లు -= 64;
    c += 64;
    m += 64;
  }
}
