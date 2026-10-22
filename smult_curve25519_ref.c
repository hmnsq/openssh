/* $OpenBSD: smult_curve25519_ref.c,v 1.2 2013/11/02 22:02:14 markus Exp $ */
/*
version 20081011
Matthew Dempsky
Public domain.
Derived from public domain code by D. J. Bernstein.
*/

ಪೂರ್ಣಾಙ್ಕ crypto_scalarmult_curve25519(unsigned ವರ್ಣ *, ಧ್ರುವ unsigned ವರ್ಣ *, ಧ್ರುವ unsigned ವರ್ಣ *);

ಸ್ಥಿರ ಶೂನ್ಯ add(unsigned ಪೂರ್ಣಾಙ್ಕ out[32],ಧ್ರುವ unsigned ಪೂರ್ಣಾಙ್ಕ a[32],ಧ್ರುವ unsigned ಪೂರ್ಣಾಙ್ಕ b[32])
{
  unsigned ಪೂರ್ಣಾಙ್ಕ j;
  unsigned ಪೂರ್ಣಾಙ್ಕ u;
  u = 0;
  ಪ್ರತಿ (j = 0;j < 31;++j) { u += a[j] + b[j]; out[j] = u & 255; u >>= 8; }
  u += a[31] + b[31]; out[31] = u;
}

ಸ್ಥಿರ ಶೂನ್ಯ sub(unsigned ಪೂರ್ಣಾಙ್ಕ out[32],ಧ್ರುವ unsigned ಪೂರ್ಣಾಙ್ಕ a[32],ಧ್ರುವ unsigned ಪೂರ್ಣಾಙ್ಕ b[32])
{
  unsigned ಪೂರ್ಣಾಙ್ಕ j;
  unsigned ಪೂರ್ಣಾಙ್ಕ u;
  u = 218;
  ಪ್ರತಿ (j = 0;j < 31;++j) {
    u += a[j] + 65280 - b[j];
    out[j] = u & 255;
    u >>= 8;
  }
  u += a[31] - b[31];
  out[31] = u;
}

ಸ್ಥಿರ ಶೂನ್ಯ squeeze(unsigned ಪೂರ್ಣಾಙ್ಕ a[32])
{
  unsigned ಪೂರ್ಣಾಙ್ಕ j;
  unsigned ಪೂರ್ಣಾಙ್ಕ u;
  u = 0;
  ಪ್ರತಿ (j = 0;j < 31;++j) { u += a[j]; a[j] = u & 255; u >>= 8; }
  u += a[31]; a[31] = u & 127;
  u = 19 * (u >> 7);
  ಪ್ರತಿ (j = 0;j < 31;++j) { u += a[j]; a[j] = u & 255; u >>= 8; }
  u += a[31]; a[31] = u;
}

ಸ್ಥಿರ ಧ್ರುವ unsigned ಪೂರ್ಣಾಙ್ಕ minusp[32] = {
 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128
} ;

ಸ್ಥಿರ ಶೂನ್ಯ freeze(unsigned ಪೂರ್ಣಾಙ್ಕ a[32])
{
  unsigned ಪೂರ್ಣಾಙ್ಕ aorig[32];
  unsigned ಪೂರ್ಣಾಙ್ಕ j;
  unsigned ಪೂರ್ಣಾಙ್ಕ negative;

  ಪ್ರತಿ (j = 0;j < 32;++j) aorig[j] = a[j];
  add(a,a,minusp);
  negative = -((a[31] >> 7) & 1);
  ಪ್ರತಿ (j = 0;j < 32;++j) a[j] ^= negative & (aorig[j] ^ a[j]);
}

ಸ್ಥಿರ ಶೂನ್ಯ mult(unsigned ಪೂರ್ಣಾಙ್ಕ out[32],ಧ್ರುವ unsigned ಪೂರ್ಣಾಙ್ಕ a[32],ಧ್ರುವ unsigned ಪೂರ್ಣಾಙ್ಕ b[32])
{
  unsigned ಪೂರ್ಣಾಙ್ಕ i;
  unsigned ಪೂರ್ಣಾಙ್ಕ j;
  unsigned ಪೂರ್ಣಾಙ್ಕ u;

  ಪ್ರತಿ (i = 0;i < 32;++i) {
    u = 0;
    ಪ್ರತಿ (j = 0;j <= i;++j) u += a[j] * b[i - j];
    ಪ್ರತಿ (j = i + 1;j < 32;++j) u += 38 * a[j] * b[i + 32 - j];
    out[i] = u;
  }
  squeeze(out);
}

ಸ್ಥಿರ ಶೂನ್ಯ mult121665(unsigned ಪೂರ್ಣಾಙ್ಕ out[32],ಧ್ರುವ unsigned ಪೂರ್ಣಾಙ್ಕ a[32])
{
  unsigned ಪೂರ್ಣಾಙ್ಕ j;
  unsigned ಪೂರ್ಣಾಙ್ಕ u;

  u = 0;
  ಪ್ರತಿ (j = 0;j < 31;++j) { u += 121665 * a[j]; out[j] = u & 255; u >>= 8; }
  u += 121665 * a[31]; out[31] = u & 127;
  u = 19 * (u >> 7);
  ಪ್ರತಿ (j = 0;j < 31;++j) { u += out[j]; out[j] = u & 255; u >>= 8; }
  u += out[j]; out[j] = u;
}

ಸ್ಥಿರ ಶೂನ್ಯ square(unsigned ಪೂರ್ಣಾಙ್ಕ out[32],ಧ್ರುವ unsigned ಪೂರ್ಣಾಙ್ಕ a[32])
{
  unsigned ಪೂರ್ಣಾಙ್ಕ i;
  unsigned ಪೂರ್ಣಾಙ್ಕ j;
  unsigned ಪೂರ್ಣಾಙ್ಕ u;

  ಪ್ರತಿ (i = 0;i < 32;++i) {
    u = 0;
    ಪ್ರತಿ (j = 0;j < i - j;++j) u += a[j] * a[i - j];
    ಪ್ರತಿ (j = i + 1;j < i + 32 - j;++j) u += 38 * a[j] * a[i + 32 - j];
    u *= 2;
    ಯದಿ ((i & 1) == 0) {
      u += a[i / 2] * a[i / 2];
      u += 38 * a[i / 2 + 16] * a[i / 2 + 16];
    }
    out[i] = u;
  }
  squeeze(out);
}

ಸ್ಥಿರ ಶೂನ್ಯ select(unsigned ಪೂರ್ಣಾಙ್ಕ p[64],unsigned ಪೂರ್ಣಾಙ್ಕ q[64],ಧ್ರುವ unsigned ಪೂರ್ಣಾಙ್ಕ r[64],ಧ್ರುವ unsigned ಪೂರ್ಣಾಙ್ಕ s[64],unsigned ಪೂರ್ಣಾಙ್ಕ b)
{
  unsigned ಪೂರ್ಣಾಙ್ಕ j;
  unsigned ಪೂರ್ಣಾಙ್ಕ t;
  unsigned ಪೂರ್ಣಾಙ್ಕ bminus1;

  bminus1 = b - 1;
  ಪ್ರತಿ (j = 0;j < 64;++j) {
    t = bminus1 & (r[j] ^ s[j]);
    p[j] = s[j] ^ t;
    q[j] = r[j] ^ t;
  }
}

ಸ್ಥಿರ ಶೂನ್ಯ mainloop(unsigned ಪೂರ್ಣಾಙ್ಕ work[64],ಧ್ರುವ unsigned ವರ್ಣ e[32])
{
  unsigned ಪೂರ್ಣಾಙ್ಕ xzm1[64];
  unsigned ಪೂರ್ಣಾಙ್ಕ xzm[64];
  unsigned ಪೂರ್ಣಾಙ್ಕ xzmb[64];
  unsigned ಪೂರ್ಣಾಙ್ಕ xzm1b[64];
  unsigned ಪೂರ್ಣಾಙ್ಕ xznb[64];
  unsigned ಪೂರ್ಣಾಙ್ಕ xzn1b[64];
  unsigned ಪೂರ್ಣಾಙ್ಕ a0[64];
  unsigned ಪೂರ್ಣಾಙ್ಕ a1[64];
  unsigned ಪೂರ್ಣಾಙ್ಕ b0[64];
  unsigned ಪೂರ್ಣಾಙ್ಕ b1[64];
  unsigned ಪೂರ್ಣಾಙ್ಕ c1[64];
  unsigned ಪೂರ್ಣಾಙ್ಕ r[32];
  unsigned ಪೂರ್ಣಾಙ್ಕ s[32];
  unsigned ಪೂರ್ಣಾಙ್ಕ t[32];
  unsigned ಪೂರ್ಣಾಙ್ಕ u[32];
  unsigned ಪೂರ್ಣಾಙ್ಕ j;
  unsigned ಪೂರ್ಣಾಙ್ಕ b;
  ಪೂರ್ಣಾಙ್ಕ pos;

  ಪ್ರತಿ (j = 0;j < 32;++j) xzm1[j] = work[j];
  xzm1[32] = 1;
  ಪ್ರತಿ (j = 33;j < 64;++j) xzm1[j] = 0;

  xzm[0] = 1;
  ಪ್ರತಿ (j = 1;j < 64;++j) xzm[j] = 0;

  ಪ್ರತಿ (pos = 254;pos >= 0;--pos) {
    b = e[pos / 8] >> (pos & 7);
    b &= 1;
    select(xzmb,xzm1b,xzm,xzm1,b);
    add(a0,xzmb,xzmb + 32);
    sub(a0 + 32,xzmb,xzmb + 32);
    add(a1,xzm1b,xzm1b + 32);
    sub(a1 + 32,xzm1b,xzm1b + 32);
    square(b0,a0);
    square(b0 + 32,a0 + 32);
    mult(b1,a1,a0 + 32);
    mult(b1 + 32,a1 + 32,a0);
    add(c1,b1,b1 + 32);
    sub(c1 + 32,b1,b1 + 32);
    square(r,c1 + 32);
    sub(s,b0,b0 + 32);
    mult121665(t,s);
    add(u,t,b0);
    mult(xznb,b0,b0 + 32);
    mult(xznb + 32,s,u);
    square(xzn1b,c1);
    mult(xzn1b + 32,r,work);
    select(xzm,xzm1,xznb,xzn1b,b);
  }

  ಪ್ರತಿ (j = 0;j < 64;++j) work[j] = xzm[j];
}

ಸ್ಥಿರ ಶೂನ್ಯ recip(unsigned ಪೂರ್ಣಾಙ್ಕ out[32],ಧ್ರುವ unsigned ಪೂರ್ಣಾಙ್ಕ z[32])
{
  unsigned ಪೂರ್ಣಾಙ್ಕ z2[32];
  unsigned ಪೂರ್ಣಾಙ್ಕ z9[32];
  unsigned ಪೂರ್ಣಾಙ್ಕ z11[32];
  unsigned ಪೂರ್ಣಾಙ್ಕ z2_5_0[32];
  unsigned ಪೂರ್ಣಾಙ್ಕ z2_10_0[32];
  unsigned ಪೂರ್ಣಾಙ್ಕ z2_20_0[32];
  unsigned ಪೂರ್ಣಾಙ್ಕ z2_50_0[32];
  unsigned ಪೂರ್ಣಾಙ್ಕ z2_100_0[32];
  unsigned ಪೂರ್ಣಾಙ್ಕ t0[32];
  unsigned ಪೂರ್ಣಾಙ್ಕ t1[32];
  ಪೂರ್ಣಾಙ್ಕ i;

  /* 2 */ square(z2,z);
  /* 4 */ square(t1,z2);
  /* 8 */ square(t0,t1);
  /* 9 */ mult(z9,t0,z);
  /* 11 */ mult(z11,z9,z2);
  /* 22 */ square(t0,z11);
  /* 2^5 - 2^0 = 31 */ mult(z2_5_0,t0,z9);

  /* 2^6 - 2^1 */ square(t0,z2_5_0);
  /* 2^7 - 2^2 */ square(t1,t0);
  /* 2^8 - 2^3 */ square(t0,t1);
  /* 2^9 - 2^4 */ square(t1,t0);
  /* 2^10 - 2^5 */ square(t0,t1);
  /* 2^10 - 2^0 */ mult(z2_10_0,t0,z2_5_0);

  /* 2^11 - 2^1 */ square(t0,z2_10_0);
  /* 2^12 - 2^2 */ square(t1,t0);
  /* 2^20 - 2^10 */ ಪ್ರತಿ (i = 2;i < 10;i += 2) { square(t0,t1); square(t1,t0); }
  /* 2^20 - 2^0 */ mult(z2_20_0,t1,z2_10_0);

  /* 2^21 - 2^1 */ square(t0,z2_20_0);
  /* 2^22 - 2^2 */ square(t1,t0);
  /* 2^40 - 2^20 */ ಪ್ರತಿ (i = 2;i < 20;i += 2) { square(t0,t1); square(t1,t0); }
  /* 2^40 - 2^0 */ mult(t0,t1,z2_20_0);

  /* 2^41 - 2^1 */ square(t1,t0);
  /* 2^42 - 2^2 */ square(t0,t1);
  /* 2^50 - 2^10 */ ಪ್ರತಿ (i = 2;i < 10;i += 2) { square(t1,t0); square(t0,t1); }
  /* 2^50 - 2^0 */ mult(z2_50_0,t0,z2_10_0);

  /* 2^51 - 2^1 */ square(t0,z2_50_0);
  /* 2^52 - 2^2 */ square(t1,t0);
  /* 2^100 - 2^50 */ ಪ್ರತಿ (i = 2;i < 50;i += 2) { square(t0,t1); square(t1,t0); }
  /* 2^100 - 2^0 */ mult(z2_100_0,t1,z2_50_0);

  /* 2^101 - 2^1 */ square(t1,z2_100_0);
  /* 2^102 - 2^2 */ square(t0,t1);
  /* 2^200 - 2^100 */ ಪ್ರತಿ (i = 2;i < 100;i += 2) { square(t1,t0); square(t0,t1); }
  /* 2^200 - 2^0 */ mult(t1,t0,z2_100_0);

  /* 2^201 - 2^1 */ square(t0,t1);
  /* 2^202 - 2^2 */ square(t1,t0);
  /* 2^250 - 2^50 */ ಪ್ರತಿ (i = 2;i < 50;i += 2) { square(t0,t1); square(t1,t0); }
  /* 2^250 - 2^0 */ mult(t0,t1,z2_50_0);

  /* 2^251 - 2^1 */ square(t1,t0);
  /* 2^252 - 2^2 */ square(t0,t1);
  /* 2^253 - 2^3 */ square(t1,t0);
  /* 2^254 - 2^4 */ square(t0,t1);
  /* 2^255 - 2^5 */ square(t1,t0);
  /* 2^255 - 21 */ mult(out,t1,z11);
}

ಪೂರ್ಣಾಙ್ಕ crypto_scalarmult_curve25519(unsigned ವರ್ಣ *q,
  ಧ್ರುವ unsigned ವರ್ಣ *n,
  ಧ್ರುವ unsigned ವರ್ಣ *p)
{
  unsigned ಪೂರ್ಣಾಙ್ಕ work[96];
  unsigned ವರ್ಣ e[32];
  unsigned ಪೂರ್ಣಾಙ್ಕ i;
  ಪ್ರತಿ (i = 0;i < 32;++i) e[i] = n[i];
  e[0] &= 248;
  e[31] &= 127;
  e[31] |= 64;
  ಪ್ರತಿ (i = 0;i < 32;++i) work[i] = p[i];
  mainloop(work,e);
  recip(work + 32,work + 32);
  mult(work + 64,work,work + 32);
  freeze(work + 64);
  ಪ್ರತಿ (i = 0;i < 32;++i) q[i] = work[64 + i];
  ಪ್ರತ್ಯಾಗಮ 0;
}
