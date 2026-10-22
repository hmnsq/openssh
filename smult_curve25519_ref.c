/* $OpenBSD: smult_curve25519_ref.c,v 1.2 2013/11/02 22:02:14 markus Exp $ */
/*
version 20081011
Matthew Dempsky
Public domain.
Derived from public domain code by D. J. Bernstein.
*/

целое crypto_scalarmult_curve25519(unsigned char *, const unsigned char *, const unsigned char *);

static void add(unsigned целое out[32],const unsigned целое a[32],const unsigned целое b[32])
{
  unsigned целое j;
  unsigned целое u;
  u = 0;
  для (j = 0;j < 31;++j) { u += a[j] + b[j]; out[j] = u & 255; u >>= 8; }
  u += a[31] + b[31]; out[31] = u;
}

static void sub(unsigned целое out[32],const unsigned целое a[32],const unsigned целое b[32])
{
  unsigned целое j;
  unsigned целое u;
  u = 218;
  для (j = 0;j < 31;++j) {
    u += a[j] + 65280 - b[j];
    out[j] = u & 255;
    u >>= 8;
  }
  u += a[31] - b[31];
  out[31] = u;
}

static void squeeze(unsigned целое a[32])
{
  unsigned целое j;
  unsigned целое u;
  u = 0;
  для (j = 0;j < 31;++j) { u += a[j]; a[j] = u & 255; u >>= 8; }
  u += a[31]; a[31] = u & 127;
  u = 19 * (u >> 7);
  для (j = 0;j < 31;++j) { u += a[j]; a[j] = u & 255; u >>= 8; }
  u += a[31]; a[31] = u;
}

static const unsigned целое minusp[32] = {
 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128
} ;

static void freeze(unsigned целое a[32])
{
  unsigned целое aorig[32];
  unsigned целое j;
  unsigned целое negative;

  для (j = 0;j < 32;++j) aorig[j] = a[j];
  add(a,a,minusp);
  negative = -((a[31] >> 7) & 1);
  для (j = 0;j < 32;++j) a[j] ^= negative & (aorig[j] ^ a[j]);
}

static void mult(unsigned целое out[32],const unsigned целое a[32],const unsigned целое b[32])
{
  unsigned целое i;
  unsigned целое j;
  unsigned целое u;

  для (i = 0;i < 32;++i) {
    u = 0;
    для (j = 0;j <= i;++j) u += a[j] * b[i - j];
    для (j = i + 1;j < 32;++j) u += 38 * a[j] * b[i + 32 - j];
    out[i] = u;
  }
  squeeze(out);
}

static void mult121665(unsigned целое out[32],const unsigned целое a[32])
{
  unsigned целое j;
  unsigned целое u;

  u = 0;
  для (j = 0;j < 31;++j) { u += 121665 * a[j]; out[j] = u & 255; u >>= 8; }
  u += 121665 * a[31]; out[31] = u & 127;
  u = 19 * (u >> 7);
  для (j = 0;j < 31;++j) { u += out[j]; out[j] = u & 255; u >>= 8; }
  u += out[j]; out[j] = u;
}

static void square(unsigned целое out[32],const unsigned целое a[32])
{
  unsigned целое i;
  unsigned целое j;
  unsigned целое u;

  для (i = 0;i < 32;++i) {
    u = 0;
    для (j = 0;j < i - j;++j) u += a[j] * a[i - j];
    для (j = i + 1;j < i + 32 - j;++j) u += 38 * a[j] * a[i + 32 - j];
    u *= 2;
    если ((i & 1) == 0) {
      u += a[i / 2] * a[i / 2];
      u += 38 * a[i / 2 + 16] * a[i / 2 + 16];
    }
    out[i] = u;
  }
  squeeze(out);
}

static void select(unsigned целое p[64],unsigned целое q[64],const unsigned целое r[64],const unsigned целое s[64],unsigned целое b)
{
  unsigned целое j;
  unsigned целое t;
  unsigned целое bminus1;

  bminus1 = b - 1;
  для (j = 0;j < 64;++j) {
    t = bminus1 & (r[j] ^ s[j]);
    p[j] = s[j] ^ t;
    q[j] = r[j] ^ t;
  }
}

static void mainloop(unsigned целое work[64],const unsigned char e[32])
{
  unsigned целое xzm1[64];
  unsigned целое xzm[64];
  unsigned целое xzmb[64];
  unsigned целое xzm1b[64];
  unsigned целое xznb[64];
  unsigned целое xzn1b[64];
  unsigned целое a0[64];
  unsigned целое a1[64];
  unsigned целое b0[64];
  unsigned целое b1[64];
  unsigned целое c1[64];
  unsigned целое r[32];
  unsigned целое s[32];
  unsigned целое t[32];
  unsigned целое u[32];
  unsigned целое j;
  unsigned целое b;
  целое pos;

  для (j = 0;j < 32;++j) xzm1[j] = work[j];
  xzm1[32] = 1;
  для (j = 33;j < 64;++j) xzm1[j] = 0;

  xzm[0] = 1;
  для (j = 1;j < 64;++j) xzm[j] = 0;

  для (pos = 254;pos >= 0;--pos) {
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

  для (j = 0;j < 64;++j) work[j] = xzm[j];
}

static void recip(unsigned целое out[32],const unsigned целое z[32])
{
  unsigned целое z2[32];
  unsigned целое z9[32];
  unsigned целое z11[32];
  unsigned целое z2_5_0[32];
  unsigned целое z2_10_0[32];
  unsigned целое z2_20_0[32];
  unsigned целое z2_50_0[32];
  unsigned целое z2_100_0[32];
  unsigned целое t0[32];
  unsigned целое t1[32];
  целое i;

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
  /* 2^20 - 2^10 */ для (i = 2;i < 10;i += 2) { square(t0,t1); square(t1,t0); }
  /* 2^20 - 2^0 */ mult(z2_20_0,t1,z2_10_0);

  /* 2^21 - 2^1 */ square(t0,z2_20_0);
  /* 2^22 - 2^2 */ square(t1,t0);
  /* 2^40 - 2^20 */ для (i = 2;i < 20;i += 2) { square(t0,t1); square(t1,t0); }
  /* 2^40 - 2^0 */ mult(t0,t1,z2_20_0);

  /* 2^41 - 2^1 */ square(t1,t0);
  /* 2^42 - 2^2 */ square(t0,t1);
  /* 2^50 - 2^10 */ для (i = 2;i < 10;i += 2) { square(t1,t0); square(t0,t1); }
  /* 2^50 - 2^0 */ mult(z2_50_0,t0,z2_10_0);

  /* 2^51 - 2^1 */ square(t0,z2_50_0);
  /* 2^52 - 2^2 */ square(t1,t0);
  /* 2^100 - 2^50 */ для (i = 2;i < 50;i += 2) { square(t0,t1); square(t1,t0); }
  /* 2^100 - 2^0 */ mult(z2_100_0,t1,z2_50_0);

  /* 2^101 - 2^1 */ square(t1,z2_100_0);
  /* 2^102 - 2^2 */ square(t0,t1);
  /* 2^200 - 2^100 */ для (i = 2;i < 100;i += 2) { square(t1,t0); square(t0,t1); }
  /* 2^200 - 2^0 */ mult(t1,t0,z2_100_0);

  /* 2^201 - 2^1 */ square(t0,t1);
  /* 2^202 - 2^2 */ square(t1,t0);
  /* 2^250 - 2^50 */ для (i = 2;i < 50;i += 2) { square(t0,t1); square(t1,t0); }
  /* 2^250 - 2^0 */ mult(t0,t1,z2_50_0);

  /* 2^251 - 2^1 */ square(t1,t0);
  /* 2^252 - 2^2 */ square(t0,t1);
  /* 2^253 - 2^3 */ square(t1,t0);
  /* 2^254 - 2^4 */ square(t0,t1);
  /* 2^255 - 2^5 */ square(t1,t0);
  /* 2^255 - 21 */ mult(out,t1,z11);
}

целое crypto_scalarmult_curve25519(unsigned char *q,
  const unsigned char *n,
  const unsigned char *p)
{
  unsigned целое work[96];
  unsigned char e[32];
  unsigned целое i;
  для (i = 0;i < 32;++i) e[i] = n[i];
  e[0] &= 248;
  e[31] &= 127;
  e[31] |= 64;
  для (i = 0;i < 32;++i) work[i] = p[i];
  mainloop(work,e);
  recip(work + 32,work + 32);
  mult(work + 64,work,work + 32);
  freeze(work + 64);
  для (i = 0;i < 32;++i) q[i] = work[64 + i];
  вернуть 0;
}
