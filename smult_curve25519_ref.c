/* $OpenBSD: smult_curve25519_ref.c,v 1.2 2013/11/02 22:02:14 markus Exp $ */
/*
version 20081011
Matthew Dempsky
Public domain.
Derived from public domain code by D. J. Bernstein.
*/

പൂർണ്ണസംഖ്യ crypto_scalarmult_curve25519(unsigned അക്ഷരം *, സ്ഥിരം unsigned അക്ഷരം *, സ്ഥിരം unsigned അക്ഷരം *);

സ്ഥിതം ശൂന്യം add(unsigned പൂർണ്ണസംഖ്യ out[32],സ്ഥിരം unsigned പൂർണ്ണസംഖ്യ a[32],സ്ഥിരം unsigned പൂർണ്ണസംഖ്യ b[32])
{
  unsigned പൂർണ്ണസംഖ്യ j;
  unsigned പൂർണ്ണസംഖ്യ u;
  u = 0;
  വേണ്ടി (j = 0;j < 31;++j) { u += a[j] + b[j]; out[j] = u & 255; u >>= 8; }
  u += a[31] + b[31]; out[31] = u;
}

സ്ഥിതം ശൂന്യം sub(unsigned പൂർണ്ണസംഖ്യ out[32],സ്ഥിരം unsigned പൂർണ്ണസംഖ്യ a[32],സ്ഥിരം unsigned പൂർണ്ണസംഖ്യ b[32])
{
  unsigned പൂർണ്ണസംഖ്യ j;
  unsigned പൂർണ്ണസംഖ്യ u;
  u = 218;
  വേണ്ടി (j = 0;j < 31;++j) {
    u += a[j] + 65280 - b[j];
    out[j] = u & 255;
    u >>= 8;
  }
  u += a[31] - b[31];
  out[31] = u;
}

സ്ഥിതം ശൂന്യം squeeze(unsigned പൂർണ്ണസംഖ്യ a[32])
{
  unsigned പൂർണ്ണസംഖ്യ j;
  unsigned പൂർണ്ണസംഖ്യ u;
  u = 0;
  വേണ്ടി (j = 0;j < 31;++j) { u += a[j]; a[j] = u & 255; u >>= 8; }
  u += a[31]; a[31] = u & 127;
  u = 19 * (u >> 7);
  വേണ്ടി (j = 0;j < 31;++j) { u += a[j]; a[j] = u & 255; u >>= 8; }
  u += a[31]; a[31] = u;
}

സ്ഥിതം സ്ഥിരം unsigned പൂർണ്ണസംഖ്യ minusp[32] = {
 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128
} ;

സ്ഥിതം ശൂന്യം freeze(unsigned പൂർണ്ണസംഖ്യ a[32])
{
  unsigned പൂർണ്ണസംഖ്യ aorig[32];
  unsigned പൂർണ്ണസംഖ്യ j;
  unsigned പൂർണ്ണസംഖ്യ negative;

  വേണ്ടി (j = 0;j < 32;++j) aorig[j] = a[j];
  add(a,a,minusp);
  negative = -((a[31] >> 7) & 1);
  വേണ്ടി (j = 0;j < 32;++j) a[j] ^= negative & (aorig[j] ^ a[j]);
}

സ്ഥിതം ശൂന്യം mult(unsigned പൂർണ്ണസംഖ്യ out[32],സ്ഥിരം unsigned പൂർണ്ണസംഖ്യ a[32],സ്ഥിരം unsigned പൂർണ്ണസംഖ്യ b[32])
{
  unsigned പൂർണ്ണസംഖ്യ i;
  unsigned പൂർണ്ണസംഖ്യ j;
  unsigned പൂർണ്ണസംഖ്യ u;

  വേണ്ടി (i = 0;i < 32;++i) {
    u = 0;
    വേണ്ടി (j = 0;j <= i;++j) u += a[j] * b[i - j];
    വേണ്ടി (j = i + 1;j < 32;++j) u += 38 * a[j] * b[i + 32 - j];
    out[i] = u;
  }
  squeeze(out);
}

സ്ഥിതം ശൂന്യം mult121665(unsigned പൂർണ്ണസംഖ്യ out[32],സ്ഥിരം unsigned പൂർണ്ണസംഖ്യ a[32])
{
  unsigned പൂർണ്ണസംഖ്യ j;
  unsigned പൂർണ്ണസംഖ്യ u;

  u = 0;
  വേണ്ടി (j = 0;j < 31;++j) { u += 121665 * a[j]; out[j] = u & 255; u >>= 8; }
  u += 121665 * a[31]; out[31] = u & 127;
  u = 19 * (u >> 7);
  വേണ്ടി (j = 0;j < 31;++j) { u += out[j]; out[j] = u & 255; u >>= 8; }
  u += out[j]; out[j] = u;
}

സ്ഥിതം ശൂന്യം square(unsigned പൂർണ്ണസംഖ്യ out[32],സ്ഥിരം unsigned പൂർണ്ണസംഖ്യ a[32])
{
  unsigned പൂർണ്ണസംഖ്യ i;
  unsigned പൂർണ്ണസംഖ്യ j;
  unsigned പൂർണ്ണസംഖ്യ u;

  വേണ്ടി (i = 0;i < 32;++i) {
    u = 0;
    വേണ്ടി (j = 0;j < i - j;++j) u += a[j] * a[i - j];
    വേണ്ടി (j = i + 1;j < i + 32 - j;++j) u += 38 * a[j] * a[i + 32 - j];
    u *= 2;
    എങ്കിൽ ((i & 1) == 0) {
      u += a[i / 2] * a[i / 2];
      u += 38 * a[i / 2 + 16] * a[i / 2 + 16];
    }
    out[i] = u;
  }
  squeeze(out);
}

സ്ഥിതം ശൂന്യം select(unsigned പൂർണ്ണസംഖ്യ p[64],unsigned പൂർണ്ണസംഖ്യ q[64],സ്ഥിരം unsigned പൂർണ്ണസംഖ്യ r[64],സ്ഥിരം unsigned പൂർണ്ണസംഖ്യ s[64],unsigned പൂർണ്ണസംഖ്യ b)
{
  unsigned പൂർണ്ണസംഖ്യ j;
  unsigned പൂർണ്ണസംഖ്യ t;
  unsigned പൂർണ്ണസംഖ്യ bminus1;

  bminus1 = b - 1;
  വേണ്ടി (j = 0;j < 64;++j) {
    t = bminus1 & (r[j] ^ s[j]);
    p[j] = s[j] ^ t;
    q[j] = r[j] ^ t;
  }
}

സ്ഥിതം ശൂന്യം mainloop(unsigned പൂർണ്ണസംഖ്യ work[64],സ്ഥിരം unsigned അക്ഷരം e[32])
{
  unsigned പൂർണ്ണസംഖ്യ xzm1[64];
  unsigned പൂർണ്ണസംഖ്യ xzm[64];
  unsigned പൂർണ്ണസംഖ്യ xzmb[64];
  unsigned പൂർണ്ണസംഖ്യ xzm1b[64];
  unsigned പൂർണ്ണസംഖ്യ xznb[64];
  unsigned പൂർണ്ണസംഖ്യ xzn1b[64];
  unsigned പൂർണ്ണസംഖ്യ a0[64];
  unsigned പൂർണ്ണസംഖ്യ a1[64];
  unsigned പൂർണ്ണസംഖ്യ b0[64];
  unsigned പൂർണ്ണസംഖ്യ b1[64];
  unsigned പൂർണ്ണസംഖ്യ c1[64];
  unsigned പൂർണ്ണസംഖ്യ r[32];
  unsigned പൂർണ്ണസംഖ്യ s[32];
  unsigned പൂർണ്ണസംഖ്യ t[32];
  unsigned പൂർണ്ണസംഖ്യ u[32];
  unsigned പൂർണ്ണസംഖ്യ j;
  unsigned പൂർണ്ണസംഖ്യ b;
  പൂർണ്ണസംഖ്യ pos;

  വേണ്ടി (j = 0;j < 32;++j) xzm1[j] = work[j];
  xzm1[32] = 1;
  വേണ്ടി (j = 33;j < 64;++j) xzm1[j] = 0;

  xzm[0] = 1;
  വേണ്ടി (j = 1;j < 64;++j) xzm[j] = 0;

  വേണ്ടി (pos = 254;pos >= 0;--pos) {
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

  വേണ്ടി (j = 0;j < 64;++j) work[j] = xzm[j];
}

സ്ഥിതം ശൂന്യം recip(unsigned പൂർണ്ണസംഖ്യ out[32],സ്ഥിരം unsigned പൂർണ്ണസംഖ്യ z[32])
{
  unsigned പൂർണ്ണസംഖ്യ z2[32];
  unsigned പൂർണ്ണസംഖ്യ z9[32];
  unsigned പൂർണ്ണസംഖ്യ z11[32];
  unsigned പൂർണ്ണസംഖ്യ z2_5_0[32];
  unsigned പൂർണ്ണസംഖ്യ z2_10_0[32];
  unsigned പൂർണ്ണസംഖ്യ z2_20_0[32];
  unsigned പൂർണ്ണസംഖ്യ z2_50_0[32];
  unsigned പൂർണ്ണസംഖ്യ z2_100_0[32];
  unsigned പൂർണ്ണസംഖ്യ t0[32];
  unsigned പൂർണ്ണസംഖ്യ t1[32];
  പൂർണ്ണസംഖ്യ i;

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
  /* 2^20 - 2^10 */ വേണ്ടി (i = 2;i < 10;i += 2) { square(t0,t1); square(t1,t0); }
  /* 2^20 - 2^0 */ mult(z2_20_0,t1,z2_10_0);

  /* 2^21 - 2^1 */ square(t0,z2_20_0);
  /* 2^22 - 2^2 */ square(t1,t0);
  /* 2^40 - 2^20 */ വേണ്ടി (i = 2;i < 20;i += 2) { square(t0,t1); square(t1,t0); }
  /* 2^40 - 2^0 */ mult(t0,t1,z2_20_0);

  /* 2^41 - 2^1 */ square(t1,t0);
  /* 2^42 - 2^2 */ square(t0,t1);
  /* 2^50 - 2^10 */ വേണ്ടി (i = 2;i < 10;i += 2) { square(t1,t0); square(t0,t1); }
  /* 2^50 - 2^0 */ mult(z2_50_0,t0,z2_10_0);

  /* 2^51 - 2^1 */ square(t0,z2_50_0);
  /* 2^52 - 2^2 */ square(t1,t0);
  /* 2^100 - 2^50 */ വേണ്ടി (i = 2;i < 50;i += 2) { square(t0,t1); square(t1,t0); }
  /* 2^100 - 2^0 */ mult(z2_100_0,t1,z2_50_0);

  /* 2^101 - 2^1 */ square(t1,z2_100_0);
  /* 2^102 - 2^2 */ square(t0,t1);
  /* 2^200 - 2^100 */ വേണ്ടി (i = 2;i < 100;i += 2) { square(t1,t0); square(t0,t1); }
  /* 2^200 - 2^0 */ mult(t1,t0,z2_100_0);

  /* 2^201 - 2^1 */ square(t0,t1);
  /* 2^202 - 2^2 */ square(t1,t0);
  /* 2^250 - 2^50 */ വേണ്ടി (i = 2;i < 50;i += 2) { square(t0,t1); square(t1,t0); }
  /* 2^250 - 2^0 */ mult(t0,t1,z2_50_0);

  /* 2^251 - 2^1 */ square(t1,t0);
  /* 2^252 - 2^2 */ square(t0,t1);
  /* 2^253 - 2^3 */ square(t1,t0);
  /* 2^254 - 2^4 */ square(t0,t1);
  /* 2^255 - 2^5 */ square(t1,t0);
  /* 2^255 - 21 */ mult(out,t1,z11);
}

പൂർണ്ണസംഖ്യ crypto_scalarmult_curve25519(unsigned അക്ഷരം *q,
  സ്ഥിരം unsigned അക്ഷരം *n,
  സ്ഥിരം unsigned അക്ഷരം *p)
{
  unsigned പൂർണ്ണസംഖ്യ work[96];
  unsigned അക്ഷരം e[32];
  unsigned പൂർണ്ണസംഖ്യ i;
  വേണ്ടി (i = 0;i < 32;++i) e[i] = n[i];
  e[0] &= 248;
  e[31] &= 127;
  e[31] |= 64;
  വേണ്ടി (i = 0;i < 32;++i) work[i] = p[i];
  mainloop(work,e);
  recip(work + 32,work + 32);
  mult(work + 64,work,work + 32);
  freeze(work + 64);
  വേണ്ടി (i = 0;i < 32;++i) q[i] = work[64 + i];
  തിരികെ 0;
}
