/* $OpenBSD: hmac.c,v 1.16 2026/02/14 00:18:34 jsg Exp $ */
/*
 * Copyright (c) 2014 Markus Friedl.  All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#समावेश "includes.h"

#समावेश <sys/types.h>

#समावेश <stdlib.h>
#समावेश <string.h>

#समावेश "digest.h"
#समावेश "hmac.h"

काष्ठा ssh_hmac_ctx {
	पूर्णांक			 alg;
	काष्ठा ssh_digest_ctx	*ictx;
	काष्ठा ssh_digest_ctx	*octx;
	काष्ठा ssh_digest_ctx	*digest;
	u_char			*buf;
	माप_प्रकार			 buf_len;
};

माप_प्रकार
ssh_hmac_bytes(पूर्णांक alg)
{
	वापस ssh_digest_bytes(alg);
}

काष्ठा ssh_hmac_ctx *
ssh_hmac_start(पूर्णांक alg)
{
	काष्ठा ssh_hmac_ctx	*ret;

	अगर ((ret = सुस्मृति(1, माप(*ret))) == शून्य)
		वापस शून्य;
	ret->alg = alg;
	अगर ((ret->ictx = ssh_digest_start(alg)) == शून्य ||
	    (ret->octx = ssh_digest_start(alg)) == शून्य ||
	    (ret->digest = ssh_digest_start(alg)) == शून्य)
		जाओ fail;
	ret->buf_len = ssh_digest_blocksize(ret->ictx);
	अगर ((ret->buf = सुस्मृति(1, ret->buf_len)) == शून्य)
		जाओ fail;
	वापस ret;
fail:
	ssh_hmac_free(ret);
	वापस शून्य;
}

पूर्णांक
ssh_hmac_init(काष्ठा ssh_hmac_ctx *ctx, स्थिर व्योम *कुंजी, माप_प्रकार klen)
{
	माप_प्रकार i;

	/* reset ictx and octx if no is key given */
	अगर (कुंजी != शून्य) {
		/* truncate long keys */
		अगर (klen <= ctx->buf_len)
			स_नकल(ctx->buf, कुंजी, klen);
		अन्यथा अगर (ssh_digest_memory(ctx->alg, कुंजी, klen, ctx->buf,
		    ctx->buf_len) < 0)
			वापस -1;
		क्रम (i = 0; i < ctx->buf_len; i++)
			ctx->buf[i] ^= 0x36;
		अगर (ssh_digest_update(ctx->ictx, ctx->buf, ctx->buf_len) < 0)
			वापस -1;
		क्रम (i = 0; i < ctx->buf_len; i++)
			ctx->buf[i] ^= 0x36 ^ 0x5c;
		अगर (ssh_digest_update(ctx->octx, ctx->buf, ctx->buf_len) < 0)
			वापस -1;
		explicit_bzero(ctx->buf, ctx->buf_len);
	}
	/* start with ictx */
	अगर (ssh_digest_copy_state(ctx->ictx, ctx->digest) < 0)
		वापस -1;
	वापस 0;
}

पूर्णांक
ssh_hmac_update(काष्ठा ssh_hmac_ctx *ctx, स्थिर व्योम *m, माप_प्रकार mlen)
{
	वापस ssh_digest_update(ctx->digest, m, mlen);
}

पूर्णांक
ssh_hmac_update_बफर(काष्ठा ssh_hmac_ctx *ctx, स्थिर काष्ठा sshbuf *b)
{
	वापस ssh_digest_update_बफर(ctx->digest, b);
}

पूर्णांक
ssh_hmac_final(काष्ठा ssh_hmac_ctx *ctx, u_char *d, माप_प्रकार dlen)
{
	माप_प्रकार len;

	len = ssh_digest_bytes(ctx->alg);
	अगर (dlen < len ||
	    ssh_digest_final(ctx->digest, ctx->buf, len))
		वापस -1;
	/* switch to octx */
	अगर (ssh_digest_copy_state(ctx->octx, ctx->digest) < 0 ||
	    ssh_digest_update(ctx->digest, ctx->buf, len) < 0 ||
	    ssh_digest_final(ctx->digest, d, dlen) < 0)
		वापस -1;
	वापस 0;
}

व्योम
ssh_hmac_free(काष्ठा ssh_hmac_ctx *ctx)
{
	अगर (ctx != शून्य) {
		ssh_digest_free(ctx->ictx);
		ssh_digest_free(ctx->octx);
		ssh_digest_free(ctx->digest);
		अगर (ctx->buf) {
			explicit_bzero(ctx->buf, ctx->buf_len);
			मुक्त(ctx->buf);
		}
		freezero(ctx, माप(*ctx));
	}
}

#अगर_घोषित TEST

/* cc -DTEST hmac.c digest.c buffer.c cleanup.c fatal.c log.c xmalloc.c -lcrypto */
अटल व्योम
hmac_test(व्योम *कुंजी, माप_प्रकार klen, व्योम *m, माप_प्रकार mlen, u_char *e, माप_प्रकार elen)
{
	काष्ठा ssh_hmac_ctx	*ctx;
	माप_प्रकार			 i;
	u_char			 digest[16];

	अगर ((ctx = ssh_hmac_start(SSH_DIGEST_MD5)) == शून्य)
		म_लिखो("ssh_hmac_start failed");
	अगर (ssh_hmac_init(ctx, कुंजी, klen) < 0 ||
	    ssh_hmac_update(ctx, m, mlen) < 0 ||
	    ssh_hmac_final(ctx, digest, माप(digest)) < 0)
		म_लिखो("ssh_hmac_xxx failed");
	ssh_hmac_free(ctx);

	अगर (स_भेद(e, digest, elen)) {
		क्रम (i = 0; i < elen; i++)
			म_लिखो("[%zu] %2.2x %2.2x\n", i, e[i], digest[i]);
		म_लिखो("mismatch\n");
	} अन्यथा
		म_लिखो("ok\n");
}

पूर्णांक
मुख्य(पूर्णांक argc, अक्षर **argv)
{
	/* try test vectors from RFC 2104 */

	u_char key1[16] = {
	    0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb,
	    0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb };
	u_char *data1 = "Hi There";
	u_char dig1[16] = {
	    0x92, 0x94, 0x72, 0x7a, 0x36, 0x38, 0xbb, 0x1c,
	    0x13, 0xf4, 0x8e, 0xf8, 0x15, 0x8b, 0xfc, 0x9d };

	u_char *key2 = "Jefe";
	u_char *data2 = "what do ya want for nothing?";
	u_char dig2[16] = {
	    0x75, 0x0c, 0x78, 0x3e, 0x6a, 0xb0, 0xb5, 0x03,
	    0xea, 0xa8, 0x6e, 0x31, 0x0a, 0x5d, 0xb7, 0x38 };

	u_char key3[16];
	u_char data3[50];
	u_char dig3[16] = {
	    0x56, 0xbe, 0x34, 0x52, 0x1d, 0x14, 0x4c, 0x88,
	    0xdb, 0xb8, 0xc7, 0x33, 0xf0, 0xe8, 0xb3, 0xf6 };
	स_रखो(key3, 0xaa, माप(key3));
	स_रखो(data3, 0xdd, माप(data3));

	hmac_test(key1, माप(key1), data1, म_माप(data1), dig1, माप(dig1));
	hmac_test(key2, म_माप(key2), data2, म_माप(data2), dig2, माप(dig2));
	hmac_test(key3, माप(key3), data3, माप(data3), dig3, माप(dig3));

	वापस 0;
}

#पूर्ण_अगर
