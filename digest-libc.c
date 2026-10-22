/* $OpenBSD: digest-libc.c,v 1.10 2026/03/03 09:57:25 dtucker Exp $ */
/*
 * Copyright (c) 2013 Damien Miller <djm@mindrot.org>
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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ifndef WITH_OPENSSL

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <limits.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>

#ଯଦି 0
#ଅନ୍ତର୍ଭାଵ <md5.h>
#endif
#ifdef HAVE_SHA1_H
#ଅନ୍ତର୍ଭାଵ <sha1.h>
#endif
#ifdef HAVE_SHA2_H
#ଅନ୍ତର୍ଭାଵ <sha2.h>
#endif

#ଯଦି !defined(SHA256_BLOCK_LENGTH) && defined(SHA256_HMAC_BLOCK_SIZE)
#define SHA256_BLOCK_LENGTH SHA256_HMAC_BLOCK_SIZE
#endif
#ଯଦି !defined(SHA384_BLOCK_LENGTH) && defined(SHA512_HMAC_BLOCK_SIZE)
#define SHA384_BLOCK_LENGTH SHA512_HMAC_BLOCK_SIZE
#endif
#ଯଦି !defined(SHA512_BLOCK_LENGTH) && defined(SHA512_HMAC_BLOCK_SIZE)
#define SHA512_BLOCK_LENGTH SHA512_HMAC_BLOCK_SIZE
#endif

#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "digest.h"

ପ୍ରକାରବ୍ୟାଖ୍ୟା ଶୂନ୍ୟ md_init_fn(ଶୂନ୍ୟ *mdctx);
ପ୍ରକାରବ୍ୟାଖ୍ୟା ଶୂନ୍ୟ md_update_fn(ଶୂନ୍ୟ *mdctx, ଅଚଳ uint8_t *m, size_t mlen);
ପ୍ରକାରବ୍ୟାଖ୍ୟା ଶୂନ୍ୟ md_final_fn(uint8_t[], ଶୂନ୍ୟ *mdctx);

ସଂରଚନା ssh_digest_ctx {
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା alg;
	ଶୂନ୍ୟ *mdctx;
};

ସଂରଚନା ssh_digest {
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା id;
	ଅଚଳ ଅକ୍ଷର *name;
	size_t block_len;
	size_t digest_len;
	size_t ctx_len;
	md_init_fn *md_init;
	md_update_fn *md_update;
	md_final_fn *md_final;
};

/* NB. Indexed directly by algorithm number */
ଅଚଳ ସଂରଚନା ssh_digest digests[SSH_DIGEST_MAX] = {
	{
		SSH_DIGEST_MD5,
		"MD5",
		MD5_BLOCK_LENGTH,
		MD5_DIGEST_LENGTH,
		ଆକାର(MD5_CTX),
		(md_init_fn *) MD5Init,
		(md_update_fn *) MD5Update,
		(md_final_fn *) MD5Final
	},
	{
		SSH_DIGEST_SHA1,
		"SHA1",
		SHA1_BLOCK_LENGTH,
		SHA1_DIGEST_LENGTH,
		ଆକାର(SHA1_CTX),
		(md_init_fn *) SHA1Init,
		(md_update_fn *) SHA1Update,
		(md_final_fn *) SHA1Final
	},
	{
		SSH_DIGEST_SHA256,
		"SHA256",
		SHA256_BLOCK_LENGTH,
		SHA256_DIGEST_LENGTH,
		ଆକାର(SHA2_CTX),
		(md_init_fn *) SHA256Init,
		(md_update_fn *) SHA256Update,
		(md_final_fn *) SHA256Final
	},
	{
		SSH_DIGEST_SHA384,
		"SHA384",
		SHA384_BLOCK_LENGTH,
		SHA384_DIGEST_LENGTH,
		ଆକାର(SHA2_CTX),
		(md_init_fn *) SHA384Init,
		(md_update_fn *) SHA384Update,
		(md_final_fn *) SHA384Final
	},
	{
		SSH_DIGEST_SHA512,
		"SHA512",
		SHA512_BLOCK_LENGTH,
		SHA512_DIGEST_LENGTH,
		ଆକାର(SHA2_CTX),
		(md_init_fn *) SHA512Init,
		(md_update_fn *) SHA512Update,
		(md_final_fn *) SHA512Final
	}
};

ସ୍ଥିର ଅଚଳ ସଂରଚନା ssh_digest *
ssh_digest_by_alg(ପୂର୍ଣ୍ଣସଂଖ୍ୟା alg)
{
	ଯଦି (alg < 0 || alg >= SSH_DIGEST_MAX)
		ଫେରନ୍ତୁ ଖାଲି;
	ଯଦି (digests[alg].id != alg) /* sanity */
		ଫେରନ୍ତୁ ଖାଲି;
	ଫେରନ୍ତୁ &(digests[alg]);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_digest_alg_by_name(ଅଚଳ ଅକ୍ଷର *name)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା alg;

	ପାଇଁ (alg = 0; alg < SSH_DIGEST_MAX; alg++) {
		ଯଦି (strcasecmp(name, digests[alg].name) == 0)
			ଫେରନ୍ତୁ digests[alg].id;
	}
	ଫେରନ୍ତୁ -1;
}

ଅଚଳ ଅକ୍ଷର *
ssh_digest_alg_name(ପୂର୍ଣ୍ଣସଂଖ୍ୟା alg)
{
	ଅଚଳ ସଂରଚନା ssh_digest *digest = ssh_digest_by_alg(alg);

	ଫେରନ୍ତୁ digest == ଖାଲି ? ଖାଲି : digest->name;
}

size_t
ssh_digest_bytes(ପୂର୍ଣ୍ଣସଂଖ୍ୟା alg)
{
	ଅଚଳ ସଂରଚନା ssh_digest *digest = ssh_digest_by_alg(alg);

	ଫେରନ୍ତୁ digest == ଖାଲି ? 0 : digest->digest_len;
}

size_t
ssh_digest_blocksize(ସଂରଚନା ssh_digest_ctx *ctx)
{
	ଅଚଳ ସଂରଚନା ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	ଫେରନ୍ତୁ digest == ଖାଲି ? 0 : digest->block_len;
}

ସଂରଚନା ssh_digest_ctx *
ssh_digest_start(ପୂର୍ଣ୍ଣସଂଖ୍ୟା alg)
{
	ଅଚଳ ସଂରଚନା ssh_digest *digest = ssh_digest_by_alg(alg);
	ସଂରଚନା ssh_digest_ctx *ret;

	ଯଦି (digest == ଖାଲି || (ret = calloc(1, ଆକାର(*ret))) == ଖାଲି)
		ଫେରନ୍ତୁ ଖାଲି;
	ଯଦି ((ret->mdctx = calloc(1, digest->ctx_len)) == ଖାଲି) {
		ମୁକ୍ତ(ret);
		ଫେରନ୍ତୁ ଖାଲି;
	}
	ret->alg = alg;
	digest->md_init(ret->mdctx);
	ଫେରନ୍ତୁ ret;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_digest_copy_state(ସଂରଚନା ssh_digest_ctx *from, ସଂରଚନା ssh_digest_ctx *to)
{
	ଅଚଳ ସଂରଚନା ssh_digest *digest = ssh_digest_by_alg(from->alg);

	ଯଦି (digest == ଖାଲି || from->alg != to->alg)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	memcpy(to->mdctx, from->mdctx, digest->ctx_len);
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_digest_update(ସଂରଚନା ssh_digest_ctx *ctx, ଅଚଳ ଶୂନ୍ୟ *m, size_t mlen)
{
	ଅଚଳ ସଂରଚନା ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	ଯଦି (digest == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	digest->md_update(ctx->mdctx, m, mlen);
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_digest_update_buffer(ସଂରଚନା ssh_digest_ctx *ctx, ଅଚଳ ସଂରଚନା sshbuf *b)
{
	ଫେରନ୍ତୁ ssh_digest_update(ctx, sshbuf_ptr(b), sshbuf_len(b));
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_digest_final(ସଂରଚନା ssh_digest_ctx *ctx, u_char *d, size_t dlen)
{
	ଅଚଳ ସଂରଚନା ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	ଯଦି (digest == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	ଯଦି (dlen > UINT_MAX)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	ଯଦି (dlen < digest->digest_len) /* No truncation allowed */
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	digest->md_final(d, ctx->mdctx);
	ଫେରନ୍ତୁ 0;
}

ଶୂନ୍ୟ
ssh_digest_free(ସଂରଚନା ssh_digest_ctx *ctx)
{
	ଅଚଳ ସଂରଚନା ssh_digest *digest;

	ଯଦି (ctx != ଖାଲି) {
		digest = ssh_digest_by_alg(ctx->alg);
		ଯଦି (digest) {
			explicit_bzero(ctx->mdctx, digest->ctx_len);
			ମୁକ୍ତ(ctx->mdctx);
			freezero(ctx, ଆକାର(*ctx));
		}
	}
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_digest_memory(ପୂର୍ଣ୍ଣସଂଖ୍ୟା alg, ଅଚଳ ଶୂନ୍ୟ *m, size_t mlen, u_char *d, size_t dlen)
{
	ସଂରଚନା ssh_digest_ctx *ctx = ssh_digest_start(alg);
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = 0;

	ଯଦି (ctx == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	ଯଦି (ssh_digest_update(ctx, m, mlen) != 0 ||
	    ssh_digest_final(ctx, d, dlen) != 0)
		ret = SSH_ERR_INVALID_ARGUMENT;
	ssh_digest_free(ctx);
	ଫେରନ୍ତୁ ret;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_digest_buffer(ପୂର୍ଣ୍ଣସଂଖ୍ୟା alg, ଅଚଳ ସଂରଚନା sshbuf *b, u_char *d, size_t dlen)
{
	ଫେରନ୍ତୁ ssh_digest_memory(alg, sshbuf_ptr(b), sshbuf_len(b), d, dlen);
}
#endif /* !WITH_OPENSSL */
