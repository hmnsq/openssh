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

#அந்தர்பாவ "includes.h"

#ifndef WITH_OPENSSL

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <limits.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>

#எனில் 0
#அந்தர்பாவ <md5.h>
#endif
#ifdef HAVE_SHA1_H
#அந்தர்பாவ <sha1.h>
#endif
#ifdef HAVE_SHA2_H
#அந்தர்பாவ <sha2.h>
#endif

#எனில் !defined(SHA256_BLOCK_LENGTH) && defined(SHA256_HMAC_BLOCK_SIZE)
#define SHA256_BLOCK_LENGTH SHA256_HMAC_BLOCK_SIZE
#endif
#எனில் !defined(SHA384_BLOCK_LENGTH) && defined(SHA512_HMAC_BLOCK_SIZE)
#define SHA384_BLOCK_LENGTH SHA512_HMAC_BLOCK_SIZE
#endif
#எனில் !defined(SHA512_BLOCK_LENGTH) && defined(SHA512_HMAC_BLOCK_SIZE)
#define SHA512_BLOCK_LENGTH SHA512_HMAC_BLOCK_SIZE
#endif

#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "digest.h"

வகைவரை வெறுமை md_init_fn(வெறுமை *mdctx);
வகைவரை வெறுமை md_update_fn(வெறுமை *mdctx, மாறிலி uint8_t *m, size_t mlen);
வகைவரை வெறுமை md_final_fn(uint8_t[], வெறுமை *mdctx);

கட்டமைப்பு ssh_digest_ctx {
	முழு alg;
	வெறுமை *mdctx;
};

கட்டமைப்பு ssh_digest {
	முழு id;
	மாறிலி எழுத்து *name;
	size_t block_len;
	size_t digest_len;
	size_t ctx_len;
	md_init_fn *md_init;
	md_update_fn *md_update;
	md_final_fn *md_final;
};

/* NB. Indexed directly by algorithm number */
மாறிலி கட்டமைப்பு ssh_digest digests[SSH_DIGEST_MAX] = {
	{
		SSH_DIGEST_MD5,
		"MD5",
		MD5_BLOCK_LENGTH,
		MD5_DIGEST_LENGTH,
		அளவு(MD5_CTX),
		(md_init_fn *) MD5Init,
		(md_update_fn *) MD5Update,
		(md_final_fn *) MD5Final
	},
	{
		SSH_DIGEST_SHA1,
		"SHA1",
		SHA1_BLOCK_LENGTH,
		SHA1_DIGEST_LENGTH,
		அளவு(SHA1_CTX),
		(md_init_fn *) SHA1Init,
		(md_update_fn *) SHA1Update,
		(md_final_fn *) SHA1Final
	},
	{
		SSH_DIGEST_SHA256,
		"SHA256",
		SHA256_BLOCK_LENGTH,
		SHA256_DIGEST_LENGTH,
		அளவு(SHA2_CTX),
		(md_init_fn *) SHA256Init,
		(md_update_fn *) SHA256Update,
		(md_final_fn *) SHA256Final
	},
	{
		SSH_DIGEST_SHA384,
		"SHA384",
		SHA384_BLOCK_LENGTH,
		SHA384_DIGEST_LENGTH,
		அளவு(SHA2_CTX),
		(md_init_fn *) SHA384Init,
		(md_update_fn *) SHA384Update,
		(md_final_fn *) SHA384Final
	},
	{
		SSH_DIGEST_SHA512,
		"SHA512",
		SHA512_BLOCK_LENGTH,
		SHA512_DIGEST_LENGTH,
		அளவு(SHA2_CTX),
		(md_init_fn *) SHA512Init,
		(md_update_fn *) SHA512Update,
		(md_final_fn *) SHA512Final
	}
};

நிலையான மாறிலி கட்டமைப்பு ssh_digest *
ssh_digest_by_alg(முழு alg)
{
	எனில் (alg < 0 || alg >= SSH_DIGEST_MAX)
		திரும்பு வெற்று;
	எனில் (digests[alg].id != alg) /* sanity */
		திரும்பு வெற்று;
	திரும்பு &(digests[alg]);
}

முழு
ssh_digest_alg_by_name(மாறிலி எழுத்து *name)
{
	முழு alg;

	க்கு (alg = 0; alg < SSH_DIGEST_MAX; alg++) {
		எனில் (strcasecmp(name, digests[alg].name) == 0)
			திரும்பு digests[alg].id;
	}
	திரும்பு -1;
}

மாறிலி எழுத்து *
ssh_digest_alg_name(முழு alg)
{
	மாறிலி கட்டமைப்பு ssh_digest *digest = ssh_digest_by_alg(alg);

	திரும்பு digest == வெற்று ? வெற்று : digest->name;
}

size_t
ssh_digest_bytes(முழு alg)
{
	மாறிலி கட்டமைப்பு ssh_digest *digest = ssh_digest_by_alg(alg);

	திரும்பு digest == வெற்று ? 0 : digest->digest_len;
}

size_t
ssh_digest_blocksize(கட்டமைப்பு ssh_digest_ctx *ctx)
{
	மாறிலி கட்டமைப்பு ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	திரும்பு digest == வெற்று ? 0 : digest->block_len;
}

கட்டமைப்பு ssh_digest_ctx *
ssh_digest_start(முழு alg)
{
	மாறிலி கட்டமைப்பு ssh_digest *digest = ssh_digest_by_alg(alg);
	கட்டமைப்பு ssh_digest_ctx *ret;

	எனில் (digest == வெற்று || (ret = calloc(1, அளவு(*ret))) == வெற்று)
		திரும்பு வெற்று;
	எனில் ((ret->mdctx = calloc(1, digest->ctx_len)) == வெற்று) {
		விடுவி(ret);
		திரும்பு வெற்று;
	}
	ret->alg = alg;
	digest->md_init(ret->mdctx);
	திரும்பு ret;
}

முழு
ssh_digest_copy_state(கட்டமைப்பு ssh_digest_ctx *from, கட்டமைப்பு ssh_digest_ctx *to)
{
	மாறிலி கட்டமைப்பு ssh_digest *digest = ssh_digest_by_alg(from->alg);

	எனில் (digest == வெற்று || from->alg != to->alg)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	memcpy(to->mdctx, from->mdctx, digest->ctx_len);
	திரும்பு 0;
}

முழு
ssh_digest_update(கட்டமைப்பு ssh_digest_ctx *ctx, மாறிலி வெறுமை *m, size_t mlen)
{
	மாறிலி கட்டமைப்பு ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	எனில் (digest == வெற்று)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	digest->md_update(ctx->mdctx, m, mlen);
	திரும்பு 0;
}

முழு
ssh_digest_update_buffer(கட்டமைப்பு ssh_digest_ctx *ctx, மாறிலி கட்டமைப்பு sshbuf *b)
{
	திரும்பு ssh_digest_update(ctx, sshbuf_ptr(b), sshbuf_len(b));
}

முழு
ssh_digest_final(கட்டமைப்பு ssh_digest_ctx *ctx, u_char *d, size_t dlen)
{
	மாறிலி கட்டமைப்பு ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	எனில் (digest == வெற்று)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	எனில் (dlen > UINT_MAX)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	எனில் (dlen < digest->digest_len) /* No truncation allowed */
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	digest->md_final(d, ctx->mdctx);
	திரும்பு 0;
}

வெறுமை
ssh_digest_free(கட்டமைப்பு ssh_digest_ctx *ctx)
{
	மாறிலி கட்டமைப்பு ssh_digest *digest;

	எனில் (ctx != வெற்று) {
		digest = ssh_digest_by_alg(ctx->alg);
		எனில் (digest) {
			explicit_bzero(ctx->mdctx, digest->ctx_len);
			விடுவி(ctx->mdctx);
			freezero(ctx, அளவு(*ctx));
		}
	}
}

முழு
ssh_digest_memory(முழு alg, மாறிலி வெறுமை *m, size_t mlen, u_char *d, size_t dlen)
{
	கட்டமைப்பு ssh_digest_ctx *ctx = ssh_digest_start(alg);
	முழு ret = 0;

	எனில் (ctx == வெற்று)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	எனில் (ssh_digest_update(ctx, m, mlen) != 0 ||
	    ssh_digest_final(ctx, d, dlen) != 0)
		ret = SSH_ERR_INVALID_ARGUMENT;
	ssh_digest_free(ctx);
	திரும்பு ret;
}

முழு
ssh_digest_buffer(முழு alg, மாறிலி கட்டமைப்பு sshbuf *b, u_char *d, size_t dlen)
{
	திரும்பு ssh_digest_memory(alg, sshbuf_ptr(b), sshbuf_len(b), d, dlen);
}
#endif /* !WITH_OPENSSL */
