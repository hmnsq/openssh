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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ifndef WITH_OPENSSL

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಯದಿ 0
#ಅನ್ತರ್ಭಾವ <md5.h>
#endif
#ifdef HAVE_SHA1_H
#ಅನ್ತರ್ಭಾವ <sha1.h>
#endif
#ifdef HAVE_SHA2_H
#ಅನ್ತರ್ಭಾವ <sha2.h>
#endif

#ಯದಿ !defined(SHA256_BLOCK_LENGTH) && defined(SHA256_HMAC_BLOCK_SIZE)
#define SHA256_BLOCK_LENGTH SHA256_HMAC_BLOCK_SIZE
#endif
#ಯದಿ !defined(SHA384_BLOCK_LENGTH) && defined(SHA512_HMAC_BLOCK_SIZE)
#define SHA384_BLOCK_LENGTH SHA512_HMAC_BLOCK_SIZE
#endif
#ಯದಿ !defined(SHA512_BLOCK_LENGTH) && defined(SHA512_HMAC_BLOCK_SIZE)
#define SHA512_BLOCK_LENGTH SHA512_HMAC_BLOCK_SIZE
#endif

#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "digest.h"

ಪ್ರಕಾರನಿರ್ದೇಶ ಶೂನ್ಯ md_init_fn(ಶೂನ್ಯ *mdctx);
ಪ್ರಕಾರನಿರ್ದೇಶ ಶೂನ್ಯ md_update_fn(ಶೂನ್ಯ *mdctx, ಧ್ರುವ uint8_t *m, size_t mlen);
ಪ್ರಕಾರನಿರ್ದೇಶ ಶೂನ್ಯ md_final_fn(uint8_t[], ಶೂನ್ಯ *mdctx);

ಸಂರಚನಾ ssh_digest_ctx {
	ಪೂರ್ಣಾಙ್ಕ alg;
	ಶೂನ್ಯ *mdctx;
};

ಸಂರಚನಾ ssh_digest {
	ಪೂರ್ಣಾಙ್ಕ id;
	ಧ್ರುವ ವರ್ಣ *name;
	size_t block_len;
	size_t digest_len;
	size_t ctx_len;
	md_init_fn *md_init;
	md_update_fn *md_update;
	md_final_fn *md_final;
};

/* NB. Indexed directly by algorithm number */
ಧ್ರುವ ಸಂರಚನಾ ssh_digest digests[SSH_DIGEST_MAX] = {
	{
		SSH_DIGEST_MD5,
		"MD5",
		MD5_BLOCK_LENGTH,
		MD5_DIGEST_LENGTH,
		ಪರಿಮಾಣ(MD5_CTX),
		(md_init_fn *) MD5Init,
		(md_update_fn *) MD5Update,
		(md_final_fn *) MD5Final
	},
	{
		SSH_DIGEST_SHA1,
		"SHA1",
		SHA1_BLOCK_LENGTH,
		SHA1_DIGEST_LENGTH,
		ಪರಿಮಾಣ(SHA1_CTX),
		(md_init_fn *) SHA1Init,
		(md_update_fn *) SHA1Update,
		(md_final_fn *) SHA1Final
	},
	{
		SSH_DIGEST_SHA256,
		"SHA256",
		SHA256_BLOCK_LENGTH,
		SHA256_DIGEST_LENGTH,
		ಪರಿಮಾಣ(SHA2_CTX),
		(md_init_fn *) SHA256Init,
		(md_update_fn *) SHA256Update,
		(md_final_fn *) SHA256Final
	},
	{
		SSH_DIGEST_SHA384,
		"SHA384",
		SHA384_BLOCK_LENGTH,
		SHA384_DIGEST_LENGTH,
		ಪರಿಮಾಣ(SHA2_CTX),
		(md_init_fn *) SHA384Init,
		(md_update_fn *) SHA384Update,
		(md_final_fn *) SHA384Final
	},
	{
		SSH_DIGEST_SHA512,
		"SHA512",
		SHA512_BLOCK_LENGTH,
		SHA512_DIGEST_LENGTH,
		ಪರಿಮಾಣ(SHA2_CTX),
		(md_init_fn *) SHA512Init,
		(md_update_fn *) SHA512Update,
		(md_final_fn *) SHA512Final
	}
};

ಸ್ಥಿರ ಧ್ರುವ ಸಂರಚನಾ ssh_digest *
ssh_digest_by_alg(ಪೂರ್ಣಾಙ್ಕ alg)
{
	ಯದಿ (alg < 0 || alg >= SSH_DIGEST_MAX)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	ಯದಿ (digests[alg].id != alg) /* sanity */
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	ಪ್ರತ್ಯಾಗಮ &(digests[alg]);
}

ಪೂರ್ಣಾಙ್ಕ
ssh_digest_alg_by_name(ಧ್ರುವ ವರ್ಣ *name)
{
	ಪೂರ್ಣಾಙ್ಕ alg;

	ಪ್ರತಿ (alg = 0; alg < SSH_DIGEST_MAX; alg++) {
		ಯದಿ (strcasecmp(name, digests[alg].name) == 0)
			ಪ್ರತ್ಯಾಗಮ digests[alg].id;
	}
	ಪ್ರತ್ಯಾಗಮ -1;
}

ಧ್ರುವ ವರ್ಣ *
ssh_digest_alg_name(ಪೂರ್ಣಾಙ್ಕ alg)
{
	ಧ್ರುವ ಸಂರಚನಾ ssh_digest *digest = ssh_digest_by_alg(alg);

	ಪ್ರತ್ಯಾಗಮ digest == ರಿಕ್ತ ? ರಿಕ್ತ : digest->name;
}

size_t
ssh_digest_bytes(ಪೂರ್ಣಾಙ್ಕ alg)
{
	ಧ್ರುವ ಸಂರಚನಾ ssh_digest *digest = ssh_digest_by_alg(alg);

	ಪ್ರತ್ಯಾಗಮ digest == ರಿಕ್ತ ? 0 : digest->digest_len;
}

size_t
ssh_digest_blocksize(ಸಂರಚನಾ ssh_digest_ctx *ctx)
{
	ಧ್ರುವ ಸಂರಚನಾ ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	ಪ್ರತ್ಯಾಗಮ digest == ರಿಕ್ತ ? 0 : digest->block_len;
}

ಸಂರಚನಾ ssh_digest_ctx *
ssh_digest_start(ಪೂರ್ಣಾಙ್ಕ alg)
{
	ಧ್ರುವ ಸಂರಚನಾ ssh_digest *digest = ssh_digest_by_alg(alg);
	ಸಂರಚನಾ ssh_digest_ctx *ret;

	ಯದಿ (digest == ರಿಕ್ತ || (ret = calloc(1, ಪರಿಮಾಣ(*ret))) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	ಯದಿ ((ret->mdctx = calloc(1, digest->ctx_len)) == ರಿಕ್ತ) {
		ಮುಕ್ತ(ret);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	ret->alg = alg;
	digest->md_init(ret->mdctx);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಪೂರ್ಣಾಙ್ಕ
ssh_digest_copy_state(ಸಂರಚನಾ ssh_digest_ctx *from, ಸಂರಚನಾ ssh_digest_ctx *to)
{
	ಧ್ರುವ ಸಂರಚನಾ ssh_digest *digest = ssh_digest_by_alg(from->alg);

	ಯದಿ (digest == ರಿಕ್ತ || from->alg != to->alg)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	memcpy(to->mdctx, from->mdctx, digest->ctx_len);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
ssh_digest_update(ಸಂರಚನಾ ssh_digest_ctx *ctx, ಧ್ರುವ ಶೂನ್ಯ *m, size_t mlen)
{
	ಧ್ರುವ ಸಂರಚನಾ ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	ಯದಿ (digest == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	digest->md_update(ctx->mdctx, m, mlen);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
ssh_digest_update_buffer(ಸಂರಚನಾ ssh_digest_ctx *ctx, ಧ್ರುವ ಸಂರಚನಾ sshbuf *b)
{
	ಪ್ರತ್ಯಾಗಮ ssh_digest_update(ctx, sshbuf_ptr(b), sshbuf_len(b));
}

ಪೂರ್ಣಾಙ್ಕ
ssh_digest_final(ಸಂರಚನಾ ssh_digest_ctx *ctx, u_char *d, size_t dlen)
{
	ಧ್ರುವ ಸಂರಚನಾ ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	ಯದಿ (digest == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	ಯದಿ (dlen > UINT_MAX)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	ಯದಿ (dlen < digest->digest_len) /* No truncation allowed */
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	digest->md_final(d, ctx->mdctx);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಶೂನ್ಯ
ssh_digest_free(ಸಂರಚನಾ ssh_digest_ctx *ctx)
{
	ಧ್ರುವ ಸಂರಚನಾ ssh_digest *digest;

	ಯದಿ (ctx != ರಿಕ್ತ) {
		digest = ssh_digest_by_alg(ctx->alg);
		ಯದಿ (digest) {
			explicit_bzero(ctx->mdctx, digest->ctx_len);
			ಮುಕ್ತ(ctx->mdctx);
			freezero(ctx, ಪರಿಮಾಣ(*ctx));
		}
	}
}

ಪೂರ್ಣಾಙ್ಕ
ssh_digest_memory(ಪೂರ್ಣಾಙ್ಕ alg, ಧ್ರುವ ಶೂನ್ಯ *m, size_t mlen, u_char *d, size_t dlen)
{
	ಸಂರಚನಾ ssh_digest_ctx *ctx = ssh_digest_start(alg);
	ಪೂರ್ಣಾಙ್ಕ ret = 0;

	ಯದಿ (ctx == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	ಯದಿ (ssh_digest_update(ctx, m, mlen) != 0 ||
	    ssh_digest_final(ctx, d, dlen) != 0)
		ret = SSH_ERR_INVALID_ARGUMENT;
	ssh_digest_free(ctx);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಪೂರ್ಣಾಙ್ಕ
ssh_digest_buffer(ಪೂರ್ಣಾಙ್ಕ alg, ಧ್ರುವ ಸಂರಚನಾ sshbuf *b, u_char *d, size_t dlen)
{
	ಪ್ರತ್ಯಾಗಮ ssh_digest_memory(alg, sshbuf_ptr(b), sshbuf_len(b), d, dlen);
}
#endif /* !WITH_OPENSSL */
