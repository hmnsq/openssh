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

#ضمن "includes.h"

#ifndef WITH_OPENSSL

#ضمن <sys/types.h>
#ضمن <limits.h>
#ضمن <stdlib.h>
#ضمن <string.h>

#إذا 0
#ضمن <md5.h>
#endif
#ifdef HAVE_SHA1_H
#ضمن <sha1.h>
#endif
#ifdef HAVE_SHA2_H
#ضمن <sha2.h>
#endif

#إذا !defined(SHA256_BLOCK_LENGTH) && defined(SHA256_HMAC_BLOCK_SIZE)
#define SHA256_BLOCK_LENGTH SHA256_HMAC_BLOCK_SIZE
#endif
#إذا !defined(SHA384_BLOCK_LENGTH) && defined(SHA512_HMAC_BLOCK_SIZE)
#define SHA384_BLOCK_LENGTH SHA512_HMAC_BLOCK_SIZE
#endif
#إذا !defined(SHA512_BLOCK_LENGTH) && defined(SHA512_HMAC_BLOCK_SIZE)
#define SHA512_BLOCK_LENGTH SHA512_HMAC_BLOCK_SIZE
#endif

#ضمن "ssherr.h"
#ضمن "sshbuf.h"
#ضمن "digest.h"

تعريفنوع فراغ md_init_fn(فراغ *mdctx);
تعريفنوع فراغ md_update_fn(فراغ *mdctx, ثابت uint8_t *m, size_t mlen);
تعريفنوع فراغ md_final_fn(uint8_t[], فراغ *mdctx);

بنية ssh_digest_ctx {
	صحيح alg;
	فراغ *mdctx;
};

بنية ssh_digest {
	صحيح id;
	ثابت حرف *name;
	size_t block_len;
	size_t digest_len;
	size_t ctx_len;
	md_init_fn *md_init;
	md_update_fn *md_update;
	md_final_fn *md_final;
};

/* NB. Indexed directly by algorithm number */
ثابت بنية ssh_digest digests[SSH_DIGEST_MAX] = {
	{
		SSH_DIGEST_MD5,
		"MD5",
		MD5_BLOCK_LENGTH,
		MD5_DIGEST_LENGTH,
		حجم(MD5_CTX),
		(md_init_fn *) MD5Init,
		(md_update_fn *) MD5Update,
		(md_final_fn *) MD5Final
	},
	{
		SSH_DIGEST_SHA1,
		"SHA1",
		SHA1_BLOCK_LENGTH,
		SHA1_DIGEST_LENGTH,
		حجم(SHA1_CTX),
		(md_init_fn *) SHA1Init,
		(md_update_fn *) SHA1Update,
		(md_final_fn *) SHA1Final
	},
	{
		SSH_DIGEST_SHA256,
		"SHA256",
		SHA256_BLOCK_LENGTH,
		SHA256_DIGEST_LENGTH,
		حجم(SHA2_CTX),
		(md_init_fn *) SHA256Init,
		(md_update_fn *) SHA256Update,
		(md_final_fn *) SHA256Final
	},
	{
		SSH_DIGEST_SHA384,
		"SHA384",
		SHA384_BLOCK_LENGTH,
		SHA384_DIGEST_LENGTH,
		حجم(SHA2_CTX),
		(md_init_fn *) SHA384Init,
		(md_update_fn *) SHA384Update,
		(md_final_fn *) SHA384Final
	},
	{
		SSH_DIGEST_SHA512,
		"SHA512",
		SHA512_BLOCK_LENGTH,
		SHA512_DIGEST_LENGTH,
		حجم(SHA2_CTX),
		(md_init_fn *) SHA512Init,
		(md_update_fn *) SHA512Update,
		(md_final_fn *) SHA512Final
	}
};

ساكن ثابت بنية ssh_digest *
ssh_digest_by_alg(صحيح alg)
{
	إذا (alg < 0 || alg >= SSH_DIGEST_MAX)
		إرجاع عدم;
	إذا (digests[alg].id != alg) /* sanity */
		إرجاع عدم;
	إرجاع &(digests[alg]);
}

صحيح
ssh_digest_alg_by_name(ثابت حرف *name)
{
	صحيح alg;

	لكل (alg = 0; alg < SSH_DIGEST_MAX; alg++) {
		إذا (strcasecmp(name, digests[alg].name) == 0)
			إرجاع digests[alg].id;
	}
	إرجاع -1;
}

ثابت حرف *
ssh_digest_alg_name(صحيح alg)
{
	ثابت بنية ssh_digest *digest = ssh_digest_by_alg(alg);

	إرجاع digest == عدم ? عدم : digest->name;
}

size_t
ssh_digest_bytes(صحيح alg)
{
	ثابت بنية ssh_digest *digest = ssh_digest_by_alg(alg);

	إرجاع digest == عدم ? 0 : digest->digest_len;
}

size_t
ssh_digest_blocksize(بنية ssh_digest_ctx *ctx)
{
	ثابت بنية ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	إرجاع digest == عدم ? 0 : digest->block_len;
}

بنية ssh_digest_ctx *
ssh_digest_start(صحيح alg)
{
	ثابت بنية ssh_digest *digest = ssh_digest_by_alg(alg);
	بنية ssh_digest_ctx *ret;

	إذا (digest == عدم || (ret = calloc(1, حجم(*ret))) == عدم)
		إرجاع عدم;
	إذا ((ret->mdctx = calloc(1, digest->ctx_len)) == عدم) {
		حرر(ret);
		إرجاع عدم;
	}
	ret->alg = alg;
	digest->md_init(ret->mdctx);
	إرجاع ret;
}

صحيح
ssh_digest_copy_state(بنية ssh_digest_ctx *from, بنية ssh_digest_ctx *to)
{
	ثابت بنية ssh_digest *digest = ssh_digest_by_alg(from->alg);

	إذا (digest == عدم || from->alg != to->alg)
		إرجاع SSH_ERR_INVALID_ARGUMENT;
	memcpy(to->mdctx, from->mdctx, digest->ctx_len);
	إرجاع 0;
}

صحيح
ssh_digest_update(بنية ssh_digest_ctx *ctx, ثابت فراغ *m, size_t mlen)
{
	ثابت بنية ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	إذا (digest == عدم)
		إرجاع SSH_ERR_INVALID_ARGUMENT;
	digest->md_update(ctx->mdctx, m, mlen);
	إرجاع 0;
}

صحيح
ssh_digest_update_buffer(بنية ssh_digest_ctx *ctx, ثابت بنية sshbuf *b)
{
	إرجاع ssh_digest_update(ctx, sshbuf_ptr(b), sshbuf_len(b));
}

صحيح
ssh_digest_final(بنية ssh_digest_ctx *ctx, u_char *d, size_t dlen)
{
	ثابت بنية ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	إذا (digest == عدم)
		إرجاع SSH_ERR_INVALID_ARGUMENT;
	إذا (dlen > UINT_MAX)
		إرجاع SSH_ERR_INVALID_ARGUMENT;
	إذا (dlen < digest->digest_len) /* No truncation allowed */
		إرجاع SSH_ERR_INVALID_ARGUMENT;
	digest->md_final(d, ctx->mdctx);
	إرجاع 0;
}

فراغ
ssh_digest_free(بنية ssh_digest_ctx *ctx)
{
	ثابت بنية ssh_digest *digest;

	إذا (ctx != عدم) {
		digest = ssh_digest_by_alg(ctx->alg);
		إذا (digest) {
			explicit_bzero(ctx->mdctx, digest->ctx_len);
			حرر(ctx->mdctx);
			freezero(ctx, حجم(*ctx));
		}
	}
}

صحيح
ssh_digest_memory(صحيح alg, ثابت فراغ *m, size_t mlen, u_char *d, size_t dlen)
{
	بنية ssh_digest_ctx *ctx = ssh_digest_start(alg);
	صحيح ret = 0;

	إذا (ctx == عدم)
		إرجاع SSH_ERR_INVALID_ARGUMENT;
	إذا (ssh_digest_update(ctx, m, mlen) != 0 ||
	    ssh_digest_final(ctx, d, dlen) != 0)
		ret = SSH_ERR_INVALID_ARGUMENT;
	ssh_digest_free(ctx);
	إرجاع ret;
}

صحيح
ssh_digest_buffer(صحيح alg, ثابت بنية sshbuf *b, u_char *d, size_t dlen)
{
	إرجاع ssh_digest_memory(alg, sshbuf_ptr(b), sshbuf_len(b), d, dlen);
}
#endif /* !WITH_OPENSSL */
