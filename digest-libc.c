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

#অন্তর্ভাব "includes.h"

#ifndef WITH_OPENSSL

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <limits.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>

#যদি 0
#অন্তর্ভাব <md5.h>
#endif
#ifdef HAVE_SHA1_H
#অন্তর্ভাব <sha1.h>
#endif
#ifdef HAVE_SHA2_H
#অন্তর্ভাব <sha2.h>
#endif

#যদি !defined(SHA256_BLOCK_LENGTH) && defined(SHA256_HMAC_BLOCK_SIZE)
#define SHA256_BLOCK_LENGTH SHA256_HMAC_BLOCK_SIZE
#endif
#যদি !defined(SHA384_BLOCK_LENGTH) && defined(SHA512_HMAC_BLOCK_SIZE)
#define SHA384_BLOCK_LENGTH SHA512_HMAC_BLOCK_SIZE
#endif
#যদি !defined(SHA512_BLOCK_LENGTH) && defined(SHA512_HMAC_BLOCK_SIZE)
#define SHA512_BLOCK_LENGTH SHA512_HMAC_BLOCK_SIZE
#endif

#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "digest.h"

প্রকারনির্দেশ শূন্য md_init_fn(শূন্য *mdctx);
প্রকারনির্দেশ শূন্য md_update_fn(শূন্য *mdctx, ধ্রুব uint8_t *m, size_t mlen);
প্রকারনির্দেশ শূন্য md_final_fn(uint8_t[], শূন্য *mdctx);

সংরচনা ssh_digest_ctx {
	পূর্ণাঙ্ক alg;
	শূন্য *mdctx;
};

সংরচনা ssh_digest {
	পূর্ণাঙ্ক id;
	ধ্রুব বর্ণ *name;
	size_t block_len;
	size_t digest_len;
	size_t ctx_len;
	md_init_fn *md_init;
	md_update_fn *md_update;
	md_final_fn *md_final;
};

/* NB. Indexed directly by algorithm number */
ধ্রুব সংরচনা ssh_digest digests[SSH_DIGEST_MAX] = {
	{
		SSH_DIGEST_MD5,
		"MD5",
		MD5_BLOCK_LENGTH,
		MD5_DIGEST_LENGTH,
		পরিমাণ(MD5_CTX),
		(md_init_fn *) MD5Init,
		(md_update_fn *) MD5Update,
		(md_final_fn *) MD5Final
	},
	{
		SSH_DIGEST_SHA1,
		"SHA1",
		SHA1_BLOCK_LENGTH,
		SHA1_DIGEST_LENGTH,
		পরিমাণ(SHA1_CTX),
		(md_init_fn *) SHA1Init,
		(md_update_fn *) SHA1Update,
		(md_final_fn *) SHA1Final
	},
	{
		SSH_DIGEST_SHA256,
		"SHA256",
		SHA256_BLOCK_LENGTH,
		SHA256_DIGEST_LENGTH,
		পরিমাণ(SHA2_CTX),
		(md_init_fn *) SHA256Init,
		(md_update_fn *) SHA256Update,
		(md_final_fn *) SHA256Final
	},
	{
		SSH_DIGEST_SHA384,
		"SHA384",
		SHA384_BLOCK_LENGTH,
		SHA384_DIGEST_LENGTH,
		পরিমাণ(SHA2_CTX),
		(md_init_fn *) SHA384Init,
		(md_update_fn *) SHA384Update,
		(md_final_fn *) SHA384Final
	},
	{
		SSH_DIGEST_SHA512,
		"SHA512",
		SHA512_BLOCK_LENGTH,
		SHA512_DIGEST_LENGTH,
		পরিমাণ(SHA2_CTX),
		(md_init_fn *) SHA512Init,
		(md_update_fn *) SHA512Update,
		(md_final_fn *) SHA512Final
	}
};

স্থির ধ্রুব সংরচনা ssh_digest *
ssh_digest_by_alg(পূর্ণাঙ্ক alg)
{
	যদি (alg < 0 || alg >= SSH_DIGEST_MAX)
		প্রত্যাগম রিক্ত;
	যদি (digests[alg].id != alg) /* sanity */
		প্রত্যাগম রিক্ত;
	প্রত্যাগম &(digests[alg]);
}

পূর্ণাঙ্ক
ssh_digest_alg_by_name(ধ্রুব বর্ণ *name)
{
	পূর্ণাঙ্ক alg;

	প্রতি (alg = 0; alg < SSH_DIGEST_MAX; alg++) {
		যদি (strcasecmp(name, digests[alg].name) == 0)
			প্রত্যাগম digests[alg].id;
	}
	প্রত্যাগম -1;
}

ধ্রুব বর্ণ *
ssh_digest_alg_name(পূর্ণাঙ্ক alg)
{
	ধ্রুব সংরচনা ssh_digest *digest = ssh_digest_by_alg(alg);

	প্রত্যাগম digest == রিক্ত ? রিক্ত : digest->name;
}

size_t
ssh_digest_bytes(পূর্ণাঙ্ক alg)
{
	ধ্রুব সংরচনা ssh_digest *digest = ssh_digest_by_alg(alg);

	প্রত্যাগম digest == রিক্ত ? 0 : digest->digest_len;
}

size_t
ssh_digest_blocksize(সংরচনা ssh_digest_ctx *ctx)
{
	ধ্রুব সংরচনা ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	প্রত্যাগম digest == রিক্ত ? 0 : digest->block_len;
}

সংরচনা ssh_digest_ctx *
ssh_digest_start(পূর্ণাঙ্ক alg)
{
	ধ্রুব সংরচনা ssh_digest *digest = ssh_digest_by_alg(alg);
	সংরচনা ssh_digest_ctx *ret;

	যদি (digest == রিক্ত || (ret = calloc(1, পরিমাণ(*ret))) == রিক্ত)
		প্রত্যাগম রিক্ত;
	যদি ((ret->mdctx = calloc(1, digest->ctx_len)) == রিক্ত) {
		মুক্ত(ret);
		প্রত্যাগম রিক্ত;
	}
	ret->alg = alg;
	digest->md_init(ret->mdctx);
	প্রত্যাগম ret;
}

পূর্ণাঙ্ক
ssh_digest_copy_state(সংরচনা ssh_digest_ctx *from, সংরচনা ssh_digest_ctx *to)
{
	ধ্রুব সংরচনা ssh_digest *digest = ssh_digest_by_alg(from->alg);

	যদি (digest == রিক্ত || from->alg != to->alg)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;
	memcpy(to->mdctx, from->mdctx, digest->ctx_len);
	প্রত্যাগম 0;
}

পূর্ণাঙ্ক
ssh_digest_update(সংরচনা ssh_digest_ctx *ctx, ধ্রুব শূন্য *m, size_t mlen)
{
	ধ্রুব সংরচনা ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	যদি (digest == রিক্ত)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;
	digest->md_update(ctx->mdctx, m, mlen);
	প্রত্যাগম 0;
}

পূর্ণাঙ্ক
ssh_digest_update_buffer(সংরচনা ssh_digest_ctx *ctx, ধ্রুব সংরচনা sshbuf *b)
{
	প্রত্যাগম ssh_digest_update(ctx, sshbuf_ptr(b), sshbuf_len(b));
}

পূর্ণাঙ্ক
ssh_digest_final(সংরচনা ssh_digest_ctx *ctx, u_char *d, size_t dlen)
{
	ধ্রুব সংরচনা ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	যদি (digest == রিক্ত)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;
	যদি (dlen > UINT_MAX)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;
	যদি (dlen < digest->digest_len) /* No truncation allowed */
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;
	digest->md_final(d, ctx->mdctx);
	প্রত্যাগম 0;
}

শূন্য
ssh_digest_free(সংরচনা ssh_digest_ctx *ctx)
{
	ধ্রুব সংরচনা ssh_digest *digest;

	যদি (ctx != রিক্ত) {
		digest = ssh_digest_by_alg(ctx->alg);
		যদি (digest) {
			explicit_bzero(ctx->mdctx, digest->ctx_len);
			মুক্ত(ctx->mdctx);
			freezero(ctx, পরিমাণ(*ctx));
		}
	}
}

পূর্ণাঙ্ক
ssh_digest_memory(পূর্ণাঙ্ক alg, ধ্রুব শূন্য *m, size_t mlen, u_char *d, size_t dlen)
{
	সংরচনা ssh_digest_ctx *ctx = ssh_digest_start(alg);
	পূর্ণাঙ্ক ret = 0;

	যদি (ctx == রিক্ত)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;
	যদি (ssh_digest_update(ctx, m, mlen) != 0 ||
	    ssh_digest_final(ctx, d, dlen) != 0)
		ret = SSH_ERR_INVALID_ARGUMENT;
	ssh_digest_free(ctx);
	প্রত্যাগম ret;
}

পূর্ণাঙ্ক
ssh_digest_buffer(পূর্ণাঙ্ক alg, ধ্রুব সংরচনা sshbuf *b, u_char *d, size_t dlen)
{
	প্রত্যাগম ssh_digest_memory(alg, sshbuf_ptr(b), sshbuf_len(b), d, dlen);
}
#endif /* !WITH_OPENSSL */
