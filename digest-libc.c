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

#যদি !defined(SHA256_BLOCK_দৈর্ঘ্য) && defined(SHA256_HMAC_BLOCK_আকার)
#define SHA256_BLOCK_দৈর্ঘ্য SHA256_HMAC_BLOCK_আকার
#endif
#যদি !defined(SHA384_BLOCK_দৈর্ঘ্য) && defined(SHA512_HMAC_BLOCK_আকার)
#define SHA384_BLOCK_দৈর্ঘ্য SHA512_HMAC_BLOCK_আকার
#endif
#যদি !defined(SHA512_BLOCK_দৈর্ঘ্য) && defined(SHA512_HMAC_BLOCK_আকার)
#define SHA512_BLOCK_দৈর্ঘ্য SHA512_HMAC_BLOCK_আকার
#endif

#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "digest.h"

প্রকারলেখ শূন্য md_init_fn(শূন্য *mdctx);
প্রকারলেখ শূন্য md_update_fn(শূন্য *mdctx, ধ্রুবক uint8_t *m, আকার_t mlen);
প্রকারলেখ শূন্য md_final_fn(uint8_t[], শূন্য *mdctx);

কাঠামো ssh_digest_ctx {
	পূর্ণসংখ্যা alg;
	শূন্য *mdctx;
};

কাঠামো ssh_digest {
	পূর্ণসংখ্যা id;
	ধ্রুবক অক্ষর *name;
	আকার_t block_len;
	আকার_t digest_len;
	আকার_t ctx_len;
	md_init_fn *md_init;
	md_update_fn *md_update;
	md_final_fn *md_final;
};

/* NB. Indexed directly by algorithm number */
ধ্রুবক কাঠামো ssh_digest digests[SSH_DIGEST_MAX] = {
	{
		SSH_DIGEST_MD5,
		"MD5",
		MD5_BLOCK_দৈর্ঘ্য,
		MD5_DIGEST_দৈর্ঘ্য,
		আকার(MD5_CTX),
		(md_init_fn *) MD5Init,
		(md_update_fn *) MD5Update,
		(md_final_fn *) MD5Final
	},
	{
		SSH_DIGEST_SHA1,
		"SHA1",
		SHA1_BLOCK_দৈর্ঘ্য,
		SHA1_DIGEST_দৈর্ঘ্য,
		আকার(SHA1_CTX),
		(md_init_fn *) SHA1Init,
		(md_update_fn *) SHA1Update,
		(md_final_fn *) SHA1Final
	},
	{
		SSH_DIGEST_SHA256,
		"SHA256",
		SHA256_BLOCK_দৈর্ঘ্য,
		SHA256_DIGEST_দৈর্ঘ্য,
		আকার(SHA2_CTX),
		(md_init_fn *) SHA256Init,
		(md_update_fn *) SHA256Update,
		(md_final_fn *) SHA256Final
	},
	{
		SSH_DIGEST_SHA384,
		"SHA384",
		SHA384_BLOCK_দৈর্ঘ্য,
		SHA384_DIGEST_দৈর্ঘ্য,
		আকার(SHA2_CTX),
		(md_init_fn *) SHA384Init,
		(md_update_fn *) SHA384Update,
		(md_final_fn *) SHA384Final
	},
	{
		SSH_DIGEST_SHA512,
		"SHA512",
		SHA512_BLOCK_দৈর্ঘ্য,
		SHA512_DIGEST_দৈর্ঘ্য,
		আকার(SHA2_CTX),
		(md_init_fn *) SHA512Init,
		(md_update_fn *) SHA512Update,
		(md_final_fn *) SHA512Final
	}
};

স্থির ধ্রুবক কাঠামো ssh_digest *
ssh_digest_by_alg(পূর্ণসংখ্যা alg)
{
	যদি (alg < 0 || alg >= SSH_DIGEST_MAX)
		ফেরত ফাঁকা;
	যদি (digests[alg].id != alg) /* sanity */
		ফেরত ফাঁকা;
	ফেরত &(digests[alg]);
}

পূর্ণসংখ্যা
ssh_digest_alg_by_name(ধ্রুবক অক্ষর *name)
{
	পূর্ণসংখ্যা alg;

	জন্য (alg = 0; alg < SSH_DIGEST_MAX; alg++) {
		যদি (strcasecmp(name, digests[alg].name) == 0)
			ফেরত digests[alg].id;
	}
	ফেরত -1;
}

ধ্রুবক অক্ষর *
ssh_digest_alg_name(পূর্ণসংখ্যা alg)
{
	ধ্রুবক কাঠামো ssh_digest *digest = ssh_digest_by_alg(alg);

	ফেরত digest == ফাঁকা ? ফাঁকা : digest->name;
}

আকার_t
ssh_digest_bytes(পূর্ণসংখ্যা alg)
{
	ধ্রুবক কাঠামো ssh_digest *digest = ssh_digest_by_alg(alg);

	ফেরত digest == ফাঁকা ? 0 : digest->digest_len;
}

আকার_t
ssh_digest_blocksize(কাঠামো ssh_digest_ctx *ctx)
{
	ধ্রুবক কাঠামো ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	ফেরত digest == ফাঁকা ? 0 : digest->block_len;
}

কাঠামো ssh_digest_ctx *
ssh_digest_start(পূর্ণসংখ্যা alg)
{
	ধ্রুবক কাঠামো ssh_digest *digest = ssh_digest_by_alg(alg);
	কাঠামো ssh_digest_ctx *ret;

	যদি (digest == ফাঁকা || (ret = calloc(1, আকার(*ret))) == ফাঁকা)
		ফেরত ফাঁকা;
	যদি ((ret->mdctx = calloc(1, digest->ctx_len)) == ফাঁকা) {
		মুক্ত(ret);
		ফেরত ফাঁকা;
	}
	ret->alg = alg;
	digest->md_init(ret->mdctx);
	ফেরত ret;
}

পূর্ণসংখ্যা
ssh_digest_copy_state(কাঠামো ssh_digest_ctx *from, কাঠামো ssh_digest_ctx *to)
{
	ধ্রুবক কাঠামো ssh_digest *digest = ssh_digest_by_alg(from->alg);

	যদি (digest == ফাঁকা || from->alg != to->alg)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	memcpy(to->mdctx, from->mdctx, digest->ctx_len);
	ফেরত 0;
}

পূর্ণসংখ্যা
ssh_digest_update(কাঠামো ssh_digest_ctx *ctx, ধ্রুবক শূন্য *m, আকার_t mlen)
{
	ধ্রুবক কাঠামো ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	যদি (digest == ফাঁকা)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	digest->md_update(ctx->mdctx, m, mlen);
	ফেরত 0;
}

পূর্ণসংখ্যা
ssh_digest_update_বাফার(কাঠামো ssh_digest_ctx *ctx, ধ্রুবক কাঠামো sshbuf *b)
{
	ফেরত ssh_digest_update(ctx, sshbuf_ptr(b), sshbuf_len(b));
}

পূর্ণসংখ্যা
ssh_digest_final(কাঠামো ssh_digest_ctx *ctx, u_char *d, আকার_t dlen)
{
	ধ্রুবক কাঠামো ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	যদি (digest == ফাঁকা)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	যদি (dlen > UINT_MAX)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	যদি (dlen < digest->digest_len) /* No truncation allowed */
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	digest->md_final(d, ctx->mdctx);
	ফেরত 0;
}

শূন্য
ssh_digest_free(কাঠামো ssh_digest_ctx *ctx)
{
	ধ্রুবক কাঠামো ssh_digest *digest;

	যদি (ctx != ফাঁকা) {
		digest = ssh_digest_by_alg(ctx->alg);
		যদি (digest) {
			explicit_bzero(ctx->mdctx, digest->ctx_len);
			মুক্ত(ctx->mdctx);
			freezero(ctx, আকার(*ctx));
		}
	}
}

পূর্ণসংখ্যা
ssh_digest_memory(পূর্ণসংখ্যা alg, ধ্রুবক শূন্য *m, আকার_t mlen, u_char *d, আকার_t dlen)
{
	কাঠামো ssh_digest_ctx *ctx = ssh_digest_start(alg);
	পূর্ণসংখ্যা ret = 0;

	যদি (ctx == ফাঁকা)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	যদি (ssh_digest_update(ctx, m, mlen) != 0 ||
	    ssh_digest_final(ctx, d, dlen) != 0)
		ret = SSH_ERR_INVALID_ARGUMENT;
	ssh_digest_free(ctx);
	ফেরত ret;
}

পূর্ণসংখ্যা
ssh_digest_বাফার(পূর্ণসংখ্যা alg, ধ্রুবক কাঠামো sshbuf *b, u_char *d, আকার_t dlen)
{
	ফেরত ssh_digest_memory(alg, sshbuf_ptr(b), sshbuf_len(b), d, dlen);
}
#endif /* !WITH_OPENSSL */
