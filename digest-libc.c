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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਜੇ 0
#ਅਨ੍ਤਰ੍ਭਾਵ <md5.h>
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_SHA1_H
#ਅਨ੍ਤਰ੍ਭਾਵ <sha1.h>
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_SHA2_H
#ਅਨ੍ਤਰ੍ਭਾਵ <sha2.h>
#ਜੇ_ਅੰਤ

#ਜੇ !defined(SHA256_ਖੰਡ_ਲੰਮਾਈ) && defined(SHA256_HMAC_ਖੰਡ_ਮਾਪ)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SHA256_ਖੰਡ_ਲੰਮਾਈ SHA256_HMAC_ਖੰਡ_ਮਾਪ
#ਜੇ_ਅੰਤ
#ਜੇ !defined(SHA384_ਖੰਡ_ਲੰਮਾਈ) && defined(SHA512_HMAC_ਖੰਡ_ਮਾਪ)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SHA384_ਖੰਡ_ਲੰਮਾਈ SHA512_HMAC_ਖੰਡ_ਮਾਪ
#ਜੇ_ਅੰਤ
#ਜੇ !defined(SHA512_ਖੰਡ_ਲੰਮਾਈ) && defined(SHA512_HMAC_ਖੰਡ_ਮਾਪ)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SHA512_ਖੰਡ_ਲੰਮਾਈ SHA512_HMAC_ਖੰਡ_ਮਾਪ
#ਜੇ_ਅੰਤ

#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "digest.h"

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਖਾਲੀ md_init_fn(ਖਾਲੀ *mdctx);
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਖਾਲੀ md_update_fn(ਖਾਲੀ *mdctx, ਅਚਲ uint8_t *m, ਮਾਪ_t mlen);
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਖਾਲੀ md_final_fn(uint8_t[], ਖਾਲੀ *mdctx);

ਬਣਤਰ ssh_digest_ctx {
	ਪੂਰਨ alg;
	ਖਾਲੀ *mdctx;
};

ਬਣਤਰ ssh_digest {
	ਪੂਰਨ id;
	ਅਚਲ ਅੱਖਰ *name;
	ਮਾਪ_t ਖੰਡ_len;
	ਮਾਪ_t digest_len;
	ਮਾਪ_t ctx_len;
	md_init_fn *md_init;
	md_update_fn *md_update;
	md_final_fn *md_final;
};

/* NB. Indexed directly by algorithm number */
ਅਚਲ ਬਣਤਰ ssh_digest digests[SSH_DIGEST_MAX] = {
	{
		SSH_DIGEST_MD5,
		"MD5",
		MD5_ਖੰਡ_ਲੰਮਾਈ,
		MD5_DIGEST_ਲੰਮਾਈ,
		ਆਕਾਰ(MD5_CTX),
		(md_init_fn *) MD5Init,
		(md_update_fn *) MD5Update,
		(md_final_fn *) MD5Final
	},
	{
		SSH_DIGEST_SHA1,
		"SHA1",
		SHA1_ਖੰਡ_ਲੰਮਾਈ,
		SHA1_DIGEST_ਲੰਮਾਈ,
		ਆਕਾਰ(SHA1_CTX),
		(md_init_fn *) SHA1Init,
		(md_update_fn *) SHA1Update,
		(md_final_fn *) SHA1Final
	},
	{
		SSH_DIGEST_SHA256,
		"SHA256",
		SHA256_ਖੰਡ_ਲੰਮਾਈ,
		SHA256_DIGEST_ਲੰਮਾਈ,
		ਆਕਾਰ(SHA2_CTX),
		(md_init_fn *) SHA256Init,
		(md_update_fn *) SHA256Update,
		(md_final_fn *) SHA256Final
	},
	{
		SSH_DIGEST_SHA384,
		"SHA384",
		SHA384_ਖੰਡ_ਲੰਮਾਈ,
		SHA384_DIGEST_ਲੰਮਾਈ,
		ਆਕਾਰ(SHA2_CTX),
		(md_init_fn *) SHA384Init,
		(md_update_fn *) SHA384Update,
		(md_final_fn *) SHA384Final
	},
	{
		SSH_DIGEST_SHA512,
		"SHA512",
		SHA512_ਖੰਡ_ਲੰਮਾਈ,
		SHA512_DIGEST_ਲੰਮਾਈ,
		ਆਕਾਰ(SHA2_CTX),
		(md_init_fn *) SHA512Init,
		(md_update_fn *) SHA512Update,
		(md_final_fn *) SHA512Final
	}
};

ਸਥਿਰ ਅਚਲ ਬਣਤਰ ssh_digest *
ssh_digest_by_alg(ਪੂਰਨ alg)
{
	ਜੇ (alg < 0 || alg >= SSH_DIGEST_MAX)
		ਵਾਪਸ ਨਿਰਾ;
	ਜੇ (digests[alg].id != alg) /* sanity */
		ਵਾਪਸ ਨਿਰਾ;
	ਵਾਪਸ &(digests[alg]);
}

ਪੂਰਨ
ssh_digest_alg_by_name(ਅਚਲ ਅੱਖਰ *name)
{
	ਪੂਰਨ alg;

	ਲਈ (alg = 0; alg < SSH_DIGEST_MAX; alg++) {
		ਜੇ (strcasecmp(name, digests[alg].name) == 0)
			ਵਾਪਸ digests[alg].id;
	}
	ਵਾਪਸ -1;
}

ਅਚਲ ਅੱਖਰ *
ssh_digest_alg_name(ਪੂਰਨ alg)
{
	ਅਚਲ ਬਣਤਰ ssh_digest *digest = ssh_digest_by_alg(alg);

	ਵਾਪਸ digest == ਨਿਰਾ ? ਨਿਰਾ : digest->name;
}

ਮਾਪ_t
ssh_digest_ਬਾਈਟਾਂ(ਪੂਰਨ alg)
{
	ਅਚਲ ਬਣਤਰ ssh_digest *digest = ssh_digest_by_alg(alg);

	ਵਾਪਸ digest == ਨਿਰਾ ? 0 : digest->digest_len;
}

ਮਾਪ_t
ssh_digest_blocksize(ਬਣਤਰ ssh_digest_ctx *ctx)
{
	ਅਚਲ ਬਣਤਰ ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	ਵਾਪਸ digest == ਨਿਰਾ ? 0 : digest->ਖੰਡ_len;
}

ਬਣਤਰ ssh_digest_ctx *
ssh_digest_ਸ਼ੁਰੂ(ਪੂਰਨ alg)
{
	ਅਚਲ ਬਣਤਰ ssh_digest *digest = ssh_digest_by_alg(alg);
	ਬਣਤਰ ssh_digest_ctx *ret;

	ਜੇ (digest == ਨਿਰਾ || (ret = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ਆਕਾਰ(*ret))) == ਨਿਰਾ)
		ਵਾਪਸ ਨਿਰਾ;
	ਜੇ ((ret->mdctx = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, digest->ctx_len)) == ਨਿਰਾ) {
		ਮੁਕਤ(ret);
		ਵਾਪਸ ਨਿਰਾ;
	}
	ret->alg = alg;
	digest->md_init(ret->mdctx);
	ਵਾਪਸ ret;
}

ਪੂਰਨ
ssh_digest_copy_state(ਬਣਤਰ ssh_digest_ctx *from, ਬਣਤਰ ssh_digest_ctx *ਮੰਜ਼ਿਲ)
{
	ਅਚਲ ਬਣਤਰ ssh_digest *digest = ssh_digest_by_alg(from->alg);

	ਜੇ (digest == ਨਿਰਾ || from->alg != ਮੰਜ਼ਿਲ->alg)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(ਮੰਜ਼ਿਲ->mdctx, from->mdctx, digest->ctx_len);
	ਵਾਪਸ 0;
}

ਪੂਰਨ
ssh_digest_update(ਬਣਤਰ ssh_digest_ctx *ctx, ਅਚਲ ਖਾਲੀ *m, ਮਾਪ_t mlen)
{
	ਅਚਲ ਬਣਤਰ ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	ਜੇ (digest == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	digest->md_update(ctx->mdctx, m, mlen);
	ਵਾਪਸ 0;
}

ਪੂਰਨ
ssh_digest_update_ਬਫਰ(ਬਣਤਰ ssh_digest_ctx *ctx, ਅਚਲ ਬਣਤਰ sshbuf *b)
{
	ਵਾਪਸ ssh_digest_update(ctx, sshbuf_ptr(b), sshbuf_len(b));
}

ਪੂਰਨ
ssh_digest_final(ਬਣਤਰ ssh_digest_ctx *ctx, u_char *d, ਮਾਪ_t dlen)
{
	ਅਚਲ ਬਣਤਰ ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	ਜੇ (digest == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	ਜੇ (dlen > UINT_MAX)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	ਜੇ (dlen < digest->digest_len) /* No truncation allowed */
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	digest->md_final(d, ctx->mdctx);
	ਵਾਪਸ 0;
}

ਖਾਲੀ
ssh_digest_free(ਬਣਤਰ ssh_digest_ctx *ctx)
{
	ਅਚਲ ਬਣਤਰ ssh_digest *digest;

	ਜੇ (ctx != ਨਿਰਾ) {
		digest = ssh_digest_by_alg(ctx->alg);
		ਜੇ (digest) {
			explicit_bzero(ctx->mdctx, digest->ctx_len);
			ਮੁਕਤ(ctx->mdctx);
			freezero(ctx, ਆਕਾਰ(*ctx));
		}
	}
}

ਪੂਰਨ
ssh_digest_ਸਮ੍ਰਿਤੀ(ਪੂਰਨ alg, ਅਚਲ ਖਾਲੀ *m, ਮਾਪ_t mlen, u_char *d, ਮਾਪ_t dlen)
{
	ਬਣਤਰ ssh_digest_ctx *ctx = ssh_digest_ਸ਼ੁਰੂ(alg);
	ਪੂਰਨ ret = 0;

	ਜੇ (ctx == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	ਜੇ (ssh_digest_update(ctx, m, mlen) != 0 ||
	    ssh_digest_final(ctx, d, dlen) != 0)
		ret = SSH_ERR_INVALID_ਦਲੀਲ;
	ssh_digest_free(ctx);
	ਵਾਪਸ ret;
}

ਪੂਰਨ
ssh_digest_ਬਫਰ(ਪੂਰਨ alg, ਅਚਲ ਬਣਤਰ sshbuf *b, u_char *d, ਮਾਪ_t dlen)
{
	ਵਾਪਸ ssh_digest_ਸਮ੍ਰਿਤੀ(alg, sshbuf_ptr(b), sshbuf_len(b), d, dlen);
}
#ਜੇ_ਅੰਤ /* !WITH_OPENSSL */
