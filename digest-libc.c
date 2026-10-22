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

#جے_بنا_تعریف WITH_OPENSSL

#ضمن <sys/types.h>
#ضمن <limits.h>
#ضمن <stdlib.h>
#ضمن <string.h>

#إذا 0
#ضمن <md5.h>
#جے_انت
#جے_تعریف_شدہ HAVE_SHA1_H
#ضمن <sha1.h>
#جے_انت
#جے_تعریف_شدہ HAVE_SHA2_H
#ضمن <sha2.h>
#جے_انت

#إذا !defined(SHA256_بلاک_لمائی) && defined(SHA256_HMAC_بلاک_ناپ)
#تعریف_کرو SHA256_بلاک_لمائی SHA256_HMAC_بلاک_ناپ
#جے_انت
#إذا !defined(SHA384_بلاک_لمائی) && defined(SHA512_HMAC_بلاک_ناپ)
#تعریف_کرو SHA384_بلاک_لمائی SHA512_HMAC_بلاک_ناپ
#جے_انت
#إذا !defined(SHA512_بلاک_لمائی) && defined(SHA512_HMAC_بلاک_ناپ)
#تعریف_کرو SHA512_بلاک_لمائی SHA512_HMAC_بلاک_ناپ
#جے_انت

#ضمن "ssherr.h"
#ضمن "sshbuf.h"
#ضمن "digest.h"

تعريفنوع فراغ md_init_fn(فراغ *mdctx);
تعريفنوع فراغ md_update_fn(فراغ *mdctx, ثابت uint8_t *m, ناپ_t mlen);
تعريفنوع فراغ md_final_fn(uint8_t[], فراغ *mdctx);

بنية ssh_digest_ctx {
	صحيح alg;
	فراغ *mdctx;
};

بنية ssh_digest {
	صحيح id;
	ثابت حرف *name;
	ناپ_t بلاک_len;
	ناپ_t digest_len;
	ناپ_t ctx_len;
	md_init_fn *md_init;
	md_update_fn *md_update;
	md_final_fn *md_final;
};

/* NB. Indexed directly by algorithm number */
ثابت بنية ssh_digest digests[SSH_DIGEST_MAX] = {
	{
		SSH_DIGEST_MD5,
		"MD5",
		MD5_بلاک_لمائی,
		MD5_DIGEST_لمائی,
		حجم(MD5_CTX),
		(md_init_fn *) MD5Init,
		(md_update_fn *) MD5Update,
		(md_final_fn *) MD5Final
	},
	{
		SSH_DIGEST_SHA1,
		"SHA1",
		SHA1_بلاک_لمائی,
		SHA1_DIGEST_لمائی,
		حجم(SHA1_CTX),
		(md_init_fn *) SHA1Init,
		(md_update_fn *) SHA1Update,
		(md_final_fn *) SHA1Final
	},
	{
		SSH_DIGEST_SHA256,
		"SHA256",
		SHA256_بلاک_لمائی,
		SHA256_DIGEST_لمائی,
		حجم(SHA2_CTX),
		(md_init_fn *) SHA256Init,
		(md_update_fn *) SHA256Update,
		(md_final_fn *) SHA256Final
	},
	{
		SSH_DIGEST_SHA384,
		"SHA384",
		SHA384_بلاک_لمائی,
		SHA384_DIGEST_لمائی,
		حجم(SHA2_CTX),
		(md_init_fn *) SHA384Init,
		(md_update_fn *) SHA384Update,
		(md_final_fn *) SHA384Final
	},
	{
		SSH_DIGEST_SHA512,
		"SHA512",
		SHA512_بلاک_لمائی,
		SHA512_DIGEST_لمائی,
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
		أرجع عدم;
	إذا (digests[alg].id != alg) /* sanity */
		أرجع عدم;
	أرجع &(digests[alg]);
}

صحيح
ssh_digest_alg_by_name(ثابت حرف *name)
{
	صحيح alg;

	لكل (alg = 0; alg < SSH_DIGEST_MAX; alg++) {
		إذا (strcasecmp(name, digests[alg].name) == 0)
			أرجع digests[alg].id;
	}
	أرجع -1;
}

ثابت حرف *
ssh_digest_alg_name(صحيح alg)
{
	ثابت بنية ssh_digest *digest = ssh_digest_by_alg(alg);

	أرجع digest == عدم ? عدم : digest->name;
}

ناپ_t
ssh_digest_بائٹاں(صحيح alg)
{
	ثابت بنية ssh_digest *digest = ssh_digest_by_alg(alg);

	أرجع digest == عدم ? 0 : digest->digest_len;
}

ناپ_t
ssh_digest_blocksize(بنية ssh_digest_ctx *ctx)
{
	ثابت بنية ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	أرجع digest == عدم ? 0 : digest->بلاک_len;
}

بنية ssh_digest_ctx *
ssh_digest_شروع(صحيح alg)
{
	ثابت بنية ssh_digest *digest = ssh_digest_by_alg(alg);
	بنية ssh_digest_ctx *ret;

	إذا (digest == عدم || (ret = صفر_حافظہ_دیو(1, حجم(*ret))) == عدم)
		أرجع عدم;
	إذا ((ret->mdctx = صفر_حافظہ_دیو(1, digest->ctx_len)) == عدم) {
		حرر(ret);
		أرجع عدم;
	}
	ret->alg = alg;
	digest->md_init(ret->mdctx);
	أرجع ret;
}

صحيح
ssh_digest_copy_state(بنية ssh_digest_ctx *from, بنية ssh_digest_ctx *منزل)
{
	ثابت بنية ssh_digest *digest = ssh_digest_by_alg(from->alg);

	إذا (digest == عدم || from->alg != منزل->alg)
		أرجع SSH_ERR_INVALID_دلیل;
	حافظہ_نقل(منزل->mdctx, from->mdctx, digest->ctx_len);
	أرجع 0;
}

صحيح
ssh_digest_update(بنية ssh_digest_ctx *ctx, ثابت فراغ *m, ناپ_t mlen)
{
	ثابت بنية ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	إذا (digest == عدم)
		أرجع SSH_ERR_INVALID_دلیل;
	digest->md_update(ctx->mdctx, m, mlen);
	أرجع 0;
}

صحيح
ssh_digest_update_بفر(بنية ssh_digest_ctx *ctx, ثابت بنية sshbuf *b)
{
	أرجع ssh_digest_update(ctx, sshbuf_ptr(b), sshbuf_len(b));
}

صحيح
ssh_digest_final(بنية ssh_digest_ctx *ctx, u_char *d, ناپ_t dlen)
{
	ثابت بنية ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	إذا (digest == عدم)
		أرجع SSH_ERR_INVALID_دلیل;
	إذا (dlen > UINT_MAX)
		أرجع SSH_ERR_INVALID_دلیل;
	إذا (dlen < digest->digest_len) /* No truncation allowed */
		أرجع SSH_ERR_INVALID_دلیل;
	digest->md_final(d, ctx->mdctx);
	أرجع 0;
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
ssh_digest_حافظہ(صحيح alg, ثابت فراغ *m, ناپ_t mlen, u_char *d, ناپ_t dlen)
{
	بنية ssh_digest_ctx *ctx = ssh_digest_شروع(alg);
	صحيح ret = 0;

	إذا (ctx == عدم)
		أرجع SSH_ERR_INVALID_دلیل;
	إذا (ssh_digest_update(ctx, m, mlen) != 0 ||
	    ssh_digest_final(ctx, d, dlen) != 0)
		ret = SSH_ERR_INVALID_دلیل;
	ssh_digest_free(ctx);
	أرجع ret;
}

صحيح
ssh_digest_بفر(صحيح alg, ثابت بنية sshbuf *b, u_char *d, ناپ_t dlen)
{
	أرجع ssh_digest_حافظہ(alg, sshbuf_ptr(b), sshbuf_len(b), d, dlen);
}
#جے_انت /* !WITH_OPENSSL */
