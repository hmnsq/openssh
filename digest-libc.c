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

#شامل "includes.h"

#اگر_غیر_تعریف_شدہ WITH_OPENSSL

#شامل <sys/types.h>
#شامل <limits.h>
#شامل <stdlib.h>
#شامل <string.h>

#اگر 0
#شامل <md5.h>
#اگر_ختم
#اگر_تعریف_شدہ HAVE_SHA1_H
#شامل <sha1.h>
#اگر_ختم
#اگر_تعریف_شدہ HAVE_SHA2_H
#شامل <sha2.h>
#اگر_ختم

#اگر !defined(SHA256_بلاک_لمبائی) && defined(SHA256_HMAC_بلاک_سائز)
#تعریف_کرو SHA256_بلاک_لمبائی SHA256_HMAC_بلاک_سائز
#اگر_ختم
#اگر !defined(SHA384_بلاک_لمبائی) && defined(SHA512_HMAC_بلاک_سائز)
#تعریف_کرو SHA384_بلاک_لمبائی SHA512_HMAC_بلاک_سائز
#اگر_ختم
#اگر !defined(SHA512_بلاک_لمبائی) && defined(SHA512_HMAC_بلاک_سائز)
#تعریف_کرو SHA512_بلاک_لمبائی SHA512_HMAC_بلاک_سائز
#اگر_ختم

#شامل "ssherr.h"
#شامل "sshbuf.h"
#شامل "digest.h"

قسمتعریف خالی md_init_fn(خالی *mdctx);
قسمتعریف خالی md_update_fn(خالی *mdctx, ثابت uint8_t *m, سائز_t mlen);
قسمتعریف خالی md_final_fn(uint8_t[], خالی *mdctx);

ساخت ssh_digest_ctx {
	صحیح alg;
	خالی *mdctx;
};

ساخت ssh_digest {
	صحیح id;
	ثابت حرف *name;
	سائز_t بلاک_len;
	سائز_t digest_len;
	سائز_t ctx_len;
	md_init_fn *md_init;
	md_update_fn *md_update;
	md_final_fn *md_final;
};

/* NB. Indexed directly by algorithm number */
ثابت ساخت ssh_digest digests[SSH_DIGEST_MAX] = {
	{
		SSH_DIGEST_MD5,
		"MD5",
		MD5_بلاک_لمبائی,
		MD5_DIGEST_لمبائی,
		حجم(MD5_CTX),
		(md_init_fn *) MD5Init,
		(md_update_fn *) MD5Update,
		(md_final_fn *) MD5Final
	},
	{
		SSH_DIGEST_SHA1,
		"SHA1",
		SHA1_بلاک_لمبائی,
		SHA1_DIGEST_لمبائی,
		حجم(SHA1_CTX),
		(md_init_fn *) SHA1Init,
		(md_update_fn *) SHA1Update,
		(md_final_fn *) SHA1Final
	},
	{
		SSH_DIGEST_SHA256,
		"SHA256",
		SHA256_بلاک_لمبائی,
		SHA256_DIGEST_لمبائی,
		حجم(SHA2_CTX),
		(md_init_fn *) SHA256Init,
		(md_update_fn *) SHA256Update,
		(md_final_fn *) SHA256Final
	},
	{
		SSH_DIGEST_SHA384,
		"SHA384",
		SHA384_بلاک_لمبائی,
		SHA384_DIGEST_لمبائی,
		حجم(SHA2_CTX),
		(md_init_fn *) SHA384Init,
		(md_update_fn *) SHA384Update,
		(md_final_fn *) SHA384Final
	},
	{
		SSH_DIGEST_SHA512,
		"SHA512",
		SHA512_بلاک_لمبائی,
		SHA512_DIGEST_لمبائی,
		حجم(SHA2_CTX),
		(md_init_fn *) SHA512Init,
		(md_update_fn *) SHA512Update,
		(md_final_fn *) SHA512Final
	}
};

ساکن ثابت ساخت ssh_digest *
ssh_digest_by_alg(صحیح alg)
{
	اگر (alg < 0 || alg >= SSH_DIGEST_MAX)
		واپس تہی;
	اگر (digests[alg].id != alg) /* sanity */
		واپس تہی;
	واپس &(digests[alg]);
}

صحیح
ssh_digest_alg_by_name(ثابت حرف *name)
{
	صحیح alg;

	برائے (alg = 0; alg < SSH_DIGEST_MAX; alg++) {
		اگر (strcasecmp(name, digests[alg].name) == 0)
			واپس digests[alg].id;
	}
	واپس -1;
}

ثابت حرف *
ssh_digest_alg_name(صحیح alg)
{
	ثابت ساخت ssh_digest *digest = ssh_digest_by_alg(alg);

	واپس digest == تہی ? تہی : digest->name;
}

سائز_t
ssh_digest_بائٹیں(صحیح alg)
{
	ثابت ساخت ssh_digest *digest = ssh_digest_by_alg(alg);

	واپس digest == تہی ? 0 : digest->digest_len;
}

سائز_t
ssh_digest_blocksize(ساخت ssh_digest_ctx *ctx)
{
	ثابت ساخت ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	واپس digest == تہی ? 0 : digest->بلاک_len;
}

ساخت ssh_digest_ctx *
ssh_digest_آغاز(صحیح alg)
{
	ثابت ساخت ssh_digest *digest = ssh_digest_by_alg(alg);
	ساخت ssh_digest_ctx *ret;

	اگر (digest == تہی || (ret = صفر_حافظہ_دو(1, حجم(*ret))) == تہی)
		واپس تہی;
	اگر ((ret->mdctx = صفر_حافظہ_دو(1, digest->ctx_len)) == تہی) {
		آزاد(ret);
		واپس تہی;
	}
	ret->alg = alg;
	digest->md_init(ret->mdctx);
	واپس ret;
}

صحیح
ssh_digest_copy_state(ساخت ssh_digest_ctx *from, ساخت ssh_digest_ctx *مقصد)
{
	ثابت ساخت ssh_digest *digest = ssh_digest_by_alg(from->alg);

	اگر (digest == تہی || from->alg != مقصد->alg)
		واپس SSH_ERR_INVALID_دلیل;
	حافظہ_نقل(مقصد->mdctx, from->mdctx, digest->ctx_len);
	واپس 0;
}

صحیح
ssh_digest_update(ساخت ssh_digest_ctx *ctx, ثابت خالی *m, سائز_t mlen)
{
	ثابت ساخت ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	اگر (digest == تہی)
		واپس SSH_ERR_INVALID_دلیل;
	digest->md_update(ctx->mdctx, m, mlen);
	واپس 0;
}

صحیح
ssh_digest_update_بفر(ساخت ssh_digest_ctx *ctx, ثابت ساخت sshbuf *b)
{
	واپس ssh_digest_update(ctx, sshbuf_ptr(b), sshbuf_len(b));
}

صحیح
ssh_digest_final(ساخت ssh_digest_ctx *ctx, u_char *d, سائز_t dlen)
{
	ثابت ساخت ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	اگر (digest == تہی)
		واپس SSH_ERR_INVALID_دلیل;
	اگر (dlen > UINT_MAX)
		واپس SSH_ERR_INVALID_دلیل;
	اگر (dlen < digest->digest_len) /* No truncation allowed */
		واپس SSH_ERR_INVALID_دلیل;
	digest->md_final(d, ctx->mdctx);
	واپس 0;
}

خالی
ssh_digest_free(ساخت ssh_digest_ctx *ctx)
{
	ثابت ساخت ssh_digest *digest;

	اگر (ctx != تہی) {
		digest = ssh_digest_by_alg(ctx->alg);
		اگر (digest) {
			explicit_bzero(ctx->mdctx, digest->ctx_len);
			آزاد(ctx->mdctx);
			freezero(ctx, حجم(*ctx));
		}
	}
}

صحیح
ssh_digest_حافظہ(صحیح alg, ثابت خالی *m, سائز_t mlen, u_char *d, سائز_t dlen)
{
	ساخت ssh_digest_ctx *ctx = ssh_digest_آغاز(alg);
	صحیح ret = 0;

	اگر (ctx == تہی)
		واپس SSH_ERR_INVALID_دلیل;
	اگر (ssh_digest_update(ctx, m, mlen) != 0 ||
	    ssh_digest_final(ctx, d, dlen) != 0)
		ret = SSH_ERR_INVALID_دلیل;
	ssh_digest_free(ctx);
	واپس ret;
}

صحیح
ssh_digest_بفر(صحیح alg, ثابت ساخت sshbuf *b, u_char *d, سائز_t dlen)
{
	واپس ssh_digest_حافظہ(alg, sshbuf_ptr(b), sshbuf_len(b), d, dlen);
}
#اگر_ختم /* !WITH_OPENSSL */
