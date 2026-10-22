/* $OpenBSD: digest-openssl.c,v 1.9 2020/10/29 02:52:43 djm Exp $ */
/*
 * Copyright (c) 2013 Damien Miller <djm@mindrot.org>
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

#اگر_تعریف_شدہ WITH_OPENSSL

#شامل <sys/types.h>
#شامل <limits.h>
#شامل <stdlib.h>
#شامل <string.h>

#شامل <openssl/evp.h>

#شامل "openbsd-compat/openssl-compat.h"

#شامل "sshbuf.h"
#شامل "digest.h"
#شامل "ssherr.h"

#اگر_غیر_تعریف_شدہ HAVE_EVP_SHA256
# define EVP_sha256 تہی
#اگر_ختم
#اگر_غیر_تعریف_شدہ HAVE_EVP_SHA384
# define EVP_sha384 تہی
#اگر_ختم
#اگر_غیر_تعریف_شدہ HAVE_EVP_SHA512
# define EVP_sha512 تہی
#اگر_ختم

ساخت ssh_digest_ctx {
	صحیح alg;
	EVP_MD_CTX *mdctx;
};

ساخت ssh_digest {
	صحیح id;
	ثابت حرف *name;
	سائز_t digest_len;
	ثابت EVP_MD *(*mdfunc)(خالی);
};

/* NB. Indexed directly by algorithm number */
ثابت ساخت ssh_digest digests[] = {
	{ SSH_DIGEST_MD5,	"MD5",		16,	EVP_md5 },
	{ SSH_DIGEST_SHA1,	"SHA1",		20,	EVP_sha1 },
	{ SSH_DIGEST_SHA256,	"SHA256",	32,	EVP_sha256 },
	{ SSH_DIGEST_SHA384,	"SHA384",	48,	EVP_sha384 },
	{ SSH_DIGEST_SHA512,	"SHA512",	64,	EVP_sha512 },
	{ -1,			تہی,		0,	تہی },
};

ساکن ثابت ساخت ssh_digest *
ssh_digest_by_alg(صحیح alg)
{
	اگر (alg < 0 || alg >= SSH_DIGEST_MAX)
		واپس تہی;
	اگر (digests[alg].id != alg) /* sanity */
		واپس تہی;
	اگر (digests[alg].mdfunc == تہی)
		واپس تہی;
	واپس &(digests[alg]);
}

صحیح
ssh_digest_alg_by_name(ثابت حرف *name)
{
	صحیح alg;

	برائے (alg = 0; digests[alg].id != -1; alg++) {
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
	واپس EVP_MD_CTX_بلاک_سائز(ctx->mdctx);
}

ساخت ssh_digest_ctx *
ssh_digest_آغاز(صحیح alg)
{
	ثابت ساخت ssh_digest *digest = ssh_digest_by_alg(alg);
	ساخت ssh_digest_ctx *ret;

	اگر (digest == تہی || ((ret = صفر_حافظہ_دو(1, حجم(*ret))) == تہی))
		واپس تہی;
	ret->alg = alg;
	اگر ((ret->mdctx = EVP_MD_CTX_new()) == تہی) {
		آزاد(ret);
		واپس تہی;
	}
	اگر (EVP_DigestInit_ex(ret->mdctx, digest->mdfunc(), تہی) != 1) {
		ssh_digest_free(ret);
		واپس تہی;
	}
	واپس ret;
}

صحیح
ssh_digest_copy_state(ساخت ssh_digest_ctx *from, ساخت ssh_digest_ctx *مقصد)
{
	اگر (from->alg != مقصد->alg)
		واپس SSH_ERR_INVALID_دلیل;
	/* we have bcopy-style order while openssl has memcpy-style */
	اگر (!EVP_MD_CTX_copy_ex(مقصد->mdctx, from->mdctx))
		واپس SSH_ERR_LIBCRYPTO_ERROR;
	واپس 0;
}

صحیح
ssh_digest_update(ساخت ssh_digest_ctx *ctx, ثابت خالی *m, سائز_t mlen)
{
	اگر (EVP_DigestUpdate(ctx->mdctx, m, mlen) != 1)
		واپس SSH_ERR_LIBCRYPTO_ERROR;
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
	u_int l = dlen;

	اگر (digest == تہی || dlen > UINT_MAX)
		واپس SSH_ERR_INVALID_دلیل;
	اگر (dlen < digest->digest_len) /* No truncation allowed */
		واپس SSH_ERR_INVALID_دلیل;
	اگر (EVP_DigestFinal_ex(ctx->mdctx, d, &l) != 1)
		واپس SSH_ERR_LIBCRYPTO_ERROR;
	اگر (l != digest->digest_len) /* sanity */
		واپس SSH_ERR_اندرونی_ERROR;
	واپس 0;
}

خالی
ssh_digest_free(ساخت ssh_digest_ctx *ctx)
{
	اگر (ctx == تہی)
		واپس;
	EVP_MD_CTX_free(ctx->mdctx);
	freezero(ctx, حجم(*ctx));
}

صحیح
ssh_digest_حافظہ(صحیح alg, ثابت خالی *m, سائز_t mlen, u_char *d, سائز_t dlen)
{
	ثابت ساخت ssh_digest *digest = ssh_digest_by_alg(alg);
	u_int mdlen;

	اگر (digest == تہی)
		واپس SSH_ERR_INVALID_دلیل;
	اگر (dlen > UINT_MAX)
		واپس SSH_ERR_INVALID_دلیل;
	اگر (dlen < digest->digest_len)
		واپس SSH_ERR_INVALID_دلیل;
	mdlen = dlen;
	اگر (!EVP_Digest(m, mlen, d, &mdlen, digest->mdfunc(), تہی))
		واپس SSH_ERR_LIBCRYPTO_ERROR;
	واپس 0;
}

صحیح
ssh_digest_بفر(صحیح alg, ثابت ساخت sshbuf *b, u_char *d, سائز_t dlen)
{
	واپس ssh_digest_حافظہ(alg, sshbuf_ptr(b), sshbuf_len(b), d, dlen);
}
#اگر_ختم /* WITH_OPENSSL */
