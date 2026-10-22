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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ <openssl/evp.h>

#ಅನ್ತರ್ಭಾವ "openbsd-compat/openssl-compat.h"

#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "digest.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_EVP_SHA256
# define EVP_sha256 ಖಾಲಿ
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_EVP_SHA384
# define EVP_sha384 ಖಾಲಿ
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_EVP_SHA512
# define EVP_sha512 ಖಾಲಿ
#ಆದರೆ_ಅಂತ್ಯ

ರಚನೆ ssh_digest_ctx {
	ಪೂರ್ಣಾಂಕ alg;
	EVP_MD_CTX *mdctx;
};

ರಚನೆ ssh_digest {
	ಪೂರ್ಣಾಂಕ id;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name;
	ಗಾತ್ರ_t digest_len;
	ಸ್ಥಿರಾಂಕ EVP_MD *(*mdfunc)(ಶೂನ್ಯ);
};

/* NB. Indexed directly by algorithm number */
ಸ್ಥಿರಾಂಕ ರಚನೆ ssh_digest digests[] = {
	{ SSH_DIGEST_MD5,	"MD5",		16,	EVP_md5 },
	{ SSH_DIGEST_SHA1,	"SHA1",		20,	EVP_sha1 },
	{ SSH_DIGEST_SHA256,	"SHA256",	32,	EVP_sha256 },
	{ SSH_DIGEST_SHA384,	"SHA384",	48,	EVP_sha384 },
	{ SSH_DIGEST_SHA512,	"SHA512",	64,	EVP_sha512 },
	{ -1,			ಖಾಲಿ,		0,	ಖಾಲಿ },
};

ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ರಚನೆ ssh_digest *
ssh_digest_by_alg(ಪೂರ್ಣಾಂಕ alg)
{
	ಆದರೆ (alg < 0 || alg >= SSH_DIGEST_MAX)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	ಆದರೆ (digests[alg].id != alg) /* sanity */
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	ಆದರೆ (digests[alg].mdfunc == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	ಹಿಂತಿರುಗಿ &(digests[alg]);
}

ಪೂರ್ಣಾಂಕ
ssh_digest_alg_by_name(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name)
{
	ಪೂರ್ಣಾಂಕ alg;

	ಗಾಗಿ (alg = 0; digests[alg].id != -1; alg++) {
		ಆದರೆ (strcasecmp(name, digests[alg].name) == 0)
			ಹಿಂತಿರುಗಿ digests[alg].id;
	}
	ಹಿಂತಿರುಗಿ -1;
}

ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
ssh_digest_alg_name(ಪೂರ್ಣಾಂಕ alg)
{
	ಸ್ಥಿರಾಂಕ ರಚನೆ ssh_digest *digest = ssh_digest_by_alg(alg);

	ಹಿಂತಿರುಗಿ digest == ಖಾಲಿ ? ಖಾಲಿ : digest->name;
}

ಗಾತ್ರ_t
ssh_digest_ಬೈಟುಗಳು(ಪೂರ್ಣಾಂಕ alg)
{
	ಸ್ಥಿರಾಂಕ ರಚನೆ ssh_digest *digest = ssh_digest_by_alg(alg);

	ಹಿಂತಿರುಗಿ digest == ಖಾಲಿ ? 0 : digest->digest_len;
}

ಗಾತ್ರ_t
ssh_digest_blocksize(ರಚನೆ ssh_digest_ctx *ctx)
{
	ಹಿಂತಿರುಗಿ EVP_MD_CTX_ಖಂಡ_ಗಾತ್ರ(ctx->mdctx);
}

ರಚನೆ ssh_digest_ctx *
ssh_digest_ಆರಂಭ(ಪೂರ್ಣಾಂಕ alg)
{
	ಸ್ಥಿರಾಂಕ ರಚನೆ ssh_digest *digest = ssh_digest_by_alg(alg);
	ರಚನೆ ssh_digest_ctx *ret;

	ಆದರೆ (digest == ಖಾಲಿ || ((ret = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ಗಾತ್ರ(*ret))) == ಖಾಲಿ))
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	ret->alg = alg;
	ಆದರೆ ((ret->mdctx = EVP_MD_CTX_new()) == ಖಾಲಿ) {
		ಬಿಡುಗಡೆ(ret);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ಆದರೆ (EVP_DigestInit_ex(ret->mdctx, digest->mdfunc(), ಖಾಲಿ) != 1) {
		ssh_digest_free(ret);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ಹಿಂತಿರುಗಿ ret;
}

ಪೂರ್ಣಾಂಕ
ssh_digest_copy_state(ರಚನೆ ssh_digest_ctx *from, ರಚನೆ ssh_digest_ctx *ಗಮ್ಯ)
{
	ಆದರೆ (from->alg != ಗಮ್ಯ->alg)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	/* we have bcopy-style order while openssl has memcpy-style */
	ಆದರೆ (!EVP_MD_CTX_copy_ex(ಗಮ್ಯ->mdctx, from->mdctx))
		ಹಿಂತಿರುಗಿ SSH_ERR_LIBCRYPTO_ERROR;
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
ssh_digest_update(ರಚನೆ ssh_digest_ctx *ctx, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *m, ಗಾತ್ರ_t mlen)
{
	ಆದರೆ (EVP_DigestUpdate(ctx->mdctx, m, mlen) != 1)
		ಹಿಂತಿರುಗಿ SSH_ERR_LIBCRYPTO_ERROR;
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
ssh_digest_update_ಬಫರ್(ರಚನೆ ssh_digest_ctx *ctx, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *b)
{
	ಹಿಂತಿರುಗಿ ssh_digest_update(ctx, sshbuf_ptr(b), sshbuf_len(b));
}

ಪೂರ್ಣಾಂಕ
ssh_digest_final(ರಚನೆ ssh_digest_ctx *ctx, u_char *d, ಗಾತ್ರ_t dlen)
{
	ಸ್ಥಿರಾಂಕ ರಚನೆ ssh_digest *digest = ssh_digest_by_alg(ctx->alg);
	u_int l = dlen;

	ಆದರೆ (digest == ಖಾಲಿ || dlen > UINT_MAX)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	ಆದರೆ (dlen < digest->digest_len) /* No truncation allowed */
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	ಆದರೆ (EVP_DigestFinal_ex(ctx->mdctx, d, &l) != 1)
		ಹಿಂತಿರುಗಿ SSH_ERR_LIBCRYPTO_ERROR;
	ಆದರೆ (l != digest->digest_len) /* sanity */
		ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;
	ಹಿಂತಿರುಗಿ 0;
}

ಶೂನ್ಯ
ssh_digest_free(ರಚನೆ ssh_digest_ctx *ctx)
{
	ಆದರೆ (ctx == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	EVP_MD_CTX_free(ctx->mdctx);
	freezero(ctx, ಗಾತ್ರ(*ctx));
}

ಪೂರ್ಣಾಂಕ
ssh_digest_ಸ್ಮರಣೆ(ಪೂರ್ಣಾಂಕ alg, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *m, ಗಾತ್ರ_t mlen, u_char *d, ಗಾತ್ರ_t dlen)
{
	ಸ್ಥಿರಾಂಕ ರಚನೆ ssh_digest *digest = ssh_digest_by_alg(alg);
	u_int mdlen;

	ಆದರೆ (digest == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	ಆದರೆ (dlen > UINT_MAX)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	ಆದರೆ (dlen < digest->digest_len)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	mdlen = dlen;
	ಆದರೆ (!EVP_Digest(m, mlen, d, &mdlen, digest->mdfunc(), ಖಾಲಿ))
		ಹಿಂತಿರುಗಿ SSH_ERR_LIBCRYPTO_ERROR;
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
ssh_digest_ಬಫರ್(ಪೂರ್ಣಾಂಕ alg, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *b, u_char *d, ಗಾತ್ರ_t dlen)
{
	ಹಿಂತಿರುಗಿ ssh_digest_ಸ್ಮರಣೆ(alg, sshbuf_ptr(b), sshbuf_len(b), d, dlen);
}
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
