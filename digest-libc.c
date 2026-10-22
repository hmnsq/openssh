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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ WITH_OPENSSL

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಆದರೆ 0
#ಅನ್ತರ್ಭಾವ <md5.h>
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_SHA1_H
#ಅನ್ತರ್ಭಾವ <sha1.h>
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_SHA2_H
#ಅನ್ತರ್ಭಾವ <sha2.h>
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ !defined(SHA256_ಖಂಡ_ಉದ್ದಳತೆ) && defined(SHA256_HMAC_ಖಂಡ_ಗಾತ್ರ)
#ವ್ಯಾಖ್ಯಾನಿಸು SHA256_ಖಂಡ_ಉದ್ದಳತೆ SHA256_HMAC_ಖಂಡ_ಗಾತ್ರ
#ಆದರೆ_ಅಂತ್ಯ
#ಆದರೆ !defined(SHA384_ಖಂಡ_ಉದ್ದಳತೆ) && defined(SHA512_HMAC_ಖಂಡ_ಗಾತ್ರ)
#ವ್ಯಾಖ್ಯಾನಿಸು SHA384_ಖಂಡ_ಉದ್ದಳತೆ SHA512_HMAC_ಖಂಡ_ಗಾತ್ರ
#ಆದರೆ_ಅಂತ್ಯ
#ಆದರೆ !defined(SHA512_ಖಂಡ_ಉದ್ದಳತೆ) && defined(SHA512_HMAC_ಖಂಡ_ಗಾತ್ರ)
#ವ್ಯಾಖ್ಯಾನಿಸು SHA512_ಖಂಡ_ಉದ್ದಳತೆ SHA512_HMAC_ಖಂಡ_ಗಾತ್ರ
#ಆದರೆ_ಅಂತ್ಯ

#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "digest.h"

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಶೂನ್ಯ md_init_fn(ಶೂನ್ಯ *mdctx);
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಶೂನ್ಯ md_update_fn(ಶೂನ್ಯ *mdctx, ಸ್ಥಿರಾಂಕ uint8_t *m, ಗಾತ್ರ_t mlen);
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಶೂನ್ಯ md_final_fn(uint8_t[], ಶೂನ್ಯ *mdctx);

ರಚನೆ ssh_digest_ctx {
	ಪೂರ್ಣಾಂಕ alg;
	ಶೂನ್ಯ *mdctx;
};

ರಚನೆ ssh_digest {
	ಪೂರ್ಣಾಂಕ id;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name;
	ಗಾತ್ರ_t ಖಂಡ_len;
	ಗಾತ್ರ_t digest_len;
	ಗಾತ್ರ_t ctx_len;
	md_init_fn *md_init;
	md_update_fn *md_update;
	md_final_fn *md_final;
};

/* NB. Indexed directly by algorithm number */
ಸ್ಥಿರಾಂಕ ರಚನೆ ssh_digest digests[SSH_DIGEST_MAX] = {
	{
		SSH_DIGEST_MD5,
		"MD5",
		MD5_ಖಂಡ_ಉದ್ದಳತೆ,
		MD5_DIGEST_ಉದ್ದಳತೆ,
		ಗಾತ್ರ(MD5_CTX),
		(md_init_fn *) MD5Init,
		(md_update_fn *) MD5Update,
		(md_final_fn *) MD5Final
	},
	{
		SSH_DIGEST_SHA1,
		"SHA1",
		SHA1_ಖಂಡ_ಉದ್ದಳತೆ,
		SHA1_DIGEST_ಉದ್ದಳತೆ,
		ಗಾತ್ರ(SHA1_CTX),
		(md_init_fn *) SHA1Init,
		(md_update_fn *) SHA1Update,
		(md_final_fn *) SHA1Final
	},
	{
		SSH_DIGEST_SHA256,
		"SHA256",
		SHA256_ಖಂಡ_ಉದ್ದಳತೆ,
		SHA256_DIGEST_ಉದ್ದಳತೆ,
		ಗಾತ್ರ(SHA2_CTX),
		(md_init_fn *) SHA256Init,
		(md_update_fn *) SHA256Update,
		(md_final_fn *) SHA256Final
	},
	{
		SSH_DIGEST_SHA384,
		"SHA384",
		SHA384_ಖಂಡ_ಉದ್ದಳತೆ,
		SHA384_DIGEST_ಉದ್ದಳತೆ,
		ಗಾತ್ರ(SHA2_CTX),
		(md_init_fn *) SHA384Init,
		(md_update_fn *) SHA384Update,
		(md_final_fn *) SHA384Final
	},
	{
		SSH_DIGEST_SHA512,
		"SHA512",
		SHA512_ಖಂಡ_ಉದ್ದಳತೆ,
		SHA512_DIGEST_ಉದ್ದಳತೆ,
		ಗಾತ್ರ(SHA2_CTX),
		(md_init_fn *) SHA512Init,
		(md_update_fn *) SHA512Update,
		(md_final_fn *) SHA512Final
	}
};

ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ರಚನೆ ssh_digest *
ssh_digest_by_alg(ಪೂರ್ಣಾಂಕ alg)
{
	ಆದರೆ (alg < 0 || alg >= SSH_DIGEST_MAX)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	ಆದರೆ (digests[alg].id != alg) /* sanity */
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	ಹಿಂತಿರುಗಿ &(digests[alg]);
}

ಪೂರ್ಣಾಂಕ
ssh_digest_alg_by_name(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name)
{
	ಪೂರ್ಣಾಂಕ alg;

	ಗಾಗಿ (alg = 0; alg < SSH_DIGEST_MAX; alg++) {
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
	ಸ್ಥಿರಾಂಕ ರಚನೆ ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	ಹಿಂತಿರುಗಿ digest == ಖಾಲಿ ? 0 : digest->ಖಂಡ_len;
}

ರಚನೆ ssh_digest_ctx *
ssh_digest_ಆರಂಭ(ಪೂರ್ಣಾಂಕ alg)
{
	ಸ್ಥಿರಾಂಕ ರಚನೆ ssh_digest *digest = ssh_digest_by_alg(alg);
	ರಚನೆ ssh_digest_ctx *ret;

	ಆದರೆ (digest == ಖಾಲಿ || (ret = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ಗಾತ್ರ(*ret))) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	ಆದರೆ ((ret->mdctx = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, digest->ctx_len)) == ಖಾಲಿ) {
		ಬಿಡುಗಡೆ(ret);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ret->alg = alg;
	digest->md_init(ret->mdctx);
	ಹಿಂತಿರುಗಿ ret;
}

ಪೂರ್ಣಾಂಕ
ssh_digest_copy_state(ರಚನೆ ssh_digest_ctx *from, ರಚನೆ ssh_digest_ctx *ಗಮ್ಯ)
{
	ಸ್ಥಿರಾಂಕ ರಚನೆ ssh_digest *digest = ssh_digest_by_alg(from->alg);

	ಆದರೆ (digest == ಖಾಲಿ || from->alg != ಗಮ್ಯ->alg)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	ಸ್ಮರಣೆ_ನಕಲು(ಗಮ್ಯ->mdctx, from->mdctx, digest->ctx_len);
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
ssh_digest_update(ರಚನೆ ssh_digest_ctx *ctx, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *m, ಗಾತ್ರ_t mlen)
{
	ಸ್ಥಿರಾಂಕ ರಚನೆ ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	ಆದರೆ (digest == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	digest->md_update(ctx->mdctx, m, mlen);
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

	ಆದರೆ (digest == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	ಆದರೆ (dlen > UINT_MAX)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	ಆದರೆ (dlen < digest->digest_len) /* No truncation allowed */
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	digest->md_final(d, ctx->mdctx);
	ಹಿಂತಿರುಗಿ 0;
}

ಶೂನ್ಯ
ssh_digest_free(ರಚನೆ ssh_digest_ctx *ctx)
{
	ಸ್ಥಿರಾಂಕ ರಚನೆ ssh_digest *digest;

	ಆದರೆ (ctx != ಖಾಲಿ) {
		digest = ssh_digest_by_alg(ctx->alg);
		ಆದರೆ (digest) {
			explicit_bzero(ctx->mdctx, digest->ctx_len);
			ಬಿಡುಗಡೆ(ctx->mdctx);
			freezero(ctx, ಗಾತ್ರ(*ctx));
		}
	}
}

ಪೂರ್ಣಾಂಕ
ssh_digest_ಸ್ಮರಣೆ(ಪೂರ್ಣಾಂಕ alg, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *m, ಗಾತ್ರ_t mlen, u_char *d, ಗಾತ್ರ_t dlen)
{
	ರಚನೆ ssh_digest_ctx *ctx = ssh_digest_ಆರಂಭ(alg);
	ಪೂರ್ಣಾಂಕ ret = 0;

	ಆದರೆ (ctx == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	ಆದರೆ (ssh_digest_update(ctx, m, mlen) != 0 ||
	    ssh_digest_final(ctx, d, dlen) != 0)
		ret = SSH_ERR_INVALID_ವಾದ;
	ssh_digest_free(ctx);
	ಹಿಂತಿರುಗಿ ret;
}

ಪೂರ್ಣಾಂಕ
ssh_digest_ಬಫರ್(ಪೂರ್ಣಾಂಕ alg, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *b, u_char *d, ಗಾತ್ರ_t dlen)
{
	ಹಿಂತಿರುಗಿ ssh_digest_ಸ್ಮರಣೆ(alg, sshbuf_ptr(b), sshbuf_len(b), d, dlen);
}
#ಆದರೆ_ಅಂತ್ಯ /* !WITH_OPENSSL */
