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

#अन्तर्भाव "includes.h"

#ifndef WITH_OPENSSL

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <limits.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>

#यदि 0
#अन्तर्भाव <md5.h>
#endif
#ifdef HAVE_SHA1_H
#अन्तर्भाव <sha1.h>
#endif
#ifdef HAVE_SHA2_H
#अन्तर्भाव <sha2.h>
#endif

#यदि !defined(SHA256_BLOCK_LENGTH) && defined(SHA256_HMAC_BLOCK_SIZE)
#define SHA256_BLOCK_LENGTH SHA256_HMAC_BLOCK_SIZE
#endif
#यदि !defined(SHA384_BLOCK_LENGTH) && defined(SHA512_HMAC_BLOCK_SIZE)
#define SHA384_BLOCK_LENGTH SHA512_HMAC_BLOCK_SIZE
#endif
#यदि !defined(SHA512_BLOCK_LENGTH) && defined(SHA512_HMAC_BLOCK_SIZE)
#define SHA512_BLOCK_LENGTH SHA512_HMAC_BLOCK_SIZE
#endif

#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "digest.h"

प्रकारनिर्देश शून्य md_init_fn(शून्य *mdctx);
प्रकारनिर्देश शून्य md_update_fn(शून्य *mdctx, ध्रुव uint8_t *m, size_t mlen);
प्रकारनिर्देश शून्य md_final_fn(uint8_t[], शून्य *mdctx);

संरचना ssh_digest_ctx {
	पूर्णाङ्क alg;
	शून्य *mdctx;
};

संरचना ssh_digest {
	पूर्णाङ्क id;
	ध्रुव वर्ण *name;
	size_t block_len;
	size_t digest_len;
	size_t ctx_len;
	md_init_fn *md_init;
	md_update_fn *md_update;
	md_final_fn *md_final;
};

/* NB. Indexed directly by algorithm number */
ध्रुव संरचना ssh_digest digests[SSH_DIGEST_MAX] = {
	{
		SSH_DIGEST_MD5,
		"MD5",
		MD5_BLOCK_LENGTH,
		MD5_DIGEST_LENGTH,
		परिमाण(MD5_CTX),
		(md_init_fn *) MD5Init,
		(md_update_fn *) MD5Update,
		(md_final_fn *) MD5Final
	},
	{
		SSH_DIGEST_SHA1,
		"SHA1",
		SHA1_BLOCK_LENGTH,
		SHA1_DIGEST_LENGTH,
		परिमाण(SHA1_CTX),
		(md_init_fn *) SHA1Init,
		(md_update_fn *) SHA1Update,
		(md_final_fn *) SHA1Final
	},
	{
		SSH_DIGEST_SHA256,
		"SHA256",
		SHA256_BLOCK_LENGTH,
		SHA256_DIGEST_LENGTH,
		परिमाण(SHA2_CTX),
		(md_init_fn *) SHA256Init,
		(md_update_fn *) SHA256Update,
		(md_final_fn *) SHA256Final
	},
	{
		SSH_DIGEST_SHA384,
		"SHA384",
		SHA384_BLOCK_LENGTH,
		SHA384_DIGEST_LENGTH,
		परिमाण(SHA2_CTX),
		(md_init_fn *) SHA384Init,
		(md_update_fn *) SHA384Update,
		(md_final_fn *) SHA384Final
	},
	{
		SSH_DIGEST_SHA512,
		"SHA512",
		SHA512_BLOCK_LENGTH,
		SHA512_DIGEST_LENGTH,
		परिमाण(SHA2_CTX),
		(md_init_fn *) SHA512Init,
		(md_update_fn *) SHA512Update,
		(md_final_fn *) SHA512Final
	}
};

स्थिर ध्रुव संरचना ssh_digest *
ssh_digest_by_alg(पूर्णाङ्क alg)
{
	यदि (alg < 0 || alg >= SSH_DIGEST_MAX)
		प्रत्यागम रिक्त;
	यदि (digests[alg].id != alg) /* sanity */
		प्रत्यागम रिक्त;
	प्रत्यागम &(digests[alg]);
}

पूर्णाङ्क
ssh_digest_alg_by_name(ध्रुव वर्ण *name)
{
	पूर्णाङ्क alg;

	प्रति (alg = 0; alg < SSH_DIGEST_MAX; alg++) {
		यदि (strcasecmp(name, digests[alg].name) == 0)
			प्रत्यागम digests[alg].id;
	}
	प्रत्यागम -1;
}

ध्रुव वर्ण *
ssh_digest_alg_name(पूर्णाङ्क alg)
{
	ध्रुव संरचना ssh_digest *digest = ssh_digest_by_alg(alg);

	प्रत्यागम digest == रिक्त ? रिक्त : digest->name;
}

size_t
ssh_digest_bytes(पूर्णाङ्क alg)
{
	ध्रुव संरचना ssh_digest *digest = ssh_digest_by_alg(alg);

	प्रत्यागम digest == रिक्त ? 0 : digest->digest_len;
}

size_t
ssh_digest_blocksize(संरचना ssh_digest_ctx *ctx)
{
	ध्रुव संरचना ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	प्रत्यागम digest == रिक्त ? 0 : digest->block_len;
}

संरचना ssh_digest_ctx *
ssh_digest_start(पूर्णाङ्क alg)
{
	ध्रुव संरचना ssh_digest *digest = ssh_digest_by_alg(alg);
	संरचना ssh_digest_ctx *ret;

	यदि (digest == रिक्त || (ret = calloc(1, परिमाण(*ret))) == रिक्त)
		प्रत्यागम रिक्त;
	यदि ((ret->mdctx = calloc(1, digest->ctx_len)) == रिक्त) {
		मुक्त(ret);
		प्रत्यागम रिक्त;
	}
	ret->alg = alg;
	digest->md_init(ret->mdctx);
	प्रत्यागम ret;
}

पूर्णाङ्क
ssh_digest_copy_state(संरचना ssh_digest_ctx *from, संरचना ssh_digest_ctx *to)
{
	ध्रुव संरचना ssh_digest *digest = ssh_digest_by_alg(from->alg);

	यदि (digest == रिक्त || from->alg != to->alg)
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;
	memcpy(to->mdctx, from->mdctx, digest->ctx_len);
	प्रत्यागम 0;
}

पूर्णाङ्क
ssh_digest_update(संरचना ssh_digest_ctx *ctx, ध्रुव शून्य *m, size_t mlen)
{
	ध्रुव संरचना ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	यदि (digest == रिक्त)
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;
	digest->md_update(ctx->mdctx, m, mlen);
	प्रत्यागम 0;
}

पूर्णाङ्क
ssh_digest_update_buffer(संरचना ssh_digest_ctx *ctx, ध्रुव संरचना sshbuf *b)
{
	प्रत्यागम ssh_digest_update(ctx, sshbuf_ptr(b), sshbuf_len(b));
}

पूर्णाङ्क
ssh_digest_final(संरचना ssh_digest_ctx *ctx, u_char *d, size_t dlen)
{
	ध्रुव संरचना ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	यदि (digest == रिक्त)
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;
	यदि (dlen > UINT_MAX)
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;
	यदि (dlen < digest->digest_len) /* No truncation allowed */
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;
	digest->md_final(d, ctx->mdctx);
	प्रत्यागम 0;
}

शून्य
ssh_digest_free(संरचना ssh_digest_ctx *ctx)
{
	ध्रुव संरचना ssh_digest *digest;

	यदि (ctx != रिक्त) {
		digest = ssh_digest_by_alg(ctx->alg);
		यदि (digest) {
			explicit_bzero(ctx->mdctx, digest->ctx_len);
			मुक्त(ctx->mdctx);
			freezero(ctx, परिमाण(*ctx));
		}
	}
}

पूर्णाङ्क
ssh_digest_memory(पूर्णाङ्क alg, ध्रुव शून्य *m, size_t mlen, u_char *d, size_t dlen)
{
	संरचना ssh_digest_ctx *ctx = ssh_digest_start(alg);
	पूर्णाङ्क ret = 0;

	यदि (ctx == रिक्त)
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;
	यदि (ssh_digest_update(ctx, m, mlen) != 0 ||
	    ssh_digest_final(ctx, d, dlen) != 0)
		ret = SSH_ERR_INVALID_ARGUMENT;
	ssh_digest_free(ctx);
	प्रत्यागम ret;
}

पूर्णाङ्क
ssh_digest_buffer(पूर्णाङ्क alg, ध्रुव संरचना sshbuf *b, u_char *d, size_t dlen)
{
	प्रत्यागम ssh_digest_memory(alg, sshbuf_ptr(b), sshbuf_len(b), d, dlen);
}
#endif /* !WITH_OPENSSL */
