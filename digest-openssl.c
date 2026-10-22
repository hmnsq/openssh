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

#അന്തര്ഭാവ "includes.h"

#ifdef WITH_OPENSSL

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <limits.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>

#അന്തര്ഭാവ <openssl/evp.h>

#അന്തര്ഭാവ "openbsd-compat/openssl-compat.h"

#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "digest.h"
#അന്തര്ഭാവ "ssherr.h"

#ifndef HAVE_EVP_SHA256
# define EVP_sha256 ശൂന്യ
#endif
#ifndef HAVE_EVP_SHA384
# define EVP_sha384 ശൂന്യ
#endif
#ifndef HAVE_EVP_SHA512
# define EVP_sha512 ശൂന്യ
#endif

ഘടന ssh_digest_ctx {
	പൂർണ്ണസംഖ്യ alg;
	EVP_MD_CTX *mdctx;
};

ഘടന ssh_digest {
	പൂർണ്ണസംഖ്യ id;
	സ്ഥിരം അക്ഷരം *name;
	size_t digest_len;
	സ്ഥിരം EVP_MD *(*mdfunc)(ശൂന്യം);
};

/* NB. Indexed directly by algorithm number */
സ്ഥിരം ഘടന ssh_digest digests[] = {
	{ SSH_DIGEST_MD5,	"MD5",		16,	EVP_md5 },
	{ SSH_DIGEST_SHA1,	"SHA1",		20,	EVP_sha1 },
	{ SSH_DIGEST_SHA256,	"SHA256",	32,	EVP_sha256 },
	{ SSH_DIGEST_SHA384,	"SHA384",	48,	EVP_sha384 },
	{ SSH_DIGEST_SHA512,	"SHA512",	64,	EVP_sha512 },
	{ -1,			ശൂന്യ,		0,	ശൂന്യ },
};

സ്ഥിതം സ്ഥിരം ഘടന ssh_digest *
ssh_digest_by_alg(പൂർണ്ണസംഖ്യ alg)
{
	എങ്കിൽ (alg < 0 || alg >= SSH_DIGEST_MAX)
		തിരികെ ശൂന്യ;
	എങ്കിൽ (digests[alg].id != alg) /* sanity */
		തിരികെ ശൂന്യ;
	എങ്കിൽ (digests[alg].mdfunc == ശൂന്യ)
		തിരികെ ശൂന്യ;
	തിരികെ &(digests[alg]);
}

പൂർണ്ണസംഖ്യ
ssh_digest_alg_by_name(സ്ഥിരം അക്ഷരം *name)
{
	പൂർണ്ണസംഖ്യ alg;

	വേണ്ടി (alg = 0; digests[alg].id != -1; alg++) {
		എങ്കിൽ (strcasecmp(name, digests[alg].name) == 0)
			തിരികെ digests[alg].id;
	}
	തിരികെ -1;
}

സ്ഥിരം അക്ഷരം *
ssh_digest_alg_name(പൂർണ്ണസംഖ്യ alg)
{
	സ്ഥിരം ഘടന ssh_digest *digest = ssh_digest_by_alg(alg);

	തിരികെ digest == ശൂന്യ ? ശൂന്യ : digest->name;
}

size_t
ssh_digest_bytes(പൂർണ്ണസംഖ്യ alg)
{
	സ്ഥിരം ഘടന ssh_digest *digest = ssh_digest_by_alg(alg);

	തിരികെ digest == ശൂന്യ ? 0 : digest->digest_len;
}

size_t
ssh_digest_blocksize(ഘടന ssh_digest_ctx *ctx)
{
	തിരികെ EVP_MD_CTX_block_size(ctx->mdctx);
}

ഘടന ssh_digest_ctx *
ssh_digest_start(പൂർണ്ണസംഖ്യ alg)
{
	സ്ഥിരം ഘടന ssh_digest *digest = ssh_digest_by_alg(alg);
	ഘടന ssh_digest_ctx *ret;

	എങ്കിൽ (digest == ശൂന്യ || ((ret = calloc(1, വലുപ്പം(*ret))) == ശൂന്യ))
		തിരികെ ശൂന്യ;
	ret->alg = alg;
	എങ്കിൽ ((ret->mdctx = EVP_MD_CTX_new()) == ശൂന്യ) {
		സ്വതന്ത്രം(ret);
		തിരികെ ശൂന്യ;
	}
	എങ്കിൽ (EVP_DigestInit_ex(ret->mdctx, digest->mdfunc(), ശൂന്യ) != 1) {
		ssh_digest_free(ret);
		തിരികെ ശൂന്യ;
	}
	തിരികെ ret;
}

പൂർണ്ണസംഖ്യ
ssh_digest_copy_state(ഘടന ssh_digest_ctx *from, ഘടന ssh_digest_ctx *to)
{
	എങ്കിൽ (from->alg != to->alg)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	/* we have bcopy-style order while openssl has memcpy-style */
	എങ്കിൽ (!EVP_MD_CTX_copy_ex(to->mdctx, from->mdctx))
		തിരികെ SSH_ERR_LIBCRYPTO_ERROR;
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
ssh_digest_update(ഘടന ssh_digest_ctx *ctx, സ്ഥിരം ശൂന്യം *m, size_t mlen)
{
	എങ്കിൽ (EVP_DigestUpdate(ctx->mdctx, m, mlen) != 1)
		തിരികെ SSH_ERR_LIBCRYPTO_ERROR;
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
ssh_digest_update_buffer(ഘടന ssh_digest_ctx *ctx, സ്ഥിരം ഘടന sshbuf *b)
{
	തിരികെ ssh_digest_update(ctx, sshbuf_ptr(b), sshbuf_len(b));
}

പൂർണ്ണസംഖ്യ
ssh_digest_final(ഘടന ssh_digest_ctx *ctx, u_char *d, size_t dlen)
{
	സ്ഥിരം ഘടന ssh_digest *digest = ssh_digest_by_alg(ctx->alg);
	u_int l = dlen;

	എങ്കിൽ (digest == ശൂന്യ || dlen > UINT_MAX)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	എങ്കിൽ (dlen < digest->digest_len) /* No truncation allowed */
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	എങ്കിൽ (EVP_DigestFinal_ex(ctx->mdctx, d, &l) != 1)
		തിരികെ SSH_ERR_LIBCRYPTO_ERROR;
	എങ്കിൽ (l != digest->digest_len) /* sanity */
		തിരികെ SSH_ERR_INTERNAL_ERROR;
	തിരികെ 0;
}

ശൂന്യം
ssh_digest_free(ഘടന ssh_digest_ctx *ctx)
{
	എങ്കിൽ (ctx == ശൂന്യ)
		തിരികെ;
	EVP_MD_CTX_free(ctx->mdctx);
	freezero(ctx, വലുപ്പം(*ctx));
}

പൂർണ്ണസംഖ്യ
ssh_digest_memory(പൂർണ്ണസംഖ്യ alg, സ്ഥിരം ശൂന്യം *m, size_t mlen, u_char *d, size_t dlen)
{
	സ്ഥിരം ഘടന ssh_digest *digest = ssh_digest_by_alg(alg);
	u_int mdlen;

	എങ്കിൽ (digest == ശൂന്യ)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	എങ്കിൽ (dlen > UINT_MAX)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	എങ്കിൽ (dlen < digest->digest_len)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	mdlen = dlen;
	എങ്കിൽ (!EVP_Digest(m, mlen, d, &mdlen, digest->mdfunc(), ശൂന്യ))
		തിരികെ SSH_ERR_LIBCRYPTO_ERROR;
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
ssh_digest_buffer(പൂർണ്ണസംഖ്യ alg, സ്ഥിരം ഘടന sshbuf *b, u_char *d, size_t dlen)
{
	തിരികെ ssh_digest_memory(alg, sshbuf_ptr(b), sshbuf_len(b), d, dlen);
}
#endif /* WITH_OPENSSL */
