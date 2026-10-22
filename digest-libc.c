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

#અન્તર્ભાવ "includes.h"

#ifndef WITH_OPENSSL

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <limits.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>

#જો 0
#અન્તર્ભાવ <md5.h>
#endif
#ifdef HAVE_SHA1_H
#અન્તર્ભાવ <sha1.h>
#endif
#ifdef HAVE_SHA2_H
#અન્તર્ભાવ <sha2.h>
#endif

#જો !defined(SHA256_BLOCK_LENGTH) && defined(SHA256_HMAC_BLOCK_SIZE)
#define SHA256_BLOCK_LENGTH SHA256_HMAC_BLOCK_SIZE
#endif
#જો !defined(SHA384_BLOCK_LENGTH) && defined(SHA512_HMAC_BLOCK_SIZE)
#define SHA384_BLOCK_LENGTH SHA512_HMAC_BLOCK_SIZE
#endif
#જો !defined(SHA512_BLOCK_LENGTH) && defined(SHA512_HMAC_BLOCK_SIZE)
#define SHA512_BLOCK_LENGTH SHA512_HMAC_BLOCK_SIZE
#endif

#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "digest.h"

પ્રકારવ્યાખ્યા શૂન્ય md_init_fn(શૂન્ય *mdctx);
પ્રકારવ્યાખ્યા શૂન્ય md_update_fn(શૂન્ય *mdctx, અચલ uint8_t *m, size_t mlen);
પ્રકારવ્યાખ્યા શૂન્ય md_final_fn(uint8_t[], શૂન્ય *mdctx);

સંરચના ssh_digest_ctx {
	પૂર્ણાંક alg;
	શૂન્ય *mdctx;
};

સંરચના ssh_digest {
	પૂર્ણાંક id;
	અચલ અક્ષર *name;
	size_t block_len;
	size_t digest_len;
	size_t ctx_len;
	md_init_fn *md_init;
	md_update_fn *md_update;
	md_final_fn *md_final;
};

/* NB. Indexed directly by algorithm number */
અચલ સંરચના ssh_digest digests[SSH_DIGEST_MAX] = {
	{
		SSH_DIGEST_MD5,
		"MD5",
		MD5_BLOCK_LENGTH,
		MD5_DIGEST_LENGTH,
		કદ(MD5_CTX),
		(md_init_fn *) MD5Init,
		(md_update_fn *) MD5Update,
		(md_final_fn *) MD5Final
	},
	{
		SSH_DIGEST_SHA1,
		"SHA1",
		SHA1_BLOCK_LENGTH,
		SHA1_DIGEST_LENGTH,
		કદ(SHA1_CTX),
		(md_init_fn *) SHA1Init,
		(md_update_fn *) SHA1Update,
		(md_final_fn *) SHA1Final
	},
	{
		SSH_DIGEST_SHA256,
		"SHA256",
		SHA256_BLOCK_LENGTH,
		SHA256_DIGEST_LENGTH,
		કદ(SHA2_CTX),
		(md_init_fn *) SHA256Init,
		(md_update_fn *) SHA256Update,
		(md_final_fn *) SHA256Final
	},
	{
		SSH_DIGEST_SHA384,
		"SHA384",
		SHA384_BLOCK_LENGTH,
		SHA384_DIGEST_LENGTH,
		કદ(SHA2_CTX),
		(md_init_fn *) SHA384Init,
		(md_update_fn *) SHA384Update,
		(md_final_fn *) SHA384Final
	},
	{
		SSH_DIGEST_SHA512,
		"SHA512",
		SHA512_BLOCK_LENGTH,
		SHA512_DIGEST_LENGTH,
		કદ(SHA2_CTX),
		(md_init_fn *) SHA512Init,
		(md_update_fn *) SHA512Update,
		(md_final_fn *) SHA512Final
	}
};

સ્થિર અચલ સંરચના ssh_digest *
ssh_digest_by_alg(પૂર્ણાંક alg)
{
	જો (alg < 0 || alg >= SSH_DIGEST_MAX)
		પાછા ખાલી;
	જો (digests[alg].id != alg) /* sanity */
		પાછા ખાલી;
	પાછા &(digests[alg]);
}

પૂર્ણાંક
ssh_digest_alg_by_name(અચલ અક્ષર *name)
{
	પૂર્ણાંક alg;

	માટે (alg = 0; alg < SSH_DIGEST_MAX; alg++) {
		જો (strcasecmp(name, digests[alg].name) == 0)
			પાછા digests[alg].id;
	}
	પાછા -1;
}

અચલ અક્ષર *
ssh_digest_alg_name(પૂર્ણાંક alg)
{
	અચલ સંરચના ssh_digest *digest = ssh_digest_by_alg(alg);

	પાછા digest == ખાલી ? ખાલી : digest->name;
}

size_t
ssh_digest_bytes(પૂર્ણાંક alg)
{
	અચલ સંરચના ssh_digest *digest = ssh_digest_by_alg(alg);

	પાછા digest == ખાલી ? 0 : digest->digest_len;
}

size_t
ssh_digest_blocksize(સંરચના ssh_digest_ctx *ctx)
{
	અચલ સંરચના ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	પાછા digest == ખાલી ? 0 : digest->block_len;
}

સંરચના ssh_digest_ctx *
ssh_digest_start(પૂર્ણાંક alg)
{
	અચલ સંરચના ssh_digest *digest = ssh_digest_by_alg(alg);
	સંરચના ssh_digest_ctx *ret;

	જો (digest == ખાલી || (ret = calloc(1, કદ(*ret))) == ખાલી)
		પાછા ખાલી;
	જો ((ret->mdctx = calloc(1, digest->ctx_len)) == ખાલી) {
		મુક્ત(ret);
		પાછા ખાલી;
	}
	ret->alg = alg;
	digest->md_init(ret->mdctx);
	પાછા ret;
}

પૂર્ણાંક
ssh_digest_copy_state(સંરચના ssh_digest_ctx *from, સંરચના ssh_digest_ctx *to)
{
	અચલ સંરચના ssh_digest *digest = ssh_digest_by_alg(from->alg);

	જો (digest == ખાલી || from->alg != to->alg)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	memcpy(to->mdctx, from->mdctx, digest->ctx_len);
	પાછા 0;
}

પૂર્ણાંક
ssh_digest_update(સંરચના ssh_digest_ctx *ctx, અચલ શૂન્ય *m, size_t mlen)
{
	અચલ સંરચના ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	જો (digest == ખાલી)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	digest->md_update(ctx->mdctx, m, mlen);
	પાછા 0;
}

પૂર્ણાંક
ssh_digest_update_buffer(સંરચના ssh_digest_ctx *ctx, અચલ સંરચના sshbuf *b)
{
	પાછા ssh_digest_update(ctx, sshbuf_ptr(b), sshbuf_len(b));
}

પૂર્ણાંક
ssh_digest_final(સંરચના ssh_digest_ctx *ctx, u_char *d, size_t dlen)
{
	અચલ સંરચના ssh_digest *digest = ssh_digest_by_alg(ctx->alg);

	જો (digest == ખાલી)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	જો (dlen > UINT_MAX)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	જો (dlen < digest->digest_len) /* No truncation allowed */
		પાછા SSH_ERR_INVALID_ARGUMENT;
	digest->md_final(d, ctx->mdctx);
	પાછા 0;
}

શૂન્ય
ssh_digest_free(સંરચના ssh_digest_ctx *ctx)
{
	અચલ સંરચના ssh_digest *digest;

	જો (ctx != ખાલી) {
		digest = ssh_digest_by_alg(ctx->alg);
		જો (digest) {
			explicit_bzero(ctx->mdctx, digest->ctx_len);
			મુક્ત(ctx->mdctx);
			freezero(ctx, કદ(*ctx));
		}
	}
}

પૂર્ણાંક
ssh_digest_memory(પૂર્ણાંક alg, અચલ શૂન્ય *m, size_t mlen, u_char *d, size_t dlen)
{
	સંરચના ssh_digest_ctx *ctx = ssh_digest_start(alg);
	પૂર્ણાંક ret = 0;

	જો (ctx == ખાલી)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	જો (ssh_digest_update(ctx, m, mlen) != 0 ||
	    ssh_digest_final(ctx, d, dlen) != 0)
		ret = SSH_ERR_INVALID_ARGUMENT;
	ssh_digest_free(ctx);
	પાછા ret;
}

પૂર્ણાંક
ssh_digest_buffer(પૂર્ણાંક alg, અચલ સંરચના sshbuf *b, u_char *d, size_t dlen)
{
	પાછા ssh_digest_memory(alg, sshbuf_ptr(b), sshbuf_len(b), d, dlen);
}
#endif /* !WITH_OPENSSL */
