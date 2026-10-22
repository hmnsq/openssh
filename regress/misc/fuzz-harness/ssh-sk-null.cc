/* $OpenBSD$ */
/*
 * Copyright (c) 2019 Google LLC
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

ਬਾਹਰੀ "C" {

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh-sk.h"

ਪੂਰਨ
sshsk_enroll(ਪੂਰਨ type, ਅਚਲ ਅੱਖਰ *provider_ਰਸਤਾ, ਅਚਲ ਅੱਖਰ *device,
    ਅਚਲ ਅੱਖਰ *application, ਅਚਲ ਅੱਖਰ *userid, uint8_t flags,
    ਅਚਲ ਅੱਖਰ *pin, ਬਣਤਰ sshbuf *challenge_buf,
    ਬਣਤਰ sshkey **keyp, ਬਣਤਰ sshbuf *attest)
{
	ਵਾਪਸ SSH_ERR_FEATURE_UNSUPPORTED;
}

ਪੂਰਨ
sshsk_sign(ਅਚਲ ਅੱਖਰ *provider_ਰਸਤਾ, ਬਣਤਰ sshkey *ਕੁੰਜੀ,
    u_char **sigp, ਮਾਪ_t *lenp, ਅਚਲ u_char *ਅੰਕੜੇ, ਮਾਪ_t datalen,
    u_int compat, ਅਚਲ ਅੱਖਰ *pin)
{
	ਵਾਪਸ SSH_ERR_FEATURE_UNSUPPORTED;
}

ਪੂਰਨ
sshsk_ਲੱਦੋ_resident(ਅਚਲ ਅੱਖਰ *provider_ਰਸਤਾ, ਅਚਲ ਅੱਖਰ *device,
    ਅਚਲ ਅੱਖਰ *pin, u_int flags, ਬਣਤਰ sshsk_resident_ਕੁੰਜੀ ***srksp,
    ਮਾਪ_t *nsrksp)
{
	ਵਾਪਸ SSH_ERR_FEATURE_UNSUPPORTED;
}

};
