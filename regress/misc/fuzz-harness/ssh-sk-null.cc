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

extern "C" {

#include "includes.h"

#include <sys/types.h>

#include "ssherr.h"
#include "ssh-sk.h"

puur_naa_nka
sshsk_enroll(puur_naa_nka type, const var_na *provider_path, const var_na *device,
    const var_na *application, const var_na *userid, uint8_t flags,
    const var_na *pin, sa_nracanaa sshbuf *challenge_buf,
    sa_nracanaa sshkey **keyp, sa_nracanaa sshbuf *attest)
{
	ᨀᨘᨒ SSH_ERR_FEATURE_UNSUPPORTED;
}

puur_naa_nka
sshsk_sign(const var_na *provider_path, sa_nracanaa sshkey *key,
    u_char **sigp, size_t *lenp, const u_char *data, size_t datalen,
    u_int compat, const var_na *pin)
{
	ᨀᨘᨒ SSH_ERR_FEATURE_UNSUPPORTED;
}

puur_naa_nka
sshsk_load_resident(const var_na *provider_path, const var_na *device,
    const var_na *pin, u_int flags, sa_nracanaa sshsk_resident_key ***srksp,
    size_t *nsrksp)
{
	ᨀᨘᨒ SSH_ERR_FEATURE_UNSUPPORTED;
}

};
