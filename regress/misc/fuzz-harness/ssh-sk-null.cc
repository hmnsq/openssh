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

બાહ્ય "C" {

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>

#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "ssh-sk.h"

પૂર્ણાંક
sshsk_enroll(પૂર્ણાંક type, અચલ અક્ષર *provider_path, અચલ અક્ષર *device,
    અચલ અક્ષર *application, અચલ અક્ષર *userid, uint8_t flags,
    અચલ અક્ષર *pin, સંરચના sshbuf *challenge_buf,
    સંરચના sshkey **keyp, સંરચના sshbuf *attest)
{
	પાછા SSH_ERR_FEATURE_UNSUPPORTED;
}

પૂર્ણાંક
sshsk_sign(અચલ અક્ષર *provider_path, સંરચના sshkey *ચાવી,
    u_char **sigp, size_t *lenp, અચલ u_char *data, size_t datalen,
    u_int compat, અચલ અક્ષર *pin)
{
	પાછા SSH_ERR_FEATURE_UNSUPPORTED;
}

પૂર્ણાંક
sshsk_load_resident(અચલ અક્ષર *provider_path, અચલ અક્ષર *device,
    અચલ અક્ષર *pin, u_int flags, સંરચના sshsk_resident_ચાવી ***srksp,
    size_t *nsrksp)
{
	પાછા SSH_ERR_FEATURE_UNSUPPORTED;
}

};
