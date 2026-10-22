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

ബാഹ്യ "C" {

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>

#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "ssh-sk.h"

പൂർണ്ണസംഖ്യ
sshsk_enroll(പൂർണ്ണസംഖ്യ type, സ്ഥിരം അക്ഷരം *provider_path, സ്ഥിരം അക്ഷരം *device,
    സ്ഥിരം അക്ഷരം *application, സ്ഥിരം അക്ഷരം *userid, uint8_t flags,
    സ്ഥിരം അക്ഷരം *pin, ഘടന sshbuf *challenge_buf,
    ഘടന sshkey **keyp, ഘടന sshbuf *attest)
{
	തിരികെ SSH_ERR_FEATURE_UNSUPPORTED;
}

പൂർണ്ണസംഖ്യ
sshsk_sign(സ്ഥിരം അക്ഷരം *provider_path, ഘടന sshkey *താക്കോൽ,
    u_char **sigp, size_t *lenp, സ്ഥിരം u_char *data, size_t datalen,
    u_int compat, സ്ഥിരം അക്ഷരം *pin)
{
	തിരികെ SSH_ERR_FEATURE_UNSUPPORTED;
}

പൂർണ്ണസംഖ്യ
sshsk_load_resident(സ്ഥിരം അക്ഷരം *provider_path, സ്ഥിരം അക്ഷരം *device,
    സ്ഥിരം അക്ഷരം *pin, u_int flags, ഘടന sshsk_resident_താക്കോൽ ***srksp,
    size_t *nsrksp)
{
	തിരികെ SSH_ERR_FEATURE_UNSUPPORTED;
}

};
