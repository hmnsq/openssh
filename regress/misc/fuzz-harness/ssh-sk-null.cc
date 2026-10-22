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

خارجي "C" {

#ضمن "includes.h"

#ضمن <sys/types.h>

#ضمن "ssherr.h"
#ضمن "ssh-sk.h"

صحيح
sshsk_enroll(صحيح type, ثابت حرف *provider_مسیر, ثابت حرف *device,
    ثابت حرف *application, ثابت حرف *userid, uint8_t flags,
    ثابت حرف *pin, بنية sshbuf *challenge_buf,
    بنية sshkey **keyp, بنية sshbuf *attest)
{
	أرجع SSH_ERR_FEATURE_UNSUPPORTED;
}

صحيح
sshsk_sign(ثابت حرف *provider_مسیر, بنية sshkey *کلید,
    u_char **sigp, اندازه_t *lenp, ثابت u_char *داده, اندازه_t datalen,
    u_int compat, ثابت حرف *pin)
{
	أرجع SSH_ERR_FEATURE_UNSUPPORTED;
}

صحيح
sshsk_بارگیری_resident(ثابت حرف *provider_مسیر, ثابت حرف *device,
    ثابت حرف *pin, u_int flags, بنية sshsk_resident_کلید ***srksp,
    اندازه_t *nsrksp)
{
	أرجع SSH_ERR_FEATURE_UNSUPPORTED;
}

};
