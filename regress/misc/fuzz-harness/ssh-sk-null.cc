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

بیرونی "C" {

#شامل "includes.h"

#شامل <sys/types.h>

#شامل "ssherr.h"
#شامل "ssh-sk.h"

صحیح
sshsk_enroll(صحیح type, ثابت نویسه *provider_path, ثابت نویسه *device,
    ثابت نویسه *application, ثابت نویسه *userid, uint8_t flags,
    ثابت نویسه *pin, ساختار sshbuf *challenge_buf,
    ساختار sshkey **keyp, ساختار sshbuf *attest)
{
	بازگشت SSH_ERR_FEATURE_UNSUPPORTED;
}

صحیح
sshsk_sign(ثابت نویسه *provider_path, ساختار sshkey *کلید,
    u_char **sigp, size_t *lenp, ثابت u_char *data, size_t datalen,
    u_int compat, ثابت نویسه *pin)
{
	بازگشت SSH_ERR_FEATURE_UNSUPPORTED;
}

صحیح
sshsk_load_resident(ثابت نویسه *provider_path, ثابت نویسه *device,
    ثابت نویسه *pin, u_int flags, ساختار sshsk_resident_کلید ***srksp,
    size_t *nsrksp)
{
	بازگشت SSH_ERR_FEATURE_UNSUPPORTED;
}

};
