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

బాహ్య "C" {

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>

#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "ssh-sk.h"

పూర్ణాంకం
sshsk_enroll(పూర్ణాంకం type, స్థిరరాశి అక్షరం *provider_మార్గం, స్థిరరాశి అక్షరం *device,
    స్థిరరాశి అక్షరం *application, స్థిరరాశి అక్షరం *userid, uint8_t flags,
    స్థిరరాశి అక్షరం *pin, నిర్మాణం sshbuf *challenge_buf,
    నిర్మాణం sshkey **keyp, నిర్మాణం sshbuf *attest)
{
	తిరిగి SSH_ERR_FEATURE_UNSUPPORTED;
}

పూర్ణాంకం
sshsk_sign(స్థిరరాశి అక్షరం *provider_మార్గం, నిర్మాణం sshkey *కీలకం,
    u_char **sigp, కొలత_t *lenp, స్థిరరాశి u_char *దత్తాంశం, కొలత_t datalen,
    u_int compat, స్థిరరాశి అక్షరం *pin)
{
	తిరిగి SSH_ERR_FEATURE_UNSUPPORTED;
}

పూర్ణాంకం
sshsk_ఎక్కించు_resident(స్థిరరాశి అక్షరం *provider_మార్గం, స్థిరరాశి అక్షరం *device,
    స్థిరరాశి అక్షరం *pin, u_int flags, నిర్మాణం sshsk_resident_కీలకం ***srksp,
    కొలత_t *nsrksp)
{
	తిరిగి SSH_ERR_FEATURE_UNSUPPORTED;
}

};
