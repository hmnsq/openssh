/*
 * Copyright (c) 2012 Damien Miller <djm@mindrot.org>
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

/* $OpenBSD: krl.h,v 1.11 2026/03/03 09:57:25 dtucker Exp $ */

#ifndef _KRL_H
#define _KRL_H

/* Functions to manage key revocation lists */

#define KRL_MAGIC		"SSHKRL\n\0"
#define KRL_FORMAT_VERSION	1

/* KRL section types */
#define KRL_SECTION_CERTIFICATES	1
#define KRL_SECTION_EXPLICIT_ଚାବି	2
#define KRL_SECTION_FINGERPRINT_SHA1	3
#define KRL_SECTION_SIGNATURE		4
#define KRL_SECTION_FINGERPRINT_SHA256	5
#define KRL_SECTION_EXTENSION		255

/* KRL_SECTION_CERTIFICATES subsection types */
#define KRL_SECTION_CERT_SERIAL_LIST	0x20
#define KRL_SECTION_CERT_SERIAL_RANGE	0x21
#define KRL_SECTION_CERT_SERIAL_BITMAP	0x22
#define KRL_SECTION_CERT_ଚାବି_ID		0x23
#define KRL_SECTION_CERT_EXTENSION	0x39

ସଂରଚନା sshkey;
ସଂରଚନା sshbuf;
ସଂରଚନା ssh_krl;

ସଂରଚନା ssh_krl *ssh_krl_init(ଶୂନ୍ୟ);
ଶୂନ୍ୟ ssh_krl_free(ସଂରଚନା ssh_krl *krl);
ଶୂନ୍ୟ ssh_krl_set_version(ସଂରଚନା ssh_krl *krl, uint64_t version);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା ssh_krl_set_comment(ସଂରଚନା ssh_krl *krl, ଅଚଳ ଅକ୍ଷର *comment);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା ssh_krl_revoke_cert_by_serial(ସଂରଚନା ssh_krl *krl,
    ଅଚଳ ସଂରଚନା sshkey *ca_ଚାବି, uint64_t serial);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା ssh_krl_revoke_cert_by_serial_range(ସଂରଚନା ssh_krl *krl,
    ଅଚଳ ସଂରଚନା sshkey *ca_ଚାବି, uint64_t lo, uint64_t hi);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା ssh_krl_revoke_cert_by_ଚାବି_id(ସଂରଚନା ssh_krl *krl,
    ଅଚଳ ସଂରଚନା sshkey *ca_ଚାବି, ଅଚଳ ଅକ୍ଷର *ଚାବି_id);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା ssh_krl_revoke_ଚାବି_explicit(ସଂରଚନା ssh_krl *krl, ଅଚଳ ସଂରଚନା sshkey *ଚାବି);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା ssh_krl_revoke_ଚାବି_sha1(ସଂରଚନା ssh_krl *krl, ଅଚଳ u_char *p, size_t len);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା ssh_krl_revoke_ଚାବି_sha256(ସଂରଚନା ssh_krl *krl, ଅଚଳ u_char *p, size_t len);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା ssh_krl_revoke_ଚାବି(ସଂରଚନା ssh_krl *krl, ଅଚଳ ସଂରଚନା sshkey *ଚାବି);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା ssh_krl_to_blob(ସଂରଚନା ssh_krl *krl, ସଂରଚନା sshbuf *buf);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା ssh_krl_from_blob(ସଂରଚନା sshbuf *buf, ସଂରଚନା ssh_krl **krlp);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା ssh_krl_check_ଚାବି(ସଂରଚନା ssh_krl *krl, ଅଚଳ ସଂରଚନା sshkey *ଚାବି);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା ssh_krl_file_contains_ଚାବି(ଅଚଳ ଅକ୍ଷର *path, ଅଚଳ ସଂରଚନା sshkey *ଚାବି);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା krl_dump(ସଂରଚନା ssh_krl *krl, FILE *f);

#endif /* _KRL_H */

