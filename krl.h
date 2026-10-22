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
#define KRL_SECTION_EXPLICIT_कुंजी	2
#define KRL_SECTION_FINGERPRINT_SHA1	3
#define KRL_SECTION_SIGNATURE		4
#define KRL_SECTION_FINGERPRINT_SHA256	5
#define KRL_SECTION_EXTENSION		255

/* KRL_SECTION_CERTIFICATES subsection types */
#define KRL_SECTION_CERT_SERIAL_LIST	0x20
#define KRL_SECTION_CERT_SERIAL_RANGE	0x21
#define KRL_SECTION_CERT_SERIAL_BITMAP	0x22
#define KRL_SECTION_CERT_कुंजी_ID		0x23
#define KRL_SECTION_CERT_EXTENSION	0x39

संरचना sshkey;
संरचना sshbuf;
संरचना ssh_krl;

संरचना ssh_krl *ssh_krl_init(शून्य);
शून्य ssh_krl_free(संरचना ssh_krl *krl);
शून्य ssh_krl_set_version(संरचना ssh_krl *krl, uint64_t version);
पूर्णाङ्क ssh_krl_set_comment(संरचना ssh_krl *krl, ध्रुव वर्ण *comment);
पूर्णाङ्क ssh_krl_revoke_cert_by_serial(संरचना ssh_krl *krl,
    ध्रुव संरचना sshkey *ca_कुंजी, uint64_t serial);
पूर्णाङ्क ssh_krl_revoke_cert_by_serial_range(संरचना ssh_krl *krl,
    ध्रुव संरचना sshkey *ca_कुंजी, uint64_t lo, uint64_t hi);
पूर्णाङ्क ssh_krl_revoke_cert_by_कुंजी_id(संरचना ssh_krl *krl,
    ध्रुव संरचना sshkey *ca_कुंजी, ध्रुव वर्ण *कुंजी_id);
पूर्णाङ्क ssh_krl_revoke_कुंजी_explicit(संरचना ssh_krl *krl, ध्रुव संरचना sshkey *कुंजी);
पूर्णाङ्क ssh_krl_revoke_कुंजी_sha1(संरचना ssh_krl *krl, ध्रुव u_char *p, माप_प्रकार len);
पूर्णाङ्क ssh_krl_revoke_कुंजी_sha256(संरचना ssh_krl *krl, ध्रुव u_char *p, माप_प्रकार len);
पूर्णाङ्क ssh_krl_revoke_कुंजी(संरचना ssh_krl *krl, ध्रुव संरचना sshkey *कुंजी);
पूर्णाङ्क ssh_krl_to_blob(संरचना ssh_krl *krl, संरचना sshbuf *buf);
पूर्णाङ्क ssh_krl_from_blob(संरचना sshbuf *buf, संरचना ssh_krl **krlp);
पूर्णाङ्क ssh_krl_check_कुंजी(संरचना ssh_krl *krl, ध्रुव संरचना sshkey *कुंजी);
पूर्णाङ्क ssh_krl_file_contains_कुंजी(ध्रुव वर्ण *path, ध्रुव संरचना sshkey *कुंजी);
पूर्णाङ्क krl_dump(संरचना ssh_krl *krl, खाता *f);

#endif /* _KRL_H */

