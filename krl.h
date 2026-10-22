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
#define KRL_SECTION_EXPLICIT_ಕೀಲಿ	2
#define KRL_SECTION_FINGERPRINT_SHA1	3
#define KRL_SECTION_SIGNATURE		4
#define KRL_SECTION_FINGERPRINT_SHA256	5
#define KRL_SECTION_EXTENSION		255

/* KRL_SECTION_CERTIFICATES subsection types */
#define KRL_SECTION_CERT_SERIAL_LIST	0x20
#define KRL_SECTION_CERT_SERIAL_RANGE	0x21
#define KRL_SECTION_CERT_SERIAL_BITMAP	0x22
#define KRL_SECTION_CERT_ಕೀಲಿ_ID		0x23
#define KRL_SECTION_CERT_EXTENSION	0x39

ಸಂರಚನಾ sshkey;
ಸಂರಚನಾ sshbuf;
ಸಂರಚನಾ ssh_krl;

ಸಂರಚನಾ ssh_krl *ssh_krl_init(ಶೂನ್ಯ);
ಶೂನ್ಯ ssh_krl_free(ಸಂರಚನಾ ssh_krl *krl);
ಶೂನ್ಯ ssh_krl_set_version(ಸಂರಚನಾ ssh_krl *krl, uint64_t version);
ಪೂರ್ಣಾಙ್ಕ ssh_krl_set_comment(ಸಂರಚನಾ ssh_krl *krl, ಧ್ರುವ ವರ್ಣ *comment);
ಪೂರ್ಣಾಙ್ಕ ssh_krl_revoke_cert_by_serial(ಸಂರಚನಾ ssh_krl *krl,
    ಧ್ರುವ ಸಂರಚನಾ sshkey *ca_ಕೀಲಿ, uint64_t serial);
ಪೂರ್ಣಾಙ್ಕ ssh_krl_revoke_cert_by_serial_range(ಸಂರಚನಾ ssh_krl *krl,
    ಧ್ರುವ ಸಂರಚನಾ sshkey *ca_ಕೀಲಿ, uint64_t lo, uint64_t hi);
ಪೂರ್ಣಾಙ್ಕ ssh_krl_revoke_cert_by_ಕೀಲಿ_id(ಸಂರಚನಾ ssh_krl *krl,
    ಧ್ರುವ ಸಂರಚನಾ sshkey *ca_ಕೀಲಿ, ಧ್ರುವ ವರ್ಣ *ಕೀಲಿ_id);
ಪೂರ್ಣಾಙ್ಕ ssh_krl_revoke_ಕೀಲಿ_explicit(ಸಂರಚನಾ ssh_krl *krl, ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ);
ಪೂರ್ಣಾಙ್ಕ ssh_krl_revoke_ಕೀಲಿ_sha1(ಸಂರಚನಾ ssh_krl *krl, ಧ್ರುವ u_char *p, size_t len);
ಪೂರ್ಣಾಙ್ಕ ssh_krl_revoke_ಕೀಲಿ_sha256(ಸಂರಚನಾ ssh_krl *krl, ಧ್ರುವ u_char *p, size_t len);
ಪೂರ್ಣಾಙ್ಕ ssh_krl_revoke_ಕೀಲಿ(ಸಂರಚನಾ ssh_krl *krl, ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ);
ಪೂರ್ಣಾಙ್ಕ ssh_krl_to_blob(ಸಂರಚನಾ ssh_krl *krl, ಸಂರಚನಾ sshbuf *buf);
ಪೂರ್ಣಾಙ್ಕ ssh_krl_from_blob(ಸಂರಚನಾ sshbuf *buf, ಸಂರಚನಾ ssh_krl **krlp);
ಪೂರ್ಣಾಙ್ಕ ssh_krl_check_ಕೀಲಿ(ಸಂರಚನಾ ssh_krl *krl, ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ);
ಪೂರ್ಣಾಙ್ಕ ssh_krl_file_contains_ಕೀಲಿ(ಧ್ರುವ ವರ್ಣ *path, ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ);
ಪೂರ್ಣಾಙ್ಕ krl_dump(ಸಂರಚನಾ ssh_krl *krl, FILE *f);

#endif /* _KRL_H */

