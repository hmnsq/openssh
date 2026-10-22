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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ _KRL_H
#ವ್ಯಾಖ್ಯಾನಿಸು _KRL_H

/* Functions to manage key revocation lists */

#ವ್ಯಾಖ್ಯಾನಿಸು KRL_MAGIC		"SSHKRL\n\0"
#ವ್ಯಾಖ್ಯಾನಿಸು KRL_FORMAT_ಆವೃತ್ತಿ	1

/* KRL section types */
#ವ್ಯಾಖ್ಯಾನಿಸು KRL_SECTION_CERTIFICATES	1
#ವ್ಯಾಖ್ಯಾನಿಸು KRL_SECTION_EXPLICIT_ಕೀಲಿ	2
#ವ್ಯಾಖ್ಯಾನಿಸು KRL_SECTION_FINGERPRINT_SHA1	3
#ವ್ಯಾಖ್ಯಾನಿಸು KRL_SECTION_SIGNATURE		4
#ವ್ಯಾಖ್ಯಾನಿಸು KRL_SECTION_FINGERPRINT_SHA256	5
#ವ್ಯಾಖ್ಯಾನಿಸು KRL_SECTION_EXTENSION		255

/* KRL_SECTION_CERTIFICATES subsection types */
#ವ್ಯಾಖ್ಯಾನಿಸು KRL_SECTION_CERT_SERIAL_LIST	0x20
#ವ್ಯಾಖ್ಯಾನಿಸು KRL_SECTION_CERT_SERIAL_RANGE	0x21
#ವ್ಯಾಖ್ಯಾನಿಸು KRL_SECTION_CERT_SERIAL_BITMAP	0x22
#ವ್ಯಾಖ್ಯಾನಿಸು KRL_SECTION_CERT_ಕೀಲಿ_ID		0x23
#ವ್ಯಾಖ್ಯಾನಿಸು KRL_SECTION_CERT_EXTENSION	0x39

ರಚನೆ sshkey;
ರಚನೆ sshbuf;
ರಚನೆ ssh_krl;

ರಚನೆ ssh_krl *ssh_krl_init(ಶೂನ್ಯ);
ಶೂನ್ಯ ssh_krl_free(ರಚನೆ ssh_krl *krl);
ಶೂನ್ಯ ssh_krl_ಗಣ_ಆವೃತ್ತಿ(ರಚನೆ ssh_krl *krl, uint64_t ಆವೃತ್ತಿ);
ಪೂರ್ಣಾಂಕ ssh_krl_ಗಣ_comment(ರಚನೆ ssh_krl *krl, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *comment);
ಪೂರ್ಣಾಂಕ ssh_krl_revoke_cert_by_serial(ರಚನೆ ssh_krl *krl,
    ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ca_ಕೀಲಿ, uint64_t serial);
ಪೂರ್ಣಾಂಕ ssh_krl_revoke_cert_by_serial_range(ರಚನೆ ssh_krl *krl,
    ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ca_ಕೀಲಿ, uint64_t lo, uint64_t hi);
ಪೂರ್ಣಾಂಕ ssh_krl_revoke_cert_by_ಕೀಲಿ_id(ರಚನೆ ssh_krl *krl,
    ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ca_ಕೀಲಿ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಕೀಲಿ_id);
ಪೂರ್ಣಾಂಕ ssh_krl_revoke_ಕೀಲಿ_explicit(ರಚನೆ ssh_krl *krl, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ);
ಪೂರ್ಣಾಂಕ ssh_krl_revoke_ಕೀಲಿ_sha1(ರಚನೆ ssh_krl *krl, ಸ್ಥಿರಾಂಕ u_char *p, ಗಾತ್ರ_t len);
ಪೂರ್ಣಾಂಕ ssh_krl_revoke_ಕೀಲಿ_sha256(ರಚನೆ ssh_krl *krl, ಸ್ಥಿರಾಂಕ u_char *p, ಗಾತ್ರ_t len);
ಪೂರ್ಣಾಂಕ ssh_krl_revoke_ಕೀಲಿ(ರಚನೆ ssh_krl *krl, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ);
ಪೂರ್ಣಾಂಕ ssh_krl_ಗಮ್ಯ_blob(ರಚನೆ ssh_krl *krl, ರಚನೆ sshbuf *buf);
ಪೂರ್ಣಾಂಕ ssh_krl_from_blob(ರಚನೆ sshbuf *buf, ರಚನೆ ssh_krl **krlp);
ಪೂರ್ಣಾಂಕ ssh_krl_check_ಕೀಲಿ(ರಚನೆ ssh_krl *krl, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ);
ಪೂರ್ಣಾಂಕ ssh_krl_file_ಒಳಗೊಂಡಿದೆ_ಕೀಲಿ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ);
ಪೂರ್ಣಾಂಕ krl_dump(ರಚನೆ ssh_krl *krl, FILE *f);

#ಆದರೆ_ಅಂತ್ಯ /* _KRL_H */

