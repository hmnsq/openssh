/*
 * Copyright (c) 2005 Reyk Floeter <reyk@openbsd.org>
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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ ಪೋರ್ಟ್_TUN_H
#ವ್ಯಾಖ್ಯಾನಿಸು ಪೋರ್ಟ್_TUN_H

ರಚನೆ Channel;
ರಚನೆ ssh;

#ಆದರೆ defined(SSH_TUN_LINUX) || defined(SSH_TUN_FREEBSD)
# define CUSTOM_SYS_TUN_OPEN
ಪೂರ್ಣಾಂಕ	  sys_tun_open(ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ಅಕ್ಷರ **);
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ defined(SSH_TUN_COMPAT_AF) || defined(SSH_TUN_PREPEND_AF)
# define SSH_TUN_FILTER
ಪೂರ್ಣಾಂಕ	 sys_tun_infilter(ರಚನೆ ssh *, ರಚನೆ Channel *, ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ);
u_char	*sys_tun_outfilter(ರಚನೆ ssh *, ರಚನೆ Channel *, u_char **, ಗಾತ್ರ_t *);
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ defined(SYS_RDOMAIN_LINUX)
# define HAVE_SYS_GET_RDOMAIN
# define HAVE_SYS_ಗಣ_RDOMAIN
# define HAVE_SYS_VALID_RDOMAIN
ಅಕ್ಷರ *sys_get_rdomain(ಪೂರ್ಣಾಂಕ fd);
ಪೂರ್ಣಾಂಕ sys_ಗಣ_rdomain(ಪೂರ್ಣಾಂಕ fd, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name);
ಪೂರ್ಣಾಂಕ sys_valid_rdomain(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name);
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ defined(SYS_RDOMAIN_XXX)
# define HAVE_SYS_ಗಣ_PROCESS_RDOMAIN
ಶೂನ್ಯ sys_ಗಣ_process_rdomain(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name);
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ_ಅಂತ್ಯ
