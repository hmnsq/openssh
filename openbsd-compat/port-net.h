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

#ifndef _PORT_TUN_H
#define _PORT_TUN_H

ಸಂರಚನಾ Channel;
ಸಂರಚನಾ ssh;

#ಯದಿ defined(SSH_TUN_LINUX) || defined(SSH_TUN_FREEBSD)
# define CUSTOM_SYS_TUN_OPEN
ಪೂರ್ಣಾಙ್ಕ	  sys_tun_open(ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ, ವರ್ಣ **);
#endif

#ಯದಿ defined(SSH_TUN_COMPAT_AF) || defined(SSH_TUN_PREPEND_AF)
# define SSH_TUN_FILTER
ಪೂರ್ಣಾಙ್ಕ	 sys_tun_infilter(ಸಂರಚನಾ ssh *, ಸಂರಚನಾ Channel *, ವರ್ಣ *, ಪೂರ್ಣಾಙ್ಕ);
u_char	*sys_tun_outfilter(ಸಂರಚನಾ ssh *, ಸಂರಚನಾ Channel *, u_char **, size_t *);
#endif

#ಯದಿ defined(SYS_RDOMAIN_LINUX)
# define HAVE_SYS_GET_RDOMAIN
# define HAVE_SYS_SET_RDOMAIN
# define HAVE_SYS_VALID_RDOMAIN
ವರ್ಣ *sys_get_rdomain(ಪೂರ್ಣಾಙ್ಕ fd);
ಪೂರ್ಣಾಙ್ಕ sys_set_rdomain(ಪೂರ್ಣಾಙ್ಕ fd, ಧ್ರುವ ವರ್ಣ *name);
ಪೂರ್ಣಾಙ್ಕ sys_valid_rdomain(ಧ್ರುವ ವರ್ಣ *name);
#endif

#ಯದಿ defined(SYS_RDOMAIN_XXX)
# define HAVE_SYS_SET_PROCESS_RDOMAIN
ಶೂನ್ಯ sys_set_process_rdomain(ಧ್ರುವ ವರ್ಣ *name);
#endif

#endif
