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

ഘടന Channel;
ഘടന ssh;

#എങ്കിൽ defined(SSH_TUN_LINUX) || defined(SSH_TUN_FREEBSD)
# define CUSTOM_SYS_TUN_OPEN
പൂർണ്ണസംഖ്യ	  sys_tun_open(പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ, അക്ഷരം **);
#endif

#എങ്കിൽ defined(SSH_TUN_COMPAT_AF) || defined(SSH_TUN_PREPEND_AF)
# define SSH_TUN_FILTER
പൂർണ്ണസംഖ്യ	 sys_tun_infilter(ഘടന ssh *, ഘടന Channel *, അക്ഷരം *, പൂർണ്ണസംഖ്യ);
u_char	*sys_tun_outfilter(ഘടന ssh *, ഘടന Channel *, u_char **, size_t *);
#endif

#എങ്കിൽ defined(SYS_RDOMAIN_LINUX)
# define HAVE_SYS_GET_RDOMAIN
# define HAVE_SYS_SET_RDOMAIN
# define HAVE_SYS_VALID_RDOMAIN
അക്ഷരം *sys_get_rdomain(പൂർണ്ണസംഖ്യ fd);
പൂർണ്ണസംഖ്യ sys_set_rdomain(പൂർണ്ണസംഖ്യ fd, സ്ഥിരം അക്ഷരം *name);
പൂർണ്ണസംഖ്യ sys_valid_rdomain(സ്ഥിരം അക്ഷരം *name);
#endif

#എങ്കിൽ defined(SYS_RDOMAIN_XXX)
# define HAVE_SYS_SET_PROCESS_RDOMAIN
ശൂന്യം sys_set_process_rdomain(സ്ഥിരം അക്ഷരം *name);
#endif

#endif
