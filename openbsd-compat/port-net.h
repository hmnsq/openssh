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

#अगर_अघोषित _PORT_TUN_H
#घोषणा _PORT_TUN_H

काष्ठा Channel;
काष्ठा ssh;

#अगर defined(SSH_TUN_LINUX) || defined(SSH_TUN_FREEBSD)
# define CUSTOM_SYS_TUN_OPEN
पूर्णांक	  sys_tun_open(पूर्णांक, पूर्णांक, अक्षर **);
#पूर्ण_अगर

#अगर defined(SSH_TUN_COMPAT_AF) || defined(SSH_TUN_PREPEND_AF)
# define SSH_TUN_FILTER
पूर्णांक	 sys_tun_infilter(काष्ठा ssh *, काष्ठा Channel *, अक्षर *, पूर्णांक);
u_char	*sys_tun_outfilter(काष्ठा ssh *, काष्ठा Channel *, u_char **, माप_प्रकार *);
#पूर्ण_अगर

#अगर defined(SYS_RDOMAIN_LINUX)
# define HAVE_SYS_GET_RDOMAIN
# define HAVE_SYS_SET_RDOMAIN
# define HAVE_SYS_VALID_RDOMAIN
अक्षर *sys_get_rdomain(पूर्णांक fd);
पूर्णांक sys_set_rdomain(पूर्णांक fd, स्थिर अक्षर *name);
पूर्णांक sys_valid_rdomain(स्थिर अक्षर *name);
#पूर्ण_अगर

#अगर defined(SYS_RDOMAIN_XXX)
# define HAVE_SYS_SET_PROCESS_RDOMAIN
व्योम sys_set_process_rdomain(स्थिर अक्षर *name);
#पूर्ण_अगर

#पूर्ण_अगर
