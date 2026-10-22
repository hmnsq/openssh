/*
 * Copyright (c) 2006 Chad Mynhier.
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

#अगर_अघोषित _PORT_SOLARIS_H

#समावेश <sys/types.h>

#समावेश <pwd.h>

व्योम solaris_contract_pre_fork(व्योम);
व्योम solaris_contract_post_fork_child(व्योम);
व्योम solaris_contract_post_fork_parent(pid_t pid);
व्योम solaris_set_default_project(काष्ठा passwd *);
# ifdef USE_SOLARIS_PRIVS
#समावेश <priv.h>
priv_set_t *solaris_basic_privset(व्योम);
व्योम solaris_drop_privs_pinfo_net_fork_exec(व्योम);
व्योम solaris_drop_privs_मूल_pinfo_net(व्योम);
व्योम solaris_drop_privs_मूल_pinfo_net_exec(व्योम);
# endif /* USE_SOLARIS_PRIVS */

#पूर्ण_अगर
