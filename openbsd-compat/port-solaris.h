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

#ifndef _PORT_SOLARIS_H

#شامل <sys/types.h>

#شامل <pwd.h>

تهی solaris_contract_pre_fork(تهی);
تهی solaris_contract_post_fork_child(تهی);
تهی solaris_contract_post_fork_parent(pid_t pid);
تهی solaris_set_default_project(ساختار passwd *);
# ifdef USE_SOLARIS_PRIVS
#شامل <priv.h>
priv_set_t *solaris_basic_privset(تهی);
تهی solaris_drop_privs_pinfo_net_fork_exec(تهی);
تهی solaris_drop_privs_ریشه_pinfo_net(تهی);
تهی solaris_drop_privs_ریشه_pinfo_net_exec(تهی);
# endif /* USE_SOLARIS_PRIVS */

#endif
