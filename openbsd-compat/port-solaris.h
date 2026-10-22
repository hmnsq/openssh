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

#جے_بنا_تعریف پورٹ_SOLARIS_H

#ضمن <sys/types.h>

#ضمن <pwd.h>

فراغ solaris_contract_pre_fork(فراغ);
فراغ solaris_contract_post_fork_بچہ(فراغ);
فراغ solaris_contract_post_fork_ماپا(pid_t pid);
فراغ solaris_سیٹ_default_project(بنية passwd *);
# ifdef USE_SOLARIS_PRIVS
#ضمن <priv.h>
priv_سیٹ_t *solaris_basic_privset(فراغ);
فراغ solaris_drop_privs_pinfo_net_fork_exec(فراغ);
فراغ solaris_drop_privs_جڑ_pinfo_net(فراغ);
فراغ solaris_drop_privs_جڑ_pinfo_net_exec(فراغ);
# endif /* USE_SOLARIS_PRIVS */

#جے_انت
