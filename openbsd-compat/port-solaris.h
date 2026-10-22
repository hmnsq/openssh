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

#यदि_अपरिभाषितम् पत्तनम्_SOLARIS_H

#अन्तर्भाव <sys/types.h>

#अन्तर्भाव <pwd.h>

शून्य solaris_contract_pre_fork(शून्य);
शून्य solaris_contract_post_fork_child(शून्य);
शून्य solaris_contract_post_fork_parent(pid_t pid);
शून्य solaris_समुच्चयः_default_project(संरचना passwd *);
# ifdef USE_SOLARIS_PRIVS
#अन्तर्भाव <priv.h>
priv_समुच्चयः_t *solaris_basic_privset(शून्य);
शून्य solaris_drop_privs_pinfo_net_fork_exec(शून्य);
शून्य solaris_drop_privs_मूलम्_pinfo_net(शून्य);
शून्य solaris_drop_privs_मूलम्_pinfo_net_exec(शून्य);
# endif /* USE_SOLARIS_PRIVS */

#यदि_अन्तः
