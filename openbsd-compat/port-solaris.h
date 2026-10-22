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

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ ਪੋਰਟ_SOLARIS_H

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <pwd.h>

ਖਾਲੀ solaris_contract_pre_fork(ਖਾਲੀ);
ਖਾਲੀ solaris_contract_post_fork_ਬੱਚਾ(ਖਾਲੀ);
ਖਾਲੀ solaris_contract_post_fork_ਮਾਪਾ(pid_t pid);
ਖਾਲੀ solaris_ਸੈੱਟ_default_project(ਬਣਤਰ passwd *);
# ifdef USE_SOLARIS_PRIVS
#ਅਨ੍ਤਰ੍ਭਾਵ <priv.h>
priv_ਸੈੱਟ_t *solaris_basic_privset(ਖਾਲੀ);
ਖਾਲੀ solaris_drop_privs_pinfo_net_fork_exec(ਖਾਲੀ);
ਖਾਲੀ solaris_drop_privs_ਜੜ੍ਹ_pinfo_net(ਖਾਲੀ);
ਖਾਲੀ solaris_drop_privs_ਜੜ੍ਹ_pinfo_net_exec(ਖਾਲੀ);
# endif /* USE_SOLARIS_PRIVS */

#ਜੇ_ਅੰਤ
