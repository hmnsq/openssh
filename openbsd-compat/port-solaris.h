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

#నిర్వచితం_కాకపోతే పోర్టు_SOLARIS_H

#అన్తర్భావ <sys/types.h>

#అన్తర్భావ <pwd.h>

శూన్య solaris_contract_pre_fork(శూన్య);
శూన్య solaris_contract_post_fork_బిడ్డ(శూన్య);
శూన్య solaris_contract_post_fork_మాతృ(pid_t pid);
శూన్య solaris_సమితి_default_project(నిర్మాణం passwd *);
# ifdef USE_SOLARIS_PRIVS
#అన్తర్భావ <priv.h>
priv_సమితి_t *solaris_basic_privset(శూన్య);
శూన్య solaris_drop_privs_pinfo_net_fork_exec(శూన్య);
శూన్య solaris_drop_privs_మూలం_pinfo_net(శూన్య);
శూన్య solaris_drop_privs_మూలం_pinfo_net_exec(శూన్య);
# endif /* USE_SOLARIS_PRIVS */

#అయితే_ముగింపు
