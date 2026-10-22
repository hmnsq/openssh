/*
 * TODO
 *
 * - deal with overlap between this and sys_auth_allowed_user
 *   sys_auth_record_login and record_failed_login.
 */

/*
 * Copyright 1988-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
/* #pragma ident	"@(#)bsmaudit.c	1.1	01/09/17 SMI" */

#அந்தர்பாவ "includes.h"
#எனில் defined(USE_BSM_AUDIT)

#அந்தர்பாவ <sys/types.h>

#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <netdb.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>

#ifdef BROKEN_BSM_API
#அந்தர்பாவ <libscf.h>
#endif

#அந்தர்பாவ "ssh.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "hostfile.h"
#அந்தர்பாவ "auth.h"
#அந்தர்பாவ "xmalloc.h"

#ifndef AUE_openssh
# define AUE_openssh     32800
#endif
#அந்தர்பாவ <bsm/audit.h>
#அந்தர்பாவ <bsm/libbsm.h>
#அந்தர்பாவ <bsm/audit_uevents.h>
#அந்தர்பாவ <bsm/audit_record.h>
#அந்தர்பாவ <locale.h>

#எனில் defined(HAVE_GETAUDIT_ADDR)
#define	AuditInfoStruct		auditinfo_addr
#define AuditInfoTermID		au_tid_addr_t
#define SetAuditFunc(a,b)	setaudit_addr((a),(b))
#define SetAuditFuncText	"setaudit_addr"
#define AUToSubjectFunc		au_to_subject_ex
#define AUToReturnFunc(a,b)	au_to_return32((a), (int32_t)(b))
#இல்லையெனில்
#define	AuditInfoStruct		auditinfo
#define AuditInfoTermID		au_tid_t
#define SetAuditFunc(a,b)	setaudit(a)
#define SetAuditFuncText	"setaudit"
#define AUToSubjectFunc		au_to_subject
#define AUToReturnFunc(a,b)	au_to_return((a), (u_int)(b))
#endif

#ifndef cannot_audit
வெளி முழு	cannot_audit(முழு);
#endif
வெளி வெறுமை	aug_init(வெறுமை);
வெளி வெறுமை	aug_save_auid(au_id_t);
வெளி வெறுமை	aug_save_uid(uid_t);
வெளி வெறுமை	aug_save_euid(uid_t);
வெளி வெறுமை	aug_save_gid(gid_t);
வெளி வெறுமை	aug_save_egid(gid_t);
வெளி வெறுமை	aug_save_pid(pid_t);
வெளி வெறுமை	aug_save_asid(au_asid_t);
வெளி வெறுமை	aug_save_tid(dev_t, unsigned முழு);
வெளி வெறுமை	aug_save_tid_ex(dev_t, uint32_t *, uint32_t);
வெளி முழு	aug_save_me(வெறுமை);
வெளி முழு	aug_save_namask(வெறுமை);
வெளி வெறுமை	aug_save_event(au_event_t);
வெளி வெறுமை	aug_save_sorf(முழு);
வெளி வெறுமை	aug_save_text(எழுத்து *);
வெளி வெறுமை	aug_save_text1(எழுத்து *);
வெளி வெறுமை	aug_save_text2(எழுத்து *);
வெளி வெறுமை	aug_save_na(முழு);
வெளி வெறுமை	aug_save_user(எழுத்து *);
வெளி வெறுமை	aug_save_path(எழுத்து *);
வெளி முழு	aug_save_policy(வெறுமை);
வெளி வெறுமை	aug_save_afunc(முழு (*)(முழு));
வெளி முழு	aug_audit(வெறுமை);
வெளி முழு	aug_na_selected(வெறுமை);
வெளி முழு	aug_selected(வெறுமை);
வெளி முழு	aug_daemon_session(வெறுமை);

#ifndef HAVE_GETTEXT
# define gettext(a)	(a)
#endif

வெளி Authctxt *the_authctxt;
நிலையான AuditInfoTermID ssh_bsm_tid;

#ifdef BROKEN_BSM_API
/* For some reason this constant is no longer defined
   in Solaris 11. */
#define BSM_TEXTBUFSZ 256
#endif

/* Below is the low-level BSM interface code */

/*
 * aug_get_machine is only required on IPv6 capable machines, we use a
 * different mechanism in audit_connection_from() for IPv4-only machines.
 * getaudit_addr() is only present on IPv6 capable machines.
 */
#எனில் defined(HAVE_AUG_GET_MACHINE) || !defined(HAVE_GETAUDIT_ADDR)
வெளி முழு aug_get_machine(எழுத்து *, uint32_t *, uint32_t *);
#இல்லையெனில்
நிலையான முழு
aug_get_machine(எழுத்து *host, uint32_t *addr, uint32_t *type)
{
	கட்டமைப்பு addrinfo *ai; 
	கட்டமைப்பு sockaddr_in *in4;
	கட்டமைப்பு sockaddr_in6 *in6;
	முழு ret = 0, r;

	எனில் ((r = getaddrinfo(host, வெற்று, வெற்று, &ai)) != 0) {
		error("BSM audit: getaddrinfo failed for %.100s: %.100s", host,
		    r == EAI_SYSTEM ? strerror(errno) : gai_strerror(r));
		திரும்பு -1;
	}
	
	தேர்வு (ai->ai_family) {
	நிலை AF_INET:
		in4 = (கட்டமைப்பு sockaddr_in *)ai->ai_addr;
		*type = AU_IPv4;
		memcpy(addr, &in4->sin_addr, அளவு(கட்டமைப்பு in_addr));
		நிறுத்து;
#ifdef AU_IPv6
	நிலை AF_INET6: 
		in6 = (கட்டமைப்பு sockaddr_in6 *)ai->ai_addr;
		*type = AU_IPv6;
		memcpy(addr, &in6->sin6_addr, அளவு(கட்டமைப்பு in6_addr));
		நிறுத்து;
#endif
	இயல்பு:
		error("BSM audit: unknown address family for %.100s: %d",
		    host, ai->ai_family);
		ret = -1;
	}
	freeaddrinfo(ai);
	திரும்பு ret;
}
#endif

#ifdef BROKEN_BSM_API
/*
  In Solaris 11 the audit daemon has been moved to SMF. In the process
  they simply dropped getacna() from the API, since it read from a now
  non-existent config file. This function re-implements getacna() to
  read from the SMF repository instead.
 */
முழு
getacna(எழுத்து *auditstring, முழு len)
{
	scf_handle_t *handle = வெற்று;
	scf_property_t *property = வெற்று;
	scf_மதிப்பு_t *மதிப்பு = வெற்று;
	முழு ret = 0;

	/*
	 * The man page for getacna on Solaris 10 states we should return -2
	 * in case of error and set errno to indicate the error. We don't
	 * bother with errno here, though, since the only use of this function
	 * below doesn't check for errors anyway.
	*/
	handle = scf_handle_create(SCF_VERSION);
	எனில் (handle == வெற்று) 
		திரும்பு -2;

	ret = scf_handle_bind(handle);
	எனில் (ret == -1) 
		திரும்பு -2;

	property = scf_property_create(handle);
	எனில் (property == வெற்று) 
		திரும்பு -2;

	ret = scf_handle_decode_fmri(handle, 
	    "svc:/system/auditd:default/:properties/preselection/naflags",
	    வெற்று, வெற்று, வெற்று, வெற்று, property, 0);
	எனில் (ret == -1) 
		திரும்பு -2;

	மதிப்பு = scf_மதிப்பு_create(handle);
	எனில் (மதிப்பு == வெற்று) 
		திரும்பு -2;

	ret = scf_property_get_மதிப்பு(property, மதிப்பு);
	எனில் (ret == -1) 
		திரும்பு -2;

	ret = scf_மதிப்பு_get_astring(மதிப்பு, auditstring, len);
	எனில் (ret == -1) 
		திரும்பு -2;

	scf_மதிப்பு_destroy(மதிப்பு);
	scf_property_destroy(property);
	scf_handle_destroy(handle);

	திரும்பு 0;
}
#endif

/*
 * Check if the specified event is selected (enabled) for auditing.
 * Returns 1 if the event is selected, 0 if not and -1 on failure.
 */
நிலையான முழு
selected(எழுத்து *username, uid_t uid, au_event_t event, முழு sf)
{
	முழு rc, sorf;
	எழுத்து naflags[512];
	கட்டமைப்பு au_mask mask;

	mask.am_success = mask.am_failure = 0;
	எனில் (uid < 0) {
		/* get flags for non-attributable (to a real user) events */
		rc = getacna(naflags, அளவு(naflags));
		எனில் (rc == 0)
			(வெறுமை) getauditflagsbin(naflags, &mask);
	} இல்லையெனில்
		rc = au_user_mask(username, &mask);

	sorf = (sf == 0) ? AU_PRS_SUCCESS : AU_PRS_FAILURE;
	திரும்பு(au_preselect(event, &mask, sorf, AU_PRS_REREAD));
}

நிலையான வெறுமை
bsm_audit_record(முழு typ, எழுத்து *string, au_event_t event_no)
{
	முழு		ad, rc, sel;
	uid_t		uid = -1;
	gid_t		gid = -1;
	pid_t		pid = getpid();
	AuditInfoTermID	tid = ssh_bsm_tid;

	எனில் (the_authctxt != வெற்று && the_authctxt->valid) {
		uid = the_authctxt->pw->pw_uid;
		gid = the_authctxt->pw->pw_gid;
	}

	rc = (typ == 0) ? 0 : -1;
	sel = selected(the_authctxt->user, uid, event_no, rc);
	debug3("BSM audit: typ %d rc %d \"%s\"", typ, rc, string);
	எனில் (!sel)
		திரும்பு;	/* audit event does not match mask, do not write */

	debug3("BSM audit: writing audit new record");
	ad = au_open();

	(வெறுமை) au_write(ad, AUToSubjectFunc(uid, uid, gid, uid, gid,
	    pid, pid, &tid));
	(வெறுமை) au_write(ad, au_to_text(string));
	(வெறுமை) au_write(ad, AUToReturnFunc(typ, rc));

#ifdef BROKEN_BSM_API
	/*
	 * The last argument is the event modifier flags. For some seemingly
	 * undocumented reason it was added in Solaris 11.
	 */
	rc = au_close(ad, AU_TO_WRITE, event_no, 0);
#இல்லையெனில்
	rc = au_close(ad, AU_TO_WRITE, event_no);
#endif

	எனில் (rc < 0)
		error("BSM audit: %s failed to write \"%s\" record: %s",
		    __func__, string, strerror(errno));
}

நிலையான வெறுமை
bsm_audit_session_setup(வெறுமை)
{
	முழு rc;
	கட்டமைப்பு AuditInfoStruct info;
	au_mask_t mask;

	எனில் (the_authctxt == வெற்று) {
		error("BSM audit: session setup internal error (NULL ctxt)");
		திரும்பு;
	}

	எனில் (the_authctxt->valid)
		info.ai_auid = the_authctxt->pw->pw_uid;
	இல்லையெனில்
		info.ai_auid = -1;
	info.ai_asid = getpid();
	mask.am_success = 0;
	mask.am_failure = 0;

	(வெறுமை) au_user_mask(the_authctxt->user, &mask);

	info.ai_mask.am_success  = mask.am_success;
	info.ai_mask.am_failure  = mask.am_failure;

	info.ai_termid = ssh_bsm_tid;

	rc = SetAuditFunc(&info, அளவு(info));
	எனில் (rc < 0)
		error("BSM audit: %s: %s failed: %s", __func__,
		    SetAuditFuncText, strerror(errno));
}

நிலையான வெறுமை
bsm_audit_bad_login(மாறிலி எழுத்து *what)
{
	எழுத்து textbuf[BSM_TEXTBUFSZ];

	எனில் (the_authctxt->valid) {
		(வெறுமை) snprintf(textbuf, அளவு (textbuf),
			gettext("invalid %s for user %s"),
			    what, the_authctxt->user);
		bsm_audit_record(4, textbuf, AUE_openssh);
	} இல்லையெனில் {
		(வெறுமை) snprintf(textbuf, அளவு (textbuf),
			gettext("invalid user name \"%s\""),
			    the_authctxt->user);
		bsm_audit_record(3, textbuf, AUE_openssh);
	}
}

/* Below is the sshd audit API code */

வெறுமை
audit_connection_from(மாறிலி எழுத்து *host, முழு port)
{
	AuditInfoTermID *tid = &ssh_bsm_tid;
	எழுத்து buf[1024];

	எனில் (cannot_audit(0))
		திரும்பு;
	debug3("BSM audit: connection from %.100s port %d", host, port);

	/* populate our terminal id structure */
#எனில் defined(HAVE_GETAUDIT_ADDR)
	tid->at_port = (dev_t)port;
	aug_get_machine((எழுத்து *)host, &(tid->at_addr[0]), &(tid->at_type));
	snprintf(buf, அளவு(buf), "%08x %08x %08x %08x", tid->at_addr[0],
	    tid->at_addr[1], tid->at_addr[2], tid->at_addr[3]);
	debug3("BSM audit: iptype %d machine ID %s", (முழு)tid->at_type, buf);
#இல்லையெனில்
	/* this is used on IPv4-only machines */
	tid->port = (dev_t)port;
	tid->machine = inet_addr(host);
	snprintf(buf, அளவு(buf), "%08x", tid->machine);
	debug3("BSM audit: machine ID %s", buf);
#endif
}

வெறுமை
audit_run_command(மாறிலி எழுத்து *command)
{
	/* not implemented */
}

வெறுமை
audit_session_open(கட்டமைப்பு logininfo *li)
{
	/* not implemented */
}

வெறுமை
audit_session_close(கட்டமைப்பு logininfo *li)
{
	/* not implemented */
}

வெறுமை
audit_event(கட்டமைப்பு ssh *ssh, ssh_audit_event_t event)
{
	எழுத்து    textbuf[BSM_TEXTBUFSZ];
	நிலையான முழு logged_in = 0;
	மாறிலி எழுத்து *user = the_authctxt ? the_authctxt->user : "(unknown user)";

	எனில் (cannot_audit(0))
		திரும்பு;

	தேர்வு(event) {
	நிலை SSH_AUTH_SUCCESS:
		logged_in = 1;
		bsm_audit_session_setup();
		snprintf(textbuf, அளவு(textbuf),
		    gettext("successful login %s"), user);
		bsm_audit_record(0, textbuf, AUE_openssh);
		நிறுத்து;

	நிலை SSH_CONNECTION_CLOSE:
		/*
		 * We can also get a close event if the user attempted auth
		 * but never succeeded.
		 */
		எனில் (logged_in) {
			snprintf(textbuf, அளவு(textbuf),
			    gettext("sshd logout %s"), the_authctxt->user);
			bsm_audit_record(0, textbuf, AUE_logout);
		} இல்லையெனில் {
			debug("%s: connection closed without authentication",
			    __func__);
		}
		நிறுத்து;

	நிலை SSH_NOLOGIN:
		bsm_audit_record(1,
		    gettext("logins disabled by /etc/nologin"), AUE_openssh);
		நிறுத்து;

	நிலை SSH_LOGIN_EXCEED_MAXTRIES:
		snprintf(textbuf, அளவு(textbuf),
		    gettext("too many tries for user %s"), the_authctxt->user);
		bsm_audit_record(1, textbuf, AUE_openssh);
		நிறுத்து;

	நிலை SSH_LOGIN_வேர்_DENIED:
		bsm_audit_record(2, gettext("not_console"), AUE_openssh);
		நிறுத்து;

	நிலை SSH_AUTH_FAIL_PASSWD:
		bsm_audit_bad_login("password");
		நிறுத்து;

	நிலை SSH_AUTH_FAIL_KBDINT:
		bsm_audit_bad_login("interactive password entry");
		நிறுத்து;

	இயல்பு:
		debug_f("unhandled event %d", event);
	}
}
#endif /* BSM */
