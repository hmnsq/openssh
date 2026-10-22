/* $OpenBSD: ssh-sk-client.c,v 1.18 2026/03/11 09:10:59 dtucker Exp $ */
/*
 * Copyright (c) 2019 Google LLC
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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/socket.h>
#అన్తర్భావ <sys/wait.h>

#అన్తర్భావ <limits.h>
#అన్తర్భావ <errno.h>
#అన్తర్భావ <signal.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <fcntl.h>

#అన్తర్భావ "log.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "msg.h"
#అన్తర్భావ "pathnames.h"
#అన్తర్భావ "ssh-sk.h"
#అన్తర్భావ "misc.h"

/* #define DEBUG_SK 1 */

స్థిర పూర్ణాంకం
ప్రారంభం_helper(పూర్ణాంకం *fdp, pid_t *pidp, శూన్య (**osigchldp)(పూర్ణాంకం))
{
	శూన్య (*osigchld)(పూర్ణాంకం);
	పూర్ణాంకం oerrno, pair[2], execpipe[2];
	ssize_t n;
	pid_t pid;
	అక్షరం execbuf[100], *helper, *verbosity = ఖాళీ;

	*fdp = -1;
	*pidp = 0;
	*osigchldp = SIG_DFL;

	helper = getenv("SSH_SK_HELPER");
	ఒకవేళ (helper == ఖాళీ || అక్షరశ్రేణి_పొడవు(helper) == 0)
		helper = మార్గం_SSH_SK_HELPER;
#నిర్వచితమైతే DEBUG_SK
	verbosity = "-vvv";
#అయితే_ముగింపు

	/* Create a O_CLOEXEC pipe to capture the execve() failure */
	ఒకవేళ (pipe(execpipe) == -1) {
		error("pipe:  %s", strerror(errno));
		తిరిగి SSH_ERR_SYSTEM_ERROR;
	}
	/* Start helper */
	ఒకవేళ (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1) {
		error("socketpair: %s", strerror(errno));
		close(execpipe[0]);
		close(execpipe[1]);
		తిరిగి SSH_ERR_SYSTEM_ERROR;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	ఒకవేళ ((pid = fork()) == -1) {
		oerrno = errno;
		error("fork: %s", strerror(errno));
		close(pair[0]);
		close(pair[1]);
		close(execpipe[0]);
		close(execpipe[1]);
		ssh_signal(SIGCHLD, osigchld);
		errno = oerrno;
		తిరిగి SSH_ERR_SYSTEM_ERROR;
	}
	ఒకవేళ (pid == 0) {
		close(execpipe[0]);
		FD_CLOSEONEXEC(execpipe[1]);
		ఒకవేళ ((dup2(pair[1], STDIN_FILENO) == -1) ||
		    (dup2(pair[1], STDOUT_FILENO) == -1)) {
			snprintf(execbuf, పరిమాణం execbuf,
			    "dup2: %s", strerror(errno));
			లిఖ(execpipe[1], execbuf, అక్షరశ్రేణి_పొడవు(execbuf)+1);
			_exit(1);
		}
		close(pair[0]);
		close(pair[1]);
		closefrom(STDERR_FILENO + 1);
		debug_f("starting %s %s", helper,
		    verbosity == ఖాళీ ? "" : verbosity);
		execlp(helper, helper, verbosity, (అక్షరం *)ఖాళీ);
		snprintf(execbuf, పరిమాణం execbuf,
		    "execlp: %s", strerror(errno));
		లిఖ(execpipe[1], execbuf, అక్షరశ్రేణి_పొడవు(execbuf)+1);
		_exit(1);
	}
	close(pair[1]);

	close(execpipe[1]);
	n = పఠ(execpipe[0], execbuf, పరిమాణం execbuf);
	close(execpipe[0]);
	ఒకవేళ (n > 0) {
		execbuf[n - 1] = '\0';
		error_f("%s", execbuf);
		తిరిగి SSH_ERR_AGENT_FAILURE;
	}

	/* success */
	debug3_f("started pid=%ld", (దీర్ఘ)pid);
	*fdp = pair[0];
	*pidp = pid;
	*osigchldp = osigchld;
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
reap_helper(pid_t pid)
{
	పూర్ణాంకం స్థితి_2, oerrno;

	debug3_f("pid=%ld", (దీర్ఘ)pid);

	errno = 0;
	అయితే (waitpid(pid, &స్థితి_2, 0) == -1) {
		ఒకవేళ (errno == EINTR) {
			errno = 0;
			కొనసాగు;
		}
		oerrno = errno;
		error_f("waitpid: %s", strerror(errno));
		errno = oerrno;
		తిరిగి SSH_ERR_SYSTEM_ERROR;
	}
	ఒకవేళ (!WIFEXITED(స్థితి_2)) {
		error_f("helper exited abnormally");
		తిరిగి SSH_ERR_AGENT_FAILURE;
	} లేకపోతే ఒకవేళ (WEXITSTATUS(స్థితి_2) != 0) {
		error_f("helper exited with non-zero exit status");
		తిరిగి SSH_ERR_AGENT_FAILURE;
	}
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
client_converse(నిర్మాణం sshbuf *సందేశం, నిర్మాణం sshbuf **respp, u_int type)
{
	పూర్ణాంకం oerrno, fd, r2, ll, r = SSH_ERR_అంతర్గత_ERROR;
	u_int rtype, rerr;
	pid_t pid;
	u_char సంస్కరణ;
	శూన్య (*osigchld)(పూర్ణాంకం);
	నిర్మాణం sshbuf *req = ఖాళీ, *resp = ఖాళీ;
	*respp = ఖాళీ;

	ఒకవేళ ((r = ప్రారంభం_helper(&fd, &pid, &osigchld)) != 0)
		తిరిగి r;

	ఒకవేళ ((req = sshbuf_new()) == ఖాళీ || (resp = sshbuf_new()) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	/* Request preamble: type, log_on_stderr, log_level */
	ll = log_level_get();
	ఒకవేళ ((r = sshbuf_put_u32(req, type)) != 0 ||
	    (r = sshbuf_put_u8(req, log_is_on_stderr() != 0)) != 0 ||
	    (r = sshbuf_put_u32(req, ll < 0 ? 0 : ll)) != 0 ||
	    (r = sshbuf_putb(req, సందేశం)) != 0) {
		error_fr(r, "compose");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = ssh_సందేశం_send(fd, SSH_SK_HELPER_సంస్కరణ, req)) != 0) {
		error_fr(r, "send");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = ssh_సందేశం_recv(fd, resp)) != 0) {
		error_fr(r, "receive");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshbuf_get_u8(resp, &సంస్కరణ)) != 0) {
		error_fr(r, "parse version");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (సంస్కరణ != SSH_SK_HELPER_సంస్కరణ) {
		error_f("unsupported version: got %u, expected %u",
		    సంస్కరణ, SSH_SK_HELPER_సంస్కరణ);
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshbuf_get_u32(resp, &rtype)) != 0) {
		error_fr(r, "parse message type");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (rtype == SSH_SK_HELPER_ERROR) {
		ఒకవేళ ((r = sshbuf_get_u32(resp, &rerr)) != 0) {
			error_fr(r, "parse");
			వెళ్ళు బహిర్గతం;
		}
		debug_f("helper returned error -%u", rerr);
		/* OpenSSH error values are negative; encoded as -err on wire */
		ఒకవేళ (rerr == 0 || rerr >= గరిష్ఠ_పూర్ణాంకం)
			r = SSH_ERR_అంతర్గత_ERROR;
		లేకపోతే
			r = -(పూర్ణాంకం)rerr;
		వెళ్ళు బహిర్గతం;
	} లేకపోతే ఒకవేళ (rtype != type) {
		error_f("helper returned incorrect message type %u, "
		    "expecting %u", rtype, type);
		r = SSH_ERR_అంతర్గత_ERROR;
		వెళ్ళు బహిర్గతం;
	}
	/* success */
	r = 0;
 బహిర్గతం:
	oerrno = errno;
	close(fd);
	ఒకవేళ ((r2 = reap_helper(pid)) != 0) {
		ఒకవేళ (r == 0) {
			r = r2;
			oerrno = errno;
		}
	}
	ఒకవేళ (r == 0) {
		*respp = resp;
		resp = ఖాళీ;
	}
	sshbuf_free(req);
	sshbuf_free(resp);
	ssh_signal(SIGCHLD, osigchld);
	errno = oerrno;
	తిరిగి r;

}

పూర్ణాంకం
sshsk_sign(స్థిరరాశి అక్షరం *provider, నిర్మాణం sshkey *కీలకం,
    u_char **sigp, కొలత_t *lenp, స్థిరరాశి u_char *దత్తాంశం, కొలత_t datalen,
    u_int compat, స్థిరరాశి అక్షరం *pin)
{
	పూర్ణాంకం oerrno, r = SSH_ERR_అంతర్గత_ERROR;
	నిర్మాణం sshbuf *kbuf = ఖాళీ, *req = ఖాళీ, *resp = ఖాళీ;

	*sigp = ఖాళీ;
	*lenp = 0;

#నిర్వచితం_కాకపోతే ENABLE_SK
	తిరిగి SSH_ERR_కీలకం_TYPE_UNKNOWN;
#అయితే_ముగింపు

	ఒకవేళ ((kbuf = sshbuf_new()) == ఖాళీ ||
	    (req = sshbuf_new()) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}

	ఒకవేళ ((r = sshkey_వ్యక్తిగత_serialize(కీలకం, kbuf)) != 0) {
		error_fr(r, "encode key");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshbuf_put_stringb(req, kbuf)) != 0 ||
	    (r = sshbuf_put_cstring(req, provider)) != 0 ||
	    (r = sshbuf_put_string(req, దత్తాంశం, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(req, ఖాళీ)) != 0 || /* alg */
	    (r = sshbuf_put_u32(req, compat)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0) {
		error_fr(r, "compose");
		వెళ్ళు బహిర్గతం;
	}

	ఒకవేళ ((r = client_converse(req, &resp, SSH_SK_HELPER_SIGN)) != 0)
		వెళ్ళు బహిర్గతం;

	ఒకవేళ ((r = sshbuf_get_string(resp, sigp, lenp)) != 0) {
		error_fr(r, "parse signature");
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (sshbuf_len(resp) != 0) {
		error_f("trailing data in response");
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	/* success */
	r = 0;
 బహిర్గతం:
	oerrno = errno;
	ఒకవేళ (r != 0) {
		freezero(*sigp, *lenp);
		*sigp = ఖాళీ;
		*lenp = 0;
	}
	sshbuf_free(kbuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	errno = oerrno;
	తిరిగి r;
}

పూర్ణాంకం
sshsk_enroll(పూర్ణాంకం type, స్థిరరాశి అక్షరం *provider_మార్గం, స్థిరరాశి అక్షరం *device,
    స్థిరరాశి అక్షరం *application, స్థిరరాశి అక్షరం *userid, uint8_t flags,
    స్థిరరాశి అక్షరం *pin, నిర్మాణం sshbuf *challenge_buf,
    నిర్మాణం sshkey **keyp, నిర్మాణం sshbuf *attest)
{
	పూర్ణాంకం oerrno, r = SSH_ERR_అంతర్గత_ERROR;
	నిర్మాణం sshbuf *kbuf = ఖాళీ, *abuf = ఖాళీ, *req = ఖాళీ, *resp = ఖాళీ;
	నిర్మాణం sshkey *కీలకం = ఖాళీ;

	*keyp = ఖాళీ;
	ఒకవేళ (attest != ఖాళీ)
		sshbuf_reset(attest);

#నిర్వచితం_కాకపోతే ENABLE_SK
	తిరిగి SSH_ERR_కీలకం_TYPE_UNKNOWN;
#అయితే_ముగింపు

	ఒకవేళ (type < 0)
		తిరిగి SSH_ERR_INVALID_వాదం;

	ఒకవేళ ((abuf = sshbuf_new()) == ఖాళీ ||
	    (kbuf = sshbuf_new()) == ఖాళీ ||
	    (req = sshbuf_new()) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}

	ఒకవేళ ((r = sshbuf_put_u32(req, (u_int)type)) != 0 ||
	    (r = sshbuf_put_cstring(req, provider_మార్గం)) != 0 ||
	    (r = sshbuf_put_cstring(req, device)) != 0 ||
	    (r = sshbuf_put_cstring(req, application)) != 0 ||
	    (r = sshbuf_put_cstring(req, userid)) != 0 ||
	    (r = sshbuf_put_u8(req, flags)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0 ||
	    (r = sshbuf_put_stringb(req, challenge_buf)) != 0) {
		error_fr(r, "compose");
		వెళ్ళు బహిర్గతం;
	}

	ఒకవేళ ((r = client_converse(req, &resp, SSH_SK_HELPER_ENROLL)) != 0)
		వెళ్ళు బహిర్గతం;

	ఒకవేళ ((r = sshbuf_get_stringb(resp, kbuf)) != 0 ||
	    (r = sshbuf_get_stringb(resp, abuf)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (sshbuf_len(resp) != 0) {
		error_f("trailing data in response");
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshkey_వ్యక్తిగత_deserialize(kbuf, &కీలకం)) != 0) {
		error_fr(r, "encode");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (attest != ఖాళీ && (r = sshbuf_putb(attest, abuf)) != 0) {
		error_fr(r, "encode attestation information");
		వెళ్ళు బహిర్గతం;
	}

	/* success */
	r = 0;
	*keyp = కీలకం;
	కీలకం = ఖాళీ;
 బహిర్గతం:
	oerrno = errno;
	sshkey_free(కీలకం);
	sshbuf_free(kbuf);
	sshbuf_free(abuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	errno = oerrno;
	తిరిగి r;
}

స్థిర శూన్య
sshsk_free_resident_కీలకం(నిర్మాణం sshsk_resident_కీలకం *srk)
{
	ఒకవేళ (srk == ఖాళీ)
		తిరిగి;
	sshkey_free(srk->కీలకం);
	freezero(srk->user_id, srk->user_id_len);
	విడుదల(srk);
}


శూన్య
sshsk_free_resident_కీలకాలు(నిర్మాణం sshsk_resident_కీలకం **srks, కొలత_t nsrks)
{
	కొలత_t i;

	ఒకవేళ (srks == ఖాళీ || nsrks == 0)
		తిరిగి;

	కొరకు (i = 0; i < nsrks; i++)
		sshsk_free_resident_కీలకం(srks[i]);
	విడుదల(srks);
}

పూర్ణాంకం
sshsk_ఎక్కించు_resident(స్థిరరాశి అక్షరం *provider_మార్గం, స్థిరరాశి అక్షరం *device,
    స్థిరరాశి అక్షరం *pin, u_int flags, నిర్మాణం sshsk_resident_కీలకం ***srksp,
    కొలత_t *nsrksp)
{
	పూర్ణాంకం oerrno, r = SSH_ERR_అంతర్గత_ERROR;
	నిర్మాణం sshbuf *kbuf = ఖాళీ, *req = ఖాళీ, *resp = ఖాళీ;
	నిర్మాణం sshkey *కీలకం = ఖాళీ;
	నిర్మాణం sshsk_resident_కీలకం *srk = ఖాళీ, **srks = ఖాళీ, **tmp;
	u_char *userid = ఖాళీ;
	కొలత_t userid_len = 0, nsrks = 0;

	*srksp = ఖాళీ;
	*nsrksp = 0;

	ఒకవేళ ((kbuf = sshbuf_new()) == ఖాళీ ||
	    (req = sshbuf_new()) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}

	ఒకవేళ ((r = sshbuf_put_cstring(req, provider_మార్గం)) != 0 ||
	    (r = sshbuf_put_cstring(req, device)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0 ||
	    (r = sshbuf_put_u32(req, flags)) != 0) {
		error_fr(r, "compose");
		వెళ్ళు బహిర్గతం;
	}

	ఒకవేళ ((r = client_converse(req, &resp, SSH_SK_HELPER_ఎక్కించు_RESIDENT)) != 0)
		వెళ్ళు బహిర్గతం;

	అయితే (sshbuf_len(resp) != 0) {
		/* key, comment, user_id */
		ఒకవేళ ((r = sshbuf_get_stringb(resp, kbuf)) != 0 ||
		    (r = sshbuf_get_cstring(resp, ఖాళీ, ఖాళీ)) != 0 ||
		    (r = sshbuf_get_string(resp, &userid, &userid_len)) != 0) {
			error_fr(r, "parse");
			r = SSH_ERR_INVALID_FORMAT;
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ ((r = sshkey_వ్యక్తిగత_deserialize(kbuf, &కీలకం)) != 0) {
			error_fr(r, "decode key");
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ ((srk = సున్నా_జ్ఞాపకం_ఇవ్వు(1, పరిమాణం(*srk))) == ఖాళీ) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			వెళ్ళు బహిర్గతం;
		}
		srk->కీలకం = కీలకం;
		కీలకం = ఖాళీ;
		srk->user_id = userid;
		srk->user_id_len = userid_len;
		userid = ఖాళీ;
		userid_len = 0;
		ఒకవేళ ((tmp = recallocarray(srks, nsrks, nsrks + 1,
		    పరిమాణం(*srks))) == ఖాళీ) {
			error_f("recallocarray keys failed");
			r = SSH_ERR_ALLOC_FAIL;
			వెళ్ళు బహిర్గతం;
		}
		debug_f("srks[%zu]: %s %s uidlen %zu", nsrks,
		    sshkey_type(srk->కీలకం), srk->కీలకం->sk_application,
		    srk->user_id_len);
		srks = tmp;
		srks[nsrks++] = srk;
		srk = ఖాళీ;
	}

	/* success */
	r = 0;
	*srksp = srks;
	*nsrksp = nsrks;
	srks = ఖాళీ;
	nsrks = 0;
 బహిర్గతం:
	oerrno = errno;
	sshsk_free_resident_కీలకం(srk);
	sshsk_free_resident_కీలకాలు(srks, nsrks);
	freezero(userid, userid_len);
	sshkey_free(కీలకం);
	sshbuf_free(kbuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	errno = oerrno;
	తిరిగి r;
}
