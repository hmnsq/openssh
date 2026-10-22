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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/socket.h>
#অন্তর্ভাব <sys/wait.h>

#অন্তর্ভাব <limits.h>
#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <signal.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <fcntl.h>

#অন্তর্ভাব "log.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "msg.h"
#অন্তর্ভাব "pathnames.h"
#অন্তর্ভাব "ssh-sk.h"
#অন্তর্ভাব "misc.h"

/* #define DEBUG_SK 1 */

স্থির পূর্ণাঙ্ক
start_helper(পূর্ণাঙ্ক *fdp, pid_t *pidp, শূন্য (**osigchldp)(পূর্ণাঙ্ক))
{
	শূন্য (*osigchld)(পূর্ণাঙ্ক);
	পূর্ণাঙ্ক oerrno, pair[2], execpipe[2];
	ssize_t n;
	pid_t pid;
	বর্ণ execbuf[100], *helper, *verbosity = রিক্ত;

	*fdp = -1;
	*pidp = 0;
	*osigchldp = SIG_DFL;

	helper = getenv("SSH_SK_HELPER");
	যদি (helper == রিক্ত || strlen(helper) == 0)
		helper = _PATH_SSH_SK_HELPER;
#ifdef DEBUG_SK
	verbosity = "-vvv";
#endif

	/* Create a O_CLOEXEC pipe to capture the execve() failure */
	যদি (pipe(execpipe) == -1) {
		error("pipe:  %s", strerror(errno));
		প্রত্যাগম SSH_ERR_SYSTEM_ERROR;
	}
	/* Start helper */
	যদি (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1) {
		error("socketpair: %s", strerror(errno));
		close(execpipe[0]);
		close(execpipe[1]);
		প্রত্যাগম SSH_ERR_SYSTEM_ERROR;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	যদি ((pid = fork()) == -1) {
		oerrno = errno;
		error("fork: %s", strerror(errno));
		close(pair[0]);
		close(pair[1]);
		close(execpipe[0]);
		close(execpipe[1]);
		ssh_signal(SIGCHLD, osigchld);
		errno = oerrno;
		প্রত্যাগম SSH_ERR_SYSTEM_ERROR;
	}
	যদি (pid == 0) {
		close(execpipe[0]);
		FD_CLOSEONEXEC(execpipe[1]);
		যদি ((dup2(pair[1], STDIN_FILENO) == -1) ||
		    (dup2(pair[1], STDOUT_FILENO) == -1)) {
			snprintf(execbuf, পরিমাণ execbuf,
			    "dup2: %s", strerror(errno));
			লিখ(execpipe[1], execbuf, strlen(execbuf)+1);
			_exit(1);
		}
		close(pair[0]);
		close(pair[1]);
		closefrom(STDERR_FILENO + 1);
		debug_f("starting %s %s", helper,
		    verbosity == রিক্ত ? "" : verbosity);
		execlp(helper, helper, verbosity, (বর্ণ *)রিক্ত);
		snprintf(execbuf, পরিমাণ execbuf,
		    "execlp: %s", strerror(errno));
		লিখ(execpipe[1], execbuf, strlen(execbuf)+1);
		_exit(1);
	}
	close(pair[1]);

	close(execpipe[1]);
	n = পঠ(execpipe[0], execbuf, পরিমাণ execbuf);
	close(execpipe[0]);
	যদি (n > 0) {
		execbuf[n - 1] = '\0';
		error_f("%s", execbuf);
		প্রত্যাগম SSH_ERR_AGENT_FAILURE;
	}

	/* success */
	debug3_f("started pid=%ld", (long)pid);
	*fdp = pair[0];
	*pidp = pid;
	*osigchldp = osigchld;
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
reap_helper(pid_t pid)
{
	পূর্ণাঙ্ক status, oerrno;

	debug3_f("pid=%ld", (long)pid);

	errno = 0;
	যাবত্ (waitpid(pid, &status, 0) == -1) {
		যদি (errno == EINTR) {
			errno = 0;
			অনুবর্ত;
		}
		oerrno = errno;
		error_f("waitpid: %s", strerror(errno));
		errno = oerrno;
		প্রত্যাগম SSH_ERR_SYSTEM_ERROR;
	}
	যদি (!WIFEXITED(status)) {
		error_f("helper exited abnormally");
		প্রত্যাগম SSH_ERR_AGENT_FAILURE;
	} অন্যথা যদি (WEXITSTATUS(status) != 0) {
		error_f("helper exited with non-zero exit status");
		প্রত্যাগম SSH_ERR_AGENT_FAILURE;
	}
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
client_converse(সংরচনা sshbuf *বার্তা, সংরচনা sshbuf **respp, u_int type)
{
	পূর্ণাঙ্ক oerrno, fd, r2, ll, r = SSH_ERR_INTERNAL_ERROR;
	u_int rtype, rerr;
	pid_t pid;
	u_char version;
	শূন্য (*osigchld)(পূর্ণাঙ্ক);
	সংরচনা sshbuf *req = রিক্ত, *resp = রিক্ত;
	*respp = রিক্ত;

	যদি ((r = start_helper(&fd, &pid, &osigchld)) != 0)
		প্রত্যাগম r;

	যদি ((req = sshbuf_new()) == রিক্ত || (resp = sshbuf_new()) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	/* Request preamble: type, log_on_stderr, log_level */
	ll = log_level_get();
	যদি ((r = sshbuf_put_u32(req, type)) != 0 ||
	    (r = sshbuf_put_u8(req, log_is_on_stderr() != 0)) != 0 ||
	    (r = sshbuf_put_u32(req, ll < 0 ? 0 : ll)) != 0 ||
	    (r = sshbuf_putb(req, বার্তা)) != 0) {
		error_fr(r, "compose");
		গচ্ছ out;
	}
	যদি ((r = ssh_বার্তা_send(fd, SSH_SK_HELPER_VERSION, req)) != 0) {
		error_fr(r, "send");
		গচ্ছ out;
	}
	যদি ((r = ssh_বার্তা_recv(fd, resp)) != 0) {
		error_fr(r, "receive");
		গচ্ছ out;
	}
	যদি ((r = sshbuf_get_u8(resp, &version)) != 0) {
		error_fr(r, "parse version");
		গচ্ছ out;
	}
	যদি (version != SSH_SK_HELPER_VERSION) {
		error_f("unsupported version: got %u, expected %u",
		    version, SSH_SK_HELPER_VERSION);
		r = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}
	যদি ((r = sshbuf_get_u32(resp, &rtype)) != 0) {
		error_fr(r, "parse message type");
		গচ্ছ out;
	}
	যদি (rtype == SSH_SK_HELPER_ERROR) {
		যদি ((r = sshbuf_get_u32(resp, &rerr)) != 0) {
			error_fr(r, "parse");
			গচ্ছ out;
		}
		debug_f("helper returned error -%u", rerr);
		/* OpenSSH error values are negative; encoded as -err on wire */
		যদি (rerr == 0 || rerr >= INT_MAX)
			r = SSH_ERR_INTERNAL_ERROR;
		অন্যথা
			r = -(পূর্ণাঙ্ক)rerr;
		গচ্ছ out;
	} অন্যথা যদি (rtype != type) {
		error_f("helper returned incorrect message type %u, "
		    "expecting %u", rtype, type);
		r = SSH_ERR_INTERNAL_ERROR;
		গচ্ছ out;
	}
	/* success */
	r = 0;
 out:
	oerrno = errno;
	close(fd);
	যদি ((r2 = reap_helper(pid)) != 0) {
		যদি (r == 0) {
			r = r2;
			oerrno = errno;
		}
	}
	যদি (r == 0) {
		*respp = resp;
		resp = রিক্ত;
	}
	sshbuf_free(req);
	sshbuf_free(resp);
	ssh_signal(SIGCHLD, osigchld);
	errno = oerrno;
	প্রত্যাগম r;

}

পূর্ণাঙ্ক
sshsk_sign(ধ্রুব বর্ণ *provider, সংরচনা sshkey *চাবি,
    u_char **sigp, size_t *lenp, ধ্রুব u_char *data, size_t datalen,
    u_int compat, ধ্রুব বর্ণ *pin)
{
	পূর্ণাঙ্ক oerrno, r = SSH_ERR_INTERNAL_ERROR;
	সংরচনা sshbuf *kbuf = রিক্ত, *req = রিক্ত, *resp = রিক্ত;

	*sigp = রিক্ত;
	*lenp = 0;

#ifndef ENABLE_SK
	প্রত্যাগম SSH_ERR_চাবি_TYPE_UNKNOWN;
#endif

	যদি ((kbuf = sshbuf_new()) == রিক্ত ||
	    (req = sshbuf_new()) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}

	যদি ((r = sshkey_private_serialize(চাবি, kbuf)) != 0) {
		error_fr(r, "encode key");
		গচ্ছ out;
	}
	যদি ((r = sshbuf_put_stringb(req, kbuf)) != 0 ||
	    (r = sshbuf_put_cstring(req, provider)) != 0 ||
	    (r = sshbuf_put_string(req, data, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(req, রিক্ত)) != 0 || /* alg */
	    (r = sshbuf_put_u32(req, compat)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0) {
		error_fr(r, "compose");
		গচ্ছ out;
	}

	যদি ((r = client_converse(req, &resp, SSH_SK_HELPER_SIGN)) != 0)
		গচ্ছ out;

	যদি ((r = sshbuf_get_string(resp, sigp, lenp)) != 0) {
		error_fr(r, "parse signature");
		r = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}
	যদি (sshbuf_len(resp) != 0) {
		error_f("trailing data in response");
		r = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}
	/* success */
	r = 0;
 out:
	oerrno = errno;
	যদি (r != 0) {
		freezero(*sigp, *lenp);
		*sigp = রিক্ত;
		*lenp = 0;
	}
	sshbuf_free(kbuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	errno = oerrno;
	প্রত্যাগম r;
}

পূর্ণাঙ্ক
sshsk_enroll(পূর্ণাঙ্ক type, ধ্রুব বর্ণ *provider_path, ধ্রুব বর্ণ *device,
    ধ্রুব বর্ণ *application, ধ্রুব বর্ণ *userid, uint8_t flags,
    ধ্রুব বর্ণ *pin, সংরচনা sshbuf *challenge_buf,
    সংরচনা sshkey **keyp, সংরচনা sshbuf *attest)
{
	পূর্ণাঙ্ক oerrno, r = SSH_ERR_INTERNAL_ERROR;
	সংরচনা sshbuf *kbuf = রিক্ত, *abuf = রিক্ত, *req = রিক্ত, *resp = রিক্ত;
	সংরচনা sshkey *চাবি = রিক্ত;

	*keyp = রিক্ত;
	যদি (attest != রিক্ত)
		sshbuf_reset(attest);

#ifndef ENABLE_SK
	প্রত্যাগম SSH_ERR_চাবি_TYPE_UNKNOWN;
#endif

	যদি (type < 0)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;

	যদি ((abuf = sshbuf_new()) == রিক্ত ||
	    (kbuf = sshbuf_new()) == রিক্ত ||
	    (req = sshbuf_new()) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}

	যদি ((r = sshbuf_put_u32(req, (u_int)type)) != 0 ||
	    (r = sshbuf_put_cstring(req, provider_path)) != 0 ||
	    (r = sshbuf_put_cstring(req, device)) != 0 ||
	    (r = sshbuf_put_cstring(req, application)) != 0 ||
	    (r = sshbuf_put_cstring(req, userid)) != 0 ||
	    (r = sshbuf_put_u8(req, flags)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0 ||
	    (r = sshbuf_put_stringb(req, challenge_buf)) != 0) {
		error_fr(r, "compose");
		গচ্ছ out;
	}

	যদি ((r = client_converse(req, &resp, SSH_SK_HELPER_ENROLL)) != 0)
		গচ্ছ out;

	যদি ((r = sshbuf_get_stringb(resp, kbuf)) != 0 ||
	    (r = sshbuf_get_stringb(resp, abuf)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}
	যদি (sshbuf_len(resp) != 0) {
		error_f("trailing data in response");
		r = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}
	যদি ((r = sshkey_private_deserialize(kbuf, &চাবি)) != 0) {
		error_fr(r, "encode");
		গচ্ছ out;
	}
	যদি (attest != রিক্ত && (r = sshbuf_putb(attest, abuf)) != 0) {
		error_fr(r, "encode attestation information");
		গচ্ছ out;
	}

	/* success */
	r = 0;
	*keyp = চাবি;
	চাবি = রিক্ত;
 out:
	oerrno = errno;
	sshkey_free(চাবি);
	sshbuf_free(kbuf);
	sshbuf_free(abuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	errno = oerrno;
	প্রত্যাগম r;
}

স্থির শূন্য
sshsk_free_resident_চাবি(সংরচনা sshsk_resident_চাবি *srk)
{
	যদি (srk == রিক্ত)
		প্রত্যাগম;
	sshkey_free(srk->চাবি);
	freezero(srk->user_id, srk->user_id_len);
	মুক্ত(srk);
}


শূন্য
sshsk_free_resident_চাবিগুলি(সংরচনা sshsk_resident_চাবি **srks, size_t nsrks)
{
	size_t i;

	যদি (srks == রিক্ত || nsrks == 0)
		প্রত্যাগম;

	প্রতি (i = 0; i < nsrks; i++)
		sshsk_free_resident_চাবি(srks[i]);
	মুক্ত(srks);
}

পূর্ণাঙ্ক
sshsk_load_resident(ধ্রুব বর্ণ *provider_path, ধ্রুব বর্ণ *device,
    ধ্রুব বর্ণ *pin, u_int flags, সংরচনা sshsk_resident_চাবি ***srksp,
    size_t *nsrksp)
{
	পূর্ণাঙ্ক oerrno, r = SSH_ERR_INTERNAL_ERROR;
	সংরচনা sshbuf *kbuf = রিক্ত, *req = রিক্ত, *resp = রিক্ত;
	সংরচনা sshkey *চাবি = রিক্ত;
	সংরচনা sshsk_resident_চাবি *srk = রিক্ত, **srks = রিক্ত, **tmp;
	u_char *userid = রিক্ত;
	size_t userid_len = 0, nsrks = 0;

	*srksp = রিক্ত;
	*nsrksp = 0;

	যদি ((kbuf = sshbuf_new()) == রিক্ত ||
	    (req = sshbuf_new()) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}

	যদি ((r = sshbuf_put_cstring(req, provider_path)) != 0 ||
	    (r = sshbuf_put_cstring(req, device)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0 ||
	    (r = sshbuf_put_u32(req, flags)) != 0) {
		error_fr(r, "compose");
		গচ্ছ out;
	}

	যদি ((r = client_converse(req, &resp, SSH_SK_HELPER_LOAD_RESIDENT)) != 0)
		গচ্ছ out;

	যাবত্ (sshbuf_len(resp) != 0) {
		/* key, comment, user_id */
		যদি ((r = sshbuf_get_stringb(resp, kbuf)) != 0 ||
		    (r = sshbuf_get_cstring(resp, রিক্ত, রিক্ত)) != 0 ||
		    (r = sshbuf_get_string(resp, &userid, &userid_len)) != 0) {
			error_fr(r, "parse");
			r = SSH_ERR_INVALID_FORMAT;
			গচ্ছ out;
		}
		যদি ((r = sshkey_private_deserialize(kbuf, &চাবি)) != 0) {
			error_fr(r, "decode key");
			গচ্ছ out;
		}
		যদি ((srk = calloc(1, পরিমাণ(*srk))) == রিক্ত) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			গচ্ছ out;
		}
		srk->চাবি = চাবি;
		চাবি = রিক্ত;
		srk->user_id = userid;
		srk->user_id_len = userid_len;
		userid = রিক্ত;
		userid_len = 0;
		যদি ((tmp = recallocarray(srks, nsrks, nsrks + 1,
		    পরিমাণ(*srks))) == রিক্ত) {
			error_f("recallocarray keys failed");
			r = SSH_ERR_ALLOC_FAIL;
			গচ্ছ out;
		}
		debug_f("srks[%zu]: %s %s uidlen %zu", nsrks,
		    sshkey_type(srk->চাবি), srk->চাবি->sk_application,
		    srk->user_id_len);
		srks = tmp;
		srks[nsrks++] = srk;
		srk = রিক্ত;
	}

	/* success */
	r = 0;
	*srksp = srks;
	*nsrksp = nsrks;
	srks = রিক্ত;
	nsrks = 0;
 out:
	oerrno = errno;
	sshsk_free_resident_চাবি(srk);
	sshsk_free_resident_চাবিগুলি(srks, nsrks);
	freezero(userid, userid_len);
	sshkey_free(চাবি);
	sshbuf_free(kbuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	errno = oerrno;
	প্রত্যাগম r;
}
