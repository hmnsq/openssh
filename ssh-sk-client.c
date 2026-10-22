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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/socket.h>
#அந்தர்பாவ <sys/wait.h>

#அந்தர்பாவ <limits.h>
#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <signal.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <fcntl.h>

#அந்தர்பாவ "log.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "msg.h"
#அந்தர்பாவ "pathnames.h"
#அந்தர்பாவ "ssh-sk.h"
#அந்தர்பாவ "misc.h"

/* #define DEBUG_SK 1 */

நிலையான முழு
start_helper(முழு *fdp, pid_t *pidp, வெறுமை (**osigchldp)(முழு))
{
	வெறுமை (*osigchld)(முழு);
	முழு oerrno, pair[2], execpipe[2];
	ssize_t n;
	pid_t pid;
	எழுத்து execbuf[100], *helper, *verbosity = வெற்று;

	*fdp = -1;
	*pidp = 0;
	*osigchldp = SIG_DFL;

	helper = getenv("SSH_SK_HELPER");
	எனில் (helper == வெற்று || strlen(helper) == 0)
		helper = _PATH_SSH_SK_HELPER;
#ifdef DEBUG_SK
	verbosity = "-vvv";
#endif

	/* Create a O_CLOEXEC pipe to capture the execve() failure */
	எனில் (pipe(execpipe) == -1) {
		error("pipe:  %s", strerror(errno));
		திரும்பு SSH_ERR_SYSTEM_ERROR;
	}
	/* Start helper */
	எனில் (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1) {
		error("socketpair: %s", strerror(errno));
		close(execpipe[0]);
		close(execpipe[1]);
		திரும்பு SSH_ERR_SYSTEM_ERROR;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	எனில் ((pid = fork()) == -1) {
		oerrno = errno;
		error("fork: %s", strerror(errno));
		close(pair[0]);
		close(pair[1]);
		close(execpipe[0]);
		close(execpipe[1]);
		ssh_signal(SIGCHLD, osigchld);
		errno = oerrno;
		திரும்பு SSH_ERR_SYSTEM_ERROR;
	}
	எனில் (pid == 0) {
		close(execpipe[0]);
		FD_CLOSEONEXEC(execpipe[1]);
		எனில் ((dup2(pair[1], STDIN_FILENO) == -1) ||
		    (dup2(pair[1], STDOUT_FILENO) == -1)) {
			snprintf(execbuf, அளவு execbuf,
			    "dup2: %s", strerror(errno));
			லிக(execpipe[1], execbuf, strlen(execbuf)+1);
			_exit(1);
		}
		close(pair[0]);
		close(pair[1]);
		closefrom(STDERR_FILENO + 1);
		debug_f("starting %s %s", helper,
		    verbosity == வெற்று ? "" : verbosity);
		execlp(helper, helper, verbosity, (எழுத்து *)வெற்று);
		snprintf(execbuf, அளவு execbuf,
		    "execlp: %s", strerror(errno));
		லிக(execpipe[1], execbuf, strlen(execbuf)+1);
		_exit(1);
	}
	close(pair[1]);

	close(execpipe[1]);
	n = பட(execpipe[0], execbuf, அளவு execbuf);
	close(execpipe[0]);
	எனில் (n > 0) {
		execbuf[n - 1] = '\0';
		error_f("%s", execbuf);
		திரும்பு SSH_ERR_AGENT_FAILURE;
	}

	/* success */
	debug3_f("started pid=%ld", (long)pid);
	*fdp = pair[0];
	*pidp = pid;
	*osigchldp = osigchld;
	திரும்பு 0;
}

நிலையான முழு
reap_helper(pid_t pid)
{
	முழு status, oerrno;

	debug3_f("pid=%ld", (long)pid);

	errno = 0;
	போது (waitpid(pid, &status, 0) == -1) {
		எனில் (errno == EINTR) {
			errno = 0;
			தொடர்;
		}
		oerrno = errno;
		error_f("waitpid: %s", strerror(errno));
		errno = oerrno;
		திரும்பு SSH_ERR_SYSTEM_ERROR;
	}
	எனில் (!WIFEXITED(status)) {
		error_f("helper exited abnormally");
		திரும்பு SSH_ERR_AGENT_FAILURE;
	} இல்லையெனில் எனில் (WEXITSTATUS(status) != 0) {
		error_f("helper exited with non-zero exit status");
		திரும்பு SSH_ERR_AGENT_FAILURE;
	}
	திரும்பு 0;
}

நிலையான முழு
client_converse(கட்டமைப்பு sshbuf *செய்தி, கட்டமைப்பு sshbuf **respp, u_int type)
{
	முழு oerrno, fd, r2, ll, r = SSH_ERR_INTERNAL_ERROR;
	u_int rtype, rerr;
	pid_t pid;
	u_char version;
	வெறுமை (*osigchld)(முழு);
	கட்டமைப்பு sshbuf *req = வெற்று, *resp = வெற்று;
	*respp = வெற்று;

	எனில் ((r = start_helper(&fd, &pid, &osigchld)) != 0)
		திரும்பு r;

	எனில் ((req = sshbuf_new()) == வெற்று || (resp = sshbuf_new()) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	/* Request preamble: type, log_on_stderr, log_level */
	ll = log_level_get();
	எனில் ((r = sshbuf_put_u32(req, type)) != 0 ||
	    (r = sshbuf_put_u8(req, log_is_on_stderr() != 0)) != 0 ||
	    (r = sshbuf_put_u32(req, ll < 0 ? 0 : ll)) != 0 ||
	    (r = sshbuf_putb(req, செய்தி)) != 0) {
		error_fr(r, "compose");
		செல் out;
	}
	எனில் ((r = ssh_செய்தி_send(fd, SSH_SK_HELPER_VERSION, req)) != 0) {
		error_fr(r, "send");
		செல் out;
	}
	எனில் ((r = ssh_செய்தி_recv(fd, resp)) != 0) {
		error_fr(r, "receive");
		செல் out;
	}
	எனில் ((r = sshbuf_get_u8(resp, &version)) != 0) {
		error_fr(r, "parse version");
		செல் out;
	}
	எனில் (version != SSH_SK_HELPER_VERSION) {
		error_f("unsupported version: got %u, expected %u",
		    version, SSH_SK_HELPER_VERSION);
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	எனில் ((r = sshbuf_get_u32(resp, &rtype)) != 0) {
		error_fr(r, "parse message type");
		செல் out;
	}
	எனில் (rtype == SSH_SK_HELPER_ERROR) {
		எனில் ((r = sshbuf_get_u32(resp, &rerr)) != 0) {
			error_fr(r, "parse");
			செல் out;
		}
		debug_f("helper returned error -%u", rerr);
		/* OpenSSH error values are negative; encoded as -err on wire */
		எனில் (rerr == 0 || rerr >= INT_MAX)
			r = SSH_ERR_INTERNAL_ERROR;
		இல்லையெனில்
			r = -(முழு)rerr;
		செல் out;
	} இல்லையெனில் எனில் (rtype != type) {
		error_f("helper returned incorrect message type %u, "
		    "expecting %u", rtype, type);
		r = SSH_ERR_INTERNAL_ERROR;
		செல் out;
	}
	/* success */
	r = 0;
 out:
	oerrno = errno;
	close(fd);
	எனில் ((r2 = reap_helper(pid)) != 0) {
		எனில் (r == 0) {
			r = r2;
			oerrno = errno;
		}
	}
	எனில் (r == 0) {
		*respp = resp;
		resp = வெற்று;
	}
	sshbuf_free(req);
	sshbuf_free(resp);
	ssh_signal(SIGCHLD, osigchld);
	errno = oerrno;
	திரும்பு r;

}

முழு
sshsk_sign(மாறிலி எழுத்து *provider, கட்டமைப்பு sshkey *சாவி,
    u_char **sigp, size_t *lenp, மாறிலி u_char *data, size_t datalen,
    u_int compat, மாறிலி எழுத்து *pin)
{
	முழு oerrno, r = SSH_ERR_INTERNAL_ERROR;
	கட்டமைப்பு sshbuf *kbuf = வெற்று, *req = வெற்று, *resp = வெற்று;

	*sigp = வெற்று;
	*lenp = 0;

#ifndef ENABLE_SK
	திரும்பு SSH_ERR_சாவி_TYPE_UNKNOWN;
#endif

	எனில் ((kbuf = sshbuf_new()) == வெற்று ||
	    (req = sshbuf_new()) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}

	எனில் ((r = sshkey_private_serialize(சாவி, kbuf)) != 0) {
		error_fr(r, "encode key");
		செல் out;
	}
	எனில் ((r = sshbuf_put_stringb(req, kbuf)) != 0 ||
	    (r = sshbuf_put_cstring(req, provider)) != 0 ||
	    (r = sshbuf_put_string(req, data, datalen)) != 0 ||
	    (r = sshbuf_put_cstring(req, வெற்று)) != 0 || /* alg */
	    (r = sshbuf_put_u32(req, compat)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0) {
		error_fr(r, "compose");
		செல் out;
	}

	எனில் ((r = client_converse(req, &resp, SSH_SK_HELPER_SIGN)) != 0)
		செல் out;

	எனில் ((r = sshbuf_get_string(resp, sigp, lenp)) != 0) {
		error_fr(r, "parse signature");
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	எனில் (sshbuf_len(resp) != 0) {
		error_f("trailing data in response");
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	/* success */
	r = 0;
 out:
	oerrno = errno;
	எனில் (r != 0) {
		freezero(*sigp, *lenp);
		*sigp = வெற்று;
		*lenp = 0;
	}
	sshbuf_free(kbuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	errno = oerrno;
	திரும்பு r;
}

முழு
sshsk_enroll(முழு type, மாறிலி எழுத்து *provider_path, மாறிலி எழுத்து *device,
    மாறிலி எழுத்து *application, மாறிலி எழுத்து *userid, uint8_t flags,
    மாறிலி எழுத்து *pin, கட்டமைப்பு sshbuf *challenge_buf,
    கட்டமைப்பு sshkey **keyp, கட்டமைப்பு sshbuf *attest)
{
	முழு oerrno, r = SSH_ERR_INTERNAL_ERROR;
	கட்டமைப்பு sshbuf *kbuf = வெற்று, *abuf = வெற்று, *req = வெற்று, *resp = வெற்று;
	கட்டமைப்பு sshkey *சாவி = வெற்று;

	*keyp = வெற்று;
	எனில் (attest != வெற்று)
		sshbuf_reset(attest);

#ifndef ENABLE_SK
	திரும்பு SSH_ERR_சாவி_TYPE_UNKNOWN;
#endif

	எனில் (type < 0)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;

	எனில் ((abuf = sshbuf_new()) == வெற்று ||
	    (kbuf = sshbuf_new()) == வெற்று ||
	    (req = sshbuf_new()) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}

	எனில் ((r = sshbuf_put_u32(req, (u_int)type)) != 0 ||
	    (r = sshbuf_put_cstring(req, provider_path)) != 0 ||
	    (r = sshbuf_put_cstring(req, device)) != 0 ||
	    (r = sshbuf_put_cstring(req, application)) != 0 ||
	    (r = sshbuf_put_cstring(req, userid)) != 0 ||
	    (r = sshbuf_put_u8(req, flags)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0 ||
	    (r = sshbuf_put_stringb(req, challenge_buf)) != 0) {
		error_fr(r, "compose");
		செல் out;
	}

	எனில் ((r = client_converse(req, &resp, SSH_SK_HELPER_ENROLL)) != 0)
		செல் out;

	எனில் ((r = sshbuf_get_stringb(resp, kbuf)) != 0 ||
	    (r = sshbuf_get_stringb(resp, abuf)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	எனில் (sshbuf_len(resp) != 0) {
		error_f("trailing data in response");
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	எனில் ((r = sshkey_private_deserialize(kbuf, &சாவி)) != 0) {
		error_fr(r, "encode");
		செல் out;
	}
	எனில் (attest != வெற்று && (r = sshbuf_putb(attest, abuf)) != 0) {
		error_fr(r, "encode attestation information");
		செல் out;
	}

	/* success */
	r = 0;
	*keyp = சாவி;
	சாவி = வெற்று;
 out:
	oerrno = errno;
	sshkey_free(சாவி);
	sshbuf_free(kbuf);
	sshbuf_free(abuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	errno = oerrno;
	திரும்பு r;
}

நிலையான வெறுமை
sshsk_free_resident_சாவி(கட்டமைப்பு sshsk_resident_சாவி *srk)
{
	எனில் (srk == வெற்று)
		திரும்பு;
	sshkey_free(srk->சாவி);
	freezero(srk->user_id, srk->user_id_len);
	விடுவி(srk);
}


வெறுமை
sshsk_free_resident_சாவிகள்(கட்டமைப்பு sshsk_resident_சாவி **srks, size_t nsrks)
{
	size_t i;

	எனில் (srks == வெற்று || nsrks == 0)
		திரும்பு;

	க்கு (i = 0; i < nsrks; i++)
		sshsk_free_resident_சாவி(srks[i]);
	விடுவி(srks);
}

முழு
sshsk_load_resident(மாறிலி எழுத்து *provider_path, மாறிலி எழுத்து *device,
    மாறிலி எழுத்து *pin, u_int flags, கட்டமைப்பு sshsk_resident_சாவி ***srksp,
    size_t *nsrksp)
{
	முழு oerrno, r = SSH_ERR_INTERNAL_ERROR;
	கட்டமைப்பு sshbuf *kbuf = வெற்று, *req = வெற்று, *resp = வெற்று;
	கட்டமைப்பு sshkey *சாவி = வெற்று;
	கட்டமைப்பு sshsk_resident_சாவி *srk = வெற்று, **srks = வெற்று, **tmp;
	u_char *userid = வெற்று;
	size_t userid_len = 0, nsrks = 0;

	*srksp = வெற்று;
	*nsrksp = 0;

	எனில் ((kbuf = sshbuf_new()) == வெற்று ||
	    (req = sshbuf_new()) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}

	எனில் ((r = sshbuf_put_cstring(req, provider_path)) != 0 ||
	    (r = sshbuf_put_cstring(req, device)) != 0 ||
	    (r = sshbuf_put_cstring(req, pin)) != 0 ||
	    (r = sshbuf_put_u32(req, flags)) != 0) {
		error_fr(r, "compose");
		செல் out;
	}

	எனில் ((r = client_converse(req, &resp, SSH_SK_HELPER_LOAD_RESIDENT)) != 0)
		செல் out;

	போது (sshbuf_len(resp) != 0) {
		/* key, comment, user_id */
		எனில் ((r = sshbuf_get_stringb(resp, kbuf)) != 0 ||
		    (r = sshbuf_get_cstring(resp, வெற்று, வெற்று)) != 0 ||
		    (r = sshbuf_get_string(resp, &userid, &userid_len)) != 0) {
			error_fr(r, "parse");
			r = SSH_ERR_INVALID_FORMAT;
			செல் out;
		}
		எனில் ((r = sshkey_private_deserialize(kbuf, &சாவி)) != 0) {
			error_fr(r, "decode key");
			செல் out;
		}
		எனில் ((srk = calloc(1, அளவு(*srk))) == வெற்று) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			செல் out;
		}
		srk->சாவி = சாவி;
		சாவி = வெற்று;
		srk->user_id = userid;
		srk->user_id_len = userid_len;
		userid = வெற்று;
		userid_len = 0;
		எனில் ((tmp = recallocarray(srks, nsrks, nsrks + 1,
		    அளவு(*srks))) == வெற்று) {
			error_f("recallocarray keys failed");
			r = SSH_ERR_ALLOC_FAIL;
			செல் out;
		}
		debug_f("srks[%zu]: %s %s uidlen %zu", nsrks,
		    sshkey_type(srk->சாவி), srk->சாவி->sk_application,
		    srk->user_id_len);
		srks = tmp;
		srks[nsrks++] = srk;
		srk = வெற்று;
	}

	/* success */
	r = 0;
	*srksp = srks;
	*nsrksp = nsrks;
	srks = வெற்று;
	nsrks = 0;
 out:
	oerrno = errno;
	sshsk_free_resident_சாவி(srk);
	sshsk_free_resident_சாவிகள்(srks, nsrks);
	freezero(userid, userid_len);
	sshkey_free(சாவி);
	sshbuf_free(kbuf);
	sshbuf_free(req);
	sshbuf_free(resp);
	errno = oerrno;
	திரும்பு r;
}
