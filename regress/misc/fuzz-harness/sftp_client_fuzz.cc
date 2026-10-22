/* Copyright 2026 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
     http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
 * Fuzzer for OpenSSH SFTP client response parser (sftp-client.c)
 *
 * Target: sftp-client.c
 *
 * Drives every public sftp-client API on a socketpair using the
 * fuzzer input as the reply payload. A helper opens a fresh
 * socketpair, pre-fills a valid FXP_VERSION reply so sftp_init
 * succeeds, then writes the fuzzer body which the API call consumes
 * as its own response. Each iteration runs all 12 APIs on the same
 * input so no API is starved by a selector byte.
 *
 * Primary functions exercised:
 * - sftp_init, sftp_stat, sftp_lstat, sftp_realpath, sftp_expand_path
 * - sftp_readdir, sftp_statvfs, sftp_get_limits
 * - sftp_rm, sftp_mkdir, sftp_rmdir, sftp_rename, sftp_symlink
 * - decode_attrib via every reply path (sftp-common.c)
 *
 * Threat model: a malicious SFTP server returning crafted attribute
 * lists, name lists, status responses, and statvfs payloads to a
 * connected client (sshfs, sftp, scp to a hostile host).
 *
 * Failure handling: sftp-client.c calls fatal() liberally on
 * protocol violations. A custom cleanup_exit() longjmp()s back to
 * the helper. fuzz_arena (linker --wrap'd malloc family) frees
 * every still-live allocation on both the success and longjmp paths
 * so LSan sees zero per-iteration leaks.
 */

#ਅਨ੍ਤਰ੍ਭਾਵ <setjmp.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stddef.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

ਬਾਹਰੀ "C" {
#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sftp.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sftp-common.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sftp-client.h"

ਖਾਲੀ fuzz_arena_begin(ਖਾਲੀ);
ਖਾਲੀ fuzz_arena_cleanup(ਖਾਲੀ);
}

ਬਾਹਰੀ "C" ਅਸਥਿਰ sig_atomic_t interrupted = 0;
ਬਾਹਰੀ "C" ਪੂਰਨ showprogress = 0;
ਬਾਹਰੀ "C" ਖਾਲੀ ਸ਼ੁਰੂ_ਤਰੱਕੀ_meter(ਅਚਲ ਅੱਖਰ *file, off_t filesize,
    off_t *ctr) { (ਖਾਲੀ)file; (ਖਾਲੀ)filesize; (ਖਾਲੀ)ctr; }
ਬਾਹਰੀ "C" ਖਾਲੀ refresh_ਤਰੱਕੀ_meter(ਪੂਰਨ force_update) { (ਖਾਲੀ)force_update; }
ਬਾਹਰੀ "C" ਖਾਲੀ stop_ਤਰੱਕੀ_meter(ਖਾਲੀ) { }

ਸਥਿਰ jmp_buf fuzz_env;
ਸਥਿਰ ਅਸਥਿਰ ਪੂਰਨ ਵਿੱਚ_fuzz = 0;

ਬਾਹਰੀ "C" ਖਾਲੀ
cleanup_exit(ਪੂਰਨ ਕੋਡ)
{
	ਜੇ (ਵਿੱਚ_fuzz)
		longjmp(fuzz_env, ਕੋਡ ? ਕੋਡ : 1);
	_exit(ਕੋਡ);
}

ਸਥਿਰ ਅਚਲ uint8_t k_ਸੰਸਕਰਣ_ਜਵਾਬ[] = {
    0x00, 0x00, 0x00, 0x05,
    0x02,
    0x00, 0x00, 0x00, 0x03,
};

ਗਿਣਤੀ {
	API_STAT,
	API_LSTAT,
	API_REALPATH,
	API_EXPAND_ਰਸਤਾ,
	API_READDIR,
	API_STATVFS,
	API_GET_LIMITS,
	API_RM,
	API_MKDIR,
	API_RMDIR,
	API_RENAME,
	API_SYMLINK,
	API_ਗਿਣਤੀ,
};

ਸਥਿਰ ਖਾਲੀ
ਲੜੀਵਾਰ_one(ਪੂਰਨ api, ਅਚਲ uint8_t *body, ਮਾਪ_t bsize)
{
	ਪੂਰਨ sv[2] = { -1, -1 };
	ਜੇ (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		ਵਾਪਸ;

	ssize_t w = ਲਿਖ(sv[0], k_ਸੰਸਕਰਣ_ਜਵਾਬ, ਆਕਾਰ(k_ਸੰਸਕਰਣ_ਜਵਾਬ));
	(ਖਾਲੀ)w;
	ਜੇ (bsize > 0)
		w = ਲਿਖ(sv[0], body, bsize);
	(ਖਾਲੀ)w;
	shutdown(sv[0], SHUT_WR);

	fuzz_arena_begin();
	ਵਿੱਚ_fuzz = 1;
	ਜੇ (setjmp(fuzz_env) == 0) {
		ਬਣਤਰ sftp_conn *conn = sftp_init(sv[1], sv[1], 32768, 64, 0);
		ਜੇ (conn != ਨਿਰਾ) {
			Attrib attr;
			attrib_clear(&attr);

			ਚੋਣ (api) {
			ਹਾਲਤ API_STAT: {
				Attrib a;
				(ਖਾਲੀ)sftp_stat(conn, "/fuzz", 1, &a);
				ਰੋਕੋ;
			}
			ਹਾਲਤ API_LSTAT: {
				Attrib a;
				(ਖਾਲੀ)sftp_lstat(conn, "/fuzz", 1, &a);
				ਰੋਕੋ;
			}
			ਹਾਲਤ API_REALPATH: {
				ਅੱਖਰ *p = sftp_realpath(conn, "/fuzz");
				ਮੁਕਤ(p);
				ਰੋਕੋ;
			}
			ਹਾਲਤ API_EXPAND_ਰਸਤਾ: {
				ਅੱਖਰ *p = sftp_expand_ਰਸਤਾ(conn, "~");
				ਮੁਕਤ(p);
				ਰੋਕੋ;
			}
			ਹਾਲਤ API_READDIR: {
				SFTP_DIRENT **dir = ਨਿਰਾ;
				(ਖਾਲੀ)sftp_readdir(conn, "/fuzz", &dir);
				ਜੇ (dir != ਨਿਰਾ)
					sftp_free_dirents(dir);
				ਰੋਕੋ;
			}
			ਹਾਲਤ API_STATVFS: {
				ਬਣਤਰ sftp_statvfs vfs;
				(ਖਾਲੀ)sftp_statvfs(conn, "/fuzz", &vfs, 1);
				ਰੋਕੋ;
			}
			ਹਾਲਤ API_GET_LIMITS: {
				ਬਣਤਰ sftp_limits lim;
				(ਖਾਲੀ)sftp_get_limits(conn, &lim);
				ਰੋਕੋ;
			}
			ਹਾਲਤ API_RM:
				(ਖਾਲੀ)sftp_rm(conn, "/fuzz");
				ਰੋਕੋ;
			ਹਾਲਤ API_MKDIR:
				(ਖਾਲੀ)sftp_mkdir(conn, "/fuzz", &attr, 0);
				ਰੋਕੋ;
			ਹਾਲਤ API_RMDIR:
				(ਖਾਲੀ)sftp_rmdir(conn, "/fuzz");
				ਰੋਕੋ;
			ਹਾਲਤ API_RENAME:
				(ਖਾਲੀ)sftp_rename(conn, "/a", "/b", 0);
				ਰੋਕੋ;
			ਹਾਲਤ API_SYMLINK:
				(ਖਾਲੀ)sftp_symlink(conn, "/a", "/b");
				ਰੋਕੋ;
			}

			sftp_free(conn);
		}
	}
	ਵਿੱਚ_fuzz = 0;
	fuzz_arena_cleanup();

	close(sv[0]);
	close(sv[1]);
}

ਬਾਹਰੀ "C" ਪੂਰਨ
LLVMFuzzer_Test_One_ਨਿਵੇਸ਼(ਅਚਲ uint8_t *ਅੰਕੜੇ, ਮਾਪ_t ਮਾਪ)
{
	ਸਥਿਰ ਪੂਰਨ initialized = 0;
	ਜੇ (!initialized) {
		initialized = 1;
		log_init("sftp_client_fuzz", SYSLOG_LEVEL_ERROR,
		    SYSLOG_FACILITY_AUTH, 0);
	}

	ਜੇ (ਮਾਪ > 65536)
		ਵਾਪਸ 0;

	ਲਈ (ਪੂਰਨ api = 0; api < API_ਗਿਣਤੀ; api++)
		ਲੜੀਵਾਰ_one(api, ਅੰਕੜੇ, ਮਾਪ);

	ਵਾਪਸ 0;
}
