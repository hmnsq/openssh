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

#અન્તર્ભાવ <setjmp.h>
#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <stddef.h>
#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <sys/socket.h>
#અન્તર્ભાવ <sys/types.h>

બાહ્ય "C" {
#અન્તર્ભાવ "includes.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "sftp.h"
#અન્તર્ભાવ "sftp-common.h"
#અન્તર્ભાવ "sftp-client.h"

શૂન્ય fuzz_arena_begin(શૂન્ય);
શૂન્ય fuzz_arena_cleanup(શૂન્ય);
}

બાહ્ય "C" અસ્થિર sig_atomic_t interrupted = 0;
બાહ્ય "C" પૂર્ણાંક showprogress = 0;
બાહ્ય "C" શૂન્ય start_progress_meter(અચલ અક્ષર *file, off_t filesize,
    off_t *ctr) { (શૂન્ય)file; (શૂન્ય)filesize; (શૂન્ય)ctr; }
બાહ્ય "C" શૂન્ય refresh_progress_meter(પૂર્ણાંક force_update) { (શૂન્ય)force_update; }
બાહ્ય "C" શૂન્ય stop_progress_meter(શૂન્ય) { }

સ્થિર jmp_buf fuzz_env;
સ્થિર અસ્થિર પૂર્ણાંક in_fuzz = 0;

બાહ્ય "C" શૂન્ય
cleanup_exit(પૂર્ણાંક code)
{
	જો (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

સ્થિર અચલ uint8_t k_version_reply[] = {
    0x00, 0x00, 0x00, 0x05,
    0x02,
    0x00, 0x00, 0x00, 0x03,
};

ગણના {
	API_STAT,
	API_LSTAT,
	API_REALPATH,
	API_EXPAND_PATH,
	API_READDIR,
	API_STATVFS,
	API_GET_LIMITS,
	API_RM,
	API_MKDIR,
	API_RMDIR,
	API_RENAME,
	API_SYMLINK,
	API_ગણતરી,
};

સ્થિર શૂન્ય
run_one(પૂર્ણાંક api, અચલ uint8_t *body, size_t bsize)
{
	પૂર્ણાંક sv[2] = { -1, -1 };
	જો (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		પાછા;

	ssize_t w = લિખ(sv[0], k_version_reply, કદ(k_version_reply));
	(શૂન્ય)w;
	જો (bsize > 0)
		w = લિખ(sv[0], body, bsize);
	(શૂન્ય)w;
	shutdown(sv[0], SHUT_WR);

	fuzz_arena_begin();
	in_fuzz = 1;
	જો (setjmp(fuzz_env) == 0) {
		સંરચના sftp_conn *conn = sftp_init(sv[1], sv[1], 32768, 64, 0);
		જો (conn != ખાલી) {
			Attrib attr;
			attrib_clear(&attr);

			પસંદગી (api) {
			સ્થિતિ API_STAT: {
				Attrib a;
				(શૂન્ય)sftp_stat(conn, "/fuzz", 1, &a);
				તોડો;
			}
			સ્થિતિ API_LSTAT: {
				Attrib a;
				(શૂન્ય)sftp_lstat(conn, "/fuzz", 1, &a);
				તોડો;
			}
			સ્થિતિ API_REALPATH: {
				અક્ષર *p = sftp_realpath(conn, "/fuzz");
				મુક્ત(p);
				તોડો;
			}
			સ્થિતિ API_EXPAND_PATH: {
				અક્ષર *p = sftp_expand_path(conn, "~");
				મુક્ત(p);
				તોડો;
			}
			સ્થિતિ API_READDIR: {
				SFTP_DIRENT **dir = ખાલી;
				(શૂન્ય)sftp_readdir(conn, "/fuzz", &dir);
				જો (dir != ખાલી)
					sftp_free_dirents(dir);
				તોડો;
			}
			સ્થિતિ API_STATVFS: {
				સંરચના sftp_statvfs vfs;
				(શૂન્ય)sftp_statvfs(conn, "/fuzz", &vfs, 1);
				તોડો;
			}
			સ્થિતિ API_GET_LIMITS: {
				સંરચના sftp_limits lim;
				(શૂન્ય)sftp_get_limits(conn, &lim);
				તોડો;
			}
			સ્થિતિ API_RM:
				(શૂન્ય)sftp_rm(conn, "/fuzz");
				તોડો;
			સ્થિતિ API_MKDIR:
				(શૂન્ય)sftp_mkdir(conn, "/fuzz", &attr, 0);
				તોડો;
			સ્થિતિ API_RMDIR:
				(શૂન્ય)sftp_rmdir(conn, "/fuzz");
				તોડો;
			સ્થિતિ API_RENAME:
				(શૂન્ય)sftp_rename(conn, "/a", "/b", 0);
				તોડો;
			સ્થિતિ API_SYMLINK:
				(શૂન્ય)sftp_symlink(conn, "/a", "/b");
				તોડો;
			}

			sftp_free(conn);
		}
	}
	in_fuzz = 0;
	fuzz_arena_cleanup();

	close(sv[0]);
	close(sv[1]);
}

બાહ્ય "C" પૂર્ણાંક
LLVMFuzzer_Test_One_આગત(અચલ uint8_t *data, size_t size)
{
	સ્થિર પૂર્ણાંક initialized = 0;
	જો (!initialized) {
		initialized = 1;
		log_init("sftp_client_fuzz", SYSLOG_LEVEL_ERROR,
		    SYSLOG_FACILITY_AUTH, 0);
	}

	જો (size > 65536)
		પાછા 0;

	માટે (પૂર્ણાંક api = 0; api < API_ગણતરી; api++)
		run_one(api, data, size);

	પાછા 0;
}
