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

#அந்தர்பாவ <setjmp.h>
#அந்தர்பாவ <signal.h>
#அந்தர்பாவ <stddef.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <sys/socket.h>
#அந்தர்பாவ <sys/types.h>

வெளி "C" {
#அந்தர்பாவ "includes.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "sftp.h"
#அந்தர்பாவ "sftp-common.h"
#அந்தர்பாவ "sftp-client.h"

வெறுமை fuzz_arena_begin(வெறுமை);
வெறுமை fuzz_arena_cleanup(வெறுமை);
}

வெளி "C" நிலையற்ற sig_atomic_t interrupted = 0;
வெளி "C" முழு showprogress = 0;
வெளி "C" வெறுமை start_progress_meter(மாறிலி எழுத்து *file, off_t filesize,
    off_t *ctr) { (வெறுமை)file; (வெறுமை)filesize; (வெறுமை)ctr; }
வெளி "C" வெறுமை refresh_progress_meter(முழு force_update) { (வெறுமை)force_update; }
வெளி "C" வெறுமை stop_progress_meter(வெறுமை) { }

நிலையான jmp_buf fuzz_env;
நிலையான நிலையற்ற முழு in_fuzz = 0;

வெளி "C" வெறுமை
cleanup_exit(முழு code)
{
	எனில் (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

நிலையான மாறிலி uint8_t k_version_reply[] = {
    0x00, 0x00, 0x00, 0x05,
    0x02,
    0x00, 0x00, 0x00, 0x03,
};

எண்ணிக்கை {
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
	API_மொத்தம்,
};

நிலையான வெறுமை
run_one(முழு api, மாறிலி uint8_t *body, size_t bsize)
{
	முழு sv[2] = { -1, -1 };
	எனில் (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		திரும்பு;

	ssize_t w = லிக(sv[0], k_version_reply, அளவு(k_version_reply));
	(வெறுமை)w;
	எனில் (bsize > 0)
		w = லிக(sv[0], body, bsize);
	(வெறுமை)w;
	shutdown(sv[0], SHUT_WR);

	fuzz_arena_begin();
	in_fuzz = 1;
	எனில் (setjmp(fuzz_env) == 0) {
		கட்டமைப்பு sftp_conn *conn = sftp_init(sv[1], sv[1], 32768, 64, 0);
		எனில் (conn != வெற்று) {
			Attrib attr;
			attrib_clear(&attr);

			தேர்வு (api) {
			நிலை API_STAT: {
				Attrib a;
				(வெறுமை)sftp_stat(conn, "/fuzz", 1, &a);
				நிறுத்து;
			}
			நிலை API_LSTAT: {
				Attrib a;
				(வெறுமை)sftp_lstat(conn, "/fuzz", 1, &a);
				நிறுத்து;
			}
			நிலை API_REALPATH: {
				எழுத்து *p = sftp_realpath(conn, "/fuzz");
				விடுவி(p);
				நிறுத்து;
			}
			நிலை API_EXPAND_PATH: {
				எழுத்து *p = sftp_expand_path(conn, "~");
				விடுவி(p);
				நிறுத்து;
			}
			நிலை API_READDIR: {
				SFTP_DIRENT **dir = வெற்று;
				(வெறுமை)sftp_readdir(conn, "/fuzz", &dir);
				எனில் (dir != வெற்று)
					sftp_free_dirents(dir);
				நிறுத்து;
			}
			நிலை API_STATVFS: {
				கட்டமைப்பு sftp_statvfs vfs;
				(வெறுமை)sftp_statvfs(conn, "/fuzz", &vfs, 1);
				நிறுத்து;
			}
			நிலை API_GET_LIMITS: {
				கட்டமைப்பு sftp_limits lim;
				(வெறுமை)sftp_get_limits(conn, &lim);
				நிறுத்து;
			}
			நிலை API_RM:
				(வெறுமை)sftp_rm(conn, "/fuzz");
				நிறுத்து;
			நிலை API_MKDIR:
				(வெறுமை)sftp_mkdir(conn, "/fuzz", &attr, 0);
				நிறுத்து;
			நிலை API_RMDIR:
				(வெறுமை)sftp_rmdir(conn, "/fuzz");
				நிறுத்து;
			நிலை API_RENAME:
				(வெறுமை)sftp_rename(conn, "/a", "/b", 0);
				நிறுத்து;
			நிலை API_SYMLINK:
				(வெறுமை)sftp_symlink(conn, "/a", "/b");
				நிறுத்து;
			}

			sftp_free(conn);
		}
	}
	in_fuzz = 0;
	fuzz_arena_cleanup();

	close(sv[0]);
	close(sv[1]);
}

வெளி "C" முழு
LLVMFuzzer_Test_One_உள்ளீடு(மாறிலி uint8_t *data, size_t size)
{
	நிலையான முழு initialized = 0;
	எனில் (!initialized) {
		initialized = 1;
		log_init("sftp_client_fuzz", SYSLOG_LEVEL_ERROR,
		    SYSLOG_FACILITY_AUTH, 0);
	}

	எனில் (size > 65536)
		திரும்பு 0;

	க்கு (முழு api = 0; api < API_மொத்தம்; api++)
		run_one(api, data, size);

	திரும்பு 0;
}
