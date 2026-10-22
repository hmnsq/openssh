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

#അന്തര്ഭാവ <setjmp.h>
#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <stddef.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <sys/socket.h>
#അന്തര്ഭാവ <sys/types.h>

ബാഹ്യ "C" {
#അന്തര്ഭാവ "includes.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "sftp.h"
#അന്തര്ഭാവ "sftp-common.h"
#അന്തര്ഭാവ "sftp-client.h"

ശൂന്യം fuzz_arena_begin(ശൂന്യം);
ശൂന്യം fuzz_arena_cleanup(ശൂന്യം);
}

ബാഹ്യ "C" അസ്ഥിര sig_atomic_t interrupted = 0;
ബാഹ്യ "C" പൂർണ്ണസംഖ്യ showprogress = 0;
ബാഹ്യ "C" ശൂന്യം start_progress_meter(സ്ഥിരം അക്ഷരം *file, off_t filesize,
    off_t *ctr) { (ശൂന്യം)file; (ശൂന്യം)filesize; (ശൂന്യം)ctr; }
ബാഹ്യ "C" ശൂന്യം refresh_progress_meter(പൂർണ്ണസംഖ്യ force_update) { (ശൂന്യം)force_update; }
ബാഹ്യ "C" ശൂന്യം stop_progress_meter(ശൂന്യം) { }

സ്ഥിതം jmp_buf fuzz_env;
സ്ഥിതം അസ്ഥിര പൂർണ്ണസംഖ്യ in_fuzz = 0;

ബാഹ്യ "C" ശൂന്യം
cleanup_exit(പൂർണ്ണസംഖ്യ code)
{
	എങ്കിൽ (in_fuzz)
		longjmp(fuzz_env, code ? code : 1);
	_exit(code);
}

സ്ഥിതം സ്ഥിരം uint8_t k_version_reply[] = {
    0x00, 0x00, 0x00, 0x05,
    0x02,
    0x00, 0x00, 0x00, 0x03,
};

എണ്ണൽ {
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
	API_എണ്ണം,
};

സ്ഥിതം ശൂന്യം
run_one(പൂർണ്ണസംഖ്യ api, സ്ഥിരം uint8_t *body, size_t bsize)
{
	പൂർണ്ണസംഖ്യ sv[2] = { -1, -1 };
	എങ്കിൽ (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		തിരികെ;

	ssize_t w = ലിഖ(sv[0], k_version_reply, വലുപ്പം(k_version_reply));
	(ശൂന്യം)w;
	എങ്കിൽ (bsize > 0)
		w = ലിഖ(sv[0], body, bsize);
	(ശൂന്യം)w;
	shutdown(sv[0], SHUT_WR);

	fuzz_arena_begin();
	in_fuzz = 1;
	എങ്കിൽ (setjmp(fuzz_env) == 0) {
		ഘടന sftp_conn *conn = sftp_init(sv[1], sv[1], 32768, 64, 0);
		എങ്കിൽ (conn != ശൂന്യ) {
			Attrib attr;
			attrib_clear(&attr);

			തിരഞ്ഞെടുപ്പ് (api) {
			അവസ്ഥ API_STAT: {
				Attrib a;
				(ശൂന്യം)sftp_stat(conn, "/fuzz", 1, &a);
				നിർത്തുക;
			}
			അവസ്ഥ API_LSTAT: {
				Attrib a;
				(ശൂന്യം)sftp_lstat(conn, "/fuzz", 1, &a);
				നിർത്തുക;
			}
			അവസ്ഥ API_REALPATH: {
				അക്ഷരം *p = sftp_realpath(conn, "/fuzz");
				സ്വതന്ത്രം(p);
				നിർത്തുക;
			}
			അവസ്ഥ API_EXPAND_PATH: {
				അക്ഷരം *p = sftp_expand_path(conn, "~");
				സ്വതന്ത്രം(p);
				നിർത്തുക;
			}
			അവസ്ഥ API_READDIR: {
				SFTP_DIRENT **dir = ശൂന്യ;
				(ശൂന്യം)sftp_readdir(conn, "/fuzz", &dir);
				എങ്കിൽ (dir != ശൂന്യ)
					sftp_free_dirents(dir);
				നിർത്തുക;
			}
			അവസ്ഥ API_STATVFS: {
				ഘടന sftp_statvfs vfs;
				(ശൂന്യം)sftp_statvfs(conn, "/fuzz", &vfs, 1);
				നിർത്തുക;
			}
			അവസ്ഥ API_GET_LIMITS: {
				ഘടന sftp_limits lim;
				(ശൂന്യം)sftp_get_limits(conn, &lim);
				നിർത്തുക;
			}
			അവസ്ഥ API_RM:
				(ശൂന്യം)sftp_rm(conn, "/fuzz");
				നിർത്തുക;
			അവസ്ഥ API_MKDIR:
				(ശൂന്യം)sftp_mkdir(conn, "/fuzz", &attr, 0);
				നിർത്തുക;
			അവസ്ഥ API_RMDIR:
				(ശൂന്യം)sftp_rmdir(conn, "/fuzz");
				നിർത്തുക;
			അവസ്ഥ API_RENAME:
				(ശൂന്യം)sftp_rename(conn, "/a", "/b", 0);
				നിർത്തുക;
			അവസ്ഥ API_SYMLINK:
				(ശൂന്യം)sftp_symlink(conn, "/a", "/b");
				നിർത്തുക;
			}

			sftp_free(conn);
		}
	}
	in_fuzz = 0;
	fuzz_arena_cleanup();

	close(sv[0]);
	close(sv[1]);
}

ബാഹ്യ "C" പൂർണ്ണസംഖ്യ
LLVMFuzzer_Test_One_നിവേശം(സ്ഥിരം uint8_t *data, size_t size)
{
	സ്ഥിതം പൂർണ്ണസംഖ്യ initialized = 0;
	എങ്കിൽ (!initialized) {
		initialized = 1;
		log_init("sftp_client_fuzz", SYSLOG_LEVEL_ERROR,
		    SYSLOG_FACILITY_AUTH, 0);
	}

	എങ്കിൽ (size > 65536)
		തിരികെ 0;

	വേണ്ടി (പൂർണ്ണസംഖ്യ api = 0; api < API_എണ്ണം; api++)
		run_one(api, data, size);

	തിരികെ 0;
}
