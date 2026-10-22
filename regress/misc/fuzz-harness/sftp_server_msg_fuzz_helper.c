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
 * Fuzzer for OpenSSH SFTP server message dispatch (sftp-server.c)
 *
 * Target: sftp-server.c
 *
 * Follows the agent_fuzz_helper.c pattern: #include's sftp-server.c so
 * process() and the static process_* handlers, plus the file-scope
 * globals (iqueue, oqueue, pw, init_done, handles), are reachable from
 * this translation unit. Each iteration bootstraps an FXP_INIT then
 * feeds the fuzzer input as a single framed SFTP message.
 *
 * Primary functions exercised:
 * - process() and the 17 base process_* handlers (open / close / read /
 *   write / stat / lstat / fstat / setstat / fsetstat / opendir /
 *   readdir / remove / mkdir / rmdir / realpath / rename / readlink /
 *   symlink)
 * - process_extended_* (11 variants including posix-rename, statvfs,
 *   hardlink, fsync, lsetstat, limits, expand-path, copy-data,
 *   home-directory, users-groups-by-id)
 * - decode_attrib / encode_attrib (sftp-common.c)
 *
 * Failure handling: fatal() -> cleanup_exit() and
 * sftp_server_cleanup_exit() are intercepted with overriding
 * definitions that longjmp() back to the entry point. fuzz_arena
 * (linker --wrap'd malloc family) frees every still-live allocation on
 * recovery so LSan sees zero per-iteration leaks.
 */

#شامل <setjmp.h>
#شامل <stdint.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <unistd.h>
#شامل <pwd.h>
#شامل <sys/types.h>

#شامل "log.h"

بیرونی تهی fuzz_arena_begin(تهی);
بیرونی تهی fuzz_arena_release(تهی);
بیرونی تهی fuzz_arena_cleanup(تهی);

ایستا jmp_buf fuzz_server_env;
ایستا فرار صحیح in_fuzz_server = 0;

تهی
cleanup_exit(صحیح code)
{
	اگر (in_fuzz_server)
		longjmp(fuzz_server_env, code ? code : 1);
	_exit(code);
}

#define sftp_server_cleanup_exit __orig_sftp_server_cleanup_exit
#شامل "../../../sftp-server.c"
#undef sftp_server_cleanup_exit

تهی
sftp_server_cleanup_exit(صحیح code)
{
	اگر (in_fuzz_server)
		longjmp(fuzz_server_env, code ? code : 1);
	_exit(code);
}

ایستا تهی (* ثابت __force_use_renamed)(صحیح) =
    __orig_sftp_server_cleanup_exit;

ایستا ساختار passwd fuzz_pw;
ایستا صحیح log_initialized = 0;

ایستا تهی
cleanup_handles(تهی)
{
	u_int i;
	اگر (handles == پوچ)
		بازگشت;
	برای (i = 0; i < رقم_handles; i++) {
		اگر (handles[i].use == HANDLE_FILE && handles[i].fd >= 0)
			close(handles[i].fd);
		وگرنه اگر (handles[i].use == HANDLE_DIR && handles[i].dirp != پوچ)
			closedir(handles[i].dirp);
		آزاد(handles[i].name);
	}
	آزاد(handles);
	handles = پوچ;
	رقم_handles = 0;
	first_unused_handle = -1;
}

ایستا تهی
reset_module_globals(تهی)
{
	pw = &fuzz_pw;
	client_addr = پوچ;
	version = 0;
	init_done = 0;
	readonly = 0;
	request_allowlist = پوچ;
	request_denylist = پوچ;
	handles = پوچ;
	رقم_handles = 0;
	first_unused_handle = -1;
	iqueue = پوچ;
	oqueue = پوچ;
}

تهی
fuzz_server_one(ثابت uint8_t *data, size_t size)
{
	اگر (!log_initialized) {
		log_initialized = 1;
		log_init("sftp_server_msg_fuzz", SYSLOG_LEVEL_ERROR,
		    SYSLOG_FACILITY_AUTH, 0);

		/* Confine filesystem syscalls (process_open/mkdir/symlink) to a fresh tmpdir. */
		نویسه tmpdir[] = "/tmp/sftp_fuzz_XXXXXX";
		اگر (mkdtemp(tmpdir) != پوچ && chdir(tmpdir) != 0)
			_exit(1);

		memset(&fuzz_pw, 0, اندازه(fuzz_pw));
		fuzz_pw.pw_name = (نویسه *)"fuzz";
		fuzz_pw.pw_uid = getuid();
		fuzz_pw.pw_gid = getgid();
		fuzz_pw.pw_dir = (نویسه *)"/tmp";
		fuzz_pw.pw_shell = (نویسه *)"/bin/sh";
	}

	اگر (size == 0 || size > 65000)
		بازگشت;

	reset_module_globals();

	fuzz_arena_begin();
	in_fuzz_server = 1;
	اگر (setjmp(fuzz_server_env) == 0) {
		client_addr = strdup("127.0.0.1");
		iqueue = sshbuf_new();
		oqueue = sshbuf_new();
		اگر (iqueue == پوچ || oqueue == پوچ)
			برو out;

		ثابت uint8_t init_پیام[] = {
		    0x00, 0x00, 0x00, 0x05,
		    SSH2_FXP_INIT,
		    0x00, 0x00, 0x00, 0x03,
		};
		اگر (sshbuf_put(iqueue, init_پیام, اندازه(init_پیام)) != 0)
			برو out;
		process();

		sshbuf_reset(iqueue);
		sshbuf_reset(oqueue);

		uint8_t hdr[4] = {
		    (uint8_t)((size >> 24) & 0xff),
		    (uint8_t)((size >> 16) & 0xff),
		    (uint8_t)((size >> 8) & 0xff),
		    (uint8_t)(size & 0xff),
		};
		اگر (sshbuf_put(iqueue, hdr, 4) != 0 ||
		    sshbuf_put(iqueue, data, size) != 0)
			برو out;
		process();
	out:
		cleanup_handles();
		sshbuf_free(iqueue);
		sshbuf_free(oqueue);
		آزاد(client_addr);
		iqueue = oqueue = پوچ;
		client_addr = پوچ;
		in_fuzz_server = 0;
		fuzz_arena_release();
		بازگشت;
	}
	cleanup_handles();
	in_fuzz_server = 0;
	fuzz_arena_cleanup();
	iqueue = oqueue = پوچ;
	client_addr = پوچ;
}
