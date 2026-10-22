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

#அந்தர்பாவ <setjmp.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <pwd.h>
#அந்தர்பாவ <sys/types.h>

#அந்தர்பாவ "log.h"

வெளி வெறுமை fuzz_arena_begin(வெறுமை);
வெளி வெறுமை fuzz_arena_release(வெறுமை);
வெளி வெறுமை fuzz_arena_cleanup(வெறுமை);

நிலையான jmp_buf fuzz_server_env;
நிலையான நிலையற்ற முழு in_fuzz_server = 0;

வெறுமை
cleanup_exit(முழு code)
{
	எனில் (in_fuzz_server)
		longjmp(fuzz_server_env, code ? code : 1);
	_exit(code);
}

#define sftp_server_cleanup_exit __orig_sftp_server_cleanup_exit
#அந்தர்பாவ "../../../sftp-server.c"
#undef sftp_server_cleanup_exit

வெறுமை
sftp_server_cleanup_exit(முழு code)
{
	எனில் (in_fuzz_server)
		longjmp(fuzz_server_env, code ? code : 1);
	_exit(code);
}

நிலையான வெறுமை (* மாறிலி __force_use_renamed)(முழு) =
    __orig_sftp_server_cleanup_exit;

நிலையான கட்டமைப்பு passwd fuzz_pw;
நிலையான முழு log_initialized = 0;

நிலையான வெறுமை
cleanup_handles(வெறுமை)
{
	u_int i;
	எனில் (handles == வெற்று)
		திரும்பு;
	க்கு (i = 0; i < இலக்கம்_handles; i++) {
		எனில் (handles[i].use == HANDLE_FILE && handles[i].fd >= 0)
			close(handles[i].fd);
		இல்லையெனில் எனில் (handles[i].use == HANDLE_DIR && handles[i].dirp != வெற்று)
			closedir(handles[i].dirp);
		விடுவி(handles[i].name);
	}
	விடுவி(handles);
	handles = வெற்று;
	இலக்கம்_handles = 0;
	first_unused_handle = -1;
}

நிலையான வெறுமை
reset_module_globals(வெறுமை)
{
	pw = &fuzz_pw;
	client_addr = வெற்று;
	version = 0;
	init_done = 0;
	readonly = 0;
	request_allowlist = வெற்று;
	request_denylist = வெற்று;
	handles = வெற்று;
	இலக்கம்_handles = 0;
	first_unused_handle = -1;
	iqueue = வெற்று;
	oqueue = வெற்று;
}

வெறுமை
fuzz_server_one(மாறிலி uint8_t *data, size_t size)
{
	எனில் (!log_initialized) {
		log_initialized = 1;
		log_init("sftp_server_msg_fuzz", SYSLOG_LEVEL_ERROR,
		    SYSLOG_FACILITY_AUTH, 0);

		/* Confine filesystem syscalls (process_open/mkdir/symlink) to a fresh tmpdir. */
		எழுத்து tmpdir[] = "/tmp/sftp_fuzz_XXXXXX";
		எனில் (mkdtemp(tmpdir) != வெற்று && chdir(tmpdir) != 0)
			_exit(1);

		memset(&fuzz_pw, 0, அளவு(fuzz_pw));
		fuzz_pw.pw_name = (எழுத்து *)"fuzz";
		fuzz_pw.pw_uid = getuid();
		fuzz_pw.pw_gid = getgid();
		fuzz_pw.pw_dir = (எழுத்து *)"/tmp";
		fuzz_pw.pw_shell = (எழுத்து *)"/bin/sh";
	}

	எனில் (size == 0 || size > 65000)
		திரும்பு;

	reset_module_globals();

	fuzz_arena_begin();
	in_fuzz_server = 1;
	எனில் (setjmp(fuzz_server_env) == 0) {
		client_addr = strdup("127.0.0.1");
		iqueue = sshbuf_new();
		oqueue = sshbuf_new();
		எனில் (iqueue == வெற்று || oqueue == வெற்று)
			செல் out;

		மாறிலி uint8_t init_செய்தி[] = {
		    0x00, 0x00, 0x00, 0x05,
		    SSH2_FXP_INIT,
		    0x00, 0x00, 0x00, 0x03,
		};
		எனில் (sshbuf_put(iqueue, init_செய்தி, அளவு(init_செய்தி)) != 0)
			செல் out;
		process();

		sshbuf_reset(iqueue);
		sshbuf_reset(oqueue);

		uint8_t hdr[4] = {
		    (uint8_t)((size >> 24) & 0xff),
		    (uint8_t)((size >> 16) & 0xff),
		    (uint8_t)((size >> 8) & 0xff),
		    (uint8_t)(size & 0xff),
		};
		எனில் (sshbuf_put(iqueue, hdr, 4) != 0 ||
		    sshbuf_put(iqueue, data, size) != 0)
			செல் out;
		process();
	out:
		cleanup_handles();
		sshbuf_free(iqueue);
		sshbuf_free(oqueue);
		விடுவி(client_addr);
		iqueue = oqueue = வெற்று;
		client_addr = வெற்று;
		in_fuzz_server = 0;
		fuzz_arena_release();
		திரும்பு;
	}
	cleanup_handles();
	in_fuzz_server = 0;
	fuzz_arena_cleanup();
	iqueue = oqueue = வெற்று;
	client_addr = வெற்று;
}
