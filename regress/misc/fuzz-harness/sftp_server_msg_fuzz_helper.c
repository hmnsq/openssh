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

#അന്തര്ഭാവ <setjmp.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <pwd.h>
#അന്തര്ഭാവ <sys/types.h>

#അന്തര്ഭാവ "log.h"

ബാഹ്യ ശൂന്യം fuzz_arena_begin(ശൂന്യം);
ബാഹ്യ ശൂന്യം fuzz_arena_release(ശൂന്യം);
ബാഹ്യ ശൂന്യം fuzz_arena_cleanup(ശൂന്യം);

സ്ഥിതം jmp_buf fuzz_server_env;
സ്ഥിതം അസ്ഥിര പൂർണ്ണസംഖ്യ in_fuzz_server = 0;

ശൂന്യം
cleanup_exit(പൂർണ്ണസംഖ്യ code)
{
	എങ്കിൽ (in_fuzz_server)
		longjmp(fuzz_server_env, code ? code : 1);
	_exit(code);
}

#define sftp_server_cleanup_exit __orig_sftp_server_cleanup_exit
#അന്തര്ഭാവ "../../../sftp-server.c"
#undef sftp_server_cleanup_exit

ശൂന്യം
sftp_server_cleanup_exit(പൂർണ്ണസംഖ്യ code)
{
	എങ്കിൽ (in_fuzz_server)
		longjmp(fuzz_server_env, code ? code : 1);
	_exit(code);
}

സ്ഥിതം ശൂന്യം (* സ്ഥിരം __force_use_renamed)(പൂർണ്ണസംഖ്യ) =
    __orig_sftp_server_cleanup_exit;

സ്ഥിതം ഘടന passwd fuzz_pw;
സ്ഥിതം പൂർണ്ണസംഖ്യ log_initialized = 0;

സ്ഥിതം ശൂന്യം
cleanup_handles(ശൂന്യം)
{
	u_int i;
	എങ്കിൽ (handles == ശൂന്യ)
		തിരികെ;
	വേണ്ടി (i = 0; i < അക്കം_handles; i++) {
		എങ്കിൽ (handles[i].use == HANDLE_FILE && handles[i].fd >= 0)
			close(handles[i].fd);
		അല്ലെങ്കിൽ എങ്കിൽ (handles[i].use == HANDLE_DIR && handles[i].dirp != ശൂന്യ)
			closedir(handles[i].dirp);
		സ്വതന്ത്രം(handles[i].name);
	}
	സ്വതന്ത്രം(handles);
	handles = ശൂന്യ;
	അക്കം_handles = 0;
	first_unused_handle = -1;
}

സ്ഥിതം ശൂന്യം
reset_module_globals(ശൂന്യം)
{
	pw = &fuzz_pw;
	client_addr = ശൂന്യ;
	version = 0;
	init_done = 0;
	readonly = 0;
	request_allowlist = ശൂന്യ;
	request_denylist = ശൂന്യ;
	handles = ശൂന്യ;
	അക്കം_handles = 0;
	first_unused_handle = -1;
	iqueue = ശൂന്യ;
	oqueue = ശൂന്യ;
}

ശൂന്യം
fuzz_server_one(സ്ഥിരം uint8_t *data, size_t size)
{
	എങ്കിൽ (!log_initialized) {
		log_initialized = 1;
		log_init("sftp_server_msg_fuzz", SYSLOG_LEVEL_ERROR,
		    SYSLOG_FACILITY_AUTH, 0);

		/* Confine filesystem syscalls (process_open/mkdir/symlink) to a fresh tmpdir. */
		അക്ഷരം tmpdir[] = "/tmp/sftp_fuzz_XXXXXX";
		എങ്കിൽ (mkdtemp(tmpdir) != ശൂന്യ && chdir(tmpdir) != 0)
			_exit(1);

		memset(&fuzz_pw, 0, വലുപ്പം(fuzz_pw));
		fuzz_pw.pw_name = (അക്ഷരം *)"fuzz";
		fuzz_pw.pw_uid = getuid();
		fuzz_pw.pw_gid = getgid();
		fuzz_pw.pw_dir = (അക്ഷരം *)"/tmp";
		fuzz_pw.pw_shell = (അക്ഷരം *)"/bin/sh";
	}

	എങ്കിൽ (size == 0 || size > 65000)
		തിരികെ;

	reset_module_globals();

	fuzz_arena_begin();
	in_fuzz_server = 1;
	എങ്കിൽ (setjmp(fuzz_server_env) == 0) {
		client_addr = strdup("127.0.0.1");
		iqueue = sshbuf_new();
		oqueue = sshbuf_new();
		എങ്കിൽ (iqueue == ശൂന്യ || oqueue == ശൂന്യ)
			പോകുക out;

		സ്ഥിരം uint8_t init_സന്ദേശം[] = {
		    0x00, 0x00, 0x00, 0x05,
		    SSH2_FXP_INIT,
		    0x00, 0x00, 0x00, 0x03,
		};
		എങ്കിൽ (sshbuf_put(iqueue, init_സന്ദേശം, വലുപ്പം(init_സന്ദേശം)) != 0)
			പോകുക out;
		process();

		sshbuf_reset(iqueue);
		sshbuf_reset(oqueue);

		uint8_t hdr[4] = {
		    (uint8_t)((size >> 24) & 0xff),
		    (uint8_t)((size >> 16) & 0xff),
		    (uint8_t)((size >> 8) & 0xff),
		    (uint8_t)(size & 0xff),
		};
		എങ്കിൽ (sshbuf_put(iqueue, hdr, 4) != 0 ||
		    sshbuf_put(iqueue, data, size) != 0)
			പോകുക out;
		process();
	out:
		cleanup_handles();
		sshbuf_free(iqueue);
		sshbuf_free(oqueue);
		സ്വതന്ത്രം(client_addr);
		iqueue = oqueue = ശൂന്യ;
		client_addr = ശൂന്യ;
		in_fuzz_server = 0;
		fuzz_arena_release();
		തിരികെ;
	}
	cleanup_handles();
	in_fuzz_server = 0;
	fuzz_arena_cleanup();
	iqueue = oqueue = ശൂന്യ;
	client_addr = ശൂന്യ;
}
