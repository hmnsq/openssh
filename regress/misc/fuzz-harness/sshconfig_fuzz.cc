// libfuzzer driver for SSH client configuration file parser.
// Covers readconf.c: process_config_line_depth() and related parsing logic.

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <pwd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

ਬਾਹਰੀ "C" {

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "readconf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"

// Stub out log output to reduce noise
ਖਾਲੀ sshsig_free(ਬਣਤਰ sshsig_ctx *ctx) {}

}  // extern "C"

ਸਥਿਰ ਬਣਤਰ passwd fuzz_pw;
ਸਥਿਰ ਅੱਖਰ fuzz_username[] = "fuzzer";
ਸਥਿਰ ਅੱਖਰ fuzz_home[] = "/tmp";
ਸਥਿਰ ਅੱਖਰ fuzz_shell[] = "/bin/sh";

ਸਥਿਰ ਖਾਲੀ init_pw(ਖਾਲੀ) {
    fuzz_pw.pw_name = fuzz_username;
    fuzz_pw.pw_uid = getuid();
    fuzz_pw.pw_gid = getgid();
    fuzz_pw.pw_dir = fuzz_home;
    fuzz_pw.pw_shell = fuzz_shell;
}

ਬਾਹਰੀ "C" ਪੂਰਨ LLVMFuzzer_Test_One_ਨਿਵੇਸ਼(ਅਚਲ uint8_t *ਅੰਕੜੇ, ਮਾਪ_t ਮਾਪ) {
    ਸਥਿਰ ਪੂਰਨ initialized = 0;
    ਜੇ (!initialized) {
        log_init("sshconfig_fuzz", SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_AUTH, 0);
        init_pw();
        initialized = 1;
    }

    // Write fuzz input to a temp file (read_config_file requires a path)
    ਅੱਖਰ tmpfile[] = "/tmp/sshconfig_fuzz_XXXXXX";
    ਪੂਰਨ fd = mkstemp(tmpfile);
    ਜੇ (fd < 0)
        ਵਾਪਸ 0;

    ਜੇ (ਲਿਖ(fd, ਅੰਕੜੇ, ਮਾਪ) != (ssize_t)ਮਾਪ) {
        close(fd);
        unlink(tmpfile);
        ਵਾਪਸ 0;
    }
    close(fd);

    Options options;
    initialize_options(&options);

    // Process each line through the config parser
    // Errors are intentional (fuzzing) — suppress but don't crash
    read_config_file(tmpfile, &fuzz_pw, "fuzz.example.com", "fuzz.example.com",
                     ਨਿਰਾ, &options, 0, ਨਿਰਾ);

    // Clean up allocated options
    // (options cleanup is intentionally omitted; leak sanitizer disabled for fuzzing)

    unlink(tmpfile);
    ਵਾਪਸ 0;
}
