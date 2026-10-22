// libfuzzer driver for SSH client configuration file parser.
// Covers readconf.c: process_config_line_depth() and related parsing logic.

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <pwd.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

ಬಾಹ್ಯ "C" {

#ಅನ್ತರ್ಭಾವ "includes.h"
#ಅನ್ತರ್ಭಾವ "ssh.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "readconf.h"
#ಅನ್ತರ್ಭಾವ "xmalloc.h"

// Stub out log output to reduce noise
ಶೂನ್ಯ sshsig_free(ಸಂರಚನಾ sshsig_ctx *ctx) {}

}  // extern "C"

ಸ್ಥಿರ ಸಂರಚನಾ passwd fuzz_pw;
ಸ್ಥಿರ ವರ್ಣ fuzz_username[] = "fuzzer";
ಸ್ಥಿರ ವರ್ಣ fuzz_home[] = "/tmp";
ಸ್ಥಿರ ವರ್ಣ fuzz_shell[] = "/bin/sh";

ಸ್ಥಿರ ಶೂನ್ಯ init_pw(ಶೂನ್ಯ) {
    fuzz_pw.pw_name = fuzz_username;
    fuzz_pw.pw_uid = getuid();
    fuzz_pw.pw_gid = getgid();
    fuzz_pw.pw_dir = fuzz_home;
    fuzz_pw.pw_shell = fuzz_shell;
}

ಬಾಹ್ಯ "C" ಪೂರ್ಣಾಙ್ಕ LLVMFuzzer_Test_One_ಒಳಹರಿವು(ಧ್ರುವ uint8_t *data, size_t size) {
    ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ initialized = 0;
    ಯದಿ (!initialized) {
        log_init("sshconfig_fuzz", SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_AUTH, 0);
        init_pw();
        initialized = 1;
    }

    // Write fuzz input to a temp file (read_config_file requires a path)
    ವರ್ಣ tmpfile[] = "/tmp/sshconfig_fuzz_XXXXXX";
    ಪೂರ್ಣಾಙ್ಕ fd = mkstemp(tmpfile);
    ಯದಿ (fd < 0)
        ಪ್ರತ್ಯಾಗಮ 0;

    ಯದಿ (ಲಿಖ(fd, data, size) != (ssize_t)size) {
        close(fd);
        unlink(tmpfile);
        ಪ್ರತ್ಯಾಗಮ 0;
    }
    close(fd);

    Options options;
    initialize_options(&options);

    // Process each line through the config parser
    // Errors are intentional (fuzzing) — suppress but don't crash
    read_config_file(tmpfile, &fuzz_pw, "fuzz.example.com", "fuzz.example.com",
                     ರಿಕ್ತ, &options, 0, ರಿಕ್ತ);

    // Clean up allocated options
    // (options cleanup is intentionally omitted; leak sanitizer disabled for fuzzing)

    unlink(tmpfile);
    ಪ್ರತ್ಯಾಗಮ 0;
}
