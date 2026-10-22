// libfuzzer driver for krl parse fuzzing.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

extern "C" {
#include "includes.h"
#include "sshkey.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "krl.h"
#include "log.h"
#include "authfile.h"
}

static 整数 initialised = 0;
static FILE *null_file;
static struct sshkey *key = NULL;

extern "C" 整数 LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // single initialisation
    如果 (!initialised) {
        log_init("krl_fuzz", SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);

        如果 ((null_file = fopen("/dev/null", "w")) == NULL) 返回 0;

        如果 (sshkey_generate(KEY_ED25519, 0, &key) != 0) 返回 0;

        initialised = 1;
    }

    // Reject empty corpus
    如果 (size < 4) 返回 0;

    // Convert fuzzer data to ssh buffer
    struct sshbuf *buf = sshbuf_from(data, size);
    如果 (!buf) 返回 0;

    // Parse the ssh buffer as krl, early exit if failed
    struct ssh_krl *krl = NULL;
    整数 ret = ssh_krl_from_blob(buf, &krl);
    sshbuf_free(buf);
    如果 (ret != 0) 返回 0;

    // Fuzz serailisation roundtrip
    struct sshbuf *output = sshbuf_new();
    struct ssh_krl *krl2 = NULL;
    ssh_krl_to_blob(krl, output);
    ssh_krl_from_blob(output, &krl2);
    ssh_krl_free(krl2);
    sshbuf_free(output);

    // Fuzz krl_dump
    krl_dump(krl, null_file);

    // Fuzz ssh_krl_check_key
    ssh_krl_check_key(krl, key);

    ssh_krl_free(krl);
    返回 0;
}
