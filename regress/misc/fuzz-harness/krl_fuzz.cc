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

static ціле initialised = 0;
static FILE *null_file;
static struct sshkey *key = NULL;

extern "C" ціле LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // single initialisation
    якщо (!initialised) {
        log_init("krl_fuzz", SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);

        якщо ((null_file = fopen("/dev/null", "w")) == NULL) повернути 0;

        якщо (sshkey_generate(KEY_ED25519, 0, &key) != 0) повернути 0;

        initialised = 1;
    }

    // Reject empty corpus
    якщо (size < 4) повернути 0;

    // Convert fuzzer data to ssh buffer
    struct sshbuf *buf = sshbuf_from(data, size);
    якщо (!buf) повернути 0;

    // Parse the ssh buffer as krl, early exit if failed
    struct ssh_krl *krl = NULL;
    ціле ret = ssh_krl_from_blob(buf, &krl);
    sshbuf_free(buf);
    якщо (ret != 0) повернути 0;

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
    повернути 0;
}
