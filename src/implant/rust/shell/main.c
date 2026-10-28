/*
 * The worked non-Rust shell over the linkable core (architecture.md
 * Sec 15.2, ADR-018): the whole wire stack comes from the static library;
 * this file is only policy -- read the candidate contract's environment,
 * hand it to the core, and pump. It mirrors the reference implant's dev
 * shape variable for variable, so the binary is a drop-in candidate
 * wherever the Rust one goes, `rod conform` included:
 *
 *   ROD_ENROLL_URL, ROD_DEPLOY_TOKEN, ROD_KILL_DATE   the contract (implants.md)
 *   ROD_VERBS, ROD_MODE, ROD_SLEEP, ROD_JITTER        the dev-shape knobs
 *
 * Silent by default: the core owns the ROD_VERBOSE diagnostics and this
 * shell prints nothing but an ABI mismatch. The exit code is the core's
 * own state read. Any language that can link the static library writes
 * this same shape; C is just the worked example.
 *
 * Build (Linux):
 *   cargo build --release
 *   cc -O2 -o rod-shell shell/main.c \
 *      target/release/librod_implant.a -lpthread -lm -ldl
 */
#include "../include/rod_core.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* The dev shape's defaults, the same numbers the crate's env profile
 * carries: a 30s cadence with 10s jitter, narrowed per deployment by the
 * environment (the conformance harness runs ROD_SLEEP=1). */
static const double k_default_sleep = 30.0;
static const double k_default_jitter = 10.0;

static const char *env_or(const char *name, const char *fallback)
{
    const char *value = getenv(name);
    return value && *value ? value : fallback;
}

/* Reads a seconds knob; atof also accepts the crate's "30s" form because
 * it stops at the unit. */
static double seconds_or(const char *name, double fallback)
{
    const char *text = getenv(name);
    if (!text || !*text)
        return fallback;
    return atof(text);
}

static void sleep_ms(unsigned milliseconds)
{
    struct timespec wait = {
        .tv_sec = milliseconds / 1000,
        .tv_nsec = (long)(milliseconds % 1000) * 1000000,
    };
    while (nanosleep(&wait, &wait) == -1) {
        /* Only EINTR resumes; the remaining time is already in wait. */
    }
}

int main(void)
{
    if (rod_core_abi_version() != ROD_CORE_ABI_VERSION) {
        fprintf(stderr, "rod-shell: core ABI %u, shell ABI %u\n",
                rod_core_abi_version(), ROD_CORE_ABI_VERSION);
        return 3;
    }

    rod_core_profile profile = {0};
    profile.struct_size = sizeof profile;
    profile.enroll_url = env_or("ROD_ENROLL_URL", "");
    profile.deploy_token = env_or("ROD_DEPLOY_TOKEN", "");
    profile.kill_date = getenv("ROD_KILL_DATE");
    profile.verbs = getenv("ROD_VERBS");
    profile.mode = env_or("ROD_MODE", "poll");
    profile.sleep_seconds = seconds_or("ROD_SLEEP", k_default_sleep);
    profile.jitter_seconds = seconds_or("ROD_JITTER", k_default_jitter);

    rod_core *core = rod_core_init_with_profile(&profile);
    if (!core)
        return 2;

    /* The shell's whole run: pump what is due, spend the wait the core
     * asks for, until the machine answers done. */
    rod_state state = {0};
    state.struct_size = sizeof state;
    while (rod_core_pump(core) != ROD_CORE_DONE) {
        if (rod_core_state(core, &state) == 0 && state.wait_ms > 0)
            sleep_ms(state.wait_ms);
    }
    rod_core_state(core, &state);
    rod_core_free(core);
    return state.exit_code;
}
