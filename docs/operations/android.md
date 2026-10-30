# Android leg -- build, lab, device

Operational runbook for the Rust implant's Android carrier leg
([architecture.md](../architecture.md) Sec 6, Sec 12.2). The carrier source
is at [the carrier source](https://github.com/rodframework/rod-implant-rust/tree/main/carrier) --
a cdylib the package's `android.app.NativeActivity` loads, running the
implant core's library target in-process. No Java anywhere: the manifest
(`hasCode=false`) is the app's whole face, and the build unit packages it
with the SDK's own tools.

The leg serves the reach story's device half: `arm64` for phones, `amd64`
for the emulator the lab proves the leg on. The bionic floor is **API 24**
(Android 7.0), baked into the NDK clang wrapper name the cross uses and
the manifest's `minSdkVersion`.

## 1. Build-host setup (Linux, once)

Everything the leg needs runs on the Linux build host the teamserver
already uses. Three host pieces, each named by the environment report
(the System page's build section) when missing:

| Piece | What needs it | Install |
|-------|---------------|---------|
| Rust std for the triples | `rustup target add aarch64-linux-android x86_64-linux-android` | every android build |
| NDK | the cross compiler/linker | every android build; set `ANDROID_NDK_HOME` to an unpacked NDK, or install under `$ANDROID_HOME/ndk` (highest version wins) |
| SDK build-tools + a platform + JDK | the `apk` packaging chain (aapt2, zipalign, apksigner, keytool) | format `apk` only; set `ANDROID_HOME`, and `JAVA_HOME` or `java` on PATH |

The `so` format needs the first two alone -- an engagement with its own
carrier app consumes the bare library. The `apk` format adds the third.

Concretely, on a fresh host:

```
rustup target add aarch64-linux-android x86_64-linux-android
# JDK 21 (Temurin LTS) and the SDK command-line tools:
#   https://api.adoptium.net/v3/binary/latest/21/ga/linux/x64/jdk/hotspot/normal/eclipse
#   https://developer.android.com/studio#command-line-tools-only
sdkmanager "platform-tools" "emulator" "ndk;<version>" \
  "build-tools;<version>" "platforms;android-<api>" \
  "system-images;android-<api>;google_apis;x86_64"   # emulator lab only
export ANDROID_HOME=$HOME/android-sdk
export JAVA_HOME=<the jdk dir>
```

## 2. Build through the pipeline (the operator path)

Build the artifact exactly as any other: the payload form (or
`POST /engagements/{id}/payloads`) with `targetOs: android`, `targetArch:
arm64` (devices) or `amd64` (the emulator), and `format`:

- **`apk`** (default in the console) -- the installable package: the
  carrier cdylib under `lib/<abi>/`, stored uncompressed and page-aligned
  (`extractNativeLibs=false`), signed with the ecosystem's debug keystore
  (`~/.android/debug.keystore`, generated on first use).
- **`so`** -- the bare `librod_carrier.so`, for an engagement that loads
  it from its own carrier app.

The first android build per triple is a cold cargo compile of the whole
dependency set (minutes); set the build cache (Settings, or
`ROD_RUST_TARGET_DIR`) as with any other cross.

**Engagement signing:** the debug keystore is the lab shape -- a build
signed with it will not install over a package signed with anything else.
For a deliverable that must survive reinstalls and updates, bring the
engagement's own keystore: replace the signing step (or re-sign the apk
with `apksigner`) and keep the key with the engagement's records. The
package id (`rod.carrier`) and label (`Rod`) in the checked-in manifest
are the lab spellings -- an engagement renames both at packaging time so
the deliverable's face is its own.

**The manifest's debuggable flag** keeps the core's stderr diagnostics in
logcat (`adb logcat`, tag-free). The engagement shape clears it -- a
release deliverable should not volunteer its stderr.

## 3. The emulator lab (amd64)

The e2e acceptance for the leg runs on a booted emulator; the integration
suite's android test gates itself on one being present (`adb get-state`
answering `device`), and skips otherwise.

```
avdmanager create avd -n rod-lab -k "system-images;android-<api>;google_apis;x86_64" -d pixel
emulator -avd rod-lab -no-window -no-audio -no-boot-anim &   # KVM on the Linux host
adb wait-for-device shell 'while [ "$(getprop sys.boot_completed)" != 1 ]; do sleep 1; done'
```

Inside the emulator the host's loopback is `10.0.2.2` -- create the
listener with the public endpoint `http://10.0.2.2:<port>` (bind
`127.0.0.1:<port>` as usual), build `amd64`/`apk`, then download the
package from the payload row (the file name is
`rod-<class>-<payload-id prefix>.apk`, the id's first 8 hex) and:

```
adb install -r rod-implant-<payload-id-prefix>.apk
adb shell am start -n rod.carrier/android.app.NativeActivity
adb logcat -d | grep -i rod     # the core's diagnostics land on stderr
```

The implant appears on the roster and takes tasking like any desktop leg.
`adb shell am force-stop rod.carrier` stops it; `adb uninstall
rod.carrier` removes it.

## 4. Real devices (arm64)

The aarch64 cross builds on the Linux host unchanged (`targetArch:
arm64`). Delivery to a device is sideloading territory, an operational
constraint no build removes:

- **USB**: the device answers `adb` over USB. From WSL2, attach the
  device with `usbipd-win` (`usbipd bind`/`attach` on the Windows side);
  the `platform-tools` adb inside WSL2 then sees it.
- **Wireless debugging**: on the device, enable Developer options ->
  Wireless debugging; `adb pair <ip:port>` then `adb connect <ip:port>`.
  The device must reach the teamserver's listener -- bind it on an
  address the device's network can dial, not loopback.
- The package installs over either path exactly as on the emulator; a
  device enrolled through a front it can reach runs the same e2e.

**SELinux and bionic on the device:** the app domain (`untrusted_app`)
allows what the leg needs -- sockets, the system shell for one-shot
execution -- and the module family refuses rather than failing: bionic
below API 30 carries no `memfd_create` symbol, and the domain denies exec
of anonymous fds, so `module.load` answers dormant on this leg. The
foreground-service upgrade (below) is the same story: it rides the
framework's own APIs or it does not ride at all.

## 5. The background-execution constraint (the durability story)

The carrier keeps the loop alive while its process lives, which is the
emulator/lab answer and the foreground-activity answer on a device. What
Android does not give a backgrounded activity is a lifetime guarantee:
under memory pressure or Doze the process is frozen or killed, and the
loop reconnects when the user (or an alarm) launches it again.

The documented shape for legs that must hold contact through backgrounding
is a **foreground service** owning the carrier process -- the framework's
own mechanism, with its visible notification and battery cost, which is
why it is an engagement decision rather than the shipped default. Building
it means a service entry in the manifest and the JNI calls that start it
(the C-ABI surface the carrier glue already sits beside); the wire, the
core, and the build stay untouched. Nothing in-tree blocks it; no
engagement has yet named the need.
