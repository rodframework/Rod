//go:build !linux

// The dormant floors (architecture.md Sec 5.4, the reference implant's cfg
// posture): the exec-v1 loader needs an anonymous fd the kernel will exec,
// and outside Linux this build hosts no loader family at all -- macOS has
// no anonymous-fd exec on the kernel, and the Windows floor's loader
// families (native-v1, coff-v1) have no Go host. module.load refuses with
// the floor named rather than staging bytes nothing can run.
package plugins

import (
	"fmt"
	"runtime"
)

// loadLibrary refuses on every non-Linux floor, naming it -- the dormant
// refusal the reference implant answers on the legs its loaders do not
// serve.
func loadLibrary(handle string, bytes []byte) (Library, error) {
	switch runtime.GOOS {
	case "darwin":
		return nil, fmt.Errorf("module.load: the module family is dormant on the macOS leg (no anonymous-fd exec on the kernel)")
	case "android":
		return nil, fmt.Errorf("module.load: the module family is dormant on the Android leg (no anonymous-fd exec under the app domain)")
	default:
		return nil, fmt.Errorf("module.load: the module family carries no loader on the %s floor", runtime.GOOS)
	}
}

// LoaderCapabilities answers no loaders: the handshake advertisement stays
// without plugin rows, so the server's requirement gate refuses module
// tasking for this build rather than delivering bytes it cannot host.
func LoaderCapabilities() []string {
	return nil
}
