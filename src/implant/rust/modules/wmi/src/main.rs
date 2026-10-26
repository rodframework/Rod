//! The Linux delivery shape (architecture.md Sec 5.4): the loader execs
//! this binary and speaks the stdio protocol over it -- same plugin, same
//! verb table as the Windows cdylib. The verb it serves is a Windows
//! technique and refuses at run time on this platform, but the shape
//! builds everywhere the seam compiles, so the loader's contract holds
//! whichever artifact carried the module.

fn main() {
    rod_plugin_sdk::serve(rod_module_wmi::Wmi);
}
