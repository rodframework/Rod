//! The Linux delivery shape: the loader execs this binary and speaks the
//! stdio protocol over it -- same plugin, same verb table as the Windows
//! cdylib.

fn main() {
    rod_plugin_sdk::serve(rod_module_conform::Conform);
}
