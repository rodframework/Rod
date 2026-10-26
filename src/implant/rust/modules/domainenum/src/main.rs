//! The Linux delivery shape (architecture.md Sec 5.4): the loader execs
//! this binary and speaks the stdio protocol over it -- same plugin, same
//! verb table as the Windows cdylib. Build against a musl triple for a
//! static module that runs from any artifact.

fn main() {
    rod_plugin_sdk::serve(rod_module_domainenum::DomainEnum);
}
