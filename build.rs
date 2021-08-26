use libbpf_cargo::SkeletonBuilder;
use std::path::Path;

const SRC: &str = "./src/bpf/tcp_lifetime.bpf.c";

fn main() {
    let skel = Path::new("./src/bpf/tcp_lifetime.skel.rs");
    SkeletonBuilder::new(SRC).generate(&skel).unwrap();
    println!("cargo:rerun-if-changed={}", SRC);
}
