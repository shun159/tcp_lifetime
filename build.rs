use libbpf_cargo::SkeletonBuilder;
use std::fs::create_dir_all;
use std::path::Path;

const SRC: &str = "./src/bpf/tcp_lifetime.bpf.c";
const DST: &str = "./src/bpf/";

fn main() {
    create_dir_all(DST).unwrap();
    let skel = Path::new("./src/bpf/tcp_lifetime.skel.rs");
    SkeletonBuilder::new(SRC).generate(&skel).unwrap();
    println!("cargo:rerun-if-changed={}", SRC);
}
