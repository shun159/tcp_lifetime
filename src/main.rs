// SPDX-License-Identifier: LGPL-2.1 OR BSD-2-Clause

use anyhow::{bail, Result};
use chrono::Local;
use core::time::Duration;
use libbpf_rs::PerfBufferBuilder;
use libc::{rlimit, setrlimit, RLIMIT_MEMLOCK};
use libc::{
    setsockopt, socket, AF_PACKET, ETH_P_ALL, SOCK_CLOEXEC, SOCK_NONBLOCK, SOCK_RAW, SOL_SOCKET,
    SO_ATTACH_BPF,
};
use plain::Plain;
use std::net::Ipv4Addr;
use std::str;
use structopt::StructOpt;

mod bpf;
use bpf::*;

unsafe impl Plain for tcp_lifetime_bss_types::tcp_lifetime {}

#[derive(Debug, StructOpt)]
struct Command {
    #[structopt(short, long)]
    verbose: bool,
}

fn attach_socket_filter(prog_fd: i32) -> Result<()> {
    unsafe {
        let sock_flg = SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC;
        match socket(AF_PACKET, sock_flg, (ETH_P_ALL as u16).to_be().into()) {
            n if n < 0 => bail!("Failed to open raw sock"),
            sock_fd => {
                if setsockopt(
                    sock_fd,
                    SOL_SOCKET,
                    SO_ATTACH_BPF,
                    &prog_fd as *const _ as *const _,
                    std::mem::size_of_val(&prog_fd) as u32,
                ) < 0
                {
                    libc::close(sock_fd);
                    bail!("Failed to setsockopt");
                } else {
                    Ok(())
                }
            }
        }
    }
}

fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { setrlimit(RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    };

    Ok(())
}

fn handle_event(_cpu: i32, data: &[u8]) {
    let mut event = tcp_lifetime_bss_types::tcp_lifetime::default();
    plain::copy_from_bytes(&mut event, data).expect("Data buffer was too short");
    let now = Local::now().format("%Y/%m/%d %H:%M:%S %Z").to_string();
    let saddr = Ipv4Addr::from(event.session.saddr);
    let sport = event.session.sport;
    let daddr = Ipv4Addr::from(event.session.daddr);
    let dport = event.session.dport;
    let duration = event.duration / 1_000_000;
    let pid = event.pid;
    let comm = str::from_utf8(&event.task)
        .unwrap()
        .trim_matches(char::from(0));
    let src = format!("{}:{}", saddr, sport);
    let dst = format!("{}:{}", daddr, dport);
    println!(
        "{:26} | {:^10} | {:^16} | {:21} → {:21} | {:>8} ms",
        now, pid, comm, src, dst, duration
    )
}

fn handle_lost_events(cpu: i32, count: u64) {
    eprintln!("Lost {} events on CPU {}", count, cpu)
}

fn apply_options(skel_builder: &mut TcpLifetimeSkelBuilder) {
    let options = Command::from_args();
    if options.verbose {
        skel_builder.obj_builder.debug(true);
    }
}

fn load_skel<'a>() -> Result<TcpLifetimeSkel<'a>> {
    let mut skel_builder = TcpLifetimeSkelBuilder::default();
    apply_options(&mut skel_builder);
    let open_skel = skel_builder.open()?;
    let skel = open_skel.load()?;
    Ok(skel)
}

fn print_header() {
    println!(
        "{:^26} | {:^10} | {:^16} | {:^21} → {:^21} | {:^11}",
        "time", "pid", "comm", "src", "dst", "duration"
    );
}

fn poll_perf_map(skel: &mut TcpLifetimeSkel) -> Result<()> {
    let perf = PerfBufferBuilder::new(skel.maps_mut().events())
        .sample_cb(handle_event)
        .lost_cb(handle_lost_events)
        .build()?;
    loop {
        perf.poll(Duration::from_millis(100))?;
    }
}

fn main() -> Result<()> {
    bump_memlock_rlimit()?;
    let mut skel = load_skel()?;
    let prog_fd = skel.progs().measure_tcp_lifetime().fd();
    skel.attach()?;
    attach_socket_filter(prog_fd)?;
    print_header();
    poll_perf_map(&mut skel)
}
