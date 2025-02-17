use libc;
use std::{env, mem};
use tokio::{signal, sync::mpsc};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

#[derive(Default)]
#[repr(C)]
struct TimeVal {
    tv_sec: libc::time_t,
    tv_usec: libc::suseconds_t,
}

#[derive(Default)]
#[repr(C)]
struct PcapPktHdr {
    ts: TimeVal,
    caplen: libc::c_uint,
    len: libc::c_uint,
}

#[link(name = "pcap")]
extern "C" {
    // int pcap_init(unsigned int opts, char *errbuf);
    fn pcap_init(opts: libc::c_uint, errbuf: *mut libc::c_char) -> libc::c_int;
    // pcap_t *pcap_open_live(const char *, int, int, int, char *);
    fn pcap_open_live(
        iface: *const libc::c_char,
        snaplen: libc::c_int,
        promisc: libc::c_int,
        to_ms: libc::c_int,
        errbuf: *mut libc::c_char,
    ) -> *const libc::c_void;
    // const u_char *pcap_next(pcap_t *, struct pcap_pkthdr *);
    fn pcap_next(handle: *const libc::c_void, header: *mut PcapPktHdr) -> *const libc::c_uchar;
    // void	pcap_breakloop(pcap_t *);
    fn pcap_breakloop(handle: *const libc::c_void);
}

// from pcap.h
const PCAP_ERRBUF_SIZE: usize = 256;
const PCAP_CHAR_ENC_UTF_8: libc::c_uint = 1;
const PCAP_OPENFLAG_PROMISCUOUS: libc::c_int = 1;

//-------------------------------------------------------------------------------------------------

const PCAP_SNAPLEN: libc::c_int = 14 + 60 + 4; // 14 byte Ethernet header, 60 byte IPv4 header, 4 byte TCP ports
const PCAP_TIMEOUT: libc::c_int = 100;

#[derive(Copy, Clone)]
struct Pcap {
    handle: *const libc::c_void,
}
unsafe impl Send for Pcap {}
unsafe impl Sync for Pcap {}

#[derive(Default)]
struct IfStats {
    iface: String,
    total_length: u64,
    packet_count: u64,
}

fn init_pcap() {
    let mut errbuf = [0u8; PCAP_ERRBUF_SIZE];
    if unsafe { pcap_init(PCAP_CHAR_ENC_UTF_8, mem::transmute(errbuf.as_mut_ptr())) } != 0 {
        panic!(
            "pcap_init failed: {}",
            String::from_utf8_lossy(errbuf.as_slice())
        );
    }
}

fn open_live(iface: &String) -> Pcap {
    let mut errbuf = [0u8; PCAP_ERRBUF_SIZE];
    let pcap: Pcap;
    unsafe {
        pcap = Pcap {
            handle: pcap_open_live(
                mem::transmute(iface.as_ptr()),
                PCAP_SNAPLEN,
                PCAP_OPENFLAG_PROMISCUOUS,
                PCAP_TIMEOUT,
                mem::transmute(errbuf.as_mut_ptr()),
            ),
        }
    }

    if pcap.handle.is_null() {
        panic!(
            "pcap_open_live failed: {}",
            String::from_utf8_lossy(errbuf.as_slice())
        );
    }

    return pcap;
}

async fn read_packets(
    ct: CancellationToken,
    handle: Pcap,
    iface: &String,
    stats_chan: mpsc::Sender<IfStats>,
) {
    let mut header = PcapPktHdr::default();
    let mut stats = IfStats::default();
    stats.iface = iface.clone();

    print!("Listening for packets on {}...\n", iface);

    loop {
        if ct.is_cancelled() {
            stats_chan.send(stats).await.unwrap();
            break;
        }
        let packet = unsafe { pcap_next(handle.handle, &mut header) };
        if !packet.is_null() {
            println!("{}: {} bytes", stats.iface, header.len);
            stats.total_length += header.len as u64;
            stats.packet_count += 1;
        }
    }
}

fn install_signal_handler(ct: CancellationToken, handles: Vec<Pcap>) {
    let ct2 = ct.clone();
    tokio::spawn(async move {
        match signal::ctrl_c().await {
            Ok(()) => println!("Received SIGINT"),
            Err(e) => println!("Error listening for signal: {}", e),
        }
        ct2.cancel();
        for handle in handles {
            unsafe { pcap_breakloop(handle.handle) };
        }
    });
}

#[tokio::main]
async fn main() {
    init_pcap();

    let mut handles: Vec<Pcap> = Vec::new();
    let (stats_tx, mut stats_rx) = mpsc::channel(env::args().len() - 1);
    let tracker = TaskTracker::new();
    let ct = CancellationToken::new();

    for iface in env::args().skip(1) {
        let h = open_live(&iface);
        handles.push(h);

        let handle = h;
        let stats_tx = stats_tx.clone();
        let ct = ct.clone();
        tracker.spawn(async move {
            read_packets(ct, handle, &iface, stats_tx).await;
        });
    }

    install_signal_handler(ct, handles);

    tracker.close();
    tracker.wait().await;
    stats_rx.close();

    println!("");

    let mut total_length: u64 = 0;
    let mut packet_count: u64 = 0;
    while let Some(stats) = stats_rx.recv().await {
        total_length += stats.total_length;
        packet_count += stats.packet_count;
        println!(
            "{}: {} bytes, {} packets",
            stats.iface, stats.total_length, stats.packet_count
        );
    }
    println!("Total: {} bytes, {} packets", total_length, packet_count);
}
