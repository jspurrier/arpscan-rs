use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};
use std::io::{self, BufRead, Write};
use std::fs::{self, File};
use std::collections::HashMap;
use std::str::FromStr;
use std::path::{Path, PathBuf};
use std::env;

use pnet::datalink::{self, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;

use lazy_static::lazy_static;
use chrono::Local;
use users::{get_current_uid, get_user_by_uid};
#[cfg(unix)]
use users::os::unix::UserExt;
#[cfg(unix)]
use nix::unistd::{chown, Uid, Gid};

lazy_static! {
    static ref OUI_MAP: HashMap<String, String> = {
        let mut map = HashMap::new();
        match File::open("/usr/share/arpscan-rs/oui.txt") {
            Ok(file) => {
                let reader = io::BufReader::new(file);
                let mut current_oui = String::new();

                for line in reader.lines().filter_map(Result::ok) {
                    let line = line.trim();
                    if line.contains("(hex)") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 3 {
                            current_oui = parts[0].replace("-", "").to_uppercase();
                        }
                    } else if !current_oui.is_empty() && line.contains("base 16") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 4 {
                            let manufacturer = parts[3..].join(" ");
                            map.insert(current_oui.clone(), manufacturer);
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to open /usr/share/arpscan-rs/oui.txt: {}", e);
            }
        }
        map
    };
}

fn get_manufacturer(mac: &MacAddr) -> String {
    let mac_prefix = format!("{:02X}{:02X}{:02X}", mac.0, mac.1, mac.2);
    OUI_MAP.get(&mac_prefix)
        .map(|s| s.to_string())
        .unwrap_or_else(|| "Unknown".to_string())
}

fn get_default_interface() -> Option<NetworkInterface> {
    let interfaces = datalink::interfaces();
    interfaces
        .into_iter()
        .find(|iface| {
            iface.is_up()
            && !iface.is_loopback()
            && !iface.ips.is_empty()
            && iface.mac.is_some()
        })
}

fn parse_cidr(cidr: &str) -> Result<(Ipv4Addr, u32), String> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err("Invalid CIDR format. Use: x.x.x.x/n".to_string());
    }

    let ip = Ipv4Addr::from_str(parts[0])
        .map_err(|e| format!("Invalid IP address: {}", e))?;
    let mask = parts[1]
        .parse::<u32>()
        .map_err(|e| format!("Invalid subnet mask: {}", e))?;

    if mask > 32 {
        return Err("Subnet mask must be between 0 and 32".to_string());
    }

    Ok((ip, mask))
}

fn ip_to_u32(ip: Ipv4Addr) -> u32 {
    u32::from_be_bytes(ip.octets())
}

fn u32_to_ip(n: u32) -> Ipv4Addr {
    Ipv4Addr::from(n.to_be_bytes())
}

fn get_documents_dir() -> Result<PathBuf, String> {
    #[cfg(unix)]
    {
        let uid = env::var("SUDO_UID")
            .ok()
            .and_then(|uid_str| uid_str.parse::<u32>().ok())
            .unwrap_or_else(get_current_uid);
        let user = get_user_by_uid(uid).ok_or("Could not determine current user")?;
        let home_dir = user.home_dir();
        let docs_dir = Path::new(home_dir).join("Documents");

        if docs_dir.exists() && docs_dir.is_dir() {
            Ok(docs_dir)
        } else {
            fs::create_dir_all(&docs_dir)
                .map_err(|e| format!("Failed to create Documents directory: {}", e))?;
            Ok(docs_dir)
        }
    }
    #[cfg(windows)]
    {
        let home_dir = env::var("USERPROFILE")
            .map_err(|e| format!("Could not get USERPROFILE: {}", e))?;
        let docs_dir = Path::new(&home_dir).join("Documents");

        if docs_dir.exists() && docs_dir.is_dir() {
            Ok(docs_dir)
        } else {
            fs::create_dir_all(&docs_dir)
                .map_err(|e| format!("Failed to create Documents directory: {}", e))?;
            Ok(docs_dir)
        }
    }
}

fn scan_network(cidr: &str) -> Result<(), String> {
    if !Path::new("/usr/share/arpscan-rs/oui.txt").exists() {
        return Err("Error: /usr/share/arpscan-rs/oui.txt not found.".to_string());
    }

    let (network, mask) = parse_cidr(cidr)?;
    let interface = get_default_interface()
        .ok_or_else(|| {
            let os_msg = if cfg!(target_os = "windows") {
                "No suitable network interface found. Ensure you’re running with administrative privileges."
            } else {
                "No suitable network interface found. Ensure you’re running with root privileges (e.g., sudo)."
            };
            os_msg.to_string()
        })?;

    let source_ip = interface.ips.iter()
        .find(|ip| ip.is_ipv4())
        .map(|ip| match ip.ip() {
            IpAddr::V4(ip) => ip,
            _ => Ipv4Addr::new(0, 0, 0, 0),
        })
        .unwrap_or(Ipv4Addr::new(0, 0, 0, 0));

    let source_mac = interface.mac.unwrap_or(MacAddr::zero());
    let mut results = HashMap::new();

    let network_u32 = ip_to_u32(network) & !(0xFFFFFFFF >> mask);
    let host_count = 1 << (32 - mask);

    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err("Unhandled channel type".to_string()),
        Err(e) => {
            let os_msg = if cfg!(target_os = "windows") {
                format!("Failed to create channel: {}. Ensure you’re running as Administrator.", e)
            } else {
                format!("Failed to create channel: {}. Ensure you’re running with sudo.", e)
            };
            return Err(os_msg);
        }
    };

    let start_time = Instant::now();

    for i in 1..host_count - 1 {
        let target_ip = u32_to_ip(network_u32 + i);

        let mut ethernet_buffer = [0u8; 42];
        let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer)
            .ok_or("Failed to create ethernet packet")?;

        ethernet_packet.set_destination(MacAddr::broadcast());
        ethernet_packet.set_source(source_mac);
        ethernet_packet.set_ethertype(EtherTypes::Arp);

        let mut arp_buffer = [0u8; 28];
        let mut arp_packet = MutableArpPacket::new(&mut arp_buffer)
            .ok_or("Failed to create ARP packet")?;

        arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_packet.set_protocol_type(EtherTypes::Ipv4);
        arp_packet.set_hw_addr_len(6);
        arp_packet.set_proto_addr_len(4);
        arp_packet.set_operation(ArpOperations::Request);
        arp_packet.set_sender_hw_addr(source_mac);
        arp_packet.set_sender_proto_addr(source_ip);
        arp_packet.set_target_hw_addr(MacAddr::zero());
        arp_packet.set_target_proto_addr(target_ip);

        ethernet_packet.set_payload(arp_packet.packet_mut());

        if tx.send_to(ethernet_packet.packet(), None).is_none() {
            println!("Warning: Failed to send packet to {}", target_ip);
        }
    }

    while start_time.elapsed() < Duration::from_secs(5) {
        match rx.next() {
            Ok(packet) => {
                if let Some(ethernet) = pnet::packet::ethernet::EthernetPacket::new(packet) {
                    if ethernet.get_ethertype() == EtherTypes::Arp {
                        if let Some(arp) = pnet::packet::arp::ArpPacket::new(ethernet.payload()) {
                            if arp.get_operation() == ArpOperations::Reply {
                                let ip = arp.get_sender_proto_addr();
                                let mac = arp.get_sender_hw_addr();
                                results.insert(ip, mac);
                            }
                        }
                    }
                }
            }
            Err(e) => {
                println!("Warning: Failed to receive packet: {}", e);
                continue;
            }
        }
    }

    // Sort results by IP address
    let mut sorted_results: Vec<(Ipv4Addr, MacAddr)> = results.into_iter().collect();
    sorted_results.sort_by(|a, b| ip_to_u32(a.0).cmp(&ip_to_u32(b.0)));

    println!("\nScan Results:");
    println!("{:<16} {:<18} {}", "IP Address", "MAC Address", "Manufacturer");
    println!("{:-<16} {:-<18} {:-<30}", "", "", "");
    for (ip, mac) in &sorted_results {
        let manufacturer = get_manufacturer(mac);
        println!("{:<16} {:<18} {}", ip, mac, manufacturer);
    }

    // Prompt user to save
    println!("\nSave results to CSV? (y/n):");
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read input");
    let save = input.trim().to_lowercase();

    if save == "y" || save == "yes" {
        let docs_base = get_documents_dir()?;
        let arpscan_dir = docs_base.join("arpscan");

        fs::create_dir_all(&arpscan_dir).map_err(|e| format!("Failed to create arpscan directory: {}", e))?;

        // On Unix, set ownership of the arpscan directory if run with sudo
        #[cfg(unix)]
        {
            if let Ok(sudo_uid) = env::var("SUDO_UID").and_then(|uid| uid.parse::<u32>().map_err(|_| env::VarError::NotPresent)) {
                let sudo_gid = env::var("SUDO_GID").and_then(|gid| gid.parse::<u32>().map_err(|_| env::VarError::NotPresent)).ok();
                let uid = Uid::from_raw(sudo_uid);
                let gid = sudo_gid.map(Gid::from_raw);
                chown(&arpscan_dir, Some(uid), gid).map_err(|e| format!("Failed to set arpscan directory ownership: {}", e))?;
            }
        }

        let timestamp = Local::now().format("%m_%d_%Y_%H_%M_%S").to_string();
        let filename = format!("arpscan_results_{}.csv", timestamp);
        let filepath = arpscan_dir.join(&filename);

        let mut file = File::create(&filepath).map_err(|e| format!("Failed to create CSV file: {}", e))?;

        // On Unix, set ownership of the file immediately after creation
        #[cfg(unix)]
        {
            if let Ok(sudo_uid) = env::var("SUDO_UID").and_then(|uid| uid.parse::<u32>().map_err(|_| env::VarError::NotPresent)) {
                let sudo_gid = env::var("SUDO_GID").and_then(|gid| gid.parse::<u32>().map_err(|_| env::VarError::NotPresent)).ok();
                let uid = Uid::from_raw(sudo_uid);
                let gid = sudo_gid.map(Gid::from_raw);
                chown(&filepath, Some(uid), gid).map_err(|e| format!("Failed to set file ownership: {}", e))?;
            }
        }

        writeln!(file, "IP Address,MAC Address,Manufacturer").map_err(|e| format!("Failed to write CSV header: {}", e))?;
        for (ip, mac) in &sorted_results {
            let manufacturer = get_manufacturer(mac);
            writeln!(file, "{},{},{}", ip, mac, manufacturer).map_err(|e| format!("Failed to write CSV row: {}", e))?;
        }

        println!("Results saved to {:?}", filepath);
    } else {
        println!("Results not saved.");
    }

    Ok(())
}

fn main() {
    println!("Enter network to scan (e.g., 192.168.1.0/24):");
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read input");

    let cidr = input.trim();

    println!("Note: This program requires elevated privileges.");
    println!("{}", if cfg!(target_os = "windows") {
        "On Windows, run as Administrator (e.g., from an elevated Command Prompt or PowerShell)."
    } else {
        "On Linux, run with sudo (e.g., 'sudo ./arpscan-rs')."
    });

    match scan_network(cidr) {
        Ok(()) => println!("\nScan completed successfully"),
        Err(e) => println!("Error: {}", e),
    }
}
