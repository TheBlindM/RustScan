//! 提供解析输入 IP 地址、CIDR 或文件的功能。
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{prelude::*, BufReader};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::str::FromStr;

use cidr_utils::cidr::{IpCidr, IpInet};
use hickory_resolver::{
    config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts},
    Resolver,
};
use log::debug;

use crate::input::Opts;
use crate::warning;

/// 将字符串解析为 IP 地址。
///
/// 遍历所有可能的 IP 输入（文件或通过参数解析）。
///
/// ```rust
/// # use rustscan::input::Opts;
/// # use rustscan::address::parse_addresses;
/// let mut opts = Opts::default();
/// opts.addresses = vec!["192.168.0.0/30".to_owned()];
///
/// let ips = parse_addresses(&opts);
/// ```
///
/// 最后，删除任何重复项以避免过度扫描。
pub fn parse_addresses(input: &Opts) -> Vec<IpAddr> {
    let mut ips: Vec<IpAddr> = Vec::new();
    let mut unresolved_addresses: Vec<&str> = Vec::new();
    let backup_resolver = get_resolver(&input.resolver);

    for address in &input.addresses {
        let parsed_ips = parse_address(address, &backup_resolver);
        if !parsed_ips.is_empty() {
            ips.extend(parsed_ips);
        } else {
            unresolved_addresses.push(address);
        }
    }

    // 如果我们到了这一步，这只能是一个文件路径或错误的输入。
    for file_path in unresolved_addresses {
        let file_path = Path::new(file_path);

        if !file_path.is_file() {
            warning!(
                format!("Host {file_path:?} could not be resolved."),
                input.greppable,
                input.accessible
            );

            continue;
        }

        if let Ok(x) = read_ips_from_file(file_path, &backup_resolver) {
            ips.extend(x);
        } else {
            warning!(
                format!("Host {file_path:?} could not be resolved."),
                input.greppable,
                input.accessible
            );
        }
    }

    let excluded_cidrs = parse_excluded_networks(&input.exclude_addresses, &backup_resolver);

    // 移除重复/排除的 IP。
    let mut seen = BTreeSet::new();
    ips.retain(|ip| seen.insert(*ip) && !excluded_cidrs.iter().any(|cidr| cidr.contains(ip)));

    ips
}

/// 给定一个字符串，将其解析为主机、IP 地址或 CIDR。
///
/// 这允许我们轻松地将文件作为主机、CIDR 或 IP 传递。
/// 每次有一个可能的 IP 或主机时调用此函数。
///
/// 如果地址是一个域名，我们可以在本地自行解析该域名
/// 或通过 DNS 解析器列表进行解析。
///
/// ```rust
/// # use rustscan::address::parse_address;
/// # use hickory_resolver::Resolver;
/// let ips = parse_address("127.0.0.1", &Resolver::default().unwrap());
/// ```
pub fn parse_address(address: &str, resolver: &Resolver) -> Vec<IpAddr> {
    if let Ok(addr) = IpAddr::from_str(address) {
        // `address` 是一个 IP 字符串
        vec![addr]
    } else if let Ok(net_addr) = IpInet::from_str(address) {
        // `address` 是一个 CIDR 字符串
        net_addr.network().into_iter().addresses().collect()
    } else {
        // `address` 是一个主机名或 DNS 名称
        // 尝试默认 DNS 查询
        match format!("{address}:80").to_socket_addrs() {
            Ok(mut iter) => vec![iter.next().unwrap().ip()],
            // 默认查询不起作用，因此尝试使用专用解析器再次查询
            Err(_) => resolve_ips_from_host(address, resolver),
        }
    }
}

/// 使用 DNS 获取与主机关联的 IP
fn resolve_ips_from_host(source: &str, backup_resolver: &Resolver) -> Vec<IpAddr> {
    let mut ips: Vec<IpAddr> = Vec::new();

    if let Ok(addrs) = source.to_socket_addrs() {
        for ip in addrs {
            ips.push(ip.ip());
        }
    } else if let Ok(addrs) = backup_resolver.lookup_ip(source) {
        ips.extend(addrs.iter());
    }

    ips
}

/// 从地址列表中解析排除的网络。
///
/// 此函数处理三种类型的输入：
/// 1. CIDR 表示法（例如 "192.168.0.0/24"）
/// 2. 单个 IP 地址（例如 "192.168.0.1"）
/// 3. 需要解析的主机名（例如 "example.com"）
///
/// ```rust
/// # use rustscan::address::parse_excluded_networks;
/// # use hickory_resolver::Resolver;
/// let resolver = Resolver::default().unwrap();
/// let excluded = parse_excluded_networks(&Some(vec!["192.168.0.0/24".to_owned()]), &resolver);
/// ```
pub fn parse_excluded_networks(
    exclude_addresses: &Option<Vec<String>>,
    resolver: &Resolver,
) -> Vec<IpCidr> {
    exclude_addresses
        .iter()
        .flatten()
        .flat_map(|addr| parse_single_excluded_address(addr, resolver))
        .collect()
}

/// 将单个地址解析为 IpCidr，处理 CIDR 表示法、IP 地址和主机名。
fn parse_single_excluded_address(addr: &str, resolver: &Resolver) -> Vec<IpCidr> {
    if let Ok(cidr) = IpCidr::from_str(addr) {
        return vec![cidr];
    }

    if let Ok(ip) = IpAddr::from_str(addr) {
        return vec![IpCidr::new_host(ip)];
    }

    resolve_ips_from_host(addr, resolver)
        .into_iter()
        .map(IpCidr::new_host)
        .collect()
}

/// 获取 DNS 解析器。
///
/// 1. 如果设置了 `resolver` 参数：
///     1. 假设该参数是一个路径并尝试读取 IP。
///     2. 将输入解析为逗号分隔的 IP 列表。
/// 2. 如果未设置 `resolver`：
///    1. 尝试从系统配置中获取解析器。（例如 *nix 上的 `/etc/resolv.conf`）。
///    2. 最后，构建一个基于 CloudFlare 的解析器（默认行为）。
fn get_resolver(resolver: &Option<String>) -> Resolver {
    match resolver {
        Some(r) => {
            let mut config = ResolverConfig::new();
            let resolver_ips = match read_resolver_from_file(r) {
                Ok(ips) => ips,
                Err(_) => r
                    .split(',')
                    .filter_map(|r| IpAddr::from_str(r).ok())
                    .collect::<Vec<_>>(),
            };
            for ip in resolver_ips {
                config.add_name_server(NameServerConfig::new(
                    SocketAddr::new(ip, 53),
                    Protocol::Udp,
                ));
            }
            Resolver::new(config, ResolverOpts::default()).unwrap()
        }
        None => match Resolver::from_system_conf() {
            Ok(resolver) => resolver,
            Err(_) => {
                Resolver::new(ResolverConfig::cloudflare_tls(), ResolverOpts::default()).unwrap()
            }
        },
    }
}

/// 解析用于 DNS 解析的 IP 输入文件。
fn read_resolver_from_file(path: &str) -> Result<Vec<IpAddr>, std::io::Error> {
    let ips = fs::read_to_string(path)?
        .lines()
        .filter_map(|line| IpAddr::from_str(line.trim()).ok())
        .collect();

    Ok(ips)
}

#[cfg(not(tarpaulin_include))]
/// 解析 IP 输入文件并使用这些 IP
fn read_ips_from_file(
    ips: &std::path::Path,
    backup_resolver: &Resolver,
) -> Result<Vec<IpAddr>, std::io::Error> {
    let file = File::open(ips)?;
    let reader = BufReader::new(file);

    let mut ips: Vec<IpAddr> = Vec::new();

    for address_line in reader.lines() {
        if let Ok(address) = address_line {
            ips.extend(parse_address(&address, backup_resolver));
        } else {
            debug!("Line in file is not valid");
        }
    }

    Ok(ips)
}

#[cfg(test)]
mod tests {
    use super::{get_resolver, parse_addresses, Opts};
    use std::net::Ipv4Addr;

    #[test]
    fn parse_correct_addresses() {
        let opts = Opts {
            addresses: vec!["127.0.0.1".to_owned(), "192.168.0.0/30".to_owned()],
            ..Default::default()
        };

        let ips = parse_addresses(&opts);

        assert_eq!(
            ips,
            [
                Ipv4Addr::new(127, 0, 0, 1),
                Ipv4Addr::new(192, 168, 0, 0),
                Ipv4Addr::new(192, 168, 0, 1),
                Ipv4Addr::new(192, 168, 0, 2),
                Ipv4Addr::new(192, 168, 0, 3)
            ]
        );
    }

    #[test]
    fn parse_addresses_with_address_exclusions() {
        let opts = Opts {
            addresses: vec!["192.168.0.0/30".to_owned()],
            exclude_addresses: Some(vec!["192.168.0.1".to_owned()]),
            ..Default::default()
        };
        let ips = parse_addresses(&opts);

        assert_eq!(
            ips,
            [
                Ipv4Addr::new(192, 168, 0, 0),
                Ipv4Addr::new(192, 168, 0, 2),
                Ipv4Addr::new(192, 168, 0, 3)
            ]
        );
    }

    #[test]
    fn parse_addresses_with_cidr_exclusions() {
        let opts = Opts {
            addresses: vec!["192.168.0.0/29".to_owned()],
            exclude_addresses: Some(vec!["192.168.0.0/30".to_owned()]),
            ..Default::default()
        };
        let ips = parse_addresses(&opts);

        assert_eq!(
            ips,
            [
                Ipv4Addr::new(192, 168, 0, 4),
                Ipv4Addr::new(192, 168, 0, 5),
                Ipv4Addr::new(192, 168, 0, 6),
                Ipv4Addr::new(192, 168, 0, 7),
            ]
        );
    }

    #[test]
    fn parse_addresses_with_incorrect_address_exclusions() {
        let opts = Opts {
            addresses: vec!["192.168.0.0/30".to_owned()],
            exclude_addresses: Some(vec!["192.168.0.1".to_owned()]),
            ..Default::default()
        };
        let ips = parse_addresses(&opts);

        assert_eq!(
            ips,
            [
                Ipv4Addr::new(192, 168, 0, 0),
                Ipv4Addr::new(192, 168, 0, 2),
                Ipv4Addr::new(192, 168, 0, 3)
            ]
        );
    }

    #[test]
    fn parse_correct_host_addresses() {
        let opts = Opts {
            addresses: vec!["google.com".to_owned()],
            ..Default::default()
        };

        let ips = parse_addresses(&opts);

        assert_eq!(ips.len(), 1);
    }

    #[test]
    fn parse_correct_and_incorrect_addresses() {
        let opts = Opts {
            addresses: vec!["127.0.0.1".to_owned(), "im_wrong".to_owned()],
            ..Default::default()
        };

        let ips = parse_addresses(&opts);

        assert_eq!(ips, [Ipv4Addr::new(127, 0, 0, 1),]);
    }

    #[test]
    fn parse_incorrect_addresses() {
        let opts = Opts {
            addresses: vec!["im_wrong".to_owned(), "300.10.1.1".to_owned()],
            ..Default::default()
        };

        let ips = parse_addresses(&opts);

        assert!(ips.is_empty());
    }

    #[test]
    fn parse_hosts_file_and_incorrect_hosts() {
        // Host file contains IP, Hosts, incorrect IPs, incorrect hosts
        let opts = Opts {
            addresses: vec!["fixtures/hosts.txt".to_owned()],
            ..Default::default()
        };

        let ips = parse_addresses(&opts);

        assert_eq!(ips.len(), 3);
    }

    #[test]
    fn parse_empty_hosts_file() {
        // Host file contains IP, Hosts, incorrect IPs, incorrect hosts
        let opts = Opts {
            addresses: vec!["fixtures/empty_hosts.txt".to_owned()],
            ..Default::default()
        };

        let ips = parse_addresses(&opts);

        assert_eq!(ips.len(), 0);
    }

    #[test]
    fn parse_naughty_host_file() {
        // Host file contains IP, Hosts, incorrect IPs, incorrect hosts
        let opts = Opts {
            addresses: vec!["fixtures/naughty_string.txt".to_owned()],
            ..Default::default()
        };

        let ips = parse_addresses(&opts);

        assert_eq!(ips.len(), 0);
    }

    #[test]
    fn parse_duplicate_cidrs() {
        let opts = Opts {
            addresses: vec!["79.98.104.0/21".to_owned(), "79.98.104.0/24".to_owned()],
            ..Default::default()
        };

        let ips = parse_addresses(&opts);

        assert_eq!(ips.len(), 2_048);
    }

    #[test]
    fn parse_overspecific_cidr() {
        // a canonical CIDR string has 0 in all host bits, but we want to treat any CIDR-like string as CIDR
        let opts = Opts {
            addresses: vec!["192.128.1.1/24".to_owned()],
            ..Default::default()
        };

        let ips = parse_addresses(&opts);

        assert_eq!(ips.len(), 256);
    }

    #[test]
    fn resolver_args_google_dns() {
        // https://developers.google.com/speed/public-dns
        let opts = Opts {
            resolver: Some("8.8.8.8,8.8.4.4".to_owned()),
            ..Default::default()
        };

        let resolver = get_resolver(&opts.resolver);
        let lookup = resolver.lookup_ip("www.example.com.").unwrap();

        assert!(lookup.iter().next().is_some());
    }
}
