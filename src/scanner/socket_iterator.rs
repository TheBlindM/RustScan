//! 迭代 IP 和端口组合的 Socket 迭代器。
use itertools::{iproduct, Product};
use std::net::{IpAddr, SocketAddr};

pub struct SocketIterator<'s> {
    // product_it 是一个笛卡尔积迭代器（交叉匹配，就是mysql中的连表），
    //  端口列表 [80, 443]
    //  地址列表 [1.1.1.1, 1.1.1.2]
    // Product 的输出:
    // 1.1.1.1:80，1.1.1.1:443，1.1.1.2:80， 1.1.1.2:443
    //
    // 为什么RustScan要用笛卡尔积迭代器？
    // 节省内存，假如你现在要扫描2个ip，和65535个端口，一般方法比如Tyan中就会将所有组合都存到Vec中那将是2*65535个，使用product的话，将是2个ip和65535个端口，并不会随扫描规模扩大而内存爆炸
    //
    // 为什么要把端口放前面，而不是Ip放前面？
    //我们设想一下：
    // 当ip在外层：会同时对一个ip连续发送成千上百个端口请求
    // 当port在外层：会同时千上百个IP的一个端口发送请求
    // 可以分散压力，避免阻塞，对一个ip发包过快，会导致socket长期处于SYN_SENT，或者SYN——Queue满啦直接被丢弃啦禁默丢弃（tcp三次握手）
    product_it:
        Product<Box<std::slice::Iter<'s, u16>>, Box<std::slice::Iter<'s, std::net::IpAddr>>>,
}

impl<'s> SocketIterator<'s> {
    pub fn new(ips: &'s [IpAddr], ports: &'s [u16]) -> Self {
        let ports_it = Box::new(ports.iter());
        let ips_it = Box::new(ips.iter());
        Self {
            product_it: iproduct!(ports_it, ips_it),
        }
    }
}

#[allow(clippy::doc_link_with_quotes)]
impl Iterator for SocketIterator<'_> {
    type Item = SocketAddr;

    /// 基于提供的 IP 和端口之一的组合返回一个 socket，
    /// 或者当这些组合用尽时返回 None。
    /// 每个 IP 将具有相同的端口，直到端口递增。
    ///
    /// let it = SocketIterator::new(&["127.0.0.1", "192.168.0.1"], &[80, 443]);
    /// it.next(); // 127.0.0.1:80
    /// it.next(); // 192.168.0.1:80
    /// it.next(); // 127.0.0.1:443
    /// it.next(); // 192.168.0.1:443
    /// it.next(); // None
    fn next(&mut self) -> Option<Self::Item> {
        self.product_it
            .next()
            .map(|(port, ip)| SocketAddr::new(*ip, *port))
    }
}

#[cfg(test)]
mod tests {
    use super::SocketIterator;
    use std::net::{IpAddr, SocketAddr};

    #[test]
    fn goes_through_every_ip_port_combination() {
        let addrs = vec![
            "127.0.0.1".parse::<IpAddr>().unwrap(),
            "192.168.0.1".parse::<IpAddr>().unwrap(),
        ];
        let ports: Vec<u16> = vec![22, 80, 443];
        let mut it = SocketIterator::new(&addrs, &ports);

        assert_eq!(Some(SocketAddr::new(addrs[0], ports[0])), it.next());
        assert_eq!(Some(SocketAddr::new(addrs[1], ports[0])), it.next());
        assert_eq!(Some(SocketAddr::new(addrs[0], ports[1])), it.next());
        assert_eq!(Some(SocketAddr::new(addrs[1], ports[1])), it.next());
        assert_eq!(Some(SocketAddr::new(addrs[0], ports[2])), it.next());
        assert_eq!(Some(SocketAddr::new(addrs[1], ports[2])), it.next());
        assert_eq!(None, it.next());
    }
}
