//! 这个 crate 暴露了 [RustScan](https://rustscan.github.io/RustScan) 端口扫描器的内部功能。
//!
//! ## 示例：对 localhost 进行扫描
//!
//! 核心扫描行为由 [`Scanner`](crate::scanner::Scanner) 管理，它反过来需要一个
//! [`PortStrategy`](crate::port_strategy::PortStrategy)：
//!
//! ```rust
//! use async_std::task::block_on;
//! use std::{net::IpAddr, time::Duration};
//!
//! use rustscan::input::{PortRange, ScanOrder};
//! use rustscan::port_strategy::PortStrategy;
//! use rustscan::scanner::Scanner;
//!
//! fn main() {
//!     let addrs = vec!["127.0.0.1".parse::<IpAddr>().unwrap()];
//!     let range = PortRange {
//!         start: 1,
//!         end: 1_000,
//!     };
//!     let strategy = PortStrategy::pick(&Some(range), None, ScanOrder::Random); // 可以是顺序的、随机的或手动的 https://github.com/RustScan/RustScan/blob/master/src/port_strategy/mod.rs
//!     let scanner = Scanner::new(
//!         &addrs, // 要扫描的地址
//!         10, // batch_size 是一次扫描多少个端口
//!         Duration::from_millis(100), // Timeout 是 RustScan 在声明端口关闭之前等待的时间。数据类型为 Duration。
//!         1, // Tries，RustScan 应该重试多少次？
//!         true, // greppable 是 RustScan 是否应该打印内容，或者等到最后只打印 ip
//!         strategy, // 使用的端口策略
//!         true, // accessible，输出是否应该符合 A11Y 标准？
//!         vec![9000], // RustScan 应该排除哪些端口？
//!         false, // 这是 UDP 扫描吗？
//!     );
//!
//!     let scan_result = block_on(scanner.run());
//!
//!     println!("{:?}", scan_result);
//! }
//! ```
#![allow(clippy::needless_doctest_main)]

pub mod tui;

pub mod input;

pub mod scanner;

pub mod port_strategy;

pub mod benchmark;

pub mod scripts;

pub mod address;

pub mod generated;
