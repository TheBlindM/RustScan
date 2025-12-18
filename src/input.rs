//! 提供一种读取、解析和保存扫描配置选项的方法。
use clap::{Parser, ValueEnum};
use serde_derive::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

const LOWEST_PORT_NUMBER: u16 = 1;
const TOP_PORT_NUMBER: u16 = 65535;

/// 表示端口扫描运行的策略。
///   - Serial 将从开始到结束运行，例如 1 到 1_000。
///   - Random 将随机化端口扫描的顺序。
#[derive(Deserialize, Debug, ValueEnum, Clone, Copy, PartialEq, Eq)]
pub enum ScanOrder {
    Serial,
    Random,
}

/// 表示脚本变体。
///   - none 将避免运行任何脚本，只显示端口扫描结果。
///   - default 将运行默认的嵌入式 nmap 脚本，这是 RustScan 从一开始就包含的一部分。
///   - custom 将读取 ScriptConfig 文件和预定义文件夹中的可用脚本
#[derive(Deserialize, Debug, ValueEnum, Clone, PartialEq, Eq, Copy)]
pub enum ScriptsRequired {
    None,
    Default,
    Custom,
}

/// 表示要扫描的端口范围。
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

#[cfg(not(tarpaulin_include))]
fn parse_range(input: &str) -> Result<PortRange, String> {
    let range = input
        .split('-')
        .map(str::parse)
        .collect::<Result<Vec<u16>, std::num::ParseIntError>>();

    if range.is_err() {
        return Err(String::from(
            "the range format must be 'start-end'. Example: 1-1000.",
        ));
    }

    match range.unwrap().as_slice() {
        [start, end] => Ok(PortRange {
            start: *start,
            end: *end,
        }),
        _ => Err(String::from(
            "the range format must be 'start-end'. Example: 1-1000.",
        )),
    }
}

#[derive(Parser, Debug, Clone)]
#[command(
    name = "rustscan",
    version = env!("CARGO_PKG_VERSION"),
    max_term_width = 120,
    help_template = "{bin} {version}\n{about}\n\nUSAGE:\n    {usage}\n\nOPTIONS:\n{options}",
)]
#[allow(clippy::struct_excessive_bools)]
/// 用 Rust 构建的快速端口扫描器。
/// 警告：不要对敏感的基础设施使用此程序，因为指定的服务器可能无法同时处理这么多 socket 连接。
/// - Discord  <http://discord.skerritt.blog>
/// - GitHub <https://github.com/RustScan/RustScan>
pub struct Opts {
    /// 以逗号分隔的列表或以换行符分隔的文件，其中包含要扫描的 CIDR、IP 或主机。
    #[arg(short, long, value_delimiter = ',')]
    pub addresses: Vec<String>,

    /// 要扫描的逗号分隔端口列表。示例：80,443,8080。
    #[arg(short, long, value_delimiter = ',')]
    pub ports: Option<Vec<u16>>,

    /// 格式为 start-end 的端口范围。示例：1-1000。
    #[arg(short, long, conflicts_with = "ports", value_parser = parse_range)]
    pub range: Option<PortRange>,

    /// 是否忽略配置文件。
    #[arg(short, long)]
    pub no_config: bool,

    /// 隐藏 banner
    #[arg(long)]
    pub no_banner: bool,

    /// 配置文件的自定义路径
    #[arg(short, long, value_parser)]
    pub config_path: Option<PathBuf>,

    /// Grep 模式。仅输出端口。没有 Nmap。用于 grep 或输出到文件。
    #[arg(short, long)]
    pub greppable: bool,

    /// 无障碍模式。关闭会对屏幕阅读器产生负面影响的功能。
    #[arg(long)]
    pub accessible: bool,

    /// 逗号分隔的列表或文件，包含 DNS 解析器。
    #[arg(long)]
    pub resolver: Option<String>,

    /// 端口扫描的批处理大小，它会增加或减慢扫描速度。
    /// 取决于操作系统的打开文件限制。如果你设置为 65535，
    /// 它将同时扫描每个端口。虽然你的操作系统可能不支持这一点。
    #[arg(short, long, default_value = "4500")]
    pub batch_size: usize,

    /// 在假定端口关闭之前的超时时间（以毫秒为单位）。
    #[arg(short, long, default_value = "1500")]
    pub timeout: u32,

    /// 在假定端口关闭之前的重试次数。
    /// 如果设置为 0，rustscan 将将其更正为 1。
    #[arg(long, default_value = "1")]
    pub tries: u8,

    /// 自动使用你提供的值提高 ULIMIT。
    #[arg(short, long)]
    pub ulimit: Option<usize>,

    /// 要执行的扫描顺序。"serial" 选项将按升序扫描端口，
    /// 而 "random" 选项将随机扫描端口。
    #[arg(long, value_enum, ignore_case = true, default_value = "serial")]
    pub scan_order: ScanOrder,

    /// 运行所需的脚本级别。
    #[arg(long, value_enum, ignore_case = true, default_value = "default")]
    pub scripts: ScriptsRequired,

    /// 使用前 1000 个端口。
    #[arg(long)]
    pub top: bool,

    /// 要运行的脚本参数。
    /// 要使用参数 -A，请以 '-- -A' 结束 RustScan 的参数。
    /// 示例：'rustscan -t 1500 -a 127.0.0.1 -- -A -sC'。
    /// 此命令会自动将 -Pn -vvv -p $PORTS 添加到 nmap。
    /// 对于像 --script '(safe and vuln)' 这样的东西，请将其括在引号中 \"'(safe and vuln)'\"
    #[arg(last = true)]
    pub command: Vec<String>,

    /// 要从扫描中排除的逗号分隔端口列表。示例：80,443,8080。
    #[arg(short, long, value_delimiter = ',')]
    pub exclude_ports: Option<Vec<u16>>,

    /// 要从扫描中排除的逗号分隔 CIDR、IP 或主机列表。
    #[arg(short = 'x', long = "exclude-addresses", value_delimiter = ',')]
    pub exclude_addresses: Option<Vec<String>>,

    /// UDP 扫描模式，查找发回响应的 UDP 端口
    #[arg(long)]
    pub udp: bool,
}

#[cfg(not(tarpaulin_include))]
impl Opts {
    pub fn read() -> Self {
        let mut opts = Opts::parse();

        if opts.ports.is_none() && opts.range.is_none() {
            opts.range = Some(PortRange {
                start: LOWEST_PORT_NUMBER,
                end: TOP_PORT_NUMBER,
            });
        }

        opts
    }

    /// 将命令行参数读取到 Opts 结构中，并合并在用户配置文件中找到的值。
    pub fn merge(&mut self, config: &Config) {
        if !self.no_config {
            self.merge_required(config);
            self.merge_optional(config);
        }
    }

    fn merge_required(&mut self, config: &Config) {
        macro_rules! merge_required {
            ($($field: ident),+) => {
                $(
                    if let Some(e) = &config.$field {
                        self.$field = e.clone();
                    }
                )+
            }
        }

        merge_required!(
            addresses, greppable, accessible, batch_size, timeout, tries, scan_order, scripts,
            command, udp, no_banner
        );
    }

    fn merge_optional(&mut self, config: &Config) {
        macro_rules! merge_optional {
            ($($field: ident),+) => {
                $(
                    if config.$field.is_some() {
                        self.$field = config.$field.clone();
                    }
                )+
            }
        }

        // 仅当用户要求时才使用 top 端口
        if self.top && config.ports.is_some() {
            self.ports = config.ports.clone();
        }

        merge_optional!(range, resolver, ulimit, exclude_ports, exclude_addresses);
    }
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            addresses: vec![],
            ports: None,
            range: None,
            greppable: true,
            batch_size: 0,
            timeout: 0,
            tries: 0,
            ulimit: None,
            command: vec![],
            accessible: false,
            resolver: None,
            scan_order: ScanOrder::Serial,
            no_config: true,
            no_banner: false,
            top: false,
            scripts: ScriptsRequired::Default,
            config_path: None,
            exclude_ports: None,
            exclude_addresses: None,
            udp: false,
        }
    }
}

/// 用于反序列化配置文件中指定的选项的结构。
/// 这些将进一步与我们的命令行参数合并，以生成最终的 Opts 结构。
#[cfg(not(tarpaulin_include))]
#[derive(Debug, Deserialize)]
pub struct Config {
    addresses: Option<Vec<String>>,
    ports: Option<Vec<u16>>,
    range: Option<PortRange>,
    greppable: Option<bool>,
    accessible: Option<bool>,
    batch_size: Option<usize>,
    timeout: Option<u32>,
    tries: Option<u8>,
    ulimit: Option<usize>,
    resolver: Option<String>,
    scan_order: Option<ScanOrder>,
    command: Option<Vec<String>>,
    scripts: Option<ScriptsRequired>,
    exclude_ports: Option<Vec<u16>>,
    exclude_addresses: Option<Vec<String>>,
    udp: Option<bool>,
    no_banner: Option<bool>,
}

#[cfg(not(tarpaulin_include))]
#[allow(clippy::doc_link_with_quotes)]
#[allow(clippy::manual_unwrap_or_default)]
impl Config {
    /// 读取 TOML 格式的配置文件并将其解析为 Config 结构。
    ///
    /// # 格式
    ///
    /// addresses = ["127.0.0.1", "127.0.0.1"]
    /// ports = [80, 443, 8080]
    /// greppable = true
    /// scan_order = "Serial"
    /// exclude_ports = [8080, 9090, 80]
    /// udp = false
    ///
    pub fn read(custom_config_path: Option<PathBuf>) -> Self {
        let mut content = String::new();
        let config_path = custom_config_path.unwrap_or_else(|| {
            let path = default_config_path();
            match path.exists() {
                true => path,
                false => old_default_config_path(),
            }
        });

        if config_path.exists() {
            content = match fs::read_to_string(config_path) {
                Ok(content) => content,
                Err(_) => String::new(),
            }
        }

        let config: Config = match toml::from_str(&content) {
            Ok(config) => config,
            Err(e) => {
                println!("Found {e} in configuration file.\nAborting scan.\n");
                std::process::exit(1);
            }
        };

        config
    }
}

/// 构造 config toml 的默认路径
pub fn default_config_path() -> PathBuf {
    let Some(mut config_path) = dirs::config_dir() else {
        panic!("Could not infer config file path.");
    };
    config_path.push(".rustscan.toml");
    config_path
}

/// 返回用于向后兼容的已弃用的主目录配置路径。
pub fn old_default_config_path() -> PathBuf {
    let Some(mut config_path) = dirs::home_dir() else {
        panic!("Could not infer config file path.");
    };
    config_path.push(".rustscan.toml");
    config_path
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser};
    use parameterized::parameterized;

    use super::{Config, Opts, PortRange, ScanOrder, ScriptsRequired};

    impl Config {
        fn default() -> Self {
            Self {
                addresses: Some(vec!["127.0.0.1".to_owned()]),
                ports: None,
                range: None,
                greppable: Some(true),
                batch_size: Some(25_000),
                timeout: Some(1_000),
                tries: Some(1),
                ulimit: None,
                command: Some(vec!["-A".to_owned()]),
                accessible: Some(true),
                resolver: None,
                scan_order: Some(ScanOrder::Random),
                scripts: None,
                exclude_ports: None,
                exclude_addresses: None,
                udp: Some(false),
                no_banner: None,
            }
        }
    }

    #[test]
    fn verify_cli() {
        Opts::command().debug_assert();
    }

    #[parameterized(input = {
        vec!["rustscan", "--addresses", "127.0.0.1"],
        vec!["rustscan", "--addresses", "127.0.0.1", "--", "-sCV"],
        vec!["rustscan", "--addresses", "127.0.0.1", "--", "-A"],
        vec!["rustscan", "-t", "1500", "-a", "127.0.0.1", "--", "-A", "-sC"],
        vec!["rustscan", "--addresses", "127.0.0.1", "--", "--script", r#""'(safe and vuln)'""#],
    }, command = {
        vec![],
        vec!["-sCV".to_owned()],
        vec!["-A".to_owned()],
        vec!["-A".to_owned(), "-sC".to_owned()],
        vec!["--script".to_owned(), "\"'(safe and vuln)'\"".to_owned()],
    })]
    fn parse_trailing_command(input: Vec<&str>, command: Vec<String>) {
        let opts = Opts::parse_from(input);

        assert_eq!(vec!["127.0.0.1".to_owned()], opts.addresses);
        assert_eq!(command, opts.command);
    }

    #[test]
    fn opts_no_merge_when_config_is_ignored() {
        let mut opts = Opts::default();
        let config = Config::default();

        opts.merge(&config);

        assert_eq!(opts.addresses, vec![] as Vec<String>);
        assert!(opts.greppable);
        assert!(!opts.accessible);
        assert_eq!(opts.timeout, 0);
        assert_eq!(opts.command, vec![] as Vec<String>);
        assert_eq!(opts.scan_order, ScanOrder::Serial);
    }

    #[test]
    fn opts_merge_required_arguments() {
        let mut opts = Opts::default();
        let config = Config::default();

        opts.merge_required(&config);

        assert_eq!(opts.addresses, config.addresses.unwrap());
        assert_eq!(opts.greppable, config.greppable.unwrap());
        assert_eq!(opts.timeout, config.timeout.unwrap());
        assert_eq!(opts.command, config.command.unwrap());
        assert_eq!(opts.accessible, config.accessible.unwrap());
        assert_eq!(opts.scan_order, config.scan_order.unwrap());
        assert_eq!(opts.scripts, ScriptsRequired::Default);
    }

    #[test]
    fn opts_merge_optional_arguments() {
        let mut opts = Opts::default();
        let mut config = Config::default();
        config.range = Some(PortRange {
            start: 1,
            end: 1_000,
        });
        config.ulimit = Some(1_000);
        config.resolver = Some("1.1.1.1".to_owned());

        opts.merge_optional(&config);

        assert_eq!(opts.range, config.range);
        assert_eq!(opts.ulimit, config.ulimit);
        assert_eq!(opts.resolver, config.resolver);
    }
}
