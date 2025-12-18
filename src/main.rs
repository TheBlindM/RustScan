#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown, clippy::if_not_else, clippy::non_ascii_literal)]

use rustscan::benchmark::{Benchmark, NamedTimer};
use rustscan::input::{self, Config, Opts, ScriptsRequired};
use rustscan::port_strategy::PortStrategy;
use rustscan::scanner::Scanner;
use rustscan::scripts::{init_scripts, Script, ScriptFile};
use rustscan::{detail, funny_opening, output, warning};

use colorful::{Color, Colorful};
use futures::executor::block_on;
use std::collections::HashMap;
use std::net::IpAddr;
use std::string::ToString;
use std::time::Duration;

use rustscan::address::parse_addresses;

extern crate colorful;
extern crate dirs;

// Average value for Ubuntu
#[cfg(unix)]
const DEFAULT_FILE_DESCRIPTORS_LIMIT: usize = 8000;
// Safest batch size based on experimentation
const AVERAGE_BATCH_SIZE: usize = 3000;

#[macro_use]
extern crate log;

#[cfg(not(tarpaulin_include))]
#[allow(clippy::too_many_lines)]
/// 使用 Rust 进行更快的 Nmap 扫描
/// 如果你想查看实际的扫描逻辑，请查看 Scanner 模块
fn main() {
    #[cfg(not(unix))]
    let _ = ansi_term::enable_ansi_support();

    // 初始化日志记录器
    env_logger::init();
    // 初始化基准测试工具
    let mut benchmarks = Benchmark::init();
    let mut rustscan_bench = NamedTimer::start("RustScan");

    // 读取命令行参数
    let mut opts: Opts = Opts::read();
    // 读取配置文件
    let config = Config::read(opts.config_path.clone());
    // 将配置文件中的选项合并到命令行参数中
    opts.merge(&config);

    debug!("Main() `opts` arguments are {opts:?}");

    // 初始化脚本
    let scripts_to_run: Vec<ScriptFile> = match init_scripts(&opts.scripts) {
        Ok(scripts_to_run) => scripts_to_run,
        Err(e) => {
            warning!(
                format!("Initiating scripts failed!\n{e}"),
                opts.greppable,
                opts.accessible
            );
            std::process::exit(1);
        }
    };

    debug!("Scripts initialized {:?}", &scripts_to_run);

    // 如果不是 grep 模式，也不是无障碍模式，且没有禁用 banner，则打印开场信息
    if !opts.greppable && !opts.accessible && !opts.no_banner {
        print_opening(&opts);
    }

    // 解析目标 IP 地址
    let ips: Vec<IpAddr> = parse_addresses(&opts);

    if ips.is_empty() {
        warning!(
            "No IPs could be resolved, aborting scan.",
            opts.greppable,
            opts.accessible
        );
        std::process::exit(1);
    }

    // 根据系统限制推断批处理大小（并发数）
    #[cfg(unix)]
    let batch_size: usize = infer_batch_size(&opts, adjust_ulimit_size(&opts));

    #[cfg(not(unix))]
    let batch_size: usize = AVERAGE_BATCH_SIZE;

    // 创建扫描器实例
    let scanner = Scanner::new(
        &ips,
        batch_size,
        Duration::from_millis(opts.timeout.into()),
        opts.tries,
        opts.greppable,
        PortStrategy::pick(&opts.range, opts.ports, opts.scan_order),
        opts.accessible,
        opts.exclude_ports.unwrap_or_default(),
        opts.udp,
    );
    debug!("Scanner finished building: {scanner:?}");

    // 开始端口扫描基准测试计时
    let mut portscan_bench = NamedTimer::start("Portscan");
    // 运行扫描器并等待结果
    let scan_result = block_on(scanner.run());
    portscan_bench.end();
    benchmarks.push(portscan_bench);

    // 用于存储每个 IP 对应的开放端口列表
    let mut ports_per_ip = HashMap::new();

    // 整理扫描结果，按 IP 分组
    for socket in scan_result {
        ports_per_ip
            .entry(socket.ip())
            .or_insert_with(Vec::new)
            .push(socket.port());
    }

    // 检查是否有 IP 没有发现开放端口，并给出提示
    for ip in ips {
        if ports_per_ip.contains_key(&ip) {
            continue;
        }

        // 如果执行到这里，说明在 HashMap 中没有找到该 IP，这意味着扫描没有发现该 IP 的任何开放端口。

        let x = format!("Looks like I didn't find any open ports for {:?}. This is usually caused by a high batch size.
        \n*I used {} batch size, consider lowering it with {} or a comfortable number for your system.
        \n Alternatively, increase the timeout if your ping is high. Rustscan -t 2000 for 2000 milliseconds (2s) timeout.\n",
        ip,
        opts.batch_size,
        "'rustscan -b <batch_size> -a <ip address>'");
        warning!(x, opts.greppable, opts.accessible);
    }

    // 开始脚本执行基准测试计时
    let mut script_bench = NamedTimer::start("Scripts");
    for (ip, ports) in &ports_per_ip {
        let vec_str_ports: Vec<String> = ports.iter().map(ToString::to_string).collect();

        // nmap 端口样式是 80,443。逗号分隔，无空格。
        let ports_str = vec_str_ports.join(",");

        // 如果 scripts 选项为 none，则不生成任何脚本
        if opts.greppable || opts.scripts == ScriptsRequired::None {
            println!("{} -> [{}]", &ip, ports_str);
            continue;
        }
        detail!("Starting Script(s)", opts.greppable, opts.accessible);

        // 运行我们根据脚本配置文件 tags 字段找到并解析的所有脚本。
        for mut script_f in scripts_to_run.clone() {
            // 这部分允许我们将命令行参数添加到脚本 call_format 中，将它们附加到命令的末尾。
            if !opts.command.is_empty() {
                let user_extra_args = &opts.command.join(" ");
                debug!("Extra args vec {user_extra_args:?}");
                if script_f.call_format.is_some() {
                    let mut call_f = script_f.call_format.unwrap();
                    call_f.push(' ');
                    call_f.push_str(user_extra_args);
                    output!(
                        format!("Running script {:?} on ip {}\nDepending on the complexity of the script, results may take some time to appear.", call_f, &ip),
                        opts.greppable,
                        opts.accessible
                    );
                    debug!("Call format {call_f}");
                    script_f.call_format = Some(call_f);
                }
            }

            // 使用 ScriptFile 中的参数和 ip-ports 构建脚本。
            let script = Script::build(
                script_f.path,
                *ip,
                ports.clone(),
                script_f.port,
                script_f.ports_separator,
                script_f.tags,
                script_f.call_format,
            );
            match script.run() {
                Ok(script_result) => {
                    detail!(script_result.clone(), opts.greppable, opts.accessible);
                }
                Err(e) => {
                    warning!(&format!("Error {e}"), opts.greppable, opts.accessible);
                }
            }
        }
    }

    // 要使用运行时基准测试，请以如下方式运行进程：RUST_LOG=info ./rustscan
    script_bench.end();
    benchmarks.push(script_bench);
    rustscan_bench.end();
    benchmarks.push(rustscan_bench);
    debug!("Benchmarks raw {benchmarks:?}");
    info!("{}", benchmarks.summary());
}

/// Prints the opening title of RustScan
#[allow(clippy::items_after_statements, clippy::needless_raw_string_hashes)]
fn print_opening(opts: &Opts) {
    debug!("Printing opening");
    let s = r#".----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner."#;

    println!("{}", s.gradient(Color::Green).bold());
    let info = r#"________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------"#;
    println!("{}", info.gradient(Color::Yellow).bold());
    funny_opening!();

    let config_path = opts
        .config_path
        .clone()
        .unwrap_or_else(input::default_config_path);

    detail!(
        format!("The config file is expected to be at {config_path:?}"),
        opts.greppable,
        opts.accessible
    );

    if opts.config_path.is_none() {
        let old_config_path = input::old_default_config_path();
        detail!(
            format!(
                "For backwards compatibility, the config file may also be at {old_config_path:?}"
            ),
            opts.greppable,
            opts.accessible
        );
    }
}

#[cfg(unix)]
/// 调整系统的 ulimit（最大打开文件描述符数）。
///
/// 返回当前生效的软限制（soft limit），即进程实际可以打开的最大文件数。
/// 在Unix/Linux 系统中，万物皆文件，所以每个socket都是一个文件，所以RustScan扫一个端口就会生成一个文件描述符
/// 为了避免崩溃，需要这种限制
fn adjust_ulimit_size(opts: &Opts) -> usize {
    use rlimit::Resource;
    use std::convert::TryInto;

    // 如果用户在选项中指定了 ulimit 值
    if let Some(limit) = opts.ulimit {
        let limit = limit as u64;
        // NOFILE (Number of Open Files) 是操作系统对进程同时打开文件数量的限制。
        // 这里尝试将软限制（Soft Limit）和硬限制（Hard Limit）都设置为用户指定的值。
        if Resource::NOFILE.set(limit, limit).is_ok() {
            detail!(
                format!("Automatically increasing ulimit value to {limit}."),
                opts.greppable,
                opts.accessible
            );
        } else {
            warning!(
                "ERROR. Failed to set ulimit value.",
                opts.greppable,
                opts.accessible
            );
        }
    }

    // 获取当前的 NOFILE 软限制
    let (soft, _) = Resource::NOFILE.get().unwrap();
    // 将其转换为 usize 并返回，如果转换失败则返回 usize::MAX
    soft.try_into().unwrap_or(usize::MAX)
}

#[cfg(unix)]
/// 根据系统文件限制推断合适的批次大小。
///
/// 此函数确保扫描任务的并发度（`batch_size`）不会超过系统的文件描述符限制（`ulimit`）。
/// 如果并发度过高超过了系统限制，会导致 socket 创建失败，程序报错。
fn infer_batch_size(opts: &Opts, ulimit: usize) -> usize {
    let mut batch_size = opts.batch_size;

    // 当 ulimit 值低于batch_size时会自动降级，确保扫描的稳定
    if ulimit < batch_size {
        warning!("File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers",
            opts.greppable, opts.accessible
        );

        // 当操作系统支持较高的文件限制（如 8000），但用户选择的批次大小
        // 高于此值时，我们应该将其降低到一个较小的数字。
        if ulimit < AVERAGE_BATCH_SIZE {
            // ulimit 小于平均批次大小
            // 用户的文件限制非常小
            // 将批次大小减少到 ulimit 的一半，以留出余量给其他文件操作
            warning!("Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. ", opts.greppable, opts.accessible);
            info!("Halving batch_size because ulimit is smaller than average batch size");
            batch_size = ulimit / 2;
        } else if ulimit > DEFAULT_FILE_DESCRIPTORS_LIMIT {
            info!("Batch size is now average batch size");
            batch_size = AVERAGE_BATCH_SIZE;
        } else {
            // 预留 100 个文件描述符给标准输入/输出和其他系统开销
            batch_size = ulimit - 100;
        }
    }
    // 当 ulimit 高于批次大小时，让用户知道除非他们自己指定了 ulimit，
    // 否则可以增加批次大小来提高速度。
    else if ulimit + 2 > batch_size && (opts.ulimit.is_none()) {
        detail!(format!("File limit higher than batch size. Can increase speed by increasing batch size '-b {}'.", ulimit - 100),
        opts.greppable, opts.accessible);
    }

    batch_size
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::{adjust_ulimit_size, infer_batch_size};
    use super::{print_opening, Opts};

    #[test]
    #[cfg(unix)]
    fn batch_size_lowered() {
        let opts = Opts {
            batch_size: 50_000,
            ..Default::default()
        };
        let batch_size = infer_batch_size(&opts, 120);

        assert!(batch_size < opts.batch_size);
    }

    #[test]
    #[cfg(unix)]
    fn batch_size_lowered_average_size() {
        let opts = Opts {
            batch_size: 50_000,
            ..Default::default()
        };
        let batch_size = infer_batch_size(&opts, 9_000);

        assert!(batch_size == 3_000);
    }
    #[test]
    #[cfg(unix)]
    fn batch_size_equals_ulimit_lowered() {
        // because ulimit and batch size are same size, batch size is lowered
        // to ULIMIT - 100
        let opts = Opts {
            batch_size: 50_000,
            ..Default::default()
        };
        let batch_size = infer_batch_size(&opts, 5_000);

        assert!(batch_size == 4_900);
    }
    #[test]
    #[cfg(unix)]
    fn batch_size_adjusted_2000() {
        // ulimit == batch_size
        let opts = Opts {
            batch_size: 50_000,
            ulimit: Some(2_000),
            ..Default::default()
        };
        let batch_size = adjust_ulimit_size(&opts);

        assert!(batch_size == 2_000);
    }

    #[test]
    #[cfg(unix)]
    fn test_high_ulimit_no_greppable_mode() {
        let opts = Opts {
            batch_size: 10,
            greppable: false,
            ..Default::default()
        };

        let batch_size = infer_batch_size(&opts, 1_000_000);

        assert!(batch_size == opts.batch_size);
    }

    #[test]
    fn test_print_opening_no_panic() {
        let opts = Opts {
            ulimit: Some(2_000),
            ..Default::default()
        };
        // print opening should not panic
        print_opening(&opts);
    }
}
