//! 提供用于捕获扫描计时信息的功能。
//!
//! # 用法
//!
//! ```rust
//! // 初始化 Benchmark 向量
//! # use rustscan::benchmark::{Benchmark, NamedTimer};
//! # use log::info;
//! let mut bm = Benchmark::init();
//! // 启动名为 "Example Bench" 的计时器
//! let mut example_bench = NamedTimer::start("Example Bench");
//! // 停止计时器
//! example_bench.end();
//! // 将计时器添加到 Benchmarks 中
//! bm.push(example_bench);
//! // 打印 Benchmark 摘要
//! info!("{}", bm.summary());
//! ```
use std::time::Instant;

/// Benchmark 结构体用于保存 NamedTimers，包含名称、开始和结束时间。
#[derive(Debug)]
pub struct Benchmark {
    named_timers: Vec<NamedTimer>,
}

impl Benchmark {
    pub fn init() -> Self {
        Self {
            named_timers: Vec::new(),
        }
    }
    pub fn push(&mut self, timer: NamedTimer) {
        self.named_timers.push(timer);
    }

    /// 性能测试摘要将解构向量，
    /// 以相同的方式格式化每个元素，并返回
    /// 包含所有可用信息的单个字符串，
    /// 以便轻松打印。
    pub fn summary(&self) -> String {
        let mut summary = String::from("\nRustScan Benchmark Summary");

        for timer in &self.named_timers {
            if timer.start.is_some() && timer.end.is_some() {
                let runtime_secs = timer
                    .end
                    .unwrap()
                    .saturating_duration_since(timer.start.unwrap())
                    .as_secs_f32();
                summary.push_str(&format!("\n{0: <10} | {1: <10}s", timer.name, runtime_secs));
            }
        }
        summary
    }
}

/// NamedTimer 的目的是保存特定计时器的名称、
/// 开始时间和结束时间。
/// 给定的名称将显示在基准测试摘要中，
/// 开始和结束时间将用于计算运行时间。
#[derive(Debug)]
pub struct NamedTimer {
    name: &'static str,
    start: Option<Instant>,
    end: Option<Instant>,
}

impl NamedTimer {
    pub fn start(name: &'static str) -> Self {
        Self {
            name,
            start: Some(Instant::now()),
            end: None,
        }
    }
    pub fn end(&mut self) {
        self.end = Some(Instant::now());
    }
}

#[test]
fn benchmark() {
    let mut benchmarks = Benchmark::init();
    let mut test_timer = NamedTimer::start("test");
    std::thread::sleep(std::time::Duration::from_millis(100));
    test_timer.end();
    benchmarks.push(test_timer);
    benchmarks.push(NamedTimer::start("only_start"));
    assert!(benchmarks
        .summary()
        .contains("\nRustScan Benchmark Summary\ntest       | 0."));
    assert!(!benchmarks.summary().contains("only_start"));
}
