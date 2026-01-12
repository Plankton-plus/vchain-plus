// 引入tracing宏，用于日志记录
#[macro_use]
extern crate tracing;

// 引入必要的依赖
use anyhow::Result;  // 错误处理库
use serde::{Deserialize, Serialize};  // 序列化/反序列化库
use serde_json::json;  // JSON处理
use std::collections::BTreeMap;  // B树映射，保持键有序
use std::fs;  // 文件系统操作
use std::path::{Path, PathBuf};  // 路径处理
use structopt::StructOpt;  // 命令行参数解析
use vchain_plus::utils::{init_tracing_subscriber, KeyPair};  // vchain_plus的工具函数
use vchain_plus::{  // vchain_plus区块链库
                    chain::{
                        block::{build::build_block, Height},  // 区块构建和区块高度
                        object::Object,  // 区块链中的对象
                        traits::WriteInterface,  // 写入接口特性
                        Parameter,  // 区块链参数
                    },
                    digest::{Digest, Digestible},  // 哈希摘要相关
                    utils::{load_raw_obj_from_file, Time},  // 工具函数：从文件加载对象、时间
                    SimChain,  // 模拟区块链
};

// 命令行参数结构体，使用StructOpt自动生成命令行解析
#[derive(StructOpt, Debug)]
struct Opt {
    /// 时间窗口大小（多个值，用逗号分隔）
    #[structopt(short, long)]
    time_win_sizes: Vec<u16>,

    /// ID树的扇出（fanout）值，表示每个节点最多有多少子节点
    #[structopt(long)]
    id_fanout: u8,

    /// 最大ID数量
    #[structopt(short, long)]
    max_id: u16,

    /// B+树的扇出值
    #[structopt(short, long)]
    bplus_fanout: u8,

    /// 维度（可能是向量空间的维度）
    #[structopt(short, long)]
    dim: u8,

    /// 密钥文件路径
    #[structopt(short, long, parse(from_os_str))]
    key_path: PathBuf,

    /// 输入数据文件路径
    #[structopt(short, long, parse(from_os_str))]
    input: PathBuf,

    /// 结果输出文件路径
    #[structopt(short, long, parse(from_os_str))]
    result: PathBuf,

    /// 区块链数据库输出目录
    #[structopt(short, long, parse(from_os_str))]
    output: PathBuf,
}

// 用于记录构建时间的结构体，可序列化为JSON
#[derive(Debug, Serialize, Deserialize)]
struct BuildTime {
    blk_height: Height,  // 区块高度
    build_time: Time,    // 构建耗时
}

/// 构建区块链的主要函数
///
/// # 参数
/// - `data_path`: 输入数据文件路径
/// - `key_path`: 密钥文件路径
/// - `db_path`: 区块链数据库存储目录
/// - `res_path`: 构建结果输出文件路径
/// - `param`: 区块链参数配置
///
/// # 返回值
/// - `Result<()>`: 成功返回Ok(())，失败返回错误
fn build_chain(
    data_path: &Path,
    key_path: &Path,
    db_path: &Path,
    res_path: &Path,
    param: &Parameter,
) -> Result<()> {
    // 如果数据库目录已存在，先删除它
    if db_path.exists() {
        fs::remove_dir_all(db_path)?;
    }
    // 创建数据库目录
    fs::create_dir_all(db_path)?;

    // 创建模拟区块链实例
    let mut chain = SimChain::create(db_path, param.clone())?;
    // 设置区块链参数
    chain.set_parameter(param)?;

    // 初始化前一个区块的哈希值为0
    let mut prev_hash = Digest::zero();

    // 从文件加载原始对象，按区块高度分组存储到BTreeMap中
    let raw_objs: BTreeMap<Height, Vec<Object<u32>>> = load_raw_obj_from_file(data_path)?;

    // 计时：加载公钥
    let timer = howlong::ProcessCPUTimer::new();
    let pk = KeyPair::load(key_path)?.pk;
    let time = timer.elapsed();
    info!("Time for loading public key: {}", time);

    // 存储每个区块的构建时间
    let mut time_set = Vec::<BuildTime>::new();

    // 计时：区块构建总时间
    let timer = howlong::ProcessCPUTimer::new();

    // 遍历每个高度的对象，构建区块
    for (blk_height, objs) in raw_objs {
        // 构建区块，返回区块头和构建耗时
        let (blk_head, duration) =
            build_block(blk_height, prev_hash, objs, &mut chain, param, &pk)?;

        // 更新前一个区块的哈希值
        prev_hash = blk_head.to_digest();

        // 记录构建时间
        time_set.push(BuildTime {
            blk_height,
            build_time: duration.into(),
        });
    }

    // 记录总构建时间
    let time = timer.elapsed();
    info!("Block building finished. Time elapsed: {}", time);

    // 构建结果JSON
    let res = json!({
        "total_time": Time::from(time),  // 总时间
        "time_set": time_set,            // 每个区块的时间
    });

    // 将结果写入文件
    let s = serde_json::to_string_pretty(&res)?;
    fs::write(res_path, &s)?;

    Ok(())
}

/// 主函数
///
/// # 流程
/// 1. 初始化日志系统
/// 2. 解析命令行参数
/// 3. 构建区块链参数
/// 4. 调用build_chain函数构建区块链
fn main() -> Result<()> {
    // 初始化tracing日志订阅者，日志级别为info
    init_tracing_subscriber("info")?;

    // 从命令行参数解析配置
    let opts = Opt::from_args();

    // 构建区块链参数结构
    let param = Parameter {
        time_win_sizes: opts.time_win_sizes,  // 时间窗口大小
        id_tree_fanout: opts.id_fanout,       // ID树扇出
        max_id_num: opts.max_id,              // 最大ID数量
        bplus_tree_fanout: opts.bplus_fanout, // B+树扇出
        num_dim: opts.dim,                    // 维度
    };

    // 调用构建函数
    build_chain(
        &opts.input,      // 输入数据文件
        &opts.key_path,   // 密钥文件
        &opts.output,     // 输出目录
        &opts.result,     // 结果文件
        &param,           // 参数
    )?;

    Ok(())
}