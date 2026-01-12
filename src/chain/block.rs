// 定义区块相关的子模块
pub mod block_ads;  // 区块的认证数据结构（ADS）模块
pub mod build;      // 区块构建逻辑模块
pub mod hash;       // 哈希计算模块

// 引入依赖
use crate::{
    chain::id_tree::IdTreeRoot,  // ID树的根节点类型
    digest::{Digest, Digestible}, // 哈希摘要和可摘要特性
};
use block_ads::BlockMultiADS;    // 区块的多重ADS结构
use hash::block_head_hash;       // 区块头哈希计算函数
use serde::{Deserialize, Serialize}; // 序列化/反序列化库
use std::num::NonZeroU16;        // 非零u16类型，确保ID不为0

/// 区块高度类型
///
/// 使用派生宏自动实现多个特性，简化代码
/// - Debug: 调试输出
/// - Default: 默认值(0)
/// - Copy/Clone: 复制/克隆
/// - Eq/PartialEq: 相等比较
/// - Ord/PartialOrd: 排序比较
/// - Hash: 哈希计算
/// - Serialize/Deserialize: 序列化/反序列化
/// - derive_more::Deref/DerefMut: 自动解引用，方便访问内部u32值
/// - derive_more::Display: 格式化显示
/// - derive_more::From/Into: 类型转换
#[derive(
    Debug,
    Default,
    Copy,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    derive_more::Deref,     // 允许使用*运算符，如*height获取u32
    derive_more::DerefMut,  // 允许可变解引用
    derive_more::Display,   // 实现Display特性，支持格式化输出
    derive_more::From,      // 实现From<u32>，允许u32转换为Height
    derive_more::Into,      // 实现Into<u32>，允许Height转换为u32
)]
pub struct Height(pub u32); // 元组结构体，包装u32表示区块高度

/// 区块内容结构体
///
/// 存储区块的实际内容，包括：
/// - 区块高度和前一个区块哈希（形成链）
/// - 各种数据结构的根节点（用于验证）
/// - 本区块包含的对象信息和索引
#[derive(Debug, Clone, Eq, PartialEq, Default, Serialize, Deserialize)]
pub struct BlockContent {
    /// 区块高度，标识区块在链中的位置
    pub blk_height: Height,

    /// 前一个区块的哈希值，形成区块链的基础
    pub prev_hash: Digest,

    /// ID树的根节点，用于映射对象ID到对象哈希
    /// 每个区块都有自己版本的ID树根，随着新区块添加而更新
    pub id_tree_root: IdTreeRoot,

    /// 区块的多重认证数据结构（ADS）
    /// 包含Trie树和B+树的根节点，用于高效查询
    pub ads: BlockMultiADS,

    /// 本区块中所有对象的哈希值列表
    /// 按对象添加顺序存储，用于计算对象根哈希
    pub obj_hashes: Vec<Digest>,

    /// 本区块中所有对象的ID号列表
    /// 与obj_hashes一一对应，每个对象有唯一的ID
    /// 使用NonZeroU16确保ID不为0，0通常作为特殊值保留
    pub obj_id_nums: Vec<NonZeroU16>,
}

impl BlockContent {
    /// 创建新的区块内容
    ///
    /// # 参数
    /// - `blk_height`: 区块高度
    /// - `prev_hash`: 前一个区块的哈希
    ///
    /// # 返回值
    /// - 返回初始化的区块内容，所有字段为默认值
    pub fn new(blk_height: Height, prev_hash: Digest) -> Self {
        Self {
            blk_height,
            prev_hash,
            id_tree_root: IdTreeRoot::default(),  // 默认ID树根
            ads: BlockMultiADS::default(),        // 默认多重ADS（空）
            obj_hashes: Vec::<Digest>::new(),     // 空对象哈希列表
            obj_id_nums: Vec::<NonZeroU16>::new(), // 空对象ID列表
        }
    }

    /// 设置ID树根节点
    ///
    /// # 参数
    /// - `new_id_tree_root`: 新的ID树根节点
    pub fn set_id_tree_root(&mut self, new_id_tree_root: IdTreeRoot) {
        self.id_tree_root = new_id_tree_root;
    }

    /// 设置多重ADS
    ///
    /// # 参数
    /// - `new_ads`: 新的多重ADS
    pub fn set_multi_ads(&mut self, new_ads: BlockMultiADS) {
        self.ads = new_ads;
    }

    /// 设置对象哈希列表
    ///
    /// # 参数
    /// - `new_hashes`: 新的对象哈希列表
    pub fn set_obj_hashes(&mut self, new_hashes: Vec<Digest>) {
        self.obj_hashes = new_hashes;
    }

    /// 设置对象ID号列表
    ///
    /// # 参数
    /// - `new_id_nums`: 新的对象ID号列表
    pub fn set_obj_id_nums(&mut self, new_id_nums: Vec<NonZeroU16>) {
        self.obj_id_nums = new_id_nums;
    }

    /// 读取对象ID号列表
    ///
    /// # 返回值
    /// - 对象ID号列表的克隆
    ///
    /// # 注意
    /// 这里返回克隆是为了避免所有权问题，但可能会影响性能
    /// 在性能敏感的场景中，可以考虑返回引用
    pub fn read_obj_id_nums(&self) -> Vec<NonZeroU16> {
        self.obj_id_nums.clone()
    }
}

/// 区块头结构体
///
/// 区块的元数据，包含验证区块所需的关键信息：
/// - 区块标识和链式关系
/// - 关键数据的哈希值，用于验证区块内容的完整性
///
/// 区块头通常被存储在区块链的每个节点中，用于快速验证和同步
#[derive(Debug, Clone, Eq, PartialEq, Default, Serialize, Deserialize)]
pub struct BlockHead {
    /// 区块高度，标识区块在链中的位置
    pub blk_height: Height,

    /// 前一个区块的哈希值，形成区块链的链式结构
    pub prev_hash: Digest,

    /// ADS根哈希，验证区块所有认证数据结构的完整性
    /// 通过这个哈希可以验证ID树、Trie树、B+树等数据结构
    pub ads_root_hash: Digest,

    /// 对象根哈希，验证区块中包含的所有对象的完整性
    /// 通常是区块中所有对象哈希的Merkle树根哈希
    pub obj_root_hash: Digest,
}

/// 为BlockHead实现Digestible特性
///
/// Digestible特性要求实现to_digest方法，用于计算对象的哈希值
/// 区块头的哈希值就是区块的唯一标识
impl Digestible for BlockHead {
    /// 计算区块头的哈希值
    ///
    /// # 返回值
    /// - 区块头的哈希摘要
    ///
    /// # 注意
    /// 这个哈希值就是区块的唯一标识，用于：
    /// 1. 区块链中的引用（prev_hash指向这个值）
    /// 2. 区块的标识和验证
    fn to_digest(&self) -> Digest {
        block_head_hash(
            self.blk_height,        // 区块高度
            &self.prev_hash,        // 前一个区块哈希
            &self.ads_root_hash,    // ADS根哈希
            &self.obj_root_hash,    // 对象根哈希
        )
    }
}

impl BlockHead {
    /// 设置ADS根哈希
    ///
    /// # 参数
    /// - `new_hash`: 新的ADS根哈希
    ///
    /// # 可见性
    /// pub(crate)表示只在当前crate内可见，外部无法直接调用
    pub(crate) fn set_ads_root_hash(&mut self, new_hash: Digest) {
        self.ads_root_hash = new_hash;
    }

    /// 设置对象根哈希
    ///
    /// # 参数
    /// - `new_hash`: 新的对象根哈希
    pub(crate) fn set_obj_root_hash(&mut self, new_hash: Digest) {
        self.obj_root_hash = new_hash;
    }

    /// 获取ADS根哈希
    ///
    /// # 返回值
    /// - 当前ADS根哈希
    pub(crate) fn get_ads_root_hash(&self) -> Digest {
        self.ads_root_hash
    }
}