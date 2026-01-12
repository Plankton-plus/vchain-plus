// 引入必要的依赖和模块
use crate::{
    acc::{set::Set, AccValue},  // 累加器相关，用于集合操作和累加器值
    chain::{range::Range, traits::Num, MAX_INLINE_BTREE_FANOUT},  // 范围、数值类型特性、最大内联B树扇出
    create_id_type_by_u32,  // 宏：创建基于u32的ID类型
    digest::{Digest, Digestible},  // 哈希摘要和可摘要特性
};
use anyhow::Result;  // 错误处理
use hash::{bplus_tree_leaf_hash, bplus_tree_non_leaf_hash};  // B+树哈希计算函数
use serde::{Deserialize, Serialize};  // 序列化/反序列化
use smallvec::SmallVec;  // 小向量优化，用于存储少量元素

// 使用宏创建BPlusTreeNodeId类型，这是一个基于u32的唯一标识符类型
// 宏会自动生成ID分配、序列化等功能
create_id_type_by_u32!(BPlusTreeNodeId);

// 定义子模块
pub mod hash;    // 哈希计算相关
pub mod proof;   // 证明生成和验证
pub mod read;    // 读取操作
pub mod write;   // 写入操作

/// B+树根节点结构
///
/// 存储B+树的根节点引用和哈希值
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct BPlusTreeRoot {
    /// B+树根节点的ID，可能为None表示空树
    pub(crate) bplus_tree_root_id: Option<BPlusTreeNodeId>,

    /// B+树根节点的哈希值，用于完整性验证
    pub(crate) bplus_tree_root_hash: Digest,
}

/// 为BPlusTreeRoot实现Digestible特性，使其可以计算哈希
impl Digestible for BPlusTreeRoot {
    fn to_digest(&self) -> Digest {
        // 直接返回存储的根节点哈希
        self.bplus_tree_root_hash
    }
}

/// B+树节点枚举，可以是叶节点或非叶节点
///
/// 使用枚举来表示不同类型的节点，这是Rust中的常见模式
/// 泛型K必须实现Num特性（数值类型）
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum BPlusTreeNode<K: Num> {
    /// 叶节点变体，存储实际的数据项
    Leaf(BPlusTreeLeafNode<K>),

    /// 非叶节点变体，存储子节点的引用
    NonLeaf(BPlusTreeNonLeafNode<K>),
}

/// B+树节点的实现
impl<K: Num> BPlusTreeNode<K> {
    /// 获取节点的ID
    pub fn get_node_id(&self) -> BPlusTreeNodeId {
        match self {
            // 如果是叶节点，返回叶节点的ID
            BPlusTreeNode::Leaf(n) => n.id,
            // 如果是非叶节点，返回非叶节点的ID
            BPlusTreeNode::NonLeaf(n) => n.id,
        }
    }

    /// 获取节点的哈希值
    pub fn get_node_hash(&self) -> Digest {
        match self {
            // 调用叶节点的to_digest方法
            BPlusTreeNode::Leaf(n) => n.to_digest(),
            // 调用非叶节点的to_digest方法
            BPlusTreeNode::NonLeaf(n) => n.to_digest(),
        }
    }

    /// 获取节点的累加器值
    ///
    /// 累加器值用于集合成员证明和范围证明
    pub fn get_node_acc(&self) -> AccValue {
        match self {
            // 返回叶节点的累加器值
            BPlusTreeNode::Leaf(n) => n.data_set_acc,
            // 返回非叶节点的累加器值
            BPlusTreeNode::NonLeaf(n) => n.data_set_acc,
        }
    }

    /// 从叶节点创建B+树节点
    pub fn from_leaf(l: BPlusTreeLeafNode<K>) -> Self {
        Self::Leaf(l)
    }

    /// 从非叶节点创建B+树节点
    pub fn from_non_leaf(n: BPlusTreeNonLeafNode<K>) -> Self {
        Self::NonLeaf(n)
    }

    /// 获取节点中的数据集合
    pub fn get_set(&self) -> &Set {
        match self {
            // 返回叶节点的数据集合
            BPlusTreeNode::Leaf(n) => &n.data_set,
            // 返回非叶节点的数据集合
            BPlusTreeNode::NonLeaf(n) => &n.data_set,
        }
    }

    /// 获取节点表示的数值范围
    ///
    /// 对于叶节点，范围是单个值（低值=高值=存储的值）
    /// 对于非叶节点，范围是子节点范围的并集
    pub fn get_range(&self) -> Range<K> {
        match self {
            // 叶节点的范围是单个值
            BPlusTreeNode::Leaf(n) => Range::new(n.num, n.num),
            // 非叶节点存储了范围信息
            BPlusTreeNode::NonLeaf(n) => n.range,
        }
    }

    /// 获取范围的最小值
    pub fn get_range_low(&self) -> K {
        match self {
            // 叶节点的低值就是存储的数值
            BPlusTreeNode::Leaf(n) => n.num,
            // 非叶节点从范围中获取低值
            BPlusTreeNode::NonLeaf(n) => n.range.get_low(),
        }
    }

    /// 获取范围的最大值
    pub fn get_range_high(&self) -> K {
        match self {
            // 叶节点的高值就是存储的数值
            BPlusTreeNode::Leaf(n) => n.num,
            // 非叶节点从范围中获取高值
            BPlusTreeNode::NonLeaf(n) => n.range.get_high(),
        }
    }
}

/// 为B+树节点实现Digestible特性
impl<K: Num> Digestible for BPlusTreeNode<K> {
    fn to_digest(&self) -> Digest {
        match self {
            // 委托给叶节点的to_digest
            BPlusTreeNode::Leaf(n) => n.to_digest(),
            // 委托给非叶节点的to_digest
            BPlusTreeNode::NonLeaf(n) => n.to_digest(),
        }
    }
}

/// B+树叶节点结构
///
/// 存储实际的数据项，包含：
/// - ID和数值
/// - 数据集合和对应的累加器值
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct BPlusTreeLeafNode<K: Num> {
    /// 节点的唯一标识符
    pub id: BPlusTreeNodeId,

    /// 叶节点存储的数值键
    pub num: K,

    /// 数据集合，存储对象ID等
    pub data_set: Set,

    /// 数据集合的累加器值，用于验证
    pub data_set_acc: AccValue,
}

/// 为叶节点实现Digestible特性
impl<K: Num> Digestible for BPlusTreeLeafNode<K> {
    fn to_digest(&self) -> Digest {
        // 使用专门的哈希函数计算叶节点哈希
        // 输入包括：数值和累加器值的哈希
        bplus_tree_leaf_hash(self.num, &self.data_set_acc.to_digest())
    }
}

/// 叶节点的实现
impl<K: Num> BPlusTreeLeafNode<K> {
    /// 创建新的叶节点
    ///
    /// # 参数
    /// - `num`: 数值键
    /// - `data_set`: 数据集合
    /// - `acc`: 累加器值
    ///
    /// # 返回值
    /// - 新的叶节点，自动分配ID
    fn new(num: K, data_set: Set, acc: AccValue) -> Self {
        Self {
            id: BPlusTreeNodeId::next_id(),  // 自动获取下一个ID
            num,
            data_set,
            data_set_acc: acc,
        }
    }
}

/// B+树非叶节点结构
///
/// 存储子节点的引用信息，包含：
/// - 范围和集合信息
/// - 子节点的哈希和ID列表
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct BPlusTreeNonLeafNode<K: Num> {
    /// 节点的唯一标识符
    pub id: BPlusTreeNodeId,

    /// 节点表示的范围（子节点范围的并集）
    pub range: Range<K>,

    /// 数据集合（所有子节点集合的并集）
    pub data_set: Set,

    /// 数据集合的累加器值
    pub data_set_acc: AccValue,

    /// 子节点的哈希值列表，用于完整性验证
    /// 使用SmallVec优化，当元素数量小于MAX_INLINE_BTREE_FANOUT时存储在栈上
    pub child_hashes: SmallVec<[Digest; MAX_INLINE_BTREE_FANOUT]>,

    /// 子节点的ID列表，用于查找子节点
    pub child_ids: SmallVec<[BPlusTreeNodeId; MAX_INLINE_BTREE_FANOUT]>,
}

/// 非叶节点的实现
impl<K: Num> BPlusTreeNonLeafNode<K> {
    /// 创建新的非叶节点
    ///
    /// # 参数
    /// - `range`: 节点范围
    /// - `data_set`: 数据集合
    /// - `data_set_acc`: 累加器值
    /// - `child_hashes`: 子节点哈希列表
    /// - `child_ids`: 子节点ID列表
    ///
    /// # 返回值
    /// - 新的非叶节点，自动分配ID
    pub fn new(
        range: Range<K>,
        data_set: Set,
        data_set_acc: AccValue,
        child_hashes: SmallVec<[Digest; MAX_INLINE_BTREE_FANOUT]>,
        child_ids: SmallVec<[BPlusTreeNodeId; MAX_INLINE_BTREE_FANOUT]>,
    ) -> Self {
        Self {
            id: BPlusTreeNodeId::next_id(),  // 自动分配ID
            range,
            data_set,
            data_set_acc,
            child_hashes,
            child_ids,
        }
    }

    /// 获取指定索引的子节点ID
    ///
    /// # 参数
    /// - `idx`: 子节点索引
    ///
    /// # 返回值
    /// - 如果索引有效，返回Some(&BPlusTreeNodeId)
    /// - 如果索引无效，返回None
    pub fn get_child_id(&self, idx: usize) -> Option<&BPlusTreeNodeId> {
        self.child_ids.get(idx)
    }

    /// 获取指定索引的子节点ID（可变引用）
    pub fn get_child_id_mut(&mut self, idx: usize) -> Option<&mut BPlusTreeNodeId> {
        self.child_ids.get_mut(idx)
    }

    /// 获取指定索引的子节点哈希
    pub fn get_child_hash(&self, idx: usize) -> Option<&Digest> {
        self.child_hashes.get(idx)
    }

    /// 获取指定索引的子节点哈希（可变引用）
    pub fn get_child_hash_mut(&mut self, idx: usize) -> Option<&mut Digest> {
        self.child_hashes.get_mut(idx)
    }
}

/// 为非叶节点实现Digestible特性
impl<K: Num> Digestible for BPlusTreeNonLeafNode<K> {
    fn to_digest(&self) -> Digest {
        // 使用专门的哈希函数计算非叶节点哈希
        // 输入包括：范围、累加器值哈希和所有子节点哈希
        bplus_tree_non_leaf_hash(
            &self.range,
            &self.data_set_acc.to_digest(),
            self.child_hashes.iter(),
        )
    }
}

/// B+树节点加载器特性
///
/// 定义加载B+树节点的接口，用于从存储中读取节点
pub trait BPlusTreeNodeLoader<K: Num> {
    /// 根据节点ID加载B+树节点
    ///
    /// # 参数
    /// - `id`: 节点ID
    ///
    /// # 返回值
    /// - 加载的B+树节点，或者错误
    fn load_node(&self, id: BPlusTreeNodeId) -> Result<BPlusTreeNode<K>>;
}

// 测试模块
#[cfg(test)]
mod tests;