// 引入必要的依赖和模块
use crate::{
    chain::MAX_ININE_ID_FANOUT,       // ID树的最大内联扇出（子节点数）常量
    create_id_type_by_u16, create_id_type_by_u32,  // 宏：创建基于u16/u32的ID类型
    digest::{Digest, Digestible},     // 哈希摘要和可摘要特性
};
use anyhow::Result;                   // 错误处理
use hash::{id_tree_leaf_hash, id_tree_non_leaf_hash, id_tree_root_hash};  // ID树哈希函数
use serde::{Deserialize, Serialize};  // 序列化/反序列化
use smallvec::SmallVec;               // 小向量优化
use std::num::NonZeroU16;             // 非零u16类型，确保ID不为0

// 使用宏创建IdTreeNodeId类型（基于u32），用于唯一标识ID树节点
// 宏会自动生成ID分配、序列化等功能
create_id_type_by_u32!(IdTreeNodeId);

// 使用宏创建IdTreeInternalId类型（基于u16），用于内部ID标识
create_id_type_by_u16!(IdTreeInternalId);

// 定义子模块
pub mod hash;    // 哈希计算相关
pub mod proof;   // 证明生成和验证
pub mod read;    // 读取操作
pub mod write;   // 写入操作

/// 对象ID类型
///
/// 包装NonZeroU16，表示区块链中对象的唯一标识符
/// 使用派生宏自动实现多个特性
#[derive(
    Debug,                       // 调试输出
    Copy, Clone,                 // 复制/克隆
    Eq, PartialEq,               // 相等比较
    Ord, PartialOrd,             // 排序比较
    Hash,                        // 哈希计算
    serde::Serialize,            // 序列化
    serde::Deserialize,          // 反序列化
    derive_more::Deref,          // 自动解引用
    derive_more::DerefMut,       // 自动可变解引用
    derive_more::Display,        // 格式化显示
    derive_more::From,           // 从NonZeroU16转换
    derive_more::Into,           // 转换为NonZeroU16
)]
pub struct ObjId(pub NonZeroU16);  // 元组结构体，包装NonZeroU16

/// 为ObjId实现Digestible特性，使其可以计算哈希
impl Digestible for ObjId {
    fn to_digest(&self) -> Digest {
        // 获取NonZeroU16的内部值，转换为哈希
        self.0.get().to_digest()
    }
}

/// ObjId的实现方法
impl ObjId {
    /// 将对象ID转换为内部ID
    ///
    /// # 说明
    /// 内部ID从0开始，而对象ID从1开始
    /// 例如：ObjId(1) -> IdTreeInternalId(0)
    pub(crate) fn to_internal_id(self) -> IdTreeInternalId {
        IdTreeInternalId(self.0.get() - 1)
    }

    /// 从内部ID创建对象ID
    ///
    /// # 安全性
    /// 使用unsafe是因为我们知道内部ID+1总是非零
    /// 内部ID从0开始，加1后总是>=1
    fn from_internal_id(id: IdTreeInternalId) -> Self {
        Self(unsafe { NonZeroU16::new_unchecked(id.0 + 1) })
    }
}

/// 为ObjId实现Default特性，提供默认值
impl Default for ObjId {
    fn default() -> Self {
        // 使用unsafe是因为1是非零值
        Self(unsafe { NonZeroU16::new_unchecked(1) })
    }
}

/// ID树根节点结构
///
/// 存储ID树的根节点信息和当前对象ID状态
#[derive(Debug, Copy, Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct IdTreeRoot {
    /// ID树根节点的ID，None表示空树
    id_tree_root_id: Option<IdTreeNodeId>,

    /// ID树根节点的哈希值，用于完整性验证
    id_tree_root_hash: Digest,

    /// 当前已分配的最大对象ID
    cur_obj_id: ObjId,
}

/// 为IdTreeRoot实现Digestible特性
impl Digestible for IdTreeRoot {
    fn to_digest(&self) -> Digest {
        // 使用专门的哈希函数计算ID树根哈希
        // 输入包括：当前对象ID的哈希和根节点哈希
        id_tree_root_hash(&self.cur_obj_id.to_digest(), &self.id_tree_root_hash)
    }
}

/// IdTreeRoot的实现方法
impl IdTreeRoot {
    /// 获取ID树根节点的ID
    pub(crate) fn get_id_tree_root_id(&self) -> Option<IdTreeNodeId> {
        self.id_tree_root_id
    }

    /// 获取当前对象ID
    pub(crate) fn get_cur_obj_id(&self) -> ObjId {
        self.cur_obj_id
    }
}

/// ID树节点枚举，可以是叶节点或非叶节点
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum IdTreeNode {
    /// 叶节点变体，存储实际的对象信息
    Leaf(IdTreeLeafNode),

    /// 非叶节点变体，包装在Box中以避免递归类型大小问题
    NonLeaf(Box<IdTreeNonLeafNode>),
}

/// ID树节点的实现方法
impl IdTreeNode {
    /// 获取节点的ID
    pub fn get_node_id(&self) -> IdTreeNodeId {
        match self {
            // 如果是叶节点，返回叶节点的ID
            IdTreeNode::Leaf(n) => n.id,
            // 如果是非叶节点，返回非叶节点的ID
            IdTreeNode::NonLeaf(n) => n.id,
        }
    }

    /// 从叶节点创建ID树节点
    pub fn from_leaf(l: IdTreeLeafNode) -> Self {
        Self::Leaf(l)
    }

    /// 从非叶节点创建ID树节点
    pub fn from_non_leaf(n: IdTreeNonLeafNode) -> Self {
        // 使用Box包装以避免递归类型的大小问题
        Self::NonLeaf(Box::new(n))
    }
}

/// 为IdTreeNode实现Digestible特性
impl Digestible for IdTreeNode {
    fn to_digest(&self) -> Digest {
        match self {
            // 委托给叶节点的to_digest方法
            IdTreeNode::Leaf(n) => n.to_digest(),
            // 委托给非叶节点的to_digest方法
            IdTreeNode::NonLeaf(n) => n.to_digest(),
        }
    }
}

/// ID树叶节点结构
///
/// 存储实际的对象信息
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct IdTreeLeafNode {
    /// 节点的唯一标识符
    pub id: IdTreeNodeId,

    /// 对象的内部ID（从0开始）
    pub obj_id: IdTreeInternalId,

    /// 对象的哈希值
    pub obj_hash: Digest,
}

/// ID树叶节点的实现方法
impl IdTreeLeafNode {
    /// 创建新的叶节点
    ///
    /// # 参数
    /// - `obj_id`: 对象的内部ID
    /// - `obj_hash`: 对象的哈希值
    ///
    /// # 返回值
    /// - 新的叶节点，自动分配节点ID
    fn new(obj_id: IdTreeInternalId, obj_hash: Digest) -> Self {
        Self {
            id: IdTreeNodeId::next_id(),  // 自动分配下一个ID
            obj_id,
            obj_hash,
        }
    }
}

/// 为IdTreeLeafNode实现Digestible特性
impl Digestible for IdTreeLeafNode {
    fn to_digest(&self) -> Digest {
        // 使用专门的哈希函数计算叶节点哈希
        // 输入包括：对象内部ID和对象哈希
        id_tree_leaf_hash(self.obj_id, &self.obj_hash)
    }
}

/// ID树非叶节点结构
///
/// 存储子节点的引用信息，不存储实际对象数据
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct IdTreeNonLeafNode {
    /// 节点的唯一标识符
    pub id: IdTreeNodeId,

    /// 子节点的哈希值列表
    /// 使用SmallVec优化，当元素数量小于MAX_ININE_ID_FANOUT时存储在栈上
    pub child_hashes: SmallVec<[Digest; MAX_ININE_ID_FANOUT]>,

    /// 子节点的ID列表
    pub child_ids: SmallVec<[IdTreeNodeId; MAX_ININE_ID_FANOUT]>,
}

/// ID树非叶节点的实现方法
impl IdTreeNonLeafNode {
    /// 创建新的非叶节点
    ///
    /// # 参数
    /// - `child_hashes`: 子节点哈希列表
    /// - `child_ids`: 子节点ID列表
    ///
    /// # 返回值
    /// - 新的非叶节点，自动分配节点ID
    pub fn new(
        child_hashes: SmallVec<[Digest; MAX_ININE_ID_FANOUT]>,
        child_ids: SmallVec<[IdTreeNodeId; MAX_ININE_ID_FANOUT]>,
    ) -> Self {
        Self {
            id: IdTreeNodeId::next_id(),  // 自动分配ID
            child_hashes,
            child_ids,
        }
    }

    /// 创建新的空非叶节点
    ///
    /// # 返回值
    /// - 新的空非叶节点，没有子节点
    pub fn new_ept() -> Self {
        Self {
            id: IdTreeNodeId::next_id(),
            child_hashes: SmallVec::new(),  // 空向量
            child_ids: SmallVec::new(),     // 空向量
        }
    }

    /// 获取指定索引的子节点ID
    ///
    /// # 参数
    /// - `idx`: 子节点索引
    ///
    /// # 返回值
    /// - 如果索引有效，返回Some(&IdTreeNodeId)
    /// - 如果索引无效，返回None
    pub fn get_child_id(&self, idx: usize) -> Option<&IdTreeNodeId> {
        self.child_ids.get(idx)
    }

    /// 获取指定索引的子节点ID（可变引用）
    pub fn get_child_id_mut(&mut self, idx: usize) -> Option<&mut IdTreeNodeId> {
        self.child_ids.get_mut(idx)
    }

    /// 向子节点ID列表末尾添加新的子节点ID
    pub fn push_child_id(&mut self, id: IdTreeNodeId) {
        self.child_ids.push(id);
    }

    /// 获取指定索引的子节点哈希
    pub fn get_child_hash(&self, idx: usize) -> Option<&Digest> {
        self.child_hashes.get(idx)
    }

    /// 获取指定索引的子节点哈希（可变引用）
    pub fn get_child_hash_mut(&mut self, idx: usize) -> Option<&mut Digest> {
        self.child_hashes.get_mut(idx)
    }

    /// 向子节点哈希列表末尾添加新的子节点哈希
    pub fn push_child_hash(&mut self, hash: Digest) {
        self.child_hashes.push(hash);
    }
}

/// 为IdTreeNonLeafNode实现Digestible特性
impl Digestible for IdTreeNonLeafNode {
    fn to_digest(&self) -> Digest {
        // 使用专门的哈希函数计算非叶节点哈希
        // 输入包括：所有子节点哈希的迭代器
        id_tree_non_leaf_hash(self.child_hashes.iter())
    }
}

/// ID树节点加载器特性
///
/// 定义加载ID树节点的接口，用于从存储中读取节点
pub trait IdTreeNodeLoader {
    /// 根据节点ID加载ID树节点
    ///
    /// # 参数
    /// - `id`: 节点ID
    ///
    /// # 返回值
    /// - 加载的ID树节点，或者错误
    fn load_node(&self, id: IdTreeNodeId) -> Result<IdTreeNode>;
}

// 测试模块
#[cfg(test)]
mod tests;