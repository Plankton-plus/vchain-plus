// 引入必要的依赖和模块
use crate::{
    acc::{set::Set, AccValue},  // 累加器相关，用于集合操作和累加器值
    create_id_type_by_u32,       // 宏：创建基于u32的ID类型
    digest::{Digest, Digestible}, // 哈希摘要和可摘要特性
};
use anyhow::Result;              // 错误处理
use hash::{trie_leaf_hash, trie_non_leaf_node_hash, trie_non_leaf_root_hash};  // Trie树哈希函数
use serde::{Deserialize, Serialize};  // 序列化/反序列化
use smol_str::SmolStr;           // 小型字符串优化类型
use std::collections::BTreeMap;  // 有序映射，按键排序

// 使用宏创建TrieNodeId类型（基于u32），用于唯一标识Trie树节点
// 宏会自动生成ID分配、序列化等功能
create_id_type_by_u32!(TrieNodeId);

// 定义子模块
pub mod hash;    // 哈希计算相关
pub mod proof;   // 证明生成和验证
pub mod read;    // 读取操作
pub mod write;   // 写入操作

/// Trie树根节点结构
///
/// 存储Trie树的根节点引用和哈希值
#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct TrieRoot {
    /// Trie树根节点的ID，None表示空树
    pub(crate) trie_root_id: Option<TrieNodeId>,

    /// Trie树根节点的哈希值，用于完整性验证
    pub(crate) trie_root_hash: Digest,
}

/// 为TrieRoot实现Digestible特性，使其可以计算哈希
impl Digestible for TrieRoot {
    fn to_digest(&self) -> Digest {
        // 直接返回存储的根节点哈希
        self.trie_root_hash
    }
}

/// Trie树节点枚举，可以是叶节点、非叶节点或非叶根节点
///
/// 使用枚举来表示不同类型的节点
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum TrieNode {
    /// 叶节点变体，存储关键词的剩余部分和数据集合
    Leaf(TrieLeafNode),

    /// 非叶节点变体，存储中间字符和子节点引用
    NonLeaf(TrieNonLeafNode),

    /// 非叶根节点变体，既有子节点引用也有数据集合（用于前缀共享）
    NonLeafRoot(TrieNonLeafRootNode),
}

/// 为TrieNode实现Digestible特性
impl Digestible for TrieNode {
    fn to_digest(&self) -> Digest {
        match self {
            // 委托给相应类型节点的to_digest方法
            TrieNode::Leaf(n) => n.to_digest(),
            TrieNode::NonLeaf(n) => n.to_digest(),
            TrieNode::NonLeafRoot(n) => n.to_digest(),
        }
    }
}

/// TrieNode的实现方法
impl TrieNode {
    /// 从叶节点创建Trie节点
    pub fn from_leaf(n: TrieLeafNode) -> Self {
        Self::Leaf(n)
    }

    /// 从非叶节点创建Trie节点
    pub fn from_non_leaf(n: TrieNonLeafNode) -> Self {
        Self::NonLeaf(n)
    }

    /// 从非叶根节点创建Trie节点
    pub fn from_non_leaf_root(n: TrieNonLeafRootNode) -> Self {
        Self::NonLeafRoot(n)
    }

    /// 获取节点的ID
    pub fn get_id(&self) -> TrieNodeId {
        match self {
            // 返回叶节点的ID
            TrieNode::Leaf(n) => n.id,
            // 返回非叶节点的ID
            TrieNode::NonLeaf(n) => n.id,
            // 返回非叶根节点的ID
            TrieNode::NonLeafRoot(n) => n.id,
        }
    }

    /// 获取节点存储的字符串部分
    ///
    /// 对于叶节点，返回rest（关键词的剩余部分）
    /// 对于非叶节点，返回nibble（前缀片段）
    pub fn get_string(&self) -> &str {
        match self {
            TrieNode::Leaf(n) => &n.rest,
            TrieNode::NonLeaf(n) => &n.nibble,
            TrieNode::NonLeafRoot(n) => &n.nibble,
        }
    }

    /// 获取节点的数据集合
    ///
    /// # Panics
    /// 如果对非叶节点调用此方法，会panic（非叶节点没有数据集合）
    pub fn get_set(&self) -> &Set {
        match self {
            TrieNode::Leaf(n) => &n.data_set,
            TrieNode::NonLeaf(_) => panic!("Cannot read set from non-leaf node"),
            TrieNode::NonLeafRoot(n) => &n.data_set,
        }
    }

    /// 获取节点的累加器值
    ///
    /// # Panics
    /// 如果对非叶节点调用此方法，会panic（非叶节点没有累加器值）
    pub fn get_acc(&self) -> &AccValue {
        match self {
            TrieNode::Leaf(n) => &n.data_set_acc,
            TrieNode::NonLeaf(_) => panic!("Cannot read set from non-leaf node"),
            TrieNode::NonLeafRoot(n) => &n.data_set_acc,
        }
    }
}

/// Trie树叶节点结构
///
/// 存储关键词的剩余部分和对应的数据集合
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct TrieLeafNode {
    /// 节点的唯一标识符
    pub id: TrieNodeId,

    /// 关键词的剩余部分（经过前缀匹配后剩下的部分）
    pub rest: SmolStr,

    /// 数据集合，存储匹配该关键词的对象ID等
    pub data_set: Set,

    /// 数据集合的累加器值，用于验证
    pub data_set_acc: AccValue,
}

/// 为TrieLeafNode实现Digestible特性
impl Digestible for TrieLeafNode {
    fn to_digest(&self) -> Digest {
        // 使用专门的哈希函数计算叶节点哈希
        // 输入包括：剩余部分的哈希和累加器值的哈希
        trie_leaf_hash(&self.rest.to_digest(), &self.data_set_acc.to_digest())
    }
}

/// TrieLeafNode的实现方法
impl TrieLeafNode {
    /// 创建新的叶节点
    ///
    /// # 参数
    /// - `rest`: 关键词的剩余部分
    /// - `data_set`: 数据集合
    /// - `data_set_acc`: 累加器值
    ///
    /// # 返回值
    /// - 新的叶节点，自动分配节点ID
    pub fn new(rest: SmolStr, data_set: Set, data_set_acc: AccValue) -> Self {
        Self {
            id: TrieNodeId::next_id(),  // 自动分配下一个ID
            rest,
            data_set,
            data_set_acc,
        }
    }
}

/// Trie树非叶节点结构
///
/// 存储前缀片段和子节点引用，没有数据集合
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct TrieNonLeafNode {
    /// 节点的唯一标识符
    pub id: TrieNodeId,

    /// 前缀片段（该节点表示的关键词片段）
    pub nibble: SmolStr,

    /// 子节点映射，按字符排序
    /// 键：下一个字符，值：(子节点ID, 子节点哈希)
    pub children: BTreeMap<char, (TrieNodeId, Digest)>,
}

/// 为TrieNonLeafNode实现Digestible特性
impl Digestible for TrieNonLeafNode {
    fn to_digest(&self) -> Digest {
        // 使用专门的哈希函数计算非叶节点哈希
        // 输入包括：前缀片段的哈希和所有子节点的哈希
        trie_non_leaf_node_hash(&self.nibble.to_digest(), self.children.iter())
    }
}

/// TrieNonLeafNode的实现方法
impl TrieNonLeafNode {
    /// 创建新的非叶节点
    ///
    /// # 参数
    /// - `nibble`: 前缀片段
    /// - `children`: 子节点映射
    ///
    /// # 返回值
    /// - 新的非叶节点，自动分配节点ID
    pub fn new(nibble: SmolStr, children: BTreeMap<char, (TrieNodeId, Digest)>) -> Self {
        Self {
            id: TrieNodeId::next_id(),  // 自动分配ID
            nibble,
            children,
        }
    }
}

/// Trie树非叶根节点结构
///
/// 既有子节点引用也有数据集合的特殊节点
/// 通常用于根节点或共享前缀的中间节点
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct TrieNonLeafRootNode {
    /// 节点的唯一标识符
    pub id: TrieNodeId,

    /// 前缀片段
    pub nibble: SmolStr,

    /// 数据集合（该前缀匹配的所有对象ID）
    pub data_set: Set,

    /// 数据集合的累加器值
    pub data_set_acc: AccValue,

    /// 子节点映射
    pub children: BTreeMap<char, (TrieNodeId, Digest)>,
}

/// 为TrieNonLeafRootNode实现Digestible特性
impl Digestible for TrieNonLeafRootNode {
    fn to_digest(&self) -> Digest {
        // 使用专门的哈希函数计算非叶根节点哈希
        // 输入包括：前缀片段的哈希、累加器值的哈希和所有子节点的哈希
        trie_non_leaf_root_hash(
            &self.nibble.to_digest(),
            &self.data_set_acc.to_digest(),
            self.children.iter(),
        )
    }
}

/// TrieNonLeafRootNode的实现方法
impl TrieNonLeafRootNode {
    /// 创建新的非叶根节点
    ///
    /// # 参数
    /// - `nibble`: 前缀片段
    /// - `data_set`: 数据集合
    /// - `data_set_acc`: 累加器值
    /// - `children`: 子节点映射
    ///
    /// # 返回值
    /// - 新的非叶根节点，自动分配节点ID
    pub fn new(
        nibble: SmolStr,
        data_set: Set,
        data_set_acc: AccValue,
        children: BTreeMap<char, (TrieNodeId, Digest)>,
    ) -> Self {
        Self {
            id: TrieNodeId::next_id(),  // 自动分配ID
            nibble,
            data_set,
            data_set_acc,
            children,
        }
    }
}

/// Trie树节点加载器特性
///
/// 定义加载Trie树节点的接口，用于从存储中读取节点
pub trait TrieNodeLoader {
    /// 根据节点ID加载Trie树节点
    ///
    /// # 参数
    /// - `id`: 节点ID
    ///
    /// # 返回值
    /// - 加载的Trie树节点，或者错误
    fn load_node(&self, id: TrieNodeId) -> Result<TrieNode>;
}

/// 计算两个字符串的公共前缀长度
///
/// # 参数
/// - `a`: 第一个字符串
/// - `b`: 第二个字符串
///
/// # 返回值
/// - 公共前缀的字符数
fn common_prefix_len(a: &str, b: &str) -> usize {
    // 逐字符比较，直到遇到不同的字符或任一字符串结束
    a.chars().zip(b.chars()).take_while(|(a, b)| a == b).count()
}

/// 在公共前缀处分割两个字符串
///
/// # 参数
/// - `a`: 第一个字符串
/// - `b`: 第二个字符串
///
/// # 返回值
/// - (公共前缀, a的剩余部分, b的剩余部分)
fn split_at_common_prefix<'a>(a: &'a str, b: &'a str) -> (&'a str, &'a str, &'a str) {
    // 计算公共前缀长度
    let prefix_len = common_prefix_len(a, b);

    // 在公共前缀处分割两个字符串
    let (common, remaining1) = a.split_at(prefix_len);
    let (_, remaining2) = b.split_at(prefix_len);

    (common, remaining1, remaining2)
}

/// 在公共前缀处分割两个字符串，返回更详细的信息
///
/// # 参数
/// - `a`: 第一个字符串
/// - `b`: 第二个字符串
///
/// # 返回值
/// - (公共前缀, a的第一个剩余字符, a的剩余部分, b的第一个剩余字符, b的剩余部分)
/// 注意：如果某个字符串在公共前缀后为空，则对应的第一个字符为'\0'
fn split_at_common_prefix2(a: &str, b: &str) -> (String, char, String, char, String) {
    // 首先获取基本分割
    let (common, remain1, remain2) = split_at_common_prefix(a, b);
    let common = common;

    let first1;
    let first2;
    let remaining1: String;
    let remaining2: String;

    // 处理第一个字符串的剩余部分
    if remain1.is_empty() {
        // 如果剩余部分为空，设置特殊字符和空字符串
        first1 = '\0';
        remaining1 = "".to_string();
    } else {
        // 分割第一个字符和剩余部分
        let (f1, r1) = remain1.split_at(1);
        first1 = f1.chars().next().expect("string is empty");
        remaining1 = r1.to_string();
    }

    // 处理第二个字符串的剩余部分
    if remain2.is_empty() {
        first2 = '\0';
        remaining2 = "".to_string();
    } else {
        let (f2, r2) = remain2.split_at(1);
        first2 = f2.chars().next().expect("string is empty");
        remaining2 = r2.to_string();
    }

    (common.to_string(), first1, remaining1, first2, remaining2)
}

// 测试模块
#[cfg(test)]
mod tests;