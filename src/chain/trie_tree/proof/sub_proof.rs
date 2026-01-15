/// SubProof枚举是Trie树证明系统的核心组件，表示Trie树的各种子证明类型。
/// 提供统一接口来处理哈希节点，叶子节点，非叶子节点和根节点证明
use crate::{
    acc::{AccPublicKey, AccValue, Set},
    chain::trie_tree::{
        proof::{leaf::TrieLeaf, non_leaf::TrieNonLeaf, sub_tree::TrieSubTree},
        TrieNodeId,
    },
    digest::{Digest, Digestible},
};
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;

use super::non_leaf_root::TrieNonLeafRoot;

/// Trie树子证明枚举，表示Trie树的各种证明节点类型
///
/// 该枚举提供了统一的证明处理接口，支持四种证明节点类型：
/// 1. Hash节点：压缩的哈希证明，表示未展开的子树
/// 2. Leaf节点：叶子节点证明，包含具体的关键词和累加器
/// 3. NonLeaf节点：普通非叶子节点证明，包含路径前缀和子节点
/// 4. NonLeafRoot节点：根节点证明，额外包含累加器值
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum SubProof {
    Hash(Box<TrieSubTree>),
    Leaf(Box<TrieLeaf>),
    NonLeaf(Box<TrieNonLeaf>),
    NonLeafRoot(Box<TrieNonLeafRoot>),
}

impl Default for SubProof {
    fn default() -> Self {
        Self::Hash(Box::new(TrieSubTree::new(None, "", Digest::zero())))
    }
}

/// 计算子证明的密码学摘要
impl Digestible for SubProof {
    fn to_digest(&self) -> Digest {
        match self {
            Self::Hash(n) => n.to_digest(),
            Self::Leaf(n) => n.to_digest(),
            Self::NonLeaf(n) => n.to_digest(),
            Self::NonLeafRoot(n) => n.to_digest(),
        }
    }
}

impl SubProof {

    ///构造方法，从值创建节点证明
    pub(crate) fn from_hash(node_id: Option<TrieNodeId>, nibble: &str, node_hash: Digest) -> Self {
        Self::Hash(Box::new(TrieSubTree::new(node_id, nibble, node_hash)))
    }

    pub(crate) fn from_non_leaf(n: TrieNonLeaf) -> Self {
        Self::NonLeaf(Box::new(n))
    }

    pub(crate) fn from_non_leaf_root(n: TrieNonLeafRoot) -> Self {
        Self::NonLeafRoot(Box::new(n))
    }

    pub(crate) fn from_leaf(l: TrieLeaf) -> Self {
        Self::Leaf(Box::new(l))
    }

    /// 根据当前关键词最终返回匹配叶子节点的累加器哈希，而不是沿路所有节点的哈希
    /// 目的是：验证某个关键词是否存在
    /// 与路径完整性to_digest 相分离，所以返回的是acc_hash
    /// 递归遍历子证明结构，根据关键词匹配结果返回相应的acc_hash,对哈希节点，总是返回空集合的累加器哈希表示未匹配
    ///
    pub(crate) fn value_acc_hash(&self, cur_key: &str, pk: &AccPublicKey) -> Digest {
        match self {
            SubProof::Hash(_) => {
                let empty_set = Set::new();
                AccValue::from_set(&empty_set, pk).to_digest()
            }
            SubProof::Leaf(n) => n.value_acc_hash(cur_key, pk),
            SubProof::NonLeaf(n) => n.value_acc_hash(cur_key, pk),
            SubProof::NonLeafRoot(n) => n.value_acc_hash(cur_key, pk),
        }
    }

    pub(crate) fn search_prefix<'a>(
        &'a mut self,
        cur_key: &'a str,
    ) -> Option<(*mut SubProof, Option<TrieNodeId>, SmolStr)> {
        match self {
            SubProof::Hash(sub_tree) => {
                let node_id = sub_tree.node_id;
                Some((self as *mut _, node_id, SmolStr::from(cur_key)))
            }
            SubProof::Leaf(n) => {
                if n.rest == cur_key {
                    let node_id = n.node_id;
                    Some((self as *mut _, node_id, SmolStr::from(cur_key)))
                } else {
                    None
                }
            }
            SubProof::NonLeaf(n) => n.search_prefix(cur_key),
            SubProof::NonLeafRoot(n) => n.search_prefix(cur_key),
        }
    }

    /// 移除所有嵌套节点的节点ID
    pub(crate) fn remove_node_id(&mut self) {
        match self {
            SubProof::Hash(n) => {
                let sub_tree = n.as_mut();
                sub_tree.node_id = None;
            }
            SubProof::Leaf(n) => {
                let leaf = n.as_mut();
                leaf.node_id = None;
            }
            SubProof::NonLeaf(n) => {
                let node = n.as_mut();
                node.remove_node_id();
            }
            SubProof::NonLeafRoot(n) => {
                let node = n.as_mut();
                node.remove_node_id();
            }
        }
    }
}
