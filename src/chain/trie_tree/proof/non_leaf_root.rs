use std::collections::BTreeMap;

use crate::{
    acc::{AccPublicKey, AccValue, Set},
    chain::trie_tree::{hash::trie_non_leaf_root_proof_hash, split_at_common_prefix2, TrieNodeId},
    digest::{Digest, Digestible},
};
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;

use super::sub_proof::SubProof;

/// 表示Trie树非叶子节点的根证明结构
/// 包含nibble路径、acc哈希和子节点映射
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct TrieNonLeafRoot {
    /// 当前节点的nibble路径
    pub(crate) nibble: String,
    /// 账户哈希值
    pub(crate) acc_hash: Digest,
    /// 子节点映射，按字符索引组织
    pub(crate) children: BTreeMap<char, Box<SubProof>>,
}

impl Digestible for TrieNonLeafRoot {
    /// 计算当前节点的摘要哈希值
    fn to_digest(&self) -> Digest {
        trie_non_leaf_root_proof_hash(
            &self.nibble.to_digest(),
            &self.acc_hash,
            self.children.iter(),
        )
    }
}

impl TrieNonLeafRoot {
    /// 从哈希值创建新的Trie非叶子根节点
    ///
    /// # 参数
    /// * `nibble` - 节点的nibble路径字符串
    /// * `acc_hash` - 账户哈希值的引用
    /// * `children` - 子节点的BTreeMap映射
    ///
    /// # 返回值
    /// 返回新创建的TrieNonLeafRoot实例
    pub(crate) fn from_hashes(
        nibble: &str,
        acc_hash: &Digest,
        children: BTreeMap<char, Box<SubProof>>,
    ) -> Self {
        Self {
            nibble: nibble.to_string(),
            acc_hash: *acc_hash,
            children,
        }
    }

    /// 获取指定键对应的acc哈希值
    ///
    /// # 参数
    /// * `cur_key` - 当前查询的键
    /// * `pk` - 账户公钥
    ///
    /// # 返回值
    /// 返回对应键的acc哈希值，如果不存在则返回空集合的哈希值
    pub(crate) fn value_acc_hash(&self, cur_key: &str, pk: &AccPublicKey) -> Digest {
        // 分割两个键的公共前缀部分
        let (_common_key, cur_idx, rest_cur_key, _node_idx, _rest_node_key) =
            split_at_common_prefix2(cur_key, &self.nibble);
        match self.children.get(&cur_idx) {
            Some(c) => c.value_acc_hash(&rest_cur_key, pk),
            None => {
                let empty_set = Set::new();
                AccValue::from_set(&empty_set, pk).to_digest()
            }
        }
    }

    /// 搜索给定键的前缀匹配
    pub(crate) fn search_prefix(
        &mut self,
        cur_key: &str,
    ) -> Option<(*mut SubProof, Option<TrieNodeId>, SmolStr)> {
        // 分割两个键的公共前缀部分
        let (_common_key, cur_idx, rest_cur_key, _node_idx, _rest_node_key) =
            split_at_common_prefix2(cur_key, &self.nibble);
        match self.children.get_mut(&cur_idx) {
            Some(child) => child.search_prefix(&rest_cur_key),
            None => None,
        }
    }

    /// 递归移除所有子节点中的节点ID
    pub(crate) fn remove_node_id(&mut self) {
        let children = &mut self.children;
        for c in children.values_mut() {
            let sub_proof = c.as_mut();
            sub_proof.remove_node_id();
        }
    }
}
