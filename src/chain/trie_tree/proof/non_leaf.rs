/// TrieNonLeaf结构体实现。
use crate::{
    acc::{AccPublicKey, AccValue, Set},
    chain::trie_tree::{
        hash::trie_non_leaf_proof_hash,
        proof::{sub_proof::SubProof, TrieNodeId},
        split_at_common_prefix2,
    },
    digest::{Digest, Digestible},
};
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct TrieNonLeaf {
    pub(crate) nibble: String,
    /// 子节点映射表。BTreeMap保证字符顺序。键为单个字符，值为子节点的证明结构。
    pub(crate) children: BTreeMap<char, Box<SubProof>>,
}

impl Digestible for TrieNonLeaf {
    ///通过对路径前缀和所有子节点的证明哈希进行组合生成代表该非叶子节点完整性的唯一摘要。
    fn to_digest(&self) -> Digest {
        trie_non_leaf_proof_hash(&self.nibble.to_digest(), self.children.iter())
    }
}

impl TrieNonLeaf {
    /// 通过路径前缀和子节点映射创建新的非叶子节点
    ///
    /// # 参数
    /// - `nibble`: 当前节点的路径前缀字符串
    /// - `children`: 子节点映射表，键为字符，值为子节点证明
    ///
    /// # 返回
    /// - `TrieNonLeaf`: 新创建的非叶子节点实例
    pub(crate) fn from_hashes(nibble: &str, children: BTreeMap<char, Box<SubProof>>) -> Self {
        Self {
            nibble: nibble.to_string(),
            children,
        }
    }

    pub(crate) fn value_acc_hash(&self, cur_key: &str, pk: &AccPublicKey) -> Digest {
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

    pub(crate) fn search_prefix(
        &mut self,
        cur_key: &str,
    ) -> Option<(*mut SubProof, Option<TrieNodeId>, SmolStr)> {
        let (_common_key, cur_idx, rest_cur_key, _node_idx, _rest_node_key) =
            split_at_common_prefix2(cur_key, &self.nibble);
        match self.children.get_mut(&cur_idx) {
            Some(child) => child.search_prefix(&rest_cur_key),
            None => None,
        }
    }

    /// 移除所有子节点的节点ID
    /// 递归遍历所有子节点，将节点ID设置为None。
    pub(crate) fn remove_node_id(&mut self) {
        let children = &mut self.children;
        for c in children.values_mut() {
            let sub_proof = c.as_mut();
            sub_proof.remove_node_id();
        }
    }
}
