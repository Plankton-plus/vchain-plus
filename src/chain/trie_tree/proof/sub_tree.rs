use crate::{
    chain::trie_tree::TrieNodeId,
    digest::{Digest, Digestible},
};
use serde::{Deserialize, Serialize};
///TrieSubTree结构体表示Trie树的压缩子树证明，是子证明系统中的哈希节点类型。通过存储子树的根哈希来压缩证明大小。
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub(crate) struct TrieSubTree {
    pub(crate) node_id: Option<TrieNodeId>,
    pub(crate) nibble: String,
    pub(crate) node_hash: Digest, //子树密码学摘要，表示整个压缩子树的默克尔根哈希。
}

impl Digestible for TrieSubTree {
    fn to_digest(&self) -> Digest {
        self.node_hash
    }
}

impl TrieSubTree {
    pub(crate) fn new(node_id: Option<TrieNodeId>, nibble: &str, node_hash: Digest) -> Self {
        Self {
            node_id,
            nibble: nibble.to_string(),
            node_hash,
        }
    }
}
