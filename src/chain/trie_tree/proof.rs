use crate::{
    acc::{AccPublicKey, AccValue, Set},
    chain::trie_tree::TrieNodeId,
    digest::{Digest, Digestible},
};
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use sub_proof::SubProof;

pub(crate) mod leaf;
pub(crate) mod non_leaf;
pub(crate) mod non_leaf_root;
pub(crate) mod sub_proof;
pub(crate) mod sub_tree;

/// Merkle Trie的证明结构，用于验证数据的存在性和完整性
///
/// 该结构包含密码学证明，可用于验证：
/// - Trie中特定键值对的存在性
/// - 特定关键词的累加器值完整性
/// - Trie结构的整体一致性


#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Proof {
    /// Trie的根子证明
    pub(crate) root: Option<SubProof>,
}

impl Proof {
    /// 创建一个空证明，表示空的Trie
    pub fn new() -> Self {
        Self::default()
    }

    /// 从根子证明创建证明
    pub(crate) fn from_subproof(root: SubProof) -> Self {
        Self { root: Some(root) }
    }

    /// 从根哈希创建证明
    ///
    /// # 参数
    /// * `root_id` - Trie中根节点的ID（可选）
    /// * `nibble` - 指向该节点的nibble路径（根节点为空字符串）
    /// * `root_hash` - 根节点的哈希值
    ///
    /// # 返回值
    /// * 如果 `root_hash` 是零摘要，返回空证明
    /// * 否则，返回包含给定哈希的单个子证明的证明
    pub fn from_root_hash(root_id: Option<TrieNodeId>, nibble: &str, root_hash: Digest) -> Self {
        if root_hash == Digest::zero() {
            Self::default()
        } else {
            Self::from_subproof(SubProof::from_hash(root_id, nibble, root_hash))
        }
    }

    /// 返回证明的根哈希值
    ///
    /// 对于空证明，返回零摘要
    pub fn root_hash(&self) -> Digest {
        match self.root.as_ref() {
            Some(root) => root.to_digest(),
            None => Digest::zero(),
        }
    }

    /// 计算证明中特定关键词的累加器哈希值
    ///
    /// 此方法遍历证明结构以查找并计算给定关键词的累加器值
    ///
    /// # 参数
    /// * `keyword` - 要验证其累加器值的关键词
    /// * `pk` - 用于累加器计算的公钥
    ///
    /// # 返回值
    /// * 关键词的计算累加器摘要
    /// * 对于空证明，返回空集合累加器的摘要
    fn value_acc_hash(&self, keyword: &str, pk: &AccPublicKey) -> Digest {
        match self.root.as_ref() {
            Some(root) => root.value_acc_hash(keyword, pk),
            None => {
                let empty_set = Set::new();
                AccValue::from_set(&empty_set, pk).to_digest()
            }
        }
    }
    /// 验证证明中的累加器值与期望值是否匹配
    ///
    /// 这是一个关键的安全性检查，确保证明包含给定关键词的正确累加器状态
    ///
    /// # 参数
    /// * `target_acc` - 要验证的期望累加器值
    /// * `keyword` - 要验证其累加器的关键词
    /// * `pk` - 用于累加器计算的公钥
    ///
    /// # 返回值
    /// * `Ok(())` 如果累加器值匹配计算值
    /// * `Err(anyhow::Error)` 如果验证失败，带有描述性消息
    ///
    /// # 错误
    /// 如果计算的累加器摘要与目标累加器的摘要不匹配，则返回错误
    pub fn verify_acc(&self, target_acc: AccValue, keyword: &str, pk: &AccPublicKey) -> Result<()> {
        let computed_acc = self.value_acc_hash(keyword, pk);
        ensure!(
            target_acc.to_digest() == computed_acc,
            "Trie verification: acc value not matched!"
        );
        Ok(())
    }
    /// 从证明结构的所有子证明中移除节点ID
    pub(crate) fn remove_node_id(&mut self) {
        if let Some(sub_proof) = &mut self.root {
            sub_proof.remove_node_id();
        }
    }
}
