use crate::{
    acc::{AccPublicKey, AccValue, Set},
    chain::trie_tree::{
        proof::{non_leaf_root::TrieNonLeafRoot, sub_proof::SubProof, Proof},
        split_at_common_prefix2, TrieNode, TrieNodeId, TrieNodeLoader,
    },
    digest::{Digest, Digestible},
};
use anyhow::{anyhow, bail, Context, Result};
use smol_str::SmolStr;
use std::collections::BTreeMap;

/// 在Trie树中查询指定关键词的数据集和累加器值，并生成验证证明
///
/// 该函数是Trie查询的主入口点，执行以下操作：
/// 1. 验证根节点ID的有效性
/// 2. 加载根节点并开始递归查询
/// 3. 返回查询结果、累加器值及相应的证明
///
/// # 参数
/// * `node_loader` - Trie节点加载器，负责从存储中加载节点数据
/// * `root_id` - 根节点的ID，None表示空树
/// * `keyword` - 要查询的关键词
/// * `pk` - 累加器公钥，用于计算累加器值
///
/// # 返回值
/// * `Ok((Set, AccValue, Proof))` - 成功时返回三元组：
///   - 查询到的数据集（如果关键词不存在则返回空集）
///   - 关键词对应的累加器值
///   - 验证证明
/// * `Err(anyhow::Error)` - 查询过程中发生错误
///
/// # 错误
/// * 根节点ID为None时返回"id树为空"错误
/// * 节点加载失败时返回相应错误
pub fn query_trie(
    node_loader: &impl TrieNodeLoader,
    root_id: Option<TrieNodeId>,
    keyword: &SmolStr,
    pk: &AccPublicKey,
) -> Result<(Set, AccValue, Proof)> {
    let trie_root_id = match root_id {
        Some(id) => id,
        None => bail!("The id tree is empty"),
    };

    // 加载根节点并开始内部查询
    let root_node = node_loader.load_node(trie_root_id)?;
    let (res, acc, p) = inner_query_trie(node_loader, trie_root_id, root_node, keyword, pk)?;
    Ok((res, acc, Proof::from_subproof(p)))
}

/// 内部递归查询函数，实际执行Trie遍历和证明生成
///
/// 该函数是查询的核心实现，递归遍历Trie树，同时构建验证证明。
/// 采用循环而非递归以避免递归深度限制。
///
/// # 参数
/// * `node_loader` - Trie节点加载器
/// * `root_id` - 当前查询的根节点ID
/// * `root_node` - 当前查询的根节点
/// * `keyword` - 要查询的关键词
/// * `pk` - 累加器公钥
///
/// # 返回值
/// * `Ok((Set, AccValue, SubProof))` - 查询结果三元组
///
/// # 算法流程
/// 1. 初始化证明为Hash类型的占位符
/// 2. 循环遍历Trie节点，直到找到叶子节点或无法继续
/// 3. 根据节点类型处理：
///    - 叶子节点：检查是否匹配关键词
///    - 非叶子节点：根据路径前缀选择子节点继续遍历
/// 4. 为每个访问的节点构建相应的子证明
fn inner_query_trie(
    node_loader: &impl TrieNodeLoader,
    root_id: TrieNodeId,
    root_node: TrieNode,
    keyword: &SmolStr,
    pk: &AccPublicKey,
) -> Result<(Set, AccValue, SubProof)> {
    use super::proof::{leaf::TrieLeaf, non_leaf::TrieNonLeaf};

    // 初始化证明为Hash类型的占位符(π_w 的起始)
    let mut query_proof = SubProof::from_hash(Some(root_id), keyword, root_node.to_digest());
    let query_val: Set;
    let res_acc: AccValue;

    // 当前遍历状态
    let mut cur_node = root_node;      // 当前处理的节点
    let mut cur_key = keyword.to_string(); // 当前要匹配的关键词剩余部分
    let mut cur_proof = &mut query_proof as *mut _; // 指针指向这个根占位符

    loop {
        match &cur_node {
            // 处理叶子节点
            TrieNode::Leaf(n) => {
                if n.rest == cur_key {
                    // 完全匹配：返回叶子节点的数据
                    query_val = n.data_set.clone();
                    res_acc = n.data_set_acc;
                    unsafe {
                        // 将当前证明替换为叶子节点证明
                        *cur_proof = SubProof::from_leaf(TrieLeaf::new(
                            Some(n.id),
                            &n.rest,
                            n.data_set_acc.to_digest(),
                        ));
                    }
                } else {
                    // 不匹配：返回空集
                    query_val = Set::new();
                    res_acc = AccValue::from_set(&query_val, pk);
                    unsafe {
                        // 保持为Hash证明
                        *cur_proof = SubProof::from_hash(Some(n.id), &n.rest, n.to_digest());//替换为Leaf证明
                    }
                }
                break;
            }
            // 处理普通非叶子节点
            TrieNode::NonLeaf(n) => {
                // 分割当前关键词和节点nibble路径的公共前缀
                let (_common_key, cur_idx, rest_cur_key, _node_idx, _rest_node_key) =
                    split_at_common_prefix2(&cur_key, &n.nibble);

                // 检查是否有对应的子节点
                match n.children.get(&cur_idx) {
                    Some((id, hash)) => {
                        // 存在子节点：加载子节点并继续遍历
                        let sub_node = node_loader.load_node(*id)?;

                        // 创建子节点的Hash证明占位符
                        let mut sub_proof =
                            Box::new(SubProof::from_hash(Some(*id), &rest_cur_key, *hash));
                        let sub_proof_ptr = &mut *sub_proof as *mut _;

                        let mut children = BTreeMap::new();
                        for (c, (i, h)) in &n.children {
                            let child_node = node_loader.load_node(*i)?;
                            children.insert(
                                *c,
                                Box::new(SubProof::from_hash(
                                    Some(child_node.get_id()),
                                    child_node.get_string(),
                                    *h,
                                )),
                            );
                        }

                        // 创建非叶子节点证明
                        let mut non_leaf = TrieNonLeaf::from_hashes(&n.nibble, children);

                        // 将当前遍历的子节点证明替换为占位符
                        *non_leaf
                            .children
                            .get_mut(&cur_idx)
                            .ok_or_else(|| anyhow!("Cannot find subproof!"))? = sub_proof;

                        // 更新当前证明为非叶子节点证明
                        unsafe {
                            *cur_proof = SubProof::from_non_leaf(non_leaf);
                        }

                        // 更新遍历状态
                        cur_node = sub_node;
                        cur_proof = sub_proof_ptr;//现在指针指向了刚刚新长出来的那个分支的末端
                        cur_key = rest_cur_key;
                        continue;
                    }
                    None => {
                        // 没有匹配的子节点：返回空集
                        query_val = Set::new();
                        res_acc = AccValue::from_set(&query_val, pk);
                        unsafe {
                            *cur_proof = SubProof::from_hash(Some(n.id), &n.nibble, n.to_digest());
                        }
                        break;
                    }
                }
            }
            // 处理根节点（特殊的非叶子节点）
            TrieNode::NonLeafRoot(n) => {
                // 处理逻辑与非叶子节点类似，但需要包含累加器值
                let (_common_key, cur_idx, rest_cur_key, _node_idx, _rest_node_key) =
                    split_at_common_prefix2(&cur_key, &n.nibble);

                match n.children.get(&cur_idx) {
                    Some((id, hash)) => {
                        let sub_node = node_loader.load_node(*id)?;
                        let mut sub_proof =
                            Box::new(SubProof::from_hash(Some(*id), &rest_cur_key, *hash));
                        let sub_proof_ptr = &mut *sub_proof as *mut _;

                        let mut children = BTreeMap::new();
                        for (c, (i, h)) in &n.children {
                            let child_node = node_loader.load_node(*i)?;
                            children.insert(
                                *c,
                                Box::new(SubProof::from_hash(
                                    Some(child_node.get_id()),
                                    child_node.get_string(),
                                    *h,
                                )),
                            );
                        }

                        // 创建根节点证明，包含累加器哈希
                        let mut root_proof = TrieNonLeafRoot::from_hashes(
                            &n.nibble,
                            &n.data_set_acc.to_digest(),
                            children,
                        );

                        *root_proof
                            .children
                            .get_mut(&cur_idx)
                            .ok_or_else(|| anyhow!("Cannot find subproof!"))? = sub_proof;

                        unsafe {
                            *cur_proof = SubProof::from_non_leaf_root(root_proof);
                        }

                        cur_node = sub_node;
                        cur_proof = sub_proof_ptr;
                        cur_key = rest_cur_key;
                        continue;
                    }
                    None => {
                        query_val = Set::new();
                        res_acc = AccValue::from_set(&query_val, pk);
                        unsafe {
                            *cur_proof = SubProof::from_hash(Some(n.id), &n.nibble, n.to_digest());
                        }
                        break;
                    }
                }
            }
        }
    }

    Ok((query_val, res_acc, query_proof))
}

/// Trie读取上下文，提供有状态的Trie查询接口
///
/// 该结构体封装了查询所需的所有状态，支持增量证明更新。
/// 特别适用于需要多次查询同一Trie状态的场景，可以复用已加载的节点信息。
///
/// # 生命周期
/// * `'a` - 节点加载器的生命周期
///
/// # 泛型
/// * `L` - 实现TrieNodeLoader trait的类型
pub struct ReadContext<'a, L: TrieNodeLoader> {
    /// Trie节点加载器
    node_loader: &'a L,
    /// 根节点ID
    root_id: Option<TrieNodeId>,
    /// 当前的验证证明
    proof: Proof,
}

impl<'a, L: TrieNodeLoader> ReadContext<'a, L> {
    /// 创建新的读取上下文
    ///
    /// # 参数
    /// * `node_loader` - Trie节点加载器
    /// * `root_id` - 根节点ID，None表示空树
    ///
    /// # 说明
    /// * 如果root_id为Some，尝试加载节点并创建相应的证明
    /// * 如果加载失败，创建零哈希证明
    /// * 如果root_id为None，创建空树证明
    pub fn new(node_loader: &'a L, root_id: Option<TrieNodeId>) -> Self {
        match root_id {
            Some(id) => match node_loader.load_node(id) {
                Ok(n) => {
                    // 成功加载节点：创建基于节点哈希的证明
                    let nibble = n.get_string();
                    let dig = n.to_digest();
                    Self {
                        node_loader,
                        root_id,
                        proof: Proof::from_root_hash(Some(id), nibble, dig),
                    }
                }
                Err(_) => {
                    // 加载失败：创建零哈希证明
                    Self {
                        node_loader,
                        root_id,
                        proof: Proof::from_root_hash(Some(id), "", Digest::zero()),
                    }
                }
            },
            None => {
                // 空树：创建零哈希证明
                Self {
                    node_loader,
                    root_id,
                    proof: Proof::from_root_hash(Some(TrieNodeId(0)), "", Digest::zero()),
                }
            }
        }
    }

    /// 获取当前证明的引用
    pub fn get_proof(&self) -> &Proof {
        &self.proof
    }

    /// 消费上下文，返回移除节点ID后的证明
    ///
    /// 该方法用于获取最终证明，会移除证明中的所有节点ID以减小证明大小。
    /// 节点ID仅用于内部索引，验证时不需要。
    pub fn into_proof(self) -> Proof {
        let mut proof = self.proof;
        proof.remove_node_id();
        proof
    }

    /// 查询指定关键词并更新证明
    ///
    /// 该方法执行增量查询和证明更新：
    /// 1. 如果当前证明为空，执行完整查询并更新整个证明
    /// 2. 如果当前证明非空，尝试在现有证明基础上增量更新
    ///
    /// # 参数
    /// * `keyword` - 要查询的关键词
    /// * `pk` - 累加器公钥
    ///
    /// # 返回值
    /// * `Ok((Set, AccValue))` - 查询结果数据集和累加器值
    ///
    /// # 错误
    /// * 子节点ID不存在时返回错误
    /// * 节点加载失败时返回相应错误
    pub fn query(&mut self, keyword: &SmolStr, pk: &AccPublicKey) -> Result<(Set, AccValue)> {
        let query_val: Set;
        let res_acc: AccValue;

        match self.proof.root.as_mut() {
            Some(root) => {
                // 现有证明非空：尝试增量更新
                match root.search_prefix(keyword) {
                    Some((sub_proof, sub_root_id_opt, cur_key)) => {
                        // 找到匹配的前缀：仅更新证明的相应部分
                        let sub_root_id = sub_root_id_opt.context("Sub root id is none")?;
                        let sub_root_node = self.node_loader.load_node(sub_root_id)?;
                        let (v, a, p) = inner_query_trie(
                            self.node_loader,
                            sub_root_id,
                            sub_root_node,
                            &cur_key,
                            pk,
                        )?;
                        unsafe {
                            // 替换子证明
                            *sub_proof = p;
                        }
                        query_val = v;
                        res_acc = a;
                    }
                    None => {
                        // 没有匹配的前缀：返回空集
                        query_val = Set::new();
                        res_acc = AccValue::from_set(&query_val, pk);
                    }
                }
            }
            None => {
                // 当前证明为空：执行完整查询
                let (v, a, p) = query_trie(self.node_loader, self.root_id, keyword, pk)?;
                self.proof = p;
                query_val = v;
                res_acc = a;
            }
        }
        Ok((query_val, res_acc))
    }
}