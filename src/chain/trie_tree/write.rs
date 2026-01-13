use crate::acc::AccPublicKey;
use crate::chain::{
    id_tree::ObjId,
    trie_tree::{
        split_at_common_prefix2, AccValue, Digest, Digestible, Set, TrieLeafNode, TrieNode,
        TrieNodeId, TrieNodeLoader, TrieNonLeafNode, TrieRoot,
    },
};
use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use std::collections::BTreeMap;
use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
};

use super::TrieNonLeafRootNode;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Apply {
    pub root: TrieRoot,
    pub nodes: HashMap<TrieNodeId, TrieNode>,
}

#[derive(Debug, Clone)]
pub struct WriteContext<'a, L: TrieNodeLoader> {
    node_loader: &'a L,
    apply: Apply,
    outdated: HashSet<TrieNodeId>,
}

impl<'a, L: TrieNodeLoader> WriteContext<'a, L> {
    pub fn new(node_loader: &'a L, root: TrieRoot) -> Self {
        Self {
            node_loader,
            apply: Apply {
                root,
                nodes: HashMap::new(),
            },
            outdated: HashSet::new(),
        }
    }

    pub fn changes(self) -> Apply {
        self.apply
    }

    pub fn write_leaf(
        &mut self,
        rest: SmolStr,
        data_set: Set,
        acc: AccValue,
    ) -> (TrieNodeId, Digest) {
        let n = TrieLeafNode::new(rest, data_set, acc);
        let id = n.id;
        let hash = n.to_digest();
        self.apply.nodes.insert(id, TrieNode::from_leaf(n));
        (id, hash)
    }

    pub fn write_non_leaf(&mut self, n: TrieNonLeafNode) -> (TrieNodeId, Digest) {
        let id = n.id;
        let hash = n.to_digest();
        self.apply.nodes.insert(id, TrieNode::from_non_leaf(n));
        (id, hash)
    }

    pub fn write_non_leaf_root(&mut self, n: TrieNonLeafRootNode) -> (TrieNodeId, Digest) {
        let id = n.id;
        let hash = n.to_digest();
        self.apply.nodes.insert(id, TrieNode::from_non_leaf_root(n));
        (id, hash)
    }

    fn get_node(&self, id: TrieNodeId) -> Result<Cow<TrieNode>> {
        Ok(match self.apply.nodes.get(&id) {
            Some(n) => Cow::Borrowed(n),
            None => Cow::Owned(self.node_loader.load_node(id)?),
        })
    }

    pub fn insert(&mut self, key: SmolStr, obj_id: ObjId, pk: &AccPublicKey) -> Result<()> {
        // 创建包含单个对象ID的集合
        let set = Set::from_single_element(obj_id.0);
        // 计算新集合的累加器值
        let new_acc = AccValue::from_set(&set, pk);
        // 从根节点开始遍历
        let mut cur_id_opt = self.apply.root.trie_root_id;
        // 保存根节点ID用于后续判断
        let root_id_opt = cur_id_opt;
        // 当前处理的键
        let mut cur_key = key;

        // 定义临时节点结构，用于存储遍历路径
        struct Leaf {
            id: TrieNodeId,  // 叶子节点ID
            hash: Digest,    // 叶子节点哈希
        }
        struct NonLeaf {
            node: TrieNonLeafNode,  // 非叶子节点
            idx: char,              // 子节点索引字符
        }
        struct NonLeafRoot {
            node: TrieNonLeafRootNode,  // 根非叶子节点
            idx: char,                  // 子节点索引字符
        }
        // 临时节点枚举类型，包含三种可能节点
        enum TempNode {
            Leaf(Box<Leaf>),
            NonLeaf(Box<NonLeaf>),
            NonLeafRoot(Box<NonLeafRoot>),
        }

        let mut temp_nodes: Vec<TempNode> = Vec::new();

        // 主循环：沿着键路径向下查找插入位置
        loop {
            match cur_id_opt {
                Some(id) => {
                    // 将当前节点标记为过时（将被修改）
                    self.outdated.insert(id);
                    let cur_node = self.get_node(id)?;

                    match cur_node.as_ref() {
                        TrieNode::Leaf(n) => {
                            // 处理叶子节点情况
                            if cur_key == n.rest {
                                // 情况1：键完全匹配，更新现有叶子节点
                                let leaf_set = &set | &n.data_set;  // 计算集合并集
                                let sets_inter = (&set) & (&n.data_set);  // 计算集合交集
                                // 更新累加器：新累加器 + 旧累加器 - 交集累加器（避免重复计算）
                                let leaf_acc =
                                    new_acc + n.data_set_acc - AccValue::from_set(&sets_inter, pk);
                                // 写入更新后的叶子节点
                                let (leaf_id, leaf_hash) =
                                    self.write_leaf(cur_key, leaf_set, leaf_acc);
                                // 保存到临时节点列表
                                temp_nodes.push(TempNode::Leaf(Box::new(Leaf {
                                    id: leaf_id,
                                    hash: leaf_hash,
                                })));
                            } else {
                                // 情况2：键不匹配，需要创建分支节点
                                // 找到两个键的公共前缀和差异部分
                                let (common_key, cur_idx, rest_cur_key, node_idx, rest_node_key) =
                                    split_at_common_prefix2(&cur_key, &n.rest);

                                // 保存原叶子节点数据
                                let node_data_set = n.data_set.clone();
                                let node_acc = n.data_set_acc;

                                // 为原叶子节点创建新的叶子节点（使用剩余部分）
                                let (node_leaf_id, node_leaf_hash) = self.write_leaf(
                                    SmolStr::from(&rest_node_key),
                                    node_data_set.clone(),
                                    node_acc,
                                );

                                // 创建BTreeMap存储子节点
                                let mut btree_map: BTreeMap<char, (TrieNodeId, Digest)> =
                                    BTreeMap::new();
                                btree_map.insert(node_idx, (node_leaf_id, node_leaf_hash));

                                if root_id_opt == Some(id) {
                                    // 如果当前节点是根节点，创建根非叶子节点
                                    let non_leaf_root_set = &set | &node_data_set;  // 合并集合
                                    let sets_inter = (&set) & (&node_data_set);  // 计算交集
                                    let non_leaf_root_acc =
                                        new_acc + node_acc - AccValue::from_set(&sets_inter, pk);

                                    let new_root = TrieNonLeafRootNode::new(
                                        SmolStr::from(&common_key),  // 公共前缀
                                        non_leaf_root_set,           // 合并后的集合
                                        non_leaf_root_acc,           // 新的累加器
                                        btree_map,                  // 子节点映射
                                    );
                                    temp_nodes.push(TempNode::NonLeafRoot(Box::new(NonLeafRoot {
                                        node: new_root,
                                        idx: cur_idx,  // 新键的差异字符
                                    })));
                                } else {
                                    // 如果不是根节点，创建普通非叶子节点
                                    let non_leaf =
                                        TrieNonLeafNode::new(SmolStr::from(&common_key), btree_map);
                                    temp_nodes.push(TempNode::NonLeaf(Box::new(NonLeaf {
                                        node: non_leaf,
                                        idx: cur_idx,  // 新键的差异字符
                                    })));
                                }

                                // 为新键创建叶子节点
                                let (leaf_id, leaf_hash) =
                                    self.write_leaf(SmolStr::from(&rest_cur_key), set, new_acc);
                                temp_nodes.push(TempNode::Leaf(Box::new(Leaf {
                                    id: leaf_id,
                                    hash: leaf_hash,
                                })));
                            }
                            break;  // 叶子节点处理完毕，退出循环
                        }
                        TrieNode::NonLeaf(n) => {
                            // 处理非叶子节点情况
                            let (common_key, cur_idx, rest_cur_key, node_idx, rest_node_key) =
                                split_at_common_prefix2(&cur_key, &n.nibble);

                            if common_key == n.nibble {
                                // 情况1：当前键完全匹配节点前缀
                                match n.children.get(&cur_idx) {
                                    Some((id, _digest)) => {
                                        // 存在对应路径，继续向下遍历
                                        temp_nodes.push(TempNode::NonLeaf(Box::new(NonLeaf {
                                            node: TrieNonLeafNode::new(
                                                SmolStr::from(&common_key),
                                                n.children.clone(),  // 复制子节点映射
                                            ),
                                            idx: cur_idx,  // 当前字符索引
                                        })));
                                        cur_id_opt = Some(*id);  // 继续处理子节点
                                        cur_key = SmolStr::from(&rest_cur_key);  // 更新剩余键
                                    }
                                    None => {
                                        // 没有对应路径，创建新叶子节点
                                        let non_leaf = TrieNonLeafNode::new(
                                            SmolStr::from(&common_key),
                                            n.children.clone(),  // 保留原有子节点
                                        );
                                        // 创建新叶子节点
                                        let (new_leaf_id, new_leaf_hash) = self.write_leaf(
                                            SmolStr::from(&rest_cur_key),
                                            set,
                                            new_acc,
                                        );
                                        // 保存非叶子节点信息
                                        temp_nodes.push(TempNode::NonLeaf(Box::new(NonLeaf {
                                            node: non_leaf,
                                            idx: cur_idx,  // 新字符索引
                                        })));
                                        // 保存新叶子节点信息
                                        temp_nodes.push(TempNode::Leaf(Box::new(Leaf {
                                            id: new_leaf_id,
                                            hash: new_leaf_hash,
                                        })));
                                        break;  // 处理完毕，退出循环
                                    }
                                }
                            } else {
                                // 情况2：当前键与节点前缀不完全匹配，需要创建新的分支节点
                                let mut btree_map: BTreeMap<char, (TrieNodeId, Digest)> =
                                    BTreeMap::new();

                                // 为原节点创建新的非叶子节点（使用剩余前缀）
                                let child_non_leaf = TrieNonLeafNode::new(
                                    SmolStr::from(&rest_node_key),
                                    n.children.clone(),  // 保留原有子节点
                                );
                                let (child_non_leaf_id, child_non_leaf_hash) =
                                    self.write_non_leaf(child_non_leaf);
                                // 将原节点添加到映射中
                                btree_map.insert(node_idx, (child_non_leaf_id, child_non_leaf_hash));

                                // 为新键创建叶子节点
                                let (new_leaf_id, new_leaf_hash) =
                                    self.write_leaf(SmolStr::from(&rest_cur_key), set, new_acc);

                                // 创建新的非叶子节点（公共前缀）
                                let non_leaf =
                                    TrieNonLeafNode::new(SmolStr::from(&common_key), btree_map);

                                // 保存新非叶子节点信息
                                temp_nodes.push(TempNode::NonLeaf(Box::new(NonLeaf {
                                    node: non_leaf,
                                    idx: cur_idx,  // 新键的差异字符
                                })));
                                // 保存新叶子节点信息
                                temp_nodes.push(TempNode::Leaf(Box::new(Leaf {
                                    id: new_leaf_id,
                                    hash: new_leaf_hash,
                                })));
                                break;  // 处理完毕，退出循环
                            }
                        }
                        TrieNode::NonLeafRoot(n) => {
                            // 处理根非叶子节点情况
                            let (common_key, cur_idx, rest_cur_key, node_idx, rest_node_key) =
                                split_at_common_prefix2(&cur_key, &n.nibble);

                            // 更新集合和累加器
                            let non_leaf_root_set = &set | &n.data_set;
                            let sets_inter = (&set) & (&n.data_set);
                            let non_leaf_root_acc =
                                new_acc + n.data_set_acc - AccValue::from_set(&sets_inter, pk);

                            if common_key == n.nibble {
                                // 情况1：当前键完全匹配节点前缀
                                match n.children.get(&cur_idx) {
                                    Some((id, _digest)) => {
                                        // 存在对应路径，继续向下遍历
                                        temp_nodes.push(TempNode::NonLeafRoot(Box::new(
                                            NonLeafRoot {
                                                node: TrieNonLeafRootNode::new(
                                                    SmolStr::from(&common_key),
                                                    non_leaf_root_set,
                                                    non_leaf_root_acc,
                                                    n.children.clone(),
                                                ),
                                                idx: cur_idx,  // 当前字符索引
                                            },
                                        )));
                                        cur_id_opt = Some(*id);  // 继续处理子节点
                                        cur_key = SmolStr::from(&rest_cur_key);  // 更新剩余键
                                    }
                                    None => {
                                        // 没有对应路径，创建新叶子节点
                                        let non_leaf = TrieNonLeafRootNode::new(
                                            SmolStr::from(&common_key),
                                            non_leaf_root_set,
                                            non_leaf_root_acc,
                                            n.children.clone(),
                                        );
                                        // 创建新叶子节点
                                        let (new_leaf_id, new_leaf_hash) = self.write_leaf(
                                            SmolStr::from(&rest_cur_key),
                                            set,
                                            new_acc,
                                        );
                                        // 保存根非叶子节点信息
                                        temp_nodes.push(TempNode::NonLeafRoot(Box::new(
                                            NonLeafRoot {
                                                node: non_leaf,
                                                idx: cur_idx,  // 新字符索引
                                            },
                                        )));
                                        // 保存新叶子节点信息
                                        temp_nodes.push(TempNode::Leaf(Box::new(Leaf {
                                            id: new_leaf_id,
                                            hash: new_leaf_hash,
                                        })));
                                        break;  // 处理完毕，退出循环
                                    }
                                }
                            } else {
                                // 情况2：需要创建新的根节点（键不完全匹配）
                                let mut btree_map: BTreeMap<char, (TrieNodeId, Digest)> =
                                    BTreeMap::new();

                                // 为原节点创建新的非叶子节点（使用剩余前缀）
                                let child_non_leaf = TrieNonLeafNode::new(
                                    SmolStr::from(&rest_node_key),
                                    n.children.clone(),
                                );
                                let (child_non_leaf_id, child_non_leaf_hash) =
                                    self.write_non_leaf(child_non_leaf);
                                // 将原节点添加到映射中
                                btree_map.insert(node_idx, (child_non_leaf_id, child_non_leaf_hash));

                                // 为新键创建叶子节点
                                let (new_leaf_id, new_leaf_hash) =
                                    self.write_leaf(SmolStr::from(&rest_cur_key), set, new_acc);

                                // 创建新的根节点（公共前缀）
                                let new_root = TrieNonLeafRootNode::new(
                                    SmolStr::from(&common_key),
                                    non_leaf_root_set,
                                    non_leaf_root_acc,
                                    btree_map,
                                );
                                // 保存新根节点信息
                                temp_nodes.push(TempNode::NonLeafRoot(Box::new(NonLeafRoot {
                                    node: new_root,
                                    idx: cur_idx,  // 新键的差异字符
                                })));
                                // 保存新叶子节点信息
                                temp_nodes.push(TempNode::Leaf(Box::new(Leaf {
                                    id: new_leaf_id,
                                    hash: new_leaf_hash,
                                })));
                                break;  // 处理完毕，退出循环
                            }
                        }
                    }
                }
                None => {
                    // 树为空，直接创建叶子节点作为根节点
                    let (leaf_id, leaf_hash) = self.write_leaf(cur_key, set, new_acc);
                    temp_nodes.push(TempNode::Leaf(Box::new(Leaf {
                        id: leaf_id,
                        hash: leaf_hash,
                    })));
                    break;  // 处理完毕，退出循环
                }
            }
        }

        // 从下向上重建树结构
        let mut new_root_id = TrieNodeId::next_id();
        let mut new_root_hash = Digest::zero();

        // 逆序遍历临时节点（从叶子节点向根节点）
        for node in temp_nodes.into_iter().rev() {
            match node {
                TempNode::Leaf(n) => {
                    // 叶子节点直接作为当前根节点
                    new_root_id = n.id;
                    new_root_hash = n.hash;
                }
                TempNode::NonLeaf(mut n) => {
                    // 非叶子节点：将当前根节点作为子节点插入
                    n.node.children.insert(n.idx, (new_root_id, new_root_hash));
                    let (id, hash) = self.write_non_leaf(n.node);
                    new_root_id = id;
                    new_root_hash = hash;
                }
                TempNode::NonLeafRoot(mut n) => {
                    // 根非叶子节点：将当前根节点作为子节点插入
                    n.node.children.insert(n.idx, (new_root_id, new_root_hash));
                    let (id, hash) = self.write_non_leaf_root(n.node);
                    new_root_id = id;
                    new_root_hash = hash;
                }
            }
        }

        // 更新树根节点信息
        self.apply.root.trie_root_id = Some(new_root_id);
        self.apply.root.trie_root_hash = new_root_hash;

        // 清理过时的节点
        for id in self.outdated.drain() {
            self.apply.nodes.remove(&id);
        }

        Ok(())
    }

    pub fn delete(&mut self, key: SmolStr, obj_id: ObjId, pk: &AccPublicKey) -> Result<()> {
        // 创建要删除的集合
        let set = Set::from_single_element(obj_id.0);
        // 计算负累加器值（用于从累加器中减去）
        let delta_acc = AccValue::from_set(&set, pk);
        // 从根节点开始遍历
        let mut cur_id_opt = self.apply.root.trie_root_id;
        let mut cur_key = key;

        // 定义临时节点结构，用于存储遍历路径
        struct Leaf {
            id: TrieNodeId,    // 叶子节点ID
            hash: Digest,      // 叶子节点哈希
            is_empty: bool,    // 标记叶子节点是否为空
        }
        struct NonLeaf {
            node: TrieNonLeafNode,  // 非叶子节点
            idx: char,              // 子节点索引字符
        }
        struct NonLeafRoot {
            node: TrieNonLeafRootNode,  // 根非叶子节点
            idx: char,                  // 子节点索引字符
        }

        // 临时节点枚举类型
        enum TempNode {
            Leaf(Box<Leaf>),
            NonLeaf(Box<NonLeaf>),
            NonLeafRoot(Box<NonLeafRoot>),
        }
        let mut temp_nodes: Vec<TempNode> = Vec::new();

        // 主循环：沿着键路径向下查找要删除的节点
        loop {
            match cur_id_opt {
                Some(id) => {
                    // 将当前节点标记为过时
                    self.outdated.insert(id);
                    let cur_node = self.get_node(id)?;

                    match cur_node.as_ref() {
                        TrieNode::Leaf(n) => {
                            // 处理叶子节点情况
                            if cur_key == n.rest {
                                // 找到要删除的叶子节点
                                let set_dif = (&n.data_set) / (&set);  // 计算集合差集
                                let old_acc = n.data_set_acc;
                                let mut is_empty = false;

                                // 检查删除后集合是否为空
                                if set_dif.is_empty() {
                                    is_empty = true;
                                }

                                // 写入更新后的叶子节点
                                let (id, hash) =
                                    self.write_leaf(cur_key, set_dif, old_acc - delta_acc);

                                // 如果节点为空，标记为过时（将被删除）
                                if is_empty {
                                    self.outdated.insert(id);
                                }

                                // 保存叶子节点信息
                                temp_nodes.push(TempNode::Leaf(Box::new(Leaf {
                                    id,
                                    hash,
                                    is_empty,
                                })));
                                break;  // 找到目标节点，退出循环
                            } else {
                                // 键不匹配，返回错误
                                return Err(anyhow!("Key {} not found for trie", cur_key));
                            }
                        }
                        TrieNode::NonLeaf(n) => {
                            // 处理非叶子节点情况
                            // 找到当前键与节点前缀的公共部分
                            let (_common_key, cur_idx, rest_cur_key, _node_idx, _rest_node_key) =
                                split_at_common_prefix2(&cur_key, &n.nibble);

                            match n.children.get(&cur_idx) {
                                Some((id, _hash)) => {
                                    // 存在对应路径，继续向下遍历
                                    let non_leaf =
                                        TrieNonLeafNode::new(n.nibble.clone(), n.children.clone());
                                    // 保存当前非叶子节点信息
                                    temp_nodes.push(TempNode::NonLeaf(Box::new(NonLeaf {
                                        node: non_leaf,
                                        idx: cur_idx,  // 当前字符索引
                                    })));
                                    cur_id_opt = Some(*id);  // 继续处理子节点
                                    cur_key = SmolStr::from(&rest_cur_key);  // 更新剩余键
                                }
                                None => {
                                    // 没有对应路径，返回错误
                                    bail!("Cannot find trie non-leaf node");
                                }
                            }
                        }
                        TrieNode::NonLeafRoot(n) => {
                            // 处理根非叶子节点情况
                            let (_common_key, cur_idx, rest_cur_key, _node_idx, _rest_node_key) =
                                split_at_common_prefix2(&cur_key, &n.nibble);

                            match n.children.get(&cur_idx) {
                                Some((id, _hash)) => {
                                    // 存在对应路径，继续向下遍历
                                    // 更新集合和累加器（减去要删除的部分）
                                    let set_dif = (&n.data_set) / (&set);
                                    let old_acc = n.data_set_acc;

                                    let new_root = TrieNonLeafRootNode::new(
                                        n.nibble.clone(),
                                        set_dif,
                                        old_acc - delta_acc,
                                        n.children.clone(),
                                    );
                                    // 保存当前根非叶子节点信息
                                    temp_nodes.push(TempNode::NonLeafRoot(Box::new(NonLeafRoot {
                                        node: new_root,
                                        idx: cur_idx,  // 当前字符索引
                                    })));
                                    cur_id_opt = Some(*id);  // 继续处理子节点
                                    cur_key = SmolStr::from(&rest_cur_key);  // 更新剩余键
                                }
                                None => {
                                    // 没有对应路径，返回错误
                                    bail!("Cannot find trie non-leaf node");
                                }
                            }
                        }
                    }
                }
                None => {
                    // 树为空，返回错误
                    bail!("Trie root id is None");
                }
            }
        }

        // 从下向上重新平衡树结构
        let mut new_root_id = TrieNodeId::next_id();
        let mut new_root_hash = Digest::zero();
        // 标记当前处理节点是否为空（需要删除）
        let mut empty_flag = false;

        // 逆序遍历临时节点（从叶子节点向根节点）
        for node in temp_nodes.into_iter().rev() {
            match node {
                TempNode::Leaf(n) => {
                    // 叶子节点：更新当前根节点信息
                    new_root_id = n.id;
                    new_root_hash = n.hash;
                    empty_flag = n.is_empty;  // 设置空标志
                }
                TempNode::NonLeaf(mut n) => {
                    // 非叶子节点处理
                    if empty_flag {
                        // 如果子节点为空，从子节点映射中移除
                        n.node.children.remove(&n.idx);
                    } else {
                        // 否则，更新子节点映射
                        n.node.children.insert(n.idx, (new_root_id, new_root_hash));
                    }

                    if n.node.children.len() == 1 {
                        // 情况1：节点只有一个子节点，需要合并
                        empty_flag = false;  // 重置空标志
                        let mut new_str: SmolStr = n.node.nibble;  // 新的前缀

                        // 遍历唯一的子节点（实际上只有一个）
                        for (c, (id, _hash)) in n.node.children {
                            // 标记子节点为过时
                            self.outdated.insert(id);
                            let child_n = self.get_node(id)?;

                            match child_n.as_ref() {
                                TrieNode::Leaf(node) => {
                                    // 子节点是叶子节点：合并前缀
                                    let mut a = new_str.to_string();
                                    let b = node.rest.as_str();
                                    if c != '\0' {
                                        a.push(c);  // 添加字符分隔符
                                    }
                                    a.push_str(b);  // 添加叶子节点的剩余部分
                                    new_str = SmolStr::from(&a);

                                    // 创建合并后的新叶子节点
                                    let new_set = node.data_set.clone();
                                    let new_acc = node.data_set_acc;
                                    let (new_id, new_hash) =
                                        self.write_leaf(new_str.clone(), new_set, new_acc);

                                    // 更新当前根节点信息
                                    new_root_id = new_id;
                                    new_root_hash = new_hash;
                                }
                                TrieNode::NonLeaf(node) => {
                                    // 子节点是非叶子节点：合并前缀
                                    let mut a = new_str.to_string();
                                    let b = node.nibble.as_str();
                                    if c != '\0' {
                                        a.push(c);  // 添加字符分隔符
                                    }
                                    a.push_str(b);  // 添加子节点的前缀
                                    new_str = SmolStr::from(&a);

                                    // 创建合并后的新非叶子节点
                                    let new_non_leaf = TrieNonLeafNode::new(
                                        new_str.clone(),
                                        node.children.clone(),
                                    );
                                    let (new_id, new_hash) = self.write_non_leaf(new_non_leaf);

                                    // 更新当前根节点信息
                                    new_root_id = new_id;
                                    new_root_hash = new_hash;
                                }
                                TrieNode::NonLeafRoot(_) => {
                                    // 不可能的情况：根节点不能是子节点
                                    bail!("impossible, root cannot be child")
                                }
                            }
                        }
                    } else {
                        // 情况2：节点有多个子节点或没有子节点
                        if n.node.children.is_empty() {
                            // 没有子节点，标记为空
                            empty_flag = true;
                        } else {
                            // 有多个子节点，不需要特殊处理
                            empty_flag = false;
                        }

                        // 写入更新后的非叶子节点
                        let (id, hash) = self.write_non_leaf(n.node);

                        // 如果节点为空，标记为过时
                        if empty_flag {
                            self.outdated.insert(id);
                        }

                        // 更新当前根节点信息
                        new_root_id = id;
                        new_root_hash = hash;
                    }
                }
                TempNode::NonLeafRoot(mut n) => {
                    // 根非叶子节点处理（与非叶子节点逻辑类似）
                    if empty_flag {
                        // 如果子节点为空，从子节点映射中移除
                        n.node.children.remove(&n.idx);
                    } else {
                        // 否则，更新子节点映射
                        n.node.children.insert(n.idx, (new_root_id, new_root_hash));
                    }

                    if n.node.children.len() == 1 {
                        // 情况1：节点只有一个子节点，需要合并
                        empty_flag = false;  // 重置空标志
                        let mut new_str: SmolStr = n.node.nibble;  // 新的前缀

                        // 遍历唯一的子节点
                        for (c, (id, _hash)) in n.node.children {
                            // 标记子节点为过时
                            self.outdated.insert(id);
                            let child_n = self.get_node(id)?;

                            match child_n.as_ref() {
                                TrieNode::Leaf(node) => {
                                    // 子节点是叶子节点：合并前缀
                                    let mut a = new_str.to_string();
                                    let b = node.rest.as_str();
                                    if c != '\0' {
                                        a.push(c);  // 添加字符分隔符
                                    }
                                    a.push_str(b);  // 添加叶子节点的剩余部分
                                    new_str = SmolStr::from(&a);

                                    // 创建合并后的新叶子节点
                                    let new_set = node.data_set.clone();
                                    let new_acc = node.data_set_acc;
                                    let (new_id, new_hash) =
                                        self.write_leaf(new_str.clone(), new_set, new_acc);

                                    // 更新当前根节点信息
                                    new_root_id = new_id;
                                    new_root_hash = new_hash;
                                }
                                TrieNode::NonLeaf(node) => {
                                    // 子节点是非叶子节点：合并前缀
                                    let mut a = new_str.to_string();
                                    let b = node.nibble.as_str();
                                    if c != '\0' {
                                        a.push(c);  // 添加字符分隔符
                                    }
                                    a.push_str(b);  // 添加子节点的前缀
                                    new_str = SmolStr::from(&a);

                                    // 创建合并后的新根非叶子节点
                                    let new_root = TrieNonLeafRootNode::new(
                                        new_str.clone(),
                                        n.node.data_set.clone(),  // 保留原集合
                                        n.node.data_set_acc,      // 保留原累加器
                                        node.children.clone(),    // 子节点的子节点
                                    );
                                    let (new_id, new_hash) = self.write_non_leaf_root(new_root);

                                    // 更新当前根节点信息
                                    new_root_id = new_id;
                                    new_root_hash = new_hash;
                                }
                                TrieNode::NonLeafRoot(_) => {
                                    // 不可能的情况：根节点不能是子节点
                                    bail!("impossible, root cannot be child")
                                }
                            }
                        }
                    } else {
                        // 情况2：节点有多个子节点或没有子节点
                        if n.node.children.is_empty() {
                            // 没有子节点，标记为空
                            empty_flag = true;
                        } else {
                            // 有多个子节点，不需要特殊处理
                            empty_flag = false;
                        }

                        // 写入更新后的根非叶子节点
                        let (id, hash) = self.write_non_leaf_root(n.node);

                        // 如果节点为空，标记为过时
                        if empty_flag {
                            self.outdated.insert(id);
                        }

                        // 更新当前根节点信息
                        new_root_id = id;
                        new_root_hash = hash;
                    }
                }
            }
        }

        // 更新树根节点信息
        self.apply.root.trie_root_id = Some(new_root_id);
        self.apply.root.trie_root_hash = new_root_hash;

        // 清理过时的节点
        for id in self.outdated.drain() {
            self.apply.nodes.remove(&id);
        }
        Ok(())
    }
}
