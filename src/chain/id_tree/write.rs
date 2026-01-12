use crate::chain::id_tree::{
    Digest, Digestible, IdTreeInternalId, IdTreeLeafNode, IdTreeNode, IdTreeNodeId,
    IdTreeNodeLoader, IdTreeNonLeafNode, IdTreeRoot, ObjId,
};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Apply {
    pub root: IdTreeRoot,
    pub nodes: HashMap<IdTreeNodeId, IdTreeNode>,
}

pub struct WriteContext<'a, L: IdTreeNodeLoader> {
    node_loader: &'a L,
    apply: Apply,
    outdated: HashSet<IdTreeNodeId>,
}

impl<'a, L: IdTreeNodeLoader> WriteContext<'a, L> {
    pub fn new(node_loader: &'a L, root: IdTreeRoot) -> Self {
        IdTreeNodeId::next_id();
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
        obj_id: IdTreeInternalId,
        obj_hash: Digest,
    ) -> (IdTreeNodeId, Digest) {
        let node = IdTreeLeafNode::new(obj_id, obj_hash);
        let id = node.id;
        let hash = node.to_digest();
        self.apply.nodes.insert(id, IdTreeNode::from_leaf(node));
        (id, hash)
    }

    pub fn write_non_leaf(&mut self, n: IdTreeNonLeafNode) -> (IdTreeNodeId, Digest) {
        let id = n.id;
        let hash = n.to_digest();
        self.apply.nodes.insert(id, IdTreeNode::from_non_leaf(n));
        (id, hash)
    }

    fn get_node(&self, id: IdTreeNodeId) -> Result<Cow<IdTreeNode>> {
        Ok(match self.apply.nodes.get(&id) {
            Some(n) => Cow::Borrowed(n),
            None => Cow::Owned(self.node_loader.load_node(id)?),
        })
    }

    /// 在ID树中插入新的对象，并返回分配给该对象的ID
    ///
    /// # 参数
    /// - `obj_hash`: 要插入的对象的哈希值
    /// - `max_id_num`: 最大对象ID数量，用于环形ID分配
    /// - `fanout`: 树的扇出（每个节点最多子节点数）
    ///
    /// # 返回值
    /// - `Result<ObjId>`: 成功时返回分配给对象的ID，失败时返回错误
    ///
    /// # 算法概述
    /// 1. 计算下一个可用的对象ID
    /// 2. 生成从根到目标叶节点的路径
    /// 3. 沿着路径向下遍历，记录遇到的节点
    /// 4. 创建新的叶节点
    /// 5. 自底向上重建路径上的节点
    /// 6. 更新根节点并清理旧节点
    pub fn insert(&mut self, obj_hash: Digest, max_id_num: u16, fanout: u8) -> Result<ObjId> {
        // ==================== 步骤1: 计算新对象ID ====================

        // 获取当前已分配的最大对象ID
        let cur_id = self.apply.root.cur_obj_id;
        // 转换为内部ID（从0开始）
        let internal_id = cur_id.to_internal_id();

        // 计算下一个内部ID，使用环形分配策略（达到最大值后回到0）
        let next_internal_id = IdTreeInternalId((internal_id.0 + 1) % max_id_num);
        // 更新当前对象ID为下一个可用的ID
        self.apply.root.cur_obj_id = ObjId::from_internal_id(next_internal_id);

        // ==================== 步骤2: 生成路径 ====================

        // 获取当前根节点ID（可能为None表示空树）
        let mut cur_id_opt = self.apply.root.id_tree_root_id;

        // 计算树的深度：log_fanout(max_id_num)
        // 使用对数计算树的最大深度，确保能容纳所有ID
        let depth = (max_id_num as f64).log(fanout as f64).floor() as usize;

        // 生成从根到叶子的反向路径
        // 例如：内部ID=5, fanout=2, depth=3 → 可能得到路径[1, 0, 1]
        let mut cur_path_rev = fanout_nary_rev(internal_id.0, fanout, depth);

        // ==================== 步骤3: 定义临时节点结构 ====================

        // 临时叶节点结构，存储新建的叶节点信息
        struct Leaf {
            id: IdTreeNodeId,    // 叶节点ID
            hash: Digest,        // 叶节点哈希
        }

        // 临时非叶节点结构，存储路径上的非叶节点信息
        struct NonLeaf {
            node: IdTreeNonLeafNode,  // 非叶节点
            idx: usize,               // 子节点在父节点中的索引
        }

        // 临时节点枚举，可以是叶节点或非叶节点
        enum TempNode {
            Leaf(Box<Leaf>),      // 叶节点（使用Box避免递归大小问题）
            NonLeaf(Box<NonLeaf>), // 非叶节点
        }

        // 存储遍历路径时遇到的所有节点（从根到叶子）
        let mut temp_nodes: Vec<TempNode> = Vec::new();

        // ==================== 步骤4: 向下遍历找到插入位置 ====================

        // 循环遍历树，直到找到插入位置
        loop {
            match cur_id_opt {
                // 当前节点存在
                Some(id) => {
                    // 将当前节点标记为过时（将被新节点替换）
                    self.outdated.insert(id);

                    // 加载当前节点
                    let cur_node = self.get_node(id)?;

                    match cur_node.as_ref() {
                        // 当前节点是叶节点：找到插入位置
                        IdTreeNode::Leaf(_n) => {
                            // 写入新的叶节点
                            let (leaf_id, leaf_hash) = self.write_leaf(internal_id, obj_hash);

                            // 将新叶节点添加到临时节点列表
                            temp_nodes.push(TempNode::Leaf(Box::new(Leaf {
                                id: leaf_id,
                                hash: leaf_hash,
                            })));

                            // 跳出循环，已经到达叶子层
                            break;
                        }

                        // 当前节点是非叶节点：继续向下遍历
                        IdTreeNode::NonLeaf(n) => {
                            // 从路径中弹出下一个子节点索引
                            let idx = cur_path_rev
                                .pop()
                                .ok_or_else(|| anyhow!("Path is empty!"))?;

                            // 保存当前非叶节点的副本（稍后修改）
                            temp_nodes.push(TempNode::NonLeaf(Box::new(NonLeaf {
                                node: IdTreeNonLeafNode::new(
                                    n.child_hashes.clone(),  // 复制子节点哈希列表
                                    n.child_ids.clone(),     // 复制子节点ID列表
                                ),
                                idx,  // 需要更新的子节点索引
                            })));

                            // 获取下一个要访问的子节点ID
                            cur_id_opt = n.get_child_id(idx).cloned();
                        }
                    }
                }

                // 当前节点不存在：需要创建新节点
                None => {
                    // 循环创建路径上缺失的节点
                    loop {
                        if cur_path_rev.is_empty() {
                            // 路径已空，到达叶子位置
                            let (leaf_id, leaf_hash) = self.write_leaf(internal_id, obj_hash);

                            temp_nodes.push(TempNode::Leaf(Box::new(Leaf {
                                id: leaf_id,
                                hash: leaf_hash,
                            })));

                            break;
                        } else {
                            // 还需要创建非叶节点
                            let idx = cur_path_rev
                                .pop()
                                .ok_or_else(|| anyhow!("Path is empty!"))?;

                            // 创建空的非叶节点
                            let non_leaf = IdTreeNonLeafNode::new_ept();

                            temp_nodes.push(TempNode::NonLeaf(Box::new(NonLeaf {
                                node: non_leaf,
                                idx,
                            })));
                        }
                    }
                    break;
                }
            }
        }

        // ==================== 步骤5: 自底向上重建节点 ====================

        // 初始化新根节点的ID和哈希
        let mut new_root_id = IdTreeNodeId::next_id();
        let mut new_root_hash = Digest::zero();

        // 反向遍历临时节点（从叶子到根）
        for node in temp_nodes.into_iter().rev() {
            match node {
                // 叶节点：直接使用其ID和哈希
                TempNode::Leaf(n) => {
                    new_root_id = n.id;
                    new_root_hash = n.hash;
                }

                // 非叶节点：更新子节点引用并写入新节点
                TempNode::NonLeaf(mut n) => {
                    // 更新子节点ID引用
                    let updated_id = n.node.get_child_id_mut(n.idx);
                    match updated_id {
                        // 如果位置已有子节点，替换它
                        Some(id) => *id = new_root_id,
                        // 如果位置为空，添加新子节点
                        None => n.node.push_child_id(new_root_id),
                    }

                    // 更新子节点哈希引用
                    let updated_hash = n.node.get_child_hash_mut(n.idx);
                    match updated_hash {
                        // 如果位置已有哈希，替换它
                        Some(hash) => *hash = new_root_hash,
                        // 如果位置为空，添加新哈希
                        None => n.node.push_child_hash(new_root_hash),
                    }

                    // 写入更新后的非叶节点，获取新节点的ID和哈希
                    let (id, hash) = self.write_non_leaf(n.node);

                    // 更新当前节点为新创建的非叶节点
                    new_root_id = id;
                    new_root_hash = hash;
                }
            }
        }

        // ==================== 步骤6: 更新根节点 ====================

        // 设置新的根节点ID和哈希
        self.apply.root.id_tree_root_id = Some(new_root_id);
        self.apply.root.id_tree_root_hash = new_root_hash;

        // ==================== 步骤7: 清理旧节点 ====================

        // 从apply节点映射中移除所有过时的节点
        for id in self.outdated.drain() {
            self.apply.nodes.remove(&id);
        }

        // 返回分配给新对象的ID
        Ok(cur_id)
    }
}


/// 将给定的数字转换为指定进制的数位序列，并返回逆序的结果
///
/// # 参数
/// * `obj_id`: 要转换的数字 (u16 类型)
/// * `fanout`: 进制基数 (u8 类型)
/// * `depth`: 结果数组的最大深度/长度
///
/// # 返回值
/// 返回一个包含余数的向量，表示按 fanout 进制分解后的逆序结果
pub fn fanout_nary_rev(obj_id: u16, fanout: u8, depth: usize) -> Vec<usize> {
    // 创建一个长度为 depth 的向量，用 0 填充，用于存储每一位的余数
    let mut path: Vec<usize> = vec![0; depth];
    // 复制输入的数字，将在循环中逐步除以 fanout
    let mut num = obj_id;
    // 记录当前已计算的位置索引
    let mut idx_size = 0;
    // 循环直到达到指定的深度
    while idx_size < depth {
        // 计算当前数字对 fanout 取模的结果，即当前位的数值
        path[idx_size] = (num % fanout as u16) as usize;
        // 更新 num 为除以 fanout 后的商，继续处理下一位
        num /= fanout as u16;
        // 增加位置计数器
        idx_size += 1;
    }
    // 返回包含各位数字的向量（低位在前，高位在后）
    path
}


#[cfg(test)]
mod tests {
    #[test]
    fn test_fanout_nary() {
        use super::fanout_nary_rev;

        let expect_ten: Vec<usize> = vec![3, 0, 7, 9, 1];
        let v_ten: Vec<usize> = fanout_nary_rev(19703, 10, 5);
        assert_eq!(v_ten, expect_ten);

        let expect_two: Vec<usize> = vec![1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let v_two: Vec<usize> = fanout_nary_rev(1025, 2, 11);
        assert_eq!(v_two, expect_two);

        let expect_two_2: Vec<usize> = vec![1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0];
        let v_two_2: Vec<usize> = fanout_nary_rev(1025, 2, 12);
        assert_eq!(v_two_2, expect_two_2);
    }
}
