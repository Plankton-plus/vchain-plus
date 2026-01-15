use crate::{
    acc::{AccPublicKey, AccValue, Set},
    chain::{
        bplus_tree::{
            proof::{sub_proof::SubProof, Proof},
            BPlusTreeNode, BPlusTreeNodeId, BPlusTreeNodeLoader,
        },
        range::Range,
        traits::Num,
        MAX_INLINE_BTREE_FANOUT,
    },
    digest::{Digest, Digestible},
};
use anyhow::{bail, Result};
use smallvec::SmallVec;
use std::collections::VecDeque;

/// 在B+树中执行范围查询，并生成验证证明
pub fn range_query<K: Num>(
    node_loader: &impl BPlusTreeNodeLoader<K>,
    root_id: Option<BPlusTreeNodeId>,
    range: Range<K>,
    pk: &AccPublicKey,
) -> Result<(Set, AccValue, Proof<K>)> {
    let bplus_tree_root_id = match root_id {
        Some(id) => id,
        None => bail!("The BPlus tree is empty"),
    };
    let (res, acc, p) = inner_range_query(node_loader, bplus_tree_root_id, range, pk)?;
    Ok((res, acc, Proof::from_subproof(p)))
}

/// 内部范围查询函数，实际执行B+树遍历和证明生成
fn inner_range_query<K: Num>(
    node_loader: &impl BPlusTreeNodeLoader<K>,
    root_id: BPlusTreeNodeId,
    range: Range<K>,
    pk: &AccPublicKey,
) -> Result<(Set, AccValue, SubProof<K>)> {
    // 导入证明相关的类型，用于构建不同类型的证明节点
    use crate::chain::bplus_tree::proof::{
        leaf::BPlusTreeLeaf, non_leaf::BPlusTreeNonLeaf, res_sub_tree::BPlusTreeResSubTree,
    };

    // 初始化结果集和累加器
    let mut query_res = Set::new();
    let mut res_acc_val: AccValue = AccValue::from_set(&query_res, pk);

    // 初始化证明为Hash类型的占位符（使用零哈希）
    let mut query_proof = SubProof::from_hash(range, Digest::zero());

    // 加载根节点
    let root_node = node_loader.load_node(root_id)?;
    let cur_proof = &mut query_proof as *mut _;

    // 使用队列进行广度优先搜索(BFS)
    let mut queue: VecDeque<(BPlusTreeNode<K>, *mut SubProof<K>)> = VecDeque::new();
    queue.push_back((root_node, cur_proof));

    // BFS主循环
    while let Some((cur_node, cur_proof_ptr)) = queue.pop_front() {
        match cur_node {
            // 处理叶子节点
            BPlusTreeNode::Leaf(n) => {
                if range.is_in_range(n.num) {
                    // 叶子节点在查询范围内：将其数据添加到结果集
                    query_res = (&query_res) | (&n.data_set);
                    res_acc_val = res_acc_val + n.data_set_acc;

                    // 创建叶子节点证明，包含键值和累加器
                    unsafe {
                        *cur_proof_ptr =
                            SubProof::from_leaf(BPlusTreeLeaf::new(n.num, n.data_set_acc));
                    }
                } else {
                    // 叶子节点不在查询范围内：创建哈希证明
                    unsafe {
                        *cur_proof_ptr =
                            SubProof::from_hash(Range::new(n.num, n.num), n.to_digest());
                    }
                }
            }
            // 处理非叶子节点（中间节点）
            BPlusTreeNode::NonLeaf(n) => {
                if n.range.is_covered(range) {
                    // 情况1：节点范围完全覆盖查询范围
                    // 整个子树都在查询范围内，无需继续展开
                    query_res = (&query_res) | (&n.data_set);
                    res_acc_val = res_acc_val + n.data_set_acc;

                    // 创建结果子树证明，包含范围、累加器和哈希
                    unsafe {
                        *cur_proof_ptr = SubProof::from_res_sub_tree(BPlusTreeResSubTree::new(
                            n.range,
                            n.data_set_acc,
                            n.to_digest(),
                        ));
                    }
                } else if n.range.has_no_intersection(range) {
                    // 情况2：节点范围与查询范围无交集
                    // 整个子树都不在查询范围内，创建哈希证明
                    unsafe {
                        *cur_proof_ptr = SubProof::from_hash(n.range, n.to_digest());
                    }
                } else if n.range.intersects(range) {
                    // 情况3：节点范围与查询范围部分重叠
                    // 需要继续展开子节点

                    // 创建子节点证明数组，使用SmallVec优化小数组性能
                    let mut cur_proof_children =
                        SmallVec::<[Option<Box<SubProof<K>>>; MAX_INLINE_BTREE_FANOUT]>::new();

                    // 为每个子节点创建哈希证明占位符，并加入队列继续处理
                    for child_id in &n.child_ids {
                        let child_node = node_loader.load_node(*child_id)?;
                        let mut sub_proof = match &child_node {
                            BPlusTreeNode::Leaf(n) => Box::new(SubProof::from_hash(
                                Range::new(n.num, n.num),
                                n.to_digest(),
                            )),
                            BPlusTreeNode::NonLeaf(n) => {
                                Box::new(SubProof::from_hash(n.range, n.to_digest()))
                            }
                        };

                        let sub_proof_ptr = sub_proof.as_mut() as *mut _;
                        cur_proof_children.push(Some(sub_proof));
                        queue.push_back((child_node, sub_proof_ptr));
                    }

                    // 创建非叶子节点证明，包含子节点证明数组
                    unsafe {
                        *cur_proof_ptr = SubProof::from_non_leaf(BPlusTreeNonLeaf::from_hashes(
                            n.range,
                            n.data_set_acc.to_digest(),
                            cur_proof_children,
                        ));
                    }
                } else {
                    // 理论上不会到达这里，因为Range的三种关系已经覆盖所有情况
                    // 保留此分支以防未来扩展
                }
            }
        }
    }

    Ok((query_res, res_acc_val, query_proof))
}