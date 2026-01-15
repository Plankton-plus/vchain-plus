use super::{query_plan::QueryPlan, TimeWin};
use crate::{
    acc::AccPublicKey,
    chain::{
        block::Height,
        bplus_tree,
        query::{
            query_param::{AndNode, Node, NotNode, OrNode},
            query_plan::{
                QPBlkRtNode, QPDiff, QPIntersec, QPKeywordNode, QPNode, QPRangeNode, QPUnion,
            },
            QueryContent,
        },
        range::Range,
        traits::{Num, ReadInterface},
        trie_tree,
    },
};
use anyhow::{bail, Context, Result};
use petgraph::{algo::toposort, graph::NodeIndex, EdgeDirection::Outgoing, Graph};
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use std::collections::{HashMap, VecDeque};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DagNode<K: Num> {
    Range(RangeNode<K>),
    Keyword(Box<KeywordNode>),
    BlkRt(Box<BlkRtNode>),
    Union(UnionNode),
    Intersec(IntersecNode),
    Diff(DiffNode),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RangeNode<K: Num> {
    pub(crate) range: Range<K>,
    pub(crate) dim: u8,
}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct KeywordNode {
    pub(crate) keyword: String,
}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct BlkRtNode {}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct UnionNode {}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct IntersecNode {}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct DiffNode {}

// return the root idx of added keyword expression
fn query_dag_add_keyword_exp<K: Num>(
    keyword_exp: &Node,
    dag: &mut Graph<DagNode<K>, bool>,
) -> Result<NodeIndex> {
    let mut queue = VecDeque::<(&Node, NodeIndex)>::new();
    let mut idx_map = HashMap::<String, NodeIndex>::new();
    let keyword_root_idx: NodeIndex;
    match keyword_exp {
        Node::And(n) => {
            let idx = dag.add_node(DagNode::Intersec(IntersecNode {}));
            keyword_root_idx = idx;
            let AndNode(c1, c2) = n.as_ref();
            let idx1: NodeIndex;
            let idx2: NodeIndex;
            match c1 {
                Node::And(_) => {
                    idx1 = dag.add_node(DagNode::Intersec(IntersecNode {}));
                }
                Node::Or(_) => {
                    idx1 = dag.add_node(DagNode::Union(UnionNode {}));
                }
                Node::Not(_) => {
                    idx1 = dag.add_node(DagNode::Diff(DiffNode {}));
                }
                Node::Input(s) => {
                    idx1 = dag.add_node(DagNode::Keyword(Box::new(KeywordNode {
                        keyword: s.to_string(),
                    })));
                    idx_map.insert(s.to_string(), idx1);
                }
            }
            dag.add_edge(idx, idx1, true);
            match c2 {
                Node::And(_) => {
                    idx2 = dag.add_node(DagNode::Intersec(IntersecNode {}));
                }
                Node::Or(_) => {
                    idx2 = dag.add_node(DagNode::Union(UnionNode {}));
                }
                Node::Not(_) => {
                    idx2 = dag.add_node(DagNode::Diff(DiffNode {}));
                }
                Node::Input(s) => {
                    idx2 = dag.add_node(DagNode::Keyword(Box::new(KeywordNode {
                        keyword: s.to_string(),
                    })));
                    idx_map.insert(s.to_string(), idx2);
                }
            }
            dag.add_edge(idx, idx2, false);
            queue.push_back((c1, idx1));
            queue.push_back((c2, idx2));
        }
        Node::Or(n) => {
            let idx = dag.add_node(DagNode::Union(UnionNode {}));
            keyword_root_idx = idx;
            let OrNode(c1, c2) = n.as_ref();
            let idx1: NodeIndex;
            let idx2: NodeIndex;
            match c1 {
                Node::And(_) => {
                    idx1 = dag.add_node(DagNode::Intersec(IntersecNode {}));
                }
                Node::Or(_) => {
                    idx1 = dag.add_node(DagNode::Union(UnionNode {}));
                }
                Node::Not(_) => {
                    idx1 = dag.add_node(DagNode::Diff(DiffNode {}));
                }
                Node::Input(s) => {
                    idx1 = dag.add_node(DagNode::Keyword(Box::new(KeywordNode {
                        keyword: s.to_string(),
                    })));
                    idx_map.insert(s.to_string(), idx1);
                }
            }
            dag.add_edge(idx, idx1, true);
            match c2 {
                Node::And(_) => {
                    idx2 = dag.add_node(DagNode::Intersec(IntersecNode {}));
                }
                Node::Or(_) => {
                    idx2 = dag.add_node(DagNode::Union(UnionNode {}));
                }
                Node::Not(_) => {
                    idx2 = dag.add_node(DagNode::Diff(DiffNode {}));
                }
                Node::Input(s) => {
                    idx2 = dag.add_node(DagNode::Keyword(Box::new(KeywordNode {
                        keyword: s.to_string(),
                    })));
                    idx_map.insert(s.to_string(), idx2);
                }
            }
            dag.add_edge(idx, idx2, false);
            queue.push_back((c1, idx1));
            queue.push_back((c2, idx2));
        }
        Node::Not(n) => {
            let idx = dag.add_node(DagNode::Diff(DiffNode {}));
            keyword_root_idx = idx;
            let NotNode(c) = n.as_ref();
            let c_idx: NodeIndex;
            match c {
                Node::And(_) => {
                    c_idx = dag.add_node(DagNode::Intersec(IntersecNode {}));
                }
                Node::Or(_) => {
                    c_idx = dag.add_node(DagNode::Union(UnionNode {}));
                }
                Node::Not(_) => {
                    c_idx = dag.add_node(DagNode::Diff(DiffNode {}));
                }
                Node::Input(s) => {
                    c_idx = dag.add_node(DagNode::Keyword(Box::new(KeywordNode {
                        keyword: s.to_string(),
                    })));
                    idx_map.insert(s.to_string(), c_idx);
                }
            }
            dag.add_edge(idx, c_idx, true);
            let blk_rt_idx = dag.add_node(DagNode::BlkRt(Box::new(BlkRtNode {})));
            dag.add_edge(idx, blk_rt_idx, false);
            queue.push_back((c, c_idx));
        }
        Node::Input(s) => {
            let idx = dag.add_node(DagNode::Keyword(Box::new(KeywordNode {
                keyword: s.to_string(),
            })));
            keyword_root_idx = idx;
        }
    }

    while let Some((node, idx)) = queue.pop_front() {
        match node {
            Node::And(n) => {
                let AndNode(c1, c2) = n.as_ref();
                let idx1: NodeIndex;
                let idx2: NodeIndex;
                match c1 {
                    Node::And(_) => {
                        idx1 = dag.add_node(DagNode::Intersec(IntersecNode {}));
                    }
                    Node::Or(_) => {
                        idx1 = dag.add_node(DagNode::Union(UnionNode {}));
                    }
                    Node::Not(_) => {
                        idx1 = dag.add_node(DagNode::Diff(DiffNode {}));
                    }
                    Node::Input(s) => {
                        if let Some(c_idx) = idx_map.get(s) {
                            idx1 = *c_idx;
                        } else {
                            idx1 = dag.add_node(DagNode::Keyword(Box::new(KeywordNode {
                                keyword: s.to_string(),
                            })));
                            idx_map.insert(s.to_string(), idx1);
                        }
                    }
                }
                dag.add_edge(idx, idx1, true);
                match c2 {
                    Node::And(_) => {
                        idx2 = dag.add_node(DagNode::Intersec(IntersecNode {}));
                    }
                    Node::Or(_) => {
                        idx2 = dag.add_node(DagNode::Union(UnionNode {}));
                    }
                    Node::Not(_) => {
                        idx2 = dag.add_node(DagNode::Diff(DiffNode {}));
                    }
                    Node::Input(s) => {
                        if let Some(c_idx) = idx_map.get(s) {
                            idx2 = *c_idx;
                        } else {
                            idx2 = dag.add_node(DagNode::Keyword(Box::new(KeywordNode {
                                keyword: s.to_string(),
                            })));
                            idx_map.insert(s.to_string(), idx2);
                        }
                    }
                }
                dag.add_edge(idx, idx2, false);
                queue.push_back((c1, idx1));
                queue.push_back((c2, idx2));
            }
            Node::Or(n) => {
                let OrNode(c1, c2) = n.as_ref();
                let idx1: NodeIndex;
                let idx2: NodeIndex;
                match c1 {
                    Node::And(_) => {
                        idx1 = dag.add_node(DagNode::Intersec(IntersecNode {}));
                    }
                    Node::Or(_) => {
                        idx1 = dag.add_node(DagNode::Union(UnionNode {}));
                    }
                    Node::Not(_) => {
                        idx1 = dag.add_node(DagNode::Diff(DiffNode {}));
                    }
                    Node::Input(s) => {
                        if let Some(c_idx) = idx_map.get(s) {
                            idx1 = *c_idx;
                        } else {
                            idx1 = dag.add_node(DagNode::Keyword(Box::new(KeywordNode {
                                keyword: s.to_string(),
                            })));
                            idx_map.insert(s.to_string(), idx1);
                        }
                    }
                }
                dag.add_edge(idx, idx1, true);
                match c2 {
                    Node::And(_) => {
                        idx2 = dag.add_node(DagNode::Intersec(IntersecNode {}));
                    }
                    Node::Or(_) => {
                        idx2 = dag.add_node(DagNode::Union(UnionNode {}));
                    }
                    Node::Not(_) => {
                        idx2 = dag.add_node(DagNode::Diff(DiffNode {}));
                    }
                    Node::Input(s) => {
                        if let Some(c_idx) = idx_map.get(s) {
                            idx2 = *c_idx;
                        } else {
                            idx2 = dag.add_node(DagNode::Keyword(Box::new(KeywordNode {
                                keyword: s.to_string(),
                            })));
                            idx_map.insert(s.to_string(), idx2);
                        }
                    }
                }
                dag.add_edge(idx, idx2, false);
                queue.push_back((c1, idx1));
                queue.push_back((c2, idx2));
            }
            Node::Not(n) => {
                let NotNode(c) = n.as_ref();
                let c_idx: NodeIndex;
                let blk_rt_idx = dag.add_node(DagNode::BlkRt(Box::new(BlkRtNode {})));
                match c {
                    Node::And(_) => {
                        c_idx = dag.add_node(DagNode::Intersec(IntersecNode {}));
                    }
                    Node::Or(_) => {
                        c_idx = dag.add_node(DagNode::Union(UnionNode {}));
                    }
                    Node::Not(_) => {
                        c_idx = dag.add_node(DagNode::Diff(DiffNode {}));
                    }
                    Node::Input(s) => {
                        if let Some(ch_idx) = idx_map.get(s) {
                            c_idx = *ch_idx;
                        } else {
                            c_idx = dag.add_node(DagNode::Keyword(Box::new(KeywordNode {
                                keyword: s.to_string(),
                            })));
                            idx_map.insert(s.to_string(), c_idx);
                        }
                    }
                }
                dag.add_edge(idx, c_idx, true);
                dag.add_edge(idx, blk_rt_idx, false);
                queue.push_back((c, c_idx));
            }
            Node::Input(_) => {}
        }
    }
    Ok(keyword_root_idx)
}

/// 生成并行查询DAG（有向无环图）
///
/// 该函数根据查询内容构建一个表示查询计划的DAG，支持关键词查询和范围查询的组合
///
/// # 参数
/// * `query_content` - 查询内容结构体，包含关键词表达式和范围条件
///
/// # 返回值
/// * `Result<Graph<DagNode<K>, bool>>` - 成功时返回构建好的DAG图，失败时返回错误
pub fn gen_parallel_query_dag<K: Num>(
    query_content: &QueryContent<K>,
) -> Result<Graph<DagNode<K>, bool>> {
    // 获取关键词表达式的可选引用
    let keyword_exp_opt = query_content.keyword_exp.as_ref();
    // 初始化空的DAG图，节点类型为DagNode<K>，边权重为bool
    let mut query_dag = Graph::<DagNode<K>, bool>::new();
    // 初始化关键词子图的根节点索引
    let mut keyword_root_idx: NodeIndex = NodeIndex::default();
    // 初始化范围查询子图的根节点索引
    let mut range_root_idx: NodeIndex = NodeIndex::default();
    // 声明布尔变量标记是否存在关键词查询
    let has_keyword_query: bool;
    // 声明布尔变量标记是否存在范围查询
    let has_range_query: bool;

    // 检查是否有关键词表达式
    if let Some(keyword_exp) = keyword_exp_opt.as_ref() {
        // 如果存在关键词表达式，设置标记为true
        has_keyword_query = true;
        // 调用辅助函数添加关键词表达式到DAG中，并返回其根节点索引
        keyword_root_idx = query_dag_add_keyword_exp(keyword_exp, &mut query_dag)?;
    } else {
        // 如果不存在关键词表达式，设置标记为false
        has_keyword_query = false;
    }

    // 检查是否存在范围查询条件
    if !query_content.range.is_empty() {
        // 设置范围查询标记为true
        has_range_query = true;
        // 使用锁标记，用于控制多个范围查询之间的连接逻辑
        let mut range_lock = false;
        // 遍历所有的范围查询条件，带索引
        for (i, r) in query_content.range.iter().enumerate() {
            // 添加范围节点到DAG中，包括具体的范围值和维度编号
            let range_idx = query_dag.add_node(DagNode::Range(RangeNode {
                range: *r,
                dim: i as u8,
            }));
            // 如果已锁定（即已有第一个范围节点），则需要将当前节点与之前的节点进行交集操作
            if range_lock {
                // 添加交集节点用于连接两个范围查询
                let intersec_idx = query_dag.add_node(DagNode::Intersec(IntersecNode {}));
                // 添加边：交集节点 -> 第一个范围节点（true表示左侧）
                query_dag.add_edge(intersec_idx, range_root_idx, true);
                // 添加边：交集节点 -> 当前范围节点（false表示右侧）
                query_dag.add_edge(intersec_idx, range_idx, false);
                // 更新范围根节点为交集节点
                range_root_idx = intersec_idx;
                // 继续下一个循环迭代
                continue;
            }
            // 如果未锁定，将当前范围节点设为范围根节点
            range_root_idx = range_idx;
            // 锁定范围处理状态
            range_lock = true;
        }
    } else {
        // 如果没有范围查询，设置标记为false
        has_range_query = false;
    }

    // 声明最终的根节点索引
    let root_idx;
    // 如果同时存在关键词查询和范围查询，则需要将两者的结果进行交集操作
    if has_keyword_query && has_range_query {
        // 添加交集节点作为整个查询的根节点
        root_idx = query_dag.add_node(DagNode::Intersec(IntersecNode {}));
        // 添加边：根节点 -> 范围查询根节点（true表示左侧）
        query_dag.add_edge(root_idx, range_root_idx, true);
        // 添加边：根节点 -> 关键词查询根节点（false表示右侧）
        query_dag.add_edge(root_idx, keyword_root_idx, false);
    }

    // 返回构建完成的查询DAG
    Ok(query_dag)
}


#[allow(clippy::type_complexity)]
pub fn gen_last_query_dag_with_cont_basic<K: Num, T: ReadInterface<K = K>>(
    time_win: &TimeWin,
    s_win_size: Option<u16>,
    e_win_size: u16,
    mut query_dag: Graph<DagNode<K>, bool>,
    chain: &T,
    pk: &AccPublicKey,
) -> Result<(Graph<DagNode<K>, bool>, QueryPlan<K>)> {
    let end_blk_height = Height(time_win.end_blk);
    let mut dag_content = HashMap::<NodeIndex, QPNode<K>>::new();
    let mut trie_ctxes = HashMap::<Height, trie_tree::read::ReadContext<T>>::new();

    // process end sub_dag
    let mut end_q_inputs = match toposort(&query_dag, None) {
        Ok(v) => v,
        Err(_) => {
            bail!("Input query graph not valid")
        }
    };
    end_q_inputs.reverse();
    let end_sub_root_idx = end_q_inputs.last().context("empty dag")?;
    let mut root_idx = *end_sub_root_idx;

    for idx in &end_q_inputs {
        if let Some(dag_node) = query_dag.node_weight(*idx) {
            match dag_node {
                DagNode::Range(node) => {
                    let bplus_root = chain
                        .read_block_content(end_blk_height)?
                        .ads
                        .read_bplus_root(e_win_size, node.dim)?;
                    let (s, a, p) = bplus_tree::read::range_query(
                        chain,
                        bplus_root.bplus_tree_root_id,
                        node.range,
                        pk,
                    )?;
                    let qp_range_node = QPRangeNode {
                        blk_height: end_blk_height,
                        set: Some((s, a, p)),
                    };
                    dag_content.insert(*idx, QPNode::Range(Box::new(qp_range_node)));
                }
                DagNode::Keyword(node) => {
                    let set;
                    let acc;
                    if let Some(ctx) = trie_ctxes.get_mut(&end_blk_height) {
                        let (s, a) = ctx.query(&SmolStr::from(&node.keyword), pk)?;
                        set = s;
                        acc = a;
                    } else {
                        let trie_root = chain
                            .read_block_content(end_blk_height)?
                            .ads
                            .read_trie_root(e_win_size)?;
                        let mut trie_ctx =
                            trie_tree::read::ReadContext::new(chain, trie_root.trie_root_id);
                        let (s, a) = trie_ctx.query(&SmolStr::from(&node.keyword), pk)?;
                        set = s;
                        acc = a;
                        trie_ctxes.insert(end_blk_height, trie_ctx);
                    }
                    let qp_keyword_node = QPKeywordNode {
                        blk_height: end_blk_height,
                        set: Some((set, acc)),
                    };
                    dag_content.insert(*idx, QPNode::Keyword(Box::new(qp_keyword_node)));
                }
                DagNode::BlkRt(_) => {
                    let blk_content = chain.read_block_content(end_blk_height)?;
                    let bplus_root = blk_content.ads.read_bplus_root(e_win_size, 0)?;
                    let bplus_root_id =
                        bplus_root.bplus_tree_root_id.context("Empty bplus root")?;
                    let bplus_root_node =
                        bplus_tree::BPlusTreeNodeLoader::load_node(chain, bplus_root_id)?;
                    let set = bplus_root_node.get_set().clone();
                    let acc = bplus_root_node.get_node_acc();
                    let qp_rt_node = QPBlkRtNode {
                        blk_height: end_blk_height,
                        set: Some((set, acc)),
                    };
                    dag_content.insert(*idx, QPNode::BlkRt(Box::new(qp_rt_node)));
                }
                DagNode::Union(_) => {
                    let mut child_idxs = Vec::<NodeIndex>::new();
                    for c_idx in query_dag.neighbors_directed(*idx, Outgoing) {
                        child_idxs.push(c_idx);
                    }
                    let qp_c_idx1 = child_idxs
                        .get(0)
                        .context("Cannot find the first qp child idx of union")?;
                    let qp_c1 = dag_content
                        .get(qp_c_idx1)
                        .context("Cannot find the first child vo node in vo_dag_content")?;
                    let c1_set = qp_c1.get_set()?;
                    let qp_c_idx2 = child_idxs
                        .get(1)
                        .context("Cannot find the second qp child idx of union")?;
                    let qp_c2 = dag_content
                        .get(qp_c_idx2)
                        .context("Cannot find the second child vo node in vo_dag_content")?;
                    let c2_set = qp_c2.get_set()?;
                    let c_union = c1_set | c2_set;
                    let qp_union_node = QPUnion { set: Some(c_union) };
                    dag_content.insert(*idx, QPNode::Union(qp_union_node));
                }
                DagNode::Intersec(_) => {
                    let mut child_idxs = Vec::<NodeIndex>::new();
                    for c_idx in query_dag.neighbors_directed(*idx, Outgoing) {
                        child_idxs.push(c_idx);
                    }
                    let qp_c_idx1 = child_idxs
                        .get(0)
                        .context("Cannot find the first qp child idx of union")?;
                    let qp_c1 = dag_content
                        .get(qp_c_idx1)
                        .context("Cannot find the first child vo node in vo_dag_content")?;
                    let c1_set = qp_c1.get_set()?;
                    let qp_c_idx2 = child_idxs
                        .get(1)
                        .context("Cannot find the second qp child idx of union")?;
                    let qp_c2 = dag_content
                        .get(qp_c_idx2)
                        .context("Cannot find the second child vo node in vo_dag_content")?;
                    let c2_set = qp_c2.get_set()?;
                    let c_intersec = c1_set & c2_set;
                    let qp_intersec_node = QPIntersec {
                        set: Some(c_intersec),
                    };
                    dag_content.insert(*idx, QPNode::Intersec(qp_intersec_node));
                }
                DagNode::Diff(_) => {
                    let mut child_idxs = Vec::<NodeIndex>::new();
                    for c_idx in query_dag.neighbors_directed(*idx, Outgoing) {
                        child_idxs.push(c_idx);
                    }
                    let mut qp_c_idx1 = child_idxs
                        .get(1)
                        .context("Cannot find the first qp child idx of difference")?;
                    let qp_c_idx2;
                    let edge_idx = query_dag
                        .find_edge(*idx, *qp_c_idx1)
                        .context("Cannot find edge")?;
                    let weight = query_dag
                        .edge_weight(edge_idx)
                        .context("Cannot find edge")?;
                    if !*weight {
                        qp_c_idx2 = child_idxs
                            .get(0)
                            .context("Cannot find the first qp child idx of difference")?;
                    } else {
                        qp_c_idx1 = child_idxs
                            .get(0)
                            .context("Cannot find the first qp child idx of difference")?;
                        qp_c_idx2 = child_idxs
                            .get(1)
                            .context("Cannot find the first qp child idx of difference")?;
                    }
                    let qp_c1 = dag_content
                        .get(qp_c_idx1)
                        .context("Cannot find the first child vo node in vo_dag_content")?;
                    let c1_set = qp_c1.get_set()?;
                    let qp_c2 = dag_content
                        .get(qp_c_idx2)
                        .context("Cannot find the second child vo node in vo_dag_content")?;
                    let c2_set = qp_c2.get_set()?;
                    let c_diff = c1_set / c2_set;
                    let qp_diff_node = QPDiff { set: Some(c_diff) };
                    dag_content.insert(*idx, QPNode::Diff(qp_diff_node));
                }
            }
        }
    }

    // process start sub_dag
    if s_win_size.is_some() && time_win.start_blk > 1 {
        let start_blk_height = Height(time_win.start_blk - 1);
        let blk_content = chain.read_block_content(start_blk_height)?;
        let bplus_root = blk_content.ads.read_bplus_root(e_win_size, 0)?;
        let bplus_root_id = bplus_root.bplus_tree_root_id.context("Empty bplus root")?;
        let bplus_root_node = bplus_tree::BPlusTreeNodeLoader::load_node(chain, bplus_root_id)?;
        let set = bplus_root_node.get_set().clone();
        let acc = bplus_root_node.get_node_acc();
        let qp_rt_node = QPBlkRtNode {
            blk_height: start_blk_height,
            set: Some((set, acc)),
        };
        let start_sub_root_idx = query_dag.add_node(DagNode::BlkRt(Box::new(BlkRtNode {})));
        dag_content.insert(start_sub_root_idx, QPNode::BlkRt(Box::new(qp_rt_node)));

        let diff_idx = query_dag.add_node(DagNode::Diff(DiffNode {}));
        query_dag.add_edge(diff_idx, start_sub_root_idx, true);
        query_dag.add_edge(diff_idx, *end_sub_root_idx, false);
        dag_content.insert(diff_idx, QPNode::Diff(QPDiff { set: None }));
        root_idx = diff_idx;
    }

    let mut trie_proofs = HashMap::new();
    for (h, trie_ctx) in trie_ctxes {
        trie_proofs.insert(h, trie_ctx.into_proof());
    }
    let qp_root_idx = root_idx;
    let qp = QueryPlan {
        end_blk_height,
        root_idx: qp_root_idx,
        dag_content,
        trie_proofs,
    };

    Ok((query_dag, qp))
}

// 为 gen_parallel_query_dag 函数编写的测试代码
#[cfg(test)]
mod dag_tests {
    use super::super::query_dag::{gen_parallel_query_dag};
    use super::super::{ Node, Range};
    use crate::chain::query::query_param::{NotNode, OrNode, QueryParam};
    #[test]
    fn test_gen_parallel_query_dag_with_not_operator() {
        let query_param = QueryParam::<u32> {
            start_blk: 1,
            end_blk: 3,
            range: vec![Range::<u32>::new(1, 5), Range::<u32>::new(2, 8)],
            keyword_exp: Some(Node::Or(Box::new(OrNode(
                Node::Input("a".to_string()),
                Node::Not(Box::new(NotNode(Node::Input("b".to_string())))),
            )))),
        };
        let query_content = query_param.gen_query_content();

        println!("=== 测试 gen_parallel_query_dag 函数 ===");
        println!("查询内容:");
        println!("  范围查询: {:?}", query_content.range);
        println!("  关键词表达式: {:?}", query_content.keyword_exp);
        println!();
        let result = gen_parallel_query_dag(&query_content);
        assert!(result.is_ok(), "gen_parallel_query_dag 函数执行失败: {:?}", result.err());
      }
}