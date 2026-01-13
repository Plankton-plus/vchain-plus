// 声明子模块
pub mod egg_qp;        // EGG查询计划优化器
pub mod query_dag;     // 查询有向无环图表示
pub mod query_param;   // 查询参数定义
pub mod query_plan;    // 查询计划执行

// 导入模块内部的类型
use self::{
    query_dag::DagNode,
    query_param::{param_to_qp, Node},
};

// 导入外部依赖
use crate::{
    acc::{
        compute_set_operation_final, compute_set_operation_intermediate, ops::Op, AccPublicKey, Set,
    },
    chain::{
        block::{hash::obj_id_nums_hash, Height},
        bplus_tree,
        id_tree::{self, ObjId},
        object::Object,
        query::{egg_qp::egg_optimize, query_dag::gen_parallel_query_dag, query_plan::QPNode},
        range::Range,
        traits::{Num, ReadInterface},
        trie_tree,
        verify::vo::{
            MerkleProof, VOBlkRtNode, VOFinalDiff, VOFinalIntersec, VOFinalUnion, VOInterDiff,
            VOInterIntersec, VOInterUnion, VOKeywordNode, VONode, VORangeNode, VoDagContent, VO,
        },
    },
    digest::{Digest, Digestible},
    utils::{QueryTime, Time},
};
use anyhow::{bail, Context, Result};
use howlong::ProcessDuration;
use petgraph::algo::toposort;
use petgraph::{graph::NodeIndex, EdgeDirection::Outgoing, Graph};
use query_param::QueryParam;
use query_plan::QueryPlan;
use rayon::prelude::*;
use smol_str::SmolStr;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

/// 时间窗口结构体，表示查询的时间范围
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TimeWin {
    pub start_blk: u32,  // 起始区块高度
    pub end_blk: u32,    // 结束区块高度
}

impl TimeWin {
    /// 创建新的时间窗口
    pub fn new(start_blk: u32, end_blk: u32) -> Self {
        Self { start_blk, end_blk }
    }

    /// 获取起始区块高度
    pub fn get_start(&self) -> u32 {
        self.start_blk
    }

    /// 获取结束区块高度
    pub fn get_end(&self) -> u32 {
        self.end_blk
    }
}

/// 查询内容结构体，包含范围查询和关键字表达式
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryContent<K: Num> {
    pub range: Vec<Range<K>>,    // 范围查询条件列表
    pub keyword_exp: Option<Node>, // 关键字表达式（可选）
}

/// 查询结果信息结构体，包含各阶段耗时和查询结果
pub struct QueryResInfo<K: Num> {
    stage1: ProcessDuration,  // 阶段1：查询计划生成耗时
    stage2: ProcessDuration,  // 阶段2：查询优化耗时
    stage3: ProcessDuration,  // 阶段3：查询执行准备耗时
    stage4: ProcessDuration,  // 阶段4：最终查询执行耗时
    res: (HashMap<ObjId, Object<K>>, VO<K>),  // 查询结果（对象映射和验证对象）
}

/// 执行最终查询处理的核心函数
#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
fn query_final<K: Num, T: ReadInterface<K = K>>(
    chain: &T,                          // 区块链读取接口
    pk: &AccPublicKey,                  // 公钥
    mut query_plan: QueryPlan<K>,       // 查询计划
    outputs: HashSet<NodeIndex>,        // 输出节点索引集合
    time_win: &TimeWin,                 // 时间窗口
    s_win_size: Option<u16>,            // 起始窗口大小（可选）
    e_win_size: u16,                    // 结束窗口大小
    query_dag: &Graph<query_dag::DagNode<K>, bool>,  // 查询DAG图
) -> Result<(HashMap<ObjId, Object<K>>, VO<K>)> {
    // 初始化各种数据结构
    let mut vo_dag_content = HashMap::<NodeIndex, VONode<K>>::new();  // VO DAG内容
    let qp_end_blk_height = query_plan.end_blk_height;                // 查询计划结束区块高度
    let qp_dag_content = &mut query_plan.dag_content;                 // 查询计划DAG内容
    let mut set_map = HashMap::<NodeIndex, Set>::new();               // 节点索引到集合的映射
    let mut trie_ctxes = HashMap::<Height, trie_tree::read::ReadContext<T>>::new();  // Trie树上下文
    let mut trie_proofs = HashMap::<Height, trie_tree::proof::Proof>::new();        // Trie树证明
    let qp_trie_proofs = query_plan.trie_proofs;                      // 查询计划的Trie证明
    let mut obj_map = HashMap::<ObjId, Object<K>>::new();             // 对象ID到对象的映射
    let mut merkle_proofs = HashMap::<Height, MerkleProof>::new();    // Merkle证明
    let mut time_win_map = HashMap::<Height, u16>::new();             // 区块高度到窗口大小的映射

    // 对查询DAG进行拓扑排序并反转，得到处理顺序
    let mut qp_inputs = match toposort(query_dag, None) {
        Ok(v) => v,
        Err(_) => {
            bail!("Input query plan graph not valid")
        }
    };
    qp_inputs.reverse();

    let mut height_dims: Vec<(Height, u8)> = Vec::new();  // 区块高度和维度列表

    // 按拓扑排序顺序处理每个节点
    for idx in qp_inputs {
        if let Some(dag_node) = query_dag.node_weight(idx) {
            match dag_node {
                // 处理范围查询节点
                query_dag::DagNode::Range(node) => {
                    let set;    // 结果集合
                    let acc;    // 累加器值
                    let proof;  // 证明

                    // 从查询计划中移除对应的Range节点
                    if let Some(QPNode::Range(n)) = qp_dag_content.remove(&idx) {
                        // 记录高度和维度
                        height_dims.push((n.blk_height, node.dim as u8));

                        let blk_height = n.blk_height;
                        // 根据区块高度确定窗口大小
                        let win_size = if blk_height.0 == time_win.get_end() {
                            e_win_size
                        } else if blk_height.0 == time_win.get_start() - 1 {
                            s_win_size.context(
                                "hight = start time_win height but start win_size is None",
                            )?
                        } else {
                            bail!("invalid blk height");
                        };

                        time_win_map.insert(blk_height, win_size);

                        // 如果查询计划中已有结果，则直接使用；否则执行范围查询
                        if let Some((s, a, p)) = n.set {
                            set = s;
                            acc = a;
                            proof = p;
                        } else {
                            let bplus_root = chain
                                .read_block_content(blk_height)?
                                .ads
                                .read_bplus_root(win_size, node.dim)?;
                            let (s, a, p) = bplus_tree::read::range_query(
                                chain,
                                bplus_root.bplus_tree_root_id,
                                node.range,
                                pk,
                            )?;
                            set = s;
                            acc = a;
                            proof = p;
                        }

                        // 创建范围查询的VO节点
                        let vo_range_node = VORangeNode {
                            blk_height: n.blk_height,
                            win_size,
                            acc,
                            proof,
                        };
                        vo_dag_content.insert(idx, VONode::Range(vo_range_node));
                        set_map.insert(idx, set);
                    }
                }

                // 处理关键字查询节点
                query_dag::DagNode::Keyword(node) => {
                    let set;
                    let acc;

                    if let Some(QPNode::Keyword(n)) = qp_dag_content.remove(&idx) {
                        let blk_height = n.blk_height;
                        // 根据区块高度确定窗口大小
                        let win_size = if blk_height.0 == time_win.get_end() {
                            e_win_size
                        } else if blk_height.0 == time_win.get_start() - 1 {
                            s_win_size.context(
                                "hight = start time_win height but start win_size is None",
                            )?
                        } else {
                            bail!("invalid blk height");
                        };

                        time_win_map.insert(blk_height, win_size);

                        // 如果查询计划中已有结果，则直接使用；否则执行关键字查询
                        if let Some((s, a)) = n.set {
                            set = s;
                            acc = a;
                        } else if let Some(ctx) = trie_ctxes.get_mut(&n.blk_height) {
                            let trie_ctx = ctx;
                            let (s, a) = trie_ctx.query(&SmolStr::from(&node.keyword), pk)?;
                            set = s;
                            acc = a;
                        } else {
                            let trie_root = chain
                                .read_block_content(blk_height)?
                                .ads
                                .read_trie_root(win_size)?;
                            let mut trie_ctx =
                                trie_tree::read::ReadContext::new(chain, trie_root.trie_root_id);
                            let (s, a) = trie_ctx.query(&SmolStr::from(&node.keyword), pk)?;
                            set = s;
                            acc = a;
                            trie_ctxes.insert(n.blk_height, trie_ctx);
                        }

                        // 创建关键字查询的VO节点
                        let vo_keyword_node = VOKeywordNode {
                            blk_height: n.blk_height,
                            win_size,
                            acc,
                        };
                        vo_dag_content.insert(idx, VONode::Keyword(vo_keyword_node));
                        set_map.insert(idx, set);
                    }
                }

                // 处理区块根节点
                query_dag::DagNode::BlkRt(_) => {
                    let set;
                    let acc;

                    if let Some(QPNode::BlkRt(n)) = qp_dag_content.remove(&idx) {
                        let blk_height = n.blk_height;
                        // 根据区块高度确定窗口大小
                        let win_size = if blk_height.0 == time_win.get_end() {
                            e_win_size
                        } else if blk_height.0 == time_win.get_start() - 1 {
                            s_win_size.context(
                                "hight = start time_win height but start win_size is None",
                            )?
                        } else {
                            bail!("invalid blk height");
                        };

                        time_win_map.insert(blk_height, win_size);

                        // 如果查询计划中已有结果，则直接使用；否则从区块中获取
                        if let Some((s, a)) = n.set {
                            set = s;
                            acc = a;
                        } else {
                            let blk_content = chain.read_block_content(blk_height)?;
                            let bplus_root = blk_content.ads.read_bplus_root(win_size, 0)?;
                            let bplus_root_id =
                                bplus_root.bplus_tree_root_id.context("Empty bplus root")?;
                            let bplus_root_node =
                                bplus_tree::BPlusTreeNodeLoader::load_node(chain, bplus_root_id)?;
                            set = bplus_root_node.get_set().clone();
                            acc = bplus_root_node.get_node_acc();
                        }

                        // 创建区块根的VO节点
                        let vo_blk_root = VOBlkRtNode {
                            blk_height: n.blk_height,
                            win_size,
                            acc,
                        };
                        vo_dag_content.insert(idx, VONode::BlkRt(vo_blk_root));
                        set_map.insert(idx, set);
                    }
                }

                // 处理并集操作节点
                query_dag::DagNode::Union(_) => {
                    if let Some(QPNode::Union(_)) = qp_dag_content.remove(&idx) {
                        // 获取子节点索引
                        let mut child_idxs = Vec::<NodeIndex>::new();
                        for c_idx in query_dag.neighbors_directed(idx, Outgoing) {
                            child_idxs.push(c_idx);
                        }

                        // 确定子节点顺序（基于边的权重）
                        let mut qp_c_idx1 = child_idxs
                            .get(1)
                            .context("Cannot find the first child idx of final difference")?;
                        let qp_c_idx2;
                        let edge_idx = query_dag
                            .find_edge(idx, *qp_c_idx1)
                            .context("Cannot find edge")?;
                        let weight = query_dag
                            .edge_weight(edge_idx)
                            .context("Cannot find edge")?;

                        if !*weight {
                            qp_c_idx2 = child_idxs
                                .get(0)
                                .context("Cannot find the second child idx of final difference")?;
                        } else {
                            qp_c_idx1 = child_idxs
                                .get(0)
                                .context("Cannot find the first qp child idx of intersection")?;
                            qp_c_idx2 = child_idxs
                                .get(1)
                                .context("Cannot find the second qp child idx of intersection")?;
                        }

                        // 获取子节点的VO和集合
                        let vo_c1 = vo_dag_content
                            .get(qp_c_idx1)
                            .context("Cannot find the first child vo node in vo_dag_content")?;
                        let c1_set = set_map
                            .get(qp_c_idx1)
                            .context("Cannot find the set in set_map")?;
                        let vo_c2 = vo_dag_content
                            .get(qp_c_idx2)
                            .context("Cannot find the second child vo node in vo_dag_content")?;
                        let c2_set = set_map
                            .get(qp_c_idx2)
                            .context("Cannot find the set in set_map")?;

                        // 根据是否是输出节点执行不同的操作
                        if !outputs.contains(&idx) {
                            // 中间节点：计算中间结果和证明
                            let (res_set, res_acc, inter_proof) =
                                compute_set_operation_intermediate(
                                    Op::Union,
                                    c1_set,
                                    vo_c1.get_acc()?,
                                    c2_set,
                                    vo_c2.get_acc()?,
                                    pk,
                                );
                            let vo_inter_union = VOInterUnion {
                                acc: res_acc,
                                proof: inter_proof,
                            };
                            vo_dag_content.insert(idx, VONode::InterUnion(vo_inter_union));
                            set_map.insert(idx, res_set);
                        } else {
                            // 输出节点：计算最终结果和证明
                            let (res_set, final_proof) =
                                compute_set_operation_final(Op::Union, c1_set, c2_set, pk);
                            let vo_final_union = VOFinalUnion { proof: final_proof };
                            vo_dag_content.insert(idx, VONode::FinalUnion(vo_final_union));
                            set_map.insert(idx, res_set);
                        }
                    }
                }

                // 处理交集操作节点
                query_dag::DagNode::Intersec(_) => {
                    if let Some(QPNode::Intersec(_)) = qp_dag_content.remove(&idx) {
                        // 获取子节点索引
                        let mut child_idxs = Vec::<NodeIndex>::new();
                        for c_idx in query_dag.neighbors_directed(idx, Outgoing) {
                            child_idxs.push(c_idx);
                        }

                        // 确定子节点顺序
                        let mut qp_c_idx1 = child_idxs
                            .get(1)
                            .context("Cannot find the first child idx of final difference")?;
                        let qp_c_idx2;
                        let edge_idx = query_dag
                            .find_edge(idx, *qp_c_idx1)
                            .context("Cannot find edge")?;
                        let weight = query_dag
                            .edge_weight(edge_idx)
                            .context("Cannot find edge")?;

                        if !*weight {
                            qp_c_idx2 = child_idxs
                                .get(0)
                                .context("Cannot find the second child idx of final difference")?;
                        } else {
                            qp_c_idx1 = child_idxs
                                .get(0)
                                .context("Cannot find the first qp child idx of intersection")?;
                            qp_c_idx2 = child_idxs
                                .get(1)
                                .context("Cannot find the second qp child idx of intersection")?;
                        }

                        // 处理交集操作，考虑空集情况
                        if let Some(vo_c1) = vo_dag_content.get(qp_c_idx1) {
                            // vo_c1不为空
                            if let Some(vo_c2) = vo_dag_content.get(qp_c_idx2) {
                                // vo_c2也不为空
                                let c1_set = set_map
                                    .get(qp_c_idx1)
                                    .context("Cannot find the set in set_map")?;
                                let c2_set = set_map
                                    .get(qp_c_idx2)
                                    .context("Cannot find the set in set_map")?;

                                if !outputs.contains(&idx) {
                                    // 中间节点：计算中间交集
                                    let (res_set, res_acc, inter_proof) =
                                        compute_set_operation_intermediate(
                                            Op::Intersection,
                                            c1_set,
                                            vo_c1.get_acc()?,
                                            c2_set,
                                            vo_c2.get_acc()?,
                                            pk,
                                        );
                                    let vo_inter_intersec = VOInterIntersec {
                                        acc: res_acc,
                                        proof: Some(inter_proof),
                                    };
                                    vo_dag_content
                                        .insert(idx, VONode::InterIntersec(vo_inter_intersec));
                                    set_map.insert(idx, res_set);
                                } else {
                                    // 输出节点：计算最终交集
                                    let (res_set, final_proof) = compute_set_operation_final(
                                        Op::Intersection,
                                        c1_set,
                                        c2_set,
                                        pk,
                                    );
                                    let vo_final_intersec = VOFinalIntersec { proof: final_proof };
                                    vo_dag_content
                                        .insert(idx, VONode::FinalIntersec(vo_final_intersec));
                                    set_map.insert(idx, res_set);
                                }
                            } else {
                                // vo_c2为空，交集结果为空
                                let vo_inter_intersec = VOInterIntersec {
                                    acc: *vo_c1.get_acc()?,
                                    proof: None,
                                };
                                vo_dag_content
                                    .insert(idx, VONode::InterIntersec(vo_inter_intersec));
                                set_map.insert(idx, Set::new());
                            }
                        } else {
                            // vo_c1为空，交集结果为空
                            let vo_c2 = vo_dag_content.get(qp_c_idx2).context(
                                "Cannot find the second child vo node in vo_dag_content",
                            )?;
                            let vo_inter_intersec = VOInterIntersec {
                                acc: *vo_c2.get_acc()?,
                                proof: None,
                            };
                            vo_dag_content.insert(idx, VONode::InterIntersec(vo_inter_intersec));
                            set_map.insert(idx, Set::new());
                        }
                    }
                }

                // 处理差集操作节点
                query_dag::DagNode::Diff(_) => {
                    if let Some(QPNode::Diff(_)) = qp_dag_content.remove(&idx) {
                        // 获取子节点索引
                        let mut child_idxs = Vec::<NodeIndex>::new();
                        for c_idx in query_dag.neighbors_directed(idx, Outgoing) {
                            child_idxs.push(c_idx);
                        }

                        // 确定子节点顺序
                        let mut qp_c_idx1 = child_idxs
                            .get(1)
                            .context("Cannot find the first qp child idx of difference")?;
                        let qp_c_idx2;
                        let edge_idx = query_dag
                            .find_edge(idx, *qp_c_idx1)
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

                        let vo_c1 = vo_dag_content
                            .get(qp_c_idx1)
                            .context("Cannot find the first child vo node in vo_dag_content")?;

                        // 处理差集操作，考虑空集情况
                        if let Some(vo_c2) = vo_dag_content.get(qp_c_idx2) {
                            // vo_c2不为空
                            let c1_set = set_map
                                .get(qp_c_idx1)
                                .context("Cannot find the set in set_map")?;
                            let c2_set = set_map
                                .get(qp_c_idx2)
                                .context("Cannot find the set in set_map")?;

                            if !outputs.contains(&idx) {
                                // 中间节点：计算中间差集
                                let (res_set, res_acc, inter_proof) =
                                    compute_set_operation_intermediate(
                                        Op::Difference,
                                        c1_set,
                                        vo_c1.get_acc()?,
                                        c2_set,
                                        vo_c2.get_acc()?,
                                        pk,
                                    );
                                let vo_inter_diff = VOInterDiff {
                                    acc: res_acc,
                                    proof: Some(inter_proof),
                                };
                                vo_dag_content.insert(idx, VONode::InterDiff(vo_inter_diff));
                                set_map.insert(idx, res_set);
                            } else {
                                // 输出节点：计算最终差集
                                let (res_set, final_proof) =
                                    compute_set_operation_final(Op::Difference, c1_set, c2_set, pk);
                                let vo_final_diff = VOFinalDiff { proof: final_proof };
                                vo_dag_content.insert(idx, VONode::FinalDiff(vo_final_diff));
                                set_map.insert(idx, res_set);
                            }
                        } else {
                            // vo_c2为空，差集结果为空
                            let vo_inter_diff = VOInterDiff {
                                acc: *vo_c1.get_acc()?,
                                proof: None,
                            };
                            vo_dag_content.insert(idx, VONode::InterDiff(vo_inter_diff));
                            set_map.insert(idx, Set::new());
                        }
                    }
                }
            }
        }
    }

    // 将Trie上下文转换为证明并合并
    for (height, trie_ctx) in trie_ctxes {
        let trie_proof = trie_ctx.into_proof();
        trie_proofs.insert(height, trie_proof);
    }

    // 添加查询计划中的Trie证明
    for (height, trie_proof) in qp_trie_proofs {
        trie_proofs.insert(height, trie_proof);
    }

    // 处理只有范围查询且最后一个子查询有起始子DAG的情况
    for (height, time_win) in &time_win_map {
        if trie_proofs.get(height).is_none() {
            let trie_root = chain
                .read_block_content(*height)?
                .ads
                .read_trie_root(*time_win)?;
            let trie_ctx = trie_tree::read::ReadContext::new(chain, trie_root.trie_root_id);
            let trie_proof = trie_ctx.into_proof();
            trie_proofs.insert(*height, trie_proof);
        }
    }

    // 从ID树中读取对象
    let id_root = chain.read_block_content(qp_end_blk_height)?.id_tree_root;
    let cur_obj_id = id_root.get_cur_obj_id();
    let mut id_tree_ctx = id_tree::read::ReadContext::new(chain, id_root.get_id_tree_root_id());
    let param = chain.get_parameter()?;
    let max_id_num = param.max_id_num;
    let id_tree_fanout = param.id_tree_fanout;

    // 遍历所有输出集合，获取对应的对象
    for idx in outputs {
        let set = set_map.get(&idx).context("Cannot find set in set_map")?;
        for i in set.iter() {
            let obj_id = ObjId(*i);
            if let Some(obj_hash) = id_tree_ctx.query(obj_id, max_id_num, id_tree_fanout)? {
                let obj = chain.read_object(obj_hash)?;
                obj_map.insert(obj_id, obj);
            }
        }
    }

    // 获取ID树证明
    let id_tree_proof = id_tree_ctx.into_proof();

    // 为每个区块高度创建Merkle证明
    for (height, time_win) in time_win_map {
        let blk_content = chain.read_block_content(height)?;
        let obj_id_nums = blk_content.read_obj_id_nums();
        let id_set_root_hash = obj_id_nums_hash(obj_id_nums.iter());

        let mut ads_hashes = BTreeMap::<u16, Digest>::new();
        let multi_ads = blk_content.ads;
        let mut extra_bplus_rt_hashes = HashMap::<u8, Digest>::new();

        // 收集广告哈希
        for (t_w, ads) in multi_ads.read_adses() {
            if *t_w != time_win {
                ads_hashes.insert(*t_w, ads.to_digest());
            } else {
                let bplus_tree_roots = &ads.bplus_tree_roots;
                for (i, rt) in bplus_tree_roots.iter().enumerate() {
                    extra_bplus_rt_hashes.insert(i as u8, rt.to_digest());
                }
                // 移除已查询的B+树根
                for (h, d) in &height_dims {
                    if *h == height {
                        extra_bplus_rt_hashes.remove(d);
                    }
                }
            }
        }

        // 获取ID树根哈希
        let id_tree_root_hash = if height == qp_end_blk_height {
            None
        } else {
            Some(chain.read_block_content(height)?.id_tree_root.to_digest())
        };

        // 创建Merkle证明
        let merkle_proof = MerkleProof {
            id_tree_root_hash,
            id_set_root_hash,
            ads_hashes,
            extra_bplus_rt_hashes,
        };
        merkle_proofs.insert(height, merkle_proof);
    }

    // 构建最终的VO DAG内容
    let vo_dag_struct = VoDagContent {
        output_sets: set_map,
        dag_content: vo_dag_content,
    };

    // 构建最终的验证对象
    let vo = VO {
        vo_dag_content: vo_dag_struct,
        trie_proofs,
        id_tree_proof,
        cur_obj_id,
        merkle_proofs,
    };

    Ok((obj_map, vo))
}

/// 选择合适的时间窗口大小，将查询时间窗口分割为多个子窗口
fn select_win_size(win_sizes: &[u16], query_time_win: TimeWin) -> Result<Vec<(TimeWin, u16)>> {
    let mut vec_res = Vec::<(TimeWin, u16)>::new();
    let mut cur_win = query_time_win;
    let max = *win_sizes.last().context("empty time win")? as u32;

    // 使用最大窗口大小尽可能多地覆盖时间窗口
    while cur_win.get_end() + 1 >= max + cur_win.get_start() {
        let new_time_win = TimeWin::new(cur_win.get_start(), cur_win.get_start() + max - 1);
        vec_res.push((new_time_win, max as u16));

        // 如果正好覆盖完，返回结果
        if cur_win.get_start() + max == cur_win.get_end() + 1 {
            return Ok(vec_res);
        } else {
            // 否则移动窗口起始位置
            cur_win = TimeWin::new(cur_win.get_start() + max, cur_win.get_end());
        }
    }

    // 处理剩余的时间窗口
    let cur_size = (cur_win.get_end() - cur_win.get_start() + 1) as u16;
    let mut last_size = 0;

    // 选择合适的大小
    for win_size in win_sizes {
        if cur_size <= *win_size {
            last_size = *win_size as u32;
            break;
        }
    }

    // 添加最后一个窗口
    let last_win = TimeWin::new(cur_win.get_end() - last_size + 1, cur_win.get_end());
    vec_res.push((last_win, last_size as u16));

    Ok(vec_res)
}

/// 并行子查询处理函数
#[allow(clippy::type_complexity)]
fn paral_sub_query_process<K: Num, T: ReadInterface<K = K>>(
    empty_set: bool,                // 是否处理空集
    time_win: &TimeWin,             // 时间窗口
    e_win_size: u16,                // 结束窗口大小
    query_dag: &Graph<query_dag::DagNode<K>, bool>,  // 查询DAG
    chain: &T,                      // 区块链接口
    pk: &AccPublicKey,              // 公钥
) -> Result<QueryResInfo<K>> {
    // 阶段1：生成查询计划
    let sub_timer = howlong::ProcessCPUTimer::new();
    let mut query_plan = param_to_qp(time_win, e_win_size, query_dag, chain, pk)?;
    let time1 = sub_timer.elapsed();

    // 阶段2：（空操作，可能预留）
    let sub_timer = howlong::ProcessCPUTimer::new();
    let time2 = sub_timer.elapsed();

    // 阶段3：准备查询执行
    let sub_timer = howlong::ProcessCPUTimer::new();
    let mut outputs;

    // 根据是否处理空集决定输出节点
    if empty_set {
        outputs = process_empty_sets(query_dag, &mut query_plan)?;
    } else {
        outputs = HashSet::new();
        let rt = &query_plan.root_idx;
        outputs.insert(*rt);
    }

    let time3 = sub_timer.elapsed();

    // 阶段4：执行最终查询
    let sub_timer = howlong::ProcessCPUTimer::new();
    let res = query_final(
        chain, pk, query_plan, outputs, time_win, None, e_win_size, query_dag,
    )?;
    let time4 = sub_timer.elapsed();

    // 返回查询结果信息
    Ok(QueryResInfo {
        stage1: time1,
        stage2: time2,
        stage3: time3,
        stage4: time4,
        res,
    })
}

/// 使用EGG优化的并行第一个子查询处理
#[allow(clippy::type_complexity)]
fn paral_first_sub_query_with_egg<K: Num, T: ReadInterface<K = K>>(
    empty_set: bool,                // 是否处理空集
    time_win: &TimeWin,             // 时间窗口
    e_win_size: u16,                // 结束窗口大小
    query_dag: &Graph<query_dag::DagNode<K>, bool>,  // 查询DAG
    chain: &T,                      // 区块链接口
    pk: &AccPublicKey,              // 公钥
) -> Result<(Result<QueryResInfo<K>>, Graph<query_dag::DagNode<K>, bool>)> {
    // 阶段1：生成查询计划
    let sub_timer = howlong::ProcessCPUTimer::new();
    let mut query_plan = param_to_qp(time_win, e_win_size, query_dag, chain, pk)?;
    let time1 = sub_timer.elapsed();

    // 阶段2：使用EGG优化查询计划
    let sub_timer = howlong::ProcessCPUTimer::new();
    let new_dag = egg_optimize(query_dag, &mut query_plan)?;
    let time2 = sub_timer.elapsed();

    // 阶段3：准备查询执行
    let sub_timer = howlong::ProcessCPUTimer::new();
    let mut outputs;

    // 根据是否处理空集决定输出节点
    if empty_set {
        outputs = process_empty_sets(&new_dag, &mut query_plan)?;
    } else {
        outputs = HashSet::new();
        let rt = &query_plan.root_idx;
        outputs.insert(*rt);
    }

    let time3 = sub_timer.elapsed();

    // 阶段4：执行最终查询
    let sub_timer = howlong::ProcessCPUTimer::new();
    let res = query_final(
        chain, pk, query_plan, outputs, time_win, None, e_win_size, &new_dag,
    )?;
    let time4 = sub_timer.elapsed();

    // 构建查询结果信息
    let query_res_info = QueryResInfo {
        stage1: time1,
        stage2: time2,
        stage3: time3,
        stage4: time4,
        res,
    };

    Ok((Ok(query_res_info), new_dag))
}

/// 处理空集的优化函数
fn process_empty_sets<K: Num>(
    query_dag: &Graph<query_dag::DagNode<K>, bool>,  // 查询DAG
    qp: &mut QueryPlan<K>,                           // 查询计划
) -> Result<HashSet<NodeIndex>> {
    let qp_root_idx = qp.root_idx;
    let qp_content = qp.get_dag_cont_mut();
    let mut sub_root_idxs = HashSet::new();
    sub_root_idxs.insert(qp_root_idx);
    let mut new_qp_content = HashMap::new();
    let mut queue = VecDeque::new();
    queue.push_back(qp_root_idx);

    // 使用队列遍历查询DAG
    while let Some(idx) = queue.pop_front() {
        let query_node = query_dag
            .node_weight(idx)
            .context("node not exist in dag")?;

        match query_node {
            DagNode::Range(_) => {
                // 范围节点直接保留
                new_qp_content.insert(idx, qp_content.remove(&idx).context("")?);
            }
            DagNode::Keyword(_) => {
                // 关键字节点直接保留
                new_qp_content.insert(idx, qp_content.remove(&idx).context("")?);
            }
            DagNode::BlkRt(_) => {
                // 区块根节点直接保留
                new_qp_content.insert(idx, qp_content.remove(&idx).context("")?);
            }
            DagNode::Union(_) => {
                // 并集节点处理
                let mut child_idxs = Vec::new();
                for c_idx in query_dag.neighbors_directed(idx, Outgoing) {
                    child_idxs.push(c_idx);
                }

                // 如果是子根节点，则将其子节点添加为新的子根
                if sub_root_idxs.contains(&idx) {
                    sub_root_idxs.remove(&idx);
                    for idx in &child_idxs {
                        sub_root_idxs.insert(*idx);
                    }
                } else {
                    new_qp_content.insert(idx, qp_content.remove(&idx).context("")?);
                }

                // 将子节点加入队列继续处理
                let qp_c_idx1 = child_idxs
                    .get(0)
                    .context("Cannot find the first child idx")?;
                let qp_c_idx2 = child_idxs
                    .get(1)
                    .context("Cannot find the second child idx")?;
                queue.push_back(*qp_c_idx1);
                queue.push_back(*qp_c_idx2);
            }
            DagNode::Intersec(_) => {
                // 交集节点处理：如果任一子节点为空，交集结果为空
                let mut child_idxs = Vec::new();
                for c_idx in query_dag.neighbors_directed(idx, Outgoing) {
                    child_idxs.push(c_idx);
                }

                let qp_c_idx1 = child_idxs
                    .get(0)
                    .context("Cannot find the first child idx")?;
                let qp_c_idx2 = child_idxs
                    .get(1)
                    .context("Cannot find the second child idx")?;

                let qp_c1 = qp_content.get(qp_c_idx1).context("")?;
                let qp_c2 = qp_content.get(qp_c_idx2).context("")?;

                // 如果任一子节点集合为空，则处理该空节点
                if qp_c1.get_set()?.is_empty() {
                    queue.push_back(*qp_c_idx1);
                    new_qp_content.insert(idx, qp_content.remove(&idx).context("")?);
                    continue;
                }
                if qp_c2.get_set()?.is_empty() {
                    queue.push_back(*qp_c_idx2);
                    new_qp_content.insert(idx, qp_content.remove(&idx).context("")?);
                    continue;
                }

                // 两个子节点都不为空，继续处理子节点
                queue.push_back(*qp_c_idx1);
                queue.push_back(*qp_c_idx2);
                new_qp_content.insert(idx, qp_content.remove(&idx).context("")?);
            }
            DagNode::Diff(_) => {
                // 差集节点处理
                let mut child_idxs = Vec::new();
                for c_idx in query_dag.neighbors_directed(idx, Outgoing) {
                    child_idxs.push(c_idx);
                }

                let mut qp_c_idx1 = child_idxs
                    .get(1)
                    .context("Cannot find the first child idx")?;
                let qp_c_idx2;
                let edge_idx = query_dag
                    .find_edge(idx, *qp_c_idx1)
                    .context("Cannot find edge")?;
                let weight = query_dag
                    .edge_weight(edge_idx)
                    .context("Cannot find edge")?;

                // 确定子节点顺序
                if !*weight {
                    qp_c_idx2 = child_idxs
                        .get(0)
                        .context("Cannot find the first qp child idx")?;
                } else {
                    qp_c_idx1 = child_idxs
                        .get(0)
                        .context("Cannot find the first qp child idx")?;
                    qp_c_idx2 = child_idxs
                        .get(1)
                        .context("Cannot find the first qp child idx")?;
                }

                let qp_c1 = qp_content.get(qp_c_idx1).context("")?;
                let qp_c2 = qp_content.get(qp_c_idx2).context("")?;

                // 如果是子根节点且第二个子节点为空，则处理子节点
                if sub_root_idxs.contains(&idx) && qp_c2.get_set()?.is_empty() {
                    sub_root_idxs.remove(&idx);
                    for idx in &child_idxs {
                        sub_root_idxs.insert(*idx);
                    }
                    queue.push_back(*qp_c_idx1);
                    queue.push_back(*qp_c_idx2);
                    continue;
                }

                // 如果第一个子节点为空，则处理该空节点
                if qp_c1.get_set()?.is_empty() {
                    queue.push_back(*qp_c_idx1);
                    new_qp_content.insert(idx, qp_content.remove(&idx).context("")?);
                    continue;
                }

                // 否则继续处理子节点
                queue.push_back(*qp_c_idx1);
                queue.push_back(*qp_c_idx2);
                new_qp_content.insert(idx, qp_content.remove(&idx).context("")?);
            }
        }
    }

    // 更新查询计划中的DAG内容
    qp.update_dag_cont(new_qp_content);

    Ok(sub_root_idxs)
}

/// 并行处理多个时间窗口的查询
fn parallel_processing<K: Num, T: ReadInterface<K = K> + std::marker::Sync + std::marker::Send>(
    empty_set: bool,                    // 是否处理空集
    egg_opt: bool,                      // 是否使用EGG优化
    complete_wins: &mut Vec<(TimeWin, u16)>,  // 完整的时间窗口列表
    dag: &Graph<DagNode<K>, bool>,     // 查询DAG
    responses: &mut Vec<Result<QueryResInfo<K>>>,  // 查询响应结果
    chain: &T,                         // 区块链接口
    pk: &AccPublicKey,                 // 公钥
) -> Result<Graph<DagNode<K>, bool>> {
    // 根据是否使用EGG优化选择不同的处理策略
    if egg_opt {
        // 使用EGG优化：处理第一个窗口并优化DAG，然后并行处理其他窗口
        if let Some((selected_win, win_size)) = complete_wins.pop() {
            let (q_res_info, new_dag) =
                paral_first_sub_query_with_egg(empty_set, &selected_win, win_size, dag, chain, pk)?;

            // 并行处理剩余的时间窗口
            complete_wins
                .par_iter()
                .map(|(time_win, e_win_size)| {
                    paral_sub_query_process(empty_set, time_win, *e_win_size, &new_dag, chain, pk)
                })
                .collect_into_vec(responses);

            // 添加第一个窗口的结果
            responses.push(q_res_info);
            Ok(new_dag)
        } else {
            bail!("Empty complete windows");
        }
    } else {
        // 不使用EGG优化：直接并行处理所有窗口
        complete_wins
            .par_iter()
            .map(|(time_win, e_win_size)| {
                paral_sub_query_process(empty_set, time_win, *e_win_size, dag, chain, pk)
            })
            .collect_into_vec(responses);
        Ok(dag.clone())
    }
}

/// 主要的查询函数，入口点
#[allow(clippy::type_complexity)]
pub fn query<K: Num, T: ReadInterface<K = K> + std::marker::Sync + std::marker::Send>(
    empty_set: bool,           // 是否处理空集
    egg_opt: bool,             // 是否使用EGG优化
    chain: T,                  // 区块链接口
    query_param: QueryParam<K>, // 查询参数
    pk: &AccPublicKey,         // 公钥
) -> Result<(
    Vec<(HashMap<ObjId, Object<K>>, VO<K>)>,  // 查询结果列表
    Graph<DagNode<K>, bool>,                  // 查询DAG
    QueryTime,                                // 查询耗时统计
)> {
    // 开始计时
    let timer = howlong::ProcessCPUTimer::new();

    // 从查询参数获取链参数和时间窗口
    let chain_param = &chain.get_parameter()?;
    let chain_win_sizes = &chain_param.time_win_sizes;

    // 生成查询时间窗口和内容
    let query_time_win = query_param.gen_time_win();
    let query_content = query_param.gen_query_content();

    // 选择合适的时间窗口大小
    let mut complete_wins = select_win_size(chain_win_sizes, query_time_win)?;
    let mut responses = Vec::with_capacity(complete_wins.len());

    // 生成并行查询DAG
    let dag = gen_parallel_query_dag(&query_content)?;

    // 执行并行查询处理
    let res_dag = parallel_processing(
        empty_set,
        egg_opt,
        &mut complete_wins,
        &dag,
        &mut responses,
        &chain,
        pk,
    )?;

    // 计算总查询时间
    let total_query_time = Time::from(timer.elapsed());

    // 统计各阶段耗时
    let mut stage1_time = Vec::<ProcessDuration>::new();
    let mut stage2_time = Vec::<ProcessDuration>::new();
    let mut stage3_time = Vec::<ProcessDuration>::new();
    let mut stage4_time = Vec::<ProcessDuration>::new();
    let mut result = Vec::<(HashMap<ObjId, Object<K>>, VO<K>)>::new();

    // 收集所有查询结果和耗时数据
    for response in responses {
        let a = response?;
        stage1_time.push(a.stage1);
        stage2_time.push(a.stage2);
        stage3_time.push(a.stage3);
        stage4_time.push(a.stage4);
        result.push(a.res);
    }

    // 计算各阶段总耗时
    let mut stage1_total_time: ProcessDuration = ProcessDuration::default();
    for t in stage1_time {
        stage1_total_time += t;
    }

    let mut stage2_total_time: ProcessDuration = ProcessDuration::default();
    for t in stage2_time {
        stage2_total_time += t;
    }

    let mut stage3_total_time: ProcessDuration = ProcessDuration::default();
    for t in stage3_time {
        stage3_total_time += t;
    }

    let mut stage4_total_time: ProcessDuration = ProcessDuration::default();
    for t in stage4_time {
        stage4_total_time += t;
    }

    // 构建查询时间统计
    let query_time = QueryTime {
        stage1: Time::from(stage1_total_time),
        stage2: Time::from(stage2_total_time),
        stage3: Time::from(stage3_total_time),
        stage4: Time::from(stage4_total_time),
        total: total_query_time,
    };

    // 返回查询结果、DAG和时间统计
    Ok((result, res_dag, query_time))
}

/// 测试模块
#[cfg(test)]
mod tests {
    use super::TimeWin;
    use crate::chain::query::select_win_size;

    /// 测试时间窗口选择功能
    #[test]
    fn test_select_win_size() {
        // 测试用例1：时间窗口1-10，可用窗口大小[2,4,8]
        let query_time_win = TimeWin::new(1, 10);
        let res = select_win_size(&vec![2, 4, 8], query_time_win).unwrap();
        let exp = vec![(TimeWin::new(1, 8), 8), (TimeWin::new(9, 10), 2)];
        assert_eq!(res, exp);

        // 测试用例2：时间窗口1-12，可用窗口大小[2,4,8]
        let query_time_win = TimeWin::new(1, 12);
        let res = select_win_size(&vec![2, 4, 8], query_time_win).unwrap();
        let exp = vec![(TimeWin::new(1, 8), 8), (TimeWin::new(9, 12), 4)];
        assert_eq!(res, exp);

        // 测试用例3：时间窗口1-13，可用窗口大小[2,4,8]
        let query_time_win = TimeWin::new(1, 13);
        let res = select_win_size(&vec![2, 4, 8], query_time_win).unwrap();
        let exp = vec![(TimeWin::new(1, 8), 8), (TimeWin::new(6, 13), 8)];
        assert_eq!(res, exp);

        // 测试用例4：时间窗口1-14，可用窗口大小[2,4,8]
        let query_time_win = TimeWin::new(1, 14);
        let res = select_win_size(&vec![2, 4, 8], query_time_win).unwrap();
        let exp = vec![(TimeWin::new(1, 8), 8), (TimeWin::new(7, 14), 8)];
        assert_eq!(res, exp);
    }
}