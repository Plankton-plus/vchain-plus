// 引入必要的依赖和模块
use crate::{
    acc::AccPublicKey,  // 累加器公钥，用于零知识证明相关
    chain::{
        block::{
            block_ads::BlockMultiADS,  // 区块的多个ADS（认证数据结构）
            hash::{ads_root_hash, obj_id_nums_hash, obj_root_hash},  // 哈希计算函数
            BlockContent, BlockHead, Height,  // 区块内容、区块头、区块高度
        },
        bplus_tree::{self, BPlusTreeNode, BPlusTreeNodeId, BPlusTreeRoot},  // B+树相关
        id_tree::{self, ObjId},  // ID树相关
        object::Object,  // 区块链对象
        traits::{Num, ReadInterface, WriteInterface},  // 数值类型、读写接口特性
        trie_tree::{self, TrieNode, TrieNodeId, TrieRoot},  // Trie树相关
        Parameter,  // 区块链参数
    },
    digest::{Digest, Digestible},  // 哈希摘要
};
use anyhow::{bail, Context, Result};  // 错误处理
use howlong::ProcessDuration;  // 性能计时
use smol_str::SmolStr;  // 小型字符串优化
use std::{collections::HashMap, num::NonZeroU16};  // 集合和特殊数字类型

/// 构建区块的核心函数
///
/// 这个函数负责构建一个新区块，包括：
/// 1. 更新ID树、Trie树、B+树等数据结构
/// 2. 计算区块哈希
/// 3. 将数据写入区块链
///
/// # 类型参数
/// - `K`: 数值类型，必须实现`Num`特性
/// - `T`: 区块链接口类型，必须同时实现`ReadInterface`和`WriteInterface`
///
/// # 参数
/// - `blk_height`: 要构建的区块高度
/// - `prev_hash`: 前一个区块的哈希值
/// - `raw_objs`: 要包含在区块中的原始对象列表
/// - `mut chain`: 区块链读写接口
/// - `param`: 区块链参数配置
/// - `pk`: 累加器公钥，用于更新数据结构
///
/// # 返回值
/// - `Result<(BlockHead, ProcessDuration)>`: 成功时返回区块头和构建耗时
pub fn build_block<K: Num, T: ReadInterface<K = K> + WriteInterface<K = K>>(
    blk_height: Height,
    prev_hash: Digest,
    raw_objs: Vec<Object<K>>,
    mut chain: T,
    param: &Parameter,
    pk: &AccPublicKey,
) -> Result<(BlockHead, ProcessDuration)> {
    // 记录开始构建区块的日志
    info!("Building block {}...", blk_height);

    // 开始计时
    let timer = howlong::ProcessCPUTimer::new();

    // 初始化区块头
    let mut block_head = BlockHead {
        blk_height,
        prev_hash,
        ..Default::default()  // 其他字段使用默认值
    };

    // 初始化区块内容
    let mut block_content = BlockContent::new(blk_height, prev_hash);

    // 获取最大ID数量
    let max_id_num = param.max_id_num;

    // 初始化区块的多重ADS（认证数据结构）
    let mut blk_multi_ads: BlockMultiADS = BlockMultiADS::default();

    // 读取前一个区块的内容（如果是第一个区块，则使用默认值）
    let pre_blk_content = if blk_height.0 > 1 {
        chain.read_block_content(Height(blk_height.0 - 1))?
    } else {
        BlockContent::default()
    };

    // 获取前一个区块的ADS
    let multi_ads = pre_blk_content.ads.read_adses();

    // 获取时间窗口配置
    let time_wins = &param.time_win_sizes;

    // ==================== 初始化写入上下文 ====================

    // 1. ID树写入上下文
    let id_tree_root = pre_blk_content.id_tree_root;
    let mut id_tree_ctx = id_tree::write::WriteContext::new(&chain, id_tree_root);

    // 2. Trie树写入上下文（每个时间窗口一个）
    let mut trie_ctxes = Vec::<(u16, trie_tree::write::WriteContext<T>)>::new();

    // 3. B+树写入上下文（每个时间窗口和维度一个）
    let mut bplus_ctxes = Vec::<(u16, Vec<bplus_tree::write::WriteContext<K, T>>)>::new();

    // ==================== 处理前一个区块的过期数据 ====================
    // 对于每个时间窗口，需要移除已过期的数据

    for &k in time_wins {
        // 读取k个区块前的内容（如果存在）
        let pre_k_blk_content = if blk_height.0 > k.into() {
            chain.read_block_content(Height(blk_height.0 - k as u32))?
        } else {
            BlockContent::default()
        };

        // 获取k个区块前的对象哈希和ID号
        let pre_k_blk_obj_hashes = &pre_k_blk_content.obj_hashes;
        let pre_k_blk_obj_id_nums = &pre_k_blk_content.obj_id_nums;

        // ==================== Trie树部分 ====================
        // 获取对应时间窗口的Trie根，如果没有则使用默认值
        let trie_root = if let Some(block_ads) = multi_ads.get(&k) {
            block_ads.trie_root
        } else {
            TrieRoot::default()
        };

        // 创建Trie树写入上下文
        let mut trie_ctx = trie_tree::write::WriteContext::new(&chain, trie_root);

        // 从Trie树中删除过期对象的索引
        for (idx, obj_hash) in pre_k_blk_obj_hashes.iter().enumerate() {
            // 读取原始对象
            let raw_obj = chain.read_object(*obj_hash)?;

            // 获取对象的ID号
            let obj_id_num = pre_k_blk_obj_id_nums
                .get(idx)
                .context("Cannot find object id number!")?;

            // 删除对象的所有关键词索引
            for key in &raw_obj.keyword_data {
                trie_ctx.delete(SmolStr::from(key), ObjId(*obj_id_num), pk)?;
            }
        }

        // 保存Trie上下文
        trie_ctxes.push((k, trie_ctx));

        // ==================== B+树部分 ====================
        // 为每个维度创建B+树写入上下文
        let mut bplus_ctx_vec = Vec::<bplus_tree::write::WriteContext<K, T>>::new();

        for dim in 0..param.num_dim {
            // 获取对应时间窗口和维度的B+树根
            let bplus_tree_root = if let Some(block_ads) = multi_ads.get(&k) {
                if let Some(bplus_root) = block_ads.bplus_tree_roots.get(dim as usize) {
                    *bplus_root
                } else {
                    bail!(
                        "Cannot find BPlusRoot for dimension {} in time window {}!",
                        dim,
                        k
                    );
                }
            } else {
                BPlusTreeRoot::default()
            };

            // 创建B+树写入上下文
            let mut bplus_ctx = bplus_tree::write::WriteContext::new(&chain, bplus_tree_root);

            // 从B+树中删除过期对象的索引
            for (idx, obj_hash) in pre_k_blk_obj_hashes.iter().enumerate() {
                let raw_obj = chain.read_object(*obj_hash)?;
                let obj_id_num = pre_k_blk_obj_id_nums
                    .get(idx)
                    .context("Cannot find object id number!")?;

                // 如果对象有该维度的数值数据，则删除索引
                if let Some(num_data) = raw_obj.num_data.get(dim as usize) {
                    bplus_ctx.delete(*num_data, ObjId(*obj_id_num), param.bplus_tree_fanout, pk)?;
                }
            }

            bplus_ctx_vec.push(bplus_ctx);
        }

        bplus_ctxes.push((k, bplus_ctx_vec));
    }

    // ==================== 处理新区块的对象 ====================

    // 准备存储对象哈希和ID号的向量
    let mut obj_hashes = Vec::<Digest>::with_capacity(raw_objs.len());
    let mut obj_id_nums = Vec::<NonZeroU16>::with_capacity(raw_objs.len());

    // 遍历所有新对象
    for obj in &raw_objs {
        // 1. 计算对象哈希
        let obj_hash = obj.to_digest();

        // 2. 插入到ID树，获取对象ID
        let obj_id = id_tree_ctx.insert(obj_hash, max_id_num, param.id_tree_fanout)?;

        // 3. 插入到所有时间窗口的Trie树中（关键词索引）
        for (_k, trie_ctx) in &mut trie_ctxes {
            for key in &obj.keyword_data {
                trie_ctx.insert(SmolStr::from(key), obj_id, pk)?;
            }
        }

        // 4. 插入到所有时间窗口和维度的B+树中（数值索引）
        for (_k, bplus_ctx_vec) in &mut bplus_ctxes {
            for (dim, bplus_ctx) in bplus_ctx_vec.iter_mut().enumerate() {
                if let Some(key) = obj.num_data.get(dim) {
                    bplus_ctx.insert(*key, obj_id, param.bplus_tree_fanout, pk)?;
                }
            }
        }

        // 保存对象哈希和ID号
        obj_hashes.push(obj_hash);
        obj_id_nums.push(obj_id.0);
    }

    // ==================== 收集变更并写入区块链 ====================

    // 1. 获取ID树变更
    let id_tree_changes = id_tree_ctx.changes();

    // 2. 获取Trie树变更
    let mut new_trie_nodes = Vec::<HashMap<TrieNodeId, TrieNode>>::new();
    let mut new_trie_roots = Vec::<(u16, TrieRoot)>::new();

    for (k, trie_ctx) in trie_ctxes {
        let trie_changes = trie_ctx.changes();
        new_trie_roots.push((k, trie_changes.root));
        new_trie_nodes.push(trie_changes.nodes);
    }

    // 设置多重Trie根到区块ADS中
    blk_multi_ads.set_multi_trie_roots(new_trie_roots.iter());

    // 3. 获取B+树变更
    let mut new_bplus_roots = Vec::<(u16, Vec<BPlusTreeRoot>)>::new();
    let mut new_bplus_nodes = Vec::<HashMap<BPlusTreeNodeId, BPlusTreeNode<K>>>::new();

    for (k, bplus_ctx_vec) in bplus_ctxes {
        let mut new_bplus_roots_dim = Vec::<BPlusTreeRoot>::new();

        for bplus_ctx in bplus_ctx_vec {
            let bplus_tree_changes = bplus_ctx.changes();
            new_bplus_roots_dim.push(bplus_tree_changes.root);
            new_bplus_nodes.push(bplus_tree_changes.nodes);
        }

        new_bplus_roots.push((k, new_bplus_roots_dim));
    }

    // 设置多重B+树根到区块ADS中
    blk_multi_ads.set_multi_bplus_roots(new_bplus_roots.iter());

    // ==================== 将节点写入区块链 ====================

    // 1. 写入ID树节点
    for (id, node) in id_tree_changes.nodes {
        chain.write_id_tree_node(id, &node)?;
    }

    // 2. 写入Trie树节点
    for map in new_trie_nodes {
        for (id, node) in map {
            chain.write_trie_node(id, &node)?;
        }
    }

    // 3. 写入B+树节点
    for map in new_bplus_nodes {
        for (id, node) in map {
            chain.write_bplus_tree_node(id, &node)?;
        }
    }

    // ==================== 写入对象到区块链 ====================

    for (obj, obj_hash) in raw_objs.iter().zip(obj_hashes.iter()) {
        chain.write_object(*obj_hash, obj)?;
    }

    // ==================== 计算区块哈希 ====================

    // 1. 计算对象根哈希
    let obj_root_hash = obj_root_hash(obj_hashes.iter());

    // 2. 计算对象ID号集合哈希
    let id_set_root_hash = obj_id_nums_hash(obj_id_nums.iter());

    // 3. 计算ADS哈希
    let ads_hash = blk_multi_ads.to_digest();

    // 4. 计算ADS根哈希（组合多个哈希）
    let ads_root_hash = ads_root_hash(
        &id_set_root_hash,
        &id_tree_changes.root.to_digest(),
        &ads_hash,
    );

    // ==================== 设置区块头和内容 ====================

    // 设置区块头的哈希值
    block_head.set_obj_root_hash(obj_root_hash);
    block_head.set_ads_root_hash(ads_root_hash);

    // 设置区块内容
    block_content.set_multi_ads(blk_multi_ads);
    block_content.set_obj_hashes(obj_hashes);
    block_content.set_obj_id_nums(obj_id_nums);
    block_content.set_id_tree_root(id_tree_changes.root);

    // ==================== 写入区块到区块链 ====================

    chain.write_block_content(blk_height, &block_content)?;
    chain.write_block_head(blk_height, &block_head)?;

    // 记录构建时间
    let time = timer.elapsed();
    info!("Time elapsed : {}.", time);

    // 返回区块头和构建时间
    Ok((block_head, time))
}