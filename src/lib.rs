// 在非测试环境下，启用clippy的unwrap_used警告，帮助编写更安全的代码
#![cfg_attr(not(test), warn(clippy::unwrap_used))]

// 引入tracing宏用于日志记录
#[macro_use]
extern crate tracing;

// 定义模块
pub mod acc;       // 可能指accumulator（累加器）相关功能
pub mod chain;     // 区块链核心逻辑
pub mod digest;    // 哈希摘要相关
pub mod utils;     // 工具函数

// 引入依赖
use anyhow::{Context, Result};  // 错误处理库，提供上下文信息
use chain::{
    block::{BlockContent, BlockHead, Height},  // 区块相关
    bplus_tree::{BPlusTreeNode, BPlusTreeNodeId},  // B+树相关
    id_tree::{IdTreeNode, IdTreeNodeId},       // ID树相关
    object::Object,                            // 区块链对象
    range::Range,                              // 范围查询
    traits::{ReadInterface, ScanQueryInterface, WriteInterface},  // 接口定义
    trie_tree::{TrieNode, TrieNodeId},         // Trie树相关
    Parameter,                                 // 系统参数
};
use digest::{Digest, Digestible};  // 哈希摘要
use rocksdb::{self, DB};           // RocksDB数据库
use std::{
    collections::HashSet,          // 哈希集合
    fs,                            // 文件系统操作
    path::{Path, PathBuf},         // 路径处理
};

/// SimChain - 模拟区块链实现
///
/// 这是一个基于RocksDB的区块链模拟器，提供了区块链的核心功能，
/// 包括数据存储、读取、写入和查询接口。
pub struct SimChain {
    /// 区块链数据存储的根路径
    root_path: PathBuf,

    /// 系统参数配置
    param: Parameter,

    /// 区块头数据库
    block_head_db: DB,

    /// 区块内容数据库
    block_content_db: DB,

    /// ID树节点数据库
    id_tree_db: DB,

    /// B+树节点数据库
    bplus_tree_db: DB,

    /// Trie树节点数据库
    trie_db: DB,

    /// 对象数据库
    obj_db: DB,
}

impl SimChain {
    /// 创建新的SimChain实例
    ///
    /// # 参数
    /// * `path` - 区块链数据的存储路径
    /// * `param` - 系统参数配置
    ///
    /// # 返回值
    /// * `Result<Self>` - 成功时返回SimChain实例，失败时返回错误
    ///
    pub fn create(path: &Path, param: Parameter) -> Result<Self> {
        // 创建目录结构，如果目录已存在则不会有影响
        fs::create_dir_all(path).with_context(|| format!("failed to create dir {:?}", path))?;

        // 将参数配置序列化为JSON并保存到文件
        fs::write(
            path.join("param.json"),
            serde_json::to_string_pretty(&param)?,
        )?;

        // 配置RocksDB选项
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);  // 如果数据库不存在则创建

        // 初始化SimChain实例，打开或创建所有数据库
        Ok(Self {
            root_path: path.to_owned(),
            param,
            block_head_db: DB::open(&opts, path.join("blk_head.db"))?,
            block_content_db: DB::open(&opts, path.join("block_content.db"))?,
            id_tree_db: DB::open(&opts, path.join("id_tree.db"))?,
            bplus_tree_db: DB::open(&opts, path.join("bplus_tree.db"))?,
            trie_db: DB::open(&opts, path.join("trie.db"))?,
            obj_db: DB::open(&opts, path.join("obj.db"))?,
        })
    }

    /// 打开已存在的SimChain实例
    ///
    /// # 参数
    /// * `path` - 区块链数据的存储路径
    ///
    /// # 返回值
    /// * `Result<Self>` - 成功时返回SimChain实例，失败时返回错误
    ///
    /// # 注意
    /// 与`create`不同，此方法假设数据库已存在，使用默认选项打开数据库
    pub fn open(path: &Path) -> Result<Self> {
        Ok(Self {
            root_path: path.to_owned(),
            param: serde_json::from_str::<Parameter>(&fs::read_to_string(
                path.join("param.json"),
            )?)?,
            block_head_db: DB::open_default(path.join("blk_head.db"))?,
            block_content_db: DB::open_default(path.join("block_content.db"))?,
            id_tree_db: DB::open_default(path.join("id_tree.db"))?,
            bplus_tree_db: DB::open_default(path.join("bplus_tree.db"))?,
            trie_db: DB::open_default(path.join("trie.db"))?,
            obj_db: DB::open_default(path.join("obj.db"))?,
        })
    }
}

/// 为不可变引用实现ReadInterface
///
/// ReadInterface提供了读取区块链数据的接口
impl ReadInterface for &SimChain {
    type K = u32;  // 键类型为u32

    /// 获取系统参数
    fn get_parameter(&self) -> Result<Parameter> {
        Ok(self.param.clone())
    }

    /// 读取指定高度的区块头
    fn read_block_head(&self, blk_height: Height) -> Result<BlockHead> {
        let data = self
            .block_head_db
            .get(blk_height.to_le_bytes())?  // 将高度转换为小端字节序作为键
            .context("failed to read block head")?;
        Ok(bincode::deserialize::<BlockHead>(&data[..])?)
    }

    /// 读取指定高度的区块内容
    fn read_block_content(&self, blk_height: Height) -> Result<BlockContent> {
        let data = self
            .block_content_db
            .get(blk_height.to_le_bytes())?
            .context("failed to read block content")?;
        Ok(bincode::deserialize::<BlockContent>(&data[..])?)
    }

    /// 读取ID树节点
    fn read_id_tree_node(&self, id_tree_node_id: IdTreeNodeId) -> Result<IdTreeNode> {
        let data = self
            .id_tree_db
            .get(id_tree_node_id.to_le_bytes())?
            .context("failed to read id tree node")?;
        Ok(bincode::deserialize::<IdTreeNode>(&data[..])?)
    }

    /// 读取B+树节点
    fn read_bplus_tree_node(
        &self,
        bplus_tree_node_id: BPlusTreeNodeId,
    ) -> Result<BPlusTreeNode<Self::K>> {
        let data = self
            .bplus_tree_db
            .get(bplus_tree_node_id.to_le_bytes())?
            .with_context(|| {
                format!(
                    "failed to read bplus tree node with id {:?}",
                    bplus_tree_node_id
                )
            })?;
        Ok(bincode::deserialize::<BPlusTreeNode<Self::K>>(&data[..])?)
    }

    /// 读取Trie树节点
    fn read_trie_node(&self, trie_node_id: TrieNodeId) -> Result<TrieNode> {
        let data = self
            .trie_db
            .get(trie_node_id.to_le_bytes())?
            .context("failed to read trie node")?;
        Ok(bincode::deserialize::<TrieNode>(&data[..])?)
    }

    /// 读取对象
    fn read_object(&self, obj_hash: Digest) -> Result<Object<Self::K>> {
        let data = self
            .obj_db
            .get(obj_hash.as_bytes())?  // 使用哈希值作为键
            .context("failed to read object")?;
        Ok(bincode::deserialize::<Object<Self::K>>(&data[..])?)
    }
}

/// 为可变引用实现ReadInterface
///
/// 此实现与不可变引用相同，允许通过可变引用进行读取操作
impl ReadInterface for &mut SimChain {
    type K = u32;
    fn get_parameter(&self) -> Result<Parameter> {
        Ok(self.param.clone())
    }
    fn read_block_head(&self, blk_height: Height) -> Result<BlockHead> {
        let data = self
            .block_head_db
            .get(blk_height.to_le_bytes())?
            .context("failed to read block head")?;
        Ok(bincode::deserialize::<BlockHead>(&data[..])?)
    }
    fn read_block_content(&self, blk_height: Height) -> Result<BlockContent> {
        let data = self
            .block_content_db
            .get(blk_height.to_le_bytes())?
            .context("failed to read block content")?;
        Ok(bincode::deserialize::<BlockContent>(&data[..])?)
    }
    fn read_id_tree_node(&self, id_tree_node_id: IdTreeNodeId) -> Result<IdTreeNode> {
        let data = self
            .id_tree_db
            .get(id_tree_node_id.to_le_bytes())?
            .context("failed to read id tree node")?;
        Ok(bincode::deserialize::<IdTreeNode>(&data[..])?)
    }
    fn read_bplus_tree_node(
        &self,
        bplus_tree_node_id: BPlusTreeNodeId,
    ) -> Result<BPlusTreeNode<Self::K>> {
        let data = self
            .bplus_tree_db
            .get(bplus_tree_node_id.to_le_bytes())?
            .with_context(|| {
                format!(
                    "failed to read bplus tree node with id {:?}",
                    bplus_tree_node_id
                )
            })?;
        Ok(bincode::deserialize::<BPlusTreeNode<Self::K>>(&data[..])?)
    }
    fn read_trie_node(&self, trie_node_id: TrieNodeId) -> Result<TrieNode> {
        let data = self
            .trie_db
            .get(trie_node_id.to_le_bytes())?
            .context("failed to read trie node")?;
        Ok(bincode::deserialize::<TrieNode>(&data[..])?)
    }
    fn read_object(&self, obj_hash: Digest) -> Result<Object<Self::K>> {
        let data = self
            .obj_db
            .get(obj_hash.as_bytes())?
            .context("failed to read object")?;
        Ok(bincode::deserialize::<Object<Self::K>>(&data[..])?)
    }
}

/// 为SimChain实现WriteInterface
///
/// WriteInterface提供了写入区块链数据的接口
impl WriteInterface for SimChain {
    type K = u32;

    /// 设置系统参数并保存到文件
    fn set_parameter(&mut self, param: &Parameter) -> Result<()> {
        self.param = param.clone();
        let data = serde_json::to_string_pretty(&self.param)?;
        fs::write(self.root_path.join("param.json"), data)?;
        Ok(())
    }

    /// 写入区块头
    fn write_block_head(&mut self, blk_height: Height, block_head: &BlockHead) -> Result<()> {
        let bytes = bincode::serialize(block_head)?;
        self.block_head_db.put(blk_height.to_le_bytes(), bytes)?;
        Ok(())
    }

    /// 写入区块内容
    fn write_block_content(
        &mut self,
        blk_height: Height,
        block_content: &BlockContent,
    ) -> Result<()> {
        let bytes = bincode::serialize(block_content)?;
        self.block_content_db.put(blk_height.to_le_bytes(), bytes)?;
        Ok(())
    }

    /// 写入ID树节点
    fn write_id_tree_node(&mut self, n_id: IdTreeNodeId, node: &IdTreeNode) -> Result<()> {
        let bytes = bincode::serialize(node)?;
        self.id_tree_db.put(n_id.to_le_bytes(), bytes)?;
        Ok(())
    }

    /// 写入B+树节点
    fn write_bplus_tree_node(
        &mut self,
        n_id: BPlusTreeNodeId,
        node: &BPlusTreeNode<Self::K>,
    ) -> Result<()> {
        let bytes = bincode::serialize(node)?;
        self.bplus_tree_db.put(n_id.to_le_bytes(), bytes)?;
        Ok(())
    }

    /// 写入Trie树节点
    fn write_trie_node(&mut self, n_id: TrieNodeId, node: &TrieNode) -> Result<()> {
        let bytes = bincode::serialize(node)?;
        self.trie_db.put(n_id.to_le_bytes(), bytes)?;
        Ok(())
    }

    /// 写入对象
    fn write_object(&mut self, obj_hash: Digest, obj: &Object<Self::K>) -> Result<()> {
        let bytes = bincode::serialize(obj)?;
        self.obj_db.put(obj_hash.as_bytes(), bytes)?;
        Ok(())
    }
}

/// 为可变引用实现WriteInterface
///
/// 与SimChain的实现相同，但通过引用操作
impl WriteInterface for &mut SimChain {
    type K = u32;
    fn set_parameter(&mut self, param: &Parameter) -> Result<()> {
        self.param = param.clone();
        let data = serde_json::to_string_pretty(&self.param)?;
        fs::write(self.root_path.join("param.json"), data)?;
        Ok(())
    }
    fn write_block_head(&mut self, blk_height: Height, block_head: &BlockHead) -> Result<()> {
        let bytes = bincode::serialize(block_head)?;
        self.block_head_db.put(blk_height.to_le_bytes(), bytes)?;
        Ok(())
    }
    fn write_block_content(
        &mut self,
        blk_height: Height,
        block_content: &BlockContent,
    ) -> Result<()> {
        let bytes = bincode::serialize(block_content)?;
        self.block_content_db.put(blk_height.to_le_bytes(), bytes)?;
        Ok(())
    }
    fn write_id_tree_node(&mut self, n_id: IdTreeNodeId, node: &IdTreeNode) -> Result<()> {
        let bytes = bincode::serialize(node)?;
        self.id_tree_db.put(n_id.to_le_bytes(), bytes)?;
        Ok(())
    }
    fn write_bplus_tree_node(
        &mut self,
        n_id: BPlusTreeNodeId,
        node: &BPlusTreeNode<Self::K>,
    ) -> Result<()> {
        let bytes = bincode::serialize(node)?;
        self.bplus_tree_db.put(n_id.to_le_bytes(), bytes)?;
        Ok(())
    }
    fn write_trie_node(&mut self, n_id: TrieNodeId, node: &TrieNode) -> Result<()> {
        let bytes = bincode::serialize(node)?;
        self.trie_db.put(n_id.to_le_bytes(), bytes)?;
        Ok(())
    }
    fn write_object(&mut self, obj_hash: Digest, obj: &Object<Self::K>) -> Result<()> {
        let bytes = bincode::serialize(obj)?;
        self.obj_db.put(obj_hash.as_bytes(), bytes)?;
        Ok(())
    }
}

/// 为不可变引用实现ScanQueryInterface
///
/// ScanQueryInterface提供了各种查询功能
impl ScanQueryInterface for &SimChain {
    type K = u32;

    /// 范围查询
    ///
    /// # 参数
    /// * `query` - 查询范围
    /// * `start_blk_height` - 起始区块高度
    /// * `end_blk_height` - 结束区块高度
    /// * `dim` - 查询维度
    ///
    /// # 返回值
    /// * 符合查询条件的对象哈希集合
    ///
    /// # 注意
    /// 此方法会遍历整个对象数据库，效率较低
    fn range_query(
        &self,
        query: Range<Self::K>,
        start_blk_height: Height,
        end_blk_height: Height,
        dim: usize,
    ) -> Result<HashSet<Digest>> {
        let mut res = HashSet::<Digest>::new();
        let db_iter = self.obj_db.iterator(rocksdb::IteratorMode::Start);

        // 遍历所有对象
        for (_key, val) in db_iter {
            let o = bincode::deserialize::<Object<u32>>(&val[..])?;

            // 检查对象是否在指定的区块高度范围内
            if o.blk_height <= end_blk_height && o.blk_height >= start_blk_height {
                // 获取指定维度的数值
                let o_num_val = if let Some(n) = o.num_data.get(dim) {
                    *n
                } else {
                    0  // 如果维度不存在，使用默认值0
                };

                // 检查数值是否在查询范围内
                if query.is_in_range(o_num_val) {
                    res.insert(o.to_digest());
                }
            }
        }
        Ok(res)
    }

    /// 关键词查询
    ///
    /// # 参数
    /// * `keyword` - 关键词
    /// * `start_blk_height` - 起始区块高度
    /// * `end_blk_height` - 结束区块高度
    ///
    /// # 返回值
    /// * 包含指定关键词的对象哈希集合
    fn keyword_query(
        &self,
        keyword: &str,
        start_blk_height: Height,
        end_blk_height: Height,
    ) -> Result<HashSet<Digest>> {
        let mut res = HashSet::<Digest>::new();
        let db_iter = self.obj_db.iterator(rocksdb::IteratorMode::Start);

        for (_key, val) in db_iter {
            let o = bincode::deserialize::<Object<u32>>(&val[..])?;

            if o.blk_height <= end_blk_height && o.blk_height >= start_blk_height {
                // 遍历对象的所有关键词
                for k in o.keyword_data.iter() {
                    if keyword == k {
                        res.insert(o.to_digest());
                    }
                }
            }
        }
        Ok(res)
    }

    /// 根查询（特定时间窗口查询）
    ///
    /// # 参数
    /// * `height` - 查询高度
    /// * `win_size` - 窗口大小
    ///
    /// # 返回值
    /// * 在指定窗口内的对象哈希集合
    ///
    /// # 注意
    /// 查询条件：对象高度 ≤ 查询高度，且对象高度 + 窗口大小 ≥ 查询高度 + 1
    fn root_query(&self, height: Height, win_size: u16) -> Result<HashSet<Digest>> {
        let mut res = HashSet::<Digest>::new();
        let db_iter = self.obj_db.iterator(rocksdb::IteratorMode::Start);

        for (_key, val) in db_iter {
            let o = bincode::deserialize::<Object<u32>>(&val[..])?;

            // 检查对象是否在时间窗口内
            if o.blk_height <= height && o.blk_height.0 + win_size as u32 >= height.0 + 1 {
                res.insert(o.to_digest());
            }
        }
        Ok(res)
    }

    /// 获取范围信息
    ///
    /// # 参数
    /// * `start_blk_height` - 起始区块高度
    /// * `end_blk_height` - 结束区块高度
    /// * `dim_num` - 维度数量
    ///
    /// # 返回值
    /// * 每个维度的数值范围（最小值到最大值）
    ///
    /// # 注意
    /// 返回的Vec中每个元素对应一个维度的范围
    #[allow(clippy::type_complexity)]
    fn get_range_info(
        &self,
        start_blk_height: Height,
        end_blk_height: Height,
        dim_num: usize,
    ) -> Result<Vec<Range<Self::K>>> {
        let mut num_ranges = Vec::<Range<Self::K>>::new();
        let db_iter = self.obj_db.iterator(rocksdb::IteratorMode::Start);

        // 初始化每个维度的范围（最小值初始为最大值，最大值初始为最小值）
        let mut num_range_scope = Vec::<(Self::K, Self::K)>::new();
        for _ in 0..dim_num {
            num_range_scope.push((std::u32::MAX, 0));
        }

        // 遍历所有对象，更新每个维度的范围
        for (_key, val) in db_iter {
            let o = bincode::deserialize::<Object<u32>>(&val[..])?;

            if o.blk_height <= end_blk_height && o.blk_height >= start_blk_height {
                let o_num_vals = o.num_data;

                for (i, num_val) in o_num_vals.iter().enumerate() {
                    if i < dim_num {
                        let lower_bound = &num_range_scope
                            .get(i)
                            .with_context(|| {
                                format!("Object does not have numerical value at dim {}", i)
                            })?
                            .0;
                        let upper_bound = &num_range_scope
                            .get(i)
                            .with_context(|| {
                                format!("Object does not have numerical value at dim {}", i)
                            })?
                            .1;

                        // 更新最小值和最大值
                        if num_val < lower_bound {
                            num_range_scope
                                .get_mut(i)
                                .with_context(|| {
                                    format!("Object does not have numerical value at dim {}", i)
                                })?
                                .0 = *num_val;
                        } else if num_val > upper_bound {
                            num_range_scope
                                .get_mut(i)
                                .with_context(|| {
                                    format!("Object does not have numerical value at dim {}", i)
                                })?
                                .1 = *num_val;
                        }
                    }
                }
            }
        }

        // 将范围元组转换为Range结构
        for (min, max) in num_range_scope {
            num_ranges.push(Range::new(min, max));
        }

        Ok(num_ranges)
    }

    /// 获取关键词信息
    ///
    /// # 参数
    /// * `start_blk_height` - 起始区块高度
    /// * `end_blk_height` - 结束区块高度
    ///
    /// # 返回值
    /// * 指定高度范围内的所有关键词集合
    fn get_keyword_info(
        &self,
        start_blk_height: Height,
        end_blk_height: Height,
    ) -> Result<HashSet<String>> {
        let mut res = HashSet::<String>::new();
        let db_iter = self.obj_db.iterator(rocksdb::IteratorMode::Start);

        for (_key, val) in db_iter {
            let o = bincode::deserialize::<Object<u32>>(&val[..])?;

            // 注意：这里使用了严格的小于和大于，与range_query不同
            if o.blk_height < end_blk_height && o.blk_height > start_blk_height {
                for k in o.keyword_data.iter() {
                    res.insert(k.to_string());
                }
            }
        }
        Ok(res)
    }

    /// 获取区块链信息
    ///
    /// # 返回值
    /// * (总对象数量, 最大区块高度)
    fn get_chain_info(&self) -> Result<(u32, u32)> {
        let db_iter = self.obj_db.iterator(rocksdb::IteratorMode::Start);
        let mut cur_height_num = 0;
        let mut total_num = 0;

        for (_key, val) in db_iter {
            let o = bincode::deserialize::<Object<u32>>(&val[..])?;

            // 更新最大区块高度
            if cur_height_num < o.blk_height.0 {
                cur_height_num = o.blk_height.0;
            }
            total_num += 1;
        }
        Ok((total_num, cur_height_num))
    }
}