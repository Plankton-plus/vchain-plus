use crate::{
    // 导入账户公私钥类型
    acc::{AccPublicKey, AccSecretKey},
    // 导入区块链相关类型
    chain::{block::Height, object::Object, query::query_param::QueryParam, traits::Num},
};
use anyhow::{ensure, Context, Error, Result};
use howlong::ProcessDuration;
use memmap2::Mmap; // 内存映射文件库
use rand::{CryptoRng, RngCore}; // 随机数生成库
use serde::{Deserialize, Serialize}; // 序列化/反序列化库
use snap::{read::FrameDecoder, write::FrameEncoder}; // 压缩库
use std::{
    collections::{BTreeMap, HashSet}, // 集合类型
    error::Error as StdError,
    fs, // 文件系统操作
    fs::File,
    io::{prelude::*, BufReader}, // IO操作
    path::{Path, PathBuf}, // 路径操作
    str::FromStr, // 字符串转换
};
use tracing_subscriber::EnvFilter; // 日志追踪过滤器

/// 宏：创建基于u32类型的ID结构体
/// 该宏会自动生成具有原子递增功能的ID类型
#[macro_export]
macro_rules! create_id_type_by_u32 {
    ($name: ident) => {
        /// 自动实现多个trait，包括序列化、显示等
        #[derive(
            Debug,
            Default,
            Copy,
            Clone,
            Eq,
            PartialEq,
            Ord,
            PartialOrd,
            Hash,
            serde::Serialize,
            serde::Deserialize,
            derive_more::Deref,      // 解引用
            derive_more::DerefMut,   // 可变解引用
            derive_more::Display,    // 显示
            derive_more::From,       // From trait
            derive_more::Into,       // Into trait
        )]
        pub struct $name(pub u32);

        impl $name {
            /// 获取下一个ID值（线程安全）
            pub fn next_id() -> Self {
                use core::sync::atomic::{AtomicU32, Ordering};
                static ID_CNT: AtomicU32 = AtomicU32::new(0);
                Self(ID_CNT.fetch_add(1, Ordering::SeqCst))
            }
        }
    };
}

/// 宏：创建基于u16类型的ID结构体
/// 该宏会自动生成具有原子递增功能的ID类型
#[macro_export]
macro_rules! create_id_type_by_u16 {
    ($name: ident) => {
        /// 自动实现多个trait，包括序列化、显示等
        #[derive(
            Debug,
            Default,
            Copy,
            Clone,
            Eq,
            PartialEq,
            Ord,
            PartialOrd,
            Hash,
            serde::Serialize,
            serde::Deserialize,
            derive_more::Deref,      // 解引用
            derive_more::DerefMut,   // 可变解引用
            derive_more::Display,    // 显示
            derive_more::From,       // From trait
            derive_more::Into,       // Into trait
        )]
        pub struct $name(pub u16);

        impl $name {
            /// 获取下一个ID值（线程安全）
            pub fn next_id() -> Self {
                use core::sync::atomic::{AtomicU16, Ordering};
                static ID_CNT: AtomicU16 = AtomicU16::new(0);
                Self(ID_CNT.fetch_add(1, Ordering::SeqCst))
            }
        }
    };
}

/// 从文件加载查询参数
///
/// # 参数
/// * `path` - 查询参数文件路径
///
/// # 返回值
/// 成功时返回QueryParams向量，失败时返回错误
///
pub fn load_query_param_from_file(path: &Path) -> Result<Vec<QueryParam<u32>>> {
    let data = fs::read_to_string(path)?;
    let query_params: Vec<QueryParam<u32>> = serde_json::from_str(&data)?;
    Ok(query_params)
}

/// 从文件加载原始对象数据
///
/// 输入格式: block_id sep [ v_data ] sep { w_data }
/// sep = \t 或空格
/// v_data = v_1 comma v_2 ...
/// w_data = w_1 comma w_2 ...
///
/// # 参数
/// * `path` - 数据文件路径
///
/// # 返回值
/// 按高度组织的对象集合，失败时返回错误
pub fn load_raw_obj_from_file<K, ParseErr>(path: &Path) -> Result<BTreeMap<Height, Vec<Object<K>>>>
where
    K: Num + FromStr<Err = ParseErr>,
    ParseErr: StdError + Sync + Send + 'static,
{
    let mut reader = BufReader::new(File::open(path)?);
    let mut buf = String::new();
    reader.read_to_string(&mut buf)?;
    load_raw_obj_from_str(&buf)
}

/// 从字符串加载原始对象数据
///
/// 输入格式: block_id sep [ v_data ] sep { w_data }
/// sep = \t 或空格
/// v_data = v_1 comma v_2 ...
/// w_data = w_1 comma w_2 ...
///
/// # 参数
/// * `input` - 包含对象数据的字符串
///
/// # 返回值
/// 按高度组织的对象集合，失败时返回错误
pub fn load_raw_obj_from_str<K, ParseErr>(input: &str) -> Result<BTreeMap<Height, Vec<Object<K>>>>
where
    K: Num + FromStr<Err = ParseErr>,
    ParseErr: StdError + Sync + Send + 'static,
{
    let mut res = BTreeMap::new();
    for line in input.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // 按'['和']'分割字符串，最多分割3部分
        let mut split_str = line.splitn(3, |c| c == '[' || c == ']');

        // 解析块高度
        let blk_height: Height = Height(
            split_str
                .next()
                .with_context(|| format!("failed to parse line {}", line))?
                .trim()
                .parse()?,
        );

        // 解析数值数据
        let v_data: Vec<K> = split_str
            .next()
            .with_context(|| format!("failed to parse line {}", line))?
            .trim()
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.parse::<K>().map_err(Error::from))
            .collect::<Result<_>>()?;

        // 解析关键词数据
        let w_data: HashSet<String> = split_str
            .next()
            .with_context(|| format!("failed to parse line {}", line))?
            .trim()
            .replace('{', "")
            .replace('}', "")
            .split(',')
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .collect();

        let raw_obj = Object::new(blk_height, v_data, w_data);
        res.entry(blk_height).or_insert_with(Vec::new).push(raw_obj);
    }
    Ok(res)
}

/// 公私钥对结构体
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct KeyPair {
    sk: AccSecretKey,     // 私钥
    pub pk: AccPublicKey, // 公钥（公开）
}

impl KeyPair {
    /// 生成新的密钥对
    ///
    /// # 参数
    /// * `q` - 用于密钥生成的参数
    /// * `rng` - 随机数生成器
    ///
    /// # 返回值
    /// 新生成的KeyPair实例
    pub fn gen(q: u64, mut rng: impl RngCore + CryptoRng) -> Self {
        let sk = AccSecretKey::rand(&mut rng);
        let sk_with_pow = sk.into();
        let pk = AccPublicKey::gen_key(&sk_with_pow, q);
        Self { sk, pk }
    }

    /// 将密钥对保存到指定路径
    ///
    /// # 参数
    /// * `path` - 保存路径
    ///
    /// # 返回值
    /// 成功时返回Ok(())，失败时返回错误
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        ensure!(!path.exists(), "{} already exists.", path.display());
        fs::create_dir_all(&path)?; // 创建目录
        let sk_f = File::create(&Self::sk_path(path))?; // 创建私钥文件
        bincode::serialize_into(sk_f, &self.sk)?; // 序列化私钥
        let pk_f = File::create(&Self::pk_path(path))?; // 创建公钥文件
        bincode::serialize_into(pk_f, &self.pk)?; // 序列化公钥
        Ok(())
    }

    /// 从指定路径加载密钥对
    ///
    /// # 参数
    /// * `path` - 加载路径
    ///
    /// # 返回值
    /// 成功时返回KeyPair实例，失败时返回错误
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let sk_file = File::open(Self::sk_path(path))?; // 打开私钥文件
        let sk_reader = BufReader::new(sk_file);
        let sk: AccSecretKey = bincode::deserialize_from(sk_reader)?; // 反序列化私钥
        let pk_file = File::open(Self::pk_path(path))?; // 打开公钥文件
        let pk_data = unsafe { Mmap::map(&pk_file) }?; // 使用内存映射读取公钥
        let pk: AccPublicKey = bincode::deserialize(&pk_data[..])?; // 反序列化公钥
        Ok(Self { sk, pk })
    }

    /// 获取私钥文件路径
    fn sk_path(path: &Path) -> PathBuf {
        path.join("sk")
    }

    /// 获取公钥文件路径
    fn pk_path(path: &Path) -> PathBuf {
        path.join("pk")
    }
}

/// 初始化tracing日志订阅者
///
/// # 参数
/// * `directives` - 日志过滤指令
///
/// # 返回值
/// 成功时返回Ok(())，失败时返回错误
pub fn init_tracing_subscriber(directives: &str) -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(directives));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .try_init()
        .map_err(Error::msg)
}

/// 查询时间统计结构体
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct QueryTime {
    pub(crate) stage1: Time, // 第一阶段耗时
    pub(crate) stage2: Time, // 第二阶段耗时
    pub(crate) stage3: Time, // 第三阶段耗时
    pub(crate) stage4: Time, // 第四阶段耗时
    pub(crate) total: Time,  // 总耗时
}

/// 时间统计结构体
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Time {
    real: u64, // 实际时间
    user: u64, // 用户态时间
    sys: u64,  // 系统态时间
}

impl From<ProcessDuration> for Time {
    /// 从ProcessDuration转换为Time
    fn from(p_duration: ProcessDuration) -> Self {
        Self {
            real: p_duration.real.as_micros() as u64,    // 转换为微秒
            user: p_duration.user.as_micros() as u64,    // 转换为微秒
            sys: p_duration.system.as_micros() as u64,   // 转换为微秒
        }
    }
}

/// 二进制编码函数
///
/// # 参数
/// * `value` - 需要编码的值
///
/// # 返回值
/// 编码后的字节数组，失败时返回错误
pub fn binary_encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut encoder = FrameEncoder::new(Vec::new()); // 创建压缩编码器
    bincode::serialize_into(&mut encoder, value).map_err(Error::msg)?; // 序列化并压缩
    Ok(encoder.into_inner()?) // 获取内部缓冲区
}

/// 二进制解码函数
///
/// # 参数
/// * `bytes` - 需要解码的字节数组
///
/// # 返回值
/// 解码后的值，失败时返回错误
pub fn binary_decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T> {
    let decoder = FrameDecoder::new(bytes); // 创建压缩解码器
    bincode::deserialize_from(decoder).map_err(Error::msg) // 解压并反序列化
}

#[cfg(test)]
mod tests {
    use super::KeyPair;
    use crate::{
        acc::{compute_set_operation_final, compute_set_operation_intermediate, AccValue, Op},
        chain::{
            block::Height,
            object::Object,
            query::query_plan::{QPKeywordNode, QPNode, QPUnion},
        },
        digest::Digestible,
        set,
        utils::{binary_decode, binary_encode, load_raw_obj_from_str},
    };
    use petgraph::Graph;
    use std::collections::BTreeMap;

    #[test]
    fn test_create_id() {
        create_id_type_by_u32!(TestId);
        assert_eq!(TestId::next_id(), TestId(0));
        assert_eq!(TestId::next_id(), TestId(1));
        assert_eq!(TestId::next_id(), TestId(2));
    }

    #[test]
    fn test_load_raw_obj() {
        let input = "1\t[1,2]\t{a,b}\n2 [ 3, 4 ] { c, d, }\n2\t[ 5, 6 ]\t { e }\n";
        let expect = {
            let mut exp: BTreeMap<Height, Vec<Object<u32>>> = BTreeMap::new();
            exp.insert(
                Height(1),
                vec![Object {
                    blk_height: Height(1),
                    num_data: vec![1, 2],
                    keyword_data: ["a".to_owned(), "b".to_owned()].iter().cloned().collect(),
                }],
            );
            exp.insert(
                Height(2),
                vec![
                    Object {
                        blk_height: Height(2),
                        num_data: vec![3, 4],
                        keyword_data: ["c".to_owned(), "d".to_owned()].iter().cloned().collect(),
                    },
                    Object {
                        blk_height: Height(2),
                        num_data: vec![5, 6],
                        keyword_data: ["e".to_owned()].iter().cloned().collect(),
                    },
                ],
            );
            exp
        };
        assert_eq!(load_raw_obj_from_str(&input).unwrap(), expect);
    }

    #[test]
    fn test_maintain_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");

        let q: u64 = 10;
        let rng = rand::thread_rng();
        let key_pair = KeyPair::gen(q, rng);
        key_pair.save(path.clone()).unwrap();

        let read_key_pair = KeyPair::load(&path).unwrap();
        assert_eq!(key_pair, read_key_pair);
    }

    #[test]
    fn test_petgraph_serialize() {
        let k1 = QPKeywordNode {
            blk_height: Height(0),
            set: None,
        };
        let k2 = QPKeywordNode {
            blk_height: Height(0),
            set: None,
        };
        let k3 = QPKeywordNode {
            blk_height: Height(0),
            set: None,
        };
        let k4 = QPKeywordNode {
            blk_height: Height(0),
            set: None,
        };
        let union = QPUnion { set: None };

        let mut qp_dag = Graph::<QPNode<u32>, bool>::new();
        let idx0 = qp_dag.add_node(QPNode::Keyword(Box::new(k1.clone())));
        let idx1 = qp_dag.add_node(QPNode::Keyword(Box::new(k2.clone())));
        let idx2 = qp_dag.add_node(QPNode::Keyword(Box::new(k3.clone())));
        let idx3 = qp_dag.add_node(QPNode::Keyword(Box::new(k4.clone())));
        let idx4 = qp_dag.add_node(QPNode::Union(union.clone()));
        let idx5 = qp_dag.add_node(QPNode::Union(union.clone()));
        let idx6 = qp_dag.add_node(QPNode::Union(union.clone()));

        qp_dag.add_edge(idx4, idx0, true);
        qp_dag.add_edge(idx4, idx1, false);
        qp_dag.add_edge(idx5, idx2, true);
        qp_dag.add_edge(idx5, idx3, false);
        qp_dag.add_edge(idx6, idx4, true);
        qp_dag.add_edge(idx6, idx5, false);

        let size_original = bincode::serialize(&qp_dag).unwrap().len();
        qp_dag.remove_node(idx0);
        qp_dag.remove_node(idx1);
        qp_dag.remove_node(idx2);
        qp_dag.remove_node(idx3);
        let size_update = bincode::serialize(&qp_dag).unwrap().len();
        println!("before: {}", size_original);
        println!("after: {}", size_update);
        assert_eq!(1, 1);
    }

    #[test]
    fn test_compress() {
        let value = String::from("hello world");
        let bin = binary_encode(&value).unwrap();
        assert_eq!(binary_decode::<String>(bin.as_ref()).unwrap(), value);
    }

    #[test]
    fn test_acc_size() {
        use crate::chain::tests::PUB_KEY;
        let set = set! {11, 12, 13, 14, 15, 16, 17, 19, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39};
        let acc = AccValue::from_set(&set, &PUB_KEY);
        let acc_size = bincode::serialize(&acc).unwrap().len();
        let dig = acc.to_digest();
        let dig_size = bincode::serialize(&dig).unwrap().len();
        assert_eq!(dig_size, 32);
        assert_eq!(acc_size, 416);
    }

    #[test]
    fn test_proof_size() {
        use crate::chain::tests::PUB_KEY;
        let set1 = set! {11, 17, 19, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30};
        let set2 = set! {12, 13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 33, 23, };
        let acc1 = AccValue::from_set(&set1, &PUB_KEY);
        let acc2 = AccValue::from_set(&set2, &PUB_KEY);
        let (_set, _acc, inter_proof) =
            compute_set_operation_intermediate(Op::Union, &set1, &acc1, &set2, &acc2, &PUB_KEY);
        let (_set, final_proof) = compute_set_operation_final(Op::Union, &set1, &set2, &PUB_KEY);
        let inter_size = bincode::serialize(&inter_proof).unwrap().len();
        let final_size = bincode::serialize(&final_proof).unwrap().len();
        assert_eq!(inter_size, 564);
        assert_eq!(final_size, 204);
    }

    use serde::{Deserialize, Serialize};
    #[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
    struct TestId(u8);
    #[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
    struct TestId2(u64);

    #[test]
    fn test_int_size() {
        let a: u8 = 1;
        let b: u32 = 1;
        let c: u64 = 1;
        let a_size = bincode::serialize(&a).unwrap().len();
        let b_size = bincode::serialize(&b).unwrap().len();
        let c_size = bincode::serialize(&c).unwrap().len();
        assert_eq!(a_size, 1);
        assert_eq!(b_size, 4);
        assert_eq!(c_size, 8);
        let a = TestId(1);
        let b = TestId2(1);
        let a_size = bincode::serialize(&a).unwrap().len();
        let b_size = bincode::serialize(&b).unwrap().len();
        assert_eq!(a_size, 1);
        assert_eq!(b_size, 8);

        let c = Some(b);
        let d: Option<TestId2> = None;
        let c_size = bincode::serialize(&c).unwrap().len();
        let d_size = bincode::serialize(&d).unwrap().len();
        assert_eq!(c_size, 9);
        assert_eq!(d_size, 1);
    }

    #[test]
    fn test_str_size() {
        let a: smol_str::SmolStr = smol_str::SmolStr::from("");
        let str_size = bincode::serialize(&a).unwrap().len();
        assert_eq!(str_size, 8);
        let a: String = String::from("");
        let str_size = bincode::serialize(&a).unwrap().len();
        assert_eq!(str_size, 8);
        let a = String::from("53c79113311e8a8ec291d412d1572516d0356a5c3aced0b108e0ad04c440de78");
        let str_size = bincode::serialize(&a).unwrap().len();
        assert_eq!(str_size, 72);
        let a = smol_str::SmolStr::from(
            "53c79113311e8a8ec291d412d1572516d0356a5c3aced0b108e0ad04c440de78",
        );
        let str_size = bincode::serialize(&a).unwrap().len();
        assert_eq!(str_size, 72);
    }
}




