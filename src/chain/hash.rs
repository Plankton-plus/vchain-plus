// 引入必要的依赖和模块
use crate::{
    chain::{
        block::Height,    // 区块高度类型
        range::Range,     // 范围类型，用于表示数值区间
        traits::Num,      // 数值类型特性，确保类型支持数值操作
    },
    digest::{
        blake2,           // BLAKE2哈希函数构造器
        concat_digest,    // 连接多个摘要的函数
        Digest,           // 哈希摘要类型
        Digestible,       // 可摘要特性，用于计算哈希
    },
};
use std::collections::HashSet;  // 哈希集合，用于存储唯一的关键词

/// 计算范围(Range)的哈希值
///
/// # 参数
/// - `range`: 要计算哈希的范围对象，包含低值和高值
///
/// # 返回值
/// - `Digest`: 范围的哈希摘要
///
/// # 算法
/// 1. 创建BLAKE2哈希状态
/// 2. 将范围的低值转换为哈希并更新到状态
/// 3. 将范围的高值转换为哈希并更新到状态
/// 4. 计算最终哈希值
///
/// # 注意
/// - `#[inline]`: 提示编译器尝试内联此函数，减少函数调用开销
/// - `pub(crate)`: 只在当前crate内可见，外部模块无法访问
#[inline]
pub(crate) fn range_hash<K: Num>(range: &Range<K>) -> Digest {
    // 创建BLAKE2哈希算法的状态机
    let mut state = blake2().to_state();

    // 更新哈希状态：添加范围低值的哈希
    // get_low()返回范围的最小值，to_digest()将其转换为哈希，as_bytes()获取哈希字节
    state.update(range.get_low().to_digest().as_bytes());

    // 更新哈希状态：添加范围高值的哈希
    state.update(range.get_high().to_digest().as_bytes());

    // 计算最终哈希并包装为Digest类型
    Digest::from(state.finalize())
}

/// 计算对象(Object)的哈希值
///
/// # 参数
/// - `blk_height`: 对象所在区块的高度
/// - `num_data`: 对象的数值数据切片（如年龄、价格等数值属性）
/// - `keyword_data`: 对象的关键词集合（如标签、分类等文本属性）
///
/// # 返回值
/// - `Digest`: 对象的完整哈希摘要
///
/// # 算法
/// 1. 创建BLAKE2哈希状态
/// 2. 添加区块高度（小端字节序）到哈希
/// 3. 计算所有数值数据的合并哈希并添加到状态
/// 4. 对关键词排序后计算合并哈希并添加到状态
/// 5. 计算最终哈希值
///
/// # 注意
/// - 关键词需要排序以确保确定性：无论输入顺序如何，相同的关键词集合产生相同的哈希
/// - 使用小端字节序存储区块高度，这是计算机中常见的字节序
#[inline]
pub(crate) fn object_hash<K: Num>(
    blk_height: Height,           // 区块高度
    num_data: &[K],               // 数值数据切片引用
    keyword_data: &HashSet<String>, // 关键词集合引用
) -> Digest {
    // 创建BLAKE2哈希状态
    let mut state = blake2().to_state();

    // 步骤1: 添加区块高度信息
    // to_le_bytes()将高度转换为小端字节序的字节数组
    state.update(&blk_height.to_le_bytes());

    // 步骤2: 计算数值数据的哈希
    // num_data.iter().map(|n| n.to_digest()): 将每个数值转换为哈希
    // concat_digest(): 将所有哈希连接后再哈希，得到单个摘要
    // 更新到哈希状态
    let num_hash = concat_digest(num_data.iter().map(|n| n.to_digest()));
    state.update(&num_hash.0);  // .0访问Digest的内部字节数组

    // 步骤3: 计算关键词数据的哈希
    // 首先将HashSet转换为Vec以便排序
    let mut keywords: Vec<_> = keyword_data.iter().collect();

    // 对关键词进行排序以确保确定性哈希
    // sort_unstable()比sort()更快但不保持相等元素的相对顺序（这里不需要）
    keywords.sort_unstable();

    // 计算排序后关键词的合并哈希
    let keyword_hash = concat_digest(keywords.iter().map(|w| w.to_digest()));
    state.update(&keyword_hash.0);

    // 计算最终哈希
    Digest::from(state.finalize())
}