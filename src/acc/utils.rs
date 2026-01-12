// 引入arkworks库中的椭圆曲线投影坐标系相关类型
use ark_ec::ProjectiveCurve;
// 引入arkworks库中的有限域相关类型，包括大整数和素域参数
use ark_ff::{BigInteger, FpParameters, PrimeField};


// Ref: https://github.com/blynn/pbc/blob/fbf4589036ce4f662e2d06905862c9e816cf9d08/arith/field.c#L251-L330
// 固定基点椭圆曲线幂运算结构体，用于优化椭圆曲线标量乘法运算
// 使用滑动窗口算法提高计算效率
pub struct FixedBaseCurvePow<G: ProjectiveCurve> {
    table: Vec<Vec<G>>,  // 预计算表，存储预计算的点倍数结果
}

impl<G: ProjectiveCurve> FixedBaseCurvePow<G> {
    // 滑动窗口大小，每次处理5个比特位
    const K: usize = 5;

    // 构建固定基点幂运算表的方法
    pub fn build(base: &G) -> Self {
        // 获取标量域的模数位数，用于确定需要多少位来表示一个标量
        let bits =
            <<G as ProjectiveCurve>::ScalarField as PrimeField>::Params::MODULUS_BITS as usize;

        // 计算需要多少个查找块
        let num_lookups = bits / Self::K + 1;

        // 每个查找块的大小（减去1是因为我们从1开始计数，而不是0）
        let lookup_size = (1 << Self::K) - 1;

        // 最后一个查找块的大小（因为总位数可能不能被K整除）
        let last_lookup_size = (1 << (bits - (num_lookups - 1) * Self::K)) - 1;

        // 初始化预计算表
        let mut table: Vec<Vec<G>> = Vec::with_capacity(num_lookups);

        // 用基点初始化乘数
        let mut multiplier = *base;

        // 为每个查找块构建子表
        for i in 0..num_lookups {
            // 确定当前查找块的大小（最后一个块可能较小）
            let table_size = if i == num_lookups - 1 {
                last_lookup_size
            } else {
                lookup_size
            };

            // 使用unfold迭代器创建当前查找块的子表
            // unfold会重复执行闭包操作，生成连续的倍数点
            let sub_table: Vec<G> = itertools::unfold(multiplier, |last| {
                let ret = *last;           // 返回当前值
                last.add_assign(&multiplier);  // 将当前值更新为其两倍
                Some(ret)                  // 返回Some包含的值
            })
                .take(table_size)              // 只取指定数量的元素
                .collect();                    // 收集为Vec

            table.push(sub_table);         // 将子表添加到主表中

            // 如果不是最后一个查找块，则更新乘数为当前子表的最后一个值
            if i != num_lookups - 1 {
                let last = *table
                    .last()
                    .expect("cannot access table last")      // 安全检查：获取最后的子表
                    .last()
                    .expect("cannot access last");           // 安全检查：获取子表最后一个元素
                multiplier.add_assign(&last);                 // 更新乘数
            }
        }
        Self { table }                   // 返回新构建的FixedBaseCurvePow实例
    }

    // 应用预计算表进行标量乘法运算的方法
    pub fn apply(&self, input: &<G as ProjectiveCurve>::ScalarField) -> G {
        let mut res = G::zero();         // 初始化结果为无穷远点（加法单位元）

        // 将输入标量转换为内部表示形式
        let input_repr = input.into_repr();

        // 计算需要多少个查找块来处理输入标量
        let num_lookups = input_repr.num_bits() as usize / Self::K + 1;

        // 遍历每个查找块
        for i in 0..num_lookups {
            let mut word: usize = 0;     // 初始化当前查找块对应的数值

            // 读取K位比特，组成一个word
            for j in 0..Self::K {
                if input_repr.get_bit(i * Self::K + j) {      // 检查第(i*K+j)位是否为1
                    word |= 1 << j;                           // 如果是1，则设置word的第j位
                }
            }

            // 如果word不为0（即至少有一个比特位为1），则添加对应的预计算值到结果中
            if word > 0 {
                res.add_assign(&self.table[i][word - 1]);     // 从预计算表中查找并累加
            }
        }
        res                               // 返回最终结果
    }
}


// 固定基点标量幂运算结构体，用于优化有限域中的幂运算
// 与FixedBaseCurvePow类似，但针对标量乘法而非椭圆曲线点乘法
pub struct FixedBaseScalarPow<F: PrimeField> {
    table: Vec<Vec<F>>,   // 预计算表，存储预计算的幂次结果
}

impl<F: PrimeField> FixedBaseScalarPow<F> {
    // 滑动窗口大小，每次处理8个比特位（比曲线版本更大）
    const K: usize = 8;

    // 构建固定基点标量幂运算表的方法
    pub fn build(base: &F) -> Self {
        // 获取标量域的模数位数
        let bits = <F as PrimeField>::Params::MODULUS_BITS as usize;

        // 计算需要多少个查找块
        let num_lookups = bits / Self::K + 1;

        // 每个查找块的大小
        let lookup_size = (1 << Self::K) - 1;

        // 最后一个查找块的大小
        let last_lookup_size = (1 << (bits - (num_lookups - 1) * Self::K)) - 1;

        // 初始化预计算表
        let mut table: Vec<Vec<F>> = Vec::with_capacity(num_lookups);

        // 用基点初始化乘数
        let mut multiplier = *base;

        // 为每个查找块构建子表
        for i in 0..num_lookups {
            // 确定当前查找块的大小
            let table_size = if i == num_lookups - 1 {
                last_lookup_size
            } else {
                lookup_size
            };

            // 使用unfold迭代器创建当前查找块的子表
            // 与曲线版本不同的是，这里使用mul_assign（乘法）而非add_assign（加法）
            let sub_table: Vec<F> = itertools::unfold(multiplier, |last| {
                let ret = *last;             // 返回当前值
                last.mul_assign(&multiplier); // 将当前值更新为其平方
                Some(ret)                    // 返回Some包含的值
            })
                .take(table_size)
                .collect();
            table.push(sub_table);

            // 如果不是最后一个查找块，则更新乘数为当前子表的最后一个值
            if i != num_lookups - 1 {
                let last = *table
                    .last()
                    .expect("cannot access table last")
                    .last()
                    .expect("cannot access last");
                multiplier.mul_assign(&last);  // 使用乘法而非加法
            }
        }
        Self { table }                     // 返回新构建的FixedBaseScalarPow实例
    }

    // 应用预计算表进行幂运算的方法
    pub fn apply(&self, input: &F) -> F {
        let mut res = F::one();           // 初始化结果为1（乘法单位元）

        // 将输入转换为内部表示形式
        let input_repr = input.into_repr();

        // 计算需要多少个查找块来处理输入
        let num_lookups = input_repr.num_bits() as usize / Self::K + 1;

        // 遍历每个查找块
        for i in 0..num_lookups {
            let mut word: usize = 0;      // 初始化当前查找块对应的数值

            // 读取K位比特，组成一个word
            for j in 0..Self::K {
                if input_repr.get_bit(i * Self::K + j) {       // 检查第(i*K+j)位是否为1
                    word |= 1 << j;                             // 如果是1，则设置word的第j位
                }
            }

            // 如果word不为0，则乘以对应的预计算值
            if word > 0 {
                res.mul_assign(&self.table[i][word - 1]);       // 从预计算表中查找并相乘
            }
        }
        res                                // 返回最终结果
    }
}


// 条件编译：只有在测试模式下才包含以下代码
#[cfg(test)]
mod tests {
    use super::*;                                    // 导入外部作用域的所有公共项
    use ark_bn254::{Fr, G1Projective, G2Projective}; // 导入BN254曲线的具体实现
    use ark_ff::Field;                               // 导入Field trait
    use core::ops::MulAssign;                        // 导入乘法赋值trait
    use rand::Rng;                                   // 导入随机数生成器trait

    // 测试G1群上的幂运算
    #[test]
    fn test_pow_g1() {
        // 构建基于G1生成元的固定基点幂运算表
        let g1p = FixedBaseCurvePow::build(&G1Projective::prime_subgroup_generator());

        // 创建随机数生成器
        let mut rng = rand::thread_rng();

        // 生成随机标量
        let num: Fr = rng.gen();

        // 手动计算期望结果（标准的椭圆曲线标量乘法）
        let mut expect = G1Projective::prime_subgroup_generator();
        expect.mul_assign(num);

        // 断言自定义算法的结果与标准算法结果相同
        assert_eq!(g1p.apply(&num), expect);
    }

    // 测试G2群上的幂运算
    #[test]
    fn test_pow_g2() {
        // 构建基于G2生成元的固定基点幂运算表
        let g2p = FixedBaseCurvePow::build(&G2Projective::prime_subgroup_generator());

        // 创建随机数生成器
        let mut rng = rand::thread_rng();

        // 生成随机标量
        let num: Fr = rng.gen();

        // 手动计算期望结果
        let mut expect = G2Projective::prime_subgroup_generator();
        expect.mul_assign(num);

        // 断言结果一致
        assert_eq!(g2p.apply(&num), expect);
    }

    // 测试有限域上的幂运算
    #[test]
    fn test_pow_fr() {
        // 创建随机数生成器
        let mut rng = rand::thread_rng();

        // 生成随机底数和指数
        let base: Fr = rng.gen();
        let num: Fr = rng.gen();

        // 构建基于给定底数的固定基点标量幂运算表
        let frp = FixedBaseScalarPow::build(&base);

        // 使用标准算法计算期望结果
        let expect = base.pow(num.into_repr());

        // 断言自定义算法的结果与标准算法结果相同
        assert_eq!(frp.apply(&num), expect);
    }
}