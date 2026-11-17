//! 选路算法策略（对齐 Go routing_policy.go）。
//!
//! 每个算法标识绑定一套完整策略：主排名键（rank）+ 是否启用粘滞滞回（sticky）
//! + 是否启用 WFQ 字节公平分摊（wfq）。"排名维度"与"稳定性/公平性"两个关注点
//! 被显式拆开，而不是混在一次排序里。

use crate::adaptive_multipath::service_us;

/// rankKey 是候选排名的度量维度。选路算法决定用哪个维度做主排名键。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RankKey {
    /// 去程稳定地板 + 本批服务时间（auto 默认）。
    OneWayPlusService,
    /// 去程稳定地板（decayed-min fwd）。
    OneWay,
    /// 内核 min_rtt 无拥塞地板的一半。
    MinRttHalf,
    /// 当前 SRTT 往返的一半。
    SrttHalf,
}

/// routingPolicy 描述一个选路算法的完整行为。
#[derive(Clone, Copy, Debug)]
pub struct RoutingPolicy {
    pub rank: RankKey,
    /// 单路径模式启用粘滞滞回（sticky slack）。
    pub sticky: bool,
    /// 活跃集内启用 WFQ 字节公平分摊。
    pub wfq: bool,
}

/// 选路层编码零点（µs）。原始相对量可为负（快于 ref 基准），而 Backend 的原子
/// 字段以 0 表示"未收敛"，故选路值按 raw+oneWayRankZeroUS 编码存储、读取时解码
/// 回有符号值。零点必须大于 |raw| 的可能上界：halfRef 受 probe_min_half_rtt_us
/// 配置上限 3_600_000µs 约束，故 raw ∈ [-3.6e6, +3.6e6]，取 4e6 保证编码值恒 >0，
/// 与未收敛哨兵（0）永不冲突。
pub const ONE_WAY_RANK_ZERO_US: i64 = 4_000_000;

#[inline]
pub fn one_way_rank_encode(raw_us: i64) -> u64 {
    (raw_us + ONE_WAY_RANK_ZERO_US) as u64
}

#[inline]
pub fn one_way_rank_decode(enc: u64) -> i64 {
    enc as i64 - ONE_WAY_RANK_ZERO_US
}

/// oneWayMode 是探针分解方向（对齐 Go client.go 的 oneWayMode* 常量）。
pub const ONE_WAY_MODE_ROUNDTRIP: i32 = 0;
pub const ONE_WAY_MODE_FWD: i32 = 1;
pub const ONE_WAY_MODE_RET: i32 = 2;

/// 把算法标识映射为 int32 码（0 = auto；未知值归一化为 0，与配置校验期拦截
/// 相配合，热路径零分配读取）。
pub fn routing_algo_code(algo: &str) -> i32 {
    match algo {
        "latency_strict" => 1,
        "latency_sticky" => 2,
        "min_rtt_strict" => 3,
        "min_rtt_adaptive" => 4,
        "roundtrip_strict" => 5,
        _ => 0,
    }
}

/// 把 int32 码映射为策略。未知码回退 auto（默认），保证配置热更前后行为不突变。
pub fn routing_policy_for_code(code: i32) -> RoutingPolicy {
    match code {
        1 => RoutingPolicy {
            rank: RankKey::OneWay,
            sticky: false,
            wfq: false,
        },
        2 => RoutingPolicy {
            rank: RankKey::OneWay,
            sticky: true,
            wfq: false,
        },
        3 => RoutingPolicy {
            rank: RankKey::MinRttHalf,
            sticky: false,
            wfq: false,
        },
        4 => RoutingPolicy {
            rank: RankKey::MinRttHalf,
            sticky: true,
            wfq: true,
        },
        5 => RoutingPolicy {
            rank: RankKey::SrttHalf,
            sticky: false,
            wfq: false,
        },
        _ => RoutingPolicy {
            rank: RankKey::OneWayPlusService,
            sticky: true,
            wfq: true,
        },
    }
}

/// 按策略计算候选的主排名键（µs，有符号）。
///
/// one_way 为探针分解的原始相对量（可为负：快于 ref 对称基准的方向），完全未测
/// 路径已折到参考 minRTT/2；rtt_us 为已归一化的 min_rtt（fairStart 路径取参考
/// minRTT），srtt_us 为原始 SRTT（未知时可能为 UNKNOWN_RTT_US 哨兵，仅观测用），
/// sched_rate 为调度速率。有符号保证快路径（负值）与慢路径的完整序参与 argmin
/// ——压非负会让快路径并列，选路退化（旧 subClamp 教训）。
pub fn candidate_rank_us(
    policy: RoutingPolicy,
    one_way: i64,
    rtt_us: u32,
    srtt_us: u32,
    incoming_bytes: u64,
    sched_rate: u64,
) -> i64 {
    match policy.rank {
        RankKey::OneWay => one_way,
        RankKey::MinRttHalf => (rtt_us as i64) / 2,
        RankKey::SrttHalf => (srtt_us as i64) / 2,
        RankKey::OneWayPlusService => {
            // 注意：incoming_bytes 与 sched_rate 对同批所有候选相同，此项是批内
            // 常数、对排序是空操作——auto 模式当前实际等价于 rankOneWay。若未来
            // sched_rate 改为 per-path 容量（按容量加权 WFQ），该项才有真实区分度。
            one_way + service_us(incoming_bytes, sched_rate) as i64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algo_code_maps_and_defaults_unknown() {
        assert_eq!(routing_algo_code("auto"), 0);
        assert_eq!(routing_algo_code("latency_strict"), 1);
        assert_eq!(routing_algo_code("latency_sticky"), 2);
        assert_eq!(routing_algo_code("min_rtt_strict"), 3);
        assert_eq!(routing_algo_code("min_rtt_adaptive"), 4);
        assert_eq!(routing_algo_code("roundtrip_strict"), 5);
        assert_eq!(routing_algo_code("bogus"), 0);
    }

    #[test]
    fn policy_matches_go_combinations() {
        // 1 latency_strict: rankOneWay, 无粘滞无 WFQ
        let p = routing_policy_for_code(1);
        assert_eq!(p.rank, RankKey::OneWay);
        assert!(!p.sticky && !p.wfq);
        // 4 min_rtt_adaptive: rankMinRTTHalf + sticky + wfq
        let p = routing_policy_for_code(4);
        assert_eq!(p.rank, RankKey::MinRttHalf);
        assert!(p.sticky && p.wfq);
        // auto 默认: rankOneWayPlusService + sticky + wfq
        let p = routing_policy_for_code(0);
        assert_eq!(p.rank, RankKey::OneWayPlusService);
        assert!(p.sticky && p.wfq);
        // 未知码回退 auto
        let p = routing_policy_for_code(99);
        assert_eq!(p.rank, RankKey::OneWayPlusService);
        assert!(p.sticky && p.wfq);
    }

    #[test]
    fn one_way_rank_round_trip() {
        // raw 可负（快于基准）：编码恒 >0，解码还原
        for raw in [-3_600_000i64, -1, 0, 1, 3_600_000] {
            let enc = one_way_rank_encode(raw);
            assert!(enc > 0, "编码值必须恒 >0，与未收敛哨兵 0 永不冲突");
            assert_eq!(one_way_rank_decode(enc), raw);
        }
    }

    #[test]
    fn candidate_rank_respects_signed_order() {
        // rankOneWay：负值（快路径）必须排在正值（慢路径）前，压非负会退化
        let p = routing_policy_for_code(1);
        let fast = candidate_rank_us(p, -500, 100_000, 100_000, 0, 25_000_000);
        let slow = candidate_rank_us(p, 500, 100_000, 100_000, 0, 25_000_000);
        assert!(fast < slow, "负 one-way 必须严格排在正 one-way 前");
    }
}
