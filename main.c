#include <stdio.h>
#include <stdint.h>

// 1. 算法常量定义
static const uint8_t SBOX[16] =
{
    0x0C, 0x05, 0x06, 0x0B, 0x09, 0x00, 0x0A, 0x0D,
    0x03, 0x0E, 0x0F, 0x08, 0x04, 0x07, 0x01, 0x02
};

// 逆 S 盒 (用于解密时逆转密钥更新中的 S 盒变换)
static const uint8_t INV_SBOX[16] =
{
    0x05, 0x0E, 0x0F, 0x08, 0x0C, 0x01, 0x02, 0x0D,
    0x0B, 0x04, 0x06, 0x03, 0x00, 0x07, 0x09, 0x0A
};

static const uint8_t ROUND_CONSTANTS[31] =
{
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x13, 0x23, 0x43, 0x83, 0x15, 0x25, 0x45, 0x85,
    0x16, 0x26, 0x46, 0x86, 0x1A, 0x2A, 0x4A, 0x8A,
    0x1C, 0x2C, 0x4C, 0x8C, 0x1F, 0x2F, 0x4F
};

// --- 工具函数 ---

static inline uint32_t rol32(uint32_t x, int n)
{
    return (x << n) | (x >> (32 - n));
}

static inline uint32_t ror32(uint32_t x, int n)
{
    return (x >> n) | (x << (32 - n));
}

static inline __uint128_t rol128(__uint128_t x, int n)
{
    return (x << n) | (x >> (128 - n));
}

static inline __uint128_t ror128(__uint128_t x, int n)
{
    return (x >> n) | (x << (128 - n));
}

// 32位字经过8个并行S盒
static uint32_t apply_sbox(uint32_t in)
{
    uint32_t out = 0;
    for (int i = 0; i < 8; i++)
    {
        out |= (uint32_t)SBOX[(in >> (i * 4)) & 0xF] << (i * 4);
    }
    return out;
}

// --- 核心功能函数 ---

// 密钥正向更新 (加密使用)
void key_update(__uint128_t *key, uint8_t rc)
{
    // 1) 循环左移 13 位
    *key = rol128(*key, 13);
    
    // 2) S盒作用于 k7...k4
    uint8_t nibble = (uint8_t)((*key >> 4) & 0xF);
    *key &= ~((__uint128_t)0xF << 4);
    *key |= ((__uint128_t)SBOX[nibble] << 4);
    
    // 3) 异或轮常数于 k63...k59
    *key ^= ((__uint128_t)(rc & 0x1F) << 59);
}

// 密钥逆向更新 (解密使用)
void key_update_inverse(__uint128_t *key, uint8_t rc)
{
    // 逆向操作顺序与加密相反
    
    // 1) 逆向异或轮常数 (异或的逆运算仍是异或)
    *key ^= ((__uint128_t)(rc & 0x1F) << 59);
    
    // 2) 逆向S盒作用于 k7...k4
    uint8_t nibble = (uint8_t)((*key >> 4) & 0xF);
    *key &= ~((__uint128_t)0xF << 4);
    *key |= ((__uint128_t)INV_SBOX[nibble] << 4);
    
    // 3) 循环右移 13 位
    *key = ror128(*key, 13);
}

// 加密函数
void lici_encrypt(uint32_t *L, uint32_t *R, __uint128_t key)
{
    for (int i = 0; i < 31; i++)
    {
        uint32_t kl = (uint32_t)((key >> 32) & 0xFFFFFFFF);
        uint32_t kr = (uint32_t)(key & 0xFFFFFFFF);

        uint32_t L_prime = apply_sbox(*L);
        
        // L_{i+1} = (L' ^ R_i ^ KR_i) <<< 3
        uint32_t next_L = rol32((L_prime ^ *R ^ kr), 3);
        // R_{i+1} = (L' ^ L_{i+1} ^ KL_i) >>> 7
        uint32_t next_R = ror32((L_prime ^ next_L ^ kl), 7);

        *L = next_L;
        *R = next_R;

        key_update(&key, ROUND_CONSTANTS[i]);
    }
}

// 解密函数
void lici_decrypt(uint32_t *L, uint32_t *R, __uint128_t key)
{
    __uint128_t round_keys[31];
    
    // 预计算所有轮密钥（因为解密需要从最后一轮密钥开始）
    for (int i = 0; i < 31; i++)
    {
        round_keys[i] = key;
        key_update(&key, ROUND_CONSTANTS[i]);
    }

    for (int i = 30; i >= 0; i--)
    {
        uint32_t kl = (uint32_t)((round_keys[i] >> 32) & 0xFFFFFFFF);
        uint32_t kr = (uint32_t)(round_keys[i] & 0xFFFFFFFF);

        // 逆向解算 L_prime 和原来的 L, R
        // 1. 从 R_{i+1} 推导 L_prime ^ L_{i+1}
        // R_{i+1} = (L' ^ L_{i+1} ^ KL_i) >>> 7  => (R_{i+1} <<< 7) ^ KL_i = L' ^ L_{i+1}
        uint32_t Lprime_xor_nextL = rol32(*R, 7) ^ kl;
        
        // 2. 得到 L_prime (因为 L_{i+1} 是已知的)
        uint32_t L_prime = Lprime_xor_nextL ^ (*L);
        
        // 3. 从 L_{i+1} 推导 R_i
        // L_{i+1} = (L' ^ R_i ^ KR_i) <<< 3 => (L_{i+1} >>> 3) ^ L' ^ KR_i = R_i
        uint32_t prev_R = ror32(*L, 3) ^ L_prime ^ kr;

        // 4. 从 L_prime 推导 L_i (LiCi 加密时左支 S 盒是可逆的，但这里直接用 L_prime 的逆推不方便)
        // 实际上在 Feistel 变体中，Li 是直接通过解出 S 盒得到的（LiCi 的 L_prime = Sbox(L_i)）
        // 我们需要一个逆 S 盒来还原 L
        uint32_t prev_L = 0;
        for (int j = 0; j < 8; j++)
        {
            prev_L |= (uint32_t)INV_SBOX[(L_prime >> (j * 4)) & 0xF] << (j * 4);
        }

        *L = prev_L;
        *R = prev_R;
    }
}

// --- 测试主函数 ---

int main()
{
    uint32_t L = 0x11223344;
    uint32_t R = 0x55667788;
    __uint128_t key = ((__uint128_t)0x0123456789ABCDEFULL << 64) | 0xFEDCBA9876543210ULL;

    printf("原始明文: L=%08X, R=%08X\n", L, R);

    lici_encrypt(&L, &R, key);
    printf("加密密文: L=%08X, R=%08X\n", L, R);

    lici_decrypt(&L, &R, key);
    printf("解密结果: L=%08X, R=%08X\n", L, R);

    return 0;
}