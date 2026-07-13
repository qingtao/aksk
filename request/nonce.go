// Package request 包含http请求的头部常量和构造函数
package request

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/coocood/freecache"
)

const (
	// DefaultNonceMinLength nonce最小长度
	DefaultNonceMinLength = 16
	// DefaultNonceMaxLength nonce最大长度
	DefaultNonceMaxLength = 64
	// DefaultNonceTTL nonce默认过期时间, 应与 core.Auth 的 acceptableSkew(默认 60s)保持一致:
	// 防重放窗口必须覆盖请求时间戳的有效窗口, 否则会出现"时间戳仍有效但 nonce 已过期"的空窗, 可被重放
	DefaultNonceTTL = 60 * time.Second
	// DefaultNonceCacheSize 默认nonce缓存最大条目数(硬上限, 防溢出)
	DefaultNonceCacheSize = 1024 * 1024
)

// NonceStore nonce存储接口, 用于防重放攻击
type NonceStore interface {
	// GenerateNonce 生成符合长度要求的随机nonce字符串
	GenerateNonce() (string, error)
	// Check 校验nonce合法性并存储, ak为访问密钥标识, nonce为待校验的随机字符串
	// 检查项: 非空、长度范围、未被使用过; 通过后存储nonce
	Check(ak, nonce string) error
}

// MemoryStore 基于 freecache 的进程内 nonce 存储, 低 GC 压力, 具有容量硬上限(防溢出)
// 与 TTL 主动过期能力。
//
// 限制:
//   - 仅适用于单实例部署; 多实例(水平扩展)下各实例缓存相互独立,
//     攻击者向不同实例重放即可绕过防重放, 需改用共享存储(如 Redis)。
//   - freecache 按最大条目数上限 + LRU 淘汰; 当写入达到上限时会淘汰最久未使用的条目,
//     因此极端高负载下仍可能提前删除尚未过期的 nonce(缩短防重放窗口)。
//     过期由 freecache 按 TTL 主动清理, 正常流量下 nonce 在 TTL 后自动失效。
//     建议按业务流量规划 DefaultNonceCacheSize/WithCacheSize, 使容量足以容纳一个 TTL 周期内的请求量。
type MemoryStore struct {
	cache  *freecache.Cache
	mu     sync.Mutex // 保护 Check 中 exists 与 store 的 check-and-set 临界区, 消除 TOCTOU 竞态
	minLen int
	maxLen int
	ttl    time.Duration
}

// MemoryStoreOption 配置MemoryStore的选项函数
type MemoryStoreOption func(*MemoryStore)

// WithCacheSize 设置缓存最大条目数(硬上限, 用于防溢出), 建议足以容纳一个 TTL 周期内的请求量
func WithCacheSize(size int) MemoryStoreOption {
	return func(s *MemoryStore) {
		if size > 0 {
			s.cache = freecache.NewCache(size)
		}
	}
}

// WithMinLen 设置nonce最小长度
func WithMinLen(n int) MemoryStoreOption {
	return func(s *MemoryStore) {
		if n > 0 {
			s.minLen = n
		}
	}
}

// WithMaxLen 设置nonce最大长度
func WithMaxLen(n int) MemoryStoreOption {
	return func(s *MemoryStore) {
		if n > 0 {
			s.maxLen = n
		}
	}
}

// WithTTL 设置nonce过期时间,最小10秒
func WithTTL(d time.Duration) MemoryStoreOption {
	return func(s *MemoryStore) {
		if d > 10 {
			s.ttl = d
		}
	}
}

// NewMemoryStore 创建 freecache nonce 存储。
//
// nonce 按 ak 隔离存储, 缓存 key 格式为 "ak:nonce", 由 freecache 按 TTL 主动过期。
//
// 默认值: cacheSize(最大条目数)=1,048,576, minLen=16, maxLen=64, ttl=60秒(与 core.Auth 的 acceptableSkew 一致)。
// 建议按流量规划 cacheSize, 使容量足以容纳一个 TTL 周期内的请求量, 避免 LRU 提前淘汰。
func NewMemoryStore(opts ...MemoryStoreOption) *MemoryStore {
	s := &MemoryStore{
		minLen: DefaultNonceMinLength,
		maxLen: DefaultNonceMaxLength,
		ttl:    DefaultNonceTTL,
	}
	for _, opt := range opts {
		opt(s)
	}
	// 仅在未通过 WithCacheSize 指定时才创建默认缓存,
	// 避免先创建默认缓存再被覆盖导致 freecache 资源泄漏
	if s.cache == nil {
		s.cache = freecache.NewCache(DefaultNonceCacheSize)
	}
	return s
}

// nonceKey 构建ak+nonce的缓存key
func nonceKey(ak, nonce string) []byte {
	return []byte(ak + ":" + nonce)
}

// store 存储nonce, 过期由 freecache 按 ttl 主动清理; value 仅作存在性标记。
// 若 nonce 已存在(尚未过期)则返回错误; Check 已在锁内做过 exists 判断, 此处为防御性重复检查
func (s *MemoryStore) store(ak, nonce string) error {
	key := nonceKey(ak, nonce)
	if _, err := s.cache.Get(key); err == nil {
		return errors.New("nonce already exists")
	}
	// Set 的第三个参数为秒级 TTL; ttl 至少为 10 秒
	expireSeconds := max(int(s.ttl.Seconds()), 10)
	if err := s.cache.Set(key, []byte{1}, expireSeconds); err != nil {
		return err
	}
	return nil
}

// exists 检查nonce在指定ak下是否存在; 已过期的条目由 freecache 自动判为不存在
func (s *MemoryStore) exists(ak, nonce string) (bool, error) {
	key := nonceKey(ak, nonce)
	if _, err := s.cache.Get(key); err == nil {
		return true, nil
	} else if err != freecache.ErrNotFound {
		return false, err
	}
	return false, nil
}

func (s *MemoryStore) MinLen() int        { return s.minLen }
func (s *MemoryStore) MaxLen() int        { return s.maxLen }
func (s *MemoryStore) TTL() time.Duration { return s.ttl }

// SetTTL 设置 nonce 过期时间, 用于与 core.Auth 的 acceptableSkew 保持一致
func (s *MemoryStore) SetTTL(d time.Duration) {
	if d > 0 {
		s.ttl = d
	}
}

// GenerateNonce 生成符合长度要求的随机nonce字符串
func (s *MemoryStore) GenerateNonce() (string, error) {
	nonce, err := s.generateNonce()
	if err != nil {
		return "", err
	}
	if err := s.validateNonceLength(nonce); err != nil {
		return "", err
	}
	return nonce, nil
}

// generateNonce 生成安全随机nonce, hex编码, 字符串长度为maxLen
func (s *MemoryStore) generateNonce() (string, error) {
	byteLen := s.maxLen / 2
	if byteLen < 8 {
		byteLen = 8
	}
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// validateNonceLength 验证nonce长度
func (s *MemoryStore) validateNonceLength(nonce string) error {
	l := len(nonce)
	if l < s.minLen {
		return errors.New("nonce too short")
	}
	if l > s.maxLen {
		return errors.New("nonce too long")
	}
	return nil
}

// Check 校验nonce合法性并存储
func (s *MemoryStore) Check(ak, nonce string) error {
	if nonce == "" {
		return errors.New("nonce is empty")
	}
	if err := s.validateNonceLength(nonce); err != nil {
		return fmt.Errorf("nonce length invalid: %w", err)
	}
	// 在锁内完成 检查是否存在 + 写入, 保证 check-and-set 的原子性,
	// 避免并发请求携带相同 nonce 时因 exists 与 store 之间非原子而同时通过
	s.mu.Lock()
	defer s.mu.Unlock()
	exists, err := s.exists(ak, nonce)
	if err != nil {
		return fmt.Errorf("check nonce error: %w", err)
	}
	if exists {
		return errors.New("nonce already used")
	}
	if err := s.store(ak, nonce); err != nil {
		return fmt.Errorf("store nonce error: %w", err)
	}
	return nil
}
