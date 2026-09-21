// Package store 提供 quota-mcp 的存储层：SQLite（modernc 纯 Go，无 CGO）+ AES-256-GCM 加密。
//
// 密文格式：hex(12 字节 nonce) : hex(16 字节 tag) : hex(密文)。
// 主密钥来源：env QUOTA_MCP_MASTER_KEY（64 hex 字符）；未设置时由机器特征派生
// （同一台机器上可解密，换机器/换用户后旧密文读不出——生产请显式设置并备份）。
package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
)

func masterKey() []byte {
	if env := os.Getenv("QUOTA_MCP_MASTER_KEY"); env != "" {
		if key, err := hex.DecodeString(strings.TrimSpace(env)); err == nil && len(key) == 32 {
			return key
		}
	}
	hostname, _ := os.Hostname()
	hash := sha256.Sum256([]byte(hostname + "-quota-mcp-v1"))
	return hash[:]
}

// Encrypt 加密任意字符串（空串返回 nil）。
func Encrypt(plaintext string) *string {
	if plaintext == "" {
		return nil
	}
	block, err := aes.NewCipher(masterKey())
	if err != nil {
		return nil
	}
	// GCM 标准 nonce 长度是 12 字节（写成 16 会让 Seal/Open 直接 panic）
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil
	}
	sealed := aesgcm.Seal(nil, nonce, []byte(plaintext), nil)
	tag := sealed[len(sealed)-16:]
	ciphertext := sealed[:len(sealed)-16]
	result := hex.EncodeToString(nonce) + ":" + hex.EncodeToString(tag) + ":" + hex.EncodeToString(ciphertext)
	return &result
}

// Decrypt 解密；格式不对或密钥不匹配返回 nil。
func Decrypt(encrypted string) *string {
	if encrypted == "" {
		return nil
	}
	parts := strings.Split(encrypted, ":")
	if len(parts) != 3 {
		return nil
	}
	block, err := aes.NewCipher(masterKey())
	if err != nil {
		return nil
	}
	nonce, err := hex.DecodeString(parts[0])
	if err != nil || len(nonce) != 12 {
		return nil
	}
	tag, err := hex.DecodeString(parts[1])
	if err != nil || len(tag) != 16 {
		return nil
	}
	ciphertext, err := hex.DecodeString(parts[2])
	if err != nil {
		return nil
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil
	}
	plaintext, err := aesgcm.Open(nil, nonce, append(ciphertext, tag...), nil)
	if err != nil {
		return nil
	}
	result := string(plaintext)
	return &result
}
