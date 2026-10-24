package data

import (
	"embed"
	"fmt"
	"io"
	"os"
)

//go:embed assets/*
var assetsFS embed.FS

// OpenRuleReader 打开规则读取器：优先读取用户指定的外部文件，若不存在则回退至内嵌 assets 资源。
// path: 外部文件路径（如 "data/cdn_keywords.txt"）
// assetName: assets 目录下的内嵌文件名（如 "cdn_keywords.txt"）
func OpenRuleReader(path string, assetName string) (io.ReadCloser, error) {
	if path != "" {
		if file, err := os.Open(path); err == nil {
			return file, nil
		}
	}

	file, err := assetsFS.Open("assets/" + assetName)
	if err != nil {
		return nil, fmt.Errorf("打开内置规则资产 assets/%s 失败: %w", assetName, err)
	}
	return file, nil
}

// LoadRuleData 读取规则数据：优先从外部文件读取，若不存在则从内置 assets 读取为字节切片。
func LoadRuleData(path string, assetName string) ([]byte, error) {
	if path != "" {
		if _, err := os.Stat(path); err == nil {
			return os.ReadFile(path)
		}
	}

	content, err := assetsFS.ReadFile("assets/" + assetName)
	if err != nil {
		return nil, fmt.Errorf("读取内置规则资产 assets/%s 失败: %w", assetName, err)
	}
	return content, nil
}
