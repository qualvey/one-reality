package data

import (
	"fmt"
	"os"
	"strings"

	"github.com/oschwald/geoip2-golang"
)

// GetEmbeddedCountryMMDB 获取内嵌的 Country.mmdb 字节数据
func GetEmbeddedCountryMMDB() ([]byte, error) {
	content, err := assetsFS.ReadFile("assets/Country.mmdb")
	if err != nil {
		return nil, fmt.Errorf("读取内置 GeoIP 资产 assets/Country.mmdb 失败: %w", err)
	}
	return content, nil
}

// HasEmbeddedCountryMMDB 判断当前构建中是否已内嵌 Country.mmdb
func HasEmbeddedCountryMMDB() bool {
	data, err := GetEmbeddedCountryMMDB()
	return err == nil && len(data) > 0
}

// OpenGeoIPReader 打开 GeoIP 国家数据库 Reader。
// 优先按顺序尝试传入的 candidatePaths 文件路径（若未传入则默认探测 "data/Country.mmdb" 与 "Country.mmdb"）；
// 若外部文件均不存在或无法成功打开，自动回退使用编译时内嵌的 Country.mmdb。
func OpenGeoIPReader(candidatePaths ...string) (*geoip2.Reader, error) {
	paths := candidatePaths
	if len(paths) == 0 {
		paths = []string{"data/Country.mmdb", "Country.mmdb"}
	}

	for _, p := range paths {
		trimmed := strings.TrimSpace(p)
		if trimmed == "" {
			continue
		}
		if fi, err := os.Stat(trimmed); err == nil && !fi.IsDir() {
			if reader, err := geoip2.Open(trimmed); err == nil {
				return reader, nil
			}
		}
	}

	// 回退使用内置内嵌版本
	data, err := GetEmbeddedCountryMMDB()
	if err != nil {
		return nil, fmt.Errorf("外部 GeoIP 数据库不可用且加载内置 Country.mmdb 失败: %w", err)
	}

	reader, err := geoip2.FromBytes(data)
	if err != nil {
		return nil, fmt.Errorf("解析内置 Country.mmdb 失败: %w", err)
	}

	return reader, nil
}
