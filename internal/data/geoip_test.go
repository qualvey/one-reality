package data

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestEmbeddedCountryMMDB(t *testing.T) {
	if !HasEmbeddedCountryMMDB() {
		t.Fatalf("内置 Country.mmdb 应该存在且非空")
	}

	bytes, err := GetEmbeddedCountryMMDB()
	if err != nil {
		t.Fatalf("获取内置 Country.mmdb 失败: %v", err)
	}
	if len(bytes) == 0 {
		t.Fatalf("内置 Country.mmdb 字节数据为空")
	}

	// 传入不存在的文件路径，应当自动回退使用内置 GeoIP 数据库
	reader, err := OpenGeoIPReader("non_existent_file.mmdb")
	if err != nil {
		t.Fatalf("使用内置 GeoIP 回退失败: %v", err)
	}
	defer reader.Close()

	// 验证查询能力 (8.8.8.8 -> GOOGLE / US)
	record, err := reader.Country(net.ParseIP("8.8.8.8"))
	if err != nil {
		t.Fatalf("查询 IP 8.8.8.8 失败: %v", err)
	}
	if record.Country.IsoCode == "" {
		t.Errorf("期望 8.8.8.8 IsoCode 非空")
	}

	// 验证查询国内 IP (114.114.114.114 -> CN)
	cnRecord, err := reader.Country(net.ParseIP("114.114.114.114"))
	if err != nil {
		t.Fatalf("查询 IP 114.114.114.114 失败: %v", err)
	}
	if cnRecord.Country.IsoCode != "CN" {
		t.Errorf("期望 114.114.114.114 为 CN，实际为: %s", cnRecord.Country.IsoCode)
	}
}

func TestOpenGeoIPReader_ExternalOverride(t *testing.T) {
	tempDir := t.TempDir()
	validBytes, err := GetEmbeddedCountryMMDB()
	if err != nil {
		t.Fatalf("获取内置数据失败: %v", err)
	}

	externalPath := filepath.Join(tempDir, "custom.mmdb")
	if err := os.WriteFile(externalPath, validBytes, 0644); err != nil {
		t.Fatalf("写入临时 mmdb 失败: %v", err)
	}

	reader, err := OpenGeoIPReader(externalPath)
	if err != nil {
		t.Fatalf("打开外部 mmdb 失败: %v", err)
	}
	defer reader.Close()

	record, err := reader.Country(net.ParseIP("1.1.1.1"))
	if err != nil {
		t.Fatalf("查询 1.1.1.1 失败: %v", err)
	}
	if record.Country.IsoCode == "" {
		t.Errorf("查询 1.1.1.1 结果为空")
	}
}
