package data

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEmbeddedRulesAvailable(t *testing.T) {
	assets := []string{"cdn_keywords.txt", "hot_websites.txt", "exclude_rules.txt"}

	for _, asset := range assets {
		data, err := LoadRuleData("", asset)
		if err != nil {
			t.Fatalf("内置规则 %s 读取失败: %v", asset, err)
		}
		if len(data) == 0 {
			t.Errorf("内置规则 %s 内容为空", asset)
		}

		reader, err := OpenRuleReader("non_existent_path.txt", asset)
		if err != nil {
			t.Fatalf("回退内置规则 %s 失败: %v", asset, err)
		}
		defer reader.Close()

		buf, err := io.ReadAll(reader)
		if err != nil {
			t.Fatalf("读取内置规则流失败: %v", err)
		}
		if len(buf) == 0 {
			t.Errorf("读取的内置规则流内容为空")
		}
	}
}

func TestExternalOverride(t *testing.T) {
	tempDir := t.TempDir()
	customFile := filepath.Join(tempDir, "custom_hot.txt")
	customContent := "# custom hot website\n*.custom-example.com\n"

	if err := os.WriteFile(customFile, []byte(customContent), 0644); err != nil {
		t.Fatalf("写入临时规则文件失败: %v", err)
	}

	// 传入已存在的外部文件路径，应当优先读取外部文件
	reader, err := OpenRuleReader(customFile, "hot_websites.txt")
	if err != nil {
		t.Fatalf("打开外部规则文件失败: %v", err)
	}
	defer reader.Close()

	buf, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("读取外部规则流失败: %v", err)
	}
	if !strings.Contains(string(buf), "custom-example.com") {
		t.Errorf("未能成功优先读取外部规则文件覆盖内容: %s", string(buf))
	}
}
