package data

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNeedsUpdate(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "test.mmdb")

	// 创建一个新文件
	if err := os.WriteFile(filePath, []byte("dummy content"), 0644); err != nil {
		t.Fatalf("创建测试文件失败: %v", err)
	}

	d := NewDownloader()

	// 刚创建的文件不需要更新
	needsUpdate, err := d.needsUpdate(filePath)
	if err != nil {
		t.Fatalf("needsUpdate 失败: %v", err)
	}
	if needsUpdate {
		t.Errorf("刚创建的文件不应该需要更新")
	}

	// 将修改时间改为 16 天前
	sixteenDaysAgo := time.Now().Add(-16 * 24 * time.Hour)
	if err := os.Chtimes(filePath, sixteenDaysAgo, sixteenDaysAgo); err != nil {
		t.Fatalf("修改文件时间戳失败: %v", err)
	}

	needsUpdate, err = d.needsUpdate(filePath)
	if err != nil {
		t.Fatalf("needsUpdate 失败: %v", err)
	}
	if !needsUpdate {
		t.Errorf("超过 15 天的文件应该需要更新")
	}
}
