package storage

import (
	"fmt"
	"strings"

	"RealityChecker/internal/types"
)

// NewStore 根据 DatabaseConfig 工厂方法创建统一存储实例 (支持 SQLite 与 PostgreSQL)
func NewStore(cfg *types.DatabaseConfig) (Store, error) {
	if cfg == nil {
		return NewTargetStore("data/reality_targets.db")
	}

	driver := strings.ToLower(strings.TrimSpace(cfg.Driver))
	switch driver {
	case "postgres", "postgresql", "pg":
		return NewPostgresStore(cfg.Postgres)
	case "sqlite", "sqlite3", "":
		path := cfg.SQLite.Path
		if path == "" {
			path = "data/reality_targets.db"
		}
		return NewTargetStore(path)
	default:
		return nil, fmt.Errorf("不支持的数据库驱动: %q (仅支持 sqlite 或 postgres)", cfg.Driver)
	}
}
