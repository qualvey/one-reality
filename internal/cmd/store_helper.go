package cmd

import (
	"strings"

	"RealityChecker/internal/storage"
	"RealityChecker/internal/types"
)

// initStore 根据命令行指定的路径/DSN与全局配置，智能构建统一的 storage.Store 实例 (支持 SQLite 与 PostgreSQL)
func initStore(explicitDB string, cfg *types.Config) (storage.Store, error) {
	if explicitDB != "" && explicitDB != "data/reality_targets.db" {
		// 命令行显式指定了路径或 DSN
		if strings.HasPrefix(explicitDB, "postgres://") || strings.HasPrefix(explicitDB, "postgresql://") {
			return storage.NewStore(&types.DatabaseConfig{
				Driver: "postgres",
				Postgres: types.PostgresConfig{
					DSN: explicitDB,
				},
			})
		}
		// 显式指定 SQLite 文件路径
		return storage.NewStore(&types.DatabaseConfig{
			Driver: "sqlite",
			SQLite: types.SQLiteConfig{
				Path: explicitDB,
			},
		})
	}

	// 优先从配置文件读取配置好的数据库驱动 (sqlite 或 postgres)
	if cfg != nil && cfg.Database.Driver != "" {
		return storage.NewStore(&cfg.Database)
	}

	// 默认采用 SQLite
	return storage.NewStore(&types.DatabaseConfig{
		Driver: "sqlite",
		SQLite: types.SQLiteConfig{
			Path: "data/reality_targets.db",
		},
	})
}
