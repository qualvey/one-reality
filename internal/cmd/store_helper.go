package cmd

import (
	"RealityChecker/internal/app"
	"RealityChecker/internal/storage"
	"RealityChecker/internal/types"
)

// initStore 根据命令行指定的路径/DSN与全局配置构建统一的 storage.Store 实例 (统一委托至 app.Container)
func initStore(explicitDB string, cfg *types.Config) (storage.Store, error) {
	container, err := app.NewContainer(app.ContainerOptions{
		Config:     cfg,
		ExplicitDB: explicitDB,
	})
	if err != nil {
		return nil, err
	}
	return container.GetStore()
}
