package cmd

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"RealityChecker/internal/storage"
	"RealityChecker/internal/types"
	"RealityChecker/internal/ui"
)

// executeMigrate 执行数据库存储引擎间的数据平滑迁移 (如 SQLite -> PostgreSQL)
func (r *RootCmd) executeMigrate(args []string) {
	flags := flag.NewFlagSet("migrate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)

	fromFlag := flags.String("from", "data/reality_targets.db", "源数据库路径或连接串 (默认: data/reality_targets.db)")
	toFlag := flags.String("to", "", "目标数据库路径或连接串 (留空则读取 config.yaml 中的 database.postgres)")
	batchSize := flags.Int("batch", 500, "批量流式写入步长")

	if err := flags.Parse(args); err != nil {
		return
	}

	ui.PrintTimestampedMessage("🚀 正在启动 REALITY 数据库平滑迁移作业...")

	// 1. 初始化源存储
	srcDriver := "sqlite"
	if strings.HasPrefix(*fromFlag, "postgres://") || strings.HasPrefix(*fromFlag, "postgresql://") {
		srcDriver = "postgres"
	}
	srcCfg := &types.DatabaseConfig{
		Driver: srcDriver,
	}
	if srcDriver == "sqlite" {
		srcCfg.SQLite.Path = *fromFlag
	} else {
		srcCfg.Postgres.DSN = *fromFlag
	}

	srcStore, err := storage.NewStore(srcCfg)
	if err != nil {
		ui.PrintError(fmt.Sprintf("打开源数据库失败 (%s): %v", *fromFlag, err))
		return
	}
	defer srcStore.Close()

	// 2. 初始化目标存储
	var dstCfg *types.DatabaseConfig
	if *toFlag != "" {
		dstDriver := "postgres"
		if !strings.HasPrefix(*toFlag, "postgres://") && !strings.HasPrefix(*toFlag, "postgresql://") {
			dstDriver = "sqlite"
		}
		dstCfg = &types.DatabaseConfig{
			Driver: dstDriver,
		}
		if dstDriver == "postgres" {
			dstCfg.Postgres.DSN = *toFlag
		} else {
			dstCfg.SQLite.Path = *toFlag
		}
	} else {
		if r.config != nil && r.config.Database.Driver == "postgres" {
			dstCfg = &r.config.Database
		} else if r.config != nil && r.config.Database.Postgres.Host != "" {
			dstCfg = &types.DatabaseConfig{
				Driver:   "postgres",
				Postgres: r.config.Database.Postgres,
			}
		} else {
			ui.PrintError("未指定目标数据库！请通过 --to 指定 PostgreSQL DSN 或在 config.yaml 中配置 database.postgres")
			return
		}
	}

	dstStore, err := storage.NewStore(dstCfg)
	if err != nil {
		ui.PrintError(fmt.Sprintf("连接目标数据库失败: %v", err))
		return
	}
	defer dstStore.Close()

	start := time.Now()

	// 3. 迁移目标资产 (reality_targets)
	ui.PrintTimestampedMessage("正在导出源库所有有效资产记录...")
	targets, err := srcStore.GetAllTargets()
	if err != nil {
		ui.PrintError(fmt.Sprintf("读取源库资产失败: %v", err))
		return
	}

	totalTargets := len(targets)
	ui.PrintTimestampedMessage("共检索到 %d 条有效资产，开始批量注入目标库 (步长: %d)...", totalTargets, *batchSize)

	for i := 0; i < totalTargets; i += *batchSize {
		end := i + *batchSize
		if end > totalTargets {
			end = totalTargets
		}
		chunk := targets[i:end]
		if err := dstStore.UpsertTargets(chunk); err != nil {
			ui.PrintError(fmt.Sprintf("写入目标库资产失败 (范围 %d-%d): %v", i, end, err))
			return
		}
	}

	// 4. 迁移 ASN 任务注册表 (asn_registry)
	ui.PrintTimestampedMessage("正在导出源库 ASN 注册表...")
	asns, err := srcStore.ListASNs("", 0, 100000, 0)
	if err == nil && len(asns) > 0 {
		ui.PrintTimestampedMessage("共检索到 %d 条 ASN 注册记录，正在同步...", len(asns))
		for i := 0; i < len(asns); i += *batchSize {
			end := i + *batchSize
			if end > len(asns) {
				end = len(asns)
			}
			chunk := asns[i:end]
			if err := dstStore.UpsertASNRecords(chunk); err != nil {
				ui.PrintTimestampedMessage("⚠️ 同步部分 ASN 记录失败: %v", err)
				break
			}
		}
	}

	elapsed := time.Since(start)
	ui.PrintTimestampedMessage("🎉 数据库迁移圆满完成！累计同步 %d 条资产与 %d 个 ASN 记录，耗时: %v", totalTargets, len(asns), elapsed)
}
