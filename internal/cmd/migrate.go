package cmd

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"RealityChecker/internal/config"
	"RealityChecker/internal/storage"
	"RealityChecker/internal/types"
	"RealityChecker/internal/ui"
)

// executeMigrate 执行数据库存储引擎间的数据平滑迁移 (如 SQLite -> PostgreSQL)
func (r *RootCmd) executeMigrate(args []string) {
	flags := flag.NewFlagSet("migrate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)

	fromFlag := flags.String("from", "data/reality_targets.db", "源数据库路径或连接串 (默认: data/reality_targets.db)")
	flags.StringVar(fromFlag, "from-sqlite", "data/reality_targets.db", "源 SQLite 数据库路径 (别名)")

	toFlag := flags.String("to", "", "目标数据库路径或连接串 (留空则读取 config.yaml 中的 database.postgres)")
	flags.StringVar(toFlag, "to-postgres", "", "目标 PostgreSQL 连接串 (别名)")

	targetDriverFlag := flags.String("target-driver", "", "目标驱动类型 (postgres / sqlite，留空自动推导)")
	flags.StringVar(targetDriverFlag, "driver", "", "目标驱动类型 (别名)")

	configFlag := flags.String("config", "", "配置文件路径 (例如 config.yml)")
	flags.StringVar(configFlag, "c", "", "配置文件路径 (别名)")

	batchSize := flags.Int("batch", 500, "批量流式写入步长")

	if err := flags.Parse(args); err != nil {
		return
	}

	// 若在 migrate 命令中显式传入了 -c / --config，则重新加载配置
	if *configFlag != "" {
		reloadedCfg, err := config.LoadConfig(*configFlag)
		if err != nil {
			ui.PrintError(fmt.Sprintf("加载指定配置文件失败 (%s): %v", *configFlag, err))
			return
		}
		r.config = reloadedCfg
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
	targetDriver := strings.ToLower(strings.TrimSpace(*targetDriverFlag))

	if *toFlag != "" {
		dstDriver := "postgres"
		if targetDriver == "sqlite" || (!strings.HasPrefix(*toFlag, "postgres://") && !strings.HasPrefix(*toFlag, "postgresql://") && targetDriver != "postgres") {
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
		if targetDriver == "postgres" || (r.config != nil && r.config.Database.Driver == "postgres") {
			if r.config != nil && (r.config.Database.Postgres.Host != "" || r.config.Database.Postgres.DSN != "") {
				dstCfg = &types.DatabaseConfig{
					Driver:   "postgres",
					Postgres: r.config.Database.Postgres,
				}
			} else {
				dstCfg = &types.DatabaseConfig{
					Driver: "postgres",
					Postgres: types.PostgresConfig{
						Host:     "127.0.0.1",
						Port:     5432,
						User:     "postgres",
						DBName:   "reality_checker",
						SSLMode:  "disable",
						MaxConns: 50,
						MinConns: 5,
					},
				}
			}
		} else if targetDriver == "sqlite" {
			dstCfg = &types.DatabaseConfig{
				Driver: "sqlite",
				SQLite: types.SQLiteConfig{Path: "data/reality_targets.db"},
			}
		} else if r.config != nil && r.config.Database.Driver != "" {
			dstCfg = &r.config.Database
		} else {
			ui.PrintError("未指定目标数据库！请通过 --to 指定 PostgreSQL DSN 或在 config.yaml 中配置 database.postgres")
			return
		}
	}

	if dstCfg.Driver == "postgres" {
		sourceDesc := "命令行 --to 参数"
		if *toFlag == "" {
			if r.config != nil && r.config.LoadedConfigFile != "" {
				sourceDesc = fmt.Sprintf("配置文件 %s", r.config.LoadedConfigFile)
			} else {
				sourceDesc = "系统缺省配置 (未探测到有效配置文件)"
			}
		}
		pg := dstCfg.Postgres
		if pg.DSN != "" {
			ui.PrintTimestampedMessage("🔗 目标数据库: PostgreSQL (来源: %s)", sourceDesc)
		} else {
			ui.PrintTimestampedMessage("🔗 目标数据库: PostgreSQL %s:%d/%s (用户: %s, 来源: %s)", pg.Host, pg.Port, pg.DBName, pg.User, sourceDesc)
		}
	}

	dstStore, err := storage.NewStore(dstCfg)
	if err != nil {
		if dstCfg.Driver == "postgres" {
			ui.PrintErrorWithDetails(
				fmt.Sprintf("连接目标数据库失败: %v", err),
				"💡 排查建议:",
				"  1. 确认当前目录下是否存在未修改的 config.yaml (系统默认 config.yaml 优先级高于 config.yml)",
				"  2. 可使用 -c 指定配置文件: ./reality-checker -c config.yml migrate",
				"  3. 或直接通过 --to 指定完整 DSN: ./reality-checker migrate --to \"postgres://rchecker:passwd@127.0.0.1:5432/reality?sslmode=disable\"",
				"  4. 检查 PostgreSQL 的 pg_hba.conf 是否放通本地或对应用户的 md5/scram-sha-256 密码认证",
			)
		} else {
			ui.PrintError(fmt.Sprintf("连接目标数据库失败: %v", err))
		}
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
