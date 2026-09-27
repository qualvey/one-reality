package cmd

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"RealityChecker/internal/asn"
	"RealityChecker/internal/config"
	"RealityChecker/internal/server"
	"RealityChecker/internal/service"
	"RealityChecker/internal/ui"
	"RealityChecker/internal/version"

	"github.com/oschwald/geoip2-golang"
)

func (r *RootCmd) executeServe(args []string) {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)

	portFlag := flags.Int("port", 8881, "HTTP 服务监听端口")
	hostFlag := flags.String("host", "0.0.0.0", "HTTP 服务监听地址")
	dbFlag := flags.String("db", "data/reality_targets.db", "SQLite 资产数据库文件路径")
	mmdbFlag := flags.String("mmdb", "data/Country.mmdb", "GeoIP 国家数据库文件路径")
	tokenFlag := flags.String("token", "", "API 访问鉴权 Token (留空则不开启鉴权)")

	if err := flags.Parse(args); err != nil {
		return
	}

	addr := fmt.Sprintf("%s:%d", *hostFlag, *portFlag)

	cfg, _ := config.LoadConfig("")

	// 1. 初始化资产库 (支持 SQLite 与 PostgreSQL)
	targetStore, err := initStore(*dbFlag, cfg)
	if err != nil {
		ui.PrintTimestampedMessage("⚠️ 资产数据库初始化失败: %v (将使用无缓存模式运行)", err)
	} else if targetStore != nil {
		defer targetStore.Close()
	}

	// 2. 初始化 GeoIP 数据库（非强制）
	var geoipReader *geoip2.Reader
	if *mmdbFlag != "" {
		if reader, err := geoip2.Open(*mmdbFlag); err == nil {
			geoipReader = reader
			defer geoipReader.Close()
		} else {
			ui.PrintTimestampedMessage("ℹ️ 未加载本地 GeoIP 数据库 (%s): %v", *mmdbFlag, err)
		}
	}

	// 3. 构建核心业务与 HTTP 实例
	asnClient := asn.NewClient(15 * time.Second)
	provService := service.NewProvisionService(targetStore, geoipReader, asnClient, cfg)

	apiToken := *tokenFlag
	if apiToken == "" {
		if envToken := os.Getenv("RC_API_TOKEN"); envToken != "" {
			apiToken = envToken
		} else if cfg != nil && cfg.Server.APIToken != "" {
			apiToken = cfg.Server.APIToken
		}
	}

	srvConfig := server.DefaultServerConfig()
	srvConfig.Addr = addr
	srvConfig.APIToken = apiToken

	targetServer := server.NewTargetServer(srvConfig, provService)

	// 4. 打印启动信息
	fmt.Println()
	fmt.Printf("🌐 RealityChecker API & Web 控制台服务启动中 [%s]\n", version.GetVersion())
	fmt.Printf("   » 监听地址: http://%s\n", addr)
	fmt.Printf("   » Web 控制台: http://%s/\n", addr)
	fmt.Printf("   » 资产数据库: %s\n", *dbFlag)
	if apiToken != "" {
		prefixLen := 4
		if len(apiToken) < 4 {
			prefixLen = len(apiToken)
		}
		fmt.Printf("   » 接口鉴权: 已启用 (Token: %s***)\n", apiToken[:prefixLen])
	} else {
		fmt.Println("   » 接口鉴权: 未启用 (公网暴露建议配置 --token 或在 config.yaml 启用)")
	}
	if geoipReader != nil {
		fmt.Printf("   » GeoIP 数据库: %s\n", *mmdbFlag)
	}
	fmt.Println("   » API 端点:")
	fmt.Printf("     • 智能同ASN权重: GET http://%s/api/targets/smart?ip=<IP>&limit=10\n", addr)
	fmt.Printf("     • 资产全量管理: GET http://%s/api/targets?page=1&page_size=20\n", addr)
	fmt.Printf("     • 资产概览统计: GET http://%s/api/stats\n", addr)
	fmt.Printf("     • SSE 流式探测: GET http://%s/api/targets/stream?ip=<IP>&limit=5\n", addr)
	fmt.Printf("     • 健康检查探测: GET http://%s/api/health\n", addr)
	fmt.Println()
	ui.PrintTimestampedMessage("服务就绪，按 Ctrl+C 优雅退出...")


	// 5. 启动服务与优雅停机
	errChan := make(chan error, 1)
	go func() {
		if err := targetServer.Start(); err != nil && err != http.ErrServerClosed {
			errChan <- err
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errChan:
		ui.PrintError(fmt.Sprintf("❌ 服务异常终止: %v", err))
	case <-sigChan:
		ui.PrintTimestampedMessage("正在平滑关闭 HTTP 服务...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := targetServer.Shutdown(shutdownCtx); err != nil {
			ui.PrintError(fmt.Sprintf("强制终止服务: %v", err))
		} else {
			ui.PrintTimestampedMessage("HTTP 服务已安全关闭。")
		}
	case <-r.ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = targetServer.Shutdown(shutdownCtx)
	}
}
