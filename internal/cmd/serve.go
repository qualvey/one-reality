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
	"RealityChecker/internal/storage"
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

	if err := flags.Parse(args); err != nil {
		return
	}

	addr := fmt.Sprintf("%s:%d", *hostFlag, *portFlag)

	// 1. 初始化 SQLite 资产库
	targetStore, err := storage.NewTargetStore(*dbFlag)
	if err != nil {
		ui.PrintTimestampedMessage("⚠️ 资产数据库初始化失败: %v (将使用无缓存模式运行)", err)
	} else {
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
	cfg, _ := config.LoadConfig("")
	provService := service.NewProvisionService(targetStore, geoipReader, asnClient, cfg)

	srvConfig := server.DefaultServerConfig()
	srvConfig.Addr = addr

	targetServer := server.NewTargetServer(srvConfig, provService)

	// 4. 打印启动信息
	fmt.Println()
	fmt.Printf("🌐 RealityChecker Headless / API 服务启动中 [%s]\n", version.GetVersion())
	fmt.Printf("   » 监听地址: http://%s\n", addr)
	fmt.Printf("   » 资产数据库: %s\n", *dbFlag)
	if geoipReader != nil {
		fmt.Printf("   » GeoIP 数据库: %s\n", *mmdbFlag)
	}
	fmt.Println("   » API 端点:")
	fmt.Printf("     • SSE 流式响应: GET http://%s/api/targets/stream?ip=<IP>&limit=5\n", addr)
	fmt.Printf("     • JSON 批量响应: GET http://%s/api/targets?ip=<IP>&limit=5\n", addr)
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
