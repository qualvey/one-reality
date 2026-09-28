package cmd

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"RealityChecker/internal/app"
	asnclient "RealityChecker/internal/asn"
	"RealityChecker/internal/config"
)

func executeASN(args []string) {
	flags := flag.NewFlagSet("asn", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	countryFlag := flags.String("country", "", "国家 ISO 代码或名称")
	dbPath := flags.String("db", "data/Country.mmdb", "GeoIP 国家数据库路径")
	storePath := flags.String("store", "data/reality_targets.db", "SQLite 目标与 ASN 数据库路径")
	seedFlag := flags.Bool("seed", false, "初始化并加载预设热门云厂商/IDC ASN 注册表")
	syncURL := flags.String("sync", "", "从远程 URL 同步全量 ASN 列表")
	statsFlag := flags.Bool("stats", false, "查看当前 ASN 任务库统计大盘")
	listFlag := flags.Bool("list", false, "列出当前库中的 ASN 记录")
	statusFilter := flags.String("status", "", "过滤 ASN 状态 (pending/scanning/completed)")
	limitFlag := flags.Int("limit", 50, "列表输出最大数量")
	ipv4Only := flags.Bool("ipv4-only", false, "仅输出 IPv4 CIDR 网段")
	flags.BoolVar(ipv4Only, "4", false, "仅输出 IPv4 CIDR 网段 (缩写)")
	ipv6Only := flags.Bool("ipv6-only", false, "仅输出 IPv6 CIDR 网段")
	flags.BoolVar(ipv6Only, "6", false, "仅输出 IPv6 CIDR 网段 (缩写)")

	if err := flags.Parse(args); err != nil {
		return
	}

	cfg, _ := config.LoadConfig("")
	proxyURL := ""
	if cfg != nil && cfg.Proxy.Download && cfg.Proxy.URL != "" {
		proxyURL = cfg.Proxy.URL
	}

	container, err := app.NewContainer(app.ContainerOptions{
		Config:       cfg,
		ExplicitDB:   *storePath,
		ExplicitMMDB: *dbPath,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "初始化应用容器失败: %v\n", err)
		return
	}
	defer container.Close()

	// 1. 注册表管理逻辑
	if *seedFlag || *syncURL != "" || *statsFlag || *listFlag {
		store, err := container.GetStore()
		if err != nil {
			fmt.Fprintf(os.Stderr, "打开数据库失败: %v\n", err)
			return
		}

		mgr := asnclient.NewRegistryManagerWithProxy(store, proxyURL)

		if *seedFlag {
			n, err := mgr.InitDefaultRegistry()
			if err != nil {
				fmt.Fprintf(os.Stderr, "初始化预设 ASN 注册表失败: %v\n", err)
				return
			}
			fmt.Printf("成功初始化并载入 %d 个预设热门公有云与 IDC ASN\n", n)
			return
		}

		if *syncURL != "" {
			fmt.Printf("正在从 %s 同步 ASN 注册表...\n", *syncURL)
			n, err := mgr.SyncFromURL(context.Background(), *syncURL)
			if err != nil {
				fmt.Fprintf(os.Stderr, "同步失败: %v\n", err)
				return
			}
			fmt.Printf("同步完成，新增/更新了 %d 个 ASN 记录\n", n)
			return
		}

		if *statsFlag {
			stats, err := mgr.GetStats()
			if err != nil {
				fmt.Fprintf(os.Stderr, "获取统计大盘失败: %v\n", err)
				return
			}
			fmt.Println("=== ASN 全网扫描任务大盘 ===")
			fmt.Printf("总自治系统数 (Total):      %d\n", stats.TotalASNs)
			fmt.Printf("等待扫描 (Pending):         %d\n", stats.PendingASNs)
			fmt.Printf("正在扫描 (Scanning):        %d\n", stats.ScanningASNs)
			fmt.Printf("已完成 (Completed):        %d\n", stats.CompletedASNs)
			fmt.Printf("高优核心厂商 (Priority>=80): %d\n", stats.HighPriority)
			return
		}

		if *listFlag {
			list, err := store.ListASNs(*statusFilter, 0, *limitFlag, 0)
			if err != nil {
				fmt.Fprintf(os.Stderr, "查询 ASN 列表失败: %v\n", err)
				return
			}
			fmt.Printf("%-8s %-6s %-8s %-12s %s\n", "ASN", "国家", "权重", "状态", "运营商/名称")
			fmt.Println(strings.Repeat("-", 60))
			for _, item := range list {
				fmt.Printf("AS%-6d %-6s %-8d %-12s %s\n", item.ASN, item.Country, item.Priority, item.ScanStatus, item.Name)
			}
			fmt.Printf("共显示 %d 条记录\n", len(list))
			return
		}
	}

	// 2. 原有的 ASN CIDR 网段查询与国家过滤
	if flags.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "用法:")
		fmt.Fprintln(os.Stderr, "  1. 查询网段: reality-checker asn [--db Country.mmdb] [-4] [-6] <ASN> <国家>")
		fmt.Fprintln(os.Stderr, "  2. 注册表管理: reality-checker asn [--store db] [--seed] [--stats] [--list] [--sync <url>]")
		return
	}
	country := *countryFlag
	if country == "" && flags.NArg() >= 2 {
		country = flags.Arg(1)
	}
	if strings.TrimSpace(country) == "" {
		fmt.Fprintln(os.Stderr, "错误：必须指定国家，例如 CN 或 US")
		return
	}

	db := container.GetGeoIP()
	if db == nil {
		fmt.Fprintf(os.Stderr, "打开GeoIP数据库失败: 未能加载有效的 GeoIP 数据库文件 (%s)\n", *dbPath)
		return
	}

	prefixes, err := asnclient.NewClientWithProxy(proxyURL).FetchPrefixes(context.Background(), flags.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "ASN查询失败: %v\n", err)
		return
	}
	filtered, err := asnclient.FilterByCountry(prefixes, db, country)
	if err != nil {
		fmt.Fprintf(os.Stderr, "国家过滤失败: %v\n", err)
		return
	}
	filtered = asnclient.FilterIPVersion(filtered, *ipv4Only, *ipv6Only)
	for _, prefix := range filtered {
		fmt.Println(prefix)
	}
	fmt.Fprintf(os.Stderr, "共找到 %d/%d 个属于 %s 的CIDR\n", len(filtered), len(prefixes), country)
}

