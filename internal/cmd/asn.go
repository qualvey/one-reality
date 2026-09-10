package cmd

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	asnclient "RealityChecker/internal/asn"

	"github.com/oschwald/geoip2-golang"
)

func executeASN(args []string) {
	flags := flag.NewFlagSet("asn", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	countryFlag := flags.String("country", "", "国家 ISO 代码或名称")
	dbPath := flags.String("db", "data/Country.mmdb", "GeoIP 国家数据库路径")
	ipv4Only := flags.Bool("ipv4-only", false, "仅输出 IPv4 CIDR 网段")
	flags.BoolVar(ipv4Only, "4", false, "仅输出 IPv4 CIDR 网段 (缩写)")
	ipv6Only := flags.Bool("ipv6-only", false, "仅输出 IPv6 CIDR 网段")
	flags.BoolVar(ipv6Only, "6", false, "仅输出 IPv6 CIDR 网段 (缩写)")
	if err := flags.Parse(args); err != nil {
		return
	}

	if flags.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "用法: reality-checker asn [--db Country.mmdb] [-4] [-6] <ASN> <国家>")
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

	db, err := geoip2.Open(*dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "打开GeoIP数据库失败: %v\n", err)
		return
	}
	defer db.Close()

	prefixes, err := asnclient.NewClient().FetchPrefixes(context.Background(), flags.Arg(0))
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
