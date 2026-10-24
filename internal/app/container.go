package app

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"RealityChecker/internal/asn"
	"RealityChecker/internal/config"
	"RealityChecker/internal/data"
	"RealityChecker/internal/scanner"
	"RealityChecker/internal/service"
	"RealityChecker/internal/storage"
	"RealityChecker/internal/types"

	"github.com/oschwald/geoip2-golang"
)

// ContainerOptions 容器装配参数
type ContainerOptions struct {
	Config          *types.Config // 已解析好的全局配置 (若为空则自动通过 ConfigPath 或默认策略加载)
	ConfigPath      string        // 配置文件路径
	ExplicitDB      string        // 显式指定的目标数据库路径或 PostgreSQL DSN
	ExplicitMMDB    string        // 显式指定的 GeoIP mmdb 文件路径
	ScannerProxyURL string        // 覆盖指定扫描器代理
}

// Container 统一的应用依赖注入中枢与生命周期管理器
// 集中管理存储、网络扫描器、GeoIP 离线库、ASN 客户端与业务供给服务的构建与优雅释放
type Container struct {
	opts ContainerOptions

	mu          sync.Mutex
	config      *types.Config
	store       storage.Store
	geoipReader *geoip2.Reader
	scanner     *scanner.Scanner
	asnClient   asn.ASNResolver
	provService *service.ProvisionService

	closed bool
}

// NewContainer 创建应用容器实例
func NewContainer(opts ContainerOptions) (*Container, error) {
	c := &Container{
		opts: opts,
	}

	// 1. 初始化配置
	if opts.Config != nil {
		c.config = opts.Config
	} else {
		loadedCfg, err := config.LoadConfig(opts.ConfigPath)
		if err != nil {
			// 若未显式传参且加载失败，回退使用默认内存配置
			c.config = &types.Config{}
		} else {
			c.config = loadedCfg
		}
	}

	return c, nil
}

// Config 获取全局配置
func (c *Container) Config() *types.Config {
	return c.config
}

// GetStore 惰性单例获取统一存储引擎 (支持 SQLite 与 PostgreSQL)
func (c *Container) GetStore() (storage.Store, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil, fmt.Errorf("container is already closed")
	}
	if c.store != nil {
		return c.store, nil
	}

	explicitDB := strings.TrimSpace(c.opts.ExplicitDB)
	if explicitDB != "" && explicitDB != "data/reality_targets.db" {
		if strings.HasPrefix(explicitDB, "postgres://") || strings.HasPrefix(explicitDB, "postgresql://") {
			store, err := storage.NewStore(&types.DatabaseConfig{
				Driver: "postgres",
				Postgres: types.PostgresConfig{
					DSN: explicitDB,
				},
			})
			if err != nil {
				return nil, err
			}
			c.store = store
			return c.store, nil
		}

		store, err := storage.NewStore(&types.DatabaseConfig{
			Driver: "sqlite",
			SQLite: types.SQLiteConfig{
				Path: explicitDB,
			},
		})
		if err != nil {
			return nil, err
		}
		c.store = store
		return c.store, nil
	}

	if c.config != nil && c.config.Database.Driver != "" {
		store, err := storage.NewStore(&c.config.Database)
		if err != nil {
			return nil, err
		}
		c.store = store
		return c.store, nil
	}

	// 默认采用 SQLite
	store, err := storage.NewStore(&types.DatabaseConfig{
		Driver: "sqlite",
		SQLite: types.SQLiteConfig{
			Path: "data/reality_targets.db",
		},
	})
	if err != nil {
		return nil, err
	}
	c.store = store
	return c.store, nil
}

// GetGeoIP 惰性单例获取 MaxMind GeoIP 国家数据库 Reader (若未找到则返回 nil，不报错)
func (c *Container) GetGeoIP() *geoip2.Reader {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed || c.geoipReader != nil {
		return c.geoipReader
	}

	explicitPath := strings.TrimSpace(c.opts.ExplicitMMDB)
	var candidatePaths []string
	if explicitPath != "" {
		candidatePaths = append(candidatePaths, explicitPath)
	} else {
		candidatePaths = append(candidatePaths, "data/Country.mmdb", "Country.mmdb")
	}

	if reader, err := data.OpenGeoIPReader(candidatePaths...); err == nil {
		c.geoipReader = reader
		return c.geoipReader
	}

	return nil
}

// GetScanner 惰性单例获取带代理感知与生命周期管理的高并发网络探测器
func (c *Container) GetScanner() *scanner.Scanner {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed || c.scanner != nil {
		return c.scanner
	}

	scanProxy := c.opts.ScannerProxyURL
	if scanProxy == "" && c.config != nil && c.config.Proxy.Scanner && c.config.Proxy.URL != "" {
		scanProxy = c.config.Proxy.URL
	}

	c.scanner = scanner.NewScanner(scanProxy)
	return c.scanner
}

// GetASNClient 惰性单例获取 ASN 解析客户端 (支持代理)
func (c *Container) GetASNClient() asn.ASNResolver {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed || c.asnClient != nil {
		return c.asnClient
	}

	proxyURL := ""
	if c.config != nil && c.config.Proxy.Download && c.config.Proxy.URL != "" {
		proxyURL = c.config.Proxy.URL
	}

	c.asnClient = asn.NewClientWithProxy(proxyURL, 15*time.Second)
	return c.asnClient
}

// GetProvisionService 组装获取端到端目标供给业务门面服务
func (c *Container) GetProvisionService() (*service.ProvisionService, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil, fmt.Errorf("container is already closed")
	}
	if c.provService != nil {
		return c.provService, nil
	}

	// 保证前置组件已被安全组装 (解锁后调用以防死锁)
	c.mu.Unlock()
	store, _ := c.GetStore()
	geoip := c.GetGeoIP()
	asnCli := c.GetASNClient()
	c.mu.Lock()

	c.provService = service.NewProvisionService(store, geoip, asnCli, c.config)
	return c.provService, nil
}

// Close 集中、有序且安全地关闭所有持有的持久连接、文件描述符与后台资源
func (c *Container) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true

	var errs []string

	if c.scanner != nil {
		c.scanner.Close()
		c.scanner = nil
	}

	if c.geoipReader != nil {
		if err := c.geoipReader.Close(); err != nil {
			errs = append(errs, fmt.Sprintf("close geoip failed: %v", err))
		}
		c.geoipReader = nil
	}

	if c.store != nil {
		if err := c.store.Close(); err != nil {
			errs = append(errs, fmt.Sprintf("close store failed: %v", err))
		}
		c.store = nil
	}

	if len(errs) > 0 {
		return fmt.Errorf("container close errors: %s", strings.Join(errs, "; "))
	}
	return nil
}
