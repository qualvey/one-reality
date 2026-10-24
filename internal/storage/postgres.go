package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"RealityChecker/internal/types"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore 基于 PostgreSQL / pgxpool 的高性能并发资产与调度存储引擎
type PostgresStore struct {
	pool *pgxpool.Pool
}

// 静态编译断言: 确保 PostgresStore 完整实现了 Store 接口
var _ Store = (*PostgresStore)(nil)

// NewPostgresStore 创建或打开 PostgreSQL 存储引擎
func NewPostgresStore(cfg types.PostgresConfig) (*PostgresStore, error) {
	connStr := cfg.DSN
	if strings.TrimSpace(connStr) == "" {
		host := cfg.Host
		if host == "" {
			host = "127.0.0.1"
		}
		port := cfg.Port
		if port <= 0 {
			port = 5432
		}
		user := cfg.User
		if user == "" {
			user = "postgres"
		}
		dbname := cfg.DBName
		if dbname == "" {
			dbname = "reality_checker"
		}
		sslmode := cfg.SSLMode
		if sslmode == "" {
			sslmode = "disable"
		}

		u := url.URL{
			Scheme: "postgres",
			Host:   fmt.Sprintf("%s:%d", host, port),
			Path:   dbname,
		}
		if cfg.Password != "" {
			u.User = url.UserPassword(user, cfg.Password)
		} else {
			u.User = url.User(user)
		}
		q := u.Query()
		q.Set("sslmode", sslmode)
		u.RawQuery = q.Encode()
		connStr = u.String()
	}

	poolConfig, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		return nil, fmt.Errorf("解析 PostgreSQL 连接配置失败: %w", err)
	}

	maxConns := int32(cfg.MaxConns)
	if maxConns <= 0 {
		maxConns = 50
	}
	minConns := int32(cfg.MinConns)
	if minConns <= 0 {
		minConns = 5
	}
	poolConfig.MaxConns = maxConns
	poolConfig.MinConns = minConns
	if cfg.MaxConnLifetime > 0 {
		poolConfig.MaxConnLifetime = cfg.MaxConnLifetime
	} else {
		poolConfig.MaxConnLifetime = time.Hour
	}
	if cfg.MaxConnIdleTime > 0 {
		poolConfig.MaxConnIdleTime = cfg.MaxConnIdleTime
	} else {
		poolConfig.MaxConnIdleTime = 30 * time.Minute
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("建立 PostgreSQL 连接池失败: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("PostgreSQL 连接探活失败: %w", err)
	}

	store := &PostgresStore{
		pool: pool,
	}

	if err := store.initSchema(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("初始化 PostgreSQL 表结构失败: %w", err)
	}

	return store, nil
}

// initSchema 创建表和高性能索引
func (s *PostgresStore) initSchema(ctx context.Context) error {
	schema := `
	CREATE TABLE IF NOT EXISTS reality_targets (
		domain VARCHAR(255) PRIMARY KEY,
		asn VARCHAR(32) NOT NULL,
		country VARCHAR(8) NOT NULL,
		ip VARCHAR(45) NOT NULL,
		port INTEGER NOT NULL DEFAULT 443,
		handshake_ms INTEGER NOT NULL,
		cert_days INTEGER NOT NULL,
		cert_expire_at TIMESTAMPTZ,
		tags TEXT NOT NULL DEFAULT '',
		status_code INTEGER NOT NULL,
		page_title TEXT,
		is_cdn BOOLEAN NOT NULL DEFAULT FALSE,
		is_hot BOOLEAN NOT NULL DEFAULT FALSE,
		is_default_page BOOLEAN NOT NULL DEFAULT FALSE,
		default_page_type VARCHAR(64),
		stars SMALLINT NOT NULL DEFAULT 0,
		is_active BOOLEAN NOT NULL DEFAULT TRUE,
		check_fail_count INTEGER NOT NULL DEFAULT 0,
		first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		last_checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	CREATE INDEX IF NOT EXISTS idx_targets_asn ON reality_targets (asn);
	CREATE INDEX IF NOT EXISTS idx_targets_country ON reality_targets (country);
	CREATE INDEX IF NOT EXISTS idx_targets_asn_country ON reality_targets (asn, country);
	CREATE INDEX IF NOT EXISTS idx_targets_last_checked ON reality_targets (last_checked_at);
	CREATE INDEX IF NOT EXISTS idx_targets_stars_active ON reality_targets (stars DESC, is_active);

	CREATE TABLE IF NOT EXISTS asn_registry (
		asn INTEGER PRIMARY KEY,
		name VARCHAR(255) NOT NULL DEFAULT '',
		country VARCHAR(8) NOT NULL DEFAULT '',
		total_ips BIGINT NOT NULL DEFAULT 0,
		priority INTEGER NOT NULL DEFAULT 10,
		scan_status VARCHAR(32) NOT NULL DEFAULT 'pending',
		last_scanned_at TIMESTAMPTZ,
		success_target_count INTEGER NOT NULL DEFAULT 0,
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	CREATE INDEX IF NOT EXISTS idx_asn_priority_status ON asn_registry (priority DESC, scan_status);
	CREATE INDEX IF NOT EXISTS idx_asn_country ON asn_registry (country);

	CREATE TABLE IF NOT EXISTS scan_checkpoints (
		task_key VARCHAR(64) NOT NULL,
		cidr VARCHAR(64) NOT NULL,
		last_ip VARCHAR(45) NOT NULL DEFAULT '',
		completed BOOLEAN NOT NULL DEFAULT FALSE,
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		PRIMARY KEY (task_key, cidr)
	);

	CREATE INDEX IF NOT EXISTS idx_checkpoints_task ON scan_checkpoints (task_key);

	CREATE TABLE IF NOT EXISTS target_patrol_logs (
		id BIGSERIAL PRIMARY KEY,
		domain VARCHAR(255) NOT NULL,
		ip VARCHAR(45) NOT NULL,
		handshake_ms INTEGER NOT NULL,
		is_success BOOLEAN NOT NULL,
		error_msg TEXT,
		checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	CREATE INDEX IF NOT EXISTS idx_patrol_domain_checked ON target_patrol_logs (domain, checked_at DESC);
	`
	if _, err := s.pool.Exec(ctx, schema); err != nil {
		return err
	}
	_, _ = s.pool.Exec(ctx, `
		ALTER TABLE reality_targets ADD COLUMN IF NOT EXISTS cert_expire_at TIMESTAMPTZ;
		ALTER TABLE reality_targets ADD COLUMN IF NOT EXISTS tags TEXT NOT NULL DEFAULT '';
	`)
	return nil
}

// Close 关闭 PostgreSQL 连接池
func (s *PostgresStore) Close() error {
	if s.pool != nil {
		s.pool.Close()
	}
	return nil
}

// UpsertTarget 插入或更新单条资产记录
func (s *PostgresStore) UpsertTarget(record *types.TargetRecord) error {
	if record == nil || record.Domain == "" {
		return nil
	}
	return s.UpsertTargets([]*types.TargetRecord{record})
}

// UpsertTargets 批量插入或更新资产记录（基于 pgx.Batch 管线化极致性能）
func (s *PostgresStore) UpsertTargets(records []*types.TargetRecord) error {
	if len(records) == 0 {
		return nil
	}

	query := `
		INSERT INTO reality_targets (
			domain, asn, country, ip, port, handshake_ms, cert_days, cert_expire_at, tags, status_code,
			page_title, is_cdn, is_hot, is_default_page, default_page_type,
			stars, is_active, check_fail_count, first_seen_at, last_checked_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
		ON CONFLICT (domain) DO UPDATE SET
			asn = EXCLUDED.asn,
			country = EXCLUDED.country,
			ip = EXCLUDED.ip,
			port = EXCLUDED.port,
			handshake_ms = EXCLUDED.handshake_ms,
			cert_days = EXCLUDED.cert_days,
			cert_expire_at = CASE WHEN EXCLUDED.cert_expire_at IS NOT NULL THEN EXCLUDED.cert_expire_at ELSE reality_targets.cert_expire_at END,
			tags = CASE WHEN EXCLUDED.tags != '' THEN EXCLUDED.tags ELSE reality_targets.tags END,
			status_code = EXCLUDED.status_code,
			page_title = EXCLUDED.page_title,
			is_cdn = EXCLUDED.is_cdn,
			is_hot = EXCLUDED.is_hot,
			is_default_page = EXCLUDED.is_default_page,
			default_page_type = EXCLUDED.default_page_type,
			stars = EXCLUDED.stars,
			is_active = EXCLUDED.is_active,
			check_fail_count = EXCLUDED.check_fail_count,
			last_checked_at = EXCLUDED.last_checked_at
	`

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	batch := &pgx.Batch{}
	now := time.Now().UTC()
	validCount := 0

	for _, rec := range records {
		if rec == nil || rec.Domain == "" {
			continue
		}
		domainKey := strings.ToLower(strings.TrimSpace(rec.Domain))
		lastChecked := rec.LastCheckedAt
		if lastChecked.IsZero() {
			lastChecked = now
		}
		firstSeen := rec.FirstSeenAt
		if firstSeen.IsZero() {
			firstSeen = lastChecked
		}
		port := rec.Port
		if port <= 0 {
			port = 443
		}
		isActive := true
		if !rec.IsActive && rec.CheckFailCount > 0 {
			isActive = false
		}

		var certExpireAtAny any = nil
		if !rec.CertExpireAt.IsZero() {
			certExpireAtAny = rec.CertExpireAt
		} else if rec.CertDays > 0 {
			certExpireAtAny = lastChecked.Add(time.Duration(rec.CertDays) * 24 * time.Hour)
		}
		tagsJoined := strings.Join(rec.Tags, ",")

		batch.Queue(query,
			sanitizeUTF8(domainKey),
			sanitizeUTF8(strings.ToUpper(strings.TrimSpace(rec.ASN))),
			sanitizeUTF8(strings.ToUpper(strings.TrimSpace(rec.Country))),
			sanitizeUTF8(rec.IP),
			port,
			rec.HandshakeMS,
			rec.CertDays,
			certExpireAtAny,
			sanitizeUTF8(tagsJoined),
			rec.StatusCode,
			sanitizeUTF8(rec.PageTitle),
			rec.IsCDN,
			rec.IsHot,
			rec.IsDefaultPage,
			sanitizeUTF8(rec.DefaultPageType),
			rec.Stars,
			isActive,
			rec.CheckFailCount,
			firstSeen,
			lastChecked,
		)
		validCount++
	}

	if validCount == 0 {
		return nil
	}

	br := s.pool.SendBatch(ctx, batch)
	defer br.Close()

	for i := 0; i < validCount; i++ {
		if _, err := br.Exec(); err != nil {
			return fmt.Errorf("批量写入资产失败 (index=%d): %w", i, err)
		}
	}

	return nil
}

func scanPostgresTargetRecord(row pgx.Row) (*types.TargetRecord, error) {
	var rec types.TargetRecord
	var pageTitle, defaultPageType, tagsStr *string
	var firstSeenAt, lastCheckedAt time.Time
	var certExpireAt *time.Time

	err := row.Scan(
		&rec.Domain,
		&rec.ASN,
		&rec.Country,
		&rec.IP,
		&rec.Port,
		&rec.HandshakeMS,
		&rec.CertDays,
		&certExpireAt,
		&tagsStr,
		&rec.StatusCode,
		&pageTitle,
		&rec.IsCDN,
		&rec.IsHot,
		&rec.IsDefaultPage,
		&defaultPageType,
		&rec.Stars,
		&rec.IsActive,
		&rec.CheckFailCount,
		&firstSeenAt,
		&lastCheckedAt,
	)
	if err != nil {
		return nil, err
	}

	if rec.Port <= 0 {
		rec.Port = 443
	}
	if pageTitle != nil {
		rec.PageTitle = *pageTitle
	}
	if defaultPageType != nil {
		rec.DefaultPageType = *defaultPageType
	}
	if certExpireAt != nil && !certExpireAt.IsZero() {
		rec.CertExpireAt = *certExpireAt
		rec.CertDays = rec.GetRemainingDays()
	}
	if tagsStr != nil && strings.TrimSpace(*tagsStr) != "" {
		for _, t := range strings.Split(*tagsStr, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				rec.Tags = append(rec.Tags, t)
			}
		}
	}
	rec.FirstSeenAt = firstSeenAt
	rec.LastCheckedAt = lastCheckedAt

	return &rec, nil
}

// GetTargetsByASN 根据 ASN 和 国家 查询未过期的有效资产
func (s *PostgresStore) GetTargetsByASN(asn, country string, maxAge time.Duration) ([]*types.TargetRecord, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	asnNorm := strings.ToUpper(strings.TrimSpace(asn))
	countryNorm := strings.ToUpper(strings.TrimSpace(country))

	withAS := asnNorm
	if !strings.HasPrefix(withAS, "AS") {
		withAS = "AS" + withAS
	}
	withoutAS := strings.TrimPrefix(asnNorm, "AS")

	query := `
		SELECT domain, asn, country, ip, port, handshake_ms, cert_days, cert_expire_at, tags, status_code,
		       page_title, is_cdn, is_hot, is_default_page, default_page_type,
		       stars, is_active, check_fail_count, first_seen_at, last_checked_at
		FROM reality_targets
		WHERE (asn = $1 OR asn = $2)
	`
	args := []any{withAS, withoutAS}
	argIdx := 3

	if countryNorm != "" {
		query += fmt.Sprintf(" AND country = $%d", argIdx)
		args = append(args, countryNorm)
		argIdx++
	}

	query += " AND is_active = TRUE"

	if maxAge > 0 {
		cutoff := time.Now().Add(-maxAge)
		query += fmt.Sprintf(" AND last_checked_at >= $%d", argIdx)
		args = append(args, cutoff)
		argIdx++
	}

	query += " ORDER BY stars DESC, handshake_ms ASC"

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []*types.TargetRecord
	for rows.Next() {
		rec, err := scanPostgresTargetRecord(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, rec)
	}

	return records, rows.Err()
}

// GetAllTargets 查询数据库中全部有效资产
func (s *PostgresStore) GetAllTargets() ([]*types.TargetRecord, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	query := `
		SELECT domain, asn, country, ip, port, handshake_ms, cert_days, cert_expire_at, tags, status_code,
		       page_title, is_cdn, is_hot, is_default_page, default_page_type,
		       stars, is_active, check_fail_count, first_seen_at, last_checked_at
		FROM reality_targets
		ORDER BY stars DESC, handshake_ms ASC
	`
	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []*types.TargetRecord
	for rows.Next() {
		rec, err := scanPostgresTargetRecord(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, rec)
	}

	return records, rows.Err()
}

// QueryTargets 分页与多维度条件检索目标资产
func (s *PostgresStore) QueryTargets(opts types.TargetQueryOptions) ([]*types.TargetRecord, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	whereClauses := []string{"1=1"}
	args := []any{}
	idx := 1

	if kw := strings.TrimSpace(opts.Keyword); kw != "" {
		likePattern := "%" + kw + "%"
		whereClauses = append(whereClauses, fmt.Sprintf("(domain ILIKE $%d OR ip ILIKE $%d OR page_title ILIKE $%d)", idx, idx+1, idx+2))
		args = append(args, likePattern, likePattern, likePattern)
		idx += 3
	}

	if asn := strings.TrimSpace(opts.ASN); asn != "" {
		asnNorm := strings.ToUpper(asn)
		withAS := asnNorm
		if !strings.HasPrefix(withAS, "AS") {
			withAS = "AS" + withAS
		}
		withoutAS := strings.TrimPrefix(asnNorm, "AS")
		whereClauses = append(whereClauses, fmt.Sprintf("(asn = $%d OR asn = $%d)", idx, idx+1))
		args = append(args, withAS, withoutAS)
		idx += 2
	}

	if country := strings.TrimSpace(opts.Country); country != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("country = $%d", idx))
		args = append(args, strings.ToUpper(country))
		idx++
	}

	if opts.MinStars > 0 {
		whereClauses = append(whereClauses, fmt.Sprintf("stars >= $%d", idx))
		args = append(args, opts.MinStars)
		idx++
	}

	if opts.IsActive != nil {
		whereClauses = append(whereClauses, fmt.Sprintf("is_active = $%d", idx))
		args = append(args, *opts.IsActive)
		idx++
	}

	whereSQL := strings.Join(whereClauses, " AND ")

	countQuery := "SELECT COUNT(*) FROM reality_targets WHERE " + whereSQL
	var total int
	if err := s.pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	orderSQL := "ORDER BY stars DESC, handshake_ms ASC"
	switch opts.SortBy {
	case "handshake_asc":
		orderSQL = "ORDER BY handshake_ms ASC, stars DESC"
	case "recent_desc":
		orderSQL = "ORDER BY last_checked_at DESC"
	case "stars_desc":
		orderSQL = "ORDER BY stars DESC, handshake_ms ASC"
	}

	limit := opts.PageSize
	if limit <= 0 {
		limit = 20
	}
	page := opts.Page
	if page <= 0 {
		page = 1
	}
	offset := (page - 1) * limit

	dataQuery := fmt.Sprintf(`
		SELECT domain, asn, country, ip, port, handshake_ms, cert_days, cert_expire_at, tags, status_code,
		       page_title, is_cdn, is_hot, is_default_page, default_page_type,
		       stars, is_active, check_fail_count, first_seen_at, last_checked_at
		FROM reality_targets
		WHERE %s
		%s
		LIMIT $%d OFFSET $%d
	`, whereSQL, orderSQL, idx, idx+1)

	dataArgs := append(append([]any{}, args...), limit, offset)
	rows, err := s.pool.Query(ctx, dataQuery, dataArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var results []*types.TargetRecord
	for rows.Next() {
		rec, err := scanPostgresTargetRecord(rows)
		if err != nil {
			return nil, 0, err
		}
		results = append(results, rec)
	}

	return results, total, rows.Err()
}

// UpdateTargetActive 切换资产的激活/禁用状态
func (s *PostgresStore) UpdateTargetActive(domain string, active bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd, err := s.pool.Exec(ctx, "UPDATE reality_targets SET is_active = $1 WHERE domain = $2", active, strings.ToLower(strings.TrimSpace(domain)))
	if err != nil {
		return err
	}
	if cmd.RowsAffected() == 0 {
		return fmt.Errorf("资产不存在: %s", domain)
	}
	return nil
}

// DeleteTarget 从数据库中永久删除指定资产
func (s *PostgresStore) DeleteTarget(domain string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd, err := s.pool.Exec(ctx, "DELETE FROM reality_targets WHERE domain = $1", strings.ToLower(strings.TrimSpace(domain)))
	if err != nil {
		return err
	}
	if cmd.RowsAffected() == 0 {
		return fmt.Errorf("资产不存在: %s", domain)
	}
	return nil
}

// Count 获取当前资产总量
func (s *PostgresStore) Count() int {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var count int
	_ = s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM reality_targets").Scan(&count)
	return count
}

// Export 导出全部资产到 JSON 文件
func (s *PostgresStore) Export(exportPath string) error {
	records, err := s.GetAllTargets()
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(exportPath, data, 0644)
}

// Import 从外部 JSON 文件导入资产
func (s *PostgresStore) Import(importPath string) (int, error) {
	data, err := os.ReadFile(importPath)
	if err != nil {
		return 0, err
	}

	var list []*types.TargetRecord
	if err := json.Unmarshal(data, &list); err != nil {
		return 0, err
	}

	if err := s.UpsertTargets(list); err != nil {
		return 0, err
	}
	return len(list), nil
}

// GetStats 获取资产全景统计指标
func (s *PostgresStore) GetStats() (*types.TargetStats, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stats := &types.TargetStats{
		CountryCounts: make(map[string]int),
		StarCounts:    make(map[int]int),
	}

	_ = s.pool.QueryRow(ctx, `
		SELECT 
			COUNT(*),
			COALESCE(SUM(CASE WHEN is_active THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN stars >= 5 THEN 1 ELSE 0 END), 0),
			COALESCE(AVG(CASE WHEN is_active AND handshake_ms > 0 THEN handshake_ms END), 0)
		FROM reality_targets
	`).Scan(&stats.TotalTargets, &stats.ActiveTargets, &stats.FiveStarTargets, &stats.AvgHandshakeMS)

	_ = s.pool.QueryRow(ctx, "SELECT COUNT(DISTINCT asn) FROM reality_targets WHERE asn != ''").Scan(&stats.TotalASNs)

	if rows, err := s.pool.Query(ctx, "SELECT country, COUNT(*) FROM reality_targets WHERE country != '' GROUP BY country ORDER BY COUNT(*) DESC LIMIT 20"); err == nil {
		for rows.Next() {
			var country string
			var count int
			if err := rows.Scan(&country, &count); err == nil {
				stats.CountryCounts[country] = count
			}
		}
		rows.Close()
	}

	if rows, err := s.pool.Query(ctx, "SELECT stars, COUNT(*) FROM reality_targets GROUP BY stars"); err == nil {
		for rows.Next() {
			var stars, count int
			if err := rows.Scan(&stars, &count); err == nil {
				stats.StarCounts[stars] = count
			}
		}
		rows.Close()
	}

	return stats, nil
}

// GetCheckpoints 获取某个任务的所有断点记录
func (s *PostgresStore) GetCheckpoints(taskKey string) (map[string]*CheckpointRecord, error) {
	if taskKey == "" {
		return nil, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rows, err := s.pool.Query(ctx, "SELECT cidr, last_ip, completed, updated_at FROM scan_checkpoints WHERE task_key = $1", taskKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	res := make(map[string]*CheckpointRecord)
	for rows.Next() {
		var rec CheckpointRecord
		rec.TaskKey = taskKey
		if err := rows.Scan(&rec.CIDR, &rec.LastIP, &rec.Completed, &rec.UpdatedAt); err != nil {
			return nil, err
		}
		res[rec.CIDR] = &rec
	}

	return res, rows.Err()
}

// RecordCheckpoint 记录单个 CIDR 的断点
func (s *PostgresStore) RecordCheckpoint(taskKey, cidr, lastIP string, completed bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := `
		INSERT INTO scan_checkpoints (task_key, cidr, last_ip, completed, updated_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (task_key, cidr) DO UPDATE SET
			last_ip = EXCLUDED.last_ip,
			completed = EXCLUDED.completed,
			updated_at = EXCLUDED.updated_at
	`
	_, err := s.pool.Exec(ctx, query, sanitizeUTF8(taskKey), sanitizeUTF8(cidr), sanitizeUTF8(lastIP), completed, time.Now().UTC())
	return err
}

// ClearCheckpoints 清空指定任务的所有断点
func (s *PostgresStore) ClearCheckpoints(taskKey string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := s.pool.Exec(ctx, "DELETE FROM scan_checkpoints WHERE task_key = $1", taskKey)
	return err
}

// UpsertASNRecords 批量录入或更新全球 ASN 元数据
func (s *PostgresStore) UpsertASNRecords(records []*types.ASNRecord) error {
	if len(records) == 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	query := `
		INSERT INTO asn_registry (
			asn, name, country, total_ips, priority, scan_status, last_scanned_at, success_target_count, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (asn) DO UPDATE SET
			name = CASE WHEN EXCLUDED.name != '' THEN EXCLUDED.name ELSE asn_registry.name END,
			country = CASE WHEN EXCLUDED.country != '' THEN EXCLUDED.country ELSE asn_registry.country END,
			total_ips = CASE WHEN EXCLUDED.total_ips > 0 THEN EXCLUDED.total_ips ELSE asn_registry.total_ips END,
			priority = EXCLUDED.priority,
			updated_at = EXCLUDED.updated_at
	`

	batch := &pgx.Batch{}
	now := time.Now().UTC()
	count := 0

	for _, rec := range records {
		if rec == nil || rec.ASN <= 0 {
			continue
		}
		status := rec.ScanStatus
		if status == "" {
			status = "pending"
		}
		prio := rec.Priority
		if prio < 0 {
			prio = 0
		}
		batch.Queue(query,
			rec.ASN,
			sanitizeUTF8(rec.Name),
			sanitizeUTF8(strings.ToUpper(strings.TrimSpace(rec.Country))),
			rec.TotalIPs,
			prio,
			sanitizeUTF8(status),
			rec.LastScannedAt,
			rec.SuccessTargetCount,
			now,
		)
		count++
	}

	if count == 0 {
		return nil
	}

	br := s.pool.SendBatch(ctx, batch)
	defer br.Close()

	for i := 0; i < count; i++ {
		if _, err := br.Exec(); err != nil {
			return err
		}
	}

	return nil
}

// GetNextPendingASN 依据优先级获取下一个待扫描的 ASN 任务
func (s *PostgresStore) GetNextPendingASN(minPriority int) (*types.ASNRecord, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := `
		SELECT asn, name, country, total_ips, priority, scan_status, last_scanned_at, success_target_count, updated_at
		FROM asn_registry
		WHERE scan_status = 'pending' AND priority >= $1
		ORDER BY priority DESC, total_ips DESC
		LIMIT 1
	`
	row := s.pool.QueryRow(ctx, query, minPriority)

	var rec types.ASNRecord
	var lastScannedAt *time.Time
	err := row.Scan(
		&rec.ASN,
		&rec.Name,
		&rec.Country,
		&rec.TotalIPs,
		&rec.Priority,
		&rec.ScanStatus,
		&lastScannedAt,
		&rec.SuccessTargetCount,
		&rec.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if lastScannedAt != nil {
		rec.LastScannedAt = *lastScannedAt
	}

	return &rec, nil
}

// UpdateASNStatus 更新 ASN 任务状态与命中成果数
func (s *PostgresStore) UpdateASNStatus(asn int, status string, successCountDelta int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	now := time.Now().UTC()
	var err error
	if status == "completed" {
		query := `
			UPDATE asn_registry
			SET scan_status = $1,
			    last_scanned_at = $2,
			    success_target_count = success_target_count + $3,
			    updated_at = $4
			WHERE asn = $5
		`
		_, err = s.pool.Exec(ctx, query, status, now, successCountDelta, now, asn)
	} else {
		query := `
			UPDATE asn_registry
			SET scan_status = $1,
			    success_target_count = success_target_count + $2,
			    updated_at = $3
			WHERE asn = $4
		`
		_, err = s.pool.Exec(ctx, query, status, successCountDelta, now, asn)
	}

	return err
}

// UpdateASNPriority 更新指定自治系统的调度优先级权重
func (s *PostgresStore) UpdateASNPriority(asn int, priority int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := s.pool.Exec(ctx, "UPDATE asn_registry SET priority = $1, updated_at = $2 WHERE asn = $3", priority, time.Now(), asn)
	return err
}

// GetASN 获取单个 ASN 记录
func (s *PostgresStore) GetASN(asn int) (*types.ASNRecord, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := `
		SELECT asn, name, country, total_ips, priority, scan_status, last_scanned_at, success_target_count, updated_at
		FROM asn_registry
		WHERE asn = $1
	`
	row := s.pool.QueryRow(ctx, query, asn)

	var rec types.ASNRecord
	var lastScannedAt *time.Time
	err := row.Scan(
		&rec.ASN,
		&rec.Name,
		&rec.Country,
		&rec.TotalIPs,
		&rec.Priority,
		&rec.ScanStatus,
		&lastScannedAt,
		&rec.SuccessTargetCount,
		&rec.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if lastScannedAt != nil {
		rec.LastScannedAt = *lastScannedAt
	}

	return &rec, nil
}

// CountASNs 统计 ASN 总量
func (s *PostgresStore) CountASNs(status string) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var count int
	var err error
	if status != "" {
		err = s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM asn_registry WHERE scan_status = $1", status).Scan(&count)
	} else {
		err = s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM asn_registry").Scan(&count)
	}
	return count, err
}

// ListASNs 分页列表展示 ASN
func (s *PostgresStore) ListASNs(status string, minPriority, limit, offset int) ([]*types.ASNRecord, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	whereClauses := []string{"1=1"}
	args := []any{}
	idx := 1

	if status != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("scan_status = $%d", idx))
		args = append(args, status)
		idx++
	}
	if minPriority > 0 {
		whereClauses = append(whereClauses, fmt.Sprintf("priority >= $%d", idx))
		args = append(args, minPriority)
		idx++
	}

	whereSQL := strings.Join(whereClauses, " AND ")
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	query := fmt.Sprintf(`
		SELECT asn, name, country, total_ips, priority, scan_status, last_scanned_at, success_target_count, updated_at
		FROM asn_registry
		WHERE %s
		ORDER BY priority DESC, total_ips DESC
		LIMIT $%d OFFSET $%d
	`, whereSQL, idx, idx+1)

	args = append(args, limit, offset)

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []*types.ASNRecord
	for rows.Next() {
		var rec types.ASNRecord
		var lastScannedAt *time.Time
		if err := rows.Scan(
			&rec.ASN,
			&rec.Name,
			&rec.Country,
			&rec.TotalIPs,
			&rec.Priority,
			&rec.ScanStatus,
			&lastScannedAt,
			&rec.SuccessTargetCount,
			&rec.UpdatedAt,
		); err != nil {
			return nil, err
		}
		if lastScannedAt != nil {
			rec.LastScannedAt = *lastScannedAt
		}
		results = append(results, &rec)
	}

	return results, rows.Err()
}

// ResetScanningASNs 将异常中断处于 scanning 状态的 ASN 重置为 pending
func (s *PostgresStore) ResetScanningASNs() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := s.pool.Exec(ctx, "UPDATE asn_registry SET scan_status = 'pending' WHERE scan_status = 'scanning'")
	return err
}

// ResetAllASNsStatus 将全部非 CDN ASN 任务重置为 pending（保留 priority=0 纯商业 CDN 为 completed）
func (s *PostgresStore) ResetAllASNsStatus() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := s.pool.Exec(ctx, "UPDATE asn_registry SET scan_status = 'pending' WHERE priority > 0")
	return err
}

// InsertPatrolLog 插入一条巡检日志记录
func (s *PostgresStore) InsertPatrolLog(log *types.PatrolLogRecord) error {
	if log == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	checkedAt := log.CheckedAt
	if checkedAt.IsZero() {
		checkedAt = time.Now().UTC()
	}

	query := `
		INSERT INTO target_patrol_logs (domain, ip, handshake_ms, is_success, error_msg, checked_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	_, err := s.pool.Exec(ctx, query, sanitizeUTF8(log.Domain), sanitizeUTF8(log.IP), log.HandshakeMS, log.IsSuccess, sanitizeUTF8(log.ErrorMsg), checkedAt)
	return err
}

// CleanExpiredPatrolLogs 清理超过保留时限的巡检历史日志
func (s *PostgresStore) CleanExpiredPatrolLogs(retention time.Duration) (int64, error) {
	if retention <= 0 {
		return 0, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cutoff := time.Now().Add(-retention)
	cmd, err := s.pool.Exec(ctx, "DELETE FROM target_patrol_logs WHERE checked_at < $1", cutoff)
	if err != nil {
		return 0, err
	}
	return cmd.RowsAffected(), nil
}

// UpdateTargetPatrolResult 事务更新存量资产的巡检指标
func (s *PostgresStore) UpdateTargetPatrolResult(domain, ip string, handshakeMS int64, certDays int, success bool, errStr string) error {
	domainKey := strings.ToLower(strings.TrimSpace(domain))
	if domainKey == "" {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	now := time.Now().UTC()

	// 1. 记录日志
	_, err = tx.Exec(ctx, `
		INSERT INTO target_patrol_logs (domain, ip, handshake_ms, is_success, error_msg, checked_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, sanitizeUTF8(domainKey), sanitizeUTF8(ip), handshakeMS, success, sanitizeUTF8(errStr), now)
	if err != nil {
		return err
	}

	// 2. 更新资产状态
	if success {
		_, err = tx.Exec(ctx, `
			UPDATE reality_targets
			SET handshake_ms = $1,
			    cert_days = $2,
			    is_active = TRUE,
			    check_fail_count = 0,
			    last_checked_at = $3
			WHERE domain = $4
		`, handshakeMS, certDays, now, domainKey)
	} else {
		_, err = tx.Exec(ctx, `
			UPDATE reality_targets
			SET check_fail_count = check_fail_count + 1,
			    is_active = CASE WHEN check_fail_count + 1 >= 3 THEN FALSE ELSE is_active END,
			    last_checked_at = $1
			WHERE domain = $2
		`, now, domainKey)
	}

	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// GetTargetsForPatrol 获取需要进行健康巡检的存量资产列表
func (s *PostgresStore) GetTargetsForPatrol(minStars int, olderThan time.Duration, limit int) ([]*types.TargetRecord, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cutoff := time.Now().Add(-olderThan)
	if limit <= 0 {
		limit = 100
	}

	query := `
		SELECT domain, asn, country, ip, port, handshake_ms, cert_days, cert_expire_at, tags, status_code,
		       page_title, is_cdn, is_hot, is_default_page, default_page_type,
		       stars, is_active, check_fail_count, first_seen_at, last_checked_at
		FROM reality_targets
		WHERE is_active = TRUE AND stars >= $1 AND last_checked_at <= $2
		ORDER BY last_checked_at ASC
		LIMIT $3
	`
	rows, err := s.pool.Query(ctx, query, minStars, cutoff, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []*types.TargetRecord
	for rows.Next() {
		rec, err := scanPostgresTargetRecord(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, rec)
	}

	return records, rows.Err()
}

// DeleteExpiredInactiveTargets 永久清理长效失效的冷资产
func (s *PostgresStore) DeleteExpiredInactiveTargets(inactiveDuration time.Duration) (int64, error) {
	if inactiveDuration <= 0 {
		return 0, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cutoff := time.Now().Add(-inactiveDuration)
	cmd, err := s.pool.Exec(ctx, `
		DELETE FROM reality_targets
		WHERE is_active = FALSE AND last_checked_at <= $1
	`, cutoff)
	if err != nil {
		return 0, err
	}

	return cmd.RowsAffected(), nil
}

// RunWALCheckpoint 在 PostgreSQL 中执行 ANALYZE 收集统计信息
func (s *PostgresStore) RunWALCheckpoint() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := s.pool.Exec(ctx, "ANALYZE reality_targets; ANALYZE asn_registry;")
	return err
}

// IsPostgresError 辅助判断是否为 PostgreSQL 原生网络或语义错误
func IsPostgresError(err error) bool {
	var pgErr *pgconn.PgError
	return err != nil && (strings.Contains(err.Error(), "pgx") || strings.Contains(err.Error(), "postgres")) || (func() bool {
		return fmt.Errorf("%w", err) == pgErr
	})()
}

// UpdateTargetCertRenewal 更新目标资产的证书续期探测状态与标签
func (s *PostgresStore) UpdateTargetCertRenewal(domain string, certExpireAt time.Time, certDays int, tags []string, handshakeMS int64) error {
	domainKey := strings.ToLower(strings.TrimSpace(domain))
	if domainKey == "" {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	now := time.Now().UTC()
	tagsStr := strings.Join(tags, ",")

	var expireVal any = nil
	if !certExpireAt.IsZero() {
		expireVal = certExpireAt
	}

	_, err := s.pool.Exec(ctx, `
		UPDATE reality_targets
		SET cert_expire_at = $1,
		    cert_days = $2,
		    tags = $3,
		    handshake_ms = CASE WHEN $4 > 0 THEN $4 ELSE handshake_ms END,
		    last_checked_at = $5
		WHERE domain = $6
	`, expireVal, certDays, sanitizeUTF8(tagsStr), handshakeMS, now, sanitizeUTF8(domainKey))
	return err
}

// sanitizeUTF8 清洗非合法 UTF-8 字节与 NUL 字符，确保符合 PostgreSQL 文本存储规范 (防御 SQLSTATE 22021)
func sanitizeUTF8(s string) string {
	if s == "" {
		return ""
	}
	if strings.ContainsRune(s, '\x00') {
		s = strings.ReplaceAll(s, "\x00", "")
	}
	return strings.ToValidUTF8(s, "")
}
