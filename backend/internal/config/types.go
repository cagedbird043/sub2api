// Package config provides configuration loading, defaults, and validation.
package config

import (
	"fmt"
	"time"
)

const (
	RunModeStandard = "standard"
	RunModeSimple   = "simple"
)

// DefaultCSPPolicy is the default Content-Security-Policy with nonce support
// __CSP_NONCE__ will be replaced with actual nonce at request time by the SecurityHeaders middleware
const DefaultCSPPolicy = "default-src 'self'; script-src 'self' __CSP_NONCE__ https://challenges.cloudflare.com https://static.cloudflareinsights.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data: https:; font-src 'self' data: https://fonts.gstatic.com; connect-src 'self' https:; frame-src https://challenges.cloudflare.com; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"

// 连接池隔离策略常量
// 用于控制上游 HTTP 连接池的隔离粒度，影响连接复用和资源消耗
const (
	// ConnectionPoolIsolationProxy: 按代理隔离
	// 同一代理地址共享连接池，适合代理数量少、账户数量多的场景
	ConnectionPoolIsolationProxy = "proxy"
	// ConnectionPoolIsolationAccount: 按账户隔离
	// 每个账户独立连接池，适合账户数量少、需要严格隔离的场景
	ConnectionPoolIsolationAccount = "account"
	// ConnectionPoolIsolationAccountProxy: 按账户+代理组合隔离（默认）
	// 同一账户+代理组合共享连接池，提供最细粒度的隔离
	ConnectionPoolIsolationAccountProxy = "account_proxy"
)

type Config struct {
	Server       ServerConfig               `mapstructure:"server"`
	CORS         CORSConfig                 `mapstructure:"cors"`
	Security     SecurityConfig             `mapstructure:"security"`
	Billing      BillingConfig              `mapstructure:"billing"`
	Turnstile    TurnstileConfig            `mapstructure:"turnstile"`
	Database     DatabaseConfig             `mapstructure:"database"`
	Redis        RedisConfig                `mapstructure:"redis"`
	Ops          OpsConfig                  `mapstructure:"ops"`
	JWT          JWTConfig                  `mapstructure:"jwt"`
	Totp         TotpConfig                 `mapstructure:"totp"`
	LinuxDo      LinuxDoConnectConfig       `mapstructure:"linuxdo_connect"`
	Default      DefaultConfig              `mapstructure:"default"`
	RateLimit    RateLimitConfig            `mapstructure:"rate_limit"`
	Pricing      PricingConfig              `mapstructure:"pricing"`
	Gateway      GatewayConfig              `mapstructure:"gateway"`
	APIKeyAuth   APIKeyAuthCacheConfig      `mapstructure:"api_key_auth_cache"`
	Dashboard    DashboardCacheConfig       `mapstructure:"dashboard_cache"`
	DashboardAgg DashboardAggregationConfig `mapstructure:"dashboard_aggregation"`
	UsageCleanup UsageCleanupConfig         `mapstructure:"usage_cleanup"`
	Concurrency  ConcurrencyConfig          `mapstructure:"concurrency"`
	TokenRefresh TokenRefreshConfig         `mapstructure:"token_refresh"`
	RunMode      string                     `mapstructure:"run_mode" yaml:"run_mode"`
	Timezone     string                     `mapstructure:"timezone"` // e.g. "Asia/Shanghai", "UTC"
	Gemini       GeminiConfig               `mapstructure:"gemini"`
	Update       UpdateConfig               `mapstructure:"update"`
}

type GeminiConfig struct {
	OAuth GeminiOAuthConfig `mapstructure:"oauth"`
	Quota GeminiQuotaConfig `mapstructure:"quota"`
}

type GeminiOAuthConfig struct {
	ClientID     string `mapstructure:"client_id"`
	ClientSecret string `mapstructure:"client_secret"`
	Scopes       string `mapstructure:"scopes"`
}

type GeminiQuotaConfig struct {
	Tiers  map[string]GeminiTierQuotaConfig `mapstructure:"tiers"`
	Policy string                           `mapstructure:"policy"`
}

type GeminiTierQuotaConfig struct {
	ProRPD          *int64 `mapstructure:"pro_rpd" json:"pro_rpd"`
	FlashRPD        *int64 `mapstructure:"flash_rpd" json:"flash_rpd"`
	CooldownMinutes *int   `mapstructure:"cooldown_minutes" json:"cooldown_minutes"`
}

type UpdateConfig struct {
	// ProxyURL 用于访问 GitHub 的代理地址
	// 支持 http/https/socks5/socks5h 协议
	// 例如: "http://127.0.0.1:7890", "socks5://127.0.0.1:1080"
	ProxyURL string `mapstructure:"proxy_url"`
}

type LinuxDoConnectConfig struct {
	Enabled             bool   `mapstructure:"enabled"`
	ClientID            string `mapstructure:"client_id"`
	ClientSecret        string `mapstructure:"client_secret"`
	AuthorizeURL        string `mapstructure:"authorize_url"`
	TokenURL            string `mapstructure:"token_url"`
	UserInfoURL         string `mapstructure:"userinfo_url"`
	Scopes              string `mapstructure:"scopes"`
	RedirectURL         string `mapstructure:"redirect_url"`          // 后端回调地址（需在提供方后台登记）
	FrontendRedirectURL string `mapstructure:"frontend_redirect_url"` // 前端接收 token 的路由（默认：/auth/linuxdo/callback）
	TokenAuthMethod     string `mapstructure:"token_auth_method"`     // client_secret_post / client_secret_basic / none
	UsePKCE             bool   `mapstructure:"use_pkce"`

	// 可选：用于从 userinfo JSON 中提取字段的 gjson 路径。
	// 为空时，服务端会尝试一组常见字段名。
	UserInfoEmailPath    string `mapstructure:"userinfo_email_path"`
	UserInfoIDPath       string `mapstructure:"userinfo_id_path"`
	UserInfoUsernamePath string `mapstructure:"userinfo_username_path"`
}

// TokenRefreshConfig OAuth token自动刷新配置
type TokenRefreshConfig struct {
	// 是否启用自动刷新
	Enabled bool `mapstructure:"enabled"`
	// 检查间隔（分钟）
	CheckIntervalMinutes int `mapstructure:"check_interval_minutes"`
	// 提前刷新时间（小时），在token过期前多久开始刷新
	RefreshBeforeExpiryHours float64 `mapstructure:"refresh_before_expiry_hours"`
	// 最大重试次数
	MaxRetries int `mapstructure:"max_retries"`
	// 重试退避基础时间（秒）
	RetryBackoffSeconds int `mapstructure:"retry_backoff_seconds"`
}

type PricingConfig struct {
	// 价格数据远程URL（默认使用LiteLLM镜像）
	RemoteURL string `mapstructure:"remote_url"`
	// 哈希校验文件URL
	HashURL string `mapstructure:"hash_url"`
	// 本地数据目录
	DataDir string `mapstructure:"data_dir"`
	// 回退文件路径
	FallbackFile string `mapstructure:"fallback_file"`
	// 更新间隔（小时）
	UpdateIntervalHours int `mapstructure:"update_interval_hours"`
	// 哈希校验间隔（分钟）
	HashCheckIntervalMinutes int `mapstructure:"hash_check_interval_minutes"`
}

type ServerConfig struct {
	Host               string    `mapstructure:"host"`
	Port               int       `mapstructure:"port"`
	Mode               string    `mapstructure:"mode"`                  // debug/release
	ReadHeaderTimeout  int       `mapstructure:"read_header_timeout"`   // 读取请求头超时（秒）
	IdleTimeout        int       `mapstructure:"idle_timeout"`          // 空闲连接超时（秒）
	TrustedProxies     []string  `mapstructure:"trusted_proxies"`       // 可信代理列表（CIDR/IP）
	MaxRequestBodySize int64     `mapstructure:"max_request_body_size"` // 全局最大请求体限制
	H2C                H2CConfig `mapstructure:"h2c"`                   // HTTP/2 Cleartext 配置
}

// H2CConfig HTTP/2 Cleartext 配置
type H2CConfig struct {
	Enabled                      bool   `mapstructure:"enabled"`                          // 是否启用 H2C
	MaxConcurrentStreams         uint32 `mapstructure:"max_concurrent_streams"`           // 最大并发流数量
	IdleTimeout                  int    `mapstructure:"idle_timeout"`                     // 空闲超时（秒）
	MaxReadFrameSize             int    `mapstructure:"max_read_frame_size"`              // 最大帧大小（字节）
	MaxUploadBufferPerConnection int    `mapstructure:"max_upload_buffer_per_connection"` // 每个连接的上传缓冲区（字节）
	MaxUploadBufferPerStream     int    `mapstructure:"max_upload_buffer_per_stream"`     // 每个流的上传缓冲区（字节）
}

type CORSConfig struct {
	AllowedOrigins   []string `mapstructure:"allowed_origins"`
	AllowCredentials bool     `mapstructure:"allow_credentials"`
}

type SecurityConfig struct {
	URLAllowlist    URLAllowlistConfig   `mapstructure:"url_allowlist"`
	ResponseHeaders ResponseHeaderConfig `mapstructure:"response_headers"`
	CSP             CSPConfig            `mapstructure:"csp"`
	ProxyProbe      ProxyProbeConfig     `mapstructure:"proxy_probe"`
}

type URLAllowlistConfig struct {
	Enabled           bool     `mapstructure:"enabled"`
	UpstreamHosts     []string `mapstructure:"upstream_hosts"`
	PricingHosts      []string `mapstructure:"pricing_hosts"`
	CRSHosts          []string `mapstructure:"crs_hosts"`
	AllowPrivateHosts bool     `mapstructure:"allow_private_hosts"`
	// 关闭 URL 白名单校验时，是否允许 http URL（默认只允许 https）
	AllowInsecureHTTP bool `mapstructure:"allow_insecure_http"`
}

type ResponseHeaderConfig struct {
	Enabled           bool     `mapstructure:"enabled"`
	AdditionalAllowed []string `mapstructure:"additional_allowed"`
	ForceRemove       []string `mapstructure:"force_remove"`
}

type CSPConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Policy  string `mapstructure:"policy"`
}

type ProxyProbeConfig struct {
	InsecureSkipVerify bool `mapstructure:"insecure_skip_verify"` // 已禁用：禁止跳过 TLS 证书验证
}

type BillingConfig struct {
	CircuitBreaker CircuitBreakerConfig `mapstructure:"circuit_breaker"`
}

type CircuitBreakerConfig struct {
	Enabled             bool `mapstructure:"enabled"`
	FailureThreshold    int  `mapstructure:"failure_threshold"`
	ResetTimeoutSeconds int  `mapstructure:"reset_timeout_seconds"`
	HalfOpenRequests    int  `mapstructure:"half_open_requests"`
}

type ConcurrencyConfig struct {
	// PingInterval: 并发等待期间的 SSE ping 间隔（秒）
	PingInterval int `mapstructure:"ping_interval"`
}

// GatewayConfig API网关相关配置
type GatewayConfig struct {
	// 等待上游响应头的超时时间（秒），0表示无超时
	// 注意：这不影响流式数据传输，只控制等待响应头的时间
	ResponseHeaderTimeout int `mapstructure:"response_header_timeout"`
	// 请求体最大字节数，用于网关请求体大小限制
	MaxBodySize int64 `mapstructure:"max_body_size"`
	// ConnectionPoolIsolation: 上游连接池隔离策略（proxy/account/account_proxy）
	ConnectionPoolIsolation string `mapstructure:"connection_pool_isolation"`

	// HTTP 上游连接池配置（性能优化：支持高并发场景调优）
	// MaxIdleConns: 所有主机的最大空闲连接总数
	MaxIdleConns int `mapstructure:"max_idle_conns"`
	// MaxIdleConnsPerHost: 每个主机的最大空闲连接数（关键参数，影响连接复用率）
	MaxIdleConnsPerHost int `mapstructure:"max_idle_conns_per_host"`
	// MaxConnsPerHost: 每个主机的最大连接数（包括活跃+空闲），0表示无限制
	MaxConnsPerHost int `mapstructure:"max_conns_per_host"`
	// IdleConnTimeoutSeconds: 空闲连接超时时间（秒）
	IdleConnTimeoutSeconds int `mapstructure:"idle_conn_timeout_seconds"`
	// MaxUpstreamClients: 上游连接池客户端最大缓存数量
	// 当使用连接池隔离策略时，系统会为不同的账户/代理组合创建独立的 HTTP 客户端
	// 此参数限制缓存的客户端数量，超出后会淘汰最久未使用的客户端
	// 建议值：预估的活跃账户数 * 1.2（留有余量）
	MaxUpstreamClients int `mapstructure:"max_upstream_clients"`
	// ClientIdleTTLSeconds: 上游连接池客户端空闲回收阈值（秒）
	// 超过此时间未使用的客户端会被标记为可回收
	// 建议值：根据用户访问频率设置，一般 10-30 分钟
	ClientIdleTTLSeconds int `mapstructure:"client_idle_ttl_seconds"`
	// ConcurrencySlotTTLMinutes: 并发槽位过期时间（分钟）
	// 应大于最长 LLM 请求时间，防止请求完成前槽位过期
	ConcurrencySlotTTLMinutes int `mapstructure:"concurrency_slot_ttl_minutes"`
	// SessionIdleTimeoutMinutes: 会话空闲超时时间（分钟），默认 5 分钟
	// 用于 Anthropic OAuth/SetupToken 账号的会话数量限制功能
	// 空闲超过此时间的会话将被自动释放
	SessionIdleTimeoutMinutes int `mapstructure:"session_idle_timeout_minutes"`

	// StreamDataIntervalTimeout: 流数据间隔超时（秒），0表示禁用
	StreamDataIntervalTimeout int `mapstructure:"stream_data_interval_timeout"`
	// StreamKeepaliveInterval: 流式 keepalive 间隔（秒），0表示禁用
	StreamKeepaliveInterval int `mapstructure:"stream_keepalive_interval"`
	// MaxLineSize: 上游 SSE 单行最大字节数（0使用默认值）
	MaxLineSize int `mapstructure:"max_line_size"`

	// 是否记录上游错误响应体摘要（避免输出请求内容）
	LogUpstreamErrorBody bool `mapstructure:"log_upstream_error_body"`
	// 上游错误响应体记录最大字节数（超过会截断）
	LogUpstreamErrorBodyMaxBytes int `mapstructure:"log_upstream_error_body_max_bytes"`

	// API-key 账号在客户端未提供 anthropic-beta 时，是否按需自动补齐（默认关闭以保持兼容）
	InjectBetaForAPIKey bool `mapstructure:"inject_beta_for_apikey"`

	// 是否允许对部分 400 错误触发 failover（默认关闭以避免改变语义）
	FailoverOn400 bool `mapstructure:"failover_on_400"`

	// 账户切换最大次数（遇到上游错误时切换到其他账户的次数上限）
	MaxAccountSwitches int `mapstructure:"max_account_switches"`
	// Gemini 账户切换最大次数（Gemini 平台单独配置，因 API 限制更严格）
	MaxAccountSwitchesGemini int `mapstructure:"max_account_switches_gemini"`

	// Antigravity 429 fallback 限流时间（分钟），解析重置时间失败时使用
	AntigravityFallbackCooldownMinutes int `mapstructure:"antigravity_fallback_cooldown_minutes"`

	// Scheduling: 账号调度相关配置
	Scheduling GatewaySchedulingConfig `mapstructure:"scheduling"`

	// TLSFingerprint: TLS指纹伪装配置
	TLSFingerprint TLSFingerprintConfig `mapstructure:"tls_fingerprint"`
}

// TLSFingerprintConfig TLS指纹伪装配置
// 用于模拟 Claude CLI (Node.js) 的 TLS 握手特征，避免被识别为非官方客户端
type TLSFingerprintConfig struct {
	// Enabled: 是否全局启用TLS指纹功能
	Enabled bool `mapstructure:"enabled"`
	// Profiles: 预定义的TLS指纹配置模板
	// key 为模板名称，如 "claude_cli_v2", "chrome_120" 等
	Profiles map[string]TLSProfileConfig `mapstructure:"profiles"`
}

// TLSProfileConfig 单个TLS指纹模板的配置
type TLSProfileConfig struct {
	// Name: 模板显示名称
	Name string `mapstructure:"name"`
	// EnableGREASE: 是否启用GREASE扩展（Chrome使用，Node.js不使用）
	EnableGREASE bool `mapstructure:"enable_grease"`
	// CipherSuites: TLS加密套件列表（空则使用内置默认值）
	CipherSuites []uint16 `mapstructure:"cipher_suites"`
	// Curves: 椭圆曲线列表（空则使用内置默认值）
	Curves []uint16 `mapstructure:"curves"`
	// PointFormats: 点格式列表（空则使用内置默认值）
	PointFormats []uint8 `mapstructure:"point_formats"`
}

// GatewaySchedulingConfig accounts scheduling configuration.
type GatewaySchedulingConfig struct {
	// 粘性会话排队配置
	StickySessionMaxWaiting  int           `mapstructure:"sticky_session_max_waiting"`
	StickySessionWaitTimeout time.Duration `mapstructure:"sticky_session_wait_timeout"`

	// 兜底排队配置
	FallbackWaitTimeout time.Duration `mapstructure:"fallback_wait_timeout"`
	FallbackMaxWaiting  int           `mapstructure:"fallback_max_waiting"`

	// 兜底层账户选择策略: "last_used"(按最后使用时间排序，默认) 或 "random"(随机)
	FallbackSelectionMode string `mapstructure:"fallback_selection_mode"`

	// 负载计算
	LoadBatchEnabled bool `mapstructure:"load_batch_enabled"`

	// 过期槽位清理周期（0 表示禁用）
	SlotCleanupInterval time.Duration `mapstructure:"slot_cleanup_interval"`

	// 受控回源配置
	DbFallbackEnabled bool `mapstructure:"db_fallback_enabled"`
	// 受控回源超时（秒），0 表示不额外收紧超时
	DbFallbackTimeoutSeconds int `mapstructure:"db_fallback_timeout_seconds"`
	// 受控回源限流（实例级 QPS），0 表示不限制
	DbFallbackMaxQPS int `mapstructure:"db_fallback_max_qps"`

	// Outbox 轮询与滞后阈值配置
	// Outbox 轮询周期（秒）
	OutboxPollIntervalSeconds int `mapstructure:"outbox_poll_interval_seconds"`
	// Outbox 滞后告警阈值（秒）
	OutboxLagWarnSeconds int `mapstructure:"outbox_lag_warn_seconds"`
	// Outbox 触发强制重建阈值（秒）
	OutboxLagRebuildSeconds int `mapstructure:"outbox_lag_rebuild_seconds"`
	// Outbox 连续滞后触发次数
	OutboxLagRebuildFailures int `mapstructure:"outbox_lag_rebuild_failures"`
	// Outbox 积压触发重建阈值（行数）
	OutboxBacklogRebuildRows int `mapstructure:"outbox_backlog_rebuild_rows"`

	// 全量重建周期配置
	// 全量重建周期（秒），0 表示禁用
	FullRebuildIntervalSeconds int `mapstructure:"full_rebuild_interval_seconds"`
}

func (s *ServerConfig) Address() string {
	return fmt.Sprintf("%s:%d", s.Host, s.Port)
}

// DatabaseConfig 数据库连接配置
// 性能优化：新增连接池参数，避免频繁创建/销毁连接
type DatabaseConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
	DBName   string `mapstructure:"dbname"`
	SSLMode  string `mapstructure:"sslmode"`
	// 连接池配置（性能优化：可配置化连接池参数）
	// MaxOpenConns: 最大打开连接数，控制数据库连接上限，防止资源耗尽
	MaxOpenConns int `mapstructure:"max_open_conns"`
	// MaxIdleConns: 最大空闲连接数，保持热连接减少建连延迟
	MaxIdleConns int `mapstructure:"max_idle_conns"`
	// ConnMaxLifetimeMinutes: 连接最大存活时间，防止长连接导致的资源泄漏
	ConnMaxLifetimeMinutes int `mapstructure:"conn_max_lifetime_minutes"`
	// ConnMaxIdleTimeMinutes: 空闲连接最大存活时间，及时释放不活跃连接
	ConnMaxIdleTimeMinutes int `mapstructure:"conn_max_idle_time_minutes"`
}

func (d *DatabaseConfig) DSN() string {
	// 当密码为空时不包含 password 参数，避免 libpq 解析错误
	if d.Password == "" {
		return fmt.Sprintf(
			"host=%s port=%d user=%s dbname=%s sslmode=%s",
			d.Host, d.Port, d.User, d.DBName, d.SSLMode,
		)
	}
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		d.Host, d.Port, d.User, d.Password, d.DBName, d.SSLMode,
	)
}

// DSNWithTimezone returns DSN with timezone setting
func (d *DatabaseConfig) DSNWithTimezone(tz string) string {
	if tz == "" {
		tz = "Asia/Shanghai"
	}
	// 当密码为空时不包含 password 参数，避免 libpq 解析错误
	if d.Password == "" {
		return fmt.Sprintf(
			"host=%s port=%d user=%s dbname=%s sslmode=%s TimeZone=%s",
			d.Host, d.Port, d.User, d.DBName, d.SSLMode, tz,
		)
	}
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s TimeZone=%s",
		d.Host, d.Port, d.User, d.Password, d.DBName, d.SSLMode, tz,
	)
}

// RedisConfig Redis 连接配置
// 性能优化：新增连接池和超时参数，提升高并发场景下的吞吐量
type RedisConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
	// 连接池与超时配置（性能优化：可配置化连接池参数）
	// DialTimeoutSeconds: 建立连接超时，防止慢连接阻塞
	DialTimeoutSeconds int `mapstructure:"dial_timeout_seconds"`
	// ReadTimeoutSeconds: 读取超时，避免慢查询阻塞连接池
	ReadTimeoutSeconds int `mapstructure:"read_timeout_seconds"`
	// WriteTimeoutSeconds: 写入超时，避免慢写入阻塞连接池
	WriteTimeoutSeconds int `mapstructure:"write_timeout_seconds"`
	// PoolSize: 连接池大小，控制最大并发连接数
	PoolSize int `mapstructure:"pool_size"`
	// MinIdleConns: 最小空闲连接数，保持热连接减少冷启动延迟
	MinIdleConns int `mapstructure:"min_idle_conns"`
	// EnableTLS: 是否启用 TLS/SSL 连接
	EnableTLS bool `mapstructure:"enable_tls"`
}

func (r *RedisConfig) Address() string {
	return fmt.Sprintf("%s:%d", r.Host, r.Port)
}

type OpsConfig struct {
	// Enabled controls whether ops features should run.
	//
	// NOTE: vNext still has a DB-backed feature flag (ops_monitoring_enabled) for runtime on/off.
	// This config flag is the "hard switch" for deployments that want to disable ops completely.
	Enabled bool `mapstructure:"enabled"`

	// UsePreaggregatedTables prefers ops_metrics_hourly/daily for long-window dashboard queries.
	UsePreaggregatedTables bool `mapstructure:"use_preaggregated_tables"`

	// Cleanup controls periodic deletion of old ops data to prevent unbounded growth.
	Cleanup OpsCleanupConfig `mapstructure:"cleanup"`

	// MetricsCollectorCache controls Redis caching for expensive per-window collector queries.
	MetricsCollectorCache OpsMetricsCollectorCacheConfig `mapstructure:"metrics_collector_cache"`

	// Pre-aggregation configuration.
	Aggregation OpsAggregationConfig `mapstructure:"aggregation"`
}

type OpsCleanupConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	Schedule string `mapstructure:"schedule"`

	// Retention days (0 disables that cleanup target).
	//
	// vNext requirement: default 30 days across ops datasets.
	ErrorLogRetentionDays      int `mapstructure:"error_log_retention_days"`
	MinuteMetricsRetentionDays int `mapstructure:"minute_metrics_retention_days"`
	HourlyMetricsRetentionDays int `mapstructure:"hourly_metrics_retention_days"`
}

type OpsAggregationConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

type OpsMetricsCollectorCacheConfig struct {
	Enabled bool          `mapstructure:"enabled"`
	TTL     time.Duration `mapstructure:"ttl"`
}

type JWTConfig struct {
	Secret     string `mapstructure:"secret"`
	ExpireHour int    `mapstructure:"expire_hour"`
	// AccessTokenExpireMinutes: Access Token有效期（分钟），默认15分钟
	// 短有效期减少被盗用风险，配合Refresh Token实现无感续期
	AccessTokenExpireMinutes int `mapstructure:"access_token_expire_minutes"`
	// RefreshTokenExpireDays: Refresh Token有效期（天），默认30天
	RefreshTokenExpireDays int `mapstructure:"refresh_token_expire_days"`
	// RefreshWindowMinutes: 刷新窗口（分钟），在Access Token过期前多久开始允许刷新
	RefreshWindowMinutes int `mapstructure:"refresh_window_minutes"`
}

// TotpConfig TOTP 双因素认证配置
type TotpConfig struct {
	// EncryptionKey 用于加密 TOTP 密钥的 AES-256 密钥（32 字节 hex 编码）
	// 如果为空，将自动生成一个随机密钥（仅适用于开发环境）
	EncryptionKey string `mapstructure:"encryption_key"`
	// EncryptionKeyConfigured 标记加密密钥是否为手动配置（非自动生成）
	// 只有手动配置了密钥才允许在管理后台启用 TOTP 功能
	EncryptionKeyConfigured bool `mapstructure:"-"`
}

type TurnstileConfig struct {
	Required bool `mapstructure:"required"`
}

type DefaultConfig struct {
	AdminEmail      string  `mapstructure:"admin_email"`
	AdminPassword   string  `mapstructure:"admin_password"`
	UserConcurrency int     `mapstructure:"user_concurrency"`
	UserBalance     float64 `mapstructure:"user_balance"`
	APIKeyPrefix    string  `mapstructure:"api_key_prefix"`
	RateMultiplier  float64 `mapstructure:"rate_multiplier"`
}

type RateLimitConfig struct {
	OverloadCooldownMinutes int `mapstructure:"overload_cooldown_minutes"` // 529过载冷却时间(分钟)
}

// APIKeyAuthCacheConfig API Key 认证缓存配置
type APIKeyAuthCacheConfig struct {
	L1Size             int  `mapstructure:"l1_size"`
	L1TTLSeconds       int  `mapstructure:"l1_ttl_seconds"`
	L2TTLSeconds       int  `mapstructure:"l2_ttl_seconds"`
	NegativeTTLSeconds int  `mapstructure:"negative_ttl_seconds"`
	JitterPercent      int  `mapstructure:"jitter_percent"`
	Singleflight       bool `mapstructure:"singleflight"`
}

// DashboardCacheConfig 仪表盘统计缓存配置
type DashboardCacheConfig struct {
	// Enabled: 是否启用仪表盘缓存
	Enabled bool `mapstructure:"enabled"`
	// KeyPrefix: Redis key 前缀，用于多环境隔离
	KeyPrefix string `mapstructure:"key_prefix"`
	// StatsFreshTTLSeconds: 缓存命中认为"新鲜"的时间窗口（秒）
	StatsFreshTTLSeconds int `mapstructure:"stats_fresh_ttl_seconds"`
	// StatsTTLSeconds: Redis 缓存总 TTL（秒）
	StatsTTLSeconds int `mapstructure:"stats_ttl_seconds"`
	// StatsRefreshTimeoutSeconds: 异步刷新超时（秒）
	StatsRefreshTimeoutSeconds int `mapstructure:"stats_refresh_timeout_seconds"`
}

// DashboardAggregationConfig 仪表盘预聚合配置
type DashboardAggregationConfig struct {
	// Enabled: 是否启用预聚合作业
	Enabled bool `mapstructure:"enabled"`
	// IntervalSeconds: 聚合刷新间隔（秒）
	IntervalSeconds int `mapstructure:"interval_seconds"`
	// LookbackSeconds: 回看窗口（秒）
	LookbackSeconds int `mapstructure:"lookback_seconds"`
	// BackfillEnabled: 是否允许全量回填
	BackfillEnabled bool `mapstructure:"backfill_enabled"`
	// BackfillMaxDays: 回填最大跨度（天）
	BackfillMaxDays int `mapstructure:"backfill_max_days"`
	// Retention: 各表保留窗口（天）
	Retention DashboardAggregationRetentionConfig `mapstructure:"retention"`
	// RecomputeDays: 启动时重算最近 N 天
	RecomputeDays int `mapstructure:"recompute_days"`
}

// DashboardAggregationRetentionConfig 预聚合保留窗口
type DashboardAggregationRetentionConfig struct {
	UsageLogsDays int `mapstructure:"usage_logs_days"`
	HourlyDays    int `mapstructure:"hourly_days"`
	DailyDays     int `mapstructure:"daily_days"`
}

// UsageCleanupConfig 使用记录清理任务配置
type UsageCleanupConfig struct {
	// Enabled: 是否启用清理任务执行器
	Enabled bool `mapstructure:"enabled"`
	// MaxRangeDays: 单次任务允许的最大时间跨度（天）
	MaxRangeDays int `mapstructure:"max_range_days"`
	// BatchSize: 单批删除数量
	BatchSize int `mapstructure:"batch_size"`
	// WorkerIntervalSeconds: 后台任务轮询间隔（秒）
	WorkerIntervalSeconds int `mapstructure:"worker_interval_seconds"`
	// TaskTimeoutSeconds: 单次任务最大执行时长（秒）
	TaskTimeoutSeconds int `mapstructure:"task_timeout_seconds"`
}
