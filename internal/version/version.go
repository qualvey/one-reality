package version

// 版本与元数据信息，支持由构建时注入 (-ldflags "-X RealityChecker/internal/version.AppName=...")
var (
	AppName   = "reality-checker"
	Version   = "dev"
	Commit    = "unknown"
	BuildTime = "unknown"
)

// GetAppName 获取程序名称
func GetAppName() string {
	return AppName
}

// GetVersion 获取版本号
func GetVersion() string {
	return Version
}

// GetCommit 获取提交哈希
func GetCommit() string {
	return Commit
}

// GetBuildTime 获取构建时间
func GetBuildTime() string {
	return BuildTime
}
