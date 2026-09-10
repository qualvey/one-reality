$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$DistDir = Join-Path $RootDir "dist"
$Version = if ($env:VERSION) { $env:VERSION } else { (git -C $RootDir describe --tags --always --dirty 2>$null) }
$Commit = if ($env:COMMIT) { $env:COMMIT } else { (git -C $RootDir rev-parse --short HEAD 2>$null) }
$BuildTime = if ($env:BUILD_TIME) { $env:BUILD_TIME } else { (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") }

if (-not $Version) { $Version = "dev" }
if (-not $Commit) { $Commit = "unknown" }
$Ldflags = "-s -w -X RealityChecker/internal/version.Version=$Version -X RealityChecker/internal/version.Commit=$Commit -X RealityChecker/internal/version.BuildTime=$BuildTime"

if (-not (Test-Path $DistDir)) {
    New-Item -ItemType Directory -Path $DistDir | Out-Null
} else {
    Get-ChildItem -Path $DistDir -Filter "reality-checker*" | Remove-Item -Force -ErrorAction SilentlyContinue
}

function Build-Target([string]$GoOS, [string]$GoArch, [string]$Extension) {
    $baseName = "reality-checker-$GoOS-$GoArch"
    $name = "$baseName$Extension"
    Write-Host "Building $GoOS/$GoArch..."
    $env:CGO_ENABLED = "0"
    $env:GOOS = $GoOS
    $env:GOARCH = $GoArch
    & go build -trimpath -ldflags $Ldflags -o (Join-Path $DistDir $name) $RootDir
    if ($LASTEXITCODE -ne 0) { throw "go build failed for $GoOS/$GoArch" }
    Compress-Archive -Path (Join-Path $DistDir $name) -DestinationPath (Join-Path $DistDir "$baseName.zip")
}

Write-Host "Version: $Version"
Write-Host "Commit: $Commit"
Write-Host "Build time: $BuildTime"

Build-Target "linux" "amd64" ""
Build-Target "linux" "arm64" ""
Build-Target "windows" "amd64" ".exe"

Remove-Item Env:CGO_ENABLED, Env:GOOS, Env:GOARCH -ErrorAction SilentlyContinue
Get-ChildItem $DistDir | Format-Table Name, Length
