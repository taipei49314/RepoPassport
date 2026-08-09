param(
    [string]$Version = "0.1.0-alpha.33"
)

$ErrorActionPreference = "Stop"
if ($Version -cne "0.1.0-alpha.33") {
    throw "Alpha.33 release builder requires version 0.1.0-alpha.33."
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$distRoot = Join-Path $repoRoot "dist"
$stagingRoot = Join-Path $repoRoot (".release-staging-" + [Guid]::NewGuid().ToString("N"))
# Keep the publish directory next to dist so the final directory move is a
# single same-volume rename, never a sequence of visible per-file copies.
$publishRoot = Join-Path $repoRoot (".release-publish-" + [Guid]::NewGuid().ToString("N"))
$versionSymbol = "github.com/taipei49314/RepoPassport/internal/cli.Version=$Version"
$expected = @(
    "repopass-linux-amd64",
    "repopass-windows-amd64.exe",
    "repopass-verify-linux-amd64",
    "repopass-verify-windows-amd64.exe",
    "repopass-verify-linux-amd64.tar",
    "repopass-verify-windows-amd64.tar",
    "SHA256SUMS"
) | Sort-Object

function Assert-ExactReleaseDirectory([string]$Path) {
    $children = @(Get-ChildItem -LiteralPath $Path -Force)
    if ($children.Count -ne $expected.Count) {
        throw "release directory does not contain exactly seven entries."
    }
    foreach ($child in $children) {
        if ($child.PSIsContainer -or
            ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "release directory contains a non-regular or reparse entry."
        }
    }
    $actual = @($children | ForEach-Object { $_.Name } | Sort-Object)
    if ((Compare-Object -CaseSensitive -ReferenceObject $expected -DifferenceObject $actual).Count -ne 0) {
        throw "release directory is not the Alpha.33 exact seven-file contract."
    }
}

if (Test-Path -LiteralPath $distRoot) {
    $distItem = Get-Item -LiteralPath $distRoot -Force
    if (-not $distItem.PSIsContainer -or
        ($distItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        @(Get-ChildItem -LiteralPath $distRoot -Force).Count -ne 0) {
        throw "dist must be absent or empty; release builder will not overwrite prior artifacts."
    }
}
$previousGOOS = $env:GOOS
$previousGOARCH = $env:GOARCH
$previousCGO = $env:CGO_ENABLED
$locationPushed = $false
try {
    New-Item -ItemType Directory -Path $stagingRoot | Out-Null
    New-Item -ItemType Directory -Path $publishRoot | Out-Null
    Push-Location $repoRoot
    $locationPushed = $true
    $targets = @(
        @{ GOOS = "linux"; GOARCH = "amd64"; Full = "repopass-linux-amd64"; Verify = "repopass-verify-linux-amd64"; Kit = "repopass-verify-linux-amd64.tar" },
        @{ GOOS = "windows"; GOARCH = "amd64"; Full = "repopass-windows-amd64.exe"; Verify = "repopass-verify-windows-amd64.exe"; Kit = "repopass-verify-windows-amd64.tar" }
    )
    foreach ($target in $targets) {
        $env:GOOS = $target.GOOS
        $env:GOARCH = $target.GOARCH
        $env:CGO_ENABLED = "0"
        foreach ($build in @(
            @{ Path = "./cmd/repopass"; Name = $target.Full },
            @{ Path = "./cmd/repopass-verify"; Name = $target.Verify }
        )) {
            $output = Join-Path $stagingRoot $build.Name
            & go build -trimpath -ldflags "-s -w -X $versionSymbol" -o $output $build.Path
            if ($LASTEXITCODE -ne 0) { throw "go build failed for $($build.Name)" }
        }
    }

    # The helper is host-only and remains in staging; it never enters dist.
    $env:GOOS = $null; $env:GOARCH = $null; $env:CGO_ENABLED = "0"
    $kitTool = Join-Path $stagingRoot "repopass-kit-host.exe"
    & go build -trimpath -ldflags "-s -w" -o $kitTool ./cmd/repopass-kit
    if ($LASTEXITCODE -ne 0) { throw "go build failed for release-kit helper" }
    foreach ($target in $targets) {
        $binary = Join-Path $stagingRoot $target.Verify
        $kit = Join-Path $stagingRoot $target.Kit
        & $kitTool -os $target.GOOS -arch $target.GOARCH -version $Version -binary $binary -output $kit
        if ($LASTEXITCODE -ne 0) { throw "release-kit creation failed for $($target.GOOS)/$($target.GOARCH)" }
    }

    $publish = @($targets | ForEach-Object { $_.Full; $_.Verify; $_.Kit }) | Sort-Object
    foreach ($name in $publish) {
        Copy-Item -LiteralPath (Join-Path $stagingRoot $name) -Destination (Join-Path $publishRoot $name)
    }
    $checksumLines = $publish | ForEach-Object {
        $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $publishRoot $_)).Hash.ToLowerInvariant()
        "$hash  $_"
    }
    [IO.File]::WriteAllText(
        (Join-Path $publishRoot "SHA256SUMS"),
        (($checksumLines -join "`n") + "`n"),
        [Text.UTF8Encoding]::new($false)
    )
    Assert-ExactReleaseDirectory $publishRoot
    # Recheck immediately before publication: a concurrent writer must not be
    # overwritten, and failure leaves no partial release visible in dist.
    if (Test-Path -LiteralPath $distRoot) {
        $distItem = Get-Item -LiteralPath $distRoot -Force
        if (-not $distItem.PSIsContainer -or
            ($distItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            @(Get-ChildItem -LiteralPath $distRoot -Force).Count -ne 0) {
            throw "dist changed during build and is no longer empty."
        }
        Remove-Item -LiteralPath $distRoot -Force
    }
    [IO.Directory]::Move($publishRoot, $distRoot)
    Assert-ExactReleaseDirectory $distRoot
}
finally {
    if ($locationPushed) {
        Pop-Location
    }
    $env:GOOS = $previousGOOS
    $env:GOARCH = $previousGOARCH
    $env:CGO_ENABLED = $previousCGO
    if (Test-Path -LiteralPath $stagingRoot) {
        Remove-Item -LiteralPath $stagingRoot -Recurse -Force
    }
    if (Test-Path -LiteralPath $publishRoot) {
        Remove-Item -LiteralPath $publishRoot -Recurse -Force
    }
}

Write-Output "Alpha.33 deterministic release artifacts:"
Get-ChildItem -LiteralPath $distRoot -File | Sort-Object Name | Select-Object Name, Length
