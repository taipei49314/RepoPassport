param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$TestedRevision,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$TestedTree
)

$ErrorActionPreference = "Stop"

function Fail-Fixed {
    param([string]$Code)
    throw $Code
}

function Invoke-GitFixed {
    param(
        [string]$FailureCode,
        [string[]]$Arguments
    )
    $output = @(& $script:gitCommand -c core.longpaths=true @Arguments 2>$null)
    if ($LASTEXITCODE -ne 0) {
        Fail-Fixed $FailureCode
    }
    return $output
}

function Assert-NoReparsePathComponents {
    param(
        [string]$Path,
        [string]$FailureCode
    )
    $full = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetPathRoot($full)
    if ([string]::IsNullOrEmpty($root)) {
        Fail-Fixed $FailureCode
    }
    $current = $root
    $suffix = $full.Substring($root.Length)
    foreach ($segment in @($suffix.Split(
        [IO.Path]::DirectorySeparatorChar,
        [StringSplitOptions]::RemoveEmptyEntries
    ))) {
        $current = Join-Path $current $segment
        if (-not [IO.Directory]::Exists($current) -and
            -not [IO.File]::Exists($current)) {
            break
        }
        $item = Get-Item -Force -LiteralPath $current -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Fail-Fixed $FailureCode
        }
    }
}

function Resolve-FixedGitCommand {
    $candidates = @()
    if ($env:OS -eq "Windows_NT") {
        if (-not [string]::IsNullOrWhiteSpace($env:ProgramFiles)) {
            $candidates += Join-Path $env:ProgramFiles "Git\cmd\git.exe"
        }
        if (-not [string]::IsNullOrWhiteSpace($env:ProgramW6432)) {
            $candidates += Join-Path $env:ProgramW6432 "Git\cmd\git.exe"
        }
        $programFilesX86 = [Environment]::GetEnvironmentVariable("ProgramFiles(x86)")
        if (-not [string]::IsNullOrWhiteSpace($programFilesX86)) {
            $candidates += Join-Path $programFilesX86 "Git\cmd\git.exe"
        }
    }
    else {
        $candidates += "/usr/bin/git"
    }

    foreach ($candidate in @($candidates | Select-Object -Unique)) {
        $full = [IO.Path]::GetFullPath($candidate)
        if (-not [IO.File]::Exists($full)) {
            continue
        }
        Assert-NoReparsePathComponents $full "REPRO_GIT_UNAVAILABLE"
        $item = Get-Item -Force -LiteralPath $full -ErrorAction Stop
        if ($item.PSIsContainer -or
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Fail-Fixed "REPRO_GIT_UNAVAILABLE"
        }
        return $full
    }
    Fail-Fixed "REPRO_GIT_UNAVAILABLE"
}

function Assert-ExactRegularInventory {
    param(
        [string]$Path,
        [string[]]$ExpectedNames
    )
    if (-not [IO.Directory]::Exists($Path)) {
        Fail-Fixed "REPRO_ARTIFACT_INVENTORY_MISMATCH"
    }
    Assert-NoReparsePathComponents $Path "REPRO_ARTIFACT_INVENTORY_MISMATCH"
    $entries = @(Get-ChildItem -Force -LiteralPath $Path -ErrorAction Stop)
    if ($entries.Count -ne $ExpectedNames.Count) {
        Fail-Fixed "REPRO_ARTIFACT_INVENTORY_MISMATCH"
    }
    $actual = @($entries | ForEach-Object { $_.Name } | Sort-Object -CaseSensitive)
    $expected = @($ExpectedNames | Sort-Object -CaseSensitive)
    if ((Compare-Object -CaseSensitive -ReferenceObject $expected -DifferenceObject $actual).Count -ne 0) {
        Fail-Fixed "REPRO_ARTIFACT_INVENTORY_MISMATCH"
    }
    foreach ($entry in $entries) {
        if ($entry.PSIsContainer -or
            ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Fail-Fixed "REPRO_ARTIFACT_INVENTORY_MISMATCH"
        }
    }
}

function Compare-FileBytes {
    param(
        [string]$First,
        [string]$Second
    )
    $firstStream = [IO.File]::Open(
        $First,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    try {
        $secondStream = [IO.File]::Open(
            $Second,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read
        )
        try {
            if ($firstStream.Length -ne $secondStream.Length) {
                Fail-Fixed "REPRO_BYTE_MISMATCH"
            }
            $firstBuffer = New-Object byte[] 65536
            $secondBuffer = New-Object byte[] 65536
            while (($firstCount = $firstStream.Read(
                $firstBuffer,
                0,
                $firstBuffer.Length
            )) -gt 0) {
                $secondCount = $secondStream.Read(
                    $secondBuffer,
                    0,
                    $secondBuffer.Length
                )
                if ($firstCount -ne $secondCount) {
                    Fail-Fixed "REPRO_BYTE_MISMATCH"
                }
                for ($index = 0; $index -lt $firstCount; $index++) {
                    if ($firstBuffer[$index] -ne $secondBuffer[$index]) {
                        Fail-Fixed "REPRO_BYTE_MISMATCH"
                    }
                }
            }
            if ($secondStream.ReadByte() -ne -1) {
                Fail-Fixed "REPRO_BYTE_MISMATCH"
            }
        }
        finally {
            $secondStream.Dispose()
        }
    }
    finally {
        $firstStream.Dispose()
    }
}

if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP) -or
    [string]::IsNullOrWhiteSpace($env:GITHUB_WORKSPACE)) {
    Fail-Fixed "REPRO_INVALID_INPUT"
}

$runnerTemp = [IO.Path]::GetFullPath($env:RUNNER_TEMP)
$sourceRoot = [IO.Path]::GetFullPath($env:GITHUB_WORKSPACE)
$separator = [string][IO.Path]::DirectorySeparatorChar
$comparison = if ($env:OS -eq "Windows_NT") {
    [StringComparison]::OrdinalIgnoreCase
}
else {
    [StringComparison]::Ordinal
}
$runnerPrefix = $runnerTemp.TrimEnd(
    [IO.Path]::DirectorySeparatorChar,
    [IO.Path]::AltDirectorySeparatorChar
) + $separator
$sourcePrefix = $sourceRoot.TrimEnd(
    [IO.Path]::DirectorySeparatorChar,
    [IO.Path]::AltDirectorySeparatorChar
) + $separator
$secondSource = [IO.Path]::GetFullPath((Join-Path $runnerTemp (
    "repopass-rfc0001-rebuild-" + [Guid]::NewGuid().ToString("N")
)))
if (-not $secondSource.StartsWith($runnerPrefix, $comparison) -or
    $secondSource.StartsWith($sourcePrefix, $comparison) -or
    $sourceRoot.StartsWith($runnerPrefix, $comparison)) {
    Fail-Fixed "REPRO_PATH_BOUNDARY_INVALID"
}

Assert-NoReparsePathComponents $runnerTemp "REPRO_PATH_BOUNDARY_INVALID"
Assert-NoReparsePathComponents $sourceRoot "REPRO_PATH_BOUNDARY_INVALID"

$gitNullDevice = if ($env:OS -eq "Windows_NT") { "NUL" } else { "/dev/null" }
$env:GIT_DIR = $null
$env:GIT_WORK_TREE = $null
$env:GIT_INDEX_FILE = $null
$env:GIT_OBJECT_DIRECTORY = $null
$env:GIT_ALTERNATE_OBJECT_DIRECTORIES = $null
$env:GIT_COMMON_DIR = $null
$env:GIT_NAMESPACE = $null
$env:GIT_CEILING_DIRECTORIES = $null
$env:GIT_DISCOVERY_ACROSS_FILESYSTEM = $null
$env:GIT_CONFIG_PARAMETERS = $null
$env:GIT_CONFIG_COUNT = "0"
$env:GIT_CONFIG_NOSYSTEM = "1"
$env:GIT_CONFIG_GLOBAL = $gitNullDevice
$env:GIT_CONFIG_SYSTEM = $gitNullDevice
$env:GIT_EXEC_PATH = $null
$env:GIT_SSH = $null
$env:GIT_SSH_COMMAND = $null
$env:GIT_ASKPASS = $null
$env:GIT_NO_REPLACE_OBJECTS = "1"
$env:GIT_TERMINAL_PROMPT = "0"
$gitCommand = Resolve-FixedGitCommand

$sourceRevision = @(Invoke-GitFixed "REPRO_SOURCE_IDENTITY_MISMATCH" @(
    "-C", $sourceRoot, "rev-parse", "--verify", "HEAD"
))
$sourceTree = @(Invoke-GitFixed "REPRO_SOURCE_IDENTITY_MISMATCH" @(
    "-C", $sourceRoot, "rev-parse", "--verify", "HEAD^{tree}"
))
$sourceStatus = @(Invoke-GitFixed "REPRO_SOURCE_DIRTY" @(
    "-C", $sourceRoot, "status", "--porcelain=v1",
    "--untracked-files=all", "--ignore-submodules=none"
))
if ($sourceRevision.Count -ne 1 -or
    ([string]$sourceRevision[0]).Trim() -cne $TestedRevision -or
    $sourceTree.Count -ne 1 -or
    ([string]$sourceTree[0]).Trim() -cne $TestedTree -or
    $sourceStatus.Count -ne 0) {
    Fail-Fixed "REPRO_SOURCE_IDENTITY_MISMATCH"
}

@(& $gitCommand -c core.longpaths=true -c protocol.file.allow=always `
    -c core.hooksPath=$gitNullDevice `
    clone --no-checkout --no-local --recurse-submodules=no --template= -- `
    $sourceRoot $secondSource 2>$null) | Out-Null
if ($LASTEXITCODE -ne 0) {
    Fail-Fixed "REPRO_CHECKOUT_FAILED"
}
@(& $gitCommand -c core.longpaths=true -C $secondSource `
    checkout --detach --force $TestedRevision 2>$null) | Out-Null
if ($LASTEXITCODE -ne 0) {
    Fail-Fixed "REPRO_CHECKOUT_FAILED"
}
Assert-NoReparsePathComponents $secondSource "REPRO_PATH_BOUNDARY_INVALID"

$rebuiltRevision = @(Invoke-GitFixed "REPRO_SOURCE_IDENTITY_MISMATCH" @(
    "-C", $secondSource, "rev-parse", "--verify", "HEAD"
))
$rebuiltTree = @(Invoke-GitFixed "REPRO_SOURCE_IDENTITY_MISMATCH" @(
    "-C", $secondSource, "rev-parse", "--verify", "HEAD^{tree}"
))
$rebuiltStatus = @(Invoke-GitFixed "REPRO_SOURCE_DIRTY" @(
    "-C", $secondSource, "status", "--porcelain=v1",
    "--untracked-files=all", "--ignore-submodules=none"
))
if ($rebuiltRevision.Count -ne 1 -or
    ([string]$rebuiltRevision[0]).Trim() -cne $TestedRevision -or
    $rebuiltTree.Count -ne 1 -or
    ([string]$rebuiltTree[0]).Trim() -cne $TestedTree -or
    $rebuiltStatus.Count -ne 0) {
    Fail-Fixed "REPRO_SOURCE_IDENTITY_MISMATCH"
}

$builder = Join-Path $secondSource "scripts/build-release.ps1"
& $builder -Version "0.1.0-alpha.33" -TestedRevision $TestedRevision `
    >$null 2>$null
if ($LASTEXITCODE -ne 0) {
    Fail-Fixed "REPRO_BUILD_FAILED"
}

$releaseInventory = @(
    "repopass-linux-amd64",
    "repopass-windows-amd64.exe",
    "repopass-verify-linux-amd64",
    "repopass-verify-windows-amd64.exe",
    "repopass-verify-linux-amd64.tar",
    "repopass-verify-windows-amd64.tar",
    "SHA256SUMS"
)
$firstDist = Join-Path $sourceRoot "dist"
$secondDist = Join-Path $secondSource "dist"
Assert-ExactRegularInventory $firstDist $releaseInventory
Assert-ExactRegularInventory $secondDist $releaseInventory
foreach ($name in $releaseInventory) {
    Compare-FileBytes (Join-Path $firstDist $name) (Join-Path $secondDist $name)
}

[Console]::Out.WriteLine(
    '{"code":"MODULE_RELEASE_REPRODUCIBLE","status":"PASS"}'
)
