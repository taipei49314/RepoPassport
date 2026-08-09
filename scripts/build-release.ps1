param(
    [string]$Version = "0.1.0-alpha.33",
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$TestedRevision
)

$ErrorActionPreference = "Stop"
if ($Version -cne "0.1.0-alpha.33") {
    throw "Alpha.33 release builder requires version 0.1.0-alpha.33."
}
$probePreviousGOENV = $env:GOENV
$probePreviousGOFLAGS = $env:GOFLAGS
$probePreviousGOTOOLCHAIN = $env:GOTOOLCHAIN
$probePreviousGOCACHEPROG = $env:GOCACHEPROG
try {
	$goCommand = (Get-Command go -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
	$gitCommand = (Get-Command git -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
	$env:GOENV = "off"
	$env:GOFLAGS = ""
	$env:GOTOOLCHAIN = "local"
	$env:GOCACHEPROG = ""
	$goVersionLine = @(& $goCommand version 2>$null)
	if ($LASTEXITCODE -ne 0 -or $goVersionLine.Count -ne 1 -or
		([string]$goVersionLine[0]) -notmatch '^go version go1\.26\.5 [^\s/]+/[^\s/]+$') {
		throw "wrong Go toolchain"
	}
}
catch {
    throw "required release build tools are unavailable."
}
finally {
	$env:GOENV = $probePreviousGOENV
	$env:GOFLAGS = $probePreviousGOFLAGS
	$env:GOTOOLCHAIN = $probePreviousGOTOOLCHAIN
	$env:GOCACHEPROG = $probePreviousGOCACHEPROG
}
$goDirectory = Split-Path -Parent $goCommand
$gitDirectory = Split-Path -Parent $gitCommand
$platformPathEntries = if ($env:OS -eq "Windows_NT") {
	@($goDirectory, $gitDirectory, [Environment]::GetFolderPath("System"))
}
else {
	@($goDirectory, $gitDirectory, "/usr/bin", "/bin")
}
$sanitizedPath = (@($platformPathEntries | Where-Object { $_ } | Select-Object -Unique) -join [IO.Path]::PathSeparator)
$gitNullDevice = if ($env:OS -eq "Windows_NT") { "NUL" } else { "/dev/null" }

$repoRoot = Split-Path -Parent $PSScriptRoot
$distRoot = Join-Path $repoRoot "dist"
$temporaryBase = [IO.Path]::GetFullPath((Split-Path -Parent $repoRoot))
$stagingRoot = Join-Path $temporaryBase ("repopass-release-staging-" + [Guid]::NewGuid().ToString("N"))
$artifactRoot = Join-Path $stagingRoot "artifacts"
$controllerRoot = Join-Path $temporaryBase ("repopass-release-controller-" + [Guid]::NewGuid().ToString("N"))
$toolRoot = $controllerRoot
# Keep the publish directory next to dist so the final directory move is a
# single same-volume rename, never a sequence of visible per-file copies.
$publishRoot = Join-Path $repoRoot (".release-publish-" + [Guid]::NewGuid().ToString("N"))
$versionSymbol = "github.com/taipei49314/RepoPassport/internal/cli.Version=$Version"
$toolInventory = @("repopass-release-qualify-host.exe")
$preHelperInventory = @(
    "repopass-linux-amd64",
    "repopass-windows-amd64.exe",
    "repopass-verify-linux-amd64",
    "repopass-verify-windows-amd64.exe",
    "repopass-kit-host.exe"
) | Sort-Object
$postHelperInventory = @(
    $preHelperInventory
    "repopass-verify-linux-amd64.tar"
    "repopass-verify-windows-amd64.tar"
) | Sort-Object
$releaseInventory = @(
    "repopass-linux-amd64",
    "repopass-windows-amd64.exe",
    "repopass-verify-linux-amd64",
    "repopass-verify-windows-amd64.exe",
    "repopass-verify-linux-amd64.tar",
    "repopass-verify-windows-amd64.tar",
    "SHA256SUMS"
) | Sort-Object

function Assert-ExactRegularFiles([string]$Path, [string[]]$ExpectedNames) {
    $directory = Get-Item -LiteralPath $Path -Force
    if (-not $directory.PSIsContainer -or
        ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "qualified inventory root is not a regular directory."
    }
    $children = @(Get-ChildItem -LiteralPath $Path -Force)
    if ($children.Count -ne $ExpectedNames.Count) {
        throw "qualified inventory does not contain the exact entry count."
    }
    foreach ($child in $children) {
        if ($child.PSIsContainer -or
            ($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "qualified inventory contains a non-regular or reparse entry."
        }
    }
    $actual = @($children | ForEach-Object { $_.Name } | Sort-Object)
    if ((Compare-Object -CaseSensitive -ReferenceObject $ExpectedNames -DifferenceObject $actual).Count -ne 0) {
        throw "qualified inventory names do not match the exact contract."
    }
}

function Assert-ExactReleaseDirectory([string]$Path) {
    Assert-ExactRegularFiles -Path $Path -ExpectedNames $releaseInventory
}

function Get-RegularFileSHA256([string]$Path) {
    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ($item.PSIsContainer -or
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "not regular"
        }
        $digest = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path -ErrorAction Stop).Hash.ToLowerInvariant()
        if ($digest -cnotmatch '^[0-9a-f]{64}$') {
            throw "invalid digest"
        }
        return $digest
    }
    catch {
        throw "unable to bind a private release tool digest."
    }
}

function Assert-FileSHA256([string]$Path, [string]$ExpectedSHA256) {
    if ((Get-RegularFileSHA256 -Path $Path) -cne $ExpectedSHA256) {
        throw "private release tool bytes changed after qualification."
    }
}

function Get-GitLine([string[]]$Arguments) {
    $lines = @(& $gitCommand --no-optional-locks @Arguments 2>$null)
    if ($LASTEXITCODE -ne 0 -or $lines.Count -ne 1) {
        throw "unable to resolve the exact source identity."
    }
    $line = ([string]$lines[0]).Trim()
    if ($line -notmatch '^[0-9a-f]{40}$') {
        throw "source identity is not one exact lowercase 40-hex value."
    }
    return $line
}

function Assert-RepositoryRoot([string]$ExpectedRoot) {
    $lines = @(& $gitCommand --no-optional-locks rev-parse --show-toplevel 2>$null)
    if ($LASTEXITCODE -ne 0 -or $lines.Count -ne 1) {
        throw "unable to resolve the repository root."
    }
    $actual = [IO.Path]::GetFullPath(([string]$lines[0]).Trim())
    $expected = [IO.Path]::GetFullPath($ExpectedRoot)
    $comparison = if ($env:OS -eq "Windows_NT") {
        [StringComparison]::OrdinalIgnoreCase
    }
    else {
        [StringComparison]::Ordinal
    }
    if (-not $actual.Equals($expected, $comparison)) {
        throw "release builder is not executing in the exact repository root."
    }
}

function Assert-SourceUnchanged(
	[string]$Revision,
	[string]$Tree,
	[string]$AllowedUntrackedRoot = "",
	[string[]]$AllowedUntrackedNames = @()
) {
    if ((Get-GitLine -Arguments @("rev-parse", "HEAD")) -cne $Revision -or
        (Get-GitLine -Arguments @("rev-parse", "HEAD^{tree}")) -cne $Tree) {
        throw "source revision or tree changed during release construction."
    }
    $status = @(& $gitCommand --no-optional-locks status --porcelain=v1 `
        --untracked-files=all --ignore-submodules=none 2>$null)
    if ($LASTEXITCODE -ne 0) {
        throw "release construction requires a clean exact checkout."
    }
	if ($AllowedUntrackedRoot -eq "") {
		if ($status.Count -ne 0) {
			throw "release construction requires a clean exact checkout."
		}
		return
	}
	$allowedFull = [IO.Path]::GetFullPath($AllowedUntrackedRoot)
	$allowedParent = [IO.Path]::GetFullPath((Split-Path -Parent $allowedFull))
	$repoFull = [IO.Path]::GetFullPath($repoRoot)
	$comparison = if ($env:OS -eq "Windows_NT") { [StringComparison]::OrdinalIgnoreCase } else { [StringComparison]::Ordinal }
	$leaf = Split-Path -Leaf $allowedFull
	if (-not $allowedParent.Equals($repoFull, $comparison) -or
		-not $leaf.StartsWith(".release-publish-", [StringComparison]::Ordinal)) {
		throw "untracked release allowlist is outside the fixed scope."
	}
	$expectedStatus = @($AllowedUntrackedNames | Sort-Object | ForEach-Object { "?? $leaf/$_" })
	if ((Compare-Object -CaseSensitive -ReferenceObject $expectedStatus -DifferenceObject @($status | Sort-Object)).Count -ne 0) {
		throw "release construction found changes outside the exact publish allowlist."
	}
}

function Assert-NoReparsePathComponents([string]$Path, [switch]$AllowMissingLeaf) {
	$current = [IO.Path]::GetFullPath($Path)
	while (-not (Test-Path -LiteralPath $current)) {
		if (-not $AllowMissingLeaf) {
			throw "required release path is unavailable."
		}
		$parent = Split-Path -Parent $current
		if ($parent -eq "" -or $parent -eq $current) {
			throw "release path has no existing trusted ancestor."
		}
		$current = $parent
	}
	while ($true) {
		$item = Get-Item -LiteralPath $current -Force
		if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
			throw "release path contains a reparse component."
		}
		$parent = Split-Path -Parent $current
		if ($parent -eq "" -or $parent -eq $current) {
			break
		}
		$current = $parent
	}
}

function Test-ScopedDirectory([string]$Parent, [string]$Path, [string]$LeafPrefix) {
    $parentFull = [IO.Path]::GetFullPath($Parent)
    if (-not $parentFull.EndsWith([string][IO.Path]::DirectorySeparatorChar)) {
        $parentFull += [IO.Path]::DirectorySeparatorChar
    }
    $pathFull = [IO.Path]::GetFullPath($Path)
    $comparison = if ($env:OS -eq "Windows_NT") {
        [StringComparison]::OrdinalIgnoreCase
    }
    else {
        [StringComparison]::Ordinal
    }
    return $pathFull.StartsWith($parentFull, $comparison) -and
        (Split-Path -Leaf $pathFull).StartsWith($LeafPrefix, [StringComparison]::Ordinal)
}

function Clear-ScopedReadOnlyAttribute([string]$Path) {
	$item = Get-Item -LiteralPath $Path -Force
	if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
		throw "release cleanup entry became a reparse point."
	}
	if ($env:OS -eq "Windows_NT" -and
		($item.Attributes -band [IO.FileAttributes]::ReadOnly) -ne 0) {
		[IO.File]::SetAttributes(
			$Path,
			($item.Attributes -band (-bnot [IO.FileAttributes]::ReadOnly))
		)
	}
}

function Remove-ScopedDirectory([string]$Parent, [string]$Path, [string]$LeafPrefix) {
    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }
    if (-not (Test-ScopedDirectory -Parent $Parent -Path $Path -LeafPrefix $LeafPrefix)) {
        throw "refusing to remove a directory outside the release task scope."
    }
	Assert-NoReparsePathComponents -Path $Parent
	Assert-NoReparsePathComponents -Path $Path
    $item = Get-Item -LiteralPath $Path -Force
    if (-not $item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "release cleanup target is not a regular directory."
    }
    $quarantine = Join-Path $Parent ($LeafPrefix + "cleanup-" + [Guid]::NewGuid().ToString("N"))
    [IO.Directory]::Move($Path, $quarantine)
	Assert-NoReparsePathComponents -Path $quarantine
    $stack = [Collections.Generic.Stack[string]]::new()
	$files = [Collections.Generic.List[string]]::new()
	$directories = [Collections.Generic.List[string]]::new()
    $stack.Push($quarantine)
    while ($stack.Count -gt 0) {
        $current = $stack.Pop()
        $currentItem = Get-Item -LiteralPath $current -Force
        if (($currentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "release cleanup quarantine contains a reparse entry."
        }
        if ($currentItem.PSIsContainer) {
            foreach ($child in @(Get-ChildItem -LiteralPath $current -Force)) {
                if (($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    throw "release cleanup quarantine contains a reparse entry."
                }
                if ($child.PSIsContainer) {
                    $stack.Push($child.FullName)
                }
				else {
					$files.Add($child.FullName)
				}
            }
			if ($current -ne $quarantine) {
				$directories.Add($current)
			}
        }
    }
	foreach ($file in $files) {
		Clear-ScopedReadOnlyAttribute -Path $file
		[IO.File]::Delete($file)
	}
	foreach ($directory in @($directories | Sort-Object { $_.Length } -Descending)) {
		Clear-ScopedReadOnlyAttribute -Path $directory
		[IO.Directory]::Delete($directory, $false)
	}
	Clear-ScopedReadOnlyAttribute -Path $quarantine
	[IO.Directory]::Delete($quarantine, $false)
}
$previousGOOS = $env:GOOS
$previousGOARCH = $env:GOARCH
$previousCGO = $env:CGO_ENABLED
$previousGOWORK = $env:GOWORK
$previousGOENV = $env:GOENV
$previousGOFLAGS = $env:GOFLAGS
$previousGOTOOLCHAIN = $env:GOTOOLCHAIN
$previousGOAMD64 = $env:GOAMD64
$previousGOEXPERIMENT = $env:GOEXPERIMENT
$previousGODEBUG = $env:GODEBUG
$previousGOROOT = $env:GOROOT
$previousGOCACHE = $env:GOCACHE
$previousGOMODCACHE = $env:GOMODCACHE
$previousGOTMPDIR = $env:GOTMPDIR
$previousGOPROXY = $env:GOPROXY
$previousGOSUMDB = $env:GOSUMDB
$previousGOPRIVATE = $env:GOPRIVATE
$previousGONOPROXY = $env:GONOPROXY
$previousGONOSUMDB = $env:GONOSUMDB
$previousGOINSECURE = $env:GOINSECURE
$previousGOAUTH = $env:GOAUTH
$previousGOCACHEPROG = $env:GOCACHEPROG
$previousGOFIPS140 = $env:GOFIPS140
$previousGOTELEMETRY = $env:GOTELEMETRY
$previousGOVCS = $env:GOVCS
$previousGO111MODULE = $env:GO111MODULE
$previousPATH = $env:PATH
$previousGIT_DIR = $env:GIT_DIR
$previousGIT_WORK_TREE = $env:GIT_WORK_TREE
$previousGIT_INDEX_FILE = $env:GIT_INDEX_FILE
$previousGIT_OBJECT_DIRECTORY = $env:GIT_OBJECT_DIRECTORY
$previousGIT_ALTERNATE_OBJECT_DIRECTORIES = $env:GIT_ALTERNATE_OBJECT_DIRECTORIES
$previousGIT_COMMON_DIR = $env:GIT_COMMON_DIR
$previousGIT_NAMESPACE = $env:GIT_NAMESPACE
$previousGIT_CEILING_DIRECTORIES = $env:GIT_CEILING_DIRECTORIES
$previousGIT_DISCOVERY_ACROSS_FILESYSTEM = $env:GIT_DISCOVERY_ACROSS_FILESYSTEM
$previousGIT_NO_REPLACE_OBJECTS = $env:GIT_NO_REPLACE_OBJECTS
$previousGIT_CONFIG_NOSYSTEM = $env:GIT_CONFIG_NOSYSTEM
$previousGIT_CONFIG_GLOBAL = $env:GIT_CONFIG_GLOBAL
$previousGIT_CONFIG_SYSTEM = $env:GIT_CONFIG_SYSTEM
$previousGIT_CONFIG_COUNT = $env:GIT_CONFIG_COUNT
$previousGIT_CONFIG_PARAMETERS = $env:GIT_CONFIG_PARAMETERS
$previousGIT_EXEC_PATH = $env:GIT_EXEC_PATH
$previousGIT_SSH = $env:GIT_SSH
$previousGIT_SSH_COMMAND = $env:GIT_SSH_COMMAND
$previousGIT_ASKPASS = $env:GIT_ASKPASS
$previousGIT_TERMINAL_PROMPT = $env:GIT_TERMINAL_PROMPT
$locationPushed = $false
$published = $false
$distWasPublished = $false
$withdrawRoot = ""
try {
    $env:GIT_DIR = $null
    $env:GIT_WORK_TREE = $null
    $env:GIT_INDEX_FILE = $null
    $env:GIT_OBJECT_DIRECTORY = $null
    $env:GIT_ALTERNATE_OBJECT_DIRECTORIES = $null
    $env:GIT_COMMON_DIR = $null
    $env:GIT_NAMESPACE = $null
    $env:GIT_CEILING_DIRECTORIES = $null
    $env:GIT_DISCOVERY_ACROSS_FILESYSTEM = $null
    $env:GIT_NO_REPLACE_OBJECTS = "1"
	$env:GIT_CONFIG_NOSYSTEM = "1"
	$env:GIT_CONFIG_GLOBAL = $gitNullDevice
	$env:GIT_CONFIG_SYSTEM = $gitNullDevice
	$env:GIT_CONFIG_COUNT = "0"
	$env:GIT_CONFIG_PARAMETERS = $null
	$env:GIT_EXEC_PATH = $null
	$env:GIT_SSH = $null
	$env:GIT_SSH_COMMAND = $null
	$env:GIT_ASKPASS = $null
	$env:GIT_TERMINAL_PROMPT = "0"
	$env:PATH = $sanitizedPath
    $env:GOENV = "off"
    $env:GOFLAGS = ""
    $env:GOTOOLCHAIN = "local"
    $env:GOAMD64 = "v1"
    $env:GOEXPERIMENT = ""
    $env:GODEBUG = ""
    $env:GOROOT = $null
    $env:GOWORK = "off"
	$env:GOAUTH = "off"
	$env:GONOPROXY = "none"
	$env:GOCACHEPROG = ""
	$env:GOFIPS140 = "off"
	$env:GOTELEMETRY = "off"
	$env:GOVCS = "*:off"
	$env:GO111MODULE = "on"
    $env:GOPRIVATE = ""
    $env:GONOSUMDB = ""
    $env:GOINSECURE = ""
	Assert-NoReparsePathComponents -Path $repoRoot
	Assert-NoReparsePathComponents -Path $temporaryBase
	Assert-NoReparsePathComponents -Path $controllerRoot -AllowMissingLeaf
	Assert-NoReparsePathComponents -Path $distRoot -AllowMissingLeaf
	Assert-NoReparsePathComponents -Path $publishRoot -AllowMissingLeaf
	if (Test-Path -LiteralPath $distRoot) {
		$distItem = Get-Item -LiteralPath $distRoot -Force
		if (-not $distItem.PSIsContainer -or
			($distItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
			@(Get-ChildItem -LiteralPath $distRoot -Force).Count -ne 0) {
			throw "dist must be absent or empty; release builder will not overwrite prior artifacts."
		}
	}
    Push-Location $repoRoot
    $locationPushed = $true
    Assert-RepositoryRoot -ExpectedRoot $repoRoot
    $head = Get-GitLine -Arguments @("rev-parse", "HEAD")
    if ($head -cne $TestedRevision) {
        throw "TestedRevision does not equal the exact checkout HEAD."
    }
    $testedTree = Get-GitLine -Arguments @("rev-parse", "HEAD^{tree}")
	Assert-SourceUnchanged -Revision $TestedRevision -Tree $testedTree

    # Host-only controllers must not inherit a caller's cross-build tuple.
    $env:GOOS = $null; $env:GOARCH = $null; $env:CGO_ENABLED = "0"
    New-Item -ItemType Directory -Path $stagingRoot | Out-Null
    New-Item -ItemType Directory -Path $artifactRoot | Out-Null
    New-Item -ItemType Directory -Path $toolRoot | Out-Null
    $env:GOCACHE = Join-Path $stagingRoot "gocache"
    $env:GOMODCACHE = Join-Path $stagingRoot "gomodcache"
    $env:GOTMPDIR = Join-Path $stagingRoot "gotmp"
    New-Item -ItemType Directory -Path $env:GOCACHE | Out-Null
    New-Item -ItemType Directory -Path $env:GOMODCACHE | Out-Null
    New-Item -ItemType Directory -Path $env:GOTMPDIR | Out-Null
    $env:GOPROXY = "https://proxy.golang.org"
    $env:GOSUMDB = "sum.golang.org"
    # Keep this fresh, task-local cache removable by the non-root Linux
    # controller after qualification.
    & $goCommand mod download -modcacherw >$null 2>$null
    if ($LASTEXITCODE -ne 0) { throw "release dependency setup failed" }
    & $goCommand mod verify >$null 2>$null
    if ($LASTEXITCODE -ne 0) { throw "release dependency verification failed" }
    $env:GOPROXY = "off"

    # This private controller is built from the exact checkout and is never a
    # release asset. It qualifies the separately built helper before execution.
    $qualifier = Join-Path $toolRoot "repopass-release-qualify-host.exe"
    & $goCommand build -trimpath -buildvcs=true -mod=readonly -ldflags "-s -w" -o $qualifier `
        ./internal/releasequalification/cmd/repopass-release-qualify >$null 2>$null
    if ($LASTEXITCODE -ne 0) { throw "go build failed for private release qualifier" }
    Assert-ExactRegularFiles -Path $toolRoot -ExpectedNames $toolInventory
    $qualifierSHA256 = Get-RegularFileSHA256 -Path $qualifier

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
            $output = Join-Path $artifactRoot $build.Name
            & $goCommand build -trimpath -buildvcs=true -mod=readonly `
                -ldflags "-s -w -X $versionSymbol" -o $output $build.Path >$null 2>$null
            if ($LASTEXITCODE -ne 0) { throw "go build failed for $($build.Name)" }
        }
    }

    # The helper is host-only and remains in staging; it never enters dist.
    $env:GOOS = $null; $env:GOARCH = $null; $env:CGO_ENABLED = "0"
    $kitTool = Join-Path $artifactRoot "repopass-kit-host.exe"
    & $goCommand build -trimpath -buildvcs=true -mod=readonly -ldflags "-s -w" `
        -o $kitTool ./cmd/repopass-kit >$null 2>$null
    if ($LASTEXITCODE -ne 0) { throw "go build failed for release-kit helper" }
    $kitToolSHA256 = Get-RegularFileSHA256 -Path $kitTool

    Assert-ExactRegularFiles -Path $artifactRoot -ExpectedNames $preHelperInventory
    Assert-SourceUnchanged -Revision $TestedRevision -Tree $testedTree
    Assert-FileSHA256 -Path $qualifier -ExpectedSHA256 $qualifierSHA256
    & $qualifier -phase pre-helper -root $artifactRoot `
        -tested-revision $TestedRevision -tree $testedTree
    $qualifierExit = $LASTEXITCODE
    Assert-FileSHA256 -Path $qualifier -ExpectedSHA256 $qualifierSHA256
    Assert-FileSHA256 -Path $kitTool -ExpectedSHA256 $kitToolSHA256
    if ($qualifierExit -ne 0) { throw "pre-helper release qualification failed" }

    foreach ($target in $targets) {
        $binary = Join-Path $artifactRoot $target.Verify
        $kit = Join-Path $artifactRoot $target.Kit
        Assert-FileSHA256 -Path $kitTool -ExpectedSHA256 $kitToolSHA256
        & $kitTool -os $target.GOOS -arch $target.GOARCH -version $Version -binary $binary -output $kit `
            >$null 2>$null
        $kitExit = $LASTEXITCODE
        Assert-FileSHA256 -Path $kitTool -ExpectedSHA256 $kitToolSHA256
        if ($kitExit -ne 0) { throw "release-kit creation failed for $($target.GOOS)/$($target.GOARCH)" }
    }

    Assert-ExactRegularFiles -Path $artifactRoot -ExpectedNames $postHelperInventory
    Assert-SourceUnchanged -Revision $TestedRevision -Tree $testedTree

    $publish = @($targets | ForEach-Object { $_.Full; $_.Verify; $_.Kit }) | Sort-Object
    New-Item -ItemType Directory -Path $publishRoot | Out-Null
    foreach ($name in $publish) {
        Copy-Item -LiteralPath (Join-Path $artifactRoot $name) -Destination (Join-Path $publishRoot $name)
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
	Assert-SourceUnchanged -Revision $TestedRevision -Tree $testedTree `
		-AllowedUntrackedRoot $publishRoot -AllowedUntrackedNames $releaseInventory
    # Resolve the destination before the final byte qualification. The
    # controller owns the same-parent rename so no script-level path re-read
    # can substitute bytes between qualification and publication.
    if (Test-Path -LiteralPath $distRoot) {
        $distItem = Get-Item -LiteralPath $distRoot -Force
        if (-not $distItem.PSIsContainer -or
            ($distItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            @(Get-ChildItem -LiteralPath $distRoot -Force).Count -ne 0) {
            throw "dist changed during build and is no longer empty."
        }
        Remove-Item -LiteralPath $distRoot -Force
    }
    Assert-FileSHA256 -Path $qualifier -ExpectedSHA256 $qualifierSHA256
	Remove-ScopedDirectory -Parent $temporaryBase -Path $stagingRoot `
		-LeafPrefix "repopass-release-staging-"
    Pop-Location
    $locationPushed = $false
    & $qualifier -phase pre-publish -root $publishRoot `
        -tested-revision $TestedRevision -tree $testedTree -publish-to $distRoot
    $qualifierExit = $LASTEXITCODE
    if ($qualifierExit -ne 0) { throw "pre-publish release qualification failed" }
	$distWasPublished = $true

    try {
		Remove-ScopedDirectory -Parent $temporaryBase -Path $controllerRoot `
			-LeafPrefix "repopass-release-controller-"
        $published = $true
    }
    catch {
        throw "post-publication cleanup failed; dist was withdrawn."
    }
}
catch {
    throw "release construction failed at a redacted fail-closed boundary."
}
finally {
    if ($locationPushed) {
        Pop-Location
    }
    $env:GOOS = $previousGOOS
    $env:GOARCH = $previousGOARCH
    $env:CGO_ENABLED = $previousCGO
    $env:GOWORK = $previousGOWORK
    $env:GOENV = $previousGOENV
    $env:GOFLAGS = $previousGOFLAGS
    $env:GOTOOLCHAIN = $previousGOTOOLCHAIN
    $env:GOAMD64 = $previousGOAMD64
    $env:GOEXPERIMENT = $previousGOEXPERIMENT
    $env:GODEBUG = $previousGODEBUG
    $env:GOROOT = $previousGOROOT
    $env:GOCACHE = $previousGOCACHE
    $env:GOMODCACHE = $previousGOMODCACHE
    $env:GOTMPDIR = $previousGOTMPDIR
    $env:GOPROXY = $previousGOPROXY
    $env:GOSUMDB = $previousGOSUMDB
    $env:GOPRIVATE = $previousGOPRIVATE
	$env:GONOPROXY = $previousGONOPROXY
    $env:GONOSUMDB = $previousGONOSUMDB
    $env:GOINSECURE = $previousGOINSECURE
	$env:GOAUTH = $previousGOAUTH
	$env:GOCACHEPROG = $previousGOCACHEPROG
	$env:GOFIPS140 = $previousGOFIPS140
	$env:GOTELEMETRY = $previousGOTELEMETRY
	$env:GOVCS = $previousGOVCS
	$env:GO111MODULE = $previousGO111MODULE
	$env:PATH = $previousPATH
    $env:GIT_DIR = $previousGIT_DIR
    $env:GIT_WORK_TREE = $previousGIT_WORK_TREE
    $env:GIT_INDEX_FILE = $previousGIT_INDEX_FILE
    $env:GIT_OBJECT_DIRECTORY = $previousGIT_OBJECT_DIRECTORY
    $env:GIT_ALTERNATE_OBJECT_DIRECTORIES = $previousGIT_ALTERNATE_OBJECT_DIRECTORIES
    $env:GIT_COMMON_DIR = $previousGIT_COMMON_DIR
    $env:GIT_NAMESPACE = $previousGIT_NAMESPACE
    $env:GIT_CEILING_DIRECTORIES = $previousGIT_CEILING_DIRECTORIES
    $env:GIT_DISCOVERY_ACROSS_FILESYSTEM = $previousGIT_DISCOVERY_ACROSS_FILESYSTEM
    $env:GIT_NO_REPLACE_OBJECTS = $previousGIT_NO_REPLACE_OBJECTS
	$env:GIT_CONFIG_NOSYSTEM = $previousGIT_CONFIG_NOSYSTEM
	$env:GIT_CONFIG_GLOBAL = $previousGIT_CONFIG_GLOBAL
	$env:GIT_CONFIG_SYSTEM = $previousGIT_CONFIG_SYSTEM
	$env:GIT_CONFIG_COUNT = $previousGIT_CONFIG_COUNT
	$env:GIT_CONFIG_PARAMETERS = $previousGIT_CONFIG_PARAMETERS
	$env:GIT_EXEC_PATH = $previousGIT_EXEC_PATH
	$env:GIT_SSH = $previousGIT_SSH
	$env:GIT_SSH_COMMAND = $previousGIT_SSH_COMMAND
	$env:GIT_ASKPASS = $previousGIT_ASKPASS
	$env:GIT_TERMINAL_PROMPT = $previousGIT_TERMINAL_PROMPT
    if (-not $published) {
		$cleanupFailed = $false
		if ($distWasPublished) {
			try {
				if (Test-Path -LiteralPath $distRoot) {
					Assert-NoReparsePathComponents -Path $repoRoot
					Assert-NoReparsePathComponents -Path $distRoot
					$withdrawRoot = Join-Path $repoRoot (".release-withdrawn-" + [Guid]::NewGuid().ToString("N"))
					Assert-NoReparsePathComponents -Path $withdrawRoot -AllowMissingLeaf
					[IO.Directory]::Move($distRoot, $withdrawRoot)
				}
			}
			catch {
				$cleanupFailed = $true
			}
		}
		try {
			Remove-ScopedDirectory -Parent $temporaryBase -Path $stagingRoot `
				-LeafPrefix "repopass-release-staging-"
		}
		catch { $cleanupFailed = $true }
		try {
			Remove-ScopedDirectory -Parent $temporaryBase -Path $controllerRoot `
				-LeafPrefix "repopass-release-controller-"
		}
		catch { $cleanupFailed = $true }
		try {
			Remove-ScopedDirectory -Parent $repoRoot -Path $publishRoot `
				-LeafPrefix ".release-publish-"
		}
		catch { $cleanupFailed = $true }
		if ($withdrawRoot -ne "") {
			try {
				Remove-ScopedDirectory -Parent $repoRoot -Path $withdrawRoot `
					-LeafPrefix ".release-withdrawn-"
			}
			catch { $cleanupFailed = $true }
		}
		if ($cleanupFailed) {
			throw "release cleanup failed at a redacted fail-closed boundary."
		}
    }
}
