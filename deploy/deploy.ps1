# ==============================================================================
# REA (Reverse Engineer Anything) Deployment Script for Windows (PowerShell)
# ==============================================================================
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Command = "help",

    [Parameter(Position = 1)]
    [string]$Group = "all",

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$RemainingArgs
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

function Write-Color([string]$text, [ConsoleColor]$color) {
    $prev = [Console]::ForegroundColor
    [Console]::ForegroundColor = $color
    Write-Host $text
    [Console]::ForegroundColor = $prev
}

function Log-Info([string]$msg) {
    Write-Host "[INFO] " -ForegroundColor Cyan -NoNewline
    Write-Host $msg
}

function Log-Success([string]$msg) {
    Write-Host "[SUCCESS] " -ForegroundColor Green -NoNewline
    Write-Host $msg
}

function Log-Warn([string]$msg) {
    Write-Host "[WARN] " -ForegroundColor Yellow -NoNewline
    Write-Host $msg
}

function Log-Error([string]$msg) {
    Write-Host "[ERROR] " -ForegroundColor Red -NoNewline
    Write-Host $msg
}

function Show-Banner {
    Write-Color @"
  ____  _____    _    
 |  _ \| ____|  / \   
 | |_) |  _|   / _ \  
 |  _ <| |___ / ___ \ 
 |_| \_\_____/_/   \_\
                      
 Reverse Engineer Anything - Windows Container Deployment
"@ Green
}

function Show-Help {
    @"
Usage: .\deploy.ps1 <command> [group] [options]

Commands:
  start [group]     Start services (default group: all).
                    Available groups: all, core, web, inspector
  stop [group]      Stop services.
  restart [group]   Restart services.
  status            Show status and health of REA containers.
  logs [service]    View logs (optional: rea-core, rea-web, rea-inspector).
  build [group]     Build or rebuild Docker images.
  cli [command...]  Execute a REA CLI command inside the rea-core container.
                    Example: .\deploy.ps1 cli doctor --json
  mcp               Launch interactive REA MCP stdio server.
  clean             Remove REA containers, volumes, and networks.
  help              Display this help message.

Service Groups:
  all         All REA services (core CLI/MCP, Web documentation, and MCP Inspector)
  core        Core REA engine container only (for CLI and Agent MCP connections)
  web         REA Documentation and Showcase website (Nginx on port 4173)
  inspector   MCP Web Inspector tool for testing tools in browser (port 6274)

Examples:
  .\deploy.ps1 start all
  .\deploy.ps1 start web
  .\deploy.ps1 cli analyze-javascript-application /workspace/targets/myapp
  .\deploy.ps1 status
"@
}

function Check-Prerequisites {
    # Check Docker
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Log-Error "Docker is not installed or not in PATH. Please install Docker Desktop."
        exit 1
    }

    try {
        docker info *> $null
    } catch {
        Log-Error "Docker daemon is not running. Please start Docker Desktop."
        exit 1
    }

    # Ensure .env exists
    if (-not (Test-Path ".env")) {
        if (Test-Path ".env.example") {
            Log-Info "No .env found. Creating .env from .env.example..."
            Copy-Item ".env.example" ".env"
            Log-Success "Created .env"
        }
    }

    # Load .env variables into process
    if (Test-Path ".env") {
        Get-Content ".env" | ForEach-Object {
            $line = $_.Trim()
            if ($line -and -not $line.StartsWith("#") -and $line.Contains("=")) {
                $parts = $line.Split("=", 2)
                [Environment]::SetEnvironmentVariable($parts[0].Trim(), $parts[1].Trim(), "Process")
            }
        }
    }

    # Create workspace directories
    $targetsDir = if ($env:REA_TARGETS_DIR) { $env:REA_TARGETS_DIR } else { "../targets" }
    $outputDir = if ($env:REA_OUTPUT_DIR) { $env:REA_OUTPUT_DIR } else { "../output" }
    if (-not (Test-Path $targetsDir)) { New-Item -ItemType Directory -Path $targetsDir -Force | Out-Null }
    if (-not (Test-Path $outputDir)) { New-Item -ItemType Directory -Path $outputDir -Force | Out-Null }
}

function Test-PortInUse([int]$port) {
    try {
        $conn = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue
        return ($null -ne $conn)
    } catch {
        $found = netstat -ano | Select-String ":$port\s"
        return ($null -ne $found)
    }
}

function Check-PortConflicts([string]$grp) {
    $webPort = if ($env:REA_WEB_PORT) { [int]$env:REA_WEB_PORT } else { 4173 }
    $inspectorPort = if ($env:REA_INSPECTOR_PORT) { [int]$env:REA_INSPECTOR_PORT } else { 6274 }

    if ($grp -eq "all" -or $grp -eq "web") {
        if (Test-PortInUse $webPort) {
            $existing = docker ps --filter "name=rea-web" --format "{{.Ports}}"
            if (-not $existing -or -not ($existing -match "$webPort")) {
                Log-Warn "Port $webPort (REA_WEB_PORT) is in use by another application!"
                Log-Warn "To avoid conflict, update REA_WEB_PORT in .env to an available port."
            }
        }
    }

    if ($grp -eq "all" -or $grp -eq "inspector") {
        if (Test-PortInUse $inspectorPort) {
            $existing = docker ps --filter "name=rea-inspector" --format "{{.Ports}}"
            if (-not $existing -or -not ($existing -match "$inspectorPort")) {
                Log-Warn "Port $inspectorPort (REA_INSPECTOR_PORT) is in use by another application!"
                Log-Warn "To avoid conflict, update REA_INSPECTOR_PORT in .env to an available port."
            }
        }
    }
}

# ------------------------------------------------------------------------------
# Dispatcher
# ------------------------------------------------------------------------------
Show-Banner
Check-Prerequisites

switch ($Command.ToLower()) {
    "start" {
        Check-PortConflicts $Group
        Log-Info "Starting REA services (group: $Group)..."
        docker compose --profile $Group up -d --remove-orphans
        Log-Success "REA services started."
        & $MyInvocation.MyCommand.Path "status"
    }
    "up" {
        Check-PortConflicts $Group
        docker compose --profile $Group up -d --remove-orphans
        & $MyInvocation.MyCommand.Path "status"
    }
    "stop" {
        Log-Info "Stopping REA services (group: $Group)..."
        docker compose --profile $Group stop
        Log-Success "Services stopped."
    }
    "down" {
        docker compose --profile $Group stop
    }
    "restart" {
        Log-Info "Restarting REA services (group: $Group)..."
        docker compose --profile $Group stop
        docker compose --profile $Group up -d --remove-orphans
        Log-Success "Restarted."
        & $MyInvocation.MyCommand.Path "status"
    }
    "status" {
        Write-Host ""
        Log-Info "REA Container Status:"
        docker compose ps --all
        Write-Host ""
        Log-Info "Endpoints & Ports:"
        $webPort = if ($env:REA_WEB_PORT) { $env:REA_WEB_PORT } else { "4173" }
        $inspPort = if ($env:REA_INSPECTOR_PORT) { $env:REA_INSPECTOR_PORT } else { "6274" }
        Write-Host "  - Web Documentation: http://localhost:$webPort"
        Write-Host "  - MCP Inspector UI:  http://localhost:$inspPort"
        Write-Host "  - CLI / MCP Engine:  container 'rea-core'"
        Write-Host "    * Run CLI command: .\deploy.ps1 cli <command>"
        Write-Host "    * AI Agent MCP:    docker exec -i rea-core rea mcp`n"
    }
    "ps" {
        & $MyInvocation.MyCommand.Path "status"
    }
    "logs" {
        if ($Group -and $Group -ne "all") {
            docker compose logs -f $Group
        } else {
            docker compose logs -f
        }
    }
    "build" {
        Log-Info "Building REA Docker images for group: $Group..."
        docker compose --profile $Group build
        Log-Success "Build complete."
    }
    "cli" {
        $running = docker ps --filter "name=rea-core" --filter "status=running" --format "{{.ID}}"
        if (-not $running) {
            Log-Warn "Container 'rea-core' is not running. Starting it now..."
            docker compose --profile core up -d rea-core
        }
        $cliArgs = @()
        if ($Group -and $Group -ne "all") { $cliArgs += $Group }
        if ($RemainingArgs) { $cliArgs += $RemainingArgs }
        docker exec -it rea-core rea @cliArgs
    }
    "mcp" {
        $running = docker ps --filter "name=rea-core" --filter "status=running" --format "{{.ID}}"
        if (-not $running) {
            docker compose --profile core up -d rea-core
        }
        docker exec -i rea-core rea mcp
    }
    "clean" {
        Log-Warn "Removing REA containers, networks, and volumes (scoped strictly to 'rea' project)..."
        docker compose down -v --remove-orphans
        Log-Success "Cleanup complete. Other containers on host remain untouched."
    }
    "help" {
        Show-Help
    }
    default {
        Log-Error "Unknown command: $Command"
        Show-Help
        exit 1
    }
}
