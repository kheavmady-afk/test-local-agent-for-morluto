#!/usr/bin/env bash
# ==============================================================================
# REA (Reverse Engineer Anything) Deployment Script for Linux / Ubuntu / macOS
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

# ------------------------------------------------------------------------------
# Colors & Formatting
# ------------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

log_info() {
    printf "${BLUE}[INFO]${NC} %s\n" "$1"
}

log_success() {
    printf "${GREEN}[SUCCESS]${NC} %s\n" "$1"
}

log_warn() {
    printf "${YELLOW}[WARN]${NC} %s\n" "$1"
}

log_error() {
    printf "${RED}[ERROR]${NC} %s\n" "$1" >&2
}

banner() {
    cat << "EOF"
  ____  _____    _    
 |  _ \| ____|  / \   
 | |_) |  _|   / _ \  
 |  _ <| |___ / ___ \ 
 |_| \_\_____/_/   \_\
                      
 Reverse Engineer Anything - Container Deployment
EOF
}

# ------------------------------------------------------------------------------
# Usage & Help
# ------------------------------------------------------------------------------
show_help() {
    cat << EOF
Usage: ./deploy.sh <command> [options]

Commands:
  start [group]     Start services (default group: all).
                    Available groups: all, core, web, inspector
  stop [group]      Stop services.
  restart [group]   Restart services.
  status            Show status and health of REA containers.
  logs [service]    View logs (optional: rea-core, rea-web, rea-inspector).
  build [group]     Build or rebuild Docker images.
  cli [command...]  Execute a REA CLI command inside the rea-core container.
                    Example: ./deploy.sh cli doctor --json
  mcp               Launch interactive REA MCP stdio server.
  clean             Remove REA containers, volumes, and networks.
  help              Display this help message.

Service Groups:
  all         All REA services (core CLI/MCP, Web documentation, and MCP Inspector)
  core        Core REA engine container only (for CLI and Agent MCP connections)
  web         REA Documentation and Showcase website (Nginx on port 4173)
  inspector   MCP Web Inspector tool for testing tools in browser (port 6274)

Examples:
  ./deploy.sh start all
  ./deploy.sh start web
  ./deploy.sh cli analyze-javascript-application /workspace/targets/myapp
  ./deploy.sh status
EOF
}

# ------------------------------------------------------------------------------
# Pre-flight Checks
# ------------------------------------------------------------------------------
check_prerequisites() {
    # Check Docker
    if ! command -v docker >/dev/null 2>&1; then
        log_error "Docker is not installed or not in PATH. Please install Docker first."
        exit 1
    fi

    if ! docker info >/dev/null 2>&1; then
        log_error "Docker daemon is not running or current user lacks docker permissions."
        exit 1
    fi

    # Check Docker Compose
    if ! docker compose version >/dev/null 2>&1; then
        log_error "Docker Compose v2 ('docker compose') is required but not found."
        exit 1
    fi

    # Ensure .env exists
    if [ ! -f ".env" ]; then
        if [ -f ".env.example" ]; then
            log_info "No .env file found. Creating .env from .env.example..."
            cp .env.example .env
            log_success "Created .env"
        else
            log_warn "Neither .env nor .env.example found."
        fi
    fi

    # Source .env if present
    if [ -f ".env" ]; then
        set -a
        # shellcheck disable=SC1091
        source .env
        set +a
    fi

    # Create workspace directories
    mkdir -p "${REA_TARGETS_DIR:-../targets}" "${REA_OUTPUT_DIR:-../output}"
    chmod 777 "${REA_OUTPUT_DIR:-../output}" 2>/dev/null || true
}

# Check if a port is in use on the host
is_port_in_use() {
    local port="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -tuln | grep -q ":${port} " && return 0
    elif command -v lsof >/dev/null 2>&1; then
        lsof -iTCP:"${port}" -sTCP:LISTEN >/dev/null 2>&1 && return 0
    elif command -v netstat >/dev/null 2>&1; then
        netstat -tuln | grep -q ":${port} " && return 0
    fi
    return 1
}

check_port_conflicts() {
    local group="${1:-all}"
    local web_port="${REA_WEB_PORT:-4173}"
    local inspector_port="${REA_INSPECTOR_PORT:-6274}"

    if [ "$group" = "all" ] || [ "$group" = "web" ]; then
        if is_port_in_use "$web_port"; then
            # Verify if it's already our own container
            if ! docker ps --filter "name=rea-web" --format "{{.Ports}}" | grep -q "$web_port"; then
                log_warn "Port ${web_port} (REA_WEB_PORT) is already in use by another application!"
                log_warn "To avoid conflicts, please update REA_WEB_PORT in .env to an available port."
            fi
        fi
    fi

    if [ "$group" = "all" ] || [ "$group" = "inspector" ]; then
        if is_port_in_use "$inspector_port"; then
            if ! docker ps --filter "name=rea-inspector" --format "{{.Ports}}" | grep -q "$inspector_port"; then
                log_warn "Port ${inspector_port} (REA_INSPECTOR_PORT) is already in use by another application!"
                log_warn "To avoid conflicts, please update REA_INSPECTOR_PORT in .env to an available port."
            fi
        fi
    fi
}

# ------------------------------------------------------------------------------
# Operations
# ------------------------------------------------------------------------------
cmd_build() {
    local group="${1:-all}"
    log_info "Building REA Docker images for group: ${group}..."
    docker compose --profile "${group}" build
    log_success "Build complete."
}

cmd_start() {
    local group="${1:-all}"
    check_port_conflicts "${group}"
    log_info "Starting REA services (group: ${group})..."
    docker compose --profile "${group}" up -d --remove-orphans
    log_success "REA services started successfully."
    cmd_status
}

cmd_stop() {
    local group="${1:-all}"
    log_info "Stopping REA services (group: ${group})..."
    docker compose --profile "${group}" stop
    log_success "Services stopped."
}

cmd_restart() {
    local group="${1:-all}"
    log_info "Restarting REA services (group: ${group})..."
    cmd_stop "${group}"
    cmd_start "${group}"
}

cmd_status() {
    printf "\n"
    log_info "REA Container Status:"
    docker compose ps --all
    printf "\n"
    log_info "Endpoints & Ports:"
    printf "  - Web Documentation: http://localhost:%s\n" "${REA_WEB_PORT:-4173}"
    printf "  - MCP Inspector UI:  http://localhost:%s\n" "${REA_INSPECTOR_PORT:-6274}"
    printf "  - CLI / MCP Engine:  container 'rea-core'\n"
    printf "    * Run CLI command: ./deploy.sh cli <command>\n"
    printf "    * AI Agent MCP:    docker exec -i rea-core rea mcp\n\n"
}

cmd_logs() {
    local service="${1:-}"
    if [ -n "$service" ]; then
        docker compose logs -f "$service"
    else
        docker compose logs -f
    fi
}

cmd_cli() {
    if ! docker ps --filter "name=rea-core" --filter "status=running" --format "{{.ID}}" | grep -q .; then
        log_warn "Container 'rea-core' is not running. Starting it now..."
        docker compose --profile core up -d rea-core
    fi
    docker exec -it rea-core rea "$@"
}

cmd_mcp() {
    if ! docker ps --filter "name=rea-core" --filter "status=running" --format "{{.ID}}" | grep -q .; then
        log_warn "Container 'rea-core' is not running. Starting it now..."
        docker compose --profile core up -d rea-core
    fi
    docker exec -i rea-core rea mcp
}

cmd_clean() {
    log_warn "Removing REA containers, networks, and volumes (scoped strictly to 'rea' project)..."
    docker compose down -v --remove-orphans
    log_success "Cleanup complete. Other containers on host remain untouched."
}

# ------------------------------------------------------------------------------
# Entrypoint Dispatcher
# ------------------------------------------------------------------------------
main() {
    banner
    check_prerequisites

    local command="${1:-help}"
    shift || true

    case "${command}" in
        start|up)
            cmd_start "${1:-all}"
            ;;
        stop|down)
            cmd_stop "${1:-all}"
            ;;
        restart)
            cmd_restart "${1:-all}"
            ;;
        status|ps)
            cmd_status
            ;;
        logs)
            cmd_logs "${1:-}"
            ;;
        build)
            cmd_build "${1:-all}"
            ;;
        cli)
            cmd_cli "$@"
            ;;
        mcp)
            cmd_mcp
            ;;
        clean)
            cmd_clean
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            log_error "Unknown command: ${command}"
            show_help
            exit 1
            ;;
    esac
}

main "$@"
