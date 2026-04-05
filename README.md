# npm-threat-observatory

本项目是一个本地 PoC，用来分析 npm 包在安装期和运行期是否出现可疑行为。当前仓库按 **Podman 优先，Docker 兼容** 的方式组织，系统提供上传归档、registry 包和本地样本三种分析来源，并提供两种检测模式：

- `portable`：适合 mac 本机，通过命令包装器和 Node hook 采集高风险行为
- `falco`：适合 Linux VM，通过 `Falco + modern eBPF` 获取更强的容器行为观测

## Components

- `control-api`: 提交分析任务、查询结果、接收 Falco webhook
- `worker`: 轮询待分析任务，拉起隔离分析容器执行安装期和运行期检查
- `analyzer`: Node.js 分析镜像，负责实际安装 npm 包和触发运行期加载
- `falco` / `falcosidekick`: Linux 模式下捕获容器行为并推送告警
- `verdaccio`: 本地 npm 代理
- `db`: 保存分析任务、容器映射、告警事件

## Quick Start

### 方式 1：mac 本机 + Podman（portable 模式）

1. 启动 Podman machine：

```bash
podman machine start
```

2. 查看 Podman machine 的 API socket。你这台机器当前默认连接名是 `podman-machine-default`，URI 是：

```text
ssh://core@127.0.0.1:54054/run/user/501/podman/podman.sock
```

通常还需要一个本地转发 socket，常见路径是：

```bash
~/.local/share/containers/podman/machine/podman.sock
```

3. 用 Podman Compose 启动 portable 模式，把宿主机 Podman socket 挂进容器：

```bash
export CONTAINER_SOCKET_PATH="$HOME/.local/share/containers/podman/machine/podman.sock"
export CONTROL_API_HOST_PORT=18000
podman compose build analyzer control-api worker
podman compose up -d
```

4. 查看健康状态，确认后端为 `portable`：

```bash
curl http://localhost:18000/health
```

### 方式 2：Linux VM（falco 模式）

1. 在 Linux VM 中安装 Podman 或 Docker，内核需支持 Falco modern eBPF。
2. 以 Falco profile 启动：

```bash
DETECTION_BACKEND=falco CONTAINER_SOCKET_PATH=/var/run/docker.sock podman compose --profile linux-falco build analyzer control-api worker
DETECTION_BACKEND=falco CONTAINER_SOCKET_PATH=/var/run/docker.sock podman compose --profile linux-falco up -d
```

如果 Linux VM 里用的是 Docker，也可以把上面的 `podman compose` 换成 `docker compose`。

### 提交一个 registry 分析任务

```bash
curl -X POST http://localhost:8000/analyses \
  -H 'Content-Type: application/json' \
  -d '{
    "package_name": "left-pad",
    "version": "1.3.0",
    "runtime_mode": "require"
  }'
```

如果你本机的 `8000`、`5432`、`4873` 或 `2801` 已被占用，可以在启动前覆盖这些环境变量：

```bash
export CONTROL_API_HOST_PORT=18000
export DB_HOST_PORT=15432
export VERDACCIO_HOST_PORT=14873
export FALCOSIDEKICK_HOST_PORT=12801
```

4. 查询任务与事件：

```bash
curl http://localhost:8000/analyses/<analysis_id>
curl http://localhost:8000/analyses/<analysis_id>/events
```

### 上传一个 npm 归档分析任务

```bash
curl -X POST http://localhost:18000/analyses/upload \
  -F file=@./package.tgz \
  -F runtime_mode=require \
  -F egress_mode=offline
```

## API

- `POST /analyses`
- `POST /analyses/upload`
- `GET /analyses/{id}`
- `GET /analyses/{id}/events`
- `GET /health`
- `POST /webhooks/falco`

## Notes

- `portable` 模式不依赖 Linux 内核能力，所以 mac 上也能演示安装期/运行期的高风险行为。
- `portable` 模式是 PoC 级降级检测，覆盖 shell 派生、可疑网络访问、敏感凭据路径访问、下载执行等高风险动作，但能力弱于内核级 Falco。
- 上传归档支持 `.tgz`、`.tar.gz`、`.zip`，默认会校验路径穿越、符号链接、文件数量和展开体积。
- 上传与 sample 任务默认 `offline`；registry 任务默认 `registry_only`，只允许访问 registry host。
- 当前 worker/control-api 仍通过 Docker-compatible API 驱动容器，所以无论底层是 Podman 还是 Docker，都需要把兼容 API socket 挂载到容器内的 `/var/run/docker.sock`。
- 在 mac 上如果 `podman info` 报无法连接，先执行 `podman machine start`，再重试 `podman system connection list` 和 `podman compose up`。
- `falco` 服务默认启用 `--modern-bpf`，要求 Linux VM 内核支持 modern eBPF。
- 如果 Linux 内核不支持 modern eBPF，需要把 `falco` 服务切换到 driver 模式。
- `samples/` 目录提供了本地恶意/正常样例，便于后续接入文件源分析或 Verdaccio uplink 验证。
