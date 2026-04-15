# NetGuardian Backend

阶段二后端基座，采用 FastAPI + SQLModel 三层结构。

## 架构分层
- API 层: `app/api/` 处理 HTTP 请求和响应模型
- Service 层: `app/services/` 处理模型推理与柔性阻断业务逻辑
- Model 层: `app/models/` 处理 SQLModel 数据结构与数据库读写

## 运行
```bash
/home/meta/miniconda3/envs/cqy/bin/python backend/run.py --reload
```

如果当前终端目录已经在 `backend/` 下，也可以直接运行：
```bash
/home/meta/miniconda3/envs/cqy/bin/python run.py --reload
```

## 关键接口
- `POST /api/v1/auth/register` 注册用户（可选注册管理员，需 `admin_code`）
- `POST /api/v1/auth/login` 登录并获取 bearer token
- `GET /api/v1/auth/me` 获取当前用户信息
- `POST /api/v1/traffic/analyze` 分析单条流量并入库
- `POST /api/v1/traffic/{log_id}/review` 人工审批待审核流量
- `GET /api/v1/traffic/logs` 查询最近日志
- `GET /api/v1/users` 管理员查看用户列表
- `PATCH /api/v1/users/{user_id}` 管理员修改用户角色/启用状态
- `GET /api/v1/traffic/required-features` 返回当前模型要求的特征列（用于采集端对齐）
- `POST /api/v1/collector/start` 启动采集守护进程（管理员）
- `POST /api/v1/collector/stop` 停止采集守护进程（管理员）
- `GET /api/v1/collector/status` 查看采集吞吐与失败队列（管理员）
- `POST /api/v1/collector/retry` 触发失败队列重试（管理员）

## 管理员注册码
- 默认未配置 `ADMIN_REGISTRATION_CODE` 时，管理员注册会被禁用。
- 复制 `backend/.env.example` 到 `backend/.env` 并设置 `ADMIN_REGISTRATION_CODE` 后可注册管理员。

## CICFlowMeter 实时接入（78维向量）
当前状态说明：
- 本仓库已实现“CICFlowMeter CSV -> 78维特征 -> NetGuardian分析”链路。
- 当前环境未内置 CICFlowMeter 二进制或 jar，请在主机上安装/部署 CICFlowMeter 后接入。

推荐部署方式（独立于本仓库）：
1. 准备抓包环境（Linux）：`tcpdump`/`tshark` 可用。
2. 安装并运行 CICFlowMeter（jar 或容器）将实时流量输出为滚动 CSV。
3. 在本系统使用桥接脚本或后端守护进程监听 CSV 目录。

示例（目录监听多文件）：
```bash
/home/meta/miniconda3/envs/cqy/bin/python backend/scripts/cicflowmeter_bridge.py \
	--csv-dir /path/to/cicflowmeter_output \
	--glob "*.csv" \
	--max-retries 3 \
	--api-base http://127.0.0.1:8000/api/v1 \
	--token <YOUR_BEARER_TOKEN>
```

1. 用 CICFlowMeter 对实时流量或 pcap 生成 flow CSV（列名保持默认）。
2. 登录获取 bearer token（`POST /api/v1/auth/login`）。
3. 启动桥接脚本，将 CSV 新行实时转发给分析接口：

```bash
/home/meta/miniconda3/envs/cqy/bin/python backend/scripts/cicflowmeter_bridge.py \
	--csv /path/to/cicflowmeter_live.csv \
	--api-base http://127.0.0.1:8000/api/v1 \
	--token <YOUR_BEARER_TOKEN>
```

目录监听多文件模式（推荐，适配 CICFlowMeter 滚动文件）：

```bash
/home/meta/miniconda3/envs/cqy/bin/python backend/scripts/cicflowmeter_bridge.py \
	--csv-dir /path/to/cicflowmeter_output \
	--glob "*.csv" \
	--max-retries 3 \
	--api-base http://127.0.0.1:8000/api/v1 \
	--token <YOUR_BEARER_TOKEN>
```

说明：
- 脚本会先调用 `GET /traffic/required-features` 拉取当前模型需要的特征列，再从 CICFlowMeter 行中抽取对应字段。
- 模型侧使用 artifact 中的特征列表，当前为 78 维训练特征；若后续模型重训改变特征，桥接脚本无需改代码。

## 后端采集守护进程（管理员）
可通过 API 在后端启动/停止 CSV 采集线程，并查看吞吐和失败重试队列：

- `POST /api/v1/collector/start`
- `POST /api/v1/collector/stop`
- `GET /api/v1/collector/status`
- `POST /api/v1/collector/retry`
- `GET /api/v1/collector/interfaces` 自动探测可用网卡列表（管理员）

`/collector/start` 请求示例：

```json
{
	"csv_dir": "/path/to/cicflowmeter_output",
	"file_glob": "*.csv",
	"poll_seconds": 1.0,
	"max_retries": 3
}
```

### 一键实时网卡链路（tcpdump + cfm + 78维分析）
你已部署 cfm：
- `/home/meta/master_pieces/NetGuardian/CICFlowMeter-4.0/bin/cfm`

推荐通过 `/api/v1/collector/start` 直接启动完整链路：

```json
{
	"enable_cfm_capture": true,
	"cfm_binary": "/home/meta/master_pieces/NetGuardian/CICFlowMeter-4.0/bin/cfm",
	"tcpdump_binary": "/usr/bin/tcpdump",
	"network_interface": "eth0",
	"capture_filter": "",
	"pcap_dir": "/tmp/cicflow/pcap",
	"pcap_glob": "*.pcap",
	"rotate_seconds": 30,
	"csv_dir": "/tmp/cicflow/csv",
	"file_glob": "*.csv",
	"poll_seconds": 1.0,
	"max_retries": 3
}
```

链路说明：
1. tcpdump 按 `rotate_seconds` 把网卡流量切片成 pcap。
2. 守护进程逐个调用 cfm 把 pcap 转成 CSV。
3. 守护进程从 CSV 提取模型要求的 78 维特征并调用 `/traffic/analyze`。
4. 分析结果入库并通过 websocket 广播到前端。

常见问题：
- 若 `collector/status` 中 `tcpdump_running=false` 且 `tcpdump_last_error` 包含 `Operation not permitted`，说明当前进程没有网卡抓包权限。
	- 方案A：用具备权限的用户运行后端（如 root）。
	- 方案B：给 tcpdump 赋予抓包能力（Linux）：
		`sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump`

频率参数说明：
- 抓包切片频率：`rotate_seconds`（默认 30 秒）
- 采集轮询频率：`poll_seconds`（默认 1 秒）
- 实际端到端更新节奏大致为：每个切片周期 + cfm 转换时间 + 一次轮询延迟
