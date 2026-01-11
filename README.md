「一键初始化新服务器」的 bootstrap 脚本，特点：
	•	适用于 Ubuntu 20.04/22.04/24.04
	•	自动安装 sing-box
	•	自动安装 sb 管理脚本
	•	自动写入 Reality 节点配置（支持 SOCKS 或 TUN）
	•	自动创建并启用 systemd 服务
	•	自动开启 IPv4 转发（TUN 需要）
	•	最后自动做一次出口测试

export $(sed -e 's/#.*//g' -e 's/ //g' templates/example.env) \
&& curl -fsSL https://raw.githubusercontent.com/scsun1978/sb-bootstrap-server/main/bootstrap-sb.sh | bash

初始化完成后你怎么管理
	•	查看状态：sb status
	•	跟踪日志：sb logs
	•	重启：sb restart
	•	停止：sb stop
	•	最近 200 行日志：sb logn 200
-（SOCKS 模式）让当前 shell 走代理：
	•	eval "$(sb env-proxy)"

⸻

MODE=tun \
SERVER= \
PORT= \
UUID= \
SNI=apple.com \
PBK= \
SID= \
FP=chrome \
FLOW=xtls-rprx-vision \
DIRECT_CIDRS="" \
curl -fsSL https://raw.githubusercontent.com/scsun1978/sb-bootstrap-server/main/bootstrap-sb.sh | bash
