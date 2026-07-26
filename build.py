#!/usr/bin/env python3
"""
Free Universal Sub Generator
拉取多个公开订阅/代理源，去重后同时输出 Clash YAML 和 Sing-box JSON。
每小时自动触发，无请求次数限制（走 GitHub raw CDN）。
"""
import os
import re
import base64
import json
import logging
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Optional
from collections import OrderedDict

# ==================== 全局配置 ====================
REQ_TIMEOUT = 20
MAX_PROXIES = 150
LOG_LEVEL = logging.INFO

SOURCES = [
    ("base64", "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/trojan"),
    ("base64", "https://raw.githubusercontent.com/freefq/free/master/v2"),
    ("base64", "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub"),
    ("base64", "https://raw.githubusercontent.com/mahdibland/SSAggregator/master/sub/sub_merge_base64.txt"),
    ("base64", "https://raw.githubusercontent.com/aiboboxx/clashfree/main/clash.yml"),
]

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; UniversalSubBot/1.0)"}

# 初始化日志
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger(__name__)


# ==================== 数据模型 ====================
@dataclass
class ProxyNode:
    """统一的代理节点中间格式"""
    name: str = ""
    type: str = ""  # clash_type / singbox_type / vmess / ss / trojan / vless
    server: str = ""
    port: int = 0
    # 协议特定字段
    uuid: str = ""
    alter_id: int = 0
    cipher: str = ""
    password: str = ""
    network: str = "tcp"
    ws_path: str = "/"
    ws_host: str = ""
    grpc_service: str = ""
    sni: str = ""
    udp: bool = True
    # 原始数据保留（用于 Clash 渲染）
    raw_clash: dict = field(default_factory=dict)


# ==================== 数据抓取层 ====================
def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=REQ_TIMEOUT) as r:
        return r.read().decode("utf-8", errors="ignore")


def decode_base64_maybe(text: str) -> str:
    text = text.strip()
    rem = len(text) % 4
    if rem:
        text += "=" * (4 - rem)
    try:
        return base64.b64decode(text).decode("utf-8", errors="ignore")
    except Exception:
        return ""


# ==================== 协议解析层 ====================
def try_parse_clash(text: str) -> list[ProxyNode]:
    m = re.search(r'(?m)^proxies:\s*\n(.*?)(?=\n\w|\Z)', text, re.DOTALL)
    if not m:
        return []
    block = m.group(1)
    proxies = []
    items = re.split(r'(?m)^\s*-\s+name:\s*', block)
    for item in items[1:]:
        lines = item.splitlines()
        if not lines:
            continue
        name = lines.strip().strip('"').strip("'")
        raw = {"name": name}
        for line in lines[1:]:
            line = line.rstrip()
            m2 = re.match(r'^\s+([\w-]+)\s*:\s*(.+)$', line)
            if m2:
                k, v = m2.group(1), m2.group(2).strip()
                if v.lower() == "true":
                    v = True
                elif v.lower() == "false":
                    v = False
                else:
                    try:
                        v = int(v)
                    except ValueError:
                        v = v.strip('"').strip("'")
                raw[k] = v
        if raw.get("name"):
            node = ProxyNode(
                name=raw["name"],
                type="clash",
                server=raw.get("server", ""),
                port=raw.get("port", 0),
                raw_clash=raw
            )
            proxies.append(node)
    return proxies


def try_parse_singbox_json(text: str) -> list[ProxyNode]:
    try:
        data = json.loads(text)
        outbounds = data.get("outbounds", [])
        proxies = []
        for ob in outbounds:
            ob_type = ob.get("type")
            if ob_type in {"vmess", "vless", "trojan", "shadowsocks", "hysteria2"}:
                node = ProxyNode(
                    name=ob.get("tag", ""),
                    type="singbox",
                    server=ob.get("server", ""),
                    port=ob.get("server_port", 0),
                    raw_clash=ob
                )
                proxies.append(node)
        return proxies
    except Exception:
        return []


def try_parse_base64_link(link: str) -> Optional[ProxyNode]:
    link = link.strip()
    if not link or link.startswith("#"):
        return None

    try:
        if link.startswith("vmess://"):
            data = json.loads(base64.b64decode(link[8:]))
            return ProxyNode(
                name=data.get("ps", ""),
                type="vmess",
                server=data.get("add", ""),
                port=int(data.get("port", 443)),
                uuid=data.get("id", ""),
                alter_id=int(data.get("aid", 0)),
                cipher=data.get("scy", "auto"),
                network=data.get("net", "tcp"),
                ws_path=data.get("path", "/"),
                ws_host=data.get("host", ""),
                grpc_service=data.get("path", ""),
            )
        elif link.startswith("ss://"):
            body, _, name = link[5:].partition("#")
            if "@" in body:
                userinfo_b64, host_port = body.rsplit("@", 1)
                userinfo = base64.b64decode(
                    userinfo_b64 + "=" * (-len(userinfo_b64) % 4)
                ).decode()
                method, pwd = userinfo.split(":", 1)
                server, port = host_port.rsplit(":", 1)
                return ProxyNode(
                    name=name or server,
                    type="ss",
                    server=server,
                    port=int(port),
                    cipher=method,
                    password=pwd,
                )
        elif link.startswith("trojan://"):
            m = re.match(
                r"trojan://([^@]+)@([^:/]+):(\d+)(?:\?([^#]*))?(?:#(.*))?$", link
            )
            if m:
                pwd, server, port, params, name = m.groups()
                ps = dict(re.findall(r"([^&=]+)=([^&]*)", params)) if params else {}
                return ProxyNode(
                    name=name or ps.get("sni", server),
                    type="trojan",
                    server=server,
                    port=int(port),
                    password=pwd,
                    sni=ps.get("sni", server),
                    udp=True,
                )
        elif link.startswith("vless://"):
            m = re.match(
                r"vless://([^@]+)@([^:/]+):(\d+)(?:\?([^#]*))?(?:#(.*))?$", link
            )
            if m:
                uuid, server, port, params, name = m.groups()
                ps = dict(re.findall(r"([^&=]+)=([^&]*)", params)) if params else {}
                return ProxyNode(
                    name=name or ps.get("sni", server),
                    type="vless",
                    server=server,
                    port=int(port),
                    uuid=uuid,
                    network=ps.get("type", "tcp"),
                    sni=ps.get("sni", server),
                    udp=True,
                )
    except Exception as e:
        logger.debug(f"解析链接失败: {e}")
    return None


def try_parse_base64(text: str) -> list[ProxyNode]:
    proxies = []
    stripped = text.strip()
    decoded = ""
    if re.match(r"^[A-Za-z0-9+/=\s\r\n]+$", stripped) and len(stripped) > 20:
        decoded = decode_base64_maybe(stripped)
    for line in (decoded or stripped).splitlines():
        p = try_parse_base64_link(line)
        if p:
            proxies.append(p)
    return proxies


# ==================== 格式渲染层 ====================
def render_clash_yaml(proxies: list[ProxyNode]) -> str:
    essential = ["type", "server", "port", "cipher", "password", "uuid",
                 "alterId", "network", "plugin-opts", "sni", "udp"]
    out = [
        "mixed-port: 7890", "allow-lan: true", "mode: Rule",
        "log-level: info", "external-controller: 127.0.0.1:9090", "", "proxies:",
    ]
    names = []
    for p in proxies:
        name = p.name or f"node-{len(names) + 1}"
        names.append(name)
        out.append(f'  - name: "{name}"')
        for k in essential:
            if k in p.raw_clash:
                v = p.raw_clash[k]
                if isinstance(v, str):
                    v = f"\"{v}\""
                elif isinstance(v, bool):
                    v = "true" if v else "false"
                out.append(f"    {k}: {v}")
        out.append("")

    out += [
        "proxy-groups:",
        "  - name: Proxy", "    type: select", "    proxies:", "      - Auto",
    ]
    out.extend([f'      - "{n}"' for n in names[:30]])
    out.extend([
        "  - name: Auto", "    type: url-test", "    proxies:",
    ])
    out.extend([f'      - "{n}"' for n in names[:30]])
    out.extend([
        "    url: http://www.gstatic.com/generate_204", "    interval: 300", "",
        "rules:", "  - MATCH,Proxy",
    ])
    return "\n".join(out)


def _parse_vmess_transport_for_singbox(p: ProxyNode) -> dict:
    net = p.network
    if net == "ws":
        t = {"type": "ws", "path": p.ws_path, "headers": {}}
        if p.ws_host:
            t["headers"]["Host"] = p.ws_host
        return t
    elif net == "grpc":
        return {"type": "grpc", "service_name": p.grpc_service}
    elif net == "h2":
        return {"type": "http", "host": [p.ws_host], "path": p.ws_path}
    return {}


def render_singbox_json(proxies: list[ProxyNode]) -> str:
    outbounds = []
    tag_list = []

    for p in proxies:
        tag = p.name or f"node-{len(tag_list) + 1}"
        ob = {"tag": tag}

        match p.type:
            case "vmess":
                ob["type"] = "vmess"
                ob["server"] = p.server
                ob["server_port"] = p.port
                ob["uuid"] = p.uuid
                ob["alter_id"] = p.alter_id
                ob["security"] = p.cipher
                transport = _parse_vmess_transport_for_singbox(p)
                if transport:
                    ob["transport"] = transport
            case "ss":
                ob["type"] = "shadowsocks"
                ob["server"] = p.server
                ob["server_port"] = p.port
                ob["method"] = p.cipher
                ob["password"] = p.password
            case "trojan":
                ob["type"] = "trojan"
                ob["server"] = p.server
                ob["server_port"] = p.port
                ob["password"] = p.password
                ob["tls"] = {
                    "enabled": True,
                    "server_name": p.sni or p.server,
                    "insecure": False,
                }
            case "vless":
                ob["type"] = "vless"
                ob["server"] = p.server
                ob["server_port"] = p.port
                ob["uuid"] = p.uuid
                ob["tls"] = {
                    "enabled": True,
                    "server_name": p.sni or p.server,
                }
                transport = _parse_vmess_transport_for_singbox(p)
                if transport:
                    ob["transport"] = transport
            case _:
                continue

        tag_list.append(tag)
        outbounds.append(ob)

    # 策略组
    proxy_tags = tag_list[:30]
    outbounds.append({
        "type": "selector", "tag": "Proxy",
        "outbounds": ["Auto"] + proxy_tags,
    })
    outbounds.append({
        "type": "urltest", "tag": "Auto",
        "outbounds": proxy_tags,
        "url": "http://www.gstatic.com/generate_204",
        "interval": "300s", "tolerance": 50,
    })

    # 1.14.0+ 推荐的 http_client 配置，替代废弃的 download_detour
    http_client = {
        "tag": "download",
        "type": "http",
        "outbound": "direct",
    }

    config = {
        "log": {"level": "info"},
        "dns": {
            "servers": [
                {"tag": "local", "address": "local"},
                {"tag": "remote", "address": "tls://8.8.8.8"},
            ],
            "rules": [
                {"outbound": "any", "server": "local"},
                {"clash_mode": "direct", "server": "local"},
                {"clash_mode": "global", "server": "remote"},
                {"rule_set": "geosite-cn", "server": "local", "outbound": "direct"},
                {"rule_set": "geosite-geolocation-!cn", "server": "remote", "outbound": "Proxy"},
            ],
            "final": "remote",
            "strategy": "prefer_ipv4",
        },
        "inbounds": [{
            "type": "mixed", "tag": "mixed-in",
            "listen": "0.0.0.0", "listen_port": 7890,
        }],
        "outbounds": outbounds,
        "route": {
            "rules": [
                {"clash_mode": "direct", "outbound": "direct"},
                {"clash_mode": "global", "outbound": "Proxy"},
                {"rule_set": "geosite-cn", "outbound": "direct"},
                {"rule_set": "geoip-cn", "outbound": "direct"},
                {"rule_set": "geosite-geolocation-!cn", "outbound": "Proxy"},
            ],
            "rule_set": [
                {
                    "tag": "geosite-cn", "type": "remote", "format": "binary",
                    "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs",
                    "http_client": "download",
                },
                {
                    "tag": "geoip-cn", "type": "remote", "format": "binary",
                    "url": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs",
                    "http_client": "download",
                },
                {
                    "tag": "geosite-geolocation-!cn", "type": "remote", "format": "binary",
                    "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-geolocation-!cn.srs",
                    "http_client": "download",
                },
            ],
            "auto_detect_interface": True,
            "final": "Proxy",
        },
        "http_clients": [http_client],
    }
    return json.dumps(config, indent=2, ensure_ascii=False)


# ==================== 去重与主流程 ====================
def dedup(proxies: list[ProxyNode]) -> list[ProxyNode]:
    seen = OrderedDict()
    for p in proxies:
        key = (p.name, p.server, str(p.port))
        if key not in seen:
            seen[key] = p
    return list(seen.values())


def main():
    root = os.path.dirname(os.path.abspath(__file__))
    dist_dir = os.path.join(root, "dist")
    os.makedirs(dist_dir, exist_ok=True)

    # 1. 抓取所有源
    all_proxies = []
    for kind, url in SOURCES:
        try:
            txt = fetch(url)
            if kind == "clash":
                nodes = try_parse_clash(txt)
            elif kind == "singbox":
                nodes = try_parse_singbox_json(txt)
            else:
                nodes = try_parse_base64(txt)
            logger.info(f"{url} => {len(nodes)} nodes")
            all_proxies.extend(nodes)
        except Exception as e:
            logger.error(f"{url} error: {e}")

    # 2. 去重 & 截断
    all_proxies = dedup(all_proxies)
    final_proxies = all_proxies[:MAX_PROXIES]
    count = len(final_proxies)

    # 3. 同时生成两种格式
    clash_yaml = render_clash_yaml(final_proxies)
    singbox_json = render_singbox_json(final_proxies)

    # 4. 写入文件
    clash_path = os.path.join(dist_dir, "clash.yaml")
    singbox_path = os.path.join(dist_dir, "config.json")

    with open(clash_path, "w", encoding="utf-8") as f:
        f.write(clash_yaml)
    with open(singbox_path, "w", encoding="utf-8") as f:
        f.write(singbox_json)

    logger.info(f"Clash:      {clash_path}")
    logger.info(f"Sing-box:   {singbox_path}")
    logger.info(f"total_unique={len(all_proxies)}  using={count}")


if __name__ == "__main__":
    main()
