# Gozargah-Node-Go
<p align="center">
    <a href="#">
        <img src="https://img.shields.io/github/license/m03ed/gozargah-node?style=flat-square" />
    </a>
    <a href="#">
        <img src="https://img.shields.io/github/stars/m03ed/gozargah-node?style=social" />
    </a>
</p>

# Attention ⚠️  
This project is in the testing and development stage. The code may undergo major changes during this phase, so use it at your own risk.  

## Table of Contents

- [Overview](#overview)
  - [Why Use Gozargah Node?](#why-use-gozargah-node)
  - [Supported Cores](#supported-cores)
- [Documentation](#documentation)
  - [Configuration](#configuration)
  - [SSL Configuration](#ssl-configuration)
  - [API](#api)
    - [Data Structure](#data-structure)
    - [Methods](#methods)
- [Official library](#official-library)
  - [Go](#go)
  - [Python](#python)
- [Donation](#donation)
- [Contributors](#contributors)

# Overview

Gozargah Node is developed by the Gozargah team to replace [Marzban-node](https://github.com/Gozargah/Marzban-node). It aims to be more stable, scalable, and efficient.

## Why Use Gozargah Node?

We designed this project to be usable in any project, even without Marzban. You can run nodes with a simple script and the help of official libraries.  
We plan to expand supported cores after the testing stage, allowing you to use any core you want.

## Supported Cores

|                       Core                        | Support |
|:-------------------------------------------------:|---------|
|  [xray-core](https://github.com/XTLS/Xray-core)   | ✅       |
| [sing-box](https://github.com/SagerNet/sing-box)  | ❌       |
| [v2ray-core](https://github.com/v2fly/v2ray-core) | ❌       |

# Documentation

## Configuration

> You can set the settings below using environment variables or by placing them in a `.env` file.

| Variable                | Description                                                                                                                                                              |
|:------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `SERVICE_PORT`          | Bind application to this port (default: `62050`).                                                                                                                        |
| `NODE_HOST`             | Bind application to this host (default: `127.0.0.1`).                                                                                                                    |
| `XRAY_EXECUTABLE_PATH`  | Path of Xray binary (default: `/usr/local/bin/xray`).                                                                                                                    |
| `XRAY_ASSETS_PATH`      | Path of Xray assets (default: `/usr/local/share/xray`).                                                                                                                  |
| `SSL_CERT_FILE`         | SSL certificate file to secure the application between master and node (it will generate a self-signed SSL if it doesn't exist; better to use a real SSL with a domain). |
| `SSL_KEY_FILE`          | SSL key file to secure the application between master and node (it will generate a self-signed SSL if it doesn't exist; better to use a real SSL with a domain).         |
| `SSL_CLIENT_CERT_FILE`  | SSL certificate file to ensure only allowed clients can connect.                                                                                                         |
| `SERVICE_PROTOCOL`      | Protocol to use: `grpc` or `rest` (recommended: `grpc`).                                                                                                                 |
| `MAX_LOG_PER_REQUEST`   | Maximum number of logs per request (only for long polling in REST connections).                                                                                          |
| `DEBUG`                 | Debug mode for development; prints core logs in the node server (default: `False`).                                                                                      |
| `GENERATED_CONFIG_PATH` | Path to the generated config by the node (default: `/var/lib/gozargah-node/generated`).                                                                                  |

## SSL Configuration

### SSL Certificates
You can use SSL certificates issued by `Let's Encrypt` or other certificate authorities.  
Make sure to set both `SSL_CERT_FILE` and `SSL_KEY_FILE` environment variables.

### mTLS
If you don't have access to a real domain or tools like `ACME`, you can use `mTLS` to connect to a node.  
Just replace the `CN` and `subjectAltName` values with your server information:

```shell
openssl req -x509 -newkey rsa:4096 -keyout /var/lib/gozargah-node/certs/ssl_key.pem \
  -out /var/lib/gozargah-node/certs/ssl_cert.pem -days 36500 -nodes \
  -subj "/CN={replace with your server IP or domain}" \
  -addext "subjectAltName = {replace with alternative names you need}"
```

## API

Gozargah Node supports two types of connection protocols: **gRPC** and **REST API**.  
We recommend using **gRPC**, with REST always available as a fallback option (in case there is a problem with gRPC).

### Data Structure

The node uses the `common/service.proto` file messages for both protocols.

| Message                | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
|:-----------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `Empty`                | Used when no input is required. Can replace `null` with `Empty`.                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `BaseInfoResponse`     | Contains:<br/>- `started` (bool): Indicates if the service is started.<br/>- `core_version` (string): Version of the core.<br/>- `node_version` (string): Version of the node.<br/>- `session_id` (string): Session ID.<br/>- `extra` (string): Additional information.                                                                                                                                                                                                                                                 |
| `Vmess`                | Contains:<br/>- `id` (string): UUID for Vmess configuration.                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `Vless`                | Contains:<br/>- `id` (string): UUID for Vless configuration.<br/>- `flow` (string): Currently only supports `xtls-rprx-vision`.                                                                                                                                                                                                                                                                                                                                                                                         |
| `Trojan`               | Contains:<br/>- `password` (string): Password for Trojan configuration.                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `Shadowsocks`          | Contains:<br/>- `password` (string): Password for Shadowsocks.<br/>- `method` (string): Encryption method. Supported methods: `aes-128-gcm`, `aes-256-gcm`, `chacha20-poly1305`, `xchacha20-poly1305`.                                                                                                                                                                                                                                                                                                                  |
| `Proxy`                | Contains:<br/>- `vmess` (Vmess): Vmess configuration.<br/>- `vless` (Vless): Vless configuration.<br/>- `trojan` (Trojan): Trojan configuration.<br/>- `shadowsocks` (Shadowsocks): Shadowsocks configuration.                                                                                                                                                                                                                                                                                                          |
| `User`                 | Contains:<br/>- `email` (string): User's email.<br/>- `proxies` (Proxy): Proxy configurations.<br/>- `inbounds` ([]string): List of inbounds.                                                                                                                                                                                                                                                                                                                                                                           |
| `BackendType`          | Enum:<br/>- `XRAY = 0`: Represents the Xray backend type.                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `Backend`              | Contains:<br/>- `type` (BackendType): Type of backend.<br/>- `config` (string): Configuration for the backend.<br/>- `users` ([]User): List of users.<br/>- `keepAlive` (uint64): hold backend alive for  `x` second after last connection                                                                                                                                                                                                                                                                              |
| `Log`                  | Contains:<br/>- `detail` (string): Log details.                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `Stat`                 | Contains:<br/>- `name` (string): Stat name.<br/>- `type` (string): Stat type.<br/>- `link` (string): Link associated with the stat.<br/>- `value` (int64): Stat value.                                                                                                                                                                                                                                                                                                                                                  |
| `StatResponse`         | Contains:<br/>- `stats` ([]Stat): List of stats.                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `StatRequest`          | Contains:<br/>- `name` (string): Name of the stat to request, user email or inbound \ outbound tag.<br/>- `reset` (bool) Whether to reset traffic stats.                                                                                                                                                                                                                                                                                                                                                                |
| `OnlineStatResponse`   | Contains:<br/>- `name` (string): User's email.<br/>- `value` (int64): Online connection number.                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `OnlineStatResponse`   | Contains:<br/>- `name` (string): User's email.<br/>- `value` (map<string, int64>): Online stat value.                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `BackendStatsResponse` | Contains:<br/>- `num_goroutine` (uint32): Number of goroutines.<br/>- `num_gc` (uint32): Number of garbage collections.<br/>- `alloc` (uint64): Allocated memory.<br/>- `total_alloc` (uint64): Total allocated memory.<br/>- `sys` (uint64): System memory.<br/>- `mallocs` (uint64): Number of mallocs.<br/>- `frees` (uint64): Number of frees.<br/>- `live_objects` (uint64): Number of live objects.<br/>- `pause_total_ns` (uint64): Total pause time in nanoseconds.<br/>- `uptime` (uint32): Uptime in seconds. |
| `SystemStatsResponse`  | Contains:<br/>- `mem_total` (uint64): Total memory.<br/>- `mem_used` (uint64): Used memory.<br/>- `cpu_cores` (uint64): Number of CPU cores.<br/>- `cpu_usage` (double): CPU usage percentage.<br/>- `incoming_bandwidth_speed` (uint64): Incoming bandwidth speed.<br/>- `outgoing_bandwidth_speed` (uint64): Outgoing bandwidth speed.                                                                                                                                                                                |
| `Users`                | Contains:<br/>- `users` ([]User): List of users.                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |

**Note:** The node receives data with `x-protobuf` as the content type in the **REST API**.

### Methods

- Add `address:port` at the beginning of the **REST API** URL.
- Use `Authorization Bearer <session_id>` in the header for authentication with the **REST API**.
- Use `authorization Bearer <session_id>` in metadata for authentication with **gRPC**.

| gRPC                         | REST                          | Input         | Output                                     | Description                                                                                                                                                                |
|:-----------------------------|:------------------------------|---------------|--------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `Start()`                    | `POST`,`/start`               | `Backend`     | `BaseInfoResponse`                         | This is the only method called before creating a connection.                                                                                                               |
| `Stop()`                     | `PUT`,`/stop`                 | `Empty`       | `Empty`                                    | Stops the backend and deactivates the connection with the client.                                                                                                          |
| `GetBaseInfo()`              | `GET`,`/info`                 | `Empty`       | `BaseInfoResponse`                         | Returns base info; can be used to check the connection between the node and client.                                                                                        |
| `GetLogs()`                  | `GET`,`/logs`                 | `Empty`       | gRPC: (stream `Log`)<br/>REST API: (`SSE`) | This method is a `SSE` connection in the REST protocol, but in gRPC, it provides a stream connection.                                                                      |
| `GetSystemStats()`           | `GET`,`/stats/system`         | `Empty`       | `SystemStatsResponse`                      | Retrieves system statistics.                                                                                                                                               |
| `GetBackendStats()`          | `GET`,`/stats/backend`        | `Empty`       | `BackendStatsResponse`                     | Retrieves backend statistics.                                                                                                                                              |
| `GetOutboundsStats()`        | `GET`, `/stats/outbounds`     | `StatRequest` | `StatResponse`                             | Retrieves outbound statistics. The `name` field in the request will be ignored.                                                                                            |
| `GetOutboundStats()`         | `GET`,`/stats/outbound`       | `StatRequest` | `StatResponse`                             | Retrieves statistics for a specific outbound.                                                                                                                              |
| `GetInboundsStats()`         | `GET`,`/stats/inbounds`       | `StatRequest` | `StatResponse`                             | Retrieves inbound statistics. The `name` field in the request will be ignored.                                                                                             |
| `GetInboundStats()`          | `GET`,`/stats/inbound`        | `StatRequest` | `StatResponse`                             | Retrieves statistics for a specific inbound.                                                                                                                               |
| `GetUsersStats()`            | `GET`,`/stats/users`          | `StatRequest` | `StatResponse`                             | Retrieves user statistics and resets traffic stats. The `name` field in the request will be ignored.                                                                       |
| `GetUserStats()`             | `GET`,`/stats/user`           | `StatRequest` | `StatResponse`                             | Retrieves statistics for a specific user.                                                                                                                                  |
| `GetUserOnlineStats()`       | `GET`,`/stats/user/online`    | `StatRequest` | `OnlineStatResponse`                       | Retrieves online statistics for a specific user. The `reset` field in the request will be ignored                                                                          |
| `GetUserOnlineIpListStats()` | `GET`,`/stats/user/online_ip` | `StatRequest` | `StatsOnlineIpListResponse`                | Retrieves ip list statistics for a specific user. The `reset` field in the request will be ignored                                                                         |
| `SyncUser()`                 | `PUT`,`/user/sync`            | `User`        | `Empty`                                    | Adds/updates/removes a user in the core. To remove a user, ensure you send empty inbounds. Provides a stream in `gRPC` but must be called for each user in the `REST API`. |
| `SyncUsers()`                | `PUT`,`/users/sync`           | `Users`       | `Empty`                                    | Removes all old users and replaces them with the provided users.                                                                                                           |

# Official library
We create some library's for you so make your job easier

## Go
[gozargah-node-bridge](https://github.com/m03ed/gozargah_node_bridge)

To add bridge to your project use:
```shell
go get github.com/m03ed/gozargah_node_bridge
```
## Python
[gozargah-node-bridge-py](https://github.com/m03ed/gozargah_node_bridge_py)
```shell
pip install gozargah-node-bridge
```

# Donation
You can help gozargah team with your donations, [Click Here](https://donate.gozargah.pro)

# Contributors

We ❤️‍🔥 contributors! If you'd like to contribute, please check out our [Contributing Guidelines](CONTRIBUTING.md) and feel free to submit a pull request or open an issue. We also welcome you to join our [Telegram](https://t.me/gozargah_marzban) group for either support or contributing guidance.

Check [open issues](https://github.com/m03ed/gozargah-node/issues) to help the progress of this project.

<p align="center">
Thanks to the all contributors who have helped improve Gozargah Node:
</p>
<p align="center">
<a href="https://github.com/m03ed/gozargah-node/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=m03ed/gozargah-node" />
</a>
</p>
<p align="center">
  Made with <a rel="noopener noreferrer" target="_blank" href="https://contrib.rocks">contrib.rocks</a>
</p>