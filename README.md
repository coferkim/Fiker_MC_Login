# Fiker MC Login

基于 **FastAPI** 的 Minecraft 中国版登录认证与好友查询服务。

## 功能

- 登录认证与会话保存。
- 获取好友列表及好友详情。
- 通过名字、邮箱或玩家编号搜索玩家。
- PE 认证数据加解密、签名及 `user-token` 生成。

## 使用

请使用抓包软件抓取自己账号的《我的世界》登录请求中的 `sauth`，将其作为 `sauth_json` 字符串提交到登录接口 `POST /login-mc`。登录成功后，即可使用其他接口。

## 接口一览

| 方法 | 路径 | 参数 | 功能 |
| --- | --- | --- | --- |
| `GET` | `/` | 无 | 检查服务运行状态 |
| `POST` | `/login-mc` | `sauth_json`：JSON 字符串 | 登录并保存会话 |
| `GET` | `/friends/all-friends` | 无 | 获取好友列表 |
| `GET` | `/friends/all-friends-detail` | 无 | 获取好友详情 |
| `GET` | `/friends/search-by-name` | `name`：字符串 | 按名字或邮箱搜索玩家 |
| `GET` | `/friends/search-by-id` | `user_id`：整数 | 按玩家编号搜索玩家 |

## 项目结构

```text
Fiker_MC_Login-main/
├── main.py                   # FastAPI 入口与路由注册
├── config.yaml               # 用户编号与登录 token
├── config.bak.yaml           # 配置模板
├── api/
│   ├── login.py              # 登录接口
│   └── friends.py            # 好友查询与玩家搜索接口
└── utils/
    ├── auth_tools.py         # 认证工具封装
    ├── client_sender.py      # 业务请求签名与发送
    ├── config_manager.py     # 配置读写
    ├── mc_auth_toolkit.py    # 认证编解码与签名工具
    └── pe_auth.py            # 登录认证流程
```

## 许可证

仓库当前未提供 `LICENSE` 文件。
