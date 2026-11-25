# Linus SSH SafeSwitch v1.0

面向 Linux VPS 的极简安全换端口工具：通过**双端口验证 + 断电自动回滚 + 防火墙/Fail2ban 自动联防**，确保远程修改 SSH 端口零失联、不污染原配置。

## 核心特性

* **双端口平滑过渡**：新旧端口同时监听，另开终端实测登录成功并输入 `YES` 后才关闭旧端口。
* **10 分钟 / 断电自动回滚**：内置防竞态互斥锁与自包含看门狗，断网、误中断或服务器意外重启均自动还原配置与防火墙。
* **全架构与防火墙适配**：原生兼容 `sshd_config.d` 与 Ubuntu `ssh.socket` 双层架构，自动联动 SELinux / UFW / firewalld / nftables / iptables（IPv4+IPv6）。
* **Fail2ban 动态联防**：换端后自动生成适配本机端口与防火墙的一键防爆破命令（缺包时自动补装依赖，避免“能看日志、不能拉黑”的空壳失效）。

## 快速使用

需以 `root` 身份运行，一键下载并启动换端（首次运行会自动安装至 `/root/linus-ssh-safeswitch.sh`）：

```bash
curl -fsSL [https://raw.githubusercontent.com/Ravexium/linus-ssh-safeswitch/main/linus-ssh-safeswitch-v1.0.sh](https://raw.githubusercontent.com/Ravexium/linus-ssh-safeswitch/main/linus-ssh-safeswitch-v1.0.sh) -o /tmp/linus-ssh-safeswitch-v1.0.sh && bash /tmp/linus-ssh-safeswitch-v1.0.sh
```

常用命令：
* 日常交互切换：`bash /root/linus-ssh-safeswitch.sh`
* 快捷传参切换：`bash /root/linus-ssh-safeswitch.sh <新端口号>`
* 强制覆盖更新：`bash /tmp/linus-ssh-safeswitch-v1.0.sh --install`
* 仅生成 Fail2ban 命令（不换端口）：`bash -c 'source <(head -n -1 /root/linus-ssh-safeswitch.sh); print_fail2ban_hint'`

## 注意事项

* **放行云安全组**：双端口就绪后，务必先到云厂商网页控制台放行新端口 TCP 入站，再另开窗口测试登录（切勿关闭当前原窗口）。
* **单端口前提**：仅接管单一 SSH 监听端口环境；若系统存在多端口定义，脚本会主动阻断并提示先清理冲突。
* **Fail2ban 粘贴执行**：引导块外层带有 `{ ... }` 保护，整段粘贴后若光标停在末尾 `}` 处，直接按一下 **Enter** 即可运行。

## 核验与删除

**1. 只读核验（执行前请将 `<新端口>` 替换为你的实际端口号）：**
```bash
ss -tlnp | grep -E ':(22|<新端口>)\b'; ufw status 2>/dev/null || true
```

**2. 安全测试 Fail2ban 联动（使用 RFC 5737 专用保留 IP，零断连风险）：**
```bash
fail2ban-client set sshd banip 192.0.2.123 && ufw status && fail2ban-client set sshd unbanip 192.0.2.123 && ufw status
```

**3. 彻底删除脚本与日志：**
脚本无常驻后台进程，删除后**完全不影响**已生效的新 SSH 端口、防火墙规则及 Fail2ban 防护（如需改回 22 端口，请先执行 `bash /root/linus-ssh-safeswitch.sh 22` 再删除）：
```bash
rm -rf /root/linus-ssh-safeswitch.sh /root/.linus-ssh-safeswitch /var/log/linus-ssh-safeswitch.log /run/linus-ssh-safeswitch*.lock /tmp/linus-ssh-safeswitch*.sh
```
