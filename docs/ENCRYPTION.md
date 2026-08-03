# docs/ENCRYPTION.md

Link 加密实现说明
=================

此分支 (加密实现) 新增了一个独立的安全 Link 实现文件 link_secure.py，目标：

- 优先使用 AEAD（AES-256-GCM）和 PBKDF2 派生密钥，保证机密性与完整性。
- 兼容旧格式（XOR keystream + HMAC）；新代码可以读取旧文件。
- 写入时默认使用新安全格式。若运行环境没有安装任何 AEAD 后端（cryptography 或 pycryptodome），
  会根据 allow_fallback 策略选择是否退回到旧不安全写入（默认允许回退以便在受限环境运行）。

新增文件
- link_secure.py: 实现 AES-GCM + PBKDF2（优先 cryptography，然后 pycryptodome），并回退到旧实现。
- tests/test_link_secure.py: 基本单元测试（使用 pytest）。

依赖与安装（手机）
- 建议先在手机环境尝试安装 cryptography：
  pip install cryptography

- 如果 cryptography 安装失败，尝试 PyCryptodome：
  pip install pycryptodome

- 如果两者都不支持，代码会在没有 AEAD 的情况下回退到旧写入（不安全）。

使用与测试
1. 备份（强烈建议）：先备份你的 link_store 目录：
   cp -r link_store link_store.bak

2. 在该分支上运行测试（需有 pytest）：
   pip install pytest
   pytest -q

3. 快速交互式测试（示例）：

```python
from link_secure import Link
L = Link(store_dir='./link_store_test')
pid = L.write({'agent':'demo','step':0}, 'pwd')
print('wrote', pid)
print('read', L.read(pid, 'pwd'))
```

迁移策略
- Dual-read only（默认/安全）：新代码可读取旧/新格式，但不会修改旧文件。适用于你不想写磁盘或保留旧数据的场景。
- On-read lazy migration：read(..., migrate_on_read=True) 成功读取旧格式后会尝试写入新格式（生成新 id），旧文件保留为备份。需要原始密码解密旧文件。
- Batch migration：在能获取所有密码/密钥的前提下运行管理员脚本遍历 link_store、解密并用新格式写回（建议先做 dry-run 并备份）。

回滚与恢复
- 任何迁移或写操作前先备份 link_store（link_store.bak）。若出问题，可用备份文件夹覆盖回去。

安全警告
- 旧的 XOR+HMAC 实现不保证机密性；仅在无法安装 AEAD 库的受限环境下作为回退使用。
- 推荐尽快在能安装 cryptography 或 pycryptodome 的环境中启用 AEAD。