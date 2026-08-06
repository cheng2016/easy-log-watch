# Easy Log Watch

本地一键解密、预览、搜索 Mars / 微信风格 **`.xlog`** 日志。

**Windows / macOS / Linux** 都能用。不用敲一长串命令、不用每次找官方脚本、不用把几十 MB 明文硬塞进记事本——启动后在浏览器里完成从解密到排障的全过程。数据只留在你本机。

<p align="center">
  <img width="900" alt="Easy Log Watch screenshot" src="https://github.com/user-attachments/assets/6e1153a1-73c5-4d21-a568-7fe4315cf838" />
</p>

---

## 适合谁？

- 客户端 / 测试同学：手里经常有一堆 `.xlog`、zip、按天分的日志目录  
- 需要对照 **未加密 / 加密** 不同解密脚本的人  
- 嫌「解完再用记事本搜」又慢又卡的人  

三步上手：启动 → 拖文件 → 搜关键词。

---

## 为什么值得用？

| 以前 | 现在 |
|------|------|
| 找脚本、装依赖、改路径、一条条跑 | 拖进页面，点「开始解密」 |
| 加密 / 未加密脚本容易用错 | 下拉切换 `scripts/` 里的解密脚本 |
| 明文太大，编辑器卡死 | 开头 / 末尾分段预览，滚动按需加载 |
| `Ctrl+F` 不好使 | 包含 / 任一 / 全部 / 正则，还可按 E/W/I 级别筛 |
| 历史对不上号 | 自动留档，可改标题、写备注 |
| 已有 `.log` 还要再解一遍 | 右侧预览区直接拖入文本 / 粘贴即可搜 |

---

## 功能亮点

**解密**

- 支持 `.xlog`、`.zip`（自动抽出 xlog）、整文件夹上传  
- 可插拔解密脚本（默认 Mars 未加密；加密脚本自己放进 `scripts/`）  
- 实时进度；多文件可打包下载  

**预览与搜索**

- 大文件分段浏览，点击搜索结果可跳转上下文  
- 关键词：`a|b` 任一、`a&b` 全部、正则；级别过滤  
- 已解密的 `.log` / `.txt` 可直接拖到右侧预览区  

**历史**

- 按日期分组；重命名 / 备注；一键删除本地缓存  

---

## 快速开始

### 环境

- **Python 3**（建议 3.10+）
- Windows / macOS / Linux

### Windows

双击项目根目录的 **`start.bat`**。

### macOS / Linux

```bash
chmod +x start.sh   # 只需第一次
./start.sh
```

脚本会自动检查依赖、后台启动服务，并打开浏览器：  
[http://127.0.0.1:5000/](http://127.0.0.1:5000/)

已经在跑时再执行一次，只会打开浏览器，不会起第二个服务。

### 手动启动（可选）

```bash
python3 -m pip install -r requirements.txt
python3 app.py
# 浏览器打开 http://127.0.0.1:5000/
```

### 第一次解密

1. 把 `.xlog` / `.zip` 拖进上传区，或点选文件 / **选文件夹**  
2. 「解密脚本」一般保持默认（未加密 xlog）  
3. 点 **开始解密**  
4. 左侧历史 → 点 **解密文件** → 预览或搜索  

---

## 更换解密脚本

所有解密脚本统一放在：

```text
scripts/
```

1. 把 `.py`（例如官方 `decode_mars_crypt_log_file.py`）放进 `scripts/`  
2. 加密脚本按说明改好 **`PRIV_KEY`**  
3. **刷新页面**，在「解密脚本」下拉里选择  

调用方式（兼容官方 Mars 风格）：

```text
python <脚本.py> <某个.xlog>
# 成功后写出: <某个.xlog>.log
```

脚本开头可加一行说明，界面会显示：

```python
# DESCRIPTION: Mars 加密 xlog：ECDH + TEA（PRIV_KEY 写在脚本内）
```

| 默认脚本 | 用途 |
|----------|------|
| `decode_mars_nocrypt_log_file.py` | Mars **未加密** xlog（zlib / zstd） |

---

## 搜索小技巧

| 写法 | 含义 |
|------|------|
| `timeout` | 包含（不区分大小写） |
| `timeout\|crash` 或 `timeout OR crash` | 命中任一 |
| `login&fail` 或 `login AND fail` | 必须同时包含 |
| 打开「正则」 | 正则匹配 |
| 点级别 E / W / I… | 只看对应级别 |

---

## 目录结构

```text
easy-log-watch/
├── README.md
├── start.bat                 # Windows 一键启动
├── start.sh                  # macOS / Linux 一键启动
├── app.py
├── script_runner.py
├── wait_ready.py
├── requirements.txt
├── scripts/                  # 只放解密用 .py
│   └── decode_mars_nocrypt_log_file.py
├── templates/
│   └── index.html
├── .uploads/                 # 运行时数据（可删）
└── .runtime/                 # 启动缓存 / 日志（可删）
```

`.uploads/`、`.runtime/` 关掉服务后可随时整夹删除，下次启动会自动重建。

---

## 依赖

见 `requirements.txt`：

- Flask — Web 界面  
- Waitress — 本地服务（Win / Mac / Linux）  
- zstandard — xlog 压缩格式  

`start.bat` / `start.sh` 会在缺依赖时自动安装。

---

## 常见问题

**Q：Mac 提示 `permission denied: ./start.sh`？**  
执行：`chmod +x start.sh`

**Q：提示找不到 `python3`？**  
安装 Python 3，或用 Homebrew：`brew install python`

**Q：页面打不开？**  
再跑一次启动脚本。Mac/Linux 可看 `.runtime/server.log`；Windows 看最小化的 `easy-log-watch` 窗口。

**Q：解密失败 / 没有明文？**  
脚本和日志类型不匹配（例如用未加密脚本解加密日志）。换对脚本后再试。

**Q：换了脚本下拉里没有？**  
确认文件在 `scripts/` 且后缀是 `.py`，然后刷新页面。

**Q：能部署到服务器给同事共用吗？**  
当前按本机工具设计。若要多人共用，请自行评估安全与隔离。

---

## 许可与致谢

解密逻辑兼容 [Tencent Mars](https://github.com/Tencent/mars) 官方 xlog 脚本风格。本仓库提供本地辅助界面，方便日常排障。

——

**Windows 双击 `start.bat`，Mac 执行 `./start.sh`，把下一份 `.xlog` 拖进去试试。**
