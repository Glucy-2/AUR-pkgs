# AUR-pkgs

Glucy2 的 AUR 软件包仓库，带有自动检测上游更新、隔离构建和发布到 AUR 的流水线。

## 目录结构

```
.
├── packages/                 # 所有包，一包一个目录（PKGBUILD、.SRCINFO、辅助文件）
│   ├── wakatime/
│   ├── neo4j-community-bin/
│   └── ...
├── scripts/                  # 自动化逻辑（Python / Bash），工作流只负责调用它们
│   ├── aur_update.py         # 命令行入口、GitHub Release 检测、AUR 基线初始化
│   ├── aur_check.py          # 候选版本、隔离构建、nali-nt-git 重试逻辑
│   ├── aur_publish.py        # 校验结果、防冲突发布到 AUR、回写 GitHub
│   ├── detect_intel.py       # intel-mlc 专用检测
│   ├── detect_neo4j.py       # neo4j-community-bin 专用检测
│   ├── arch-package.sh       # 在 Arch 容器内运行：校验源与摘要、makepkg 构建
│   ├── arch_verify.py        # 容器内的摘要、元数据和产物审计
│   └── tests/                # 单元测试
├── .automation/
│   ├── packages.json         # 包注册表：是否启用、检测方式、发布白名单
│   └── aur-state.json        # 每个包上次发布时对应的 AUR master 提交
└── .github/workflows/update.yaml   # 定时/手动触发，只调度上述脚本
```

## 包列表

### 自动维护（13 个）

| 包 | 检测方式 | 说明 |
|---|---|---|
| ddns-go-bin、ecapture-bin、ifrextractor-rs、ifrextractor-rs-bin、nali-nt、nali-nt-bin、opencl-vanity-gpg、opencl-vanity-gpg-bin、wakatime | `github-release` | 取最新的正式、非预发布、`vX.Y.Z` 形式的 Release，按 Arch `vercmp` 比较 |
| intel-mlc | `intel-mlc` | 读取 Intel 官方下载页的镜像地址与 SHA256 |
| neo4j-community-bin | `neo4j-community` | 读取 Neo4j 部署中心的 Community 版本，并从 `.deb` 解析 Java 最低版本 |
| nali-nt-git、mcping-git | `vcs-build-first` | 见下文 |

### 草稿（不检测、不构建、不发布）

`honk-core`、`fastflowlm`、`fastflowlm-git`、`sherpa-onnx-bin`、`yukigram-desktop`

草稿在注册表里 `enabled` 为 `false`。需要启用时，在 `.automation/packages.json` 里给它指定检测方式，并补全 `.SRCINFO`。

## 工作流程

1. **检测**：`aur_update.py` 按注册表的 `detector` 查询上游，得到候选版本。
2. **准备**：只替换配方中顶层的 `pkgver`、`pkgrel` 等指定字段，再用 `updpkgsums` 重新生成校验和，用 `makepkg --printsrcinfo` 生成 `.SRCINFO`，不手写。
3. **隔离构建**：在一次性的 `archlinux:base-devel` 容器里，以非 root 用户运行 `makepkg`。容器不挂载 Docker socket、SSH 目录，也不带任何令牌。
   - 实际构建 x86_64（`any` 包也在此构建）。
   - 其余声明的架构只验证源文件与校验和，不做原生构建。
4. **产物检查**：确认包名、版本、架构和关键可执行文件（如 `/usr/bin/neo4j`）都存在。
5. **发布**：`aur_publish.py` 只复制白名单内的文件，在已有的 AUR 提交历史之上提交，从不强推。
   - AUR 的 master 在检查之后被他人改过且内容不同，则报告冲突，不覆盖。
   - 内容已一致则视为已发布，只恢复状态记录。
6. **回写**：把 `aur-state.json` 和已发布的配方提交回 GitHub，提交信息带 `[skip ci]`，避免循环触发。

### VCS 包（nali-nt-git、mcping-git）

不会为了追上游最新提交而发布新版本：

- 每次先原样构建现有配方。成功就保持 `unchanged`，构建过程自动产生的 `pkgver` 变化被丢弃。
- 只有实际编译失败时，才重新获取上游默认分支 HEAD，固定到该提交后再完整构建一次，成功才保留新版本。
- 两次都失败则报告失败，不发布。改 `pkgver` 本身不能修复编译错误。

## 在 GitHub Actions 中运行

- 每天 UTC 04:17 定时运行；也可手动触发（`workflow_dispatch`），参数：
  - `package`：包名，或 `all`
  - `dry_run`：默认 `true`，只检查和显示差异，不写任何远端
- 推送到 `main` 且修改了包、脚本或注册表时也会运行；Pull Request 只做检查，拿不到密钥。
- 流程：`matrix`（生成包列表）→ `unit-tests` → `check`（每包一个并行任务，上传结果）→ `publish`（用下载的结果发布）。
- 发布步骤只运行 `aur_update.py publish`，不会执行任何包内脚本。

### 凭据

GitHub 和 AUR 使用同一把专用的 Ed25519 密钥：

- 私钥只存在于仓库 secret `AUR_GITHUB_SSH_KEY`，只在 `publish` 步骤里写入临时的 `0600` 文件。
- 公钥同时登记为本仓库的可写 Deploy key，以及 AUR 账号的 SSH 公钥。
- 撤销时需要三处都清理：仓库 Deploy key、AUR 账号公钥、仓库 secret。
- Deploy key 不能创建或更新 `.github/workflows/` 下的文件，修改工作流需要另用带 `workflow` 权限的凭据。

## 本地使用

需要 Python 3、Docker（或兼容的 Podman）和 `archlinux:base-devel` 镜像。

```sh
# 列出启用的包
python3 scripts/aur_update.py matrix

# 只读检测上游版本
python3 scripts/aur_update.py inspect --package wakatime

# 完整检查：检测、校验和、构建（目录必须是新建的空目录）
python3 scripts/aur_update.py check --package wakatime \
    --work-dir "$(mktemp -d)/work" --result-dir "$(mktemp -d)/results"

# 试运行发布：只显示差异，不改动任何远端
python3 scripts/aur_update.py publish --package wakatime --results-dir <结果目录> --dry-run

# 单元测试
python3 -m unittest discover -s scripts/tests -v
```

## 添加新包

1. 把配方放进 `packages/<包名>/`（至少有 `PKGBUILD` 和 `.SRCINFO`）。
2. 在 `.automation/packages.json` 增加一项：`pkgbase`、`enabled`、`detector`、`upstream`，以及要发布到 AUR 的 `files` 白名单（辅助文件如 `.install` 要列进去）。
3. 在 `.gitignore` 里为该目录放行这些文件。
4. 在 `scripts/aur_check.py` 的 `ENTRIES` 和 `scripts/arch-package.sh` 里登记要检查的可执行文件；如果是 VCS 包，还要加入 `scripts/arch_verify.py` 的 `VCS_PACKAGES`。
5. 运行 `python3 scripts/aur_update.py bootstrap-state` 记录它的 AUR master 基线，再跑一次 `check` 确认通过。

新包必须已经存在于 AUR；自动模式不会创建新的 pkgbase。
