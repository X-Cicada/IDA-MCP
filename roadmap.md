# IDA-MCP Roadmap

## 当前状态

项目已经完成从“单实例 + 零散工具”向“多实例网关 + HTTP-first proxy + 结构化工具集”的收敛：

- `open_in_ida` 已支持显式 `autonomous`、staging、数据库优先打开、`wsl_path_bridge`
- gateway / proxy / direct instance 三个入口已经稳定分层
- 核心分析、建模、类型、调试、资源接口基本齐全
- `install.py`、`README`、`API.md`、生命周期测试已与当前实现基本对齐

下面的 roadmap 关注的是“进一步降低维护成本”和“把运行体验做稳定”。

## 近期目标（P0）

### 1. 稳定 `open_in_ida` 启动体验

目标：减少 loader / 架构确认框、减少环境差异导致的打开失败。

工作项：

- 继续验证 `autonomous=true/false` 在不同 IDA 版本下的行为差异
- 把 staging / companion database / WSL bridge 的异常信息再做细化
- 补齐 Windows 宿主机 + WSL 控制端的端到端回归测试
- 明确哪些场景必须依赖 `open_in_ida_bundle_dir`

完成标准：

- 常见 Windows / WSL 路径场景可预测
- `open_in_ida` 失败时能直接从返回信息定位配置问题

### 2. 清理遗留工具与兼容残留

目标：彻底移除旧工具命名和过时接口认知。

工作项：

- 确认 `get_function`、`get_pseudocode_function`、`get_pseudocode_lines` 等旧名只保留在“已移除”测试断言里
- 检查 README / API / wiki 是否还残留旧接口描述
- 明确后续新增功能只围绕 `decompile`、`disasm`、`get_function_signature` 等现有主接口扩展

## 中期目标（P1）

### 3. 继续降低对 `py_eval` 的依赖

目标：把高频分析/修改场景从“任意 Python”收敛到结构化 MCP 工具。

优先补齐方向：

- 更完整的局部变量、类型恢复、结构体字段操作
- 更细粒度的函数属性、段属性、xref 摘要接口
- 更稳定的批量修改接口，减少 AI 直接拼 IDAPython

完成标准：

- 日常逆向流程主要靠结构化工具完成
- `py_eval` 更多用于调试、实验和尚未产品化的能力

### 4. 强化网关/代理可观测性

目标：让多实例、转发、启动失败问题更容易排查。

工作项：

- 统一 internal API / proxy / instance 的错误格式
- 补充网关日志、实例选择、端口占用、注册失败的诊断信息
- 为 `command.py` 增加更清晰的状态输出和错误提示

## 长期目标（P2）

### 5. 做成更稳定的“可安装产品”

目标：降低新环境落地成本。

工作项：

- 继续完善 `install.py` 的交互提示、路径校验、WSL 场景校验
- 补齐面向新用户的配置模板与最小工作流
- 评估将测试、安装、发布说明进一步标准化

### 6. 提升资源接口与自动化协作能力

目标：让 LLM 更偏向用 resource/tool 合同，而不是依赖上下文猜测。

工作项：

- 扩展 `ida://` 资源覆盖范围
- 提升 tools / resources 文档一致性
- 为高频分析路径提供更适合 agent 消费的返回结构

## 不再继续的方向

- 不恢复 `get_function` / `get_pseudocode_function` 这类旧工具名
- 不鼓励以 `py_eval` 作为主工作流
- 不把 proxy 和 direct instance 的参数语义再次做分叉
