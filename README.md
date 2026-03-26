# IDA PWN Vulnerability Detector

一个面向 CTF/PWN 场景的 IDA Pro 插件，用于自动检测常见漏洞（当前以栈溢出、堆误用为主），并提供有限的一键修补能力。

## 当前状态

当前代码已完成从“脚本堆叠”到“规则引擎化”的重构，核心框架可稳定运行，能在 IDA 中输出统一格式的漏洞结果并高亮定位。

已实现能力：

- 统一检测模型：`Vulnerability` / `FixAction`
- 统一调度引擎：`PwnDetectionEngine`
- 可扩展检测器体系：`BaseDetector` + detector 插件化注册
- UI 统一展示：漏洞列表、注释、着色、双击跳转
- 自动修补（最小可用）：支持对 `HEAP.DOUBLE_FREE` 的第二次 `free` 调用点打 NOP

## 规则覆盖（当前）

### 1) Stack Overflow

- 无界写入：`gets/strcpy/strcat/sprintf/vsprintf` 对栈变量写入
- 可解析长度超界：`read/recv/fgets/memcpy/memmove/strncpy`（当 size 常量可解且超出栈变量宽度）
- `scanf` 字符串输入缺少宽度限制（`%s` 或 scanset）

### 2) Heap Misuse

- `HEAP.DOUBLE_FREE`：同一槽位/绑定在未重绑定前重复 free（支持 free-like 包装函数识别）
- `HEAP.UAF.CALL`：free 后作为参数传给读写 sink（如 `puts/read/write/memcpy` 等）
- `HEAP.UAF.DEREF`：free 后继续解引用
- `HEAP.FREE.NOT_CLEARED`：delete/free 后检测到指针槽位未清空（例如只清 size 不清 ptr）
- `HEAP.FLAG_OFFSET_MISMATCH`：free 后状态清理写入了错误字段偏移（如写到 `+0x200` 但状态位在 `+0x208`）
- `HEAP.ALLOC.UNINITIALIZED_CONTAINER`：控制容器由 `malloc` 建立后未初始化就进入全局状态路径
- `HEAP.CSTR.UNBOUNDED_PRINTF`：`printf("%s", ptr)` 这类无长度上限字符串输出，参数来自堆路径时可导致越界读/信息泄露

堆规则已升级为“槽位状态跟踪”：

- 自动提取候选指针槽位（含 `ptr_slot[idx]`）
- 跟踪状态：`UNKNOWN / FREED / NULL`
- 轻量传播：当已释放槽位赋值到新指针变量时，保留 freed 状态
- 包含一层“局部变量 -> 全局槽位”别名收束，降低路径噪音

## 一键修补（当前）

当前仅实现一个保守动作：

- `disable_second_free_call`
  - 对 `HEAP.DOUBLE_FREE` 的第二次 `free` call 指令 patch 为 NOP
  - 插件会先询问确认，再执行 patch，然后自动触发重新扫描

> 说明：其他规则目前只给“修复建议”，尚未自动改写指令。

## 已知限制

- 当前状态跟踪以“单函数内”为主，跨函数别名传播还不完整。
- 暂不支持完善的跨函数/跨容器别名追踪（例如复杂全局数组槽位、结构体间接传递）。
- 自动修补能力刻意收敛，避免高误改；目前没有 UI 级回滚面板。
- 某些动态索引槽位（`[*]` / `[dyn]`）仍可能带来保守告警，建议结合上下文人工确认。

## 下一步（计划）

按你的目标推进以下能力（优先级从高到低）：

1. 识别堆指针容器（`ptr_slot[idx]`）与配套 size/state 容器
2. 扩展跨函数状态机（当前主要是函数内），减少包装函数场景漏报
3. 在槽位级完善轻量污点传播（仅跟踪堆指针流，不做全程序重污点）
4. 输出更完整的“证据链”报告（分配点/释放点/使用点/可利用路径）

## 项目结构

```text
ida_pwn_vuln_detector/
├── main.py                 # IDA 插件入口
├── core/
│   ├── engine.py           # 检测调度
│   ├── context.py          # 函数分析上下文
│   ├── models.py           # 漏洞/修补数据模型
│   └── fixer.py            # 一键修补引擎
├── detectors/
│   ├── stack_overflow.py   # 栈溢出规则
│   └── heap_vuln.py        # 堆误用规则
├── utils/
│   ├── hexrays_helper.py   # Hex-Rays 辅助函数
│   ├── ui_helper.py        # UI 展示与高亮
│   └── logger.py           # 日志
└── ARCHITECTURE.md         # 架构说明
```

## 使用方式（IDA）

1. 确保 IDA Pro + Hex-Rays 可用。
2. 将项目目录放到 IDA 可加载的 Python 路径，或将 `main.py` 作为插件入口放入 IDA 插件目录。
3. 在 IDA 中运行插件（默认热键：`Ctrl-Alt-P`）。
4. 查看漏洞列表与注释高亮，按需执行自动修补。

## 备注

如果你要把这个项目用于真实二进制而不是 CTF 样本，建议先把“槽位级堆污点状态机”做完，再扩展自动修补策略。
