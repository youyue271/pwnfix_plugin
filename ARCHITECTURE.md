# IDA PWN 漏洞检测插件架构说明

## 1. 当前目标（已完成）

第一阶段目标是把“自动检测”做成可维护、可扩展、可追踪的架构，而不是继续在旧逻辑上叠补丁。

当前已完成：

1. 统一漏洞结果模型（`Vulnerability` + `FixAction`）。
2. 统一检测调度引擎（`PwnDetectionEngine`）。
3. 检测器基类（`BaseDetector`）与规则化上报接口（`report()`）。
4. 栈类与堆类检测器迁移到新框架。
5. UI 列表、注释与高亮统一展示（规则 ID、严重性、置信度、建议修复）。
6. 第二阶段“一键修补”已接入最小可用能力（当前仅自动处理 Double Free 的第二次 `free` 调用点）。

## 2. 运行流程

`main.py` 插件入口：

1. 初始化 Hex-Rays 环境。
2. 运行前清理旧高亮。
3. 调用 `PwnDetectionEngine.analyze_program()`。
4. 汇总所有检测结果并去重。
5. 在 IDA 界面中高亮/注释并弹出漏洞列表。

`core/engine.py` 调度逻辑：

1. 遍历所有函数（跳过 `FUNC_LIB` 与 `FUNC_THUNK`）。
2. 反编译为 `cfunc`。
3. 构建 `FunctionContext`（变量赋值索引、调用索引）。
4. 逐个 detector 执行 `analyze()` 并聚合结果。
5. 用 `dedupe_key` 去重，按地址和规则排序输出。

## 3. 检测模型设计

`core/models.py`：

- `Vulnerability`：规则 ID、类别、严重性、置信度、EA、函数信息、证据、建议修复、可执行修复动作。
- `FixAction`：后续自动修补要执行的动作描述与 `patchable` 标记。

`detectors/base.py`：

- 所有规则 detector 统一继承此类。
- 用 `report()` 创建标准化漏洞对象。
- 同一 detector 内自动去重，降低重复告警噪音。

## 4. 已实现规则

### 4.1 栈溢出类（`detectors/stack_overflow.py`）

- 无界写入：`gets/strcpy/strcat/sprintf/vsprintf` 写入栈对象。
- 有界但可解析超界：`read/recv/fgets/memcpy/memmove/strncpy`，当解析出的长度大于栈变量宽度时报高危。
- `scanf/isoc99_scanf`：检测 `%s` 或 scanset 未加宽度的栈写入。

### 4.2 堆利用类（`detectors/heap_vuln.py`）

- 规则已升级为“槽位状态跟踪”模型（函数内）：
  - 提取候选指针槽位（包括 `ptr_slot[idx]`）
  - 跟踪状态：`UNKNOWN / FREED / NULL`
  - 支持 free-like 包装函数识别（内部调用 `free/munmap` 的子函数）
- `HEAP.DOUBLE_FREE`：同一槽位二次 `free` 且中间无重绑定。
- `HEAP.UAF.CALL`：free 后作为参数传入读写 sink。
- `HEAP.UAF.DEREF`：free 后发生解引用访问。
- `HEAP.FREE.NOT_CLEARED`：free/delete 后槽位未置空（典型“只清 size 不清 ptr”）。

## 5. UI 展示

`utils/ui_helper.py`：

1. 漏洞表格包含：
   - Address / Function / Rule / Severity / Confidence / Description / Suggested Fix
2. 根据严重性着色。
3. 在 EA 上写注释：规则 + 简述 + 第一条修复建议。
4. 双击条目跳转到对应地址。

## 6. 第二阶段（一键修补）现状

`core/fixer.py` 当前能力：

- `collect_candidates(findings)`：从 `fix_actions` 收集可修补候选。
- `apply_all(findings)`：执行可自动修补动作并返回结果统计（applied/skipped/failed）。
- 已实现动作：`disable_second_free_call`
  - 场景：`HEAP.DOUBLE_FREE`
  - 操作：将第二次 `free` 的 call 指令 patch 为 NOP。

`main.py` 接入方式：

1. 首次扫描后收集 `patchable=True` 的修补候选。
2. 弹出确认框询问是否应用自动修补。
3. 应用成功后等待 IDA 分析完成并自动重新扫描。
4. 最终展示“修补后的最新告警”。

后续建议（下一步增强）：

1. 在 UI 中增加“仅修补选中项”而不是全量修补。
2. 引入 patch 预览与回滚（当前仅记录 patch 地址与原字节，未开放 UI 回滚）。
3. 为 `gets/strcpy/strcat/sprintf` 增加可执行的替代修补策略（例如跳转到安全包装函数）。
