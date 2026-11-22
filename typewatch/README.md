# TypeWatch — PHP 类型比较安全检测工具

静态污点分析 + 版本规则引擎 + 动态 PoC 验证，专门检测 PHP 松散类型比较导致的
安全判断绕过（登录绕过、签名校验绕过、权限检查绕过）。

## 它解决什么问题

PHP 的 `==`、`in_array()`（无 strict）、`strcmp()`、`switch()` 遵循类型杂凑
（type juggling）规则，历史上导致大量漏洞：

- 两个不同的 `0e\d+` 哈希被 `==` 判等（magic hash）
- 数组参数让 `md5()`/`strcmp()` 返回 NULL，`NULL == 0` 绕过（PHP 7）
- 数字与字符串比较结果反直觉，`"abc" == 0` 在 PHP 7 为 true
- 规则在 PHP 7 → 8 之间发生变化，同一 payload 在不同版本结果不同

## 架构

```
PHP 源码
  │
  ├─ Lexer.php        手写词法分析器（无扩展依赖）
  ├─ Parser.php       递归下降语法分析器 → AST
  │
  ├─ TaintAnalyzer.php  流不敏感 may-taint 分析
  │     source: $_GET/$_POST/$_REQUEST/$_COOKIE/filter_input/...
  │     传播: 赋值、函数参数/返回值（跨函数摘要）、类型转换、内置函数
  │     sink:  ==/!=、in_array/array_search、strcmp 系列、switch
  │
  ├─ MagicHash.php    经运行时校验的 magic hash 原像表
  ├─ VersionRules.php 7.x / 8.x 版本可利用性判定 + 利用技术 + payload
  ├─ RouteDiscovery.php  路由参数发现（switch/if 路由 → 行号映射）
  ├─ ExploitBuilder.php  构造 HTTP PoC（含数组参数、baseline 对照）
  ├─ DynamicVerifier.php 启动 php -S 真实发包，差分验证绕过
  ├─ FixAdvisor.php   针对性修复代码（hash_equals / === / strict=true）
  └─ Report.php       text / json / markdown 报告
```

## 使用

```bash
# 静态扫描（目录或文件）
php typewatch scan ../demo-app
php typewatch scan src/ --format=json > report.json
php typewatch scan src/ --format=md   > report.md

# 静态 + 动态验证（自动起 PHP 内建服务器发包）
php typewatch verify ../demo-app --docroot=../demo-app

# 自测（37 项断言：解析、污点、版本矩阵、PoC、修复、端到端）
php typewatch selftest
```

## 版本规则矩阵（核心）

| 比较形态 | PHP 7.x | PHP 8.x | 攻击 payload |
|---|---|---|---|
| `md5(input) == "0e..."` | 可利用 | 可利用 | magic hash 原像（两版皆通） |
| `input == 0` | 可利用 | 不可利用 | 任意非数字字符串，如 `abc` |
| `input == 0`（数字串） | 可利用 | 可利用 | `0e1` |
| `strcmp(array(),x)==0` | 可利用（NULL==0） | TypeError | `token[]=` |
| `md5(array)==md5(...)` | 可利用（NULL==NULL） | TypeError | `sig[]=` |
| `in_array($needle,$h)` 含 0 元素 | 可利用 | 部分可利用 | `abc` / `0e1` |
| `input == true` | 可利用 | 可利用 | 任意 truthy 值 |
| `input == "普通字符串"` | 不可利用 | 不可利用 | 仅精确匹配 |

## 检测的 sink 类型

1. `loose_equality` — `==` / `!=` 松散比较
2. `strcmp_compare` — `strcmp/strncmp/strcasecmp/...` 返回值当等值判断
3. `in_array_loose` — `in_array`/`array_search` 未传第三个 strict 参数
4. `loose_switch` — `switch()` 的 `==` 语义 case 匹配

## 多层传递处理

污点在以下链路中持续跟踪（见 demo 的 `layered_token`）：

```
$_POST['raw_token']
  → wrapForCompare()      (normalizeInput → trim → strtolower)
  → computeDigest('md5')  (hash 包装，算法名经实参绑定恢复)
  → $digest == loadKnownToken()
```

跨函数通过函数摘要（parameter → return term）实现，含递归保护和
字面量实参绑定（让包装函数内的 `hash($algo, ...)` 能还原算法名）。

## 动态验证的判定方式

每个 PoC 配一个 benign baseline 请求，只有当 PoC 命中安全分支标记
（AUTH_OK / ACCESS_GRANTED / `ok:true` 且非 help 响应）而 baseline 没有时，
才判定 `BYPASS_CONFIRMED`，避免误报。PHP 8 上数组 payload 返回 TypeError
时标记为版本符合预期而非漏洞。

## 修复建议

- 哈希/密钥比较 → `hash_equals($known, $input)`（时序安全 + 类型严格）
- 普通等值 → `===`，并先 `is_string()` 守卫，拒绝数组参数
- `in_array`/`array_search` → 第三个参数传 `true`
- `switch` → 严格 `match()` 或白名单 + `in_array(..., true)`

## 局限

- 流不敏感（flow-insensitive）的 may-analysis，倾向保守（可能误报，不会漏报已知模式）
- 对象属性、动态变量、`extract()`/`parse_str()` 的动态别名不完整建模
- 常量返回值的跨函数传播仅限单一 return 的纯字面量函数
- 动态验证需要可本地运行的入口文件；纯库代码只做静态分析
