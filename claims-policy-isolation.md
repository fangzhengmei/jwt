# 跨服务 JWT 声明策略隔离分析

> 范围：`golang-jwt/jwt` v5，仓库修订 `f411663`（`Reject line breaks in token segments (#553)`），本机 Go 1.24.4。
> 性质：内部审计笔记，未修改仓库代码。按 [AGENTS.md](./AGENTS.md) 的要求，本文件不构成 upstream issue/PR；如需上游动作，须由人类先与维护者讨论并获得同意。
> 结论标注：**【证实】** = 源码可直接读出，且在固定时钟下运行验证；**【推断】** = 机制由源码证实，但实际是否触发取决于部署/调用方式，需在目标服务中核实。

---

## 0. 问题

同一签发方（IdP）签发的 JWT 被多个 SSO 服务复用校验逻辑时，每个服务在接受令牌前，实际上由四类约束共同决定：

1. `aud`（服务受众）
2. `iss`（签发者）
3. 必需的时效声明（`exp` / `nbf` / `iat`）
4. 自定义业务校验（`ClaimsValidator`，如 tenant、scope、client_id）

本库的默认行为是**尽量不拒绝**：`aud`、`iss`、`sub` 不校验，`exp`、`nbf` 可缺失，`iat` 不校验。因此“多个服务共享同一份校验代码/中间件”时，**默认配置和多数单选项组合都不能把一个服务的令牌挡在另一个服务之外**。

---

## 1. 结论摘要

- **【证实】默认 `jwt.Parse` 几乎不校验声明**：没有 `WithAudience` / `WithIssuer` 时，`aud`、`iss` 完全被忽略；`exp` 缺失也接受；只有令牌自带 `exp` 且已过期、或自带 `nbf` 且尚未生效时才拒绝（`validator.go:112-149`）。
- **【证实】只设置 `iss` 不能隔离服务**：同一 IdP 的服务间 `iss` 相同，`WithIssuer(...)` 只区分“哪个 IdP”，不区分“哪个服务”。在本矩阵中仅设 `iss` 的策略会接受 `aud=B`、`aud=C`、无 `aud` 的令牌（P8 行）。
- **【证实】`aud` 是唯一能把令牌绑定到服务的内建声明**，但必须每个服务单独设置为**自己的单一值**；传入多个值等价于“任一匹配即可”（`validator.go:250-259`），会重新打开跨服务接受。
- **【证实】自定义业务校验不是“默认开启”的**：`Parse()` 永远使用新建的 `MapClaims`，它不实现 `ClaimsValidator`；只有 `ParseWithClaims` + 动态类型正确实现该接口时才会执行（`parser.go:48,58`，`validator.go:153-158`）。传值时若方法是指针接收者，会直接 JSON 解码失败而不是执行校验。
- **【证实】`WithoutClaimsValidation()` 会同时关闭标准校验和自定义 `Validate()`**，且 `token.Valid` 仍为 `true`（P9 列）。共享中间件里出现这个选项，等于所有下游服务都失去隔离。
- **【证实】选项是“覆盖式”而非“追加式”**：重复 `WithAudience`/`WithIssuer` 后者覆盖前者；`WithAllAudiences` 之后再追加 `WithAudience` 会丢掉先前受众列表却保留“全匹配”模式。空参数还会静默禁用 `iss`/`sub` 校验。
- **【证实】失败时仍返回已解析的 `token`（含未验证/未通过校验的 claims）**，只是 `Valid=false`。调用方若以 `token != nil` 或读取 `token.Claims` 作为接受条件，会直接误接受。
- **【证实】复用 claims 对象会“继承”上一个令牌的声明**：`json.Unmarshal` 不清空结构体/映射中缺失的字段，因此复用的 `MapClaims` / 结构体 / `RegisteredClaims` 指针会让缺失的 `tenant`、`exp` 被上一次的值补上。
- **【推断】跨服务误接受的主要来源不是密码学，而是策略默认值与组合方式**：签名校验在所有声明校验之前完成，密钥/算法/`typ` 的隔离完全由调用方 `keyfunc` 承担。

---

## 2. 库的实际默认值与执行顺序

### 2.1 默认值（`Validator` 零值，`validator.go:36-72`）

| 字段 | 默认值 | 实际效果 | 源码 |
|---|---|---|---|
| `leeway` | `0` | 无时钟偏移容忍 | `validator.go:38` |
| `timeFunc` | `nil` → `time.Now()` | 使用系统时钟 | `validator.go:42,102-107` |
| `requireExp` | `false` | **`exp` 可缺失** | `validator.go:45` |
| `requireNbf` | `false` | `nbf` 可缺失 | `validator.go:48` |
| `verifyIat` | `false` | **`iat` 完全不看**（含未来时间） | `validator.go:55` |
| `expectedAud` | `nil` | **不校验 `aud`** | `validator.go:57-59` |
| `expectAllAud` | `false` | 任一匹配即可 | `validator.go:63` |
| `expectedIss` | `""` | **不校验 `iss`** | `validator.go:67` |
| `expectedSub` | `""` | **不校验 `sub`** | `validator.go:71` |

补充默认值：

- `Parser.validMethods` 默认 `nil`，即 **不限制 `alg`**（`parser.go:65` 的 `if p.validMethods != nil`）。
- 未调用 `NewParser` 的零值 `Parser` 在首次 `ParseWithClaims` 时惰性创建 validator（`parser.go:115-118`）。
- `TimePrecision = time.Second`、`MarshalSingleStringAsArray = true` 是**包级可变全局变量**（`types.go:18,28`），同一进程内所有服务共享。

### 2.2 执行顺序（`Validator.Validate`，`validator.go:95-165`）

```
1. exp   （始终检查，若存在）        validator.go:112
2. nbf   （始终检查，若存在）        validator.go:119
3. iat   （仅 verifyIat=true）       validator.go:124-128
4. aud   （仅 len(expectedAud)>0）   validator.go:131-135
5. iss   （仅 expectedIss != ""）    validator.go:138-142
6. sub   （仅 expectedSub != ""）    validator.go:145-149
7. ClaimsValidator.Validate()        validator.go:153-158
8. 全部错误 join 后返回              validator.go:160-164
```

要点：

- **不短路**：`exp` 过期与 `aud` 错误会同时出现在错误链中（`errors.go:31-56`）。用 `errors.Is` 可分别判定。
- **签名先于声明**：`parser.go:86-111` 先验签，`parser.go:113-123` 才校验声明。`keyfunc` 拿到的是**未验证 claims**（`parser.go:86` 早于 `120`）。
- **边界比较**：`exp` 用 `cmp.Before(exp+leeway)`，因此 `exp == now` 也拒绝（实测 `leeway=0` 时返回 `expired by 0s`；`leeway=1s` 时接受）。
- **`nbf`/`iat` 的 leeway 方向**：`!cmp.Before(nbf-leeway)`、`!cmp.Before(iat-leeway)`，即 leeway 允许提前生效；`leeway` 是**所有时间声明共用的单一数值**，不能按声明分别设置。
- **`aud` 缺省判定**：`len(aud)==0` 或 `aud==[""]` 视为缺失（`validator.go:245-248`）；只要 `expectedAud` 非空就返回 `ErrTokenRequiredClaimMissing`。注意这条“单元素空串”的特判只在 `aud` 恰好是 `[""]` 时生效；`["", "A"]` 是合法受众列表，空串元素会参与匹配，若 `expectedAud` 里也含空串则匹配成功（实测 `WithAudience("")` 接受 `aud=["",A]`）。
- **`iss`/`sub` 空字符串视为缺失**：`verifyIssuer`/`verifySubject` 用 `iss == ""` 判断（`validator.go:285,305`）。这正是 `WithIssuer("")` / `WithSubject("")` 变成静默禁用的原因。
- `MapClaims` 的 `exp:null` / `nbf:null` / `iat:null` 是**类型错误**（`MapClaims.parseNumericDate` 对 `nil` 落到 default 分支，`map_claims.go:45-61`）；而 `aud:null`、`iss:null`、`sub:null` 视为缺失（`map_claims.go:80-83,98-115`），不会报错。`iat:null` 仅在 `WithIssuedAt()` 启用时才会暴露为错误。

---

## 3. 选项叠加的语义与陷阱

所有 `ParserOption` 都直接写 `p.validator.*` 或 `p.*`，没有校验、没有合并逻辑（`parser_option.go:13-151`）。因此组合顺序和空值会直接改变安全语义。

### 3.1 覆盖式赋值

| 写法 | 结果 | 实测 |
|---|---|---|
| `WithIssuer("idp")` + `WithIssuer("other")` | 只认 `other` | `iss=idp` 被拒 |
| `WithAudience(A)` + `WithAudience(B)` | 只认 `B` | `aud=A` 被拒，`aud=B` 接受 |
| `WithValidMethods(nil)` | 等价于未设置（`nil` 检查） | 任意 alg 通过 |
| `WithValidMethods([]string{})` | **拒绝所有 alg** | HS256 被拒 |
| `WithAudience()`（无参数） | `len==0`，aud 校验被禁用 | 任意 `aud` / 无 `aud` 均接受 |
| `WithAudience("")` | `len==1`，校验启用，但只匹配空串 | 真实受众被拒（失败关闭）；但 `aud=["",A]` 会被接受（实测） |
| `WithIssuer("")` / `WithSubject("")` | 校验被禁用 | 任意 `iss`/`sub` 接受 |

> **配置注入风险【推断】**：如果 `iss`/`aud` 来自环境变量或配置中心，变量缺失/拼写错误时：
> - `iss` 缺失 → `WithIssuer("")` → **静默关闭 issuer 校验**；
> - `aud` 缺失 → `WithAudience()` → **静默关闭 audience 校验**；
> - 两者失败方向相反（`aud` 无参是关闭，`aud` 空串是失败关闭），很容易在代码审查中漏掉。

### 3.2 `expectAllAud` 是粘滞的

`WithAllAudiences` 同时设置 `expectedAud` 和 `expectAllAud=true`（`parser_option.go:99-104`）；而 `WithAudience` **只覆盖 `expectedAud`，不重置 `expectAllAud`**（`parser_option.go:83-87`）。实测：

| 组合 | 令牌 `aud` | 结果 |
|---|---|---|
| `WithAllAudiences(A,B)` 后 `WithAudience(A,B)` | `[A]` | 拒绝（仍要求 A、B 全在） |
| `WithAllAudiences(A,B)` 后 `WithAudience(A)` | `[A,B]` | **接受**（列表被换成 `[A]`，B 的要求静默消失） |
| `WithAudience(B)` 后 `WithAllAudiences(A)` | `aud=A` 的 A 令牌 | 接受 |
| `WithAllAudiences(A)` 后 `WithAudience(B)` | `aud=A` | 拒绝（只认 B） |

结论：**“先设全匹配，再追加任一匹配”会悄悄降级**；共享基础配置 + 服务侧追加选项时尤其危险。

### 3.3 切片别名

`WithAudience(aud ...string)` 把调用方传入的切片**直接存进 validator**（`parser_option.go:85`）；`WithValidMethods(methods []string)` 同样直接存（`parser_option.go:15`）。实测：

- 用 `shared := []string{A, B}` 构造 parser 后再修改 `shared[0] = B`，同一 parser 的接受集合随之改变。
- `WithValidMethods` 的切片被外部修改后，算法白名单也会改变。

### 3.4 时间相关

- `exp` 按 `TimePrecision`（默认秒）**向下截断**（`types.go:38-40,80-98`）。实测 `exp=1.05s`（相对固定时钟）被解析为 `1.00s`；当 `now=1.10s` 时 `leeway=100ms` 仍拒绝，因为 `exp+leeway` 恰好等于 `now`，而边界条件是严格 `cmp.Before(exp+leeway)`（`validator.go:185`）。截断误差最大接近一个 `TimePrecision`，且方向是**提前过期**（失败关闭）；但为它补偿的 `leeway` 会同时放宽 `nbf`/`iat`（失败开放）。
- `WithIssuedAt()` 只检查“`iat` 不在未来”，**不检查令牌年龄**。`iat=10 年前`、`exp=100 年后`的令牌在 `WithExpirationRequired()` + `WithIssuedAt()` 下依然接受（实测）。
- `exp` 可以远在未来：`exp=now+100 年` 且启用 `WithExpirationRequired()` 依然接受。**本库没有 max-age / max-lifetime 概念**。

### 3.5 解析器与包级全局状态

- `NewParser` 会初始化 `validator`（`parser.go:32-43`），因此**构造后只读共享是并发安全的**。
- 零值 `&jwt.Parser{}` 在 `ParseWithClaims` 内会写入 `p.validator`（`parser.go:117`），并发使用存在数据竞争（`go run -race` 实测报告 `parser.go:117` 写 / `parser.go:120` 读）。
- 对零值 `Parser` 直接应用**所有作用于 validator 的 `ParserOption`**（`WithLeeway`、`WithTimeFunc`、`WithIssuedAt`、`WithExpirationRequired`、`WithNotBeforeRequired`、`WithAudience`、`WithAllAudiences`、`WithIssuer`、`WithSubject`）会 **nil pointer panic**（选项写的是 `p.validator.*`）。只有操作 `Parser` 自身字段的选项（`WithValidMethods`、`WithJSONNumber`、`WithoutClaimsValidation`、`WithPaddingAllowed`、`WithStrictDecoding`）在零值上安全（逐项实测）。`request.ParseFromRequest` 的默认值正是 `&jwt.Parser{}`（`request/request.go:28-30`），所以该路径必须通过 `WithParser(jwt.NewParser(...))` 注入策略，不能把受众/签发者选项直接传给 `ParseFromRequest`（该函数也不接受 `jwt.ParserOption`）。
- `TimePrecision` / `MarshalSingleStringAsArray` 是进程级全局变量（`types.go:18,28`），一个服务修改会影响同进程其他服务。精度方向：较粗精度会把 `nbf`/`iat` 向下截断，使其最多提前一个精度生效（失败开放方向）；`exp` 则始终向下截断、提前失效（失败关闭方向）。实测 `nbf=5.9s` 在默认秒精度下截断为 `5s`（`now=5s` 时接受），改成 `100ms` 精度后同一令牌被拒绝。

---

## 4. 自定义业务校验（`ClaimsValidator`）的真实生效条件

接口定义（`validator.go:26-29`）：`Validate() error`。调用点：`validator.go:153-158`，按 `claims.(ClaimsValidator)` 做动态类型断言。

必须同时满足：

1. 使用 `ParseWithClaims` 并传入**实现了 `Claims` 的具体类型**；`Parse()` 内部固定用 `MapClaims`（`parser.go:48`），而 `MapClaims` 不实现 `Validate()`。
2. 对**结构体**类型的 claims，必须传**指针**（`&T{}`）。`parser.go:166-172` 只对 `MapClaims` 做了值类型特判，其余情况走 `json.Unmarshal(claimBytes, &claims)`（`claims` 是接口变量），实测传结构体值会得到 `could not JSON decode claim: json: cannot unmarshal object into Go value of type jwt.Claims`。
3. `Validate` 方法的接收者与传入值的动态类型匹配：
   - 指针接收者 `func (c *T) Validate()` 只有 `*T` 实现该接口，必须传 `&T{}`；
   - 值接收者 `func (c T) Validate()` 时 `T` 和 `*T` 都实现，但在 `ParseWithClaims` 下仍应传 `&T{}`（原因见第 2 条）；
   - **例外**：若直接用 `NewValidator(...).Validate(claims)`，传入值类型 `T{}`（指针接收者）不会报错，而是**静默跳过**自定义校验——实测 `tenant=b` 返回 `nil`，传 `&T{}` 才返回业务错误。这是“自定义校验看似存在、实际未执行”的隐蔽路径。
4. 没有使用 `WithoutClaimsValidation()`，否则**连自定义校验一起跳过**（实测 `err=nil`、`token.Valid=true`）。
5. `Validate()` 的签名不带参数，**拿不到 `Validator.timeFunc`**。业务侧若需要“令牌年龄/租户生效时间”等时间判断，只能自己取时钟，无法与被测/生产注入的固定时钟保持一致。这一点会让“测试通过、生产不同”的情况难以发现。

另：`NewValidator` 明确**不做签名校验**（`validator.go:81-83`）；`ParseUnverified` 同样不做（`parser.go:131-136`）。若共享链路采用“先解析、后校验”，任何可写 claims 的伪造令牌都能通过声明校验。

---

## 5. 跨服务误接受风险清单

| ID | 风险 | 触发条件 | 证据 | 状态 |
|---|---|---|---|---|
| R1 | 服务 A 接受为服务 B 签发的令牌 | 未设 `WithAudience`；`iss` 相同、密钥相同 | `validator.go:131` 守卫；P0/P1 对 `aud=B` 的结果 | 【证实】 |
| R2 | 只设 `iss` 不能隔离服务 | 同一 IdP 的服务共享 `iss` | P8 对 T2/T4/T5 全部接受 | 【证实】 |
| R3 | 多受众配置等价于“任一匹配” | `WithAudience(A,B)` 用于多服务共用配置 | `validator.go:250-259`；P3 对 T2 接受 | 【证实】 |
| R4 | 全匹配被静默降级 | `WithAllAudiences(A,B)` 之后追加 `WithAudience(A)` | `parser_option.go:99-104` vs `83-87`；实测 B 的要求消失 | 【证实】 |
| R5 | 空参数静默关闭校验 | `WithIssuer("")` / `WithAudience()` / `WithSubject("")` | `validator.go:138,285,305`；实测任意 `iss` 接受 | 【证实】 |
| R6 | 算法不受限 / alg 混淆 | 未设 `WithValidMethods`，且 `keyfunc` 不做类型检查 | `parser.go:65`；`WithValidMethods(nil)` 实测无限制；`none` 仅在 keyfunc 返回魔术常量时可行（`none.go:28-41`） | 【证实】 |
| R7 | 关闭全部声明校验 | 共享中间件含 `WithoutClaimsValidation()` | `parser_option.go:29-33`；P9 全接受 | 【证实】 |
| R8 | 自定义业务校验实际未执行 | 使用 `Parse`（MapClaims）；或 `NewValidator` 路径传值类型给指针接收者 | `parser.go:48`；`validator.go:153`；实测 `%T = jwt.MapClaims` 不实现接口；`NewValidator(ptrClaims{tenant:"b"})` 返回 nil | 【证实】 |
| R9 | 复用 claims 对象继承旧值 | 请求级复用 `MapClaims` / 结构体 / `RegisteredClaims` 指针 | `parser.go:166-182` 不清空目标；实测 `tenant`、`ExpiresAt` 保留，导致 `WithExpirationRequired` 误通过 | 【证实】机制存在；实际是否复用【推断】 |
| R10 | 业务时间校验与库时钟不一致 | `Validate()` 无参数，自带 `time.Now()` | `validator.go:26-29,153-158` | 【证实】 |
| R11 | 长寿命令牌 / 无重放防护 | `exp` 可缺失、可远未来；`iat` 默认不校验；`Claims` 接口无 `jti`（仅字段 `registered_claims.go:32`） | `validator.go:45,55`；实测 100 年 `exp` 接受 | 【证实】 |
| R12 | leeway 放宽所有时间声明 | 为时钟偏移设置 `WithLeeway` | `validator.go:185,206,227`；实测 `leeway=10s` 同时放宽 `exp`/`nbf`/`iat` | 【证实】 |
| R13 | 以返回的 `token`/`claims` 作为接受条件 | 调用方只判 `token != nil` 或读取 claims | 失败路径返回非 nil token（`parser.go:59-62,120-122`）；实测验签失败仍有完整 claims | 【证实】机制；调用方写法【推断】 |
| R14 | 共享零值 Parser 的并发竞争 / 选项 panic | 多个 goroutine 复用 `&jwt.Parser{}`；对零值 Parser 应用选项 | `parser.go:115-118`；`-race` 实测；选项 panic 实测 | 【证实】 |
| R15 | `typ`/`cty` 不参与校验 | 同 Issuer 同密钥签发 access/id/refresh 多种令牌 | 全库无 `typ` 校验；`token.go:35-42` 仅定义常量；实测 `typ=at+jwt` 与普通 JWT 同样通过 | 【证实】 |
| R16 | `keyfunc` 基于未验证 claims 做决策 | keyfunc 用 `iss`/`kid` 选密钥或做授权判断 | `parser.go:86` 早于声明校验；实测 keyfunc 看到 `iss=evil` | 【证实】 |

> 安全影响属敏感信息，按 [SECURITY.md](./SECURITY.md) 处理，不应提交公开 issue/PR。

---

## 6. 约束归属：哪些必须由调用方分别设置

### 6.1 每个服务必须分别设置（不能共享成一份）

| 约束 | 推荐写法 | 说明 |
|---|---|---|
| 受众 | `WithAudience("<本服务唯一 aud>")`，**恰好一个值** | 唯一能把令牌绑定到服务的内建声明。禁止用 `WithAudience(A,B)` 或“平台通用受众” |
| 签发者 | `WithIssuer("<期望 iss>")` | 同一 IdP 下各服务值相同，但**必须各自显式设置**；不能让空配置落到 `""` |
| `exp` 必需 | `WithExpirationRequired()` | 默认缺失即接受，必须显式打开 |
| 令牌类型 | 在 `keyfunc` 检查 `token.Header[jwt.HeaderType]` / `cty` | 库不校验；防 access/id/refresh 互换 |
| 算法 | `WithValidMethods([]string{"RS256"})` + `keyfunc` 内类型断言 | 库默认不限制；两者建议同时做 |
| 业务规则 | 自定义 `ClaimsValidator`（指针接收者 + `ParseWithClaims`） | tenant / scope / client_id / `aud` 与 tenant 绑定 / 最大令牌年龄（`now-iat <= maxAge`）/ 重放缓存 |

### 6.2 可以基础设施统一，但必须在每个服务实例上显式应用

- `iss` 的期望值（常量，可集中配置）。
- `leeway`：建议全局限定在一个小值（如 30s）；不要用它掩盖过期，也不要在单个服务里放大。
- `WithIssuedAt()`：建议全开；注意它只防“未来签发”，不限制年龄。
- 密钥/算法策略：同一 IdP 下可共享，但每个服务仍应确认自己的 `keyfunc` 只接受本环境、本 Issuer、本 `typ` 的密钥。

注意 `WithSubject()` **不能替代 `WithAudience()`**：它把令牌固定到某一个 `sub`，对多用户 SSO 令牌不适用；它只能用于“只允许某个服务账号/主体”的窄场景。`WithNotBeforeRequired()` 同理只是把 `nbf` 变成必需，不提供受众隔离。

### 6.3 绝不应共享

- **带服务专属 `expectedAud` 的 `Parser` 实例**：每个服务用 `NewParser` 单独构造；共享一个实例意味着最后一个配置覆盖所有服务。
- **`expectedAud` 切片、`validMethods` 切片**：会被直接别名持有，外部修改会改变校验结果。
- **claims 对象**（`MapClaims`、结构体、`RegisteredClaims` 指针）：复用会继承上一个令牌的 `tenant`/`exp`，破坏业务校验与必需声明。使用 `Parse` 时 `parser.go:48` 每次新建 `MapClaims`，不会继承；风险来自调用方自己传入并复用的对象。
- **含 `WithoutClaimsValidation()` 的中间件**：会把所有下游服务一起变成“只验签”。
- **受众并集/通配**：`WithAudience(A,B)` 与 `WithAllAudiences(A,B)` 都不能表达“只接受 A”。
- 零值 `Parser` 并发解析有数据竞争；且作用于 validator 的 `ParserOption` 在该对象上会 panic。`request.ParseFromRequest` 的默认 parser 正是零值，务必用 `WithParser(jwt.NewParser(...))` 覆盖。

### 6.4 参考配置（服务 A）

```go
// 必须每个服务独立构造；A、B 两个服务不应共用这个 Parser。
var parser = jwt.NewParser(
    jwt.WithValidMethods([]string{"RS256"}),
    jwt.WithAudience("https://svc-a.example.com"), // 恰好一个；缺失时启动失败
    jwt.WithIssuer("https://idp.example.com"),    // 缺失时启动失败
    jwt.WithExpirationRequired(),
    jwt.WithIssuedAt(),
    jwt.WithLeeway(30*time.Second),
)

func verify(raw string) (*svcClaims, error) {
    // 每次请求新的 claims 对象，禁止池化复用。
    claims := &svcClaims{}
    tok, err := parser.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
        if typ, _ := t.Header[jwt.HeaderType].(string); typ != "at+jwt" {
            return nil, fmt.Errorf("unexpected typ %q", typ)
        }
        // 只返回本环境、本 Issuer 的 JWKS 中与该 kid 匹配的密钥；
        // 不要用 t.Claims（此时尚未验证）做授权判断。
        return keyFor(t.Header[jwt.HeaderKeyID])
    })
    if err != nil || tok == nil || !tok.Valid { // 必须同时检查 err 与 Valid
        return nil, err
    }
    return claims, nil
}
```

`svcClaims.Validate()` 中自行完成 tenant、scope、最大年龄、`aud`-tenant 绑定等业务约束；由于 `Validate()` 无时钟参数，建议在 claims 结构体内注入时钟，避免与 `WithTimeFunc` 语义分叉。

---

## 7. 固定时钟双受众矩阵

### 7.1 环境

- 固定时钟：`now = 2026-01-01T00:00:00Z`（Unix `1767225600`），所有策略都显式 `WithTimeFunc(func() time.Time { return now })`。
- 两个服务受众：`A = https://svc-a.example.com`，`B = https://svc-b.example.com`；另有一个无关受众 `C = https://svc-c.example.com`。
- IdP：`iss = https://idp.example.com`。
- **假设**（见 §8.2）：A、B 共享同一签名密钥（SSO 复用签发的典型情形）；所有令牌签名有效；`exp` 为整数秒。

### 7.2 令牌

| ID | `aud` | 其他声明 | 说明 |
|---|---|---|---|
| T1 | `["A"]` | `iss=idp, exp=now+1h` | 正常 A 令牌 |
| T2 | `["B"]` | 同上 | 正常 B 令牌（跨服务探针） |
| T3 | `["A","B"]` | 同上 | 多受众令牌 |
| T4 | `["C"]` | 同上 | 无关受众 |
| T5 | 缺失 | 同上 | 无受众 |
| T6 | `["A"]` | `iss=https://evil.example.com` | 错误签发者（假设共享密钥） |
| T7 | `["A"]` | `exp=now-1h` | 已过期 |
| T8 | `["A"]` | **无 `exp`** | 无过期时间 |
| T9 | `"A"`（字符串形式） | 同上 | RFC 允许的标量形式 |
| T10 | `[]` | 同上 | 空数组 |
| T11 | `["", "A"]` | 同上 | 含空串 |
| T12 | `["A"]` | `nbf=now+1h` | 尚未生效 |
| T13 | `["A"]` | `iat=now+10h` | 未来签发 |
| T14 | `["A"]` | `tenant=b` | 业务属性不允许 |
| T15 | `["A"]` | `tenant=a` | 业务属性允许 |

### 7.3 策略

| ID | 配置 |
|---|---|
| P0 | 仅 `WithTimeFunc`（库默认） |
| P1 | `WithAudience(A)` |
| P2 | `WithAudience(B)`（作为对照，模拟服务 B） |
| P3 | `WithAudience(A, B)`（任一匹配） |
| P4 | `WithAudience(A)` + `WithIssuer(idp)` |
| P5 | P4 + `WithExpirationRequired()` |
| P6 | `WithAllAudiences(A, B)` |
| P7 | `WithAudience(A)` + 自定义 `Validate`（`tenant=="a"`，指针接收者） |
| P8 | `WithIssuer(idp)` |
| P9 | `WithAudience(A)` + `WithoutClaimsValidation()` |
| P10 | `WithAudience(A)` + `WithIssuedAt()` |
| P11 | `WithAudience()`（无参数） |

### 7.4 主矩阵（P0–P8）

✅ 接受；❌ 后是从 join 错误链中按 `exp → missing → aud → iss → nbf → iat → type` 优先级挑出的一个原因，仅用于说明“为什么拒绝”；同一格可能同时命中多个错误（例如 T12 在 P6 下同时 `aud` 与 `nbf` 失败，但显示为 `❌aud`）。

| 令牌 | P0 默认 | P1 aud=A | P2 aud=B | P3 aud∈{A,B} | P4 A+iss | P5 A+iss+exp必需 | P6 全匹配 A,B | P7 A+业务 | P8 仅 iss |
|---|---|---|---|---|---|---|---|---|---|
| T1 aud=A | ✅ | ✅ | ❌aud | ✅ | ✅ | ✅ | ❌aud | ❌tenant | ✅ |
| T2 aud=B | ✅ | ❌aud | ✅ | ✅ | ❌aud | ❌aud | ❌aud | ❌aud | ✅ |
| T3 aud=[A,B] | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌tenant | ✅ |
| T4 aud=C | ✅ | ❌aud | ❌aud | ❌aud | ❌aud | ❌aud | ❌aud | ❌aud | ✅ |
| T5 无 aud | ✅ | ❌missing | ❌missing | ❌missing | ❌missing | ❌missing | ❌missing | ❌missing | ✅ |
| T6 iss=evil | ✅ | ✅ | ❌aud | ✅ | ❌iss | ❌iss | ❌aud | ❌tenant | ❌iss |
| T7 已过期 | ❌exp | ❌exp | ❌exp | ❌exp | ❌exp | ❌exp | ❌exp | ❌exp | ❌exp |
| T8 无 exp | ✅ | ✅ | ❌aud | ✅ | ✅ | ❌missing | ❌aud | ❌tenant | ✅ |
| T9 aud 字符串 | ✅ | ✅ | ❌aud | ✅ | ✅ | ✅ | ❌aud | ❌tenant | ✅ |
| T10 aud=[] | ✅ | ❌missing | ❌missing | ❌missing | ❌missing | ❌missing | ❌missing | ❌missing | ✅ |
| T11 aud=["",A] | ✅ | ✅ | ❌aud | ✅ | ✅ | ✅ | ❌aud | ❌tenant | ✅ |
| T12 nbf 未来 | ❌nbf | ❌nbf | ❌aud | ❌nbf | ❌nbf | ❌nbf | ❌aud | ❌nbf | ❌nbf |
| T13 iat 未来 | ✅ | ✅ | ❌aud | ✅ | ✅ | ✅ | ❌aud | ❌tenant | ✅ |
| T14 tenant=b | ✅ | ✅ | ❌aud | ✅ | ✅ | ✅ | ❌aud | ❌tenant | ✅ |
| T15 tenant=a | ✅ | ✅ | ❌aud | ✅ | ✅ | ✅ | ❌aud | ✅ | ✅ |

### 7.5 补充矩阵（P9–P11）

| 令牌 | P9 aud=A + 关闭声明校验 | P10 aud=A + iat | P11 WithAudience() |
|---|---|---|---|
| T1 | ✅ | ✅ | ✅ |
| T2 aud=B | ✅ | ❌aud | ✅ |
| T3 | ✅ | ✅ | ✅ |
| T4 aud=C | ✅ | ❌aud | ✅ |
| T5 无 aud | ✅ | ❌missing | ✅ |
| T6 iss=evil | ✅ | ✅ | ✅ |
| T7 已过期 | **✅** | ❌exp | ❌exp |
| T8 无 exp | ✅ | ✅ | ✅ |
| T9 | ✅ | ✅ | ✅ |
| T10 aud=[] | ✅ | ❌missing | ✅ |
| T11 | ✅ | ✅ | ✅ |
| T12 nbf 未来 | **✅** | ❌nbf | ❌nbf |
| T13 iat 未来 | ✅ | **❌iat** | ✅ |
| T14 tenant=b | ✅ | ✅ | ✅ |
| T15 | ✅ | ✅ | ✅ |

### 7.6 从矩阵读出的跨服务结论

把“服务 A 必须拒绝为 B/C/未知受众签发的令牌”作为验收目标。P2 是服务 B 的对照配置，不属于服务 A 的候选策略，因此下表分母为其余 11 个策略；各策略对非 A 令牌的接受集合如下：

| 非 A 令牌 | 仍会接受它的策略（服务 A 视角） | 误接受数 |
|---|---|---|
| T2 `aud=B` | P0, P3, P8, P9, P11 | 5/11 |
| T4 `aud=C` | P0, P8, P9, P11 | 4/11 |
| T5 无 `aud` | P0, P8, P9, P11 | 4/11 |
| T10 `aud=[]` | P0, P8, P9, P11 | 4/11 |
| T8 无 `exp` | P0, P1, P3, P4, P8, P9, P10, P11 | 8/11 |
| T14 `tenant=b` | P0, P1, P3, P4, P5, P8, P9, P10, P11 | 9/11 |
| T13 `iat` 未来 | P0, P1, P3, P4, P5, P8, P9, P11 | 8/11 |
| T6 `iss=evil` + `aud=A` | P0, P1, P3, P9, P10, P11 | 6/11 |

几个直接推论：

1. **对 T2（B 的令牌）拒绝的是所有带 `aud=A` 的策略（P1、P4、P5、P7、P10）以及 P6**；接受的是 P0、P3、P8、P9、P11（P2 本就是服务 B，不算误接受）。P6 虽拒绝 T2，但它同时拒绝 T1（A 自己的令牌），因为它要求 A、B 同时出现在 `aud` 中——这本身就是错误的服务策略。P1/P10 单独使用时仍会接受 T6（错误 issuer + 正确 aud）；P7 不会因为 `aud` 失败而跳过业务校验（`Validator.Validate` 不短路，所有检查都会执行并把错误 join 起来），所以 P7 的每格是“标准声明结果 ∪ 业务结果”。
2. **P4 是“内建声明”的最小隔离配置**（aud + iss）；再叠加 `WithExpirationRequired()`（P5）才同时覆盖无 `exp` 的令牌。
3. **P8（仅 iss）对 `aud` 的隔离能力等价于默认配置**，只是额外拒绝了 T6；**P11（空受众）完全等价于默认配置**，B/C/无受众令牌全部接受。
4. **P3（受众并集）会让服务 A 接受 B 的令牌**：这是“平台通用配置”最常见的误用。
5. **P9 连过期令牌和未生效令牌都接受**：共享中间件只要带上 `WithoutClaimsValidation()`，前面所有隔离都归零。
6. **P7 的 `❌tenant` 出现在 T1/T3/T6/T8/T9/T11/T13/T14**：这是业务校验在“该令牌没有 tenant 或 tenant 不为 a”时的失败关闭。注意 P7 没有设置 `WithIssuer`：T6（错误 issuer + 正确 aud + 无 tenant）被拒绝只是因为 tenant 缺失，而不是 issuer 校验。补充实测：`aud=A` + `iss=https://evil.example.com` + `tenant=a` 在 P7 下**被接受**；同一令牌在 P4/P5 下被 `iss` 拒绝。业务字段的存在不能替代 `iss` 校验。
7. **P10 只处理 `iat` 未来**，不限制令牌年龄；`iat=10 年前、exp=100 年后`的令牌在 `WithExpirationRequired()` + `WithIssuedAt()` + `WithAudience(A)` 下依然接受（§3.4 单独实测）。

---

## 8. 源码可证实 vs 待验证假设

### 8.1 已由源码 + 运行证实（可直接作为结论）

- 默认不校验 `aud`/`iss`/`sub`，`exp`/`nbf` 可缺失，`iat` 不校验：`validator.go:44-71,112-149`。
- 声明校验顺序、错误 join 与 `errors.Is` 可分解：`validator.go:95-165`，`errors.go:31-56`。
- 选项是覆盖式赋值，无合并/校验；空值语义如 §3.1 所述：`parser_option.go:13-151`。
- `WithAllAudiences` → `WithAudience` 的 `expectAllAud` 粘滞：`parser_option.go:83-87,99-104`。
- `aud` 匹配为字符串精确比较（大小写、末尾斜杠、空格都敏感）：`validator.go:250-267`；实测 `A/`、`HTTPS://...` 均拒绝。
- `exp == now` 拒绝；`leeway` 全局作用于 `exp`/`nbf`/`iat`：`validator.go:185,206,227`。
- `Parse` 固定使用 `MapClaims`，自定义 `Validate` 仅在 `ParseWithClaims` + 正确动态类型时执行：`parser.go:48,58`，`validator.go:153-158`。
- `ParseWithClaims` 传入结构体值（而非指针）会导致 JSON 解码失败：实测 `cannot unmarshal object into Go value of type jwt.Claims`；而 `NewValidator` 路径传值给指针接收者类型会静默跳过 `Validate`。
- `WithoutClaimsValidation()` 同时跳过标准与自定义校验，`token.Valid=true`：`parser.go:114-123`。
- 失败路径返回非 nil token 与已解码 claims：`parser.go:59-62,120-122`。
- 复用 claims 对象会保留旧字段（`json.Unmarshal` 不清空）：`parser.go:166-182`；实测 `tenant`、`ExpiresAt` 继承。
- 验签先于声明校验，`keyfunc` 看到未验证 claims：`parser.go:86,113-123`。
- 零值 `Parser` 并发解析有数据竞争；对零值 `Parser` 应用作用于 validator 的 `ParserOption` 会 panic：`parser.go:115-118`，`parser_option.go:36-132`。
- 无 `typ`/`cty` 校验：全库无相关校验代码；只有 header 常量（`token.go:32-43`）。
- 无 max-age、无 `jti` 访问器（`claims.go:9-16`、`registered_claims.go:32` 仅字段）。
- `NewValidator`/`ParseUnverified` 均不验签：`validator.go:81-83`，`parser.go:131-203`。

### 8.2 需要在目标部署中核实的假设（不能从源码断言）

1. **密钥拓扑**：本分析假设同一 IdP 的多个服务共享同一签名密钥。若各服务使用独立密钥，R1/R2 的严重性下降，但同 Issuer 内的 `aud` 混用仍然存在。请核对 JWKS/密钥分发方式。
2. **IdP 是否签发多受众令牌**：若 SSO 会为一次登录签发 `aud=[A,B]`（token exchange/多 RP），那么 T3 被两个服务接受是设计而非缺陷；反之若 `aud` 本应单值，T3 就是配置错误。
3. **各服务实际是否设置了 `aud`**：本分析只覆盖库的默认值和选项语义，没有审计真实服务代码。需要逐服务确认 `WithAudience` 存在且值是单一、精确的受众。
4. **是否存在请求级 claims 复用/对象池**：R9 的机制已证实，但真实代码是否复用 `MapClaims`/结构体/`RegisteredClaims` 需要审计。
5. **是否存在共享 `Parser`/共享中间件**：R4、R7、R13 的影响取决于是否真的共享。特别检查是否有人把 `WithoutClaimsValidation` 放进公共链路。
6. **调用方如何判定成功**：是否同时检查 `err != nil` 与 `token.Valid`；是否会在失败后继续读取 `token.Claims`。
7. **算法与 `typ` 策略**：实际使用的 `alg` 集合、`keyfunc` 是否做类型断言、是否检查 `typ`/`cty`、是否接受 `none`（需 `UnsafeAllowNoneSignatureType`）。
8. **时钟与 leeway**：各节点 NTP 偏差、现有 `WithLeeway` 值，以及是否有服务依赖 leeway 掩盖过期。固定时钟矩阵只用于消除时间变量，不代表生产边界。
9. **`aud` 的规范化约定**：库按字节精确比较；如果 IdP 与服务对 `aud` 的大小写、末尾斜杠、端口写法不一致，会出现失败关闭而非误接受，但也会造成跨服务行为不一致。
10. **业务校验的接收者与时钟**：`Validate` 是否为指针接收者、是否在结构体内注入时钟、是否覆盖 max-age/重放/租户与受众绑定。
11. **是否使用 `WithJSONNumber`**：`MapClaims` 默认用 `float64` 解析数值声明，极大时间戳可能存在精度问题；`WithJSONNumber` 可避免，但不改变校验顺序。
12. **是否有外部撤销/重放层**：`jti` 不在 `Claims` 接口中，本库不提供撤销；若依赖外部黑名单，需确认它在所有服务生效。

---

## 9. 验收清单（按服务逐项核对）

- [ ] 每个服务使用 `jwt.NewParser(...)` 独立构造，**不共享带 `expectedAud` 的 Parser 实例**。
- [ ] `WithAudience(<本服务唯一值>)`，不传并集、不传通配；配置缺失时**启动失败**而不是退化为 `WithAudience()`。
- [ ] `WithIssuer(<精确 iss>)`；配置缺失时启动失败（避免 `WithIssuer("")` 静默关闭）。
- [ ] `WithExpirationRequired()`；如业务需要，另加 `WithNotBeforeRequired()`。
- [ ] `WithIssuedAt()` + 业务侧最大令牌年龄检查（`now - iat <= maxAge`）。
- [ ] `WithValidMethods([...])` 与 `keyfunc` 内的算法类型断言**同时**存在。
- [ ] `keyfunc` 校验 `typ`/`cty`；不依据未验证的 `iss`/`kid`/claims 做授权。
- [ ] `ParseWithClaims` 传指针，且 `ClaimsValidator` 为指针接收者；有编译期断言 `var _ jwt.ClaimsValidator = (*T)(nil)`。
- [ ] 若使用独立的 `NewValidator().Validate(...)`，同样传指针，否则指针接收者的 `Validate` 会被静默跳过。
- [ ] 每次请求使用**新的** claims 对象；不复用 `MapClaims`、结构体或 `RegisteredClaims`。
- [ ] 成功判定为 `err == nil && token.Valid`；失败后不读取 `token.Claims`。
- [ ] 不使用 `WithoutClaimsValidation()`；如确需，必须限定在已完成独立校验的场景并记录原因。
- [ ] `leeway` 全局限定小值；`aud`/`iss` 不被 `leeway` 影响（已由源码保证）。
- [ ] 明确 `TimePrecision`/`MarshalSingleStringAsArray` 的进程级影响；跨服务进程不要各自修改。
- [ ] 对非本服务受众的令牌有回归测试（对应本文件 T2/T4/T5/T10 与 P1/P4/P5）。

---

## 10. 复现方法

本文件的矩阵由仓库外的临时模块生成，未向仓库添加任何文件或依赖。核心步骤：

1. 临时模块 `go.mod` 使用 `replace github.com/golang-jwt/jwt/v5 => <本仓库路径>`。
2. 固定时钟 `now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)`，每个策略都追加 `jwt.WithTimeFunc(func() time.Time { return now })`。
3. 用 `jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)` 生成 T1–T15。
4. 对每个策略调用 `jwt.Parse` / `jwt.ParseWithClaims`，按 `errors.Is(err, jwt.ErrTokenExpired / ErrTokenRequiredClaimMissing / ErrTokenInvalidAudience / ErrTokenInvalidIssuer / ErrTokenNotValidYet / ErrTokenUsedBeforeIssued)` 分类。
5. 业务校验列（P7）使用：

```go
type svcClaims struct {
    Tenant string `json:"tenant"`
    jwt.RegisteredClaims
}
func (c *svcClaims) Validate() error {
    if c.Tenant != "a" { return errors.New("tenant not allowed") }
    return nil
}
```

6. 补充实验（§3、§4、§5、§8.1）分别覆盖：选项覆盖/别名、`expectAllAud` 粘滞、空参数、`ClaimsValidator` 动态类型、claims 复用、`WithoutClaimsValidation`、`typ`、亚秒截断、零值 Parser 并发/panic。

如需把这些检查固化进项目测试，应遵循 [AGENTS.md](./AGENTS.md)：先确认已有 issue 与维护者意见，单个小而聚焦的改动，附失败测试与通过记录，不在公开渠道披露安全影响。
