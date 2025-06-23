# GaussDB Python Async 驱动测试运行结果记录


| 测试文件                   | 结果       | 通过数 | 错误数 | 主要兼容性差异与备注                                               |
|---------------------------|------------|--------|--------|--------------------------------------------------------------------|
| tests/test_types.py       | 全部通过   | 1      | 0      | 类型系统与数据编解码兼容性良好                                     |
| tests/test_connect.py     | 有错误     | --     | 4      | 依赖 pg_ctl 工具，GaussDB 不支持自动集群管理                       |
| tests/test_execute.py     | 有错误     | 19     | 1      | 批量插入唯一约束冲突时行为与PG不同，错误反馈时机不确定              |
| tests/test_transaction.py | 有错误     | 3      | 3      | 不支持 UNLISTEN，隔离级别断言需放宽                                |
| tests/test_codecs.py      | 有错误     | 25 | 11   | 非法用户名、citext 扩展等与PG不兼容            |
| tests/test_cursor.py    | 全部通过   | 10     | 0      | 游标相关功能（fetch、scroll、生命周期等）在 GaussDB 下兼容性良好 |
| tests/test_exceptions.py | 全部通过   | 3      | 0      | 异常与错误处理相关功能在 GaussDB 下兼容性良好                   |
| tests/test_utils.py      | 全部通过   | 2      | 0      | 工具函数与通用功能在 GaussDB 下兼容性良好                      |
| tests/test_prepare.py    | 全部通过   | 34     | 0      | 预编译语句相关功能全部通过，驱动已适配 GaussDB 特有错误为标准异常 |
| tests/test_record.py     | 全部通过   | 25     | 0      | Record 结果集对象相关功能在 GaussDB 下兼容性良好                |
| tests/test_logging.py     | 全部通过   | 2      | 0      | 日志与警告消息处理在 GaussDB 下兼容性良好                      |
| tests/test_cache_invalidation.py | 有错误     | 7      | 2      | 2个用例因GaussDB不支持UNLISTEN而失败，事件/通知机制与PG不兼容 |
| tests/test_timeout.py     | 全部通过   | 9      | 0      | 超时与取消相关功能在 GaussDB 下兼容性良好                      |
| tests/test_adversity.py   | 全部跳过   | 0      | 0      | 4 个用例全部跳过，依赖特定逆境环境或不适用于当前测试环境         |
| tests/test__environment.py | 全部跳过   | 0      | 0      | 2 个用例全部跳过，依赖特定环境变量或配置，当前环境下未执行     |
| tests/test_test.py        | 全部通过   | 2      | 0      | 主流程/回归用例在 GaussDB 下兼容性良好                        |
| tests/test_introspection.py | 有错误     | 2      | 5      | 不支持 EXTENSION/INHERITS，DOMAIN|
|tests/test_listeners.py    | 有错误     | 0      | N     |都不支持   |
| tests/test_logging.py     | 全部通过   | 2      | 0      | 日志与警告消息处理在 GaussDB 下兼容性良好                      |
| tests/test_cancellation.py | 全部通过   | 4      | 0      | SQL 任务取消与中断在 GaussDB 下兼容性良好                      |
| tests/test_copy.py         | 全部失败   | 12      | 11      | GaussDB 不支持 COPY ... TO STDOUT 协议，所有流式导入导出测试均失败 |
| tests/test_pool.py         | 有错误     | 12     | 29     | 连接池 reset/release 时依赖 UNLISTEN，GaussDB 不支持事件通知机制，相关用例均失败 |
---




## 详细测试现象与分析

### 1. tests/test_connect.py
- 部分用例依赖 PostgreSQL 的 pg_ctl 工具，GaussDB 环境下无法运行。
- 主要为集群管理、自动化环境搭建相关，不影响主流程。

### 2. tests/test_execute.py
- 大部分用例通过。
- `TestExecuteMany.test_executemany_server_failure_during_writes` 用例多次运行时，`pos`（被消费的 generator 条数）有时等于 128，有时小于 128，存在不确定性。
- 断言 `self.assertLess(pos, 128, 'should stop early')` 或 `self.assertEqual(pos, 128, ...)` 均可能失败。
- 现象分析：GaussDB 在批量插入遇到唯一约束冲突时，错误反馈时机不确定，可能提前终止，也可能全部消费，和 PostgreSQL 行为不同。
- 建议：放宽断言条件，或仅做日志记录，文档注明行为差异。

### 3. tests/test_transaction.py
- 6 个用例中 3 个通过，3 个失败。
- 失败1：`UNLISTEN statement is not yet supported.`，GaussDB 不支持 LISTEN/UNLISTEN。
- 失败2：`nested transaction has a different isolation level: current 'read_committed' != outer 'repeatable_read'`，断言内容与实际隔离级别不符。
- 现象分析：GaussDB 默认隔离级别为 `read committed`，部分测试用例假设为 `repeatable read` 或 `serializable`，需放宽断言。
- 已建议将断言内容改为 `r"current .+ != outer .+"` 以兼容多种隔离级别。

### 4. tests/test_codecs.py
- 有错误，主要是因为复合类型 codec 注册、非法用户名、citext 扩展等与PG不兼容。
- 建议：相关用例用合法用户名，跳过不支持的扩展和类型注册测试。

### 5. tests/test_cursor.py
- 全部通过，游标相关功能（fetch、scroll、生命周期等）在 GaussDB 下兼容性良好。

### 6. tests/test_exceptions.py
- 全部通过，异常与错误处理相关功能在 GaussDB 下兼容性良好。

### 7. tests/test_utils.py
- 全部通过，工具函数与通用功能在 GaussDB 下兼容性良好。

### 8. tests/test_prepare.py
- 34 个用例全部通过，1 个用例被跳过（与数据库版本相关）。
- 预编译语句（prepared statement）相关的缓存、参数绑定、并发、异常处理等功能在 GaussDB 下表现正常。
- **兼容性修正说明**：
  - GaussDB 在表结构变更后，原有 prepared statement 查询会报 `cached plan must not change result type`，原本被驱动识别为 UnknownPostgresError。
  - 本次驱动层已改进，将该错误自动映射为 InvalidCachedStatementError，与 PostgreSQL 行为保持一致，测试用例无需修改即可通过。

### 9. tests/test_record.py
- 全部 25 个用例通过。
- 结果集 Record 对象的字段访问、迭代、序列化等功能在 GaussDB 下表现正常，无兼容性问题。
### 10. tests/test_logging.py
- 全部 2 个用例通过。
- 日志（WARNING、NOTICE 等）消息的捕获与处理在 GaussDB 下表现正常，无兼容性问题。
### 11. tests/test_cache_invalidation.py
- 7 个用例通过，2 个用例失败。
- 失败用例均因执行 `UNLISTEN` 时报 `FeatureNotSupportedError: UNLISTEN statement is not yet supported.`
- 事件/通知机制（LISTEN/NOTIFY/UNLISTEN）为 PostgreSQL 特有，GaussDB 当前版本不支持，相关缓存失效机制不可用。
- 建议：跳过依赖该机制的测试，并在文档中注明兼容性差异。

### 12. tests/test_timeout.py
- 全部 9 个用例通过。
- SQL 执行超时、任务取消、并发等待等功能在 GaussDB 下表现正常，无兼容性问题。
### 13. tests/test_adversity.py
- 全部 4 个用例被跳过。
- 这些用例依赖特定的逆境/异常环境（如网络抖动、数据库重启等），在当前测试环境下未执行。

### 14. tests/test__environment.py
- 全部 2 个用例被跳过。
- 这些用例依赖特定的环境变量或配置参数，在当前测试环境下未执行。
### 15. tests/test_test.py
- 全部 2 个用例通过。
- 主流程、回归、sanity check 等用例在 GaussDB 下表现正常，无兼容性问题。

### 16. tests/test_introspection.py
- 2 个用例通过，5 个用例失败。
- 失败1、2：`test_introspection_no_stmt_cache_01/02`，因 GaussDB 不支持 `CREATE EXTENSION`，相关 introspection 测试无法通过。
- 失败3：`test_introspection_on_large_db`，因 GaussDB 不支持 `CREATE TABLE ... INHERITS`，表继承 introspection 测试无法通过。
- 失败4、5：`test_introspection_retries_after_cache_bust`、`test_introspection_loads_basetypes_of_domains`，GaussDB 实际支持 DOMAIN，但测试用例未加 `DROP DOMAIN IF EXISTS`，导致重复创建时报错，且驱动异常映射不准确，将所有 DOMAIN 相关错误都映射为 `FeatureNotSupportedError`。
- 建议：DOMAIN 相关测试加 `DROP DOMAIN IF EXISTS`，驱动层区分"对象已存在"与"功能不支持"的异常。EXTENSION/INHERITS 相关测试可跳过或注明不支持。

### 17. tests/test_logging.py
- 全部 2 个用例通过。
- 日志（WARNING、NOTICE 等）消息的捕获与处理在 GaussDB 下表现正常，无兼容性问题。
### 18. tests/test_cancellation.py
- 全部 4 个用例通过。
- SQL 任务的取消（如超时、手动取消等）在 GaussDB 下表现正常，无兼容性问题。


### 19.tests/test_copy.py
- 所有用例失败，失败原因一致。
- 现象：表内数据插入正常，但执行 `copy_from_table`/`copy_to_table` 时，返回 'COPY 0' 或抛出协议不支持异常。
- 手动在 DBeaver 执行 `COPY public.copytab TO STDOUT;` 报错：The driver currently does not support COPY operations.
- 结论：GaussDB 当前版本不支持 PostgreSQL 的 COPY ... TO STDOUT 协议（流式导入导出），导致所有相关测试无法通过。
- 建议：如需大数据量导入导出，请使用文件方式或联系 GaussDB 厂商确认支持计划。相关测试可跳过或在文档中注明兼容性限制。

### tests/test_pool.py
- 12 个用例通过，29 个用例失败，4 个用例跳过，1 个用例报错。
- 绝大多数失败用例的根本原因：GaussDB 不支持 PostgreSQL 的 LISTEN/UNLISTEN/NOTIFY 事件通知机制，导致连接池在 reset/release 连接时执行 `UNLISTEN *` 报 `FeatureNotSupportedError`。
- 其它失败用例有表已存在（DuplicateTableError）和断言失败，但主因仍为事件通知机制不兼容。
- 结论：连接池主流程功能可用，但所有依赖事件通知机制的用例均无法通过。建议驱动层适配或跳过相关测试，并在文档中注明兼容性限制。
---

## 兼容性结论与建议
- GaussDB 与 PostgreSQL 在部分协议、隔离级别、批量插入错误处理等方面存在差异。
- 建议：
  1. 对于依赖 PostgreSQL 特性的用例（如 pg_ctl、UNLISTEN），可跳过或文档注明。
  2. 对于隔离级别、批量插入等行为差异，放宽断言或动态适配。
  3. 在 README 或开发文档中补充兼容性说明。

---

## PostgreSQL和GaussDB对比

### 1. 集群管理与测试环境
- **PostgreSQL**：支持通过 `pg_ctl` 工具自动启动和关闭测试集群，便于自动化测试环境的搭建与回收。
- **GaussDB**：不提供 `pg_ctl` 类似工具，相关依赖自动集群管理的测试无法运行。需手动配置数据库环境，建议跳过此类用例或在文档中注明。

### 2. 批量插入（executemany）与唯一约束
- **PostgreSQL**：批量插入遇到唯一约束冲突时，通常会立即终止，未消费完的 generator 条目不会被继续处理，断言 `pos < 128` 能稳定通过。
- **GaussDB**：批量插入遇到唯一约束冲突时，错误反馈时机不确定，有时提前终止，有时会全部消费 generator，导致 `pos` 可能等于 128 或小于 128，断言不稳定。
- **建议**：放宽断言条件，或仅做日志记录，并在文档中注明此行为差异。

### 3. 事务隔离级别与嵌套事务
- **PostgreSQL**：默认隔离级别为 `read committed`，部分测试用例假设为 `repeatable read` 或 `serializable`，嵌套事务/保存点行为与标准 SQL 一致。
- **GaussDB**：同为 `read committed`，但嵌套事务或保存点的隔离级别行为与 PostgreSQL 略有不同，部分断言（如隔离级别不一致）需放宽。
- **建议**：断言内容建议采用正则 `r"current .+ != outer .+"`，以兼容不同数据库的隔离级别实现。

### 4. LISTEN/UNLISTEN/NOTIFY 事件通知
- **PostgreSQL**：原生支持 LISTEN/UNLISTEN/NOTIFY 事件通知机制，相关测试可正常通过。
- **GaussDB**：当前版本不支持 LISTEN/UNLISTEN/NOTIFY，执行相关 SQL 会报 `FeatureNotSupportedError`，导致依赖事件通知的测试全部失败。
- **建议**：跳过相关测试，并在文档中明确说明 GaussDB 不支持该特性。

### 5. 类型系统与扩展支持
- **复合类型 codec 注册**：
  - **PostgreSQL**：支持为自定义复合类型注册 codec，类型 introspect 能正常工作。
  - **GaussDB**：注册自定义复合类型 codec 时 introspect 失败，提示 `unknown type: public.mycomplex`，可能与协议或 DDL 可见性有关。
- **用户名合法性**：
  - **PostgreSQL**：部分特殊字符用户名（如 `"u1'"`）可用，但不推荐。
  - **GaussDB**：用户名字符限制更严格，包含 `'` 等特殊字符会报错。
- **citext 扩展**：
  - **PostgreSQL**：支持 `citext` 扩展。
  - **GaussDB**：不支持，创建扩展时报 `UndefinedFileError`。
- **建议**：相关测试用例应使用合法用户名，跳过不支持的扩展和类型注册测试，并在文档中注明兼容性限制。

---

