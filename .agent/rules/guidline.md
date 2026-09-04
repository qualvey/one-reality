---
trigger: always_on
---

---

## 2. Git 版本控制与提交规范

### 2.1 原子化提交 (Atomic Commits - 强制要求)
- **最小可行粒度**：每完成一个独立的小功能、一次明确的重构、一个 bug 修复，必须**立即做一个独立的 commit**。
- **禁止大杂烩**：严禁将不相关的改动（如“修复节点编辑 bug” + “优化 DNS 样式” + “修改后端 API”）合并在一个 commit 中。
- **构建保证**：每一个 commit 必须是一个可编译、测试通过的状态。

### 2.2 Commit Message 格式
遵循 Conventional Commits 规范：
```text
<type>(<scope>): <subject>

[optional body]
```

- **Type 类型**：
  - `feat`: 新增业务功能
  - `fix`: 修复 bug
  - `refactor`: 代码重构（无功能变更）
  - `perf`: 性能优化
  - `style`: 代码格式/样式微调（不影响功能逻辑）
  - `test`: 新增或修改单元测试
  - `docs`: 文档变更
  - `chore`: 构建流程、依赖更新或配置辅助工具变更
- **Scope 范围**（可选）：
  - 后端：`api`, `store`, `supervisor`, `collector`, `models`, `realtime`
  - 前端：`proxies`, `outbounds`, `inbounds`, `routes`, `dns`, `i18n`, `ui`, `settings`
- **示例**：
  ```bash
  feat(outbounds): 支持 VLESS Reality 密钥对生成
  fix(store): 修复多态类型反序列化缺少 include.Context 问题
  refactor(views): 抽离 OutboundEditDialog 为独立组件
  test(api): 补充 route rule_set 引用保护测试用例
  ```

---