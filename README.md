# VulnScope - 漏洞情报收集平台

VulnScope是一个现代化的漏洞情报收集和分析平台，专为安全运营工程师、分析师和安全主管设计。

## 功能特点

### 🔐 用户认证系统
- **用户注册** (`/register`): 新用户注册账户
  - 支持多种用户角色：安全分析师、安全运营工程师、查看者
  - 密码强度验证和实时反馈
  - 邮箱验证和用户名唯一性检查
  
- **用户登录** (`/login`): 安全的用户认证
  - JWT Token认证机制
  - 记住我功能
  - 密码显示/隐藏切换
  - 快速登录按钮（演示用）

### 📊 核心功能
- **实时仪表板** (`/`): 漏洞统计和趋势分析
- **漏洞管理** (`/vulnerabilities`): 漏洞列表和详情查看
- **高级搜索** (`/search`): 多条件漏洞搜索
- **数据分析** (`/analytics`): 趋势分析和图表展示
- **系统设置** (`/settings`): 系统配置和数据源管理

### 🤖 自动化收集
- 支持多个漏洞数据源：
  - NVD (国家漏洞数据库)
  - GitHub Security Advisories
  - Exploit-DB
  - CVE Details
- 实时数据同步和更新
- 智能去重和数据标准化

## 快速开始

### 环境要求
- Rust 1.70+
- PostgreSQL 12+
- Docker (可选)

### 安装运行

1. **克隆项目**
```bash
git clone <repository-url>
cd VulnScope
```

2. **设置环境变量**
```bash
cp .env.example .env
# 编辑 .env 文件，配置数据库连接等信息
```

3. **安装依赖并构建**
```bash
cargo build --release
```

4. **启动服务**
```bash
cargo run
```

5. **访问应用**
- 仪表板: http://localhost:3000
- 登录页面: http://localhost:3000/login
- 注册页面: http://localhost:3000/register

### 默认演示账户

为了便于演示，登录页面提供了快速登录按钮：

- **管理员登录**: 用户名 `admin`, 密码 `admin123`
- **分析师登录**: 用户名 `analyst`, 密码 `analyst123`

## API接口

### 认证接口
- `POST /api/auth/login` - 用户登录
- `POST /api/auth/register` - 用户注册
- `GET /api/users/profile` - 获取用户信息

### 漏洞接口
- `GET /api/vulnerabilities` - 获取漏洞列表
- `GET /api/vulnerabilities/:id` - 获取漏洞详情
- `GET /api/search` - 搜索漏洞
- `GET /api/stats` - 获取统计信息

### 系统接口
- `GET /api/health` - 健康检查

## 用户角色权限

| 角色 | 描述 | 权限 |
|------|------|------|
| 管理员 | 系统管理员 | 全部权限 |
| 安全运营工程师 | 安全运营人员 | 查看、分析、配置 |
| 安全分析师 | 安全分析人员 | 查看、分析 |
| 查看者 | 只读用户 | 仅查看 |

## 技术架构

### 后端技术栈
- **框架**: Axum (异步Web框架)
- **数据库**: PostgreSQL + SQLx
- **认证**: JWT + bcrypt
- **HTTP客户端**: reqwest
- **序列化**: serde
- **日志**: tracing
- **配置**: 环境变量

### 前端技术栈
- **样式**: Tailwind CSS
- **图标**: Font Awesome
- **图表**: Chart.js
- **交互**: 原生JavaScript
- **响应式**: 移动端适配

### 安全特性
- JWT Token认证
- 密码哈希存储 (bcrypt)
- CORS跨域保护
- SQL注入防护
- XSS防护
- 密码强度验证

## 数据库模式

### 主要表结构
- `vulnerabilities` - 漏洞信息
- `users` - 用户账户
- `collection_logs` - 收集日志
- 自定义枚举类型：`severity`, `vuln_status`, `user_role`

## 开发指南

### 添加新的数据收集器
1. 在 `src/collectors/` 下创建新文件
2. 实现 `VulnerabilityCollector` trait
3. 在 `mod.rs` 中注册收集器

### 自定义API端点
1. 在 `src/handlers.rs` 中添加处理函数
2. 在 `src/main.rs` 中注册路由

### 前端页面开发
1. 在 `templates/` 下创建HTML文件
2. 使用Tailwind CSS进行样式设计
3. 添加相应的路由处理

## 部署说明

### Docker部署
```bash
# 构建镜像
docker build -t vulnscope .

# 运行容器
docker run -p 3000:3000 vulnscope
```

### 生产环境配置
- 设置强密码和安全的JWT密钥
- 配置HTTPS
- 设置反向代理 (Nginx)
- 配置日志轮转
- 设置监控和告警

## 许可证

MIT License

## 贡献指南

欢迎提交Issue和Pull Request！

## 联系我们

- 项目主页: [GitHub Repository]
- 文档: [Documentation]
- 支持: [Support Email]

---

VulnScope - 让漏洞管理更简单、更智能、更安全。 