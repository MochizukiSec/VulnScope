# VulnScope - 漏洞情报收集平台

[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-12+-blue.svg)](https://www.postgresql.org)

VulnScope是一个现代化的漏洞情报收集和分析平台，基于Rust构建，专为安全运营工程师、分析师和安全主管设计。平台提供实时漏洞数据收集、智能分析和可视化展示，帮助安全团队及时发现和响应威胁。

## ✨ 功能特点

### 🔐 完整的用户认证系统
- **用户注册** (`/register`): 新用户注册账户
  - 支持多种用户角色：管理员、安全分析师、安全运营工程师、查看者
  - 密码强度验证和实时反馈
  - 邮箱验证和用户名唯一性检查
  
- **用户登录** (`/login`): 安全的用户认证
  - JWT Token认证机制
  - 记住我功能
  - 密码显示/隐藏切换
  - 快速登录按钮（演示用）
  - 安全的退出登录功能

### 📊 核心功能模块
- **实时仪表板** (`/`): 漏洞统计和趋势分析
  - 实时漏洞数量统计
  - 严重程度分布图表
  - 数据源状态监控
  - 收集器运行状态
  
- **漏洞管理** (`/vulnerabilities`): 漏洞列表和详情查看
  - 高级搜索和筛选功能
  - 多维度排序
  - 分页显示
  - 详细漏洞信息展示
  
- **智能搜索** (`/search`): 多条件漏洞搜索
  - 关键词搜索
  - 严重程度筛选
  - 数据源筛选
  - 时间范围筛选
  
- **数据分析** (`/analytics`): 趋势分析和图表展示
  - 漏洞趋势分析
  - 数据源对比
  - 统计报表生成
  
- **系统设置** (`/settings`): 系统配置和数据源管理
  - 收集器配置
  - 用户管理
  - 系统参数设置

### 🤖 多源自动化收集
- **国际数据源**：
  - NVD (国家漏洞数据库)
  - GitHub Security Advisories
  - Exploit-DB
  - CVE Details
  
- **中文数据源**：
  - 长亭漏洞库
  - 奇安信威胁情报
  - 阿里云漏洞库
  - 微步在线威胁情报

- **智能特性**：
  - 实时数据同步和更新
  - 智能去重和数据标准化
  - 自动数据验证和清洗
  - 增量更新机制

## 🚀 快速开始

### 环境要求
- **Rust**: 1.70+ 
- **PostgreSQL**: 12+ 
- **操作系统**: macOS / Linux / Windows

### 安装运行

1. **克隆项目**
```bash
git clone https://github.com/MochizukiSec/VulnScope.git
cd VulnScope
```

2. **安装PostgreSQL并创建数据库**
```bash
# macOS
brew install postgresql
brew services start postgresql
createdb vulnscope

# Ubuntu/Debian
sudo apt-get install postgresql postgresql-contrib
sudo systemctl start postgresql
sudo -u postgres createdb vulnscope
```

3. **配置环境变量**
```bash
# 创建.env文件
cat > .env << EOF
DATABASE_URL=postgresql://username:password@localhost/vulnscope
JWT_SECRET=your-super-secret-jwt-key-here
SERVER_HOST=127.0.0.1
SERVER_PORT=3000
LOG_LEVEL=info
EOF
```

4. **运行数据库迁移**
```bash
# 安装sqlx-cli (如果未安装)
cargo install sqlx-cli

# 运行迁移
sqlx migrate run
```

5. **构建并启动服务**
```bash
# 开发模式
cargo run

# 生产模式
cargo build --release
./target/release/vulnscope
```

6. **访问应用**
- 🏠 主页: http://localhost:3000
- 🔑 登录页面: http://localhost:3000/login
- 📝 注册页面: http://localhost:3000/register

### 默认演示账户

为了便于快速体验，系统提供了预设的演示账户：

- **管理员账户**: 
  - 用户名: `admin` 
  - 密码: `admin123`
  - 权限: 完整系统管理权限

- **分析师账户**: 
  - 用户名: `analyst` 
  - 密码: `analyst123`
  - 权限: 数据查看和分析权限

## 📡 API接口文档

### 认证相关
- `POST /api/auth/login` - 用户登录
- `POST /api/auth/logout` - 用户退出
- `POST /api/auth/register` - 用户注册
- `GET /api/users/profile` - 获取用户信息

### 漏洞数据
- `GET /api/vulnerabilities` - 获取漏洞列表
- `GET /api/vulnerabilities/:id` - 获取漏洞详情
- `GET /api/search` - 搜索漏洞
- `GET /api/stats` - 获取统计信息

### 系统管理
- `GET /api/health` - 健康检查
- `GET /api/collectors/status` - 收集器状态
- `POST /api/collectors/:name/start` - 启动收集器
- `POST /api/collectors/:name/stop` - 停止收集器

## 👥 用户角色权限

| 角色 | 描述 | 权限范围 |
|------|------|----------|
| 管理员 | 系统管理员 | 全部权限（用户管理、系统配置、数据管理） |
| 安全运营工程师 | 安全运营人员 | 查看、分析、配置收集器 |
| 安全分析师 | 安全分析人员 | 查看、分析漏洞数据 |
| 查看者 | 只读用户 | 仅查看漏洞信息 |

## 🏗️ 技术架构

### 后端技术栈
- **Web框架**: Axum (高性能异步Web框架)
- **数据库**: PostgreSQL + SQLx (类型安全的SQL查询)
- **认证**: JWT + bcrypt (安全的身份验证)
- **HTTP客户端**: reqwest (异步HTTP请求)
- **序列化**: serde (高效的数据序列化)
- **日志**: tracing (结构化日志记录)
- **配置管理**: 环境变量

### 前端技术栈
- **CSS框架**: Tailwind CSS (实用优先的CSS框架)
- **图标库**: Font Awesome (丰富的图标集)
- **图表库**: Chart.js (交互式数据可视化)
- **JavaScript**: 现代ES6+原生JavaScript
- **响应式设计**: 移动端优先的适配

### 安全特性
- 🔐 JWT Token认证
- 🔒 bcrypt密码哈希存储
- 🛡️ CORS跨域保护
- 🚫 SQL注入防护
- ⚡ XSS防护
- 📊 密码强度验证
- 🔄 自动Token刷新

## 🗃️ 数据库设计

### 核心表结构
- **vulnerabilities** - 漏洞信息主表
  - 漏洞ID、CVE编号、标题、描述
  - 严重程度、CVSS评分
  - 发布日期、更新日期
  - 数据源信息

- **users** - 用户账户表
  - 用户信息、角色权限
  - 密码哈希、创建时间
  - 最后登录时间

- **collection_logs** - 收集日志表
  - 收集任务记录
  - 成功/失败状态
  - 数据统计信息

### 自定义数据类型
- `severity` - 漏洞严重程度枚举
- `vuln_status` - 漏洞状态枚举  
- `user_role` - 用户角色枚举

## 🛠️ 开发指南

### 添加新的数据收集器
1. 在 `src/collectors/` 目录下创建新的收集器文件
2. 实现 `VulnerabilityCollector` trait
3. 在 `src/collectors/mod.rs` 中注册新收集器
4. 添加相应的配置参数

### 扩展API端点
1. 在 `src/handlers.rs` 中添加新的处理函数
2. 在 `src/main.rs` 中注册新的路由
3. 更新相应的数据模型

### 前端页面开发
1. 在 `templates/` 目录下创建HTML模板
2. 使用统一的CSS类和组件
3. 添加相应的JavaScript交互逻辑
4. 更新导航菜单

## 🚀 部署指南

### 生产环境配置

1. **环境变量设置**
```bash
# 生产环境配置
DATABASE_URL=postgresql://prod_user:strong_password@localhost/vulnscope_prod
JWT_SECRET=super-long-random-secret-key-for-production
SERVER_HOST=0.0.0.0
SERVER_PORT=3000
LOG_LEVEL=warn
RUST_LOG=vulnscope=info
```

2. **数据库优化**
```sql
-- 创建索引优化查询性能
CREATE INDEX idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX idx_vulnerabilities_published_date ON vulnerabilities(published_date);
CREATE INDEX idx_vulnerabilities_source ON vulnerabilities(source);
```

3. **反向代理配置 (Nginx)**
```nginx
server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

4. **系统服务配置**
```ini
# /etc/systemd/system/vulnscope.service
[Unit]
Description=VulnScope Vulnerability Intelligence Platform
After=network.target

[Service]
Type=simple
User=vulnscope
WorkingDirectory=/opt/vulnscope
ExecStart=/opt/vulnscope/target/release/vulnscope
Restart=always

[Install]
WantedBy=multi-user.target
```


### 系统截图
<img width="1476" alt="iShot_2025-06-06_15 03 38" src="https://github.com/user-attachments/assets/5d57ba6d-f425-45c1-a3ce-8f67d56a880b" />
<img width="1475" alt="iShot_2025-06-06_15 03 46" src="https://github.com/user-attachments/assets/e6957cf7-2095-4897-9a9a-0797763f4795" />
<img width="1480" alt="iShot_2025-06-06_15 03 57" src="https://github.com/user-attachments/assets/14bed2d4-774e-447b-a5e7-ff5eb1955e19" />
<img width="1480" alt="iShot_2025-06-06_15 04 02" src="https://github.com/user-attachments/assets/43eada3d-09df-4982-b227-d8c60e76b420" />


### 监控和日志
- 配置日志轮转
- 设置性能监控
- 配置告警机制
- 定期数据备份

## 📄 许可证

本项目采用 [MIT License](LICENSE) 开源协议。

## 🤝 贡献指南

我们欢迎各种形式的贡献！

### 如何贡献
1. Fork 本仓库
2. 创建你的特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交你的更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启一个 Pull Request

### 贡献类型
- 🐛 报告Bug
- 💡 提出新功能建议
- 📝 改进文档
- 🔧 代码优化
- 🌍 多语言支持

## 📞 联系我们

- 🏠 **项目主页**: [GitHub Repository](https://github.com/MochizukiSec/VulnScope)
- 📋 **问题反馈**: [GitHub Issues](https://github.com/MochizukiSec/VulnScope/issues)
- 💬 **讨论交流**: [GitHub Discussions](https://github.com/MochizukiSec/VulnScope/discussions)

## 🎯 未来规划

- 🔄 支持更多国内外漏洞数据源
- 🤖 AI驱动的漏洞影响分析
- 📱 移动端App支持
- 🔗 与其他安全工具集成
- 📊 高级数据分析和预测
- 🌐 多语言界面支持

---

**VulnScope** - 让漏洞管理更简单、更智能、更安全 🛡️ 
