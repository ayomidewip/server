# App Base Server

A comprehensive Node.js server application featuring advanced file management, real-time collaboration, Redis caching, and robust authentication systems.

## 🚀 Features

### Core Systems
- **Advanced Authentication**: JWT-based system with access/refresh tokens, 2FA support, and role-based access control
- **File Management System**: Complete file CRUD with version control, auto-save, compression, and GridFS storage
- **Real-time Collaboration**: WebSocket-powered collaborative editing using Yjs and Socket.IO
- **Caching Layer**: Redis-powered caching with automatic invalidation and cleanup
- **Email Service**: Template-based email system with SMTP support
- **Comprehensive Logging**: Winston-based logging with MongoDB persistence and colorized console output

### Advanced Features
- **File Compression**: Automatic file compression using Brotli, Gzip, and Deflate algorithms
- **Storage Management**: Intelligent storage routing between inline and GridFS based on file characteristics
- **Auto-save System**: Persistent auto-save with configurable intervals and cache-to-database synchronization
- **Rate Limiting**: Configurable rate limiting for general and authentication endpoints
- **Security**: Helmet, HPP, CORS protection with file upload security
- **API Documentation**: Comprehensive REST API with filtering, pagination, and sorting

## 📋 Requirements

- **Node.js** 18+ (LTS recommended)
- **MongoDB** 5+ (MongoDB Atlas or local installation)
- **Redis** 6+ (Optional but recommended for optimal performance)
- **npm** or **yarn**

## 🚀 Quick Start

1. **Clone and Install**
   ```bash
   git clone <repository-url>
   cd server
   npm install
   ```

2. **Environment Setup**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration (see Environment Configuration section)
   ```

3. **Database Setup** (Optional - see Database Setup section)
   ```bash
   # MongoDB will create the database automatically when first accessed
   # Redis setup instructions below for optimal performance
   ```

4. **Start Development Server**
   ```bash
   npm run dev
   ```

## ⚙️ Environment Configuration

The application uses environment variables for configuration. Copy the example file and customize it:

```bash
cp .env.example .env
```

### Key Configuration Requirements

1. **Generate Secure Secrets** (Required for JWT authentication):
   ```bash
   # Generate random secrets for JWT tokens
   node -e "console.log('ACCESS_TOKEN_SECRET=' + require('crypto').randomBytes(32).toString('hex'))"
   node -e "console.log('REFRESH_TOKEN_SECRET=' + require('crypto').randomBytes(32).toString('hex'))"
   ```

2. **Database Connection** (Required):
   ```bash
   # Local MongoDB
   MONGODB_URI=mongodb://localhost:27017/app-base-db
   
   # MongoDB Atlas (cloud)
   MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/app-base-db
   ```

3. **Redis Connection** (Optional but recommended):
   ```bash
   # Default Redis connection
   REDIS_HOST=localhost
   REDIS_PORT=6379
   CACHE_ENABLED=true
   ```

All configuration options are documented in the `.env.example` file with descriptions and default values.

## 📊 Redis Setup (Optional but Recommended)

Redis provides caching capabilities that significantly improve API performance and enable advanced features like auto-save persistence and cache cleanup services.

### Quick Setup Options

- **Local Development**: Follow the [official Redis installation guide](https://redis.io/docs/getting-started/installation/) for your platform
- **Docker**: `docker run -d --name redis -p 6379:6379 redis:alpine`
- **Cloud Services**: [Redis Cloud](https://redis.com/redis-enterprise-cloud/), [AWS ElastiCache](https://aws.amazon.com/elasticache/), [DigitalOcean Managed Redis](https://www.digitalocean.com/products/managed-databases)

### Configuration

Update your `.env` file:
```bash
# Local Redis
REDIS_HOST=localhost
REDIS_PORT=6379
CACHE_ENABLED=true

# Remote Redis (with authentication)
REDIS_HOST=your.remote.redis.server.com
REDIS_PORT=6379
REDIS_PASSWORD=your_secure_password
CACHE_ENABLED=true
```

### Verification
```bash
redis-cli ping  # Should return: PONG
npm run dev     # Check for Redis connection logs
```


## 🗄️ Database Setup

### MongoDB Installation

Follow the [official MongoDB installation guide](https://www.mongodb.com/docs/manual/installation/) for your platform:

- **Windows**: [MongoDB Community Edition Installation](https://www.mongodb.com/docs/manual/tutorial/install-mongodb-on-windows/)
- **macOS**: [Install with Homebrew](https://www.mongodb.com/docs/manual/tutorial/install-mongodb-on-os-x/) or [Manual Installation](https://www.mongodb.com/docs/manual/tutorial/install-mongodb-on-os-x-tarball/)
- **Linux**: [Ubuntu/Debian](https://www.mongodb.com/docs/manual/tutorial/install-mongodb-on-ubuntu/), [Red Hat/CentOS](https://www.mongodb.com/docs/manual/tutorial/install-mongodb-on-red-hat/), [SUSE](https://www.mongodb.com/docs/manual/tutorial/install-mongodb-on-suse/)

### Quick Setup
```bash
# Verify MongoDB is running
mongosh

# Create database and user (optional)
use app-base-db
db.createUser({
  user: "appbaseuser", 
  pwd: "your_secure_password",
  roles: [{ role: "readWrite", db: "app-base-db" }]
})
```

### Configuration Examples
```bash
# Local MongoDB
MONGODB_URI=mongodb://localhost:27017/app-base-db

# With authentication
MONGODB_URI=mongodb://appbaseuser:password@localhost:27017/app-base-db

# MongoDB Atlas (cloud)
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/app-base-db
```

### Tools
- **[MongoDB Compass](https://www.mongodb.com/products/compass)**: GUI for database management
- **[MongoDB Atlas](https://www.mongodb.com/atlas)**: Managed cloud MongoDB service

## 📧 Email Service Setup

The application includes a comprehensive email system with template support.

### Quick SMTP Configuration

#### Gmail (Recommended for Development)
```bash
# .env configuration
EMAIL_ENABLED=true
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USER=your-gmail@gmail.com
EMAIL_PASS=your_app_password  # Generate App Password in Google Account Settings
EMAIL_FROM=noreply@yourapp.com
```

#### Other Providers
```bash
# Outlook/Hotmail
EMAIL_HOST=smtp-mail.outlook.com
EMAIL_PORT=587

# Yahoo Mail
EMAIL_HOST=smtp.mail.yahoo.com
EMAIL_PORT=587
```

### Features
- **Template System**: Handlebars-based responsive email templates
- **Test Endpoints**: `/api/v1/email/test` and `/api/v1/email/template/render`
- **Built-in Templates**: Welcome, verification, password reset, security alerts
- **Variables**: `{{firstName}}`, `{{email}}`, `{{appName}}`, `{{appUrl}}`, `{{resetUrl}}`

## 📁 Advanced File System

### File Storage Architecture

The application uses intelligent storage routing:

- **Inline Storage**: Small text files stored directly in MongoDB documents
- **GridFS Storage**: Large files and binary content stored in MongoDB GridFS
- **Automatic Detection**: Storage type determined by file size and MIME type

### File Compression

Automatic compression using multiple algorithms:
- **Brotli**: Best compression ratio (priority 1)
- **Gzip**: Good compatibility (priority 2)
- **Deflate**: Fallback option (priority 3)

Configuration:
```bash
COMPRESSION_MIN_SIZE=1024      # Minimum file size for compression
COMPRESSION_MIN_RATIO=0.05     # Minimum space savings required
```

### Supported File Types

The system supports extensive file type detection:
- **Text**: txt, md, log, csv
- **Code**: js, ts, jsx, tsx, py, java, cpp, css, html, json
- **Config**: ini, conf, env, toml, yaml
- **Documentation**: md, rst, adoc, tex
- **Web**: html, css, js, vue, svelte
- **Binary**: pdf, docx, xlsx, images, etc.

### File Security

- **Upload Filtering**: Configurable blocked file extensions
- **Path Validation**: Prevents directory traversal attacks
- **MIME Type Validation**: Validates file content matches extension
- **Size Limits**: Configurable upload size limits (default 500MB)

## 🔄 Real-time Collaboration

### WebSocket-based Collaborative Editing

The application uses **Socket.IO** with **Yjs** for real-time collaborative editing:

- **Yjs Integration**: Conflict-free replicated data types (CRDTs) for operational transformation
- **MongoDB Persistence**: Collaborative documents stored using `y-mongodb-provider`
- **WebSocket Server**: Socket.IO server for real-time communication
- **Presence Awareness**: Track and display active collaborators per file
- **Access Control**: JWT-based authentication for WebSocket connections

### WebSocket Connection

```javascript
// Client-side connection example
const socket = io('http://localhost:8080', {
  auth: { token: 'your-jwt-token' }
});

// Join a file collaboration session
socket.emit('join-file', { fileId: 'file-id' });

// Listen for document updates
socket.on('document-update', (update) => {
  // Handle Yjs document updates
});
```

### API Endpoints

```http
GET  /api/v1/files/:filePath/collaborators  # Get active collaborators
POST /api/v1/files/:fileId/sync            # Sync collaborative document
```

## 🔐 Advanced Authentication

### JWT Token System

- **Access Tokens**: Short-lived (20 minutes default) for API access
- **Refresh Tokens**: Long-lived (7 days default) for token renewal
- **Token Blacklisting**: Secure logout with Redis-backed token invalidation
- **Auto-renewal**: Automatic token refresh for seamless user experience

### Two-Factor Authentication (2FA)

- **TOTP Support**: Time-based one-time passwords using Speakeasy
- **QR Code Generation**: Easy setup with authenticator apps
- **Recovery Codes**: Backup codes for account recovery

### Role-Based Access Control

Five hierarchical roles with granular permissions:

1. **OWNER**: Complete system control
2. **ADMIN**: Administrative privileges (cannot delete users)
3. **SUPER_CREATOR**: Extended creation and management rights
4. **CREATOR**: Basic content creation rights
5. **USER**: Personal account management only

### Security Features

- **Rate Limiting**: Separate limits for general API and authentication endpoints
- **Password Complexity**: Enforced strong password requirements
- **Account Lockout**: Protection against brute force attacks
- **Security Alerts**: Email notifications for suspicious login activity

## 🛠️ Logging System

The server uses Winston for advanced structured logging with colorized output and MongoDB persistence.

### Log Levels (Priority Order)

1. **error** (🔴 ❌) - Critical failures requiring immediate attention
2. **warn** (🟡 ⚠️) - Concerning issues that aren't critical failures  
3. **info** (🟢 ℹ️) - General operational information (default)
4. **http** (🟣 📡) - HTTP request/response logging with method-specific icons
5. **debug** (🔵 ✨) - Detailed debugging information for troubleshooting

Setting `LOG_LEVEL=info` shows info, warn, and error logs. Setting `LOG_LEVEL=debug` shows all log levels.

### Logging Features

- **Colorized Console**: Beautiful colored output with emojis and formatting
- **Database Persistence**: HTTP requests automatically stored in MongoDB
- **Request Logging**: Comprehensive request/response logging with timing
- **Log Aggregation**: Query and analyze logs through API endpoints
- **Console Override**: Redirect console.log to Winston when `LOG_OVERRIDE=true`

### Log Configuration
```bash
LOG_LEVEL=http          # Set minimum log level
LOG_REQUESTS=true       # Enable HTTP request logging  
LOG_OVERRIDE=true       # Redirect console methods to Winston
```

## 🚀 API Documentation

### Authentication Endpoints
```http
POST /api/v1/auth/signup          # Register new user
POST /api/v1/auth/login           # User login with credentials
POST /api/v1/auth/refresh-token   # Refresh access token
POST /api/v1/auth/logout          # Secure logout (blacklist tokens)
GET  /api/v1/auth/me             # Get current user profile
POST /api/v1/auth/forgot-password # Request password reset
POST /api/v1/auth/reset-password/:token # Reset password with token

# Two-Factor Authentication
POST /api/v1/auth/2fa/setup       # Setup 2FA with QR code
POST /api/v1/auth/2fa/verify      # Verify 2FA token
POST /api/v1/auth/2fa/disable     # Disable 2FA
```

### User Management
```http
GET    /api/v1/users              # Get all users (admin only)
POST   /api/v1/users              # Create user (admin only)
GET    /api/v1/users/:id          # Get specific user
PUT    /api/v1/users/:id          # Update user profile
DELETE /api/v1/users/:id          # Delete user
PATCH  /api/v1/users/:id/change-password # Change password
GET    /api/v1/users/:id/stats    # Get user statistics
```

### Advanced File System
```http
# File Operations
GET    /api/v1/files              # List files with filtering/pagination
POST   /api/v1/files              # Create new file
GET    /api/v1/files/:filePath    # Get file metadata
PUT    /api/v1/files/:filePath    # Update file metadata  
DELETE /api/v1/files/:filePath    # Delete file/version
GET    /api/v1/files/:filePath/content # Get file content
PUT    /api/v1/files/:filePath/autosave # Auto-save to cache
POST   /api/v1/files/:filePath/save # Save as new version
POST   /api/v1/files/:filePath/publish # Publish current content

# File Versions
GET    /api/v1/files/:filePath/versions # Get all versions
DELETE /api/v1/files/:filePath/versions/:version # Delete version

# File Upload
POST   /api/v1/files/upload       # Upload single file
POST   /api/v1/files/upload-multiple # Upload multiple files

# File Management  
GET    /api/v1/files/types        # Get supported file types
GET    /api/v1/files/stats        # File storage statistics
GET    /api/v1/files/compression/stats # Compression statistics (admin)
GET    /api/v1/files/admin/stats  # Admin file statistics
GET    /api/v1/files/autosave/status # Auto-save service status (admin)
POST   /api/v1/files/bulk         # Bulk operations
POST   /api/v1/files/directory    # Create directory
GET    /api/v1/files/tree         # Get file tree structure
GET    /api/v1/files/access/:accessType # Get files by access type
GET    /api/v1/files/directory/:dirPath/contents # Directory contents
GET    /api/v1/files/directory/:dirPath/stats # Directory statistics

# File Operations
PUT    /api/v1/files/:filePath/move # Move file/directory
POST   /api/v1/files/:filePath/copy # Copy file/directory
GET    /api/v1/files/:filePath/download # Download file
GET    /api/v1/files/:filePath/info # Get file MIME info

# Collaboration & Real-time Editing
GET    /api/v1/files/:filePath/collaborators # Active collaborators
POST   /api/v1/files/:fileId/sync # Sync collaborative document

# WebSocket Endpoints (Socket.IO)
# Connect to: ws://localhost:8080/socket.io/ with JWT token
# Events: 'join-file', 'document-update', 'cursor-position', 'user-presence'
```

### File Sharing & Permissions
```http
GET    /api/v1/files/:filePath/share # Get sharing info
POST   /api/v1/files/:filePath/share # Share with users
DELETE /api/v1/files/:filePath/share # Remove sharing
```

### Cache Management
```http
GET    /api/v1/cache/stats        # Cache statistics
DELETE /api/v1/cache/clear        # Clear cache (admin)
GET    /api/v1/cache/keys         # List cache keys (admin)
DELETE /api/v1/cache/keys/:key    # Delete specific key (admin)
```

### Application Management
```http
GET    /api/v1/health             # Health check
GET    /api/v1/stats/overview     # System statistics (admin)
GET    /api/v1/logs               # Application logs (admin)
DELETE /api/v1/logs               # Clear logs (admin)

# Email Testing (Admin)
POST   /api/v1/email/template/render # Preview email template
POST   /api/v1/email/test         # Send test email
```

### Query Parameters

#### File Listing (`GET /api/v1/files`)
```http
?page=1&limit=20                  # Pagination
&sortBy=updatedAt&sortOrder=desc  # Sorting
&search=filename                  # Search in filename/content
&type=file                        # Filter by type (file/directory)
&mimeType=text/plain             # Filter by MIME type
&tags=important,project          # Filter by tags
&minSize=1024&maxSize=1048576    # Size filtering
&owner=true                      # Show only owned files
&shared=true                     # Show only shared files
```

#### User Listing (`GET /api/v1/users`)
```http
?page=1&limit=20                 # Pagination
&sortBy=createdAt&sortOrder=asc  # Sorting  
&search=john                     # Search users
&role=ADMIN                      # Filter by role
&active=true                     # Filter by status
&fields=id,username,email,roles  # Select specific fields
```

## 🔧 Development

### Available Scripts
```bash
npm run dev        # Start development server with nodemon
npm start          # Start production server
npm test           # Run test suite with Jest
```

### Project Structure
```
server/
├── config/          # Database and user rights configuration
│   ├── db.js        # MongoDB connection and GridFS utilities
│   └── rights.js    # User roles and permissions system
├── controllers/     # Request handlers and business logic
│   ├── app.controller.js    # Health, stats, and system endpoints
│   ├── auth.controller.js   # Authentication and 2FA
│   ├── cache.controller.js  # Cache management and cleanup
│   ├── file.controller.js   # File operations and collaboration
│   └── user.controller.js   # User management
├── middleware/      # Express middleware functions
│   ├── app.middleware.js      # Core middleware and Redis client
│   ├── auth.middleware.js     # JWT and permission checking
│   ├── cache.middleware.js    # Response caching and invalidation
│   ├── error.middleware.js    # Global error handling
│   ├── file.middleware.js     # File upload and compression
│   ├── user.middleware.js     # User validation middleware
│   └── validation.middleware.js # Request validation with Joi
├── models/          # MongoDB schemas and data models
│   ├── file.model.js   # File schema with GridFS support
│   ├── log.model.js    # Request logging schema
│   ├── schemas.js      # Joi validation schemas
│   └── user.model.js   # User schema with roles/permissions
├── routes/          # API route definitions
│   ├── app.routes.js    # System routes (health, logs, email)
│   ├── auth.routes.js   # Authentication endpoints
│   ├── cache.routes.js  # Cache management endpoints
│   ├── file.routes.js   # File system and collaboration
│   └── user.routes.js   # User management endpoints
├── templates/       # Email templates (Handlebars)
│   └── emails/      # Email template files
├── utils/           # Utility functions and helpers
│   ├── app.logger.js  # Winston logging with colorized output
│   ├── sanitize.js    # HTML sanitization utilities
│   └── validator.js   # Custom validation functions
├── .env.example     # Environment variables template
├── index.js         # Application entry point
├── server.js        # Server class with WebSocket support
└── package.json     # Dependencies and npm scripts
```

### Key Features Implementation

#### Auto-save System
- Files cached in Redis during editing
- Configurable persistence interval (default: 5 minutes)
- Automatic synchronization to MongoDB
- Conflict detection for concurrent edits

#### Caching Strategy  
- Response caching with automatic invalidation
- Entity-based cache keys with dependency tracking
- TTL-based expiration with cleanup service
- Cache warming for frequently accessed data

#### File Compression
- Automatic compression for eligible files
- Multiple algorithm support (Brotli, Gzip, Deflate)
- Intelligent storage routing based on compression results
- Configurable compression thresholds

## 🚢 Production Deployment

### Environment Configuration
```bash
NODE_ENV=production
LOG_LEVEL=warn
CACHE_ENABLED=true
EMAIL_ENABLED=true
# Use strong random secrets in production
ACCESS_TOKEN_SECRET=your_production_access_secret
REFRESH_TOKEN_SECRET=your_production_refresh_secret
```

### Performance Recommendations

1. **MongoDB Optimization**:
   - Use MongoDB Atlas or properly configured replica set
   - Enable connection pooling
   - Create appropriate indexes for file paths and user queries
   - Configure GridFS for large file storage

2. **Redis Optimization**:
   - Configure memory limits and eviction policies
   - Use Redis persistence for important cache data
   - Monitor Redis memory usage
   - Set up Redis clustering for high availability

3. **WebSocket/Socket.IO Scaling**:
   - Use Redis adapter for Socket.IO clustering
   - Configure sticky sessions for load balancing
   - Monitor WebSocket connection limits
   - Implement connection pooling for Yjs documents

4. **Security Hardening**:
   - Use HTTPS/TLS in production
   - Configure proper CORS origins for both HTTP and WebSocket
   - Enable rate limiting for both API and WebSocket connections
   - Regular security updates and dependency scanning

5. **Monitoring & Observability**:
   - Set up log aggregation with structured logging
   - Monitor application metrics and WebSocket connections
   - Configure health check endpoints
   - Track collaborative document usage and performance

## 🐛 Troubleshooting

### Common Issues

#### Database Connection Failed
```bash
# Check MongoDB status
mongosh mongodb://localhost:27017/app-base-db
```

#### Redis Connection Issues
```bash
# Check Redis status
redis-cli ping
```

#### Email Service Not Working
```bash
# Check email configuration in logs
npm run dev
```

#### WebSocket/Collaboration Issues
```bash
# Test WebSocket connection
LOG_LEVEL=debug npm run dev
```

### Debug Mode
```bash
LOG_LEVEL=debug npm run dev
```

For detailed troubleshooting guides, see:
- [MongoDB Troubleshooting](https://www.mongodb.com/docs/manual/faq/diagnostics/)
- [Redis Troubleshooting](https://redis.io/docs/getting-started/faq/)
- [Node.js Troubleshooting](https://nodejs.org/en/docs/guides/debugging-getting-started)

## 🤝 Contributing

[Add contributing guidelines here]

---

**Built with ❤️ using Node.js, Express, MongoDB, and Redis**

