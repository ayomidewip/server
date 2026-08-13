# App Base Server

**Backend API Server Template with Authentication, User Management, Dynamic Themes, and Caching**

A comprehensive Node.js + Express server template featuring robust authentication, role-based access control, user connections, dynamic themes, Redis caching, and a template-based email service. This is the server half of the App Base template that other apps (e.g., Creator Base, FilesystemOne) are built on.

> **Note:** File management, GridFS storage, compression, and real-time (Yjs) collaboration are **not** part of App Base. Those features live in FilesystemOne (`filesystem-one/file-server`), which extends this template.

## 🚀 Features

### Core Systems
- **Advanced Authentication**: JWT access/refresh tokens with rotation and reuse detection, CSRF protection, TOTP 2FA with backup codes, email verification, device tracking, and role-based access control
- **User Management**: User CRUD, public user directory, per-user and overview statistics, and LinkedIn-style connections (request/accept/reject)
- **Dynamic Themes**: User-created theme token documents with visibility controls, built-in presets, and forking (`/api/v1/themes`)
- **Caching Layer**: Redis-powered caching with automatic invalidation and cleanup
- **Email Service**: Template-based email system with SMTP support
- **Comprehensive Logging**: Winston-based logging with MongoDB persistence and colorized console output

### Advanced Features
- **Role System**: Five hierarchical roles (OWNER → USER) with rights mapping and an owner-approval role-elevation flow
- **Rate Limiting**: Configurable rate limiting for general and authentication endpoints
- **Security**: Helmet, HPP, CORS protection, input sanitization, and route allowlisting
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
   cd app-base/server
   npm install
   ```

2. **Environment Setup**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration (see Environment Configuration section)
   ```

   **Critical Configuration:**
   ```bash
   # Generate unique JWT secrets (Required!)
   node -e "console.log('ACCESS_TOKEN_SECRET=' + require('crypto').randomBytes(32).toString('hex'))"
   node -e "console.log('REFRESH_TOKEN_SECRET=' + require('crypto').randomBytes(32).toString('hex'))"
   
   # MongoDB connection (Required)
   MONGODB_URI=mongodb://localhost:27017/app-base-db
   
   # Redis cache (Optional but recommended)
   REDIS_URL=redis://localhost:6379
   CACHE_ENABLED=true
   
   # CORS - Add your frontend URL
   ALLOWED_ORIGINS=http://localhost:8080,http://localhost:8088
   ```

3. **Database Setup** (Optional - see Database Setup section)
   ```bash
   # MongoDB will create the database automatically when first accessed
   # Redis setup instructions below for optimal performance
   ```

4. **Start Development Server**
   ```bash
   npm run dev
   # Server will run on http://localhost:8080
   ```

5. **Verify Server is Running**
   ```bash
   # Check health endpoint
   curl http://localhost:8080/api/v1/health
   # Should return: {"success":true,"message":"Server is healthy!","status":"online"}
   ```

## ⚙️ Environment Configuration

The application uses environment variables for configuration. Copy the example file and configure it:

```bash
cp .env.example .env
```

**All environment variables are documented in the [`.env.example`](./.env.example) file** with detailed descriptions and default values. This includes:

- Application settings (port, environment)
- MongoDB Atlas connection (required)
- JWT authentication secrets (required - must be generated)
- Redis cache configuration (optional but recommended)
- CORS origins for frontend
- Email service (SMTP configuration)
- Request payload size limits
- Logging, rate limiting, and more

### Critical Setup Steps

1. **Generate JWT Secrets** (Required):
   ```bash
   node -e "console.log('ACCESS_TOKEN_SECRET=' + require('crypto').randomBytes(32).toString('hex'))"
   node -e "console.log('REFRESH_TOKEN_SECRET=' + require('crypto').randomBytes(32).toString('hex'))"
   ```
   Copy these generated secrets to your `.env` file.

2. **MongoDB Atlas Setup** - See detailed guide below

3. **Email Service Setup** - See detailed guide below (optional but recommended)

## 📊 Redis Setup (Optional but Recommended)

Redis provides caching capabilities that significantly improve API performance and enable features like response caching, token blacklisting, and the cache cleanup service.

### Quick Setup Options

- **Local Development**: Follow the [official Redis installation guide](https://redis.io/docs/getting-started/installation/) for your platform
- **Docker**: `docker run -d --name redis -p 6379:6379 redis:alpine`
- **Cloud Services**: [Redis Cloud](https://redis.com/redis-enterprise-cloud/), [AWS ElastiCache](https://aws.amazon.com/elasticache/), [DigitalOcean Managed Redis](https://www.digitalocean.com/products/managed-databases)

### Configuration

Update your `.env` file:

```bash
# Local Redis
REDIS_URL=redis://localhost:6379
CACHE_ENABLED=true

# Render/Cloud Redis (they provide this format)
REDIS_URL=redis://red-xxxxx.render.com:6379
CACHE_ENABLED=true

# With authentication
REDIS_URL=redis://username:password@redis-host:6379
CACHE_ENABLED=true
```

### Verification
```bash
redis-cli ping  # Should return: PONG
npm run dev     # Check for Redis connection logs
```


## 🗄️ MongoDB Atlas Setup (Cloud Database)

MongoDB Atlas is a fully managed cloud database service. Follow these steps to set up your database:

### Step 1: Create MongoDB Atlas Account

1. Go to [https://www.mongodb.com/cloud/atlas/register](https://www.mongodb.com/cloud/atlas/register)
2. Sign up for a free account (no credit card required for the free tier)
3. Verify your email address
4. Log in to your MongoDB Atlas account

### Step 2: Create a New Cluster

1. Click **"Build a Database"** or **"Create"** button
2. Choose **"M0 FREE"** tier (includes 512 MB storage - perfect for development)
3. Select your preferred **Cloud Provider** (AWS, Google Cloud, or Azure)
4. Choose a **Region** closest to your location for best performance
5. Name your cluster (e.g., `AppBaseCluster`) or keep the default name
6. Click **"Create Cluster"** (this takes 3-5 minutes)

### Step 3: Create Database User

1. Click **"Database Access"** in the left sidebar under Security
2. Click **"Add New Database User"**
3. Choose **"Password"** authentication method
4. Set a username (e.g., `appbaseuser`)
5. Click **"Autogenerate Secure Password"** or create your own strong password
6. **Important**: Copy and save this password securely - you'll need it for your connection string
7. Under **"Database User Privileges"**, select **"Read and write to any database"**
8. Click **"Add User"**

### Step 4: Configure Network Access

1. Click **"Network Access"** in the left sidebar under Security
2. Click **"Add IP Address"**
3. For development, click **"Allow Access from Anywhere"** (adds `0.0.0.0/0`)
   - For production, add only your specific IP addresses
4. Click **"Confirm"**

### Step 5: Get Your Connection String

1. Click **"Database"** in the left sidebar (or go to your cluster dashboard)
2. Click **"Connect"** button on your cluster
3. Choose **"Drivers"** as the connection method
4. Select **"Node.js"** as the driver and choose the latest version
5. Copy the connection string - it looks like:
   ```
   mongodb+srv://<username>:<password>@cluster.mongodb.net/?retryWrites=true&w=majority
   ```

### Step 6: Configure Your Application

1. Open your `.env` file in the server directory
2. Replace the `MONGODB_URI` value with your connection string:
   ```bash
   MONGODB_URI=mongodb+srv://appbaseuser:YOUR_PASSWORD@cluster.mongodb.net/app-base-db?retryWrites=true&w=majority&appName=AppBase
   ```
3. **Important replacements**:
   - Replace `<username>` with your database username (e.g., `appbaseuser`)
   - Replace `<password>` with your actual database password
   - Add your database name after `.net/` (e.g., `app-base-db`)
   - Add `&appName=AppBase` at the end for better monitoring

### Step 7: Test Your Connection

Start your server to test the connection:

```bash
npm run dev
```

Look for this success message in the console:
```
🌱 MongoDB connection established! cluster.mongodb.net/app-base-db
⚡ Transaction support confirmed
```

### Troubleshooting

**Connection Timeout Errors:**
- Verify your IP address is whitelisted in Network Access
- Check that your password doesn't contain special characters that need URL encoding
- Ensure your internet connection is stable

**Authentication Failed:**
- Double-check your username and password
- Make sure the password is URL-encoded if it contains special characters
- Example: `p@ssw0rd!` should be `p%40ssw0rd%21`

**Database Name Not Created:**
- The database will be created automatically when the first document is inserted
- No need to manually create the database in Atlas

### Managing Your Database

**MongoDB Atlas Web Interface:**
- View collections and documents in the **"Collections"** tab
- Monitor performance in the **"Metrics"** tab
- Set up automated backups in the **"Backup"** tab
- View logs in the **"Logs"** tab

**MongoDB Compass (Desktop GUI):**
1. Download [MongoDB Compass](https://www.mongodb.com/products/compass)
2. Use the same connection string to connect
3. Browse collections, run queries, and analyze data visually

### Free Tier Limitations

The M0 FREE tier includes:
- ✅ 512 MB storage
- ✅ Shared RAM
- ✅ Unlimited connections
- ✅ Basic support
- ❌ No automated backups (on free tier)
- ❌ Limited to 3 clusters per project

**This is perfect for development and small applications!**

## 📧 Email Service Setup (SMTP Configuration)

The application includes a comprehensive email system with Handlebars template support for user verification, password resets, and notifications.

### Why You Need Email Service

Email functionality enables:
- ✉️ User email verification
- 🔒 Password reset functionality
- 🚨 Security alerts for suspicious activity
- 👋 Welcome emails for new users
- 📋 System notifications

### Option 1: Gmail SMTP (Recommended for Development)

Gmail provides free SMTP service that's easy to set up. Follow these steps:

#### Step 1: Enable 2-Step Verification

1. Go to your [Google Account Settings](https://myaccount.google.com/)
2. Click **"Security"** in the left sidebar
3. Under **"How you sign in to Google"**, click **"2-Step Verification"**
4. Click **"Get Started"** and follow the setup process
5. Verify your identity with your phone number
6. Turn on 2-Step Verification

#### Step 2: Generate App Password

1. Return to [Google Account Security](https://myaccount.google.com/security)
2. Under **"How you sign in to Google"**, click **"App passwords"**
   - If you don't see this option, make sure 2-Step Verification is enabled
3. Click **"Select app"** and choose **"Other (Custom name)"**
4. Enter a name like "App Base Server" or "Node Mailer"
5. Click **"Generate"**
6. **Important**: Copy the 16-character app password shown (format: `xxxx xxxx xxxx xxxx`)
   - You won't be able to see this password again!

#### Step 3: Configure Your `.env` File

Add these settings to your `.env` file:

```bash
EMAIL_ENABLED=true
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USER=your-gmail@gmail.com
EMAIL_PASS=xxxx xxxx xxxx xxxx  # Your 16-character app password (remove spaces)
EMAIL_FROM=noreply@yourapp.com   # Can be any email format
APP_URL=http://localhost:8080    # Your application URL
```

**Important Notes:**
- Remove spaces from the app password: `xxxxxxxxxxxxxxxx`
- `EMAIL_FROM` is the "from" address users will see (doesn't need to match EMAIL_USER)
- Make sure `EMAIL_ENABLED=true` to activate the email system

### Option 2: Outlook/Hotmail SMTP

Microsoft Outlook and Hotmail also provide SMTP service:

#### Configuration

```bash
EMAIL_ENABLED=true
EMAIL_HOST=smtp-mail.outlook.com
EMAIL_PORT=587
EMAIL_USER=your-email@outlook.com    # or @hotmail.com
EMAIL_PASS=your_account_password     # Your actual Outlook password
EMAIL_FROM=your-email@outlook.com
APP_URL=http://localhost:8080
```

#### Security Settings

1. Go to [Outlook Account Security](https://account.microsoft.com/security)
2. Enable **"Less secure app access"** if prompted
3. Verify the login attempt if Microsoft sends you a security code

### Option 3: SendGrid (Production Recommended)

SendGrid offers a generous free tier (100 emails/day) and is more reliable for production:

#### Setup Steps

1. Sign up at [https://signup.sendgrid.com/](https://signup.sendgrid.com/)
2. Verify your email address
3. Go to **Settings** → **API Keys**
4. Click **"Create API Key"**
5. Give it a name and select **"Full Access"**
6. Copy the API key (starts with `SG.`)

#### Configuration

```bash
EMAIL_ENABLED=true
EMAIL_HOST=smtp.sendgrid.net
EMAIL_PORT=587
EMAIL_USER=apikey                    # Literally the word "apikey"
EMAIL_PASS=SG.your_api_key_here     # Your actual SendGrid API key
EMAIL_FROM=verified@yourdomain.com   # Must verify this email in SendGrid
APP_URL=http://localhost:8080
```

**Important**: You must verify your sender email in SendGrid before sending emails.

### Option 4: Other SMTP Providers

| Provider | Host | Port | Notes |
|----------|------|------|-------|
| **Yahoo Mail** | `smtp.mail.yahoo.com` | 587 | Requires app password |
| **Mailgun** | `smtp.mailgun.org` | 587 | 5,000 free emails/month |
| **Amazon SES** | `email-smtp.region.amazonaws.com` | 587 | Pay-as-you-go pricing |
| **Zoho Mail** | `smtp.zoho.com` | 587 | Free tier available |

### Step 4: Test Your Email Configuration

Once configured, test your email service:

#### Method 1: Using the API Endpoint

Start your server:
```bash
npm run dev
```

Send a test email using curl:
```bash
curl -X POST http://localhost:8080/api/v1/email/test \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{
    "to": "your-test-email@example.com",
    "subject": "Test Email",
    "text": "This is a test email from App Base!"
  }'
```

#### Method 2: Check Logs

When your server starts with email enabled, you should see:
```
✅ Email service configured
📧 Email host: smtp.gmail.com
```

If email is not configured correctly, you'll see:
```
⚠️  Email service disabled or not configured
```

### Troubleshooting Email Issues

#### "Invalid login" or "Authentication failed"

**Gmail:**
- Verify 2-Step Verification is enabled
- Make sure you're using the App Password, not your Gmail password
- Remove all spaces from the app password
- Check that EMAIL_USER matches the Gmail account that generated the app password

**Outlook:**
- Use your actual account password
- Check if Microsoft blocked the login attempt (check your email for security alerts)
- Enable less secure app access if needed

#### "Connection timeout" or "ETIMEDOUT"

- Check your firewall settings
- Verify port 587 is not blocked
- Try using port 465 with `secure: true` (see advanced configuration below)
- Check your internet connection

#### Emails not being sent

1. Check server logs for error messages:
   ```bash
   LOG_LEVEL=debug npm run dev
   ```

2. Verify EMAIL_ENABLED is set to `true`

3. Test with the simplest configuration first (Gmail with app password)

4. Check spam folder - test emails often end up there

#### "Greeting never received" error

- Try changing EMAIL_PORT from 587 to 465
- Add `secure: true` to your configuration (see advanced section)

### Advanced Configuration

For more control over email settings, you can modify `server/controllers/app.controller.js`:

```javascript
// Example: Using SSL (port 465)
const transporter = nodemailer.createTransporter({
    host: process.env.EMAIL_HOST,
    port: 465,  // SSL port
    secure: true,  // Use SSL
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});
```

### Email Templates

The application includes pre-built Handlebars email templates:

- `welcome.hbs` - New user welcome email
- `email-verification.hbs` - Email verification with token
- `password-reset.hbs` - Password reset instructions
- `password-changed.hbs` - Password change confirmation
- `security-alert.hbs` - Suspicious login alerts

Templates are located in `server/templates/emails/` and can be customized to match your brand.

### Testing Templates

Preview email templates without sending:

```bash
POST http://localhost:8080/api/v1/email/template/render
Content-Type: application/json

{
  "template": "welcome",
  "data": {
    "firstName": "John",
    "email": "john@example.com",
    "appName": "App Base",
    "appUrl": "http://localhost:8080"
  }
}
```

### Production Recommendations

For production deployment:

1. **Use a dedicated email service** (SendGrid, Mailgun, Amazon SES)
2. **Verify your domain** to improve deliverability
3. **Set up SPF and DKIM** records for your domain
4. **Monitor email bounce rates** and unsubscribes
5. **Use environment-specific APP_URL** for links in emails
6. **Implement rate limiting** for email endpoints
7. **Log all email sends** for audit trails

### Skipping Email Configuration

If you don't need email functionality during development:

```bash
EMAIL_ENABLED=false
```

The application will function normally, but features requiring email (verification, password reset) will be disabled.

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
5. **verbose** (🔍) - Detailed information useful for development
6. **debug** (🔵 ✨) - Detailed debugging information for troubleshooting
7. **silly** (🧐) - Extremely verbose diagnostic information

Setting `LOG_LEVEL=info` shows info, warn, and error logs. Setting `LOG_LEVEL=debug` shows all logs except silly.

### Logging Features

- **Colorized Console**: Beautiful colored output with emojis and formatting
- **Database Persistence**: HTTP requests automatically stored in MongoDB
- **Request Logging**: Comprehensive request/response logging with timing
- **Log Aggregation**: Query and analyze logs through API endpoints

### Log Types

**HTTP Requests**: Traditional REST API calls logged with method-specific icons
```
📡 HTTP GET /api/v1/users 200 ✅ 45.23ms [ObjectId]
```

### Log Configuration
```bash
LOG_LEVEL=http          # Set minimum log level (error, warn, info, http, verbose, debug, silly)
```

## 🚀 API Documentation

### Authentication Endpoints
```http
GET  /api/v1/auth/csrf-token      # Get a fresh CSRF token
POST /api/v1/auth/signup          # Register new user
POST /api/v1/auth/login           # User login with credentials
POST /api/v1/auth/refresh-token   # Refresh access token (rotation + reuse detection)
GET  /api/v1/auth/ws-token        # Short-lived token for WebSocket auth
POST /api/v1/auth/logout          # Secure logout (blacklist tokens)
GET  /api/v1/auth/me              # Get current user profile
GET  /api/v1/auth/devices         # List known devices for the user
POST /api/v1/auth/forgot-password # Request password reset
POST /api/v1/auth/reset-password/:token # Reset password with token

# Two-Factor Authentication
POST /api/v1/auth/2fa/setup        # Setup 2FA with QR code
POST /api/v1/auth/2fa/verify-setup # Verify token and enable 2FA
POST /api/v1/auth/2fa/disable      # Disable 2FA
GET  /api/v1/auth/2fa/status       # Get 2FA status
POST /api/v1/auth/2fa/backup-codes # Generate new backup codes

# Email Verification
POST /api/v1/auth/send-verification-email # Send verification email
GET  /api/v1/auth/verify-email/:token     # Verify email with token

# Role Management
POST /api/v1/auth/roles/request-elevation  # Request a role elevation
POST /api/v1/auth/roles/approve/:userId    # Approve role request (owner only)
POST /api/v1/auth/roles/reject/:userId     # Reject role request (owner only)
GET  /api/v1/auth/roles/pending-requests   # List pending requests (owner only)
```

### User Management
```http
GET    /api/v1/users              # Get all users (admin only)
POST   /api/v1/users              # Create user (admin only)
GET    /api/v1/users/public       # Public user directory (limited fields)
GET    /api/v1/users/stats/overview # User overview stats (admin only)
GET    /api/v1/users/:id          # Get specific user
PUT    /api/v1/users/:id          # Update user profile
DELETE /api/v1/users/:id          # Delete user
PUT    /api/v1/users/:id/password # Change password
GET    /api/v1/users/:id/stats    # Get user statistics
GET    /api/v1/users/:id/stats/fields?fields=a.b,c.d # Select specific stat fields
```

### Connections (LinkedIn-style)
```http
POST   /api/v1/users/:id/connect            # Send connection request
PUT    /api/v1/users/:id/connect            # Accept/reject a request
DELETE /api/v1/users/:id/connect            # Remove connection / cancel request
GET    /api/v1/users/connections/pending    # Incoming pending requests
GET    /api/v1/users/connections/sent       # Sent outgoing requests
GET    /api/v1/users/:id/connections        # Connections list
GET    /api/v1/users/:id/connection-counts  # Connection counts
GET    /api/v1/users/:id/connection-status  # Status between you and :id
```

### Themes
```http
GET    /api/v1/themes/presets     # Built-in preset themes (public)
GET    /api/v1/themes/public      # Public theme gallery (public, filterable)
GET    /api/v1/themes             # Get own themes
POST   /api/v1/themes             # Create theme (CREATOR and above)
GET    /api/v1/themes/:id         # Get single theme (visibility enforced)
PUT    /api/v1/themes/:id         # Update theme (owner or MANAGE_ALL_CONTENT)
DELETE /api/v1/themes/:id         # Delete theme (owner or MANAGE_ALL_CONTENT)
POST   /api/v1/themes/:id/fork    # Fork a theme (CREATOR and above)
```

### Cache Management
```http
GET    /api/v1/cache/stats        # Cache statistics (admin)
DELETE /api/v1/cache              # Clear cache (admin)
GET    /api/v1/cache/cleanup      # Cleanup service status (admin)
POST   /api/v1/cache/cleanup      # Trigger manual cleanup (admin)
GET    /api/v1/cache/health       # Cache health check (admin)
```

### Application Management
```http
GET    /api/v1/health             # Health check
POST   /api/v1/contact            # Contact form submission (public)
GET    /api/v1/stats/overview     # System statistics (admin)
GET    /api/v1/stats/performance  # Performance statistics (admin)
GET    /api/v1/logs               # Application logs (admin, filterable)
GET    /api/v1/logs/stats         # Log statistics (admin, optional userId)
GET    /api/v1/logs/:id           # Single log entry (admin)
DELETE /api/v1/logs               # Clear logs (admin)

# Email Testing (Admin)
POST   /api/v1/email/template/render # Preview email template
POST   /api/v1/email/test         # Send test email
```

### Query Parameters

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
npm test           # Run test suite with Vitest
```

### Project Structure
```
server/
├── config/          # Database, rights, and taxonomy configuration
│   ├── db.js            # MongoDB connection utilities
│   ├── disciplines.js   # Creative discipline taxonomy + media block types
│   └── rights.js        # User roles and permissions system
├── controllers/     # Request handlers and business logic
│   ├── app.controller.js    # Health, stats, logs, email, contact, themes
│   ├── auth.controller.js   # Authentication, 2FA, email verification, roles
│   ├── cache.controller.js  # Cache management and cleanup service
│   └── user.controller.js   # User management and connections
├── middleware/      # Express middleware functions
│   ├── app.middleware.js      # Core middleware, Redis client, route allowlist
│   ├── auth.middleware.js     # JWT, CSRF, permission checking, WS auth
│   ├── cache.middleware.js    # Response caching and invalidation
│   ├── error.middleware.js    # Global error handling (AppError)
│   ├── user.middleware.js     # User validation, devices, stats filters
│   └── validation.middleware.js # Request validation with Joi
├── models/          # MongoDB schemas and data models
│   ├── log.model.js    # Request logging schema
│   ├── schemas.js      # Joi validation schemas
│   ├── theme.model.js  # Dynamic theme token documents
│   └── user.model.js   # User schema (roles, 2FA, devices) + Connection
├── routes/          # API route definitions
│   ├── app.routes.js    # System routes (health, logs, email, stats, themes)
│   ├── auth.routes.js   # Authentication endpoints
│   ├── cache.routes.js  # Cache management endpoints
│   └── user.routes.js   # User management and connection endpoints
├── templates/       # Email templates (Handlebars)
│   └── emails/      # Email template files
├── utils/           # Utility functions and helpers
│   ├── app.logger.js  # Winston logging with colorized output
│   ├── sanitize.js    # HTML sanitization utilities
│   └── validator.js   # Custom validation functions
├── .env.example     # Environment variables template
├── index.js         # Application entry point
├── server.js        # Server class (lifecycle, env validation, route registration)
└── package.json     # Dependencies and npm scripts
```

### Key Features Implementation

#### Caching Strategy  
- Response caching with automatic invalidation
- Entity-based cache keys with dependency tracking
- TTL-based expiration with cleanup service
- Cache warming for frequently accessed data

#### Role Elevation Flow
- Any authenticated user can request elevated roles
- Requests are queued as pending until the OWNER approves or rejects
- Elevated roles (anything above USER) always require owner approval

## 🚢 Production Deployment

### Pre-Deployment Checklist

Before deploying to production, ensure:

- ✅ Strong JWT secrets are generated (not the example ones!)
- ✅ `NODE_ENV=production` in your environment
- ✅ MongoDB Atlas cluster is configured with proper network access
- ✅ Email service is set up and tested
- ✅ CORS origins include your production frontend domain
- ✅ LOG_LEVEL is set to `warn` or `error` (not `debug`)
- ✅ Redis is configured for caching (highly recommended)
- ✅ All sensitive data is in environment variables (not hardcoded)

### Performance Recommendations

1. **MongoDB Optimization**:
   - Use MongoDB Atlas or properly configured replica set
   - Enable connection pooling
   - Create appropriate indexes for user and log queries

2. **Redis Optimization**:
   - Configure memory limits and eviction policies
   - Use Redis persistence for important cache data
   - Monitor Redis memory usage
   - Set up Redis clustering for high availability

3. **Security Hardening**:
   - Use HTTPS/TLS in production
   - Configure proper CORS origins
   - Enable rate limiting for API and auth endpoints
   - Regular security updates and dependency scanning

4. **Monitoring & Observability**:
   - Set up log aggregation with structured logging
   - Monitor application metrics
   - Configure health check endpoints

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

#### Troubleshooting Common Issues

For troubleshooting any server problems, refer to the [Logging System](#-logging-system) section and set `LOG_LEVEL=debug` as described there.

For detailed troubleshooting guides, see:
- [MongoDB Troubleshooting](https://www.mongodb.com/docs/manual/faq/diagnostics/)
- [Redis Troubleshooting](https://redis.io/docs/getting-started/faq/)
- [Node.js Troubleshooting](https://nodejs.org/en/docs/guides/debugging-getting-started)

## 📄 License

See [LICENSE.md](./LICENSE.md) for license information.

---

**Built with ❤️ using Node.js, Express, MongoDB, and Redis**
