# App Base Server

A robust Node.js server with Express, MongoDB, and JWT authentication.

## Features

- **Authentication**: Complete JWT auth system with access and refresh tokens
- **User Management**: CRUD operations for user accounts
- **File System**: Advanced file management with version control, auto-save, and Redis caching
- **Role-Based Permissions**: Hierarchical role system with granular permissions
- **Validation**: Request validation with Joi
- **Security**: Implementation of best practices for API security
- **Error Handling**: Comprehensive error handling and logging

## Requirements

- Node.js 18+ 
- MongoDB 5+
- npm or yarn

## Quick Start

1. Clone the repository
2. Install dependencies
3. Configure environment variables
4. Start the server

```bash
npm install
npm run dev
```

## Environment Setup

Create a `.env` file in the server directory. The following variables are **required**:

```bash
# Server Configuration (Required)
PORT=8080                                     # Server port
NODE_ENV=development                          # Environment (development/production/test)
MONGODB_URI=mongodb://localhost:27017/app-base-db  # MongoDB connection URI
ALLOWED_ORIGINS=http://localhost:8080,http://localhost:8083  # CORS allowed origins

# Authentication (Required)
ACCESS_TOKEN_SECRET=your_access_token_secret   # JWT access token secret
REFRESH_TOKEN_SECRET=your_refresh_token_secret # JWT refresh token secret
ACCESS_TOKEN_EXPIRY=15m                       # JWT access token expiry
REFRESH_TOKEN_EXPIRY=7d                       # JWT refresh token expiry

# Logging Configuration (Optional)
LOG_LEVEL=info                                # Log level (error, warn, info, http, debug)
LOG_REQUESTS=true                             # Enable HTTP request logging
LOG_OVERRIDE=true                             # Redirect console methods to Winston
```

To generate secure random tokens for JWT:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

## Logging System

The server uses Winston for structured logging with customizable log levels:

### Log Levels (in order of priority)

1. **error** (highest priority)
   - Critical failures requiring immediate attention
   - Displayed with red background (🔴) and ❌ icon
   - Example: Database connection failures, unhandled exceptions

2. **warn**
   - Concerning issues that aren't critical failures
   - Displayed with yellow background (🟡) and ⚠️ icon
   - Example: Deprecated feature usage, validation warnings

3. **info** (default)
   - General operational information
   - Displayed with green background (🟢) and ℹ️ icon
   - Example: Server startup, successful connections

4. **http**
   - HTTP request/response logging
   - Displayed with magenta color (🟣) and 📡 icon
   - HTTP methods have specific icons: GET (🔍), POST (📤), PUT (📝), etc.

5. **debug** (lowest priority)
   - Detailed debugging information for troubleshooting
   - Displayed with cyan color (🔵) and ✨ icon
   - Example: Variable values, function call traces

Setting a log level in `.env` displays that level and all higher priority levels. For instance, setting `LOG_LEVEL=info` will show error, warn, and info logs, but not http or debug logs.

### Additional Logging Features

- **Console Override**: When `LOG_OVERRIDE=true`, standard console methods are redirected to Winston
- **HTTP Logging**: Set `LOG_REQUESTS=true` to log detailed information about HTTP requests
- **Database Logging**: HTTP logs are stored in MongoDB for audit purposes

## MongoDB Setup

### Installation

#### Windows
1. Download MongoDB Community Server from [MongoDB website](https://www.mongodb.com/try/download/community)
2. Run installer and follow the prompts
3. Choose "Complete" installation
4. Check "Install MongoDB as a Service"

#### macOS
```bash
brew tap mongodb/brew
brew install mongodb-community
```

#### Linux (Ubuntu)
```bash
wget -qO - https://www.mongodb.org/static/pgp/server-5.0.asc | sudo apt-key add -
echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/5.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-5.0.list
sudo apt update
sudo apt install -y mongodb-org
sudo systemctl start mongod
sudo systemctl enable mongod
```

### Setting up MongoDB Compass

1. Download MongoDB Compass from [MongoDB Compass website](https://www.mongodb.com/products/compass)
2. Install MongoDB Compass
3. Open MongoDB Compass
4. Connect to your MongoDB instance:
   - For local development, use: `mongodb://localhost:27017`
   - For remote instances, use the connection string from your MongoDB provider

### Creating the Database

1. In MongoDB Compass, click "Create Database"
2. Enter database name: `app-base-db`
3. Create an initial collection: `users`

### Database Connection

1. Ensure your `.env` file has the correct `MONGODB_URI` pointing to your database
2. The server will automatically connect to the database on startup
3. Check the console logs for successful connection

## API Routes

### Authentication
- `POST /api/v1/auth/signup` - Register a new user
- `POST /api/v1/auth/login` - Authenticate a user
- `POST /api/v1/auth/refresh-token` - Refresh the access token
- `GET /api/v1/auth/me` - Get the current user's profile
- `POST /api/v1/auth/forgot-password` - Request a password reset
- `POST /api/v1/auth/reset-password/:token` - Reset password with token

### User Management
- `GET /api/v1/users` - Get all users (admin only)
- `GET /api/v1/users/:id` - Get a specific user
- `POST /api/v1/users` - Create a new user (admin only)
- `PUT /api/v1/users/:id` - Update a user
- `DELETE /api/v1/users/:id` - Delete a user
- `PATCH /api/v1/users/:id/change-password` - Change user password

### File System
- `GET /api/v1/files` - Get list of files with filtering and pagination
- `POST /api/v1/files` - Create a new file
- `GET /api/v1/files/:id` - Get file metadata
- `PUT /api/v1/files/:id` - Update file metadata
- `DELETE /api/v1/files/:id` - Delete file or specific version
- `GET /api/v1/files/:id/content` - Get file content
- `PUT /api/v1/files/:id/autosave` - Auto-save file content to cache
- `POST /api/v1/files/:id/save` - Save file content as new version
- `GET /api/v1/files/:id/versions` - Get all versions of a file
- `GET /api/v1/files/types` - Get supported file types

## Role-Based Permissions

The system includes five roles with hierarchical permissions:

1. `OWNER`: Can do everything including deleting users
2. `ADMIN`: Can do everything except deleting users
3. `SUPER_CREATOR`: Extended creation privileges
4. `CREATOR`: Basic creation privileges
5. `USER`: Can only manage their own account

## Development

Start the server in development mode:

```bash
npm run dev
```

## Production Deployment

For production deployment, update environment variables and start with:

```bash
NODE_ENV=production npm start
```

## Security Considerations

The server implements:
- CORS protection
- Rate limiting
- Data sanitization
- JWT authentication
- Password hashing
- Input validation
- Error handling

## Troubleshooting

### Connection Issues
- Verify MongoDB is running: `systemctl status mongod` (Linux) or through Services (Windows)
- Check MongoDB connection string in `.env`
- Ensure network allows connections to MongoDB port (27017 by default)

### Authentication Issues
- Verify token secrets in `.env`
- Check token expiration settings
- Clear cookies and local storage in browser

