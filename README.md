# GitHub AI Tool

A powerful AI-powered tool for GitHub integration that provides repository analysis, code review assistance, documentation generation, dependency analysis, security scanning, and template generation.

## Features

- **Repository Analysis**: Get AI-powered insights about your code repositories
- **Code Quality Checker**: Receive automated code quality checks and recommendations
- **Security Scanner**: Identify security vulnerabilities in your code
- **Dependency Analyzer**: Analyze project dependencies and get update suggestions
- **Documentation Generation**: Generate documentation from your code
- **Template Generator**: Create PR/Issue templates and contributing guides using AI
- **Issue and PR Summarization**: Summarize lengthy GitHub issues and PRs

## System Requirements

- Python 3.8 or higher
- Redis (for caching)
- Node.js (for JavaScript analysis)
- The following tools (installed by the setup script):
  - flake8 and bandit (for Python code analysis)
  - eslint (for JavaScript code analysis)

## Quick Start

The easiest way to get started is to use the provided setup script:

```bash
# Clone the repository
git clone https://github.com/whitehathackerpr/github_ai_tool.git
cd github_ai_tool

# Run the setup script
chmod +x setup.sh
./setup.sh

# Start the application
source venv/bin/activate  # If not already activated
python -m app.main
```

### Using Docker

You can also use Docker to run the application without installing dependencies locally:

```bash
# Clone the repository
git clone https://github.com/whitehathackerpr/github_ai_tool.git
cd github_ai_tool

# Copy the example environment file and edit it
cp .env.example .env
# Edit the .env file with your settings

# Build and start the development environment
docker-compose up --build

# Access the application at http://localhost:8000
```

## Manual Installation

If you prefer to set up manually:

```bash
# Clone the repository
git clone https://github.com/yourusername/github_ai_tool.git
cd github_ai_tool

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install Python dependencies
pip install -r requirements.txt

# Install system dependencies
# For Ubuntu/Debian:
sudo apt-get update
sudo apt-get install -y redis-server npm python3-dev
pip install flake8 bandit
sudo npm install -g eslint

# Create necessary directories
mkdir -p tmp/repos

# Create .env file from example
cp .env.example .env
# Edit the .env file with your configuration
```

## Configuration

1. Register a new OAuth application on GitHub:
   - Go to GitHub Settings > Developer settings > OAuth Apps > New OAuth App
   - Application name: GitHub AI Tool
   - Homepage URL: http://localhost:8000
   - Authorization callback URL: http://localhost:8000/auth/callback
   - Note down the Client ID and Client Secret

2. Get an OpenAI API key:
   - Go to https://platform.openai.com/api-keys
   - Create a new API key

3. Edit the `.env` file with your settings:
```
# Required settings
GITHUB_CLIENT_ID=your_client_id_here
GITHUB_CLIENT_SECRET=your_client_secret_here
OPENAI_API_KEY=your_openai_api_key_here
SECRET_KEY=random_secure_string_here

# Optional settings
DEBUG=False
PORT=8000
REDIS_HOST=localhost
```

## Usage

Start the application:

```bash
# With activated virtual environment
python -m app.main
```

Then navigate to:
- API Documentation: http://localhost:8000/docs
- Authentication: http://localhost:8000/auth/login
- Health Check: http://localhost:8000/health

## API Endpoints

### Authentication Endpoints
- `POST /token` - Get an access token using username/password
- `GET /auth/login` - GitHub OAuth login
- `GET /auth/callback` - OAuth callback handler

### Repository Analysis
- `POST /api/repos/analyze` - Analyze repository structure

### Code Quality
- `POST /api/code/quality` - Check code quality

### Security Scanning
- `POST /api/security/scan` - Scan code for security vulnerabilities

### Dependency Analysis
- `POST /api/dependencies/analyze` - Analyze project dependencies
- `POST /api/dependencies/suggestions` - Get dependency update suggestions

### Template Generation
- `POST /api/templates/generate` - Generate GitHub templates (PR, issue, contributing)

### Health Check
- `GET /health` - Check application health

## Development

This project follows a standard Python project structure:
- `app/` - Main application code
  - `app/services/` - Core service modules
  - `app/config.py` - Application configuration
  - `app/main.py` - FastAPI application and routes
- `tests/` - Unit and integration tests

## Troubleshooting

### Redis Not Running
If Redis is not running, start it with:
```bash
# On Linux
sudo systemctl start redis
# OR
sudo service redis-server start

# On macOS
brew services start redis
```

### Dependency Issues
If you encounter issues with dependencies, ensure you have the correct Python version and all system dependencies installed:
```bash
python --version  # Should be 3.8+
pip install -r requirements.txt
which flake8 bandit  # Should return paths
which eslint  # Should return path
```

## Docker Support

### Development Environment

To run the application in development mode:

```bash
# Build and start the development environment
docker-compose up --build

# Run tests
docker-compose run tests
```

### Production Environment

To run the application in production mode:

```bash
# Build and start the production environment
docker-compose -f docker-compose.prod.yml up --build -d

# Scale the web service (optional)
docker-compose -f docker-compose.prod.yml up --scale web=3

# View logs
docker-compose -f docker-compose.prod.yml logs -f
```

### Docker Commands

Common Docker commands:

```bash
# Stop all containers
docker-compose down

# View container logs
docker-compose logs -f [service_name]

# Execute commands in a container
docker-compose exec web python -m pytest

# Remove all containers and volumes
docker-compose down -v
```

### Docker Troubleshooting

Common issues and solutions:

1. **Redis Connection Issues**
   - Check if Redis container is running: `docker-compose ps`
   - Verify Redis logs: `docker-compose logs redis`
   - Ensure REDIS_PASSWORD matches in .env and docker-compose files

2. **Permission Issues**
   - All containers run as non-root users for security in production
   - Volume permissions might need adjustment on the host

3. **Performance Issues**
   - Check container resources: `docker stats`
   - Adjust worker count in production compose file
   - Monitor Redis memory usage

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the project
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)

