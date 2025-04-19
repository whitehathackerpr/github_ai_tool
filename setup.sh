#!/bin/bash

# GitHub AI Tool Setup Script
# This script sets up the necessary dependencies and environment for the GitHub AI Tool

set -e  # Exit on error
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}==== GitHub AI Tool Setup ====${NC}"
echo "This script will set up the required dependencies and environment."

# Check operating system
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="Linux"
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$NAME
    fi
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macOS"
else
    echo -e "${RED}Unsupported operating system: $OSTYPE${NC}"
    echo "This script supports Linux and macOS. For Windows, please follow the manual setup instructions in the README."
    exit 1
fi

echo -e "${GREEN}Detected operating system: $OS${NC}"
if [ "$OS" == "Linux" ]; then
    echo -e "Distribution: $DISTRO"
fi

# Check if Python is installed
echo -e "\n${GREEN}Checking Python installation...${NC}"
if command -v python3 &>/dev/null; then
    PYTHON_VERSION=$(python3 --version | awk '{print $2}')
    echo -e "Python $PYTHON_VERSION is installed."
    if [[ "${PYTHON_VERSION:0:1}" -lt 3 || ("${PYTHON_VERSION:0:1}" -eq 3 && "${PYTHON_VERSION:2:1}" -lt 8) ]]; then
        echo -e "${YELLOW}Warning: Python 3.8 or higher is recommended.${NC}"
    fi
else
    echo -e "${RED}Python not found. Please install Python 3.8 or higher.${NC}"
    exit 1
fi

# Check/create virtual environment
echo -e "\n${GREEN}Setting up virtual environment...${NC}"
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
    echo -e "${GREEN}Virtual environment created.${NC}"
else
    echo "Virtual environment already exists."
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate
echo -e "${GREEN}Virtual environment activated.${NC}"

# Install Python dependencies
echo -e "\n${GREEN}Installing Python dependencies...${NC}"
pip install --upgrade pip
pip install -r requirements.txt
echo -e "${GREEN}Python dependencies installed.${NC}"

# Install system-level dependencies
echo -e "\n${GREEN}Installing system-level dependencies...${NC}"

if [ "$OS" == "Linux" ]; then
    # Linux installation
    if [[ "$DISTRO" == "Ubuntu"* || "$DISTRO" == "Debian"* ]]; then
        echo "Installing dependencies using apt..."
        sudo apt-get update
        sudo apt-get install -y redis-server npm python3-dev
        
        # Install code analysis tools
        pip install flake8 bandit
        
        # Install eslint globally
        sudo npm install -g eslint
    elif [[ "$DISTRO" == "Fedora"* || "$DISTRO" == "CentOS"* || "$DISTRO" == "Red Hat"* ]]; then
        echo "Installing dependencies using dnf/yum..."
        sudo dnf install -y redis nodejs python3-devel || sudo yum install -y redis nodejs python3-devel
        
        # Install code analysis tools
        pip install flake8 bandit
        
        # Install eslint globally
        sudo npm install -g eslint
    else
        echo -e "${YELLOW}Unsupported Linux distribution: $DISTRO${NC}"
        echo "Please install Redis, npm, and Python development packages manually."
        echo "Then run: pip install flake8 bandit && npm install -g eslint"
    fi
elif [ "$OS" == "macOS" ]; then
    # macOS installation
    if command -v brew &>/dev/null; then
        echo "Installing dependencies using Homebrew..."
        brew install redis node python
        
        # Start Redis
        brew services start redis
        
        # Install code analysis tools
        pip install flake8 bandit
        
        # Install eslint globally
        npm install -g eslint
    else
        echo -e "${YELLOW}Homebrew not found. Please install Homebrew first:${NC}"
        echo "https://brew.sh/"
        echo "Then run this script again."
        exit 1
    fi
fi

echo -e "${GREEN}System-level dependencies installed.${NC}"

# Create necessary directories
echo -e "\n${GREEN}Creating necessary directories...${NC}"
mkdir -p tmp/repos
echo -e "${GREEN}Directories created.${NC}"

# Create .env file from example if it doesn't exist
echo -e "\n${GREEN}Setting up environment variables...${NC}"
if [ ! -f ".env" ]; then
    cp .env.example .env
    echo -e "${GREEN}.env file created from example.${NC}"
    echo -e "${YELLOW}Please edit the .env file to set your GitHub OAuth credentials and other settings.${NC}"
else
    echo ".env file already exists."
fi

# Check Redis
echo -e "\n${GREEN}Checking Redis...${NC}"
if command -v redis-cli &>/dev/null; then
    REDIS_PING=$(redis-cli ping 2>/dev/null)
    if [[ "$REDIS_PING" == "PONG" ]]; then
        echo -e "${GREEN}Redis is running.${NC}"
    else
        echo -e "${YELLOW}Redis is installed but not running. Starting Redis...${NC}"
        if [ "$OS" == "Linux" ]; then
            sudo systemctl start redis || sudo service redis-server start
        elif [ "$OS" == "macOS" ]; then
            brew services start redis
        fi
        
        # Check again
        REDIS_PING=$(redis-cli ping 2>/dev/null)
        if [[ "$REDIS_PING" == "PONG" ]]; then
            echo -e "${GREEN}Redis is now running.${NC}"
        else
            echo -e "${YELLOW}Redis could not be started automatically. Please start it manually.${NC}"
        fi
    fi
else
    echo -e "${YELLOW}Redis CLI not found. Make sure Redis is installed and running.${NC}"
fi

# GitHub OAuth setup instructions
echo -e "\n${GREEN}==== GitHub OAuth Setup Instructions ====${NC}"
echo -e "To enable GitHub integration, you need to register an OAuth application:"
echo -e "1. Go to ${YELLOW}https://github.com/settings/developers${NC}"
echo -e "2. Click on 'New OAuth App'"
echo -e "3. Fill in the following details:"
echo -e "   - Application name: GitHub AI Tool"
echo -e "   - Homepage URL: http://localhost:8000"
echo -e "   - Authorization callback URL: http://localhost:8000/auth/callback"
echo -e "4. Click 'Register application'"
echo -e "5. On the next page, note your Client ID"
echo -e "6. Click 'Generate a new client secret' and note the secret"
echo -e "7. Update your .env file with these values:"
echo -e "   GITHUB_CLIENT_ID=your_client_id"
echo -e "   GITHUB_CLIENT_SECRET=your_client_secret"

# OpenAI API key instructions
echo -e "\n${GREEN}==== OpenAI API Setup Instructions ====${NC}"
echo -e "For AI-powered features, you need an OpenAI API key:"
echo -e "1. Go to ${YELLOW}https://platform.openai.com/api-keys${NC}"
echo -e "2. Create a new API key"
echo -e "3. Update your .env file with:"
echo -e "   OPENAI_API_KEY=your_api_key"

# Final instructions
echo -e "\n${GREEN}==== Setup Complete ====${NC}"
echo -e "To start the application, run:"
echo -e "${YELLOW}source venv/bin/activate${NC} (if not already activated)"
echo -e "${YELLOW}python -m app.main${NC}"
echo -e "\nThe API will be available at http://localhost:8000"
echo -e "API documentation: http://localhost:8000/docs"
echo -e "\n${GREEN}For more details, refer to the README.md file.${NC}"

