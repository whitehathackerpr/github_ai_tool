# GitHub AI Tool

A powerful AI-powered tool for GitHub integration that provides repository analysis, code review assistance, documentation generation, and issue/PR summarization.

## Features

- **Repository Analysis**: Get AI-powered insights about your code repositories
- **Code Review Assistance**: Receive automated code review suggestions
- **Documentation Generation**: Generate documentation from your code
- **Issue and PR Summarization**: Summarize lengthy GitHub issues and PRs

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/github_ai_tool.git
cd github_ai_tool

# Create a virtual environment (optional)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Configuration

1. Register a new OAuth application on GitHub:
   - Go to GitHub Settings > Developer settings > OAuth Apps > New OAuth App
   - Set the callback URL to `http://localhost:8000/auth/callback` for local development
   - Note down the Client ID and Client Secret

2. Create a `.env` file in the project root with the following:
```
GITHUB_CLIENT_ID=your_client_id_here
GITHUB_CLIENT_SECRET=your_client_secret_here
SECRET_KEY=random_secret_key_for_jwt
```

## Usage

Start the application:

```bash
uvicorn app.main:app --reload
```

Then navigate to `http://localhost:8000` in your web browser.

## API Endpoints

- `/auth/login` - GitHub OAuth login
- `/auth/callback` - OAuth callback handler
- `/repos/analyze` - Analyze repository structure
- `/repos/review` - AI-powered code review
- `/repos/documentation` - Generate documentation
- `/repos/issues/summarize` - Summarize issues and PRs

## Development

This project follows a standard Python project structure:
- `app/` - Main application code
- `tests/` - Unit and integration tests
- `config/` - Configuration files

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

