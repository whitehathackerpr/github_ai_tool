import os
import logging
import re
from typing import Dict, Any, List, Optional
import json
from app.services.ai_service import AIService

logger = logging.getLogger(__name__)

class TemplateGenerator:
    """Generate templates for PRs, issues, and other GitHub documents using AI."""
    
    def __init__(self):
        """Initialize template generator."""
        self.ai_service = AIService()
    
    async def generate_pr_template(self, repo_name: str, repo_description: str, repo_type: str = None) -> str:
        """Generate a PR template based on repository information."""
        try:
            Create a detailed GitHub issue template for a {issue_type} report in a repository named {repo_name}.
            
            Repository description: {repo_description}
            
            The issue template should include:
            1. A clear title section
            2. A description of the issue or feature request
            3. Steps to reproduce (for bugs)
            4. Expected behavior
            5. Actual behavior (for bugs)
            6. Screenshots or examples (if applicable)
            7. Environment information (OS, browser, etc. for bugs)
            8. Additional context
            
            Format the template using Markdown and make it specific to the repository's domain and purpose.
            Only return the template content, without any explanation.
            """
            
            result = await self.ai_service.generate_text(
                prompt_template=prompt_template,
                repo_name=repo_name,
                repo_description=repo_description,
                issue_type=issue_type
            )
            
            return result
        except Exception as e:
            logger.error(f"Failed to generate issue template: {str(e)}")
            return self._get_fallback_issue_template(repo_name, issue_type)
    
    async def generate_contributing_guide(self, repo_name: str, repo_description: str) -> str:
        """Generate a CONTRIBUTING.md guide based on repository information."""
        try:
            prompt_template = """
            Create a comprehensive CONTRIBUTING.md guide for a GitHub repository named {repo_name}.
            
            Repository description: {repo_description}
            
            The contributing guide should include:
            1. Introduction and welcome message
            2. Code of conduct reference
            3. Getting started with development
            4. How to submit changes (PR process)
            5. Coding standards and style guide
            6. Testing requirements
            7. How to report bugs
            8. Community and communication channels
            
            Format the guide using Markdown and make it specific to the repository's domain and purpose.
            Only return the guide content, without any explanation.
            """
            
            result = await self.ai_service.generate_text(
                prompt_template=prompt_template,
                repo_name=repo_name,
                repo_description=repo_description
            )
            
            return result
        except Exception as e:
            logger.error(f"Failed to generate contributing guide: {str(e)}")
            return self._get_fallback_contributing_guide(repo_name)
    
    def _get_fallback_pr_template(self, repo_name: str) -> str:
        """Return a fallback PR template when AI generation fails."""
        return f"""# Pull Request for {repo_name}

## Description
<!-- Provide a brief description of the changes made in this PR -->

## Type of change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## How Has This Been Tested?
<!-- Describe the tests you ran to verify your changes -->

## Checklist:
- [ ] My code follows the style guidelines of this project
- [ ] I have performed a self-review of my own code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have made corresponding changes to the documentation
- [ ] My changes generate no new warnings
- [ ] I have added tests that prove my fix is effective or that my feature works
- [ ] New and existing unit tests pass locally with my changes

## Screenshots (if applicable)
<!-- Add screenshots here -->

## Related Issues
<!-- Reference any related issues here -->
"""
    
    def _get_fallback_issue_template(self, repo_name: str, issue_type: str) -> str:
        """Return a fallback issue template when AI generation fails."""
        if issue_type.lower() == "feature":
            return f"""# Feature Request for {repo_name}

## Description
<!-- Describe the feature you'd like to see implemented -->

## Problem It Solves
<!-- Explain what problem this feature would solve -->

## Proposed Solution
<!-- If you have ideas on how to implement this feature, describe them here -->

## Alternatives Considered
<!-- Describe any alternative solutions or features you've considered -->

## Additional Context
<!-- Add any other context, screenshots, or examples about the feature request here -->
"""
        else:  # Default to bug report
            return f"""# Bug Report for {repo_name}

## Description
<!-- Provide a clear and concise description of the bug -->

## Steps To Reproduce
1. <!-- First step -->
2. <!-- Second step -->
3. <!-- And so on... -->

## Expected Behavior
<!-- What you expected to happen -->

## Actual Behavior
<!-- What actually happened -->

## Screenshots
<!-- If applicable, add screenshots to help explain your problem -->

## Environment
- OS: <!-- e.g. iOS, Windows -->
- Browser: <!-- e.g. Chrome, Safari -->
- Version: <!-- e.g. 22 -->

## Additional Context
<!-- Add any other context about the problem here -->
"""
    
    def _get_fallback_contributing_guide(self, repo_name: str) -> str:
        """Return a fallback contributing guide when AI generation fails."""
        return f"""# Contributing to {repo_name}

Thank you for considering contributing to {repo_name}!

## Code of Conduct

Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## How Can I Contribute?

### Reporting Bugs

This section guides you through submitting a bug report. Following these guidelines helps maintainers and the community understand your report, reproduce the behavior, and find related reports.

Before creating bug reports, please check the issue tracker as you might find out that you don't need to create one. When you are creating a bug report, please include as many details as possible.

### Suggesting Enhancements

This section guides you through submitting an enhancement suggestion, including completely new features and minor improvements to existing functionality.

### Pull Requests

- Fill in the required template
- Do not include issue numbers in the PR title
- Include screenshots and animated GIFs in your pull request whenever possible
- Follow the style guidelines
- End all files with a newline

## Style Guidelines

### Git Commit Messages

* Use the present tense ("Add feature" not "Added feature")
* Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
* Limit the first line to 72 characters or less
* Reference issues and pull requests liberally after the first line

### JavaScript Style Guide

* Use 2 spaces for indentation
* Use semicolons
* Use single quotes

### Python Style Guide

* Follow PEP 8
* Use 4 spaces for indentation

## Additional Notes

### Issue and Pull Request Labels

This section lists the labels we use to help us track and manage issues and pull requests.
"""
            1. A clear title section
            2. A description of changes
            3. Type of change (bug fix, feature, breaking change, etc.)
            4. Checklist of items to be completed before merging
            5. Testing instructions
            6. Screenshots section (if applicable)
            7. Any relevant issue numbers
            
            Format the template using Markdown and make it specific to the repository's domain and purpose.
            Only return the template content, without any explanation.
            """
            
            result = await self.ai_service.generate_text(
                prompt_template=prompt_template,
                repo_name=repo_name,
                repo_description=repo_description,
                repo_type=repo_type or "Not specified"
            )
            
            return result
        except Exception as e:
            logger.error(f"Failed to generate PR template: {str(e)}")
            return self._get_fallback_pr_template(repo_name)
    
    async def generate_issue_template(self, repo_name: str, repo_description: str, issue_type: str = "bug") -> str:
        """Generate an issue template based on repository information and issue type."""
        try:
            prompt_template = """
            Create a detailed GitHub issue template for a {issue_type} report in a repository named {repo_name}.
            
            Repository description: {repo_description}
            
            The issue template should include:
            1. A clear title section
            

