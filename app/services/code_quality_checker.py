import os
import logging
import subprocess
import tempfile
from typing import Dict, Any, List, Optional
import re

logger = logging.getLogger(__name__)

class CodeQualityChecker:
    """Checks code quality using various linters and static analyzers."""
    
    def __init__(self):
        """Initialize code quality checker."""
        pass
    
    async def _run_flake8(self, file_path: str) -> Dict[str, Any]:
        """Run flake8 on a Python file."""
        try:
            # Check if flake8 is installed
            result = subprocess.run(['which', 'flake8'], capture_output=True, text=True)
            if result.returncode != 0:
                return {'error': 'flake8 not installed'}
            
            # Run flake8
            result = subprocess.run(['flake8', file_path], capture_output=True, text=True)
            
            issues = []
            if result.stdout:
                for line in result.stdout.splitlines():
                    parts = line.split(':', 3)
                    if len(parts) >= 4:
                        issues.append({
                            'line': int(parts[1]),
                            'column': int(parts[2]),
                            'message': parts[3].strip()
                        })
            
            return {
                'issues': issues,
                'count': len(issues)
            }
        except Exception as e:
            logger.error(f"Failed to run flake8: {str(e)}")
            return {'error': str(e)}
    
    async def _run_pylint(self, file_path: str) -> Dict[str, Any]:
        """Run pylint on a Python file."""
        try:
            # Check if pylint is installed
            result = subprocess.run(['which', 'pylint'], capture_output=True, text=True)
            if result.returncode != 0:
                return {'error': 'pylint not installed'}
            
            # Run pylint
            result = subprocess.run(
                ['pylint', '--output-format=json', file_path], 
                capture_output=True, 
                text=True
            )
            
            # Parse JSON output
            issues = []
            try:
                import json
                if result.stdout.strip():
                    pylint_issues = json.loads(result.stdout)
                    for issue in pylint_issues:
                        issues.append({
                            'line': issue.get('line', 0),
                            'column': issue.get('column', 0),
                            'message': issue.get('message', ''),
                            'symbol': issue.get('symbol', ''),
                            'type': issue.get('type', '')
                        })
            except json.JSONDecodeError:
                # Fallback to text parsing if JSON parsing fails
                if result.stdout:
                    for line in result.stdout.splitlines():
                        if ':' in line:
                            parts = line.split(':', 2)
                            if len(parts) >= 3:
                                issues.append({
                                    'line': 0,  # Can't determine from this format
                                    'column': 0,
                                    'message': parts[2].strip()
                                })
            
            score = 10.0  # Default score
            # Extract score from pylint output (typically in the format: "Your code has been rated at 7.50/10")
            for line in result.stderr.splitlines() + result.stdout.splitlines():
                if "Your code has been rated at" in line:
                    match = re.search(r'(\d+\.\d+)/10', line)
                    if match:
                        score = float(match.group(1))
            
            return {
                'issues': issues,
                'count': len(issues),
                'score': score
            }
        except Exception as e:
            logger.error(f"Failed to run pylint: {str(e)}")
            return {'error': str(e)}
    
    async def _run_eslint(self, file_path: str) -> Dict[str, Any]:
        """Run eslint on a JavaScript file."""
        try:
            # Check if eslint is installed
            result = subprocess.run(['which', 'eslint'], capture_output=True, text=True)
            if result.returncode != 0:
                return {'error': 'eslint not installed'}
            
            # Run eslint with JSON format
            result = subprocess.run(
                ['eslint', '--format=json', file_path], 
                capture_output=True, 
                text=True
            )
            
            # Parse JSON output
            issues = []
            try:
                import json
                if result.stdout.strip():
                    eslint_results = json.loads(result.stdout)
                    for file_result in eslint_results:
                        for message in file_result.get('messages', []):
                            issues.append({
                                'line': message.get('line', 0),
                                'column': message.get('column', 0),
                                'message': message.get('message', ''),
                                'rule': message.get('ruleId', ''),
                                'severity': message.get('severity', 1)
                            })
            except json.JSONDecodeError:
                logger.warning("Failed to parse ESLint JSON output")
            
            return {
                'issues': issues,
                'count': len(issues)
            }
        except Exception as e:
            logger.error(f"Failed to run eslint: {str(e)}")
            return {'error': str(e)}
    
    async def _analyze_complexity(self, code: str) -> Dict[str, Any]:
        """Analyze code complexity using simple heuristics."""
        try:
            # Count lines
            lines = code.splitlines()
            line_count = len(lines)
            
            # Count functions/methods
            function_pattern = re.compile(r'(def|function|class|\w+\s*=\s*function)\s+\w+\s*\(')
            functions = function_pattern.findall(code)
            function_count = len(functions)
            
            # Count conditional statements
            conditionals_pattern = re.compile(r'\b(if|else|switch|case|for|while|do)\b')
            conditionals = conditionals_pattern.findall(code)
            conditional_count = len(conditionals)
            
            # Count nested loops/conditions (a simple approximation)
            nested_pattern = re.compile(r'(if|for|while).*\{[^{}]*((if|for|while).*\{[^{}]*\})[^{}]*\}')
            nested_count = len(nested_pattern.findall(code))
            
            # Calculate complexity score (simple heuristic)
            # Higher score means more complex
            complexity_score = 0
            if line_count > 0:
                complexity_score = (
                    (function_count / max(1, line_count / 100)) * 0.3 +
                    (conditional_count / max(1, line_count / 20)) * 0.5 +
                    (nested_count / max(1, line_count / 50)) * 0.2
                ) * 10
            
            # Limit to 0-10 scale
            complexity_score = min(10, max(0, complexity_score))
            
            return {
                'line_count': line_count,
                'function_count': function_count,
                'conditional_count': conditional_count,
                'nested_count': nested_count,
                'complexity_score': complexity_score
            }
        except Exception as e:
            logger.error(f"Failed to analyze complexity: {str(e)}")
            return {'error': str(e)}
                temp_path = temp.name
            
            results = {
                'eslint': await self._run_eslint(temp_path),
                'complexity': await self._analyze_complexity(code)
            }
            
            # Clean up temporary file
            os.unlink(temp_path)
            
            return results
        except Exception as e:
            logger.error(f"Failed to analyze JavaScript code: {str(e)}")
            return {'error': str(e)}
    
    async def _run_flake8(self, file_path: str) -> Dict[str, Any]:
        """Run flake8 on a Python file."""
        try:
            # Check if flake8 is installed
            result = subprocess.run(['which', 'flake8'], capture_output=True, text=True)
            if result.returncode != 0:
                return {'error': 'flake8 not installed'}
            
            # Run flake8
            result = subprocess.run(['flake8', file_path], capture_output=True, text=True)
            
            issues = []
            if result.stdout:
                for line in result.stdout.splitlines():
                    parts = line.split(':', 3)
                    if len(parts) >= 4:
                        issues.append({
                            'line': int(parts[1]),
                            'column': int(parts[2]),
                            'message': parts[3].strip()
                        })
            
            return {
                'issues': issues,
                'count': len(issues)
            }
        except Exception as e:
            logger.error(f"Failed to run fl

