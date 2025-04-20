import os
import logging
from typing import List, Dict, Any, Optional
import json

from langchain.chains import LLMChain
from langchain.prompts import PromptTemplate
from langchain_community.llms import OpenAI
from langchain_core.language_models.base import BaseLLM
from tenacity import retry, stop_after_attempt, wait_exponential

logger = logging.getLogger(__name__)

class AIService:
    """Base service for AI operations using LangChain."""
    
    def __init__(self, model_name: str = "gpt-3.5-turbo"):
        """Initialize AI service with a specific model."""
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            logger.warning("OPENAI_API_KEY not set. AI features will not work correctly.")
        
        self.llm = self._initialize_llm(model_name, api_key)
    
    def _initialize_llm(self, model_name: str, api_key: Optional[str]) -> BaseLLM:
        """Initialize the language model."""
        try:
            return OpenAI(model_name=model_name, openai_api_key=api_key, temperature=0.7)
        except Exception as e:
            logger.error(f"Failed to initialize LLM: {str(e)}")
            raise
    
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    async def generate_text(self, prompt_template: str, **kwargs) -> str:
        """Generate text based on a prompt template and variables."""
        try:
            prompt = PromptTemplate(
                input_variables=list(kwargs.keys()),
                template=prompt_template
            )
            
            chain = LLMChain(llm=self.llm, prompt=prompt)
            return chain.run(**kwargs)
        except Exception as e:
            logger.error(f"Error generating text: {str(e)}")
            raise

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    async def analyze_code(self, code: str, language: str) -> Dict[str, Any]:
        """Analyze code quality and provide suggestions."""
        prompt_template = """
        You are a senior software engineer reviewing this {language} code:
        
        ```{language}
        {code}
        ```
        
        Please analyze this code and provide:
        1. Quality assessment (1-10)
        2. Identified issues
        3. Improvement suggestions
        4. Best practices that aren't being followed
        
        Format your response as JSON with keys: quality_score, issues, suggestions, and best_practices.
        """
        
        result = await self.generate_text(
            prompt_template=prompt_template,
            code=code,
            language=language
        )
        
        try:
            # Parse the JSON response
            return json.loads(result)
        except json.JSONDecodeError:
            # If not valid JSON, return a formatted response
            return {
                "quality_score": 5,
                "issues": ["Could not parse LLM response into JSON"],
                "suggestions": ["Try again with a different prompt"],
                "best_practices": []
            }
    
    async def summarize_issue(self, issue_text: str) -> str:
        """Summarize a lengthy GitHub issue."""
        prompt_template = """
        Summarize the following GitHub issue concisely while preserving the essential information:
        
        {issue_text}
        
        Summary:
        """
        
        return await self.generate_text(
            prompt_template=prompt_template,
            issue_text=issue_text
        )
    
    async def generate_documentation(self, code: str, language: str) -> str:
        """Generate documentation for code."""
        prompt_template = """
        Generate comprehensive documentation for the following {language} code:
        
        ```{language}
        {code}
        ```
        
        Include:
        - Overview of what the code does
        - Function/method descriptions
        - Parameter details
        - Return value information
        - Usage examples
        
        Documentation:
        """
        
        return await self.generate_text(
            prompt_template=prompt_template,
            code=code,
            language=language
        )
        
    async def analyze_security_issues(self, code: str, language: str) -> Dict[str, Any]:
        """Analyze code for potential security issues."""
        prompt_template = """
        You are a security expert reviewing this {language} code for vulnerabilities:
        
        ```{language}
        {code}
        ```
        
        Please identify any security vulnerabilities, including but not limited to:
        - Injection vulnerabilities (SQL, command, etc.)
        - Authentication issues
        - Authorization problems
        - Cryptographic failures
        - Data exposure
        - Security misconfiguration
        - Cross-site scripting (XSS)
        - Use of unsafe functions
        - Hardcoded credentials
        - Insecure deserialization
        
        Format your response as JSON with keys: vulnerability_count, vulnerabilities (list of issues, each with name, severity, description, and remediation).
        """
        
        result = await self.generate_text(
            prompt_template=prompt_template,
            code=code,
            language=language
        )
        
        try:
            # Parse the JSON response
            return json.loads(result)
        except json.JSONDecodeError:
            # If not valid JSON, return a formatted response
            return {
                "vulnerability_count": 0,
                "vulnerabilities": [
                    {
                        "name": "LLM Response Error",
                        "severity": "Low",
                        "description": "Could not parse LLM response into JSON",
                        "remediation": "Try again with a different prompt"
                    }
                ]
            }

import os
from typing import List, Dict, Any, Optional
import logging
from langchain.chains import LLMChain
from langchain.prompts import PromptTemplate
from langchain_community.llms import OpenAI
from langchain_core.language_models.base import BaseLLM
from tenacity import retry, stop_after_attempt, wait_exponential

logger = logging.getLogger(__name__)

class AIService:
    """Base service for AI operations using LangChain."""
    
    def __init__(self, model_name: str = "gpt-3.5-turbo"):
        """Initialize AI service with a specific model."""
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            logger.warning("OPENAI_API_KEY not set. AI features will not work correctly.")
        
        self.llm = self._initialize_llm(model_name, api_key)
    
    def _initialize_llm(self, model_name: str, api_key: Optional[str]) -> BaseLLM:
        """Initialize the language model."""
        try:
            return OpenAI(model_name=model_name, openai_api_key=api_key, temperature=0.7)
        except Exception as e:
            logger.error(f"Failed to initialize LLM: {str(e)}")
            raise
    
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    async def generate_text(self, prompt_template: str, **kwargs) -> str:
        """Generate text based on a prompt template and variables."""
        try:
            prompt = PromptTemplate(
                input_variables=list(kwargs.keys()),
                template=prompt_template
            )
            
            chain = LLMChain(llm=self.llm, prompt=prompt)
            return chain.run(**kwargs)
        except Exception as e:
            logger.error(f"Error generating text: {str(e)}")
            raise

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    async def analyze_code(self, code: str, language: str) -> Dict[str, Any]:
        """Analyze code quality and provide suggestions."""
        prompt_template = """
        You are a senior software engineer reviewing this {language} code:
        
        ```{language}
        {code}
        ```
        
        Please analyze this code and provide:
        1. Quality assessment (1-10)
        2. Identified issues
        3. Improvement suggestions
        4. Best practices that aren't being followed
        
        Format your response as JSON with keys: quality_score, issues, suggestions, and best_practices.
        """
        
        result = await self.generate_text(
            prompt_template=prompt_template,
            code=code,
            language=language
        )
        
        # In a real implementation, we would parse the JSON here
        # For now, we'll return a placeholder
        return {
            "quality_score": 7,
            "issues": ["Example issue 1", "Example issue 2"],
            "suggestions": ["Example suggestion 1", "Example suggestion 2"],
            "best_practices": ["Example best practice 1", "Example best practice 2"]
        }
    
    async def summarize_issue(self, issue_text: str) -> str:
        """Summarize a lengthy GitHub issue."""
        prompt_template = """
        Summarize the following GitHub issue concisely while preserving the essential information:
        
        {issue_text}
        
        Summary:
        """
        
        return await self.generate_text(
            prompt_template=prompt_template,
            issue_text=issue_text
        )
    
    async def generate_documentation(self, code: str, language: str) -> str:
        """Generate documentation for code."""
        prompt_template = """
        Generate comprehensive documentation for the following {language} code:
        
        ```{language}
        {code}
        ```
        
        Include:
        - Overview of what the code does
        - Function/method descriptions
        - Parameter details
        - Return value information
        - Usage examples
        
        Documentation:
        """
        
        return await self.generate_text(
            prompt_template=prompt_template,
            code=code,
            language=language
        )

