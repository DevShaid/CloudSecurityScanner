# Contributing to CloudGuard Enhanced

Thank you for your interest in contributing to CloudGuard Enhanced! We welcome contributions from the community and are grateful for your help in making this project better.

## 🤝 How to Contribute

### Reporting Issues
- **🐛 Bug Reports**: Use the GitHub issue template
- **💡 Feature Requests**: Use the GitHub issue template
- **📖 Documentation**: Help improve our docs
- **🧪 Testing**: Help us test on different AWS environments

### Code Contributions
- **🔧 Bug Fixes**: Fix issues and submit PRs
- **✨ New Features**: Add new security checks
- **⚡ Performance**: Optimize scanning performance
- **📊 Reporting**: Enhance report formats

## 🚀 Getting Started

### Development Setup
```bash
# Fork and clone the repository
git clone https://github.com/your-username/cloudguard-enhanced.git
cd cloudguard-enhanced

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install
```

### Development Dependencies
```bash
# Install additional dev dependencies
pip install pytest pytest-cov black flake8 mypy pre-commit
```

## 📝 Development Guidelines

### Code Style
- **Python 3.7+** compatibility required
- **PEP 8** style guidelines
- **Type hints** for all functions
- **Docstrings** for all public methods
- **Black** formatting (line length 88)

### Testing Requirements
- **Unit tests** for all new features
- **Integration tests** for AWS API calls
- **Performance tests** for large accounts
- **Coverage** must be > 80%

### Commit Message Format
```
type(scope): description

Examples:
feat(s3): add MFA delete check for sensitive buckets
fix(iam): resolve pagination issue with large user lists
perf(scan): optimize parallel execution for better performance
docs(readme): update installation instructions
```

## 🧪 Testing

### Running Tests
```bash
# Run all tests
python -m pytest

# Run with coverage
python -m pytest --cov=cg --cov-report=html

# Run specific test categories
python -m pytest tests/unit/
python -m pytest tests/integration/
python -m pytest tests/performance/
```

### Test Categories
- **Unit Tests**: Individual function testing
- **Integration Tests**: AWS API interaction testing
- **Performance Tests**: Large account benchmarking
- **Security Tests**: Scanner security validation

### AWS Testing
```bash
# Test with AWS credentials (requires valid AWS account)
export AWS_PROFILE=test-profile
python -m pytest tests/integration/ --aws-profile test-profile
```

## 🔧 Adding New Security Checks

### 1. Create the Check Method
```python
@retry_with_backoff()
def scan_new_service(self) -> List[Finding]:
    """Scan new AWS service for security issues"""
    findings = []
    client = AWSClientManager.get_client("new-service", self.session)
    
    try:
        # Your security check logic here
        resources = client.list_resources().get("Resources", [])
        
        for resource in resources:
            # Check for security issues
            if security_issue_detected:
                findings.append(self._make_finding(
                    id=f"new-service-issue-{resource_id}",
                    title="Security Issue Title",
                    description="Detailed description of the issue",
                    severity=Severity.HIGH,
                    resource_type="New Service Resource",
                    resource_id=resource_id,
                    remediation="Step-by-step fix instructions",
                    risk_score=75,
                    metadata={"additional": "info"}
                ))
                
    except ClientError as e:
        logger.error(f"New service scan failed: {e}")
        
    return findings
```

### 2. Add to Service List
```python
# In run_all() method, add to all_checks list:
("new-service", "New Service", self.scan_new_service),
```

### 3. Add Tests
```python
def test_scan_new_service():
    """Test new service security scanning"""
    scanner = AWSScanner()
    findings = scanner.scan_new_service()
    
    assert isinstance(findings, list)
    # Add specific test assertions
```

## 📊 Performance Guidelines

### Large Account Testing
- Test with accounts having **1000+ resources**
- Measure **scan duration** and **memory usage**
- Ensure **parallel execution** works correctly
- Validate **pagination** for large datasets

### Performance Benchmarks
```bash
# Run performance tests
python tests/benchmark.py --account-size large --workers 16

# Memory profiling
python -m memory_profiler cg.py --workers 8
```

## 🔒 Security Guidelines

### AWS Credentials
- **Never commit** AWS credentials to the repository
- Use **IAM roles** or **environment variables** for testing
- **Minimal permissions** - only what's needed for scanning
- **Test accounts** should be isolated from production

### Code Security
- **No hardcoded secrets** or credentials
- **Input validation** for all user inputs
- **Error handling** that doesn't expose sensitive information
- **Logging** should not include sensitive data

## 📖 Documentation

### Code Documentation
- **Docstrings** for all public methods
- **Type hints** for better IDE support
- **Comments** for complex logic
- **Examples** in docstrings where helpful

### User Documentation
- **README updates** for new features
- **Usage examples** for new options
- **Troubleshooting guides** for common issues
- **Performance tips** for large accounts

## 🚀 Release Process

### Version Numbering
- **Semantic versioning** (MAJOR.MINOR.PATCH)
- **MAJOR**: Breaking changes
- **MINOR**: New features, backward compatible
- **PATCH**: Bug fixes, backward compatible

### Release Checklist
- [ ] All tests passing
- [ ] Documentation updated
- [ ] Changelog updated
- [ ] Version bumped
- [ ] Release notes written
- [ ] GitHub release created

## 🐛 Bug Reports

### Before Reporting
1. **Search existing issues** to avoid duplicates
2. **Test with latest version** to ensure it's not fixed
3. **Gather information** about your environment
4. **Reproduce the issue** with minimal steps

### Bug Report Template
```markdown
**Describe the bug**
A clear description of what the bug is.

**To Reproduce**
Steps to reproduce the behavior:
1. Run command '...'
2. See error '...'

**Expected behavior**
What you expected to happen.

**Environment:**
- OS: [e.g. Ubuntu 20.04]
- Python version: [e.g. 3.9.7]
- AWS account size: [e.g. 1000+ resources]
- CloudGuard version: [e.g. 2.0.0]

**Additional context**
Any other context about the problem.
```

## ✨ Feature Requests

### Before Requesting
1. **Check roadmap** to see if it's planned
2. **Search issues** to see if it's already requested
3. **Consider complexity** and implementation effort
4. **Think about use cases** and benefits

### Feature Request Template
```markdown
**Is your feature request related to a problem?**
A clear description of what the problem is.

**Describe the solution you'd like**
A clear description of what you want to happen.

**Describe alternatives you've considered**
Any alternative solutions or workarounds.

**Additional context**
Any other context about the feature request.
```

## 🏷️ Pull Request Process

### Before Submitting
- [ ] **Fork** the repository
- [ ] **Create** a feature branch
- [ ] **Write tests** for your changes
- [ ] **Update documentation** if needed
- [ ] **Run all tests** and ensure they pass
- [ ] **Check code style** with black and flake8

### PR Template
```markdown
## Description
Brief description of changes.

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests pass
- [ ] Manual testing completed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Tests added/updated
```

## 🎯 Areas for Contribution

### High Priority
- **New AWS services** (ECS, EKS, API Gateway, etc.)
- **Performance optimizations** for large accounts
- **Enhanced reporting** formats (PDF, CSV, etc.)
- **CI/CD integrations** (GitLab, Azure DevOps, etc.)

### Medium Priority
- **Custom compliance frameworks**
- **Automated remediation** capabilities
- **Web dashboard** for results visualization
- **Multi-cloud support** (Azure, GCP)

### Low Priority
- **UI improvements** for HTML reports
- **Additional output formats**
- **Enhanced logging** and debugging
- **Documentation improvements**

## 💬 Community Guidelines

### Code of Conduct
- **Be respectful** and inclusive
- **Help others** learn and grow
- **Provide constructive feedback**
- **Follow the golden rule**

### Communication
- **GitHub Issues** for bug reports and feature requests
- **GitHub Discussions** for questions and ideas
- **Pull Requests** for code contributions
- **Security issues** should be reported privately

## 🏆 Recognition

### Contributors
- **Contributors** will be listed in README
- **Major contributors** will be added to AUTHORS
- **Significant contributions** will be highlighted in releases
- **Community feedback** is always appreciated

### Types of Contributions
- **Code contributions** (new features, bug fixes)
- **Documentation** improvements
- **Testing** on different environments
- **Community support** and feedback
- **Security research** and vulnerability reports

## 📞 Getting Help

### Resources
- **📖 Documentation**: [Wiki](https://github.com/your-org/cloudguard-enhanced/wiki)
- **💬 Discussions**: [GitHub Discussions](https://github.com/your-org/cloudguard-enhanced/discussions)
- **🐛 Issues**: [GitHub Issues](https://github.com/your-org/cloudguard-enhanced/issues)
- **📧 Email**: security-team@company.com

### Development Support
- **Code reviews** for all PRs
- **Mentorship** for new contributors
- **Pair programming** sessions available
- **Office hours** for questions

---

Thank you for contributing to CloudGuard Enhanced! Together, we can make AWS security scanning more accessible and effective for everyone. 🛡️
