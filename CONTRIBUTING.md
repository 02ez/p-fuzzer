# Contributing to LabLeakFinder

Thank you for your interest in contributing to LabLeakFinder! This document provides guidelines for participating in the project.

## 🤝 Ways to Contribute

### 1. Reporting Bugs
- **Check existing issues** first to avoid duplicates
- **Provide clear reproduction steps**
- **Include environment details**:
  - Python version
  - Operating system
  - LabLeakFinder version
  - Error messages and logs
- **Include expected vs. actual behavior**

### 2. Suggesting Features
- **Describe the use case** clearly
- **Explain the benefit** to users
- **Provide implementation ideas** if possible
- **Link related issues** if applicable

### 3. Code Contributions
- **Fork the repository**
- **Create a feature branch**: `git checkout -b feature/your-feature`
- **Write clean, documented code**
- **Add tests for new functionality**
- **Ensure all tests pass**: `python -m pytest`
- **Submit a pull request** with clear description

### 4. Documentation
- **Fix typos and errors**
- **Improve clarity and examples**
- **Add missing documentation**
- **Translate to other languages**
- **Create video tutorials**

### 5. Testing & Quality Assurance
- **Test on different platforms**
- **Report compatibility issues**
- **Validate against compliance frameworks**
- **Performance testing**

---

## 📋 Code Style Guide

### Python Standards
- Follow PEP 8 style guide
- Use type hints for function arguments
- Keep functions focused and under 50 lines when possible
- Add docstrings to all functions and classes

### Naming Conventions
- `snake_case` for functions and variables
- `CamelCase` for class names
- `UPPER_SNAKE_CASE` for constants
- Descriptive names (avoid abbreviations)

### Documentation
```python
def function_name(param1: str, param2: int) -> bool:
    """
    Brief description of function.
    
    Args:
        param1: Description of param1
        param2: Description of param2
    
    Returns:
        Description of return value
    
    Raises:
        ValueError: When validation fails
    """
```

---

## 🧪 Testing Requirements

### Unit Tests
- Minimum 80% code coverage
- Test both success and failure cases
- Use descriptive test names

### Integration Tests
- Test component interactions
- Validate report generation
- Test attack chain execution

### Performance Tests
- Benchmark key operations
- Monitor memory usage
- Track report generation time

---

## 📝 Commit Message Format

```
Type: Subject (imperative mood, max 50 chars)

Body (max 72 chars per line):
- Explain what, why, and how
- Reference related issues: Closes #123
- Break into multiple paragraphs if needed

Type options:
- feat: New feature
- fix: Bug fix
- docs: Documentation
- style: Code style (formatting)
- refactor: Code restructuring
- perf: Performance improvement
- test: Test additions/improvements
- chore: Build/dependency updates
```

---

## 🔍 Review Process

1. **Author submits** pull request with clear description
2. **Automated tests** run (must pass)
3. **Code review** by maintainers
4. **Feedback** provided (if needed)
5. **Updates** made based on feedback
6. **Approval** and merge

---

## 📊 Performance Benchmarks

When contributing optimization code, ensure:
- Report generation: < 2 seconds
- HTML output: < 1 second
- JSON export: < 500ms
- Attack chain execution: < 15 minutes

---

## 🔐 Security Considerations

- No hardcoded credentials
- Validate all user input
- Encrypt sensitive data
- Use secure libraries
- Report security issues privately

---

## 📚 Documentation Updates

- Update README.md for user-facing changes
- Update FEATURES.md for capability changes
- Add/update docstrings in code
- Include examples where applicable

---

## 🎯 Project Priorities

1. **Stability**: No breaking changes without major version bump
2. **Security**: Regular dependency updates and security audits
3. **Performance**: Maintain or improve execution speed
4. **Usability**: Clear documentation and error messages
5. **Compliance**: Keep frameworks aligned with standards

---

## 💬 Communication

- Use GitHub Issues for bug reports and features
- Use GitHub Discussions for questions
- Join our community for real-time chat
- Respect code of conduct

---

## 📜 Code of Conduct

- **Be respectful** to all contributors
- **Be inclusive** of diverse backgrounds
- **No harassment** or hostile language
- **Professional** discussions focused on code
- **Report violations** to maintainers

---

## 🙏 Acknowledgments

Contributors will be:
- Listed in CONTRIBUTORS.md
- Credited in release notes
- Recognized in project documentation

---

## ❓ Questions?

Contact: [02ez@tostupidtooquit.com](mailto:02ez@tostupidtooquit.com)

---

**Thank you for contributing to LabLeakFinder!** 🚀
