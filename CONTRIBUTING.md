# Contributing to AI Model Security Tools

Thank you for your interest in contributing to this security toolkit. We welcome contributions that improve the security, reliability, and usability of these tools.

## Core Principles

1. **Do No Harm**: All contributions must be intended for defensive security purposes only
2. **Privacy First**: Never collect or expose sensitive user data
3. **Transparency**: Document all security mechanisms and changes
4. **Responsibility**: Test thoroughly before submitting changes

## How to Contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-security-feature`)
3. Commit your changes (`git commit -m 'Add new security feature'`)
4. Push to your branch (`git push origin feature/amazing-security-feature`)
5. Open a Pull Request

## Development Guidelines

- Add tests for any new features
- Update documentation for changes
- Follow PEP 8 style guidelines
- Use type hints for all new code
- Add logging for security-relevant events
- Comment security-critical code sections

## Security Requirements

- No code that could enable attacks or exploitation
- No weakening of existing security measures
- No collection of unnecessary user data
- No hard-coded credentials or secrets
- No disabled security features by default

## Testing

- Add unit tests for new features
- Include integration tests where appropriate
- Test edge cases and error conditions
- Verify no security weaknesses introduced

## Documentation

When adding or modifying features:
- Update README.md
- Add docstrings to functions/classes
- Document security implications
- Include usage examples

## Need Help?

- Open an issue for bugs or security concerns
- Use discussions for feature ideas
- Tag security-critical issues appropriately

## Code of Conduct

- Be respectful and constructive
- Focus on improving security
- No malicious or harmful contributions
- Report security issues responsibly

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
