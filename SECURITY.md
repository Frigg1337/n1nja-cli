# Security Policy

## Supported Versions

This project is currently in active development. The latest version is supported for security updates.

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly:

1. **Do not** open a public issue
2. Contact the maintainers directly via [your preferred contact method]
3. Provide detailed information about the vulnerability
4. Include steps to reproduce if possible
5. Allow time for the issue to be addressed before public disclosure

## Security Best Practices

When using this tool, please follow these security practices:

- **Never commit sensitive information** like API keys to version control
- **Use environment variables** for sensitive data (the `.env` file)
- **Keep your API keys secure** and limit their permissions
- **Verify the code** before running it in your environment
- **Use in isolated environments** for sensitive tasks when possible

## Dependencies

This project uses various Python libraries. Please ensure:
- Keep dependencies updated for security patches
- Review new dependencies before installation
- Check for known vulnerabilities in dependencies

## Configuration

- The `.gitignore` file is configured to prevent `.env` files from being committed
- Always use your own API keys and never hardcode them in the source
- Regularly rotate your API keys for security