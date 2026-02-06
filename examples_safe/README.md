# examples_safe/

This folder contains **secure versions** of the insecure code examples found in `../examples/`. The purpose is to demonstrate how to fix common security vulnerabilities and allow users to compare the analyzer output between insecure and secure code.

## Purpose

- **Before/After Comparison**: Show the security improvements when vulnerabilities are properly addressed
- **Best Practice Examples**: Demonstrate secure coding patterns for each OWASP category
- **Lower Risk Scores**: When analyzed, these files should produce dramatically fewer findings and lower risk scores

## File Mappings

| Insecure Example                                 | Secure Version                                   | Vulnerabilities Fixed                                                                                                                                 |
| ------------------------------------------------ | ------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `identification_authentication_failures_test.py` | `identification_authentication_failures_safe.py` | ✅ Uses bcrypt/argon2 for password hashing<br>✅ Constant-time comparisons<br>✅ No hardcoded credentials<br>✅ Proper session token generation       |
| `cryptographic_failures.py`                      | `cryptographic_failures_safe.py`                 | ✅ No hardcoded secrets (uses env vars)<br>✅ SHA-256 instead of MD5/SHA1<br>✅ `secrets` module for tokens<br>✅ Proper password hashing with argon2 |
| `sql_injection.py`                               | `sql_injection_safe.py`                          | ✅ Parameterized queries<br>✅ Input validation<br>✅ ORM examples<br>✅ Whitelist validation for dynamic parts                                       |
| `security_misconfiguration.py`                   | `security_misconfiguration_safe.py`              | ✅ Debug controlled by environment<br>✅ Explicit CORS allowlist<br>✅ Security headers<br>✅ Environment-specific configs                            |
| `requirements_unpinned.txt`                      | `requirements_pinned_safe.txt`                   | ✅ All dependencies pinned to exact versions<br>✅ No loose version constraints                                                                       |
| `pyproject_unpinned.toml`                        | `pyproject_pinned_safe.toml`                     | ✅ All dependencies pinned with `==`<br>✅ Includes dev dependencies                                                                                  |
| `unsafe_deserialization.py`                      | `unsafe_deserialization_safe.py`                 | ✅ JSON instead of pickle<br>✅ `yaml.safe_load()` instead of `yaml.load()`<br>✅ Data validation<br>✅ Schema enforcement                            |
| `security_logging_monitoring_failures.py`        | `security_logging_monitoring_failures_safe.py`   | ✅ Structured logging with context<br>✅ Error-level logging for failures<br>✅ Telemetry/metrics emission<br>✅ Security-critical audit logging      |

## Usage

### Compare Analyzer Output

```bash
# Analyze insecure examples
coderisk analyze examples/cryptographic_failures.py

# Analyze secure version
coderisk analyze examples_safe/cryptographic_failures_safe.py
```

You should see significantly fewer findings and lower risk scores in the `examples_safe/` versions.

### Review Secure Patterns

Each safe example includes:

- **Comments** explaining the security improvements
- **Type hints** for better code clarity
- **Error handling** with proper logging
- **Industry best practices** for each vulnerability category

## Key Security Patterns Demonstrated

### Authentication (A07)

- ✅ Use `bcrypt` or `argon2` for password hashing
- ✅ Use `secrets.compare_digest()` for constant-time comparison
- ✅ Never hardcode credentials in code
- ✅ Generate tokens with `secrets.token_urlsafe()`

### Cryptography (A02)

- ✅ Load secrets from environment variables or secrets managers
- ✅ Use SHA-256 or better for general hashing
- ✅ Use argon2/bcrypt for password hashing
- ✅ Use `secrets` module for cryptographic randomness
- ✅ Use `os.urandom()` for random bytes

### SQL Injection (A03)

- ✅ Always use parameterized queries (`?` placeholders)
- ✅ Use ORMs when possible (auto-parameterization)
- ✅ Validate/whitelist dynamic SQL parts (table/column names)
- ✅ Never concatenate user input into SQL strings

### Security Misconfiguration (A05)

- ✅ Control debug mode via environment variables
- ✅ Use explicit CORS allowlists, never wildcards
- ✅ Add security headers (HSTS, CSP, X-Frame-Options)
- ✅ Different configs for dev/staging/production

### Dependencies (A06)

- ✅ Pin all dependencies to exact versions (`==`)
- ✅ Maintain lockfiles for reproducibility
- ✅ Replace deprecated packages with maintained alternatives
- ✅ Regular dependency audits and updates

### Deserialization (A08)

- ✅ Use JSON instead of pickle for untrusted data
- ✅ Use `yaml.safe_load()` instead of `yaml.load()`
- ✅ Validate deserialized data structure
- ✅ Use dataclasses/Pydantic for schema enforcement

### Logging & Monitoring (A09)

- ✅ Log all exceptions with `logger.exception()`
- ✅ Include context in log messages (user ID, request ID)
- ✅ Use appropriate log levels (ERROR, WARN, INFO)
- ✅ Emit metrics/telemetry for failure paths
- ✅ Never silently swallow exceptions

## Testing

The test suite includes verification that:

- `examples_safe/` produces fewer findings than `examples/`
- Risk scores are lower in safe versions
- Security best practices are followed

Run tests:

```bash
python tests/test_no_cli_language.py
```

## Contributing

When adding new examples:

1. Add the insecure version to `examples/`
2. Add the secure fixed version to `examples_safe/`
3. Update this README with the mapping
4. Verify the secure version produces fewer findings
