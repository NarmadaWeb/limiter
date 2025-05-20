# Contributing to Fiber Limiter

First off, thank you for considering contributing to Fiber Limiter! We greatly appreciate your time and effort. Your contributions help make this project better for everyone.

There are many ways to contribute, from writing code, creating documentation, reporting bugs, to suggesting new features.

## Table of Contents

- [How Can I Contribute?](#how-can-i-contribute)
  - [Reporting Bugs](#reporting-bugs)
  - [Suggesting Enhancements](#suggesting-enhancements)
  - [Code Contributions](#code-contributions)
  - [Documentation Contributions](#documentation-contributions)
- [Development Setup Guide](#development-setup-guide)
  - [Prerequisites](#prerequisites)
  - [Getting the Code](#getting-the-code)
  - [Running Tests](#running-tests)
- [Code Style & Standards](#code-style--standards)
- [Pull Request Process](#pull-request-process)
- [License](#license)
- [Code of Conduct](#code-of-conduct)

## How Can I Contribute?

### Reporting Bugs

If you find a bug, please check the existing [Issues](https://github.com/NarmadaWeb/limiter/issues) to see if it has already been reported. If not, please create a new issue.

When reporting a bug, please include as much information as possible:
- The Go version you are using.
- The Fiber Limiter version you are using.
- A clear and concise description of the bug.
- Steps to reproduce the bug.
- A minimal code example that reproduces the problem (if possible).
- The expected behavior and what actually happened.
- Any error messages or stack traces (if applicable).

### Suggesting Enhancements

We welcome ideas for new features or improvements! Please check the [Issues](https://github.com/NarmadaWeb/limiter/issues) to see if the feature has already been suggested. If not, create a new issue with the `enhancement` or `feature request` label.

Describe the feature in detail:
- What problem is this feature trying to solve?
- How would this feature benefit users?
- Are there any existing alternatives or workarounds?
- (Optional) Implementation suggestions or use case examples.

### Code Contributions

If you'd like to contribute code, please:
1.  **Fork** the `NarmadaWeb/limiter` repository.
2.  Create a new branch from `main` for your work (e.g., `feature/new-cool-feature` or `fix/bug-description`).
    ```bash
    git checkout -b feature/your-feature-name
    ```
3.  Make your code changes.
4.  Ensure your code follows the [Code Style & Standards](#code-style--standards).
5.  Write new unit tests for your feature or bug fix. Ensure all tests pass.
6.  Commit your changes with clear and descriptive commit messages. We recommend using [Conventional Commits](https://www.conventionalcommits.org/).
    Example: `feat: add new token bucket configuration option` or `fix: resolve panic on empty redis client`.
7.  Push your branch to your fork.
    ```bash
    git push origin feature/your-feature-name
    ```
8.  Open a Pull Request (PR) to the `main` branch of the `NarmadaWeb/limiter` repository.
9.  In your PR description, explain the changes you've made and link any relevant issues.
10. Ensure your PR passes all automated checks (CI).

Possible areas for code contributions:
- Implementation of new rate-limiting algorithms.
- Support for new storage options.
- Performance improvements.
- Bug fixes.
- Addition of more diverse usage examples.

### Documentation Contributions

Good documentation is crucial! If you find areas in the documentation (including this `README.md` or code comments) that can be improved, please submit a Pull Request. This could be grammar fixes, clarifications, better examples, or adding new sections.

## Development Setup Guide

### Prerequisites

- [Go](https://golang.org/dl/) (recommended version is the latest stable or the one specified in `go.mod`).
- [Git](https://git-scm.com/).
- (Optional) [Redis](https://redis.io/download) if you want to test Redis integration. [Docker](https://www.docker.com/get-started) can be an easy way to run Redis.

### Getting the Code

1.  Fork the `github.com/NarmadaWeb/limiter` repository.
2.  Clone your fork locally:
    ```bash
    git clone https://github.com/YOUR_USERNAME/limiter.git
    cd limiter
    ```
3.  Add the main repository as an upstream remote:
    ```bash
    git remote add upstream https://github.com/NarmadaWeb/limiter.git
    ```
4.  Install dependencies:
    ```bash
    go mod tidy
    ```

### Running Tests

To run all unit tests:
```bash
go test ./...
```
If you add new functionality, ensure you add relevant tests. If you fix a bug, add a test that reproduces the bug before the fix.

If you are contributing to Redis-related functionality, ensure you have a running and accessible Redis instance for testing.

## Code Style & Standards

- Follow idiomatic Go practices.
- Use `gofmt` to format your code before committing. Many editors can be configured to do this automatically on save.
- Use `go vet ./...` and `golangci-lint run` (if the project uses it) to check for potential issues.
- Write clear and concise comments for complex or non-obvious code.
- Keep functions and methods short and focused on a single task.
- Adhere to existing standards in the codebase.
- When changing response headers or behavior related to standards (like RFC 6585 for `RateLimit` headers), ensure the changes remain compliant or explain why.

## Pull Request Process

1.  Ensure all tests pass (`go test ./...`).
2.  Ensure your code has been formatted with `gofmt`.
3.  Update `README.md` or other documentation if your changes affect usage or configuration.
4.  Create a PR targeting the `main` branch of `NarmadaWeb/limiter`.
5.  Provide a clear PR title and description. Explain *why* the change is needed and *what* it does. Link relevant issues (e.g., `Closes #123`).
6.  One or more maintainers will review your PR. Please be patient and responsive to feedback.
7.  Once approved and all CI checks pass, your PR will be merged.

## License

By contributing to Fiber Limiter, you agree that your contributions will be licensed under the same [MIT License](LICENSE) that covers the project.

## Code of Conduct

This project and everyone participating in it is governed by the [Fiber Limiter Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior.

---

Thank you again for your interest in contributing to Fiber Limiter!
