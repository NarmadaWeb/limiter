# Go Pull Request Template

## Description

Please include a concise summary of the changes and reference the related issue. Explain your motivation and design decisions.

Fixes # (issue)

## Type of change

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Refactoring (no functional changes)
- [ ] Documentation update
- [ ] CI/CD pipeline update

## Code Quality Checklist

- [ ] My code follows the [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
- [ ] I have run `golangci-lint` on my code
- [ ] I have added appropriate godoc comments for exported functions/types
- [ ] I have written unit tests for new code (coverage >= 80%)
- [ ] I have updated existing tests to work with my changes
- [ ] I have benchmarked performance-critical changes (if applicable)

## Testing

**Test Environment:**

- Go version:
- OS:
- Additional details:

**Tests Performed:**

- [ ] Unit tests (`go test -v ./...`)
- [ ] Integration tests
- [ ] Race detector (`go test -race`)
- [ ] Benchmarks (if applicable)

## Additional Notes

- Any trade-offs made in the implementation?
- Backward compatibility considerations?
- Deployment considerations?
