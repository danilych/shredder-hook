# Contributing to ZK Privacy Hook 🤝

We welcome contributions to the ZK Privacy Hook project! This document provides guidelines for contributing to the project.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Contribution Workflow](#contribution-workflow)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Documentation](#documentation)
- [Security](#security)
- [Community](#community)

## 🤝 Code of Conduct

This project adheres to a code of conduct that promotes a welcoming and inclusive environment. Please read our [Code of Conduct](CODE_OF_CONDUCT.md) before participating.

## 🚀 Getting Started

### Prerequisites

- [Foundry](https://getfoundry.sh/) (latest version)
- [Git](https://git-scm.com/)
- Node.js 16+ (for ZK tooling)
- Basic understanding of:
  - Solidity smart contracts
  - Uniswap V4 hooks
  - Zero-knowledge proofs
  - Cryptographic commitments

### Areas for Contribution

We welcome contributions in the following areas:

#### 🏗️ Core Development
- Hook implementation improvements
- Gas optimization
- Security enhancements
- ZK proof integration

#### 🧪 Testing
- Unit test coverage
- Integration tests
- Fuzz testing
- Property-based testing

#### 📚 Documentation
- Code documentation
- API reference
- Tutorials and guides
- Architecture documentation

#### 🔧 Tooling
- Development scripts
- CI/CD improvements
- Testing utilities
- Deployment tools

## 💻 Development Setup

1. **Fork the Repository**
   ```bash
   git clone https://github.com/your-username/zk-privacy-hook
   cd zk-privacy-hook
   ```

2. **Install Dependencies**
   ```bash
   forge install
   ```

3. **Build the Project**
   ```bash
   forge build
   ```

4. **Run Tests**
   ```bash
   forge test
   ```

5. **Set Up Environment**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

## 🔄 Contribution Workflow

### 1. Issue Creation

Before starting work:
- Search existing issues to avoid duplicates
- Create a detailed issue describing the problem or feature
- Wait for maintainer feedback before starting work

### 2. Development Process

1. **Create a Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make Changes**
   - Follow coding standards
   - Write comprehensive tests
   - Update documentation
   - Ensure all tests pass

3. **Commit Changes**
   ```bash
   git add .
   git commit -m "feat: add new privacy feature"
   ```

   Use [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat:` for new features
   - `fix:` for bug fixes
   - `docs:` for documentation
   - `test:` for tests
   - `refactor:` for refactoring
   - `perf:` for performance improvements

4. **Push Changes**
   ```bash
   git push origin feature/your-feature-name
   ```

5. **Create Pull Request**
   - Use the provided PR template
   - Include detailed description
   - Link related issues
   - Request reviews from maintainers

### 3. Review Process

- All PRs require at least one maintainer review
- Address feedback promptly
- Keep PRs focused and atomic
- Ensure CI passes before requesting review

## 📝 Coding Standards

### Solidity Style Guide

Follow the [official Solidity Style Guide](https://docs.soliditylang.org/en/latest/style-guide.html):

#### Contract Structure
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BaseHook} from "v4-periphery/src/utils/BaseHook.sol";

/// @title Contract Title
/// @notice High-level description
/// @dev Technical details
contract YourContract is BaseHook {
    // Type declarations
    // State variables
    // Events
    // Modifiers
    // Functions
}
```

#### Function Documentation
```solidity
/// @notice What the function does
/// @dev Technical implementation details
/// @param param1 Description of parameter
/// @return Description of return value
function yourFunction(uint256 param1) external returns (uint256) {
    // Implementation
}
```

#### Naming Conventions
- **Contracts**: PascalCase (`ZKPrivacyHook`)
- **Functions**: camelCase (`privateDeposit`)
- **Variables**: camelCase (`totalDeposits`)
- **Constants**: SCREAMING_SNAKE_CASE (`MAX_PRIVATE_AMOUNT`)
- **Private/Internal**: leading underscore (`_verifyProof`)

### Gas Optimization

- Use `uint256` instead of smaller types when possible
- Pack structs efficiently
- Use `calldata` for external function parameters
- Cache storage reads in memory
- Use events for data that doesn't need on-chain storage

### Security Best Practices

- Follow [ConsenSys Security Best Practices](https://consensys.github.io/smart-contract-best-practices/)
- Use `ReentrancyGuard` for state-changing functions
- Validate all inputs
- Handle edge cases
- Use safe math operations
- Implement proper access controls

## 🧪 Testing Guidelines

### Test Structure

Organize tests by contract and functionality:
```
test/
├── ZKPrivacyHook.t.sol           # Unit tests
├── ZKPrivacyHookIntegration.t.sol # Integration tests  
├── ZKPrivacyHookFuzz.t.sol       # Fuzz tests
└── mocks/
    └── MockZKVerifier.sol        # Test utilities
```

### Test Requirements

#### Unit Tests
- Test all public functions
- Cover edge cases and error conditions
- Use descriptive test names
- Assert expected outcomes

```solidity
function testPrivateDepositValidCommitment() public {
    // Arrange
    uint256 amount = 100e18;
    bytes32 commitment = hook.generateCommitment(amount, currency0, 12345);
    
    // Act
    vm.prank(alice);
    hook.privateDeposit(commitment, amount, currency0);
    
    // Assert
    assertTrue(hook.commitmentExists(commitment));
    (uint256 totalDeposits,) = hook.getPrivateStats(currency0);
    assertEq(totalDeposits, amount);
}
```

#### Integration Tests
- Test cross-contract interactions
- Verify end-to-end workflows
- Test with realistic scenarios

#### Fuzz Tests
- Test mathematical operations
- Verify invariants hold
- Use property-based testing

```solidity
function testFuzzCommitmentGeneration(uint256 amount, uint256 secret) public {
    amount = bound(amount, 1, 1000000 * 1e18);
    secret = bound(secret, 1, type(uint256).max);
    
    bytes32 commitment = hook.generateCommitment(amount, currency0, secret);
    assertNotEq(commitment, bytes32(0));
}
```

### Coverage Requirements

- Minimum 80% line coverage
- 100% coverage for critical functions
- Test all error conditions

```bash
# Generate coverage report
forge coverage

# Generate detailed HTML report
forge coverage --report lcov
genhtml lcov.info -o coverage/
```

## 📚 Documentation

### Code Documentation

- Use NatSpec for all public functions
- Include examples in documentation
- Explain complex algorithms
- Document security considerations

### README Updates

When adding features:
- Update usage examples
- Add new configuration options
- Update performance metrics
- Include migration guides

### Architecture Documents

For significant changes:
- Create design documents
- Explain trade-offs
- Include diagrams
- Document security implications

## 🔒 Security

### Reporting Vulnerabilities

- **DO NOT** create public issues for security vulnerabilities
- Email security@yourproject.com with details
- Include steps to reproduce
- Allow 90 days for fix before public disclosure

### Security Review Process

1. All PRs undergo security review
2. Critical changes require multiple reviews  
3. Use automated security tools
4. Consider formal verification for critical functions

### Known Security Considerations

- ZK proof verification is currently mocked
- Requires trusted setup for production
- Secret management is user responsibility
- Smart contract risks apply

## 🌐 Community

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **Discord**: Real-time development discussion
- **Twitter**: Project updates and announcements

### Development Meetings

- Weekly developer calls (Wednesdays 2PM UTC)
- Monthly community calls
- Quarterly roadmap reviews

### Recognition

Contributors are recognized through:
- GitHub contributor recognition
- Community hall of fame
- Conference speaking opportunities
- Bounty programs for significant contributions

## 📋 Issue Labels

We use the following labels to categorize issues:

- `bug`: Something isn't working
- `enhancement`: New feature or request
- `documentation`: Improvements to documentation
- `good first issue`: Good for newcomers
- `help wanted`: Extra attention is needed
- `security`: Security-related issues
- `performance`: Performance improvements
- `zk-proofs`: Zero-knowledge proof related

## 🚀 Release Process

1. **Feature Freeze**: No new features before release
2. **Testing**: Comprehensive testing of release candidate
3. **Security Review**: External security audit
4. **Documentation**: Update all documentation
5. **Release**: Tagged release with changelog

## 📞 Getting Help

Need help getting started?

1. Check existing issues and documentation
2. Join our Discord community
3. Attend weekly developer calls
4. Reach out to maintainers

## 🙏 Thank You

Thank you for contributing to ZK Privacy Hook! Your contributions help build the future of private decentralized finance.

---

*This contributing guide is a living document and will be updated as the project evolves.*
