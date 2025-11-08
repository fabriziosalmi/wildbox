# 🤝 Contributing to Wildbox

We welcome contributions from the security community! In the current evaluation phase, we especially need your feedback and expertise to make Wildbox more robust, feature-rich, and easy to use.

## 🔥 High Priority Contributions (Evaluation Phase)

As we are in an early evaluation phase, we are looking for feedback on the following:

**Testing & Feedback** (No coding required)
- [ ] Deploy Wildbox and share your experience.
- [ ] Test different deployment scenarios (Docker, cloud, on-premise).
- [ ] Try various security integrations and workflows.
- [ ] Report bugs and edge cases you discover.
- [ ] Suggest features based on your security needs.
- [ ] Performance testing in different environments.

**Issues & Bug Reports**
- [ ] Compatibility issues (OS, Python, Node versions).
- [ ] Documentation gaps or unclear sections.
- [ ] Error messages that need improvement.
- [ ] Configuration options that are confusing.
- [ ] Performance bottlenecks you discover.

**Real-World Feedback**
- [ ] Share your deployment architecture.
- [ ] Document security use cases you implement.
- [ ] Suggest integrations with your tools.
- [ ] Provide scaling feedback (10, 100, 1000+ events/sec).
- [ ] Report operational issues and solutions.

## 💻 Code Contribution Process

1.  **Fork** the repository on GitHub.
2.  **Create** a feature branch: `git checkout -b feature/my-feature`.
3.  **Make** your changes with clear, descriptive commits.
4.  **Test** your changes thoroughly.
5.  **Push** to your fork: `git push origin feature/my-feature`.
6.  **Create** a Pull Request with a detailed description of your changes.

## 💡 Contribution Areas

### Easy Wins for New Contributors
- [ ] Documentation improvements and clarifications.
- [ ] README translations to other languages.
- [ ] Additional example configurations.
- [ ] Docker Compose variations for different scenarios.
- [ ] Helpful scripts and automation.
- [x] **API Documentation** - Document service endpoints ([Contributing Guide](docs/api/CONTRIBUTING.md)).
  - [x] Guardian Service API endpoints and examples.
  - [x] Agents Service AI analysis endpoints.
  - [x] Data Service aggregation endpoints.
  - [x] Tools Service execution endpoints.
  - [x] Responder Service playbook endpoints.
  - [ ] CSPM Service cloud security endpoints.

### Medium-Level Contributions
- [ ] New SOAR playbook examples.
- [ ] Additional threat intelligence sources.
- [ ] Cloud provider integrations (starter).
- [ ] Dashboard improvements and visualizations.
- [ ] API client libraries in different languages.

### Advanced Contributions
- [ ] Multi-tenancy support.
- [ ] High-availability clustering.
- [ ] Advanced analytics features.
- [ ] Custom authentication backends.
- [ ] Performance optimizations.

## 🔒 Security Contributions

Found a security vulnerability?

**Please report security issues privately:**
- Email: fabrizio.salmi@gmail.com
- **Do NOT create public GitHub issues for security vulnerabilities.**
- Include: description, reproduction steps, and impact assessment.
- Allow 48 hours for an initial response.

## 🎨 Code Style

- **Python**: Follow PEP 8 and use Black for formatting.
- **TypeScript**: Follow the ESLint configuration and use Prettier.
- **Commits**: Use clear, descriptive messages following the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) specification.
- **Documentation**: Update relevant documentation with your changes.

## ✅ Testing Requirements

- Write unit tests for all new code.
- Add integration tests for API changes.
- Create E2E tests for user-facing features.
- Maintain >80% code coverage.

## 💬 Getting Help

- **Questions?** Ask in [GitHub Discussions](https://github.com/fabriziosalmi/wildbox/discussions).
- **Feature Ideas?** Post in [Discussions > Ideas](https://github.com/fabriziosalmi/wildbox/discussions/categories/ideas).
- **Found a Bug?** Create an [Issue](https://github.com/fabriziosalmi/wildbox/issues) with details.
- **Want to Help?** Check [open issues](https://github.com/fabriziosalmi/wildbox/issues) marked as `help-wanted`.
