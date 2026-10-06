# Wildbox Use Cases

Worked examples of Wildbox for specific security operations scenarios.

## Available use cases

### Web attack detection

Directory: [web-attack-detection/](web-attack-detection/)
Components: sensor, gateway, data service

Ingests nginx access logs through the sensor and stores them as telemetry
events, in which these common web attack patterns can be looked for (Wildbox
does not detect them itself):

- SQL injection
- Cross-site scripting (XSS)
- Path traversal
- Command injection
- Brute force login attempts
- Security scanner activity

It covers:

- Configuring the sensor for log forwarding
- Generating sample nginx access logs that contain attack patterns
- Querying stored telemetry events through the gateway

```bash
cd web-attack-detection
./quick-start.sh
```

## Ideas for further use cases

None of these exist yet. Each line names the Wildbox components such a use case
would build on.

- **Cloud security monitoring** (CSPM, data service, agents): check AWS accounts
  for misconfigurations. AWS is the only cloud provider the CSPM service
  implements.
- **Threat intelligence enrichment** (data service, agents): enrich events with
  indicators from the data service's seven threat-feed collectors.
- **Automated incident response** (responder, agents, gateway): respond to
  incidents with the responder's YAML playbooks.
- **Endpoint threat hunting** (sensor, data service, agents): hunt with osquery
  queries run by the sensor.
- **API security monitoring** (gateway, data service, agents).

## Use case template

To contribute a use case, use this structure:

```text
use-cases/
└── your-use-case-name/
    ├── README.md              # Main documentation
    ├── quick-start.sh         # Automated setup script
    ├── sample-data/           # Sample data for testing
    │   └── generate.py        # Data generator (optional)
    ├── configs/               # Configuration files
    │   └── config.yaml
    └── docs/                  # Additional documentation
        ├── architecture.md
        └── troubleshooting.md
```

### Required sections in README.md

1. **Overview**: what the use case demonstrates
2. **Architecture**: component diagram
3. **Prerequisites**: what is needed to run it
4. **Quick start**: step-by-step setup instructions
5. **Testing**: how to verify it works
6. **Next steps**: how to extend the use case

## Contributing use cases

1. Fork the repository.
2. Create your use case following the template above.
3. Test it on a fresh installation.
4. Document every dependency and step.
5. Open a pull request that describes the use case.

Guidelines:

- Use real-world scenarios and include sample data.
- Provide an automated setup script.
- Do not include sensitive data.
- Do not require paid external services unless clearly marked optional.

See [CONTRIBUTING.md](../CONTRIBUTING.md) for the general process.

## Additional resources

- [Wildbox documentation](../docs/)
- [Architecture overview](../README.md#architecture)
- [Quick start guide](../docs/guides/quickstart.md)

## License

The use cases are part of the Wildbox project and licensed under the MIT
License.
