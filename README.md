## Detect-Rootkits.sh

This script scans for suspicious kernel modules that may indicate the presence of rootkits, providing a JSON-formatted output for integration with your SIEM.

### Overview

The `Detect-Rootkits.sh` script identifies potential security risks in loaded kernel modules by analyzing their signatures, paths, and visibility. It outputs results in a standardized JSON format suitable for active response workflows.

### Script Details

#### Core Features

1. **Unsigned Module Detection**: Identifies kernel modules that lack a valid signature.
2. **Temporary Directory Detection**: Flags modules loaded from temporary directories such as `/tmp`, `/var/tmp`, or `/dev/shm`.
3. **Hidden Module Detection**: Detects modules that are loaded but hidden from `lsmod`.
4. **JSON Output**: Generates a structured JSON report for integration with security tools.
5. **Logging Framework**: Provides detailed logs for script execution and findings.
6. **Log Rotation**: Implements automatic log rotation to manage log file size.

### How the Script Works

#### Command Line Execution
```bash
./Detect-Rootkits.sh [PROC_MODULES_FILE]
```

#### Parameters

| Parameter           | Type   | Default Value                  | Description                                      |
|---------------------|--------|--------------------------------|--------------------------------------------------|
| `PROC_MODULES_FILE` | string | `/proc/modules`                | Path to the file containing the list of loaded kernel modules |
| `ARLog`             | string | `/var/ossec/active-response/active-responses.log` | Path for active response JSON output            |
| `LogPath`           | string | `/tmp/Detect-Rootkits.sh-script.log` | Path for detailed execution logs                |
| `LogMaxKB`          | int    | 100                            | Maximum log file size in KB before rotation     |
| `LogKeep`           | int    | 5                              | Number of rotated log files to retain           |

#### Example Invocation

```bash
# Run the script with default parameters
./Detect-Rootkits.sh

# Run the script with a custom modules file
./Detect-Rootkits.sh /custom/path/to/modules
```

### Script Execution Flow

#### 1. Initialization Phase
- Clears the active response log file.
- Rotates the detailed log file if it exceeds the size limit.
- Logs the start of the script execution.

#### 2. Kernel Module Analysis
- **Unsigned Module Check**: Flags modules without a valid signature.
- **Temporary Directory Check**: Flags modules loaded from `/tmp`, `/var/tmp`, or `/dev/shm`.
- **Hidden Module Check**: Flags modules that are loaded but not visible in `lsmod`.

#### 3. JSON Output Generation
- Formats findings into a JSON array.
- Writes the JSON result to the active response log.

#### 4. Completion Phase
- Logs the duration of the script execution.
- Outputs the final JSON result.

### JSON Output Format

#### Suspicious Modules Found
```json
{
  "timestamp": "2025-07-18T10:30:45.123Z",
  "host": "HOSTNAME",
  "action": "Detect-Rootkits.sh",
  "data": [
    {
      "module": "suspicious_module",
      "path": "/tmp/suspicious.ko",
      "reason": "Module loaded from temp directory"
    },
    {
      "module": "hidden_module",
      "path": "",
      "reason": "Module hidden from lsmod"
    }
  ],
  "copilot_soar": true
}
```

#### No Suspicious Modules Found
```json
{
  "timestamp": "2025-07-18T10:30:45.123Z",
  "host": "HOSTNAME",
  "action": "Detect-Rootkits.sh",
  "data": [],
  "copilot_soar": true
}
```

### Implementation Guidelines

#### Best Practices
- Run the script with appropriate permissions to access kernel module information.
- Validate the JSON output for compatibility with your security tools.
- Test the script in isolated environments before production use.

#### Security Considerations
- Ensure the script runs with minimal privileges.
- Validate all input paths to prevent injection attacks.
- Protect the active response log file from unauthorized access.

### Troubleshooting

#### Common Issues
1. **Permission Errors**: Ensure the script has read access to `/proc/modules` and other required files.
2. **Empty Results**: Verify that the modules file contains valid kernel module information.
3. **Log File Issues**: Check write permissions for the log paths.

#### Debugging
Enable verbose logging by setting the `VERBOSE` environment variable:
```bash
VERBOSE=1 ./Detect-Rootkits.sh
```

### Contributing

When modifying this script:
1. Maintain the core logging, JSON output, and log rotation structure.
2. Follow Shell scripting best practices.
3. Document any additional functionality or parameters.
4. Test thoroughly in isolated environments.
