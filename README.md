# BackdoorRemover

[Watch on YouTube](https://www.youtube.com/watch?v=8LRwmoFy-sU)

The #1 Backdoor detector/scanner & disinfector for Minecraft servers.

BackdoorRemover is a Spigot/Paper plugin designed to protect your Minecraft server by detecting, analyzing, and removing malicious backdoors from plugin jars. Whether you're running a large network or a small server, this tool helps you stay protected!

## Installation

1. Download the latest JAR file from releases
2. Place it in your server's `plugins/` folder
3. Restart your server
4. Configure as needed in `plugins/BackdoorRemover/config.yml`

## Commands

### Main Scanner
```
/backdoorfinder scan [plugin.jar|all]     - Scan specific plugin or all plugins
/backdoorfinder thicc [plugin.jar|all]    - Scan only for known Thicc RAT markers
/backdoorfinder cleanup [plugin.jar|all]  - Remove confirmed RAT infections
/backdoorfinder reload                    - Reload configuration
```

Aliases: `/bdf`

### L10 Detection
```
/antil10 scan                  - Scan for L10 markers
/antil10 quarantine            - Quarantine L10-infected plugins
```

## Configuration

Edit `plugins/BackdoorRemover/config.yml`:

```yaml
webhook-url: "ur webhook here :D"
auto-scan-on-startup: false
include-clean-results: false
suspicious-score-threshold: 40
min-score-to-send: 0
max-evidence-per-rule: 4
```

## Permissions

- `backdoorfinder.use` - Use the main scanner commands (default: OP)
- `backdoorfinder.scan` - Scan plugins (default: OP)
- `backdoorfinder.cleanup` - Disinfect/quarantine plugins (default: OP)
- `backdoorfinder.reload` - Reload config (default: OP)
- `antil10.admin` - Use L10 detection commands (default: OP)

## How It Works

BackdoorRemover scans plugin JAR files for:
- Known malware signatures and patterns
- Suspicious class structures
- Command hooks that indicate backdoors
- Configuration remnants from previous infections

What can it do?:
1. Scan any plugin for malware and give you a rating & the things that flagged it
2. Can automatically disinfect ThiccIndustries Malware 
3. Creates backups before any modifications
4. Quarantines files
5. Notifies admins via Discord (if configured)

## To Do List

- **False Positives**
- **L10 Disinfector**

## Requirements

- Java 21 or higher
- Paper 1.20.6+ (or compatible Spigot fork)

## Support

Found a bug? Have a suggestion? Open an issue on GitHub, or open a pull request.
