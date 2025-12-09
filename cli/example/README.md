# CodeDefender CLI

Example CodeDefender CLI usage:

```ps
$env:CD_API_KEY=eyJ0eX....
# Usage: codedefender-cli.exe --config <FILE> --api-key <API_KEY> --input-file <INPUT> --output <OUTPUT>

codedefender-cli --config example\config.yaml --input-file=example\HelloWorld.exe --pdb-file=example\HelloWorld.pdb --output=obfuscated.zip
```

# Building

You can also build CodeDefender CLI for linux, MacOS, etc using cargo without issue.