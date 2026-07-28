## Summary

Describe what changed and why.

## Validation

- [ ] `python3 -m unittest discover -s tests -v`
- [ ] `./bin/osint forge validate`
- [ ] `bash -n bootstrap.sh bin/osint scripts/*.sh plugins/*/*.sh`
- [ ] Relevant dry-run or clean-install checks

## Safety and privacy

- [ ] No credentials, cookies, tokens, personal information, targets, or case data are included.
- [ ] Adapter commands remain argument arrays without target interpolation through a shell.
- [ ] Network or infrastructure behavior uses restrained defaults and documents authorization requirements.
- [ ] New plugins declare their upstream project and license.
