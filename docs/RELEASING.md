# Releasing OSINT Forge

1. Ensure `main` is green in GitHub Actions.
2. Replace the development version in `forge/osint_forge.py` with the release
   version.
3. Move relevant entries from `CHANGELOG.md` under a dated version heading.
4. Run:

   ```bash
   python3 -m unittest discover -s tests -v
   ./bin/osint forge validate
   bash -n bootstrap.sh bin/osint scripts/*.sh plugins/*/*.sh
   ```

5. Test `bootstrap.sh` on clean Debian and Ubuntu virtual machines.
6. Commit the release preparation as `Prepare vX.Y.Z`.
7. Create an annotated tag:

   ```bash
   git tag -a vX.Y.Z -m "OSINT Forge vX.Y.Z"
   git push origin main vX.Y.Z
   ```

8. Create a GitHub release from the tag with the matching changelog section.

Do not publish a release containing target data, reports, credentials, cookies,
tokens, local state, or investigation artifacts.
