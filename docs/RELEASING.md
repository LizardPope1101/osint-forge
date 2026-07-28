# Releasing OSINT Forge

1. Ensure `main` is green in GitHub Actions.
2. Replace the development version in `forge/osint_forge.py` with the release
   version.
3. Move relevant entries from `CHANGELOG.md` under a dated version heading.
4. Run:

   ```bash
   ./scripts/dev-check.sh
   ```

5. Confirm the Python 3.10–3.13, ShellCheck, and Debian integration jobs pass.
6. Test `bootstrap.sh` on clean Debian and Ubuntu virtual machines.
7. Commit the release preparation as `Prepare vX.Y.Z`.
8. Create an annotated tag:

   ```bash
   git tag -a vX.Y.Z -m "OSINT Forge vX.Y.Z"
   git push origin main vX.Y.Z
   ```

9. Create a GitHub release from the tag with the matching changelog section.

Do not publish a release containing target data, reports, credentials, cookies,
tokens, local state, or investigation artifacts.
