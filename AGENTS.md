# Repository safeguards

## Local Xcode settings

- `apps/ios/Config/Local.xcconfig` contains only local development-team and Bundle ID overrides. It is excluded by `.gitignore`; never force-add or commit it.
- After cloning the repository, run `git config core.hooksPath .githooks` to enable the commit hooks.

## Git pre-commit checks

- Before every `git commit`, inspect the staged `apps/ios/Addressee.xcodeproj/project.pbxproj`, not just the working-tree file.
- For `DEVELOPMENT_TEAM` and `PRODUCT_BUNDLE_IDENTIFIER`, only an absent setting, `KEY = ;`, or `KEY = "";` is permitted. Reject any nonempty assignment and direct the user to move it to `apps/ios/Config/Local.xcconfig`.
- `.githooks/pre-commit` performs these checks automatically. It can also be run directly to inspect the staged files. If the hook is not enabled, enable it and perform the equivalent checks manually first.
- Never use `git commit --no-verify` or any other means to bypass these safeguards.
