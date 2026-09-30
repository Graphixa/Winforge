# WinForge configuration schema v1 — design draft 1

Prepared 1 October 2026. This is a complete design proposal for the current sample configuration and reviewed implementation options, not an implemented runtime release. The reference YAML illustrates choices; it is not a recommended machine baseline.

## Files

- `winforge.reference.yaml`: commented full reference, including installation, configuration, removals and migrations.
- `winforge.schema.json`: JSON Schema 2020-12 for editor completion and structural validation of parsed YAML.
- This document: execution contract, complete field reference, migration mapping and implementation decisions.

## Agreed design

1. Independent top-level domains: explorer, taskbar, theme, startMenu, defender, updates, features and each Google product. There is no desktop/windows/google grouping umbrella. Nest only when fields belong to the same actual resource, such as a mapped drive or UAC policy.
2. Use lowerCamelCase keys and enable/disable, allow/block, show/hide values. No `ensure`, `present`, `absent`, `enabled`, `disabled`, `allowed`, `blocked`, `visible` or `hidden` state vocabulary.
3. Resource collections use add/remove. Features use enable/disable lists because disabling a Windows feature is not necessarily removing its payload.
4. All top-level sections and individual settings are optional. `{}` is valid and performs no managed-system changes. An empty YAML document may be normalised to `{}` by the loader; an explicit null property is invalid. Once a list entry is specified, its identity and required payload must be complete: optional configuration does not permit an anonymous registry value or package.
5. Omitted means unmanaged, not reset, not disabled and not removed. Empty objects/lists also request no changes. No hidden baseline, automatic restore point, Explorer restart or reboot for a no-op config.
6. A declared desired state that already matches causes no mutation. Read-only discovery and latest-version checks may still happen.
7. Reject unknown keys, unsupported enum values, duplicate YAML keys and conflicting declarations before applying anything. No silent fallback.
8. Native identifiers (package IDs, feature IDs, registry names, Office IDs) retain their native spelling; enum tokens defined by WinForge are canonical and case-sensitive.

## Registry contract

`registry.add` creates every missing parent key along the path, then creates or updates the named value and its type. If path, type and value match, it does nothing. It does not overwrite unrelated values. No createMissing flag is necessary.

`registry.remove` removes only the specified value. A missing path/value is already compliant: do nothing and do not create the path. A name is mandatory; an empty name explicitly addresses the default value. Omitting name never means delete an entire key. Whole-key deletion and .reg import are outside this v1 contract.

Compare binary values byte-for-byte, multiString arrays in order and scalar values using their declared registry type. dword/qword are unsigned integers within the schema bounds. expandString preserves its literal value for Windows expansion; it must not be eagerly expanded by WinForge. Registry view (32/64-bit) and HKCU user identity must be resolved explicitly by the runner and included in the plan.

## Application contract

`apps.add`: an absent app is installed; an exact quoted version is compared and converged to. If the installed version equals the exact version, no change. If version is omitted or latest, resolve the provider's latest version once for this run; install if absent or upgrade if older. If already current, do nothing. Do not automatically downgrade a newer installed version under latest policy; report it as newer than the resolved repository version. Explicit exact-version downgrades require provider support and clear failure otherwise.

`apps.remove`: remove an installed app; missing app is a no-op. Apps omitted entirely are unmanaged. Resolve identity using effective provider plus canonical ID. Reject add/remove overlap or conflicting versions, including overlap with Google installation declarations and expanded removal profiles. Provider omission selects winget only for declared entries; it does not install a manager until an entry requires it. Native installers, package managers and language/font installers need verified exit-code and version detection.

Google product `install: add/remove` controls that product only; it is omitted for policy-only changes. Product adapters must identify the matching apps resource and provide the same latest-version convergence semantics. Remove combined with product policy settings is a conflict. GCPW enrolment requirements are checked before a requested installation, without forcing token changes when only unrelated policy is managed.

## Files, tasks, shortcuts and commands

- files.add creates missing parent directories. For a file with source/content, compare content and update only when different; source and content are mutually exclusive. Without either, ensure existence without truncating an existing file. A directory source merges the source tree; it never prunes unspecified destination children. Reject source/destination overlap or cycles. Wrong existing resource type is an error, not permission to destroy it.
- files.remove removes the named file or directory tree; absent target is a no-op. Validate declared type. Reject overlaps with add/move/rename destinations and protected-root deletions. Extra directory children are only removed when the directory itself is explicitly in remove.
- Move/rename cannot infer success merely because the source disappeared. On first application, record the source/destination identity and content fingerprint. On a repeat, verify the destination against the saved record or supplied expectedSha256. Missing source with unverified destination is an error. Never overwrite a different existing destination. Directory verification requires a persisted tree manifest; a file hash does not prove directory identity. When both source and destination exist, equal content can be reconciled deliberately; differing content is a conflict. A successful repeated migration does not move unrelated replacement data.
- Task identity is folder plus name. Compare canonical task definition and explicit properties before registering/updating; omitted optional properties on an existing task remain unmanaged unless they are part of the explicitly supplied XML. Repository imports expand a pinned commit into explicit tasks before conflict checking. Supplied description/state override the XML only when declared.
- Shortcut identity is location plus name. Compare target and supplied properties before writing; omitted optional properties are preserved on existing shortcuts. Creating a new shortcut uses native defaults for omitted optional properties. Missing removal target is a no-op. Never infer arguments by splitting on spaces.
- Commands are the explicit code-execution escape hatch. Each command has a stable ID, a read-only test and either program/arguments or a script. Test exit 0 skips apply; 1 requests apply; other codes fail. The apply command must succeed and a second test must return 0. Run tests in isolated child processes, so exit cannot end the engine. This enables guarded repeatability, not a guarantee about arbitrary user code. Order custom commands as listed, after declarative resources; reject undeclared inter-resource dependency assumptions.

## Optional fields and partial configurations

Partial settings on existing resources update only the specified properties. For new resources, validate all necessary construction inputs before mutation. Office is the main case: an existing installation can receive an updates-only change; installation on an absent machine requires productId, languages, channel and architecture. Missing information is a preflight error, not permission to invent a product/channel. Empty languages means no language changes and cannot satisfy a new-install requirement.

User-scoped settings require an explicitly resolved target user. The runner can use the interactive caller when appropriate, but must not silently apply HKCU/UI/drive settings to SYSTEM or the administrator account when another user was intended. All user-domain sections share that resolved identity. A plan must show user versus machine scope. Omitted UI fields remain unchanged; aggregate any necessary shell refresh into one action after actual changes.

Power timeouts apply to AC and battery in this draft, preserving existing broad behaviour without deeper nesting. A later independent override design is possible. `never` is explicit; omission is untouched. Reject disable sleep/hibernate combined with a finite corresponding timeout, and reject fastStartup enable when hibernate disable is requested. Enabling a feature without a timeout preserves existing timeout values. Reboot decisions remain with the runner; office.restart describes installer behaviour and cannot override a stricter runner restart policy. An already compliant Office configuration does not reboot because restart is always.

## Validation layers and security

The JSON Schema validates structure, vocabulary, required resource fields, some mutual exclusions and registry value types. It cannot validate the machine, resolve secret references, detect case-insensitive identity overlaps across arrays, check all cross-setting conflicts, or determine package-provider capabilities. The engine must perform semantic validation and target preflight before apply. JSON Schema validation alone is not deployment authorisation.

Version strings must be quoted. Reject malformed or duplicate-key YAML, unsafe tags and non-JSON types. Unknown schema versions fail; absent schemaVersion selects v1. Version 1 is a draft namespace and will be frozen only when implementation is ready. Convert legacy files explicitly; never silently parse old keys as new keys.

Secret references are opaque names supplied by a runtime secret provider or an explicit secure prompt. A config does not contain secret-provider credentials. The encrypted config envelope is handled before schema validation; normal deployment decrypts in memory. Do not evaluate $env: or $() expressions from paths/values. Restrict %NAME% substitution to documented filesystem paths and environment values; literal command scripts are the explicit exception. Registry strings remain literal, especially expandString.

Local relative sources resolve against the original config location, never its downloaded temporary location. Remote relative sources resolve against the original HTTPS URL under a documented trust policy. Executable/task/config sources need trusted digests or signatures; the optional sha256 field does not establish trust if an attacker can change both source and digest. Validate target time zones, locales, feature availability, Office product/channel combinations and Windows policy support at preflight. Unsupported settings fail clearly, never report success after an ineffective write.

## Existing gaps preserved as explicit design work

The old sample advertises some fields that the current code ignores or does not dispatch. They remain represented in this design; inclusion here does not claim implementation support. In particular: animations, personalised advertising, sleep/hibernate timeout handling, ASR, Defender full-scan scheduling/network scanning/default action, command dispatch and language dispatch need implementation work. Exact Windows/Google/Office mappings must be verified against supported versions before release.

- ASR: the legacy boolean never defined a rule set. `attackSurfaceReduction: enable/disable` reserves that intent, but must fail target preflight until an immutable reviewed rule profile is specified. There is no invented all-rules default.
- Diagnostic data: legacy DisableDiagnosticData has no handler. Proposed consolidation with diagnosticData needs deliberate migration review. Disable requests a policy state supported by the target; it is not a claim that Windows emits no telemetry.
- Defender cloud and sample settings currently overlap: consolidate them and reject contradictory legacy values instead of keeping last-write-wins.
- Update day numbering and AUOptions comments are inconsistent in the old sample. Migration must show the chosen named mode/day and reject ambiguous values. New schedules require mode scheduledInstall and a complete day/time pair when constructing a schedule; partial updates can use inspected existing schedule values. Do not silently interpret old numeric values using misleading comments.
- UAC prompts require correct consent and secure-desktop policy combinations. A prompt declaration with state disable is a conflict.
- legacyBloatwareV1 is an optional compatibility profile, not a recommendation. Its fixed names are listed below. Preserve all-users/provisioned-package scope in the plan, and inspect installed and provisioned state independently. Removing the profile later does not reinstall its apps.
- New explicit complements (remove for fonts/languages/environment/PATH/drives/exclusions/shortcuts), audit modes, secure references and command guards are design extensions required for consistent management; they are not claimed existing functionality.

## Complete property reference

Objects and lists may be omitted or empty. Required columns apply only inside an explicitly supplied resource entry. Semantic requirements may additionally depend on target state, as explained above.

### schemaVersion

| Field | Type / values | Required in entry | Meaning |
|---|---|---|---|
| `schemaVersion` | `1` | No | Optional in v1; omitted selects v1. The completely empty object is valid. |

### system

| Field | Type / values | Required in entry | Meaning |
|---|---|---|---|
| `system` | object | No |  |
| `system.hostname` | string | No |  |
| `system.locale` | string | No |  |
| `system.timeZone` | string | No | Validated against target Windows time-zone IDs. |
| `system.deviceSetupPrompts` | `show`, `hide` | No |  |
| `system.languages` | object | No |  |
| `system.languages.add` | array | No |  |
| `system.languages.add[]` | string | No | Language tag. |
| `system.languages.remove` | array | No |  |
| `system.languages.remove[]` | string | No | Language tag. |

### activation

| Field | Type / values | Required in entry | Meaning |
|---|---|---|---|
| `activation` | object | No |  |
| `activation.edition` | `home`, `pro`, `education`, `enterprise` | No |  |
| `activation.productKeyRef` | string | No | Reference resolved by the runner/secret provider, not a literal password or token. |

### apps

| Field | Type / values | Required in entry | Meaning |
|---|---|---|---|
| `apps` | object | No |  |
| `apps.provider` | `winget`, `chocolatey` | No | Omitted uses winget; entry-level provider overrides it. |
| `apps.add` | array | No |  |
| `apps.add[]` | object | No |  |
| `apps.add[].id` | string | Yes | Exact provider-specific package ID. |
| `apps.add[].provider` | `winget`, `chocolatey` | No |  |
| `apps.add[].version` | string | No | Quoted exact version or latest. Omitted means check latest and upgrade if outdated. |
| `apps.remove` | array | No |  |
| `apps.remove[]` | object | No |  |
| `apps.remove[].id` | string | Yes | Exact provider-specific package ID. |
| `apps.remove[].provider` | `winget`, `chocolatey` | No |  |
| `apps.storeAccess` | `allow`, `block` | No |  |
| `apps.oneDrive` | `allow`, `block` | No | Allow/block usage; does not install/uninstall OneDrive. |
| `apps.removeProfiles` | array | No |  |
| `apps.removeProfiles[]` | `legacyBloatwareV1` | No | Explicit fixed manifest carried from the reviewed commit; preview every removal. |

### environment

| Field | Type / values | Required in entry | Meaning |
|---|---|---|---|
| `environment` | object | No |  |
| `environment.add` | array | No |  |
| `environment.add[]` | object | No |  |
| `environment.add[].name` | string | Yes |  |
| `environment.add[].scope` | `user`, `machine` | Yes | User is the explicitly resolved deployment user; machine is system-wide. |
| `environment.add[].value` | string | Yes |  |
| `environment.remove` | array | No |  |
| `environment.remove[]` | object | No |  |
| `environment.remove[].name` | string | Yes |  |
| `environment.remove[].scope` | `user`, `machine` | Yes | User is the explicitly resolved deployment user; machine is system-wide. |

### path

| Field | Type / values | Required in entry | Meaning |
|---|---|---|---|
| `path` | object | No |  |
| `path.add` | array | No |  |
| `path.add[]` | object | No |  |
| `path.add[].value` | string | Yes |  |
| `path.add[].scope` | `user`, `machine` | Yes | User is the explicitly resolved deployment user; machine is system-wide. |
| `path.remove` | array | No |  |
| `path.remove[]` | object | No |  |
| `path.remove[].value` | string | Yes |  |
| `path.remove[].scope` | `user`, `machine` | Yes | User is the explicitly resolved deployment user; machine is system-wide. |

### explorer

| Field | Type / values | Required in entry | Meaning |
|---|---|---|---|
| `explorer` | object | No |  |
| `explorer.fileExtensions` | `show`, `hide` | No |  |
| `explorer.hiddenItems` | `show`, `hide` | No |  |
| `explorer.contextMenu` | `classic`, `modern` | No |  |
| `explorer.allTasksFolder` | `add`, `remove` | No | The former God Mode folder; omitted leaves it alone. |

### taskbar

| Field | Type / values | Required in entry | Meaning |
|---|---|---|---|
| `taskbar` | object | No |  |
| `taskbar.alignment` | `left`, `centre` | No |  |
| `taskbar.meetNow` | `show`, `hide` | No |  |
| `taskbar.widgets` | `show`, `hide` | No |  |
| `taskbar.taskView` | `show`, `hide` | No |  |
| `taskbar.search` | `show`, `hide` | No |  |

### startMenu

| Field | Type / values | Required in entry | Meaning |
|---|---|---|---|
| `startMenu` | object | No |  |
| `startMenu.appLaunchTracking` | `enable`, `disable` | No |  |
| `startMenu.recentlyAddedApps` | `show`, `hide` | No |  |
| `startMenu.suggestions` | `show`, `hide` | No |  |

### theme

| Field | Type / values | Required in entry | Meaning |
|---|---|---|---|
| `theme` | object | No |  |
| `theme.mode` | `light`, `dark` | No |  |
| `theme.desktopIconSize` | `small`, `medium`, `large` | No |  |
| `theme.wallpaper` | string | No | Local path relative to the config origin, absolute path, or HTTPS URL. Never evaluate PowerShell expressions. |
| `theme.lockScreen` | string | No | Local path relative to the config origin, absolute path, or HTTPS URL. Never evaluate PowerShell expressions. |
| `theme.transparency` | `enable`, `disable` | No |  |
| `theme.animations` | `enable`, `disable` | No |  |

### power

| Field | Type / values | Required in entry | Meaning |
|---|---|---|---|
| `power` | object | No | Timeouts apply to both AC and battery in this v1 design, matching the existing broad scope. |
| `power.plan` | `balanced`, `highPerformance`, `powerSaver` | No |  |
| `power.sleep` | `enable`, `disable` | No |  |
| `power.hibernate` | `enable`, `disable` | No |  |
| `power.fastStartup` | `enable`, `disable` | No |  |
| `power.displayTimeout` | string | No | Positive whole duration in minutes/hours, or never. Never is a managed value, not omission. |
| `power.sleepTimeout` | string | No | Positive whole duration in minutes/hours, or never. Never is a managed value, not omission. |
| `power.hibernateTimeout` | string | No | Positive whole duration in minutes/hours, or never. Never is a managed value, not omission. |

### network

| Field | Type / values | Required in entry | Meaning |
|---|---|---|---|
| `network` | object | No |  |
| `network.discovery` | `enable`, `disable` | No |  |
| `network.fileAndPrinterSharing` | `enable`, `disable` | No |  |
| `network.drives` | object | No |  |
| `network.drives.add` | array | No |  |
| `network.drives.add[]` | object | No |  |
| `network.drives.add[].letter` | string | Yes |  |
| `network.drives.add[].path` | string | Yes |  |
| `network.drives.add[].username` | string | No |  |
| `network.drives.add[].passwordRef` | string | No | Reference resolved by the runner/secret provider, not a literal password or token. |
| `network.drives.remove` | array | No |  |
| `network.drives.remove[]` | object | No |  |
| `network.drives.remove[].letter` | string | Yes |  |

### privacy

| Field | Type / values | Required in entry | Meaning |
|---|---|---|---|
| `privacy` | object | No |  |
| `privacy.diagnosticData` | `disable`, `required`, `optional` | No | Intent; validate edition/build support. Never promise zero telemetry from the token alone. |
| `privacy.diagnosticTracking` | `enable`, `disable` | No |  |
| `privacy.location` | `allow`, `block` | No |  |
| `privacy.microphone` | `allow`, `block` | No |  |
| `privacy.camera` | `allow`, `block` | No |  |
| `privacy.personalisedAdvertising` | `allow`, `block` | No |  |
| `privacy.activityHistory` | `enable`, `disable` | No |  |
| `privacy.clipboardHistory` | `enable`, `disable` | No |  |
| `privacy.recall` | `enable`, `disable` | No |  |
| `privacy.copilot` | `enable`, `disable` | No |  |

### fonts

| Field | Type / values | Required in entry | Meaning |
|---|---|---|---|
| `fonts` | object | No |  |
| `fonts.add` | array | No |  |
| `fonts.add[]` | string | No | Font ID resolved through the documented font catalogue. |
| `fonts.remove` | array | No |  |
| `fonts.remove[]` | string | No | Font ID resolved through the documented font catalogue. |

### googleDrive

| Field | Type / values | Required in entry | Meaning |
|---|---|---|---|
| `googleDrive` | object | No |  |
| `googleDrive.install` | `add`, `remove` | No | Omitted means do not manage installation. Policy-only declarations do not install software. |
| `googleDrive.browserPath` | string | No |  |
| `googleDrive.onboardingDialog` | `show`, `hide` | No |  |
| `googleDrive.photosSync` | `enable`, `disable` | No |  |
| `googleDrive.startAtLogin` | `enable`, `disable` | No |  |
| `googleDrive.officeFiles` | `googleDocs`, `desktopApp` | No |  |

### googleChrome

| Field | Type / values | Required in entry | Meaning |
|---|---|---|---|
| `googleChrome` | object | No |  |
| `googleChrome.install` | `add`, `remove` | No | Omitted means do not manage installation. Policy-only declarations do not install software. |
| `googleChrome.enrolmentTokenRef` | string | No | Reference resolved by the runner/secret provider, not a literal password or token. |
| `googleChrome.pdfHandling` | `browser`, `external` | No |  |
| `googleChrome.signIn` | `disable`, `optional`, `required` | No |  |

### googleGcpw

| Field | Type / values | Required in entry | Meaning |
|---|---|---|---|
| `googleGcpw` | object | No |  |
| `googleGcpw.install` | `add`, `remove` | No | Omitted means do not manage installation. Policy-only declarations do not install software. |
| `googleGcpw.enrolmentTokenRef` | string | No | Reference resolved by the runner/secret provider, not a literal password or token. |
| `googleGcpw.allowedDomains` | array | No |  |
| `googleGcpw.allowedDomains[]` | string | No |  |

### security

| Field | Type / values | Required in entry | Meaning |
|---|---|---|---|
| `security` | object | No |  |
| `security.autoPlay` | `enable`, `disable` | No |  |
| `security.remoteDesktop` | `enable`, `disable` | No |  |
| `security.uac` | object | No |  |
| `security.uac.state` | `enable`, `disable` | No |  |
| `security.uac.prompt` | `alwaysNotify`, `notifyChanges`, `notifyWithoutDimming`, `neverNotify` | No | User-facing policy requiring verified consent and secure-desktop mappings. |

### defender

| Field | Type / values | Required in entry | Meaning |
|---|---|---|---|
| `defender` | object | No |  |
| `defender.realTimeProtection` | `enable`, `disable` | No |  |
| `defender.cloudProtection` | `disable`, `basic`, `advanced` | No | Consolidates CloudProtection and MAPSReporting, which currently write the same preference. |
| `defender.sampleSubmission` | `prompt`, `safeSamples`, `allSamples`, `never` | No |  |
| `defender.networkProtection` | `disable`, `audit`, `block` | No |  |
| `defender.controlledFolderAccess` | `disable`, `audit`, `block` | No |  |
| `defender.attackSurfaceReduction` | `enable`, `disable` | No | Uses a fixed, reviewed rule profile; never enable an unspecified changing rule set. |
| `defender.exclusions` | object | No |  |
| `defender.exclusions.paths` | object | No |  |
| `defender.exclusions.paths.add` | array | No |  |
| `defender.exclusions.paths.add[]` | string | No |  |
| `defender.exclusions.paths.remove` | array | No |  |
| `defender.exclusions.paths.remove[]` | string | No |  |
| `defender.exclusions.extensions` | object | No |  |
| `defender.exclusions.extensions.add` | array | No |  |
| `defender.exclusions.extensions.add[]` | string | No |  |
| `defender.exclusions.extensions.remove` | array | No |  |
| `defender.exclusions.extensions.remove[]` | string | No |  |
| `defender.exclusions.processes` | object | No |  |
| `defender.exclusions.processes.add` | array | No |  |
| `defender.exclusions.processes.add[]` | string | No |  |
| `defender.exclusions.processes.remove` | array | No |  |
| `defender.exclusions.processes.remove[]` | string | No |  |
| `defender.scans` | object | No |  |
| `defender.scans.quickTime` | string | No | Local target-machine time, HH:mm. |
| `defender.scans.fullDay` | `daily`, `monday`, `tuesday`, `wednesday`, `thursday`, `friday`, `saturday`, `sunday` | No |  |
| `defender.scans.fullTime` | string | No | Local target-machine time, HH:mm. |
| `defender.scans.removableDrives` | `enable`, `disable` | No |  |
| `defender.scans.archives` | `enable`, `disable` | No |  |
| `defender.scans.networkFiles` | `enable`, `disable` | No |  |
| `defender.defaultThreatAction` | `clean`, `quarantine`, `remove`, `allow`, `userDefined`, `block` | No | Validate supported actions and define severity coverage before application. |

### updates

| Field | Type / values | Required in entry | Meaning |
|---|---|---|---|
| `updates` | object | No |  |
| `updates.mode` | `disable`, `notifyBeforeDownload`, `downloadAndNotify`, `scheduledInstall` | No |  |
| `updates.minorUpdates` | `automatic`, `manual` | No |  |
| `updates.day` | `daily`, `monday`, `tuesday`, `wednesday`, `thursday`, `friday`, `saturday`, `sunday` | No |  |
| `updates.time` | string | No | Local target-machine time, HH:mm. |

### features

| Field | Type / values | Required in entry | Meaning |
|---|---|---|---|
| `features` | object | No |  |
| `features.enable` | array | No |  |
| `features.enable[]` | string | No | Windows optional-feature ID. |
| `features.disable` | array | No |  |
| `features.disable[]` | string | No | Windows optional-feature ID. |

### office

| Field | Type / values | Required in entry | Meaning |
|---|---|---|---|
| `office` | object | No |  |
| `office.productId` | string | No |  |
| `office.productKeyRef` | string | No | Reference resolved by the runner/secret provider, not a literal password or token. |
| `office.languages` | array | No |  |
| `office.languages[]` | string | No |  |
| `office.channel` | string | No | Native Office channel ID; validate against supported provider values. |
| `office.architecture` | `x86`, `x64` | No |  |
| `office.installerUi` | `show`, `hide` | No |  |
| `office.restart` | `never`, `ifRequired`, `always` | No |  |
| `office.updates` | `enable`, `disable` | No |  |

### registry

| Field | Type / values | Required in entry | Meaning |
|---|---|---|---|
| `registry` | object | No |  |
| `registry.add` | array | No |  |
| `registry.add[]` | object | No |  |
| `registry.add[].path` | string | Yes | Registry key path. Add creates missing parent keys. Remove never creates keys. |
| `registry.add[].name` | string | Yes | Empty string identifies the default value. |
| `registry.add[].type` | `string`, `expandString`, `dword`, `qword`, `binary`, `multiString` | Yes |  |
| `registry.add[].value` | choice | Yes |  |
| `registry.add[].description` | string | No |  |
| `registry.remove` | array | No |  |
| `registry.remove[]` | object | No |  |
| `registry.remove[].path` | string | Yes | Registry key path. Add creates missing parent keys. Remove never creates keys. |
| `registry.remove[].name` | string | Yes |  |
| `registry.remove[].description` | string | No |  |

### tasks

| Field | Type / values | Required in entry | Meaning |
|---|---|---|---|
| `tasks` | object | No |  |
| `tasks.add` | array | No |  |
| `tasks.add[]` | object | No |  |
| `tasks.add[].name` | string | Yes |  |
| `tasks.add[].folder` | string | No | Task Scheduler folder; omitted uses root. |
| `tasks.add[].source` | string | Yes | Local path relative to the config origin, absolute path, or HTTPS URL. Never evaluate PowerShell expressions. |
| `tasks.add[].sha256` | string | No | SHA-256 digest in hexadecimal. |
| `tasks.add[].description` | string | No |  |
| `tasks.add[].state` | `enable`, `disable` | No |  |
| `tasks.remove` | array | No |  |
| `tasks.remove[]` | object | No |  |
| `tasks.remove[].name` | string | Yes |  |
| `tasks.remove[].folder` | string | No |  |
| `tasks.repositories` | array | No |  |
| `tasks.repositories[]` | object | No |  |
| `tasks.repositories[].url` | string | Yes | HTTPS Git repository URL. |
| `tasks.repositories[].revision` | string | Yes | Immutable commit SHA. |
| `tasks.repositories[].path` | string | No | Directory of task XML files; root if omitted. |

### files

| Field | Type / values | Required in entry | Meaning |
|---|---|---|---|
| `files` | object | No |  |
| `files.add` | array | No |  |
| `files.add[]` | object | No |  |
| `files.add[].path` | string | Yes |  |
| `files.add[].type` | `file`, `directory` | Yes |  |
| `files.add[].source` | string | No | Local path relative to the config origin, absolute path, or HTTPS URL. Never evaluate PowerShell expressions. |
| `files.add[].content` | string | No |  |
| `files.add[].sha256` | string | No | SHA-256 digest in hexadecimal. |
| `files.remove` | array | No |  |
| `files.remove[]` | object | No |  |
| `files.remove[].path` | string | Yes |  |
| `files.remove[].type` | `file`, `directory` | Yes |  |
| `files.move` | array | No |  |
| `files.move[]` | object | No |  |
| `files.move[].source` | string | Yes |  |
| `files.move[].destination` | string | Yes |  |
| `files.move[].type` | `file`, `directory` | Yes |  |
| `files.move[].expectedSha256` | string | No | SHA-256 digest in hexadecimal. |
| `files.rename` | array | No |  |
| `files.rename[]` | object | No |  |
| `files.rename[].path` | string | Yes |  |
| `files.rename[].newName` | string | Yes | Basename only, in the same directory. |
| `files.rename[].type` | `file`, `directory` | Yes |  |
| `files.rename[].expectedSha256` | string | No | SHA-256 digest in hexadecimal. |

### shortcuts

| Field | Type / values | Required in entry | Meaning |
|---|---|---|---|
| `shortcuts` | object | No |  |
| `shortcuts.add` | array | No |  |
| `shortcuts.add[]` | object | No |  |
| `shortcuts.add[].name` | string | Yes |  |
| `shortcuts.add[].location` | string | Yes | desktop, startMenu, programs, startup; commonDesktop/commonStartMenu/commonPrograms/commonStartup; or an explicit directory path. QuickLaunch requires an explicit path. |
| `shortcuts.add[].target` | string | Yes |  |
| `shortcuts.add[].arguments` | array | No |  |
| `shortcuts.add[].arguments[]` | string | No |  |
| `shortcuts.add[].icon` | object | No |  |
| `shortcuts.add[].icon.path` | string | Yes |  |
| `shortcuts.add[].icon.index` | integer | No |  |
| `shortcuts.add[].workingDirectory` | string | No |  |
| `shortcuts.remove` | array | No |  |
| `shortcuts.remove[]` | object | No |  |
| `shortcuts.remove[].name` | string | Yes |  |
| `shortcuts.remove[].location` | string | Yes | desktop, startMenu, programs, startup; commonDesktop/commonStartMenu/commonPrograms/commonStartup; or an explicit directory path. QuickLaunch requires an explicit path. |

### commands

| Field | Type / values | Required in entry | Meaning |
|---|---|---|---|
| `commands` | array | No | Intentional code execution with a mandatory read-only compliance test. Verify again after apply. |
| `commands[]` | object | No |  |
| `commands[].id` | string | Yes | Unique stable command identity. |
| `commands[].shell` | `process`, `powershell`, `cmd` | Yes |  |
| `commands[].program` | string | No |  |
| `commands[].arguments` | array | No |  |
| `commands[].arguments[]` | string | No |  |
| `commands[].script` | string | No |  |
| `commands[].test` | object | Yes |  |
| `commands[].test.shell` | `powershell`, `cmd` | Yes |  |
| `commands[].test.script` | string | Yes | Read-only detection script; exit 0 means already compliant, 1 means apply, other codes mean error. |

## Legacy-to-v1 migration map

Coverage: every one of the **141** distinct leaf options in the current sample, plus implementation/schema aliases; **164** paths in total. A mapping accounts for an option; it does not imply that old code actually applied it. Removed aliases must cause a validation error in new configs. Migration must surface ambiguous fields and conflicting declarations.

| Old path | New path | Conversion / notes |
|---|---|---|
| `System.ComputerName` | `system.hostname` | Rename; preserve explicit intent. |
| `System.Locale` | `system.locale` | Rename; preserve explicit intent. |
| `System.Timezone` | `system.timeZone` | Reject invalid IDs; AU is not a complete time-zone identifier. |
| `System.DisableWindowsStore` | `apps.storeAccess` | true -> block; false -> allow. |
| `System.DisableOneDrive` | `apps.oneDrive` | true -> block; false -> allow. Uninstallation is separate. |
| `System.DisableCopilot` | `privacy.copilot` | true -> disable; false -> enable. |
| `System.DisableWindowsRecall` | `privacy.recall` | true -> disable; false -> enable. Conflicting duplicate aliases are errors. |
| `Privacy.DisableWindowsRecall` | `privacy.recall` | true -> disable; false -> enable. Conflicting duplicate aliases are errors. |
| `System.DisableRemoteDesktop` | `security.remoteDesktop` | true -> disable; false -> enable. |
| `System.DisableSetupDevicePrompt` | `system.deviceSetupPrompts` | true -> hide; false -> show. |
| `System.LanguagePacks[]` | `system.languages.add[]` | Rename; preserve explicit intent. |
| `Activation.ProductKey` | `activation.productKeyRef` | Move the value to the runner secret provider, then reference it; never copy a key into this reference field. |
| `Activation.Version` | `activation.edition` | Use lower-camel canonical enum. |
| `Applications.PackageManager` | `apps.provider` | winget or chocolatey. |
| `Applications.Install[].App` | `apps.add[].id` | Rename; preserve explicit intent. |
| `Applications.Install[].Version` | `apps.add[].version` | Exact quoted version; omitted or latest resolves newest on each run. |
| `Applications.Uninstall[].App` | `apps.remove[].id` | Rename; preserve explicit intent. |
| `Applications.RemoveBloatware` | `apps.removeProfiles[]` | true -> legacyBloatwareV1; false -> omit. Freeze the reviewed manifest; never infer an inverse reinstall. |
| `Applications.RemoveMSEdge` | `apps.remove[].id` | Implementation contains an unwired AppConfig.RemoveMSEdge branch. Express removal as Microsoft.Edge with the chosen provider; unsupported/protected uninstall must fail clearly, not force bypass. |
| `EnvironmentVariables.User[].Name` | `environment.add[].name` | Set scope: user. |
| `EnvironmentVariables.User[].Value` | `environment.add[].value` | Set scope: user; literal data, safe %NAME% substitution only. |
| `EnvironmentVariables.AddToPath.User[]` | `path.add[].value` | Set scope: user. |
| `EnvironmentVariables.System[].Name` | `environment.add[].name` | Set scope: machine. |
| `EnvironmentVariables.System[].Value` | `environment.add[].value` | Set scope: machine; literal data, safe %NAME% substitution only. |
| `EnvironmentVariables.AddToPath.System[]` | `path.add[].value` | Set scope: machine. |
| `Explorer.ShowFileExtensions` | `explorer.fileExtensions` | true -> show; false -> hide. |
| `System.ShowFileExtensions` | `explorer.fileExtensions` | true -> show; false -> hide. |
| `Explorer.ShowHiddenFolders` | `explorer.hiddenItems` | true -> show; false -> hide; covers files and folders. |
| `System.ShowHiddenFiles` | `explorer.hiddenItems` | true -> show; false -> hide; covers files and folders. |
| `Taskbar.TaskbarAlignment` | `taskbar.alignment` | Left -> left; Center -> centre. |
| `Taskbar.DisableMeetNow` | `taskbar.meetNow` | true -> hide; false -> show. |
| `Taskbar.DisableWidgets` | `taskbar.widgets` | true -> hide; false -> show. |
| `Taskbar.DisableTaskView` | `taskbar.taskView` | true -> hide; false -> show. |
| `Taskbar.DisableSearch` | `taskbar.search` | true -> hide; false -> show. |
| `Theme.DarkMode` | `theme.mode` | true -> dark; false -> light. |
| `Theme.DesktopIconSize` | `theme.desktopIconSize` | Lower-case values. |
| `Theme.WallpaperPath` | `theme.wallpaper` | Rename; preserve explicit intent. |
| `Theme.LockScreenPath` | `theme.lockScreen` | Rename; preserve explicit intent. |
| `Theme.DisableTransparencyEffects` | `theme.transparency` | true -> disable; false -> enable. Reject conflicting aliases. |
| `Theme.DisableTransparency` | `theme.transparency` | true -> disable; false -> enable. Reject conflicting aliases. |
| `Theme.TransparencyEffects` | `theme.transparency` | true -> enable; false -> disable; implementation-only name. |
| `Theme.DisableWindowsAnimations` | `theme.animations` | true -> disable; false -> enable; advertised but not handled in current theme function. |
| `Tweaks.ClassicRightClickMenu` | `explorer.contextMenu` | true -> classic; false -> modern. |
| `Tweaks.GodModeFolder` | `explorer.allTasksFolder` | true -> add; false -> remove; EnableGodMode is implementation alias. |
| `Tweaks.EnableGodMode` | `explorer.allTasksFolder` | true -> add; false -> remove; EnableGodMode is implementation alias. |
| `Power.PowerPlan` | `power.plan` | Canonical named plan. |
| `Power.AllowSleep` | `power.sleep` | true -> enable; false -> disable. |
| `Power.DisableSleep` | `power.sleep` | true -> disable; false -> enable; implementation alias. |
| `Power.AllowHibernate` | `power.hibernate` | true -> enable; false -> disable. |
| `Power.DisableHibernate` | `power.hibernate` | true -> disable; false -> enable; implementation alias. |
| `Power.DisableFastStartup` | `power.fastStartup` | true -> disable; false -> enable. |
| `Power.MonitorTimeout` | `power.displayTimeout` | Minutes -> Nm; zero -> never. Sleep/Hibernate timeouts are advertised but not currently applied. |
| `Power.SleepTimeout` | `power.sleepTimeout` | Minutes -> Nm; zero -> never. Sleep/Hibernate timeouts are advertised but not currently applied. |
| `Power.HibernateTimeout` | `power.hibernateTimeout` | Minutes -> Nm; zero -> never. Sleep/Hibernate timeouts are advertised but not currently applied. |
| `Network.EnableNetworkDiscovery` | `network.discovery` | true -> enable; false -> disable. |
| `Network.AllowNetworkDiscovery` | `network.discovery` | true -> enable; false -> disable. |
| `Network.EnableFileAndPrinterSharing` | `network.fileAndPrinterSharing` | true -> enable; false -> disable. |
| `Network.AllowFileAndPrinterSharing` | `network.fileAndPrinterSharing` | true -> enable; false -> disable. |
| `Network.MapNetworkDrive[].DriveLetter` | `network.drives.add[].letter` | Rename. |
| `Network.MapNetworkDrive[].Path` | `network.drives.add[].path` | Rename. |
| `Network.MapNetworkDrive[].Username` | `network.drives.add[].username` | Rename. |
| `Network.MapNetworkDrive[].Password` | `network.drives.add[].passwordRef` | Password must move to secret provider. |
| `Privacy.DisableTelemetry` | `privacy.diagnosticData` | Current handler requests 0 for true and 1 for false: proposed disable/required intent; validate target support. |
| `Privacy.DisableDiagnosticData` | `privacy.diagnosticData` | Advertised without a handler: proposed consolidation; do not guess migration intent if conflicting. |
| `Privacy.DisableDiagTrack` | `privacy.diagnosticTracking` | true -> disable; false -> enable. |
| `Privacy.DisableAppPrivacy` | `privacy.location + privacy.microphone + privacy.camera` | Current code sets all three: true -> block for each; false -> allow for each. |
| `Privacy.DisablePersonalisedAdvertising` | `privacy.personalisedAdvertising` | true -> block; false -> allow; advertised without handler. |
| `Privacy.DisableStartMenuTracking` | `startMenu.appLaunchTracking + startMenu.recentlyAddedApps` | Preserve both effects: true -> disable/hide; false -> enable/show. |
| `Privacy.DisableActivityHistory` | `privacy.activityHistory` | true -> disable; false -> enable. |
| `Privacy.DisableClipboardDataCollection` | `privacy.clipboardHistory` | Current handler changes clipboard history, not generic collection. true -> disable; false -> enable. |
| `Privacy.DisableStartMenuSuggestions` | `startMenu.suggestions` | true -> hide; false -> show. |
| `Fonts[]` | `fonts.add[]` | Rename; preserve explicit intent. |
| `Fonts.Font[]` | `fonts.add[]` | Rename; preserve explicit intent. |
| `Google.Drive.Install` | `googleDrive.install` | true -> add; false -> remove, matching the existing install/uninstall branches. |
| `Google.Chrome.Install` | `googleChrome.install` | true -> add; false -> remove, matching the existing install/uninstall branches. |
| `Google.GCPW.Install` | `googleGcpw.install` | true -> add; false -> remove, matching the existing install/uninstall branches. |
| `Google.Drive.DefaultWebBrowser` | `googleDrive.browserPath` | Rename. |
| `Google.Drive.DisableOnboardingDialog` | `googleDrive.onboardingDialog` | true -> hide; false -> show. |
| `Google.Drive.DisablePhotosSync` | `googleDrive.photosSync` | true -> disable; false -> enable. |
| `Google.Drive.AutoStartOnLogin` | `googleDrive.startAtLogin` | true -> enable; false -> disable. |
| `Google.Drive.OpenOfficeFilesInDocs` | `googleDrive.officeFiles` | true -> googleDocs; false -> desktopApp. |
| `Google.Chrome.CloudManagementEnrollmentToken` | `googleChrome.enrolmentTokenRef` | Move token to secret provider. |
| `Google.Chrome.AlwaysOpenPdfExternally` | `googleChrome.pdfHandling` | true -> external; false -> browser. |
| `Google.Chrome.BrowserSignin` | `googleChrome.signIn` | 0 -> disable; 1 -> optional; 2 -> required. |
| `Google.GCPW.EnrollmentToken` | `googleGcpw.enrolmentTokenRef` | Move token to secret provider. |
| `Google.GCPW.DomainsAllowedToLogin` | `googleGcpw.allowedDomains[]` | Normalise to a list. |
| `Security.DisableAutoPlay` | `security.autoPlay` | true -> disable; false -> enable. |
| `Security.UAC.Enable` | `security.uac.state` | true -> enable; false -> disable. |
| `Security.UAC.Level` | `security.uac.prompt` | AlwaysNotify -> alwaysNotify; NotifyChanges -> notifyChanges; NotifyNoDesktop -> notifyWithoutDimming; NeverNotify -> neverNotify. Verify actual Windows mappings. |
| `Security.MicrosoftDefender` | `defender.realTimeProtection` | Existing MicrosoftDefender changes real-time monitoring, not Defender installation; normalise positive/negative alias carefully. |
| `Security.DisableMicrosoftDefender` | `defender.realTimeProtection` | Existing MicrosoftDefender changes real-time monitoring, not Defender installation; normalise positive/negative alias carefully. |
| `WindowsDefender.RealTimeProtection` | `defender.realTimeProtection` | true -> enable; false -> disable. ASR advertised but lacks handler; fixed profile must be defined. |
| `WindowsDefender.AttackSurfaceReduction` | `defender.attackSurfaceReduction` | true -> enable; false -> disable. ASR advertised but lacks handler; fixed profile must be defined. |
| `WindowsDefender.CloudProtection` | `defender.cloudProtection` | Current mapping: true -> advanced; false -> disable. |
| `WindowsDefender.ThreatSettings.MAPSReporting` | `defender.cloudProtection` | Disabled -> disable; Basic -> basic; Advanced -> advanced. Reject conflict with CloudProtection. |
| `WindowsDefender.AutomaticSampleSubmission` | `defender.sampleSubmission` | true -> safeSamples; false -> never. |
| `WindowsDefender.ThreatSettings.SubmitSamplesConsent` | `defender.sampleSubmission` | AlwaysPrompt -> prompt; SendSafeSamples -> safeSamples; NeverSend -> never; SendAllSamples -> allSamples. Reject conflicting aliases. |
| `WindowsDefender.NetworkProtection` | `defender.networkProtection` | true -> block; false -> disable; audit is an explicit extension. |
| `WindowsDefender.ControlledFolderAccess` | `defender.controlledFolderAccess` | true -> block; false -> disable; audit is an explicit extension. |
| `WindowsDefender.ExclusionPaths[]` | `defender.exclusions.paths.add[]` | Rename; preserve explicit intent. |
| `WindowsDefender.ExclusionExtensions[]` | `defender.exclusions.extensions.add[]` | Rename; preserve explicit intent. |
| `WindowsDefender.ExclusionProcesses[]` | `defender.exclusions.processes.add[]` | Rename; preserve explicit intent. |
| `WindowsDefender.ScanSettings.QuickScanTime` | `defender.scans.quickTime` | Time/day use named values; booleans -> enable/disable. Full day and network scanning advertised without handlers. |
| `WindowsDefender.ScanSettings.FullScanDay` | `defender.scans.fullDay` | Time/day use named values; booleans -> enable/disable. Full day and network scanning advertised without handlers. |
| `WindowsDefender.ScanSettings.ScanRemovableDrives` | `defender.scans.removableDrives` | Time/day use named values; booleans -> enable/disable. Full day and network scanning advertised without handlers. |
| `WindowsDefender.ScanSettings.ScanArchives` | `defender.scans.archives` | Time/day use named values; booleans -> enable/disable. Full day and network scanning advertised without handlers. |
| `WindowsDefender.ScanSettings.ScanNetworkFiles` | `defender.scans.networkFiles` | Time/day use named values; booleans -> enable/disable. Full day and network scanning advertised without handlers. |
| `WindowsDefender.ThreatSettings.DefaultAction` | `defender.defaultThreatAction` | Lower-camel names; advertised without handler; verify supported actions/severity coverage. |
| `WindowsUpdate.EnableAutomaticUpdates` | `updates.mode` | Resolve together. false -> disable. For enabled: recognised native 2 -> notifyBeforeDownload, 3 -> downloadAndNotify, 4 -> scheduledInstall; ambiguous/other legacy values require review, not blind conversion. |
| `WindowsUpdate.AUOptions` | `updates.mode` | Resolve together. false -> disable. For enabled: recognised native 2 -> notifyBeforeDownload, 3 -> downloadAndNotify, 4 -> scheduledInstall; ambiguous/other legacy values require review, not blind conversion. |
| `WindowsUpdate.AutoInstallMinorUpdates` | `updates.minorUpdates` | true -> automatic; false -> manual; validate target support. |
| `WindowsUpdate.ScheduledInstallDay` | `updates.day` | Legacy sample comments and native numbering disagree: require explicit day selection during migration. |
| `WindowsUpdate.ScheduledInstallTime` | `updates.time` | Integer hour -> quoted HH:00, including midnight. |
| `WindowsFeatures.Enable[]` | `features.enable[]` | Rename; preserve explicit intent. |
| `WindowsFeatures.Disable[]` | `features.disable[]` | Rename; preserve explicit intent. |
| `WindowsFeatures.Feature[].Name` | `features.enable[] or features.disable[]` | Implementation-only shape: distribute Name by State; reject conflicts. |
| `WindowsFeatures.Feature[].State` | `features.enable[] or features.disable[]` | Implementation-only shape: distribute Name by State; reject conflicts. |
| `Office.LicenseKey` | `office.productKeyRef` | Move to secret provider. |
| `Office.ProductID` | `office.productId` | Preserve native identifier. |
| `Office.LanguageID` | `office.languages[]` | Wrap as list. |
| `Office.DisplayLevel` | `office.installerUi` | None -> hide; Full -> show. |
| `Office.SetupReboot` | `office.restart` | Never -> never; Always -> always; add ifRequired. |
| `Office.Channel` | `office.channel` | Preserve native identifier. |
| `Office.OfficeClientEdition` | `office.architecture` | 32 -> x86; 64 -> x64. |
| `Office.UpdatesEnabled` | `office.updates` | true -> enable; false -> disable. |
| `Registry.Add[].Name` | `registry.add[].name` | Normalise type names; preserve native paths/value names. Add creates missing key ancestry; remove does not. |
| `Registry.Add[].Path` | `registry.add[].path` | Normalise type names; preserve native paths/value names. Add creates missing key ancestry; remove does not. |
| `Registry.Add[].Type` | `registry.add[].type` | Normalise type names; preserve native paths/value names. Add creates missing key ancestry; remove does not. |
| `Registry.Add[].Value` | `registry.add[].value` | Normalise type names; preserve native paths/value names. Add creates missing key ancestry; remove does not. |
| `Registry.Add[].Description` | `registry.add[].description` | Normalise type names; preserve native paths/value names. Add creates missing key ancestry; remove does not. |
| `Registry.Remove[].Name` | `registry.remove[].name` | Normalise type names; preserve native paths/value names. Add creates missing key ancestry; remove does not. |
| `Registry.Remove[].Path` | `registry.remove[].path` | Normalise type names; preserve native paths/value names. Add creates missing key ancestry; remove does not. |
| `Registry.Remove[].Description` | `registry.remove[].description` | Normalise type names; preserve native paths/value names. Add creates missing key ancestry; remove does not. |
| `Tasks.Add[].Name` | `tasks.add[].name` | Rename. |
| `Tasks.Add[].Description` | `tasks.add[].description` | Rename. |
| `Tasks.Add[].Path` | `tasks.add[].source` | Rename. |
| `Tasks.Remove[].Name` | `tasks.remove[].name` | Rename. |
| `Tasks.Remove[].Description` | `tasks.remove[].description` | Task remove description is migration-only annotation, not an execution field. |
| `Tasks.AddRepository` | `tasks.repositories[]` | Split URL/path and require immutable revision before application. |
| `Commands.Run[].Program` | `commands[].program` | Assign stable id and shell (process/cmd/powershell), preserve argument boundaries, add a read-only compliance test. Never invent a test automatically. |
| `Commands.Run[].Arguments` | `commands[].arguments[]` | Assign stable id and shell (process/cmd/powershell), preserve argument boundaries, add a read-only compliance test. Never invent a test automatically. |
| `Commands.Cmd[].Command` | `commands[].script` | Assign stable id and shell (process/cmd/powershell), preserve argument boundaries, add a read-only compliance test. Never invent a test automatically. |
| `Commands.Powershell[].Command` | `commands[].script` | Assign stable id and shell (process/cmd/powershell), preserve argument boundaries, add a read-only compliance test. Never invent a test automatically. |
| `FileOperations.Copy[].Source` | `files.add[].source` | Resolve file/directory type. Rename destination with a different directory becomes move. Copy directory uses merge, not deletion of unspecified children. |
| `FileOperations.Copy[].Destination` | `files.add[].path` | Resolve file/directory type. Rename destination with a different directory becomes move. Copy directory uses merge, not deletion of unspecified children. |
| `FileOperations.Move[].Source` | `files.move[].source` | Resolve file/directory type. Rename destination with a different directory becomes move. Copy directory uses merge, not deletion of unspecified children. |
| `FileOperations.Move[].Destination` | `files.move[].destination` | Resolve file/directory type. Rename destination with a different directory becomes move. Copy directory uses merge, not deletion of unspecified children. |
| `FileOperations.Rename[].Source` | `files.rename[].path` | Resolve file/directory type. Rename destination with a different directory becomes move. Copy directory uses merge, not deletion of unspecified children. |
| `FileOperations.Rename[].NewName` | `files.rename[].newName` | Resolve file/directory type. Rename destination with a different directory becomes move. Copy directory uses merge, not deletion of unspecified children. |
| `FileOperations.New[].Type` | `files.add[].type` | Resolve file/directory type. Rename destination with a different directory becomes move. Copy directory uses merge, not deletion of unspecified children. |
| `FileOperations.New[].Path` | `files.add[].path` | Resolve file/directory type. Rename destination with a different directory becomes move. Copy directory uses merge, not deletion of unspecified children. |
| `FileOperations.Delete[].Path` | `files.remove[].path` | Resolve file/directory type. Rename destination with a different directory becomes move. Copy directory uses merge, not deletion of unspecified children. |
| `FileOperations.Shortcut[].Name` | `shortcuts.add[].name` | Preserve argument boundaries; split icon path/index; omit empty workingDirectory. QuickLaunch requires explicit path. |
| `Shortcuts.Shortcut[].Name` | `shortcuts.add[].name` | Preserve argument boundaries; split icon path/index; omit empty workingDirectory. QuickLaunch requires explicit path. |
| `FileOperations.Shortcut[].Target` | `shortcuts.add[].target` | Preserve argument boundaries; split icon path/index; omit empty workingDirectory. QuickLaunch requires explicit path. |
| `Shortcuts.Shortcut[].Target` | `shortcuts.add[].target` | Preserve argument boundaries; split icon path/index; omit empty workingDirectory. QuickLaunch requires explicit path. |
| `FileOperations.Shortcut[].Location` | `shortcuts.add[].location` | Preserve argument boundaries; split icon path/index; omit empty workingDirectory. QuickLaunch requires explicit path. |
| `Shortcuts.Shortcut[].Location` | `shortcuts.add[].location` | Preserve argument boundaries; split icon path/index; omit empty workingDirectory. QuickLaunch requires explicit path. |
| `FileOperations.Shortcut[].Arguments` | `shortcuts.add[].arguments[]` | Preserve argument boundaries; split icon path/index; omit empty workingDirectory. QuickLaunch requires explicit path. |
| `Shortcuts.Shortcut[].Arguments` | `shortcuts.add[].arguments[]` | Preserve argument boundaries; split icon path/index; omit empty workingDirectory. QuickLaunch requires explicit path. |
| `FileOperations.Shortcut[].IconPath` | `shortcuts.add[].icon.path + icon.index` | Preserve argument boundaries; split icon path/index; omit empty workingDirectory. QuickLaunch requires explicit path. |
| `Shortcuts.Shortcut[].IconPath` | `shortcuts.add[].icon.path + icon.index` | Preserve argument boundaries; split icon path/index; omit empty workingDirectory. QuickLaunch requires explicit path. |
| `FileOperations.Shortcut[].WorkingDirectory` | `shortcuts.add[].workingDirectory` | Preserve argument boundaries; split icon path/index; omit empty workingDirectory. QuickLaunch requires explicit path. |
| `Shortcuts.Shortcut[].WorkingDirectory` | `shortcuts.add[].workingDirectory` | Preserve argument boundaries; split icon path/index; omit empty workingDirectory. QuickLaunch requires explicit path. |

## Fixed legacyBloatwareV1 manifest

Names copied from the reviewed source, with no additional packages. Matching must use these declared identities, not a broadened substring search. Preview resolved package identities and all-users/provisioned scope.

```text
Microsoft.3DBuilder
Microsoft.549981C3F5F10
Microsoft.Copilot
Microsoft.Messaging
Microsoft.BingFinance
Microsoft.BingFoodAndDrink
Microsoft.BingHealthAndFitness
Microsoft.BingNews
Microsoft.BingSports
Microsoft.BingTravel
Microsoft.MicrosoftOfficeHub
Microsoft.MicrosoftSolitaireCollection
Microsoft.News
Microsoft.MixedReality.Portal
Microsoft.Office.OneNote
Microsoft.OutlookForWindows
Microsoft.Office.Sway
Microsoft.OneConnect
Microsoft.People
Microsoft.SkypeApp
Microsoft.Todos
Microsoft.WindowsMaps
Microsoft.ZuneVideo
Microsoft.ZuneMusic
MicrosoftCorporationII.MicrosoftFamily
MSTeams
Outlook
LinkedInforWindows
Microsoft.XboxApp
Microsoft.XboxGamingOverlay
Microsoft.Xbox.TCUI
Microsoft.XboxGameOverlay
Microsoft.WindowsCommunicationsApps
Microsoft.YourPhone
MicrosoftCorporationII.QuickAssist
ACGMediaPlayer
ActiproSoftwareLLC
AdobeSystemsIncorporated.AdobePhotoshopExpress
Amazon.com.Amazon
AmazonVideo.PrimeVideo
Asphalt8Airborne
AutodeskSketchBook
CaesarsSlotsFreeCasino
COOKINGFEVER
CyberLinkMediaSuiteEssentials
DisneyMagicKingdoms
Disney
DrawboardPDF
Duolingo-LearnLanguagesforFree
EclipseManager
Facebook
FarmVille2CountryEscape
fitbit
Flipboard
HiddenCity
HULULLC.HULUPLUS
iHeartRadio
Instagram
king.com.BubbleWitch3Saga
king.com.CandyCrushSaga
king.com.CandyCrushSodaSaga
MarchofEmpires
Netflix
NYTCrossword
OneCalendar
PandoraMediaInc
PhototasticCollage
PicsArt-PhotoStudio
Plex
PolarrPhotoEditorAcademicEdition
RoyalRevolt
Shazam
Sidia.LiveWallpaper
SlingTV
Spotify
TikTok
TuneInRadio
Twitter
Viber
WinZipUniversal
Wunderlist
XING
```

## Acceptance checks for implementation

- Empty config and empty sections perform zero managed writes.
- New registry ancestry is created during add; missing paths during remove stay missing.
- Matching registry type/value and exact app version produce no mutation.
- App version omitted resolves latest and upgrades only when outdated; failures to resolve latest are surfaced.
- All explicit negative states (disable/block/hide), midnight and never work without truthiness bugs.
- Unknown fields, duplicate keys and overlapping add/remove identities fail before changes.
- The second apply is unchanged; deliberate drift is corrected on the next apply.
- Files, migrations, tasks and shortcuts compare content/properties rather than only existence.
- Missing secrets, unsupported policies and incompatible Office settings fail before applying.
- CLI, TUI and migration tooling share the same schema and semantic validator.

## Sources and scope

This proposal is grounded in the repository snapshot at commit `93b0b5983b994383662fd7e1695f783c02a29a04`, the current YAML sample, implementation handlers and configuration guide, plus the design decisions in this conversation. Historical TOML test-only fields are not represented as supported current options.

- [Current YAML sample](https://github.com/Graphixa/Winforge/blob/93b0b5983b994383662fd7e1695f783c02a29a04/winforge.yaml)
- [Implementation](https://github.com/Graphixa/Winforge/blob/93b0b5983b994383662fd7e1695f783c02a29a04/winforge.ps1)
- [Configuration guide](https://github.com/Graphixa/Winforge/blob/93b0b5983b994383662fd7e1695f783c02a29a04/docs/Configuration-Guide.md)
- [Issue 5: schema consistency](https://github.com/Graphixa/Winforge/issues/5)
- [Issue 6: idempotency](https://github.com/Graphixa/Winforge/issues/6)

No deployment was executed and no production runtime or GitHub issue was changed by creating these draft artifacts.

## Draft validation performed

The reference YAML parsed without duplicate keys. A local structural checker covering the JSON Schema keywords used here accepted the full reference and 12 positive cases and rejected 16 negative cases. Every sample leaf option has a migration entry. This was not a full standards-validator conformance test or a Windows deployment test. Cross-resource semantics and target compatibility remain implementation acceptance criteria.
