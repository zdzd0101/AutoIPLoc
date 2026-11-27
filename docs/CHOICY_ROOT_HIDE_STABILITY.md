# Choicy, RootHide and AutoIPLoc stability notes — 2026-11-27

## What the repository proves

- AutoIPLoc's tweak filter lists `com.apple.Maps`, `com.apple.geod`, `com.apple.GeoServices`, `com.apple.locationd`, and `com.apple.UIKit`.
- It does **not** list `com.apple.Preferences`.
- The Hook constructor explicitly returns when the process name is `Preferences`.
- Therefore the present AutoIPLoc Hook has no direct declared injection target in the Settings app. This does not prove that other installed tweaks or the injection platform are conflict-free.

## Choicy pane visibility

Choicy is a preference bundle managed through PreferenceLoader. Choicy's own source identifies PreferenceLoader as an always-injected component for Preferences and prevents the Preferences process from being configured with the ordinary "Disable Tweak Injection" toggle.

When the global Tweak Injection switch is off, a missing Choicy pane is consistent with Preferences not loading PreferenceLoader/Choicy. Do not add AutoIPLoc to Preferences to fix this; doing so would expand an unrelated Hook into Settings and is not supported by the current design.

On the device, verify in Sileo (same RootHide repository/bootstrap):
1. Choicy package is installed and its architecture matches the device.
2. PreferenceLoader is installed and not disabled.
3. AltList dependency is installed at a version satisfying Choicy's package dependency.
4. No duplicate Choicy packages are installed from different repositories.
5. After package changes, close Settings completely and reopen it. Do not leave global tweak injection enabled if it causes application crashes.

The RootHide package index currently surfaces a Choicy 1.5.4 arm64e package, while Choicy's upstream changelog lists 1.5.4-2 dated 12 August 2026. The upstream package declares dependencies on mobilesubstrate, PreferenceLoader, and AltList (com.opa334.altlist >= 1.0.4). The exact installed package and source on the device are unknown; verify them in Sileo rather than assuming the latest upstream release is installed. Do not mix a conventional rootless package with a RootHide package.

## Tweak Injection crash isolation

A global Tweak Injection switch exposes all currently installed tweaks to the selected injection platform's target processes. A crash after enabling it cannot be attributed to AutoIPLoc based on timing alone.

For stability diagnosis only:
1. Keep the global switch in the last known stable state.
2. Capture one crash report for one affected app immediately after a reproducible crash.
3. Compare the same app launched once with tweaks disabled (Choicy's "Launch Without Tweaks" feature, where available) and once under its ordinary configuration.
4. Record the exception type, crashed thread, top stack frames, and whether `AutoIPLocHook.dylib` appears in Binary Images.
5. Do not enable all injection globally as a workaround, and do not use per-app tweak settings to evade a third-party app's security or integrity checks.

This comparison distinguishes an injection-related crash from an app crash that persists without tweaks. A crash report is required before changing any AutoIPLoc filter.

## RootHide path and package uncertainty

RootHide uses a randomized `.jbroot-*` directory rather than guaranteeing a fixed `/var/jb` path. The current app now reports all Hook file candidates rather than silently selecting the first. This is diagnostic only; it does not claim which candidate is the active RootHide root.

The current CI produces a conventional DEB layout under `var/jb/Library/MobileSubstrate/DynamicLibraries`. RootHide's developer documentation describes a RootHide-specific path scheme and its `jbroot` path APIs. The existing build has not been proven to be a native RootHide-scheme package on the user's installation. This remains a compatibility question, not something CI can establish.

## Uninstall / rollback behavior

The DEB `postrm` handler now deletes only:
- `/var/tmp/com.autoiploc.jbroot.txt`
- AutoIPLoc Hook status plist files

It intentionally preserves:
- `com.autoiploc.geo.plist`
- `com.autoiploc.wifi.plist`

Do not manually delete any `.jbroot-*` directory. Remove the Hook package through Sileo and the app through TrollStore separately. Keep a copy of the last working TIPA/DEB before upgrading. Real-device removal and rollback still require device testing.


## Re-audit against the current branch HEAD (2026-11-27)

Current audited source: `dcf860baa2a0ad877150d362fe9ca26f16ac8184`.
A UI-only follow-up commit `0e1885688cdf9be20fc9a97fd9085edf025bde9e` makes private location simulation request status explicit; it does not change Hook targets or the private API call sequence.

### CI package format versus the device-side RootHide Patcher step

The CI workflow produces a conventional rootless input package under `deb_pkg/var/jb/Library/MobileSubstrate/DynamicLibraries` with `Architecture: iphoneos-arm64`; it does not itself use the RootHide Theos package scheme. This alone does not establish that the package cannot be installed on the user's device, because the user's phone has RootHide Patcher installed and the observed 4.3.5 files strongly match the Patcher's AutoPatches conversion layout (see the correction section below). Do not treat a raw CI artifact as a tested RootHide installation until the exact device-side conversion mode and resulting live file paths are verified.

### Runtime root-selection mismatch

The package `postinst` writes every discovered `.jbroot-*` directory to `/var/tmp/com.autoiploc.jbroot.txt`. The Hook's `ResolveElleKitRuntime()` tries the saved list before deriving a root from the currently loaded Hook image with `dladdr()`. The main app's new resolver only reports candidate files; it does not control or validate this runtime loader sequence. Thus the app can report root ambiguity while the Hook may still attempt roots in saved-list order. This is a verified code-path mismatch, not proof that a particular device loaded the wrong library.

This re-audit does not change the runtime loader or broaden injection. The loader is part of the pre-existing Hook behavior and requires a separate, safety-scoped compatibility decision before any change.

### RootHide Bootstrap injection constraints

If the device is running the official RootHide Bootstrap model, its README says third-party app injection is off by default and controlled per application from App List; it also says injection into SpringBoard or daemons is not supported by its official mechanism. AutoIPLoc's filter lists `com.apple.geod` and `com.apple.locationd`, which are system services. First identify the exact installed RootHide/Dopamine product and version. Do not enable a broad global injection switch as a workaround, and do not assume that app injection permission enables daemon injection.

### File-access evidence still missing

- The app's `writeSharedPlist` sets configuration files to mode `0600` and validates by reading them back as the app. This proves app-side read-back only.
- Hook processes read fixed paths under `/var/mobile/Library/Preferences` and `/var/tmp`; their real UID/GID and access result must be confirmed on the device.
- The Hook records Geo/Wi-Fi readability per reporting process, but its two status-file `writeToFile` return values are currently ignored. A missing status file is therefore not a complete diagnosis of why reporting failed.
- Do not relax configuration permissions to world-readable without confirming the target service identities and data-sharing requirement.

### Private API and geod state semantics

- `CLSimulationManager` methods are signature-checked as void methods. The current code submits start/stop/clear calls but receives no success result from those calls. The app UI follow-up now says that a request was sent and the system effect is unverified; it does not claim successful simulation.
- Cache maintenance deletes only the Maps and GeoServices cache directories. No service restart, fresh location read-back, or recovery of `geod` is verified by this action.
- A successful host-side build cannot perform either device-level verification.

### Choicy package verification

Choicy upstream 1.5.4-2 is listed in its changelog (12 August 2026); the RootHide package index may expose a different package build/version. Verify the installed package ID, version, architecture, source, PreferenceLoader, and AltList dependency on the device. The current AutoIPLoc filter does not explicitly list `com.apple.Preferences`, and the constructor returns for process name `Preferences`; this reduces evidence for a direct AutoIPLoc Settings hook but does not identify the cause of the reported crashes. Obtain the Settings and affected-app crash logs before attributing them to AutoIPLoc.

### Acceptance status

The C helper tests cover clone ownership, out-of-order releases, duplicate release, and concurrent registry lifecycle. The CI workflow runs ASan/UBSan with `ASAN_OPTIONS=detect_leaks=0`; therefore leak detection itself is not established by that job. CI also does not exercise RootHide's package manager, real process credentials, private CoreLocation simulation, geod recovery, Choicy pane loading, or on-device crash stability.

Keep PR #1 Draft. Required device evidence remains: installed RootHide/Dopamine version and package scheme; Choicy/PreferenceLoader/AltList package metadata; per-process injection state; file owner/mode and read test from each target; Settings and app crash reports; fresh CoreLocation read-back after a simulation request; post-cache-cleanup location recovery; and install/upgrade/uninstall/rollback results.

### Primary references

- RootHide developer path and package guidance: https://github.com/RootHide/Developer/blob/main/roothide.md
- RootHide path API: https://github.com/RootHide/Developer/blob/main/interface.md
- RootHide Bootstrap injection model: https://github.com/RootHide/Bootstrap#usage
- Choicy source constants for PreferenceLoader and Preferences: https://github.com/opa334/Choicy/blob/master/Shared.h
- Choicy upstream changelog: https://opa334.github.io/depic/Choicy/changelog.html


## 2026-11-27 — device package inventory snapshot supplied by user

The following facts come from the user's NewTerm output. They are package inventory observations, not a filesystem or injection success test.

### Packages reported installed

- `com.opa334.choicy` 1.5.4 (`iphoneos-arm64e`)
- `com.opa334.altlist` 1.0.11 (`iphoneos-arm64e`)
- `preferenceloader` 2.2.8 (`iphoneos-arm64e`)
- `ellekit` 1.2-3 (`iphoneos-arm64e`)
- `com.roothide.manager` 1.4.0
- `com.roothide.patcher` 2.1.4-1+debug (the pasted output repeats this entry; confirm with `dpkg-query`)
- `com.roothide.patchloader` 0.0.8
- `roothide` 0.1.0
- `dopamine-basebin-link` 1.0.0
- Installed AutoIPLoc Hook: `com.local.autoiploc.hook` 4.3.5

Choicy, AltList and PreferenceLoader are present in the package inventory, so their complete absence is not the explanation for the missing Choicy pane. This does not prove PreferenceLoader loaded in Settings, that Choicy's preference bundle registered, or that the relevant RootHide injection configuration is active. The device-side inventory is consistent with RootHide-related packages and ElleKit being installed, but the precise Bootstrap/manager build and active injection state remain unconfirmed.

The installed AutoIPLoc Hook is 4.3.5; Build #196 creates 4.3.6. Do not upgrade from the current package to the conventional `var/jb` artifact until the RootHide package scheme and destination path are established.

### AutoIPLoc files and crash report listing

The user reported that all six queried Geo/Wi-Fi/status plist paths were missing:
- `/var/mobile/Library/Preferences/com.autoiploc.geo.plist`
- `/var/mobile/Library/Preferences/com.autoiploc.wifi.plist`
- `/var/mobile/Library/Preferences/com.autoiploc.hookstatus.plist`
- `/var/tmp/com.autoiploc.geo.plist`
- `/var/tmp/com.autoiploc.wifi.plist`
- `/var/tmp/com.autoiploc.hookstatus.plist`

This means the queried locations currently provide no configuration or Hook report evidence. It does not distinguish whether the app has not yet written configuration, the Hook did not run, the reporting process could not write, or paths are being mapped differently in this RootHide environment.

The supplied `ls -lt /var/mobile/Library/Logs/CrashReporter` produced no entries. Since stderr was redirected, this does not distinguish an empty directory from a missing/inaccessible directory. No crash log was supplied, so the Choicy/Tweak Injection crash cause remains unassigned.

### RootHide path observation requiring interpretation

The user reported:
`/var/containers/Bundle/Application/.jbroot-B65E3B6A7115A07D -> //`

This was observed as a symbolic link by `ls -ld`. Do not infer the active jbroot from the link name or link target string alone. RootHide documentation describes both a randomized jbroot root directory and per-Mach-O-directory `.jbroot` links. Obtain `readlink`, `realpath`, `stat`, and a shallow listing of the resolved target before classifying this device's path layout.

### Next read-only device checks

Use non-loop commands to avoid NewTerm multiline-paste ambiguity:

```sh
echo "=== exact package status ==="
dpkg-query -W -f='${binary:Package} ${Version} ${Architecture} ${db:Status-Abbrev}\n' com.local.autoiploc.hook com.opa334.choicy com.opa334.altlist preferenceloader ellekit com.roothide.manager com.roothide.patcher com.roothide.patchloader roothide 2>&1

echo "=== RootHide link details ==="
readlink /var/containers/Bundle/Application/.jbroot-B65E3B6A7115A07D 2>&1
realpath /var/containers/Bundle/Application/.jbroot-B65E3B6A7115A07D 2>&1
stat -f '%N type=%HT owner=%Su group=%Sg mode=%Lp' /var/containers/Bundle/Application/.jbroot-B65E3B6A7115A07D 2>&1
ls -la /var/containers/Bundle/Application/.jbroot-B65E3B6A7115A07D/. 2>&1 | head -20

echo "=== package-owned Hook files ==="
dpkg-query -L com.local.autoiploc.hook 2>&1
ls -la /var/jb/Library/MobileSubstrate/DynamicLibraries/AutoIPLocHook.* 2>&1
```

For crash logs, check both the active and retired reports without suppressing errors:
```sh
ls -la /var/mobile/Library/Logs/CrashReporter 2>&1 | head -30
ls -la /var/mobile/Library/Logs/CrashReporter/Retired 2>&1 | head -30
```

Do not run cache deletion, remove packages, toggle global Tweak Injection, or modify any `.jbroot` link while collecting these facts.


## Correction — RootHide Patcher conversion evidenced on the user's device (2026-11-27)

The user's latest NewTerm output materially changes the interpretation of the earlier path warning.

### Observed device state

- Installed AutoIPLoc package: `com.local.autoiploc.hook 4.3.5 iphoneos-arm64e`.
- Installed RootHide Patcher: `com.roothide.patcher 2.1.4-1+debug`.
- Installed RootHide PatchLoader: `com.roothide.patchloader 0.0.8`.
- The reported package file listing includes:
  - `/var/mobile/Library/pkgmirror/Library/MobileSubstrate/DynamicLibraries/AutoIPLocHook.dylib`
  - `/var/mobile/Library/pkgmirror/Library/MobileSubstrate/DynamicLibraries/AutoIPLocHook.plist`
- The user also observed:
  - `/var/jb/Library/MobileSubstrate/DynamicLibraries/AutoIPLocHook.dylib`
  - `/var/jb/Library/MobileSubstrate/DynamicLibraries/AutoIPLocHook.plist`
  - `AutoIPLocHook.dylib.roothidepatch -> /usr/lib/DynamicPatches/AutoPatches.dylib`

### Interpretation revised from the previous section

The above `pkgmirror` paths and `.roothidepatch` symlink match the documented RootHide Patcher implementation when its AutoPatches conversion path is used:

- RootHide Patcher copies the converted package tree into `var/mobile/Library/pkgmirror` and stores its package metadata under a package-specific `DEBIAN.*` directory.
- In AutoPatches mode, it creates a `.roothidepatch` symlink beside the Mach-O target pointing to `/usr/lib/DynamicPatches/AutoPatches.dylib`.
- It converts the package architecture metadata from `iphoneos-arm64` to `iphoneos-arm64e`.
- RootHide Dynamic Patches documentation states that PatchLoader loads the linked dynamic patch before the target Mach-O executes.

Therefore, the device evidence is consistent with the installed 4.3.5 package having been processed by RootHide Patcher using AutoPatches. The presence of the mirror is not, by itself, evidence of a duplicate active installation or stale garbage. The `.roothidepatch` link is not the AutoIPLoc Hook itself; it is a registration link to the RootHide AutoPatches module.

This corrects the earlier overly broad implication that the traditional rootless DEB layout necessarily means the installed device package was not converted for RootHide. The CI artifact is still a conventional rootless input package; the user's device appears to have a separate Patcher conversion step. Whether that conversion succeeds for every AutoIPLoc Mach-O, script, config path, injection target and iOS 16.2 process remains unproven. RootHide Patcher itself warns that not all packages are supported.

### What remains unverified

- Whether the files under `/var/mobile/Library/pkgmirror` are only preserved source copies, and which exact paths the converted package manager registered as live files.
- Whether `/var/jb` resolves through the RootHide compatibility layout on this device.
- Whether the `.roothidepatch` link resolves and PatchLoader actually loads AutoPatches for AutoIPLocHook.
- Whether AutoPatches modifies this Hook in a way compatible with its own runtime and current iOS 16.2.
- Whether the Hook's hard-coded `/var/mobile/Library/Preferences` and `/var/tmp` reads/writes resolve to the intended data domains after conversion.
- Why Geo/Wi-Fi and Hook-status plists were absent at the queried locations.

### Revised safety and install decision

Do not delete either copy, do not remove `.roothidepatch`, and do not manually alter `/var/jb` or any `.jbroot*` link. Do not install raw Build #196 over 4.3.5 yet. If #196 is tested later, the test must explicitly compare (a) the raw artifact, (b) the exact RootHide Patcher conversion mode and output metadata, and (c) installed live/mirror paths, with a verified rollback package. A successful dpkg conversion alone is not runtime acceptance.

### Focused read-only checks still needed

Run these separately in NewTerm and preserve their full unwrapped output:

```sh
echo "=== RootHide compatibility link ==="
readlink /var/jb 2>&1
stat -f '%N type=%HT owner=%Su group=%Sg mode=%Lp' /var/jb 2>&1
realpath /var/jb 2>&1

echo "=== active/mirror package ownership ==="
dpkg-query -S /var/jb/Library/MobileSubstrate/DynamicLibraries/AutoIPLocHook.dylib 2>&1
dpkg-query -S /var/mobile/Library/pkgmirror/Library/MobileSubstrate/DynamicLibraries/AutoIPLocHook.dylib 2>&1
ls -l /var/jb/Library/MobileSubstrate/DynamicLibraries/AutoIPLocHook.dylib.roothidepatch 2>&1
readlink /var/jb/Library/MobileSubstrate/DynamicLibraries/AutoIPLocHook.dylib.roothidepatch 2>&1
ls -l /usr/lib/DynamicPatches/AutoPatches.dylib 2>&1

echo "=== exact .jbroot target (do not modify) ==="
readlink /var/containers/Bundle/Application/.jbroot-B65E3B6A7115A07D 2>&1
stat -f '%N type=%HT owner=%Su group=%Sg mode=%Lp' /var/containers/Bundle/Application/.jbroot-B65E3B6A7115A07D 2>&1
```

No package remove/reinstall, permission change, global injection toggle, or filesystem cleanup is authorized as part of this diagnostic step.


## 2026-11-27 — missing Geo/Wi-Fi plist call-graph finding

Static call-site inspection of the current `main.swift` found:

- `syncEnvironment(forceReanchor:)` is defined but has no call site in `main.swift`.
- The visible "查询当前出口 IP 地理信息" button calls only `refreshIPGeoInfo()`; that path fetches and displays IP database information and does not write Geo/Wi-Fi configuration files.
- `commitSimulation()` (which writes the Geo plist and Wi-Fi plist) is called only by `syncEnvironment()`.
- The visible `stopSimulation()` control can write disabled Geo/Wi-Fi state, but it only does so after the stop method returns success.
- The Wi-Fi "换一批" action calls `regenerateWiFiList(save: true)`, which can write the Wi-Fi plist independently.

Therefore the missing Geo plist is not, by itself, proof of cross-process permission failure: the current visible app UI has no active start/sync control reaching the Geo write path. This is a control-flow/UI reachability finding. It must be kept separate from the missing Hook status report, which is expected from a successfully initialized target process and remains unexplained.

This audit does not reconnect or expose the previous profile-generation pipeline, does not add a new simulation trigger, and does not enable existing identity/network-obfuscation behavior. The user-facing IP database display remains a separate factual read-only path.

## 2026-11-27 — RootHide file-mirror namespace caution

RootHide's developer `filemirror.md` identifies `/var/containers` and `/var/mobile/Containers` as paths mirrored from the original iOS root filesystem into jbroot; it does not list `/var/mobile/Library` as one of those mirrored paths. Therefore, in a RootHide jbroot context, `/var/mobile/Library/Preferences` and `/var/mobile/Library/Logs` must not automatically be assumed to be the same directory as the original root filesystem's corresponding path. Verify both jbroot and `/rootfs` paths before concluding that configuration or crash-log files do not exist.

Read-only comparison:
- `/var/mobile/Library/Preferences` versus `/rootfs/var/mobile/Library/Preferences`
- `/var/mobile/Library/Logs` versus `/rootfs/var/mobile/Library/Logs`
- `/var/tmp` versus `/rootfs/var/tmp`

This is a path-namespace hypothesis grounded in RootHide's file-mirror list, not yet a diagnosis of the current device.
