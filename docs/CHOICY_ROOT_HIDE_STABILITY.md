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

RootHide's package index has listed Choicy 1.5.4 for arm64e with dependencies on mobilesubstrate, AltList, and PreferenceLoader. Choicy's upstream changelog lists 1.5.4-2 (12 August 2026) and notes earlier iOS 16 preference fixes in 1.5.3-2. Use the version provided for the installed RootHide bootstrap rather than mixing a normal-rootless package with a RootHide package.

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
