# ClipVault Android TWA

This Android Studio project wraps the live ClipVault PWA at `https://www.clipvault.lol/` as a Trusted Web Activity (TWA). It was generated from the site's web manifest with Bubblewrap. The Android application ID is `lol.clipvault.app`; keep it unchanged after publishing to Google Play.

## Build and sign

Open this `android-twa` folder in Android Studio, let Gradle sync, then build a signed Android App Bundle (`.aab`) for Google Play. The project currently has no signing keystore. Create and securely back up a release keystore before the first release; do not commit it. Set its path and alias in `twa-manifest.json` when using Bubblewrap, or configure the release signing credentials in Android Studio.

The generated Gradle project targets Android API 36. Building requires Android SDK Build Tools and JDK 17.

## Verify the website association

A TWA needs a Digital Asset Links statement served from:

```text
https://www.clipvault.lol/.well-known/assetlinks.json
```

After creating the release signing key, get its SHA-256 certificate fingerprint and add it to `fingerprints` in `twa-manifest.json`. Generate the association file with Bubblewrap:

```sh
npx @bubblewrap/cli fingerprint generateAssetLinks --manifest=./twa-manifest.json --output=./assetlinks.json
```

Copy the generated file to the website's `public/.well-known/assetlinks.json` and deploy the website. If Google Play App Signing is enabled, also add the Play app-signing certificate fingerprint from Play Console and regenerate the file. The website file must use the exact package ID above and be served over HTTPS as JSON.

The association file is not included yet because it must contain the real release signing certificate fingerprint. An empty or placeholder statement will not verify the TWA.
