#!/usr/bin/env bash
# Build OverlayTestApp.apk using Android SDK command-line tools (no Gradle required).
set -euo pipefail

PROJ="$(cd "$(dirname "$0")" && pwd)"
SDK="${ANDROID_HOME:-$HOME/Android/Sdk}"
BT="$SDK/build-tools/37.0.0"
PLATFORM="$SDK/platforms/android-35/android.jar"
OUT="$PROJ/out"

echo "=== OverlayTestApp build ==="
echo "  SDK     : $SDK"
echo "  OUT     : $OUT"

# Clean
rm -rf "$OUT"
mkdir -p "$OUT/compiled" "$OUT/classes" "$OUT/dex" "$OUT/gen"

# 1. Compile resources
echo "[1/6] aapt2 compile..."
"$BT/aapt2" compile --dir "$PROJ/res" -o "$OUT/compiled.zip"

# 2. Link resources → base APK + R.java
echo "[2/6] aapt2 link..."
"$BT/aapt2" link \
    -I "$PLATFORM" \
    --manifest "$PROJ/AndroidManifest.xml" \
    --java "$OUT/gen" \
    -o "$OUT/app_base.apk" \
    "$OUT/compiled.zip"

# 3. Compile Java
echo "[3/6] javac..."
mapfile -t JAVA_FILES < <(find "$PROJ/src" "$OUT/gen" -name "*.java")
javac --release 11 \
    -classpath "$PLATFORM" \
    -d "$OUT/classes" \
    "${JAVA_FILES[@]}"

# 4. DEX
echo "[4/6] d8 → dex..."
mapfile -t CLASS_FILES < <(find "$OUT/classes" -name "*.class")
"$BT/d8" \
    --output "$OUT/dex" \
    --lib "$PLATFORM" \
    --min-api 26 \
    "${CLASS_FILES[@]}"

# 5. Inject DEX into APK (jar = JDK zip tool, always available)
echo "[5/6] packaging dex..."
cp "$OUT/app_base.apk" "$OUT/app_unaligned.apk"
(cd "$OUT/dex" && jar -uf "$OUT/app_unaligned.apk" classes.dex)

# 6. Align + sign
echo "[6/6] zipalign + apksigner..."
"$BT/zipalign" -f 4 "$OUT/app_unaligned.apk" "$OUT/app_aligned.apk"

KEYSTORE="$HOME/.android/debug.keystore"
if [ ! -f "$KEYSTORE" ]; then
    echo "  [i] Generating debug keystore..."
    keytool -genkeypair -v \
        -keystore "$KEYSTORE" \
        -alias androiddebugkey \
        -keyalg RSA -keysize 2048 -validity 10000 \
        -storepass android -keypass android \
        -dname "CN=Android Debug,O=Android,C=US"
fi

"$BT/apksigner" sign \
    --ks "$KEYSTORE" \
    --ks-pass pass:android \
    --key-pass pass:android \
    --out "$PROJ/OverlayTestApp.apk" \
    "$OUT/app_aligned.apk"

echo ""
echo "[+] Build complete: $PROJ/OverlayTestApp.apk"
ls -lh "$PROJ/OverlayTestApp.apk"
