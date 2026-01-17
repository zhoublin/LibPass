#!/bin/bash

# 端到端APK验证脚本
# 集成：签名检查、SDK版本修复、完整验证
# 输入：original.apk 和 adversarial.apk

ORIGINAL_APK="$1"
ADVERSARIAL_APK="$2"
OUTPUT_DIR="${3:-./validation_output}"
MIN_SDK=24

if [ -z "$ORIGINAL_APK" ] || [ -z "$ADVERSARIAL_APK" ]; then
    echo "Usage: $0 <original_apk> <adversarial_apk> [output_dir]"
    echo ""
    echo "This script will:"
    echo "  1. Check and sign adversarial APK if needed"
    echo "  2. Check and fix SDK versions (minimum $MIN_SDK)"
    echo "  3. Run Monkey tests on both original and adversarial APKs"
    echo "  4. Compare Monkey test results to check functional consistency"
    echo "  5. Validate both APKs (no screenshots)"
    exit 1
fi

if [ ! -f "$ORIGINAL_APK" ]; then
    echo "Error: Original APK not found: $ORIGINAL_APK"
    exit 1
fi

if [ ! -f "$ADVERSARIAL_APK" ]; then
    echo "Error: Adversarial APK not found: $ADVERSARIAL_APK"
    exit 1
fi

# 检查设备连接
if ! adb devices 2>/dev/null | grep -q "device$"; then
    echo "Error: No Android device connected"
    exit 1
fi

# 获取脚本目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 创建输出目录
mkdir -p "$OUTPUT_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="$OUTPUT_DIR/validation_report_${TIMESTAMP}.txt"
JSON_REPORT="$OUTPUT_DIR/validation_report_${TIMESTAMP}.json"

# 初始化报告
echo "=== End-to-End APK Validation Report ===" > "$REPORT_FILE"
echo "Timestamp: $(date)" >> "$REPORT_FILE"
echo "Original APK: $ORIGINAL_APK" >> "$REPORT_FILE"
echo "Adversarial APK: $ADVERSARIAL_APK" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# JSON报告初始化
echo "{" > "$JSON_REPORT"
echo "  \"timestamp\": \"$(date -Iseconds)\"," >> "$JSON_REPORT"
echo "  \"original_apk\": \"$ORIGINAL_APK\"," >> "$JSON_REPORT"
echo "  \"adversarial_apk\": \"$ADVERSARIAL_APK\"," >> "$JSON_REPORT"
echo "  \"min_sdk_version\": $MIN_SDK," >> "$JSON_REPORT"
echo "  \"steps\": [" >> "$JSON_REPORT"

STEP_COUNT=0

# 辅助函数：添加步骤到JSON
add_json_step() {
    local step_name="$1"
    local status="$2"
    local message="$3"
    
    if [ $STEP_COUNT -gt 0 ]; then
        echo "," >> "$JSON_REPORT"
    fi
    STEP_COUNT=$((STEP_COUNT + 1))
    
    echo "    {" >> "$JSON_REPORT"
    echo "      \"step\": \"$step_name\"," >> "$JSON_REPORT"
    echo "      \"status\": \"$status\"," >> "$JSON_REPORT"
    echo "      \"message\": \"$message\"" >> "$JSON_REPORT"
    echo -n "    }" >> "$JSON_REPORT"
}

# 查找Android SDK工具
find_android_tools() {
    ANDROID_HOME="${ANDROID_HOME:-${ANDROID_SDK_ROOT}}"
    if [ -z "$ANDROID_HOME" ]; then
        if [ -d "$HOME/Library/Android/sdk" ]; then
            ANDROID_HOME="$HOME/Library/Android/sdk"
        elif [ -d "$HOME/.android/sdk" ]; then
            ANDROID_HOME="$HOME/.android/sdk"
        fi
    fi
    
    if [ -n "$ANDROID_HOME" ] && [ -d "$ANDROID_HOME/build-tools" ]; then
        BUILD_TOOLS_DIR="$ANDROID_HOME/build-tools"
        LATEST_VERSION=$(ls -1 "$BUILD_TOOLS_DIR" 2>/dev/null | sort -V | tail -1)
        AAPT="$BUILD_TOOLS_DIR/$LATEST_VERSION/aapt"
        APKSIGNER="$BUILD_TOOLS_DIR/$LATEST_VERSION/apksigner"
        return 0
    fi
    return 1
}

# 查找Java工具
find_java_tools() {
    JAVA_HOME="${JAVA_HOME:-$(dirname $(dirname $(readlink -f $(which java 2>/dev/null) 2>/dev/null)))}"
    if [ -z "$JAVA_HOME" ] || [ ! -d "$JAVA_HOME" ]; then
        JAVA_HOME=$(dirname $(dirname $(readlink -f $(which java 2>/dev/null) 2>/dev/null || echo "")))
    fi
    
    if [ -n "$JAVA_HOME" ] && [ -d "$JAVA_HOME/bin" ]; then
        JARSIGNER="$JAVA_HOME/bin/jarsigner"
        KEYTOOL="$JAVA_HOME/bin/keytool"
        return 0
    fi
    
    # 从PATH查找
    JARSIGNER=$(which jarsigner 2>/dev/null)
    KEYTOOL=$(which keytool 2>/dev/null)
    
    if [ -n "$JARSIGNER" ] && [ -n "$KEYTOOL" ]; then
        return 0
    fi
    return 1
}

# 对比Monkey测试结果
compare_monkey_tests() {
    local original_file="$1"
    local adversarial_file="$2"
    local output_file="$3"
    
    echo "=== Monkey Test Comparison ===" > "$output_file"
    echo "Original APK: $original_file" >> "$output_file"
    echo "Adversarial APK: $adversarial_file" >> "$output_file"
    echo "" >> "$output_file"
    
    # 提取关键信息
    ORIGINAL_EVENTS=$(grep -i "Events injected:" "$original_file" 2>/dev/null | tail -1 || echo "Unknown")
    ADVERSARIAL_EVENTS=$(grep -i "Events injected:" "$adversarial_file" 2>/dev/null | tail -1 || echo "Unknown")
    
    ORIGINAL_CRASHES=$(grep -iE "(crash|exception|fatal|ANR)" "$original_file" 2>/dev/null | wc -l | tr -d ' ')
    ADVERSARIAL_CRASHES=$(grep -iE "(crash|exception|fatal|ANR)" "$adversarial_file" 2>/dev/null | wc -l | tr -d ' ')
    
    # 提取错误类型（从logcat文件，如果存在）
    if [ -f "${original_file%.txt}_logcat.txt" ]; then
        ORIGINAL_ERRORS=$(grep -iE "(FATAL|Exception|Error|VerifyError|ClassNotFoundException|NoClassDefFoundError)" "${original_file%.txt}_logcat.txt" 2>/dev/null | sort -u | head -20)
    else
        ORIGINAL_ERRORS=$(grep -iE "(FATAL|Exception|Error|VerifyError|ClassNotFoundException|NoClassDefFoundError)" "$original_file" 2>/dev/null | sort -u | head -20)
    fi
    
    if [ -f "${adversarial_file%.txt}_logcat.txt" ]; then
        ADVERSARIAL_ERRORS=$(grep -iE "(FATAL|Exception|Error|VerifyError|ClassNotFoundException|NoClassDefFoundError)" "${adversarial_file%.txt}_logcat.txt" 2>/dev/null | sort -u | head -20)
    else
        ADVERSARIAL_ERRORS=$(grep -iE "(FATAL|Exception|Error|VerifyError|ClassNotFoundException|NoClassDefFoundError)" "$adversarial_file" 2>/dev/null | sort -u | head -20)
    fi
    
    echo "Events Injected:" >> "$output_file"
    echo "  Original: $ORIGINAL_EVENTS" >> "$output_file"
    echo "  Adversarial: $ADVERSARIAL_EVENTS" >> "$output_file"
    echo "" >> "$output_file"
    
    echo "Error Count:" >> "$output_file"
    echo "  Original: $ORIGINAL_CRASHES errors" >> "$output_file"
    echo "  Adversarial: $ADVERSARIAL_CRASHES errors" >> "$output_file"
    echo "" >> "$output_file"
    
    # 计算差异
    DIFF_COUNT=$((ADVERSARIAL_CRASHES - ORIGINAL_CRASHES))
    if [ "$DIFF_COUNT" -eq 0 ]; then
        echo "✓ No additional errors in adversarial APK (same as original)" >> "$output_file"
        COMPARISON_STATUS="consistent"
    elif [ "$DIFF_COUNT" -lt 0 ]; then
        echo "⚠ Adversarial APK has $((DIFF_COUNT * -1)) fewer errors than original" >> "$output_file"
        COMPARISON_STATUS="better"
    else
        echo "✗ Adversarial APK has $DIFF_COUNT more errors than original" >> "$output_file"
        COMPARISON_STATUS="worse"
    fi
    echo "" >> "$output_file"
    
    # 显示新增的错误（仅在对抗性APK中出现的错误）
    if [ "$ADVERSARIAL_CRASHES" -gt "$ORIGINAL_CRASHES" ]; then
        echo "New Errors in Adversarial APK (not in original):" >> "$output_file"
        # 找出仅在对抗性APK中出现的错误模式
        for error_line in $(echo "$ADVERSARIAL_ERRORS" | head -10); do
            if [ -n "$error_line" ] && ! echo "$ORIGINAL_ERRORS" | grep -q "$error_line" 2>/dev/null; then
                echo "  - $error_line" >> "$output_file"
            fi
        done
        echo "" >> "$output_file"
    fi
    
    # 显示原始APK中的错误（用于参考）
    if [ "$ORIGINAL_CRASHES" -gt 0 ]; then
        echo "Errors in Original APK (for reference):" >> "$output_file"
        echo "$ORIGINAL_ERRORS" | head -5 | sed 's/^/  - /' >> "$output_file"
        echo "" >> "$output_file"
    fi
}

# 初始化工具
echo "=== Step 1: Initializing Tools ==="
echo "[1/7] Initializing tools..."

if ! find_android_tools; then
    echo "✗ Android SDK not found"
    add_json_step "tool_init" "error" "Android SDK not found"
    exit 1
fi

if ! find_java_tools; then
    echo "✗ Java tools not found"
    add_json_step "tool_init" "error" "Java tools not found"
    exit 1
fi

echo "✓ Android SDK: $ANDROID_HOME"
echo "✓ Java tools found"
add_json_step "tool_init" "success" "Tools initialized"
echo ""

# 步骤1：检查并签名对抗APK
echo "=== Step 2: Checking and Signing Adversarial APK ==="
echo "[2/7] Checking adversarial APK signature..."

# 检查APK是否已签名
SIGNED=false
if [ -f "$APKSIGNER" ]; then
    if "$APKSIGNER" verify "$ADVERSARIAL_APK" > /dev/null 2>&1; then
        SIGNED=true
        echo "✓ Adversarial APK is already signed"
        add_json_step "adversarial_signature_check" "success" "APK is signed"
    fi
elif [ -n "$JARSIGNER" ]; then
    if "$JARSIGNER" -verify "$ADVERSARIAL_APK" > /dev/null 2>&1; then
        SIGNED=true
        echo "✓ Adversarial APK is already signed"
        add_json_step "adversarial_signature_check" "success" "APK is signed"
    fi
fi

# 如果未签名，进行签名
if [ "$SIGNED" = "false" ]; then
    echo "⚠ Adversarial APK is not signed, signing..."
    
    ./sign_apk.sh "$ADVERSARIAL_APK"
fi
echo ""

# 步骤2：检查并修复SDK版本
echo "=== Step 3: Checking and Fixing SDK Versions ==="
echo "[3/7] Checking SDK versions..."

# 检查原始APK的SDK版本
ORIGINAL_SDK=$("$AAPT" dump badging "$ORIGINAL_APK" 2>/dev/null | \
    grep -oE "targetSdkVersion:'[0-9]+'" | \
    sed -E "s/targetSdkVersion:'([0-9]+)'/\1/" | head -1)

# 检查对抗APK的SDK版本
ADVERSARIAL_SDK=$("$AAPT" dump badging "$ADVERSARIAL_APK" 2>/dev/null | \
    grep -oE "targetSdkVersion:'[0-9]+'" | \
    sed -E "s/targetSdkVersion:'([0-9]+)'/\1/" | head -1)

echo "  Original APK targetSdkVersion: ${ORIGINAL_SDK:-unknown}"
echo "  Adversarial APK targetSdkVersion: ${ADVERSARIAL_SDK:-unknown}"

# 检查是否需要修复
NEED_FIX_ORIGINAL=false
NEED_FIX_ADVERSARIAL=false

if [ -n "$ORIGINAL_SDK" ] && [ "$ORIGINAL_SDK" -lt "$MIN_SDK" ]; then
    NEED_FIX_ORIGINAL=true
    echo "  ⚠ Original APK SDK version too low ($ORIGINAL_SDK < $MIN_SDK)"
fi

if [ -n "$ADVERSARIAL_SDK" ] && [ "$ADVERSARIAL_SDK" -lt "$MIN_SDK" ]; then
    NEED_FIX_ADVERSARIAL=true
    echo "  ⚠ Adversarial APK SDK version too low ($ADVERSARIAL_SDK < $MIN_SDK)"
fi

# 修复SDK版本（使用apktool）
if [ "$NEED_FIX_ORIGINAL" = "true" ] || [ "$NEED_FIX_ADVERSARIAL" = "true" ]; then
    if ! command -v apktool &> /dev/null; then
        echo "⚠ apktool not installed, cannot fix SDK version automatically"
        echo "  Install: brew install apktool (macOS) or sudo apt-get install apktool (Linux)"
        add_json_step "sdk_version_fix" "skipped" "apktool not available"
    else
        # 修复原始APK（如果需要）
        if [ "$NEED_FIX_ORIGINAL" = "true" ]; then
            echo "  Fixing original APK SDK version..."
            TEMP_DIR=$(mktemp -d)
            apktool d "$ORIGINAL_APK" -o "$TEMP_DIR" -f > /dev/null 2>&1
            
            if [ -f "$TEMP_DIR/AndroidManifest.xml" ]; then
                # 修改targetSdkVersion
                sed -i.bak "s/android:targetSdkVersion=\"[0-9]\+\"/android:targetSdkVersion=\"$MIN_SDK\"/g" "$TEMP_DIR/AndroidManifest.xml" 2>/dev/null || \
                sed -i '' "s/android:targetSdkVersion=\"[0-9]\+\"/android:targetSdkVersion=\"$MIN_SDK\"/g" "$TEMP_DIR/AndroidManifest.xml" 2>/dev/null
                
                # 如果没有uses-sdk标签，添加一个
                if ! grep -q "<uses-sdk" "$TEMP_DIR/AndroidManifest.xml"; then
                    sed -i.bak "s|</manifest>|    <uses-sdk android:targetSdkVersion=\"$MIN_SDK\" android:minSdkVersion=\"14\"/>\\n</manifest>|" "$TEMP_DIR/AndroidManifest.xml" 2>/dev/null || \
                    sed -i '' "s|</manifest>|    <uses-sdk android:targetSdkVersion=\"$MIN_SDK\" android:minSdkVersion=\"14\"/>\\n</manifest>|" "$TEMP_DIR/AndroidManifest.xml" 2>/dev/null
                fi
                
                ORIGINAL_APK_FIXED="${ORIGINAL_APK%.apk}_fixed.apk"
                apktool b "$TEMP_DIR" -o "$ORIGINAL_APK_FIXED" > /dev/null 2>&1
                
                if [ -f "$ORIGINAL_APK_FIXED" ]; then
                    # 重新签名
                    if [ -f "$APKSIGNER" ]; then
                        "$APKSIGNER" sign --ks "$KEYSTORE_PATH" --ks-pass pass:android \
                            --ks-key-alias androiddebugkey --key-pass pass:android \
                            "$ORIGINAL_APK_FIXED" > /dev/null 2>&1
                    elif [ -n "$JARSIGNER" ]; then
                        "$JARSIGNER" -verbose -sigalg SHA256withRSA -digestalg SHA-256 \
                            -keystore "$KEYSTORE_PATH" -storepass android -keypass android \
                            "$ORIGINAL_APK_FIXED" androiddebugkey > /dev/null 2>&1
                    fi
                    
                    ORIGINAL_APK="$ORIGINAL_APK_FIXED"
                    echo "  ✓ Original APK fixed: $ORIGINAL_APK"
                fi
                rm -rf "$TEMP_DIR"
            fi
        fi
        
        # 修复对抗APK（如果需要）
        if [ "$NEED_FIX_ADVERSARIAL" = "true" ]; then
            echo "  Fixing adversarial APK SDK version..."
            TEMP_DIR=$(mktemp -d)
            apktool d "$ADVERSARIAL_APK" -o "$TEMP_DIR" -f > /dev/null 2>&1
            
            if [ -f "$TEMP_DIR/AndroidManifest.xml" ]; then
                # 修改targetSdkVersion
                sed -i.bak "s/android:targetSdkVersion=\"[0-9]\+\"/android:targetSdkVersion=\"$MIN_SDK\"/g" "$TEMP_DIR/AndroidManifest.xml" 2>/dev/null || \
                sed -i '' "s/android:targetSdkVersion=\"[0-9]\+\"/android:targetSdkVersion=\"$MIN_SDK\"/g" "$TEMP_DIR/AndroidManifest.xml" 2>/dev/null
                
                # 如果没有uses-sdk标签，添加一个
                if ! grep -q "<uses-sdk" "$TEMP_DIR/AndroidManifest.xml"; then
                    sed -i.bak "s|</manifest>|    <uses-sdk android:targetSdkVersion=\"$MIN_SDK\" android:minSdkVersion=\"14\"/>\\n</manifest>|" "$TEMP_DIR/AndroidManifest.xml" 2>/dev/null || \
                    sed -i '' "s|</manifest>|    <uses-sdk android:targetSdkVersion=\"$MIN_SDK\" android:minSdkVersion=\"14\"/>\\n</manifest>|" "$TEMP_DIR/AndroidManifest.xml" 2>/dev/null
                fi
                
                ADVERSARIAL_APK_FIXED="${ADVERSARIAL_APK%.apk}_fixed.apk"
                apktool b "$TEMP_DIR" -o "$ADVERSARIAL_APK_FIXED" > /dev/null 2>&1
                
                if [ -f "$ADVERSARIAL_APK_FIXED" ]; then
                    # 重新签名
                    if [ -f "$APKSIGNER" ]; then
                        "$APKSIGNER" sign --ks "$KEYSTORE_PATH" --ks-pass pass:android \
                            --ks-key-alias androiddebugkey --key-pass pass:android \
                            "$ADVERSARIAL_APK_FIXED" > /dev/null 2>&1
                    elif [ -n "$JARSIGNER" ]; then
                        "$JARSIGNER" -verbose -sigalg SHA256withRSA -digestalg SHA-256 \
                            -keystore "$KEYSTORE_PATH" -storepass android -keypass android \
                            "$ADVERSARIAL_APK_FIXED" androiddebugkey > /dev/null 2>&1
                    fi
                    
                    ADVERSARIAL_APK="$ADVERSARIAL_APK_FIXED"
                    echo "  ✓ Adversarial APK fixed: $ADVERSARIAL_APK"
                fi
                rm -rf "$TEMP_DIR"
            fi
        fi
        
        if [ "$NEED_FIX_ORIGINAL" = "true" ] || [ "$NEED_FIX_ADVERSARIAL" = "true" ]; then
            add_json_step "sdk_version_fix" "success" "SDK versions updated to $MIN_SDK"
        fi
    fi
else
    echo "  ✓ SDK versions OK (>= $MIN_SDK)"
    add_json_step "sdk_version_check" "success" "SDK versions OK"
fi
echo ""

# 步骤3：提取包名
echo "=== Step 4: Extracting Package Names ==="
echo "[4/7] Extracting package names..."

ORIGINAL_PACKAGE=$("$AAPT" dump badging "$ORIGINAL_APK" 2>/dev/null | \
    grep -oE "package: name='[^']+'" | \
    sed -E "s/package: name='([^']+)'/\1/")
ADVERSARIAL_PACKAGE=$("$AAPT" dump badging "$ADVERSARIAL_APK" 2>/dev/null | \
    grep -oE "package: name='[^']+'" | \
    sed -E "s/package: name='([^']+)'/\1/")

if [ -z "$ORIGINAL_PACKAGE" ] || [ -z "$ADVERSARIAL_PACKAGE" ]; then
    echo "✗ Failed to extract package names"
    add_json_step "package_extraction" "error" "Failed to extract package names"
    exit 1
fi

if [ "$ORIGINAL_PACKAGE" = "$ADVERSARIAL_PACKAGE" ]; then
    PACKAGE_NAME="$ORIGINAL_PACKAGE"
    echo "✓ Package name: $PACKAGE_NAME"
    add_json_step "package_extraction" "success" "Package: $PACKAGE_NAME"
else
    echo "⚠ Package names differ:"
    echo "  Original: $ORIGINAL_PACKAGE"
    echo "  Adversarial: $ADVERSARIAL_PACKAGE"
    PACKAGE_NAME="$ADVERSARIAL_PACKAGE"
    add_json_step "package_extraction" "warning" "Package names differ"
fi
echo ""

# 步骤4：安装和验证原始APK
echo "=== Step 5: Installing and Validating Original APK ==="
echo "[5/7] Installing original APK..."

# 卸载旧版本
adb uninstall "$PACKAGE_NAME" > /dev/null 2>&1
sleep 1

# 安装原始APK
if adb install -r "$ORIGINAL_APK" > /dev/null 2>&1; then
    echo "✓ Original APK installed"
    add_json_step "original_apk_install" "success" "Installed successfully"
    
    # 测试启动
    adb logcat -c > /dev/null 2>&1
    adb shell monkey -p "$PACKAGE_NAME" -c android.intent.category.LAUNCHER 1 > /dev/null 2>&1
    sleep 3
    
    # 检查崩溃
    ORIGINAL_CRASHES=$(adb logcat -d 2>/dev/null | grep -i "$PACKAGE_NAME" | \
        grep -iE "(FATAL|Exception|crash|force close|ANR)" | wc -l | tr -d ' ')
    
    if [ "$ORIGINAL_CRASHES" -eq 0 ]; then
        echo "✓ Original APK: No crashes detected"
        ORIGINAL_CRASH_STATUS="success"
    else
        echo "⚠ Original APK: Found $ORIGINAL_CRASHES potential crash/error messages"
        ORIGINAL_CRASH_STATUS="warning"
    fi
    
    # 收集日志
    adb logcat -d > "$OUTPUT_DIR/original_logcat.txt" 2>/dev/null
    
    # Monkey测试（与对抗性APK相同的测试）
    echo "  Running Monkey stress test on original APK..."
    adb logcat -c > /dev/null 2>&1
    adb shell monkey -p "$PACKAGE_NAME" -v 100 -s 2025 > "$OUTPUT_DIR/original_monkey_test.txt" 2>&1
    ORIGINAL_MONKEY_EXIT=$?
    
    ORIGINAL_MONKEY_CRASHES=$(grep -iE "(crash|exception|fatal)" "$OUTPUT_DIR/original_monkey_test.txt" | wc -l | tr -d ' ')
    
    if [ $ORIGINAL_MONKEY_EXIT -eq 0 ] && [ "$ORIGINAL_MONKEY_CRASHES" -eq 0 ]; then
        echo "✓ Original APK Monkey test passed (100 events, no crashes)"
        ORIGINAL_MONKEY_STATUS="success"
    else
        echo "⚠ Original APK Monkey test: $ORIGINAL_MONKEY_CRASHES potential issues"
        ORIGINAL_MONKEY_STATUS="warning"
    fi
    
    # 收集monkey测试期间的日志
    adb logcat -d > "$OUTPUT_DIR/original_monkey_logcat.txt" 2>/dev/null
    
    # 卸载
    adb uninstall "$PACKAGE_NAME" > /dev/null 2>&1
    sleep 1
else
    echo "✗ Failed to install original APK"
    add_json_step "original_apk_install" "error" "Installation failed"
    exit 1
fi
echo ""

# 步骤5：安装和验证对抗APK
echo "=== Step 6: Installing and Validating Adversarial APK ==="
echo "[6/7] Installing adversarial APK..."

# 确保已卸载
adb uninstall "$PACKAGE_NAME" > /dev/null 2>&1
sleep 1

# 安装对抗APK
if adb install "$ADVERSARIAL_APK" > /dev/null 2>&1; then
    echo "✓ Adversarial APK installed"
    add_json_step "adversarial_apk_install" "success" "Installed successfully"
    
    # 测试启动
    adb logcat -c > /dev/null 2>&1
    adb shell monkey -p "$PACKAGE_NAME" -c android.intent.category.LAUNCHER 1 > /dev/null 2>&1
    sleep 5
    
    # 检查崩溃
    ADVERSARIAL_CRASHES=$(adb logcat -d 2>/dev/null | grep -i "$PACKAGE_NAME" | \
        grep -iE "(FATAL|Exception|crash|force close|ANR)" | wc -l | tr -d ' ')
    
    if [ "$ADVERSARIAL_CRASHES" -eq 0 ]; then
        echo "✓ Adversarial APK: No crashes detected"
        ADVERSARIAL_CRASH_STATUS="success"
    else
        echo "✗ Adversarial APK: Found $ADVERSARIAL_CRASHES potential crash/error messages"
        ADVERSARIAL_CRASH_STATUS="failed"
        adb logcat -d > "$OUTPUT_DIR/adversarial_logcat_errors.txt" 2>/dev/null
    fi
    
    # 检查进程
    PROCESS=$(adb shell ps 2>/dev/null | grep "$PACKAGE_NAME" | grep -v grep)
    if [ -z "$PROCESS" ]; then
        # 尝试其他方法
        PID=$(adb shell pidof "$PACKAGE_NAME" 2>/dev/null)
        if [ -z "$PID" ]; then
            MEMINFO=$(adb shell dumpsys meminfo "$PACKAGE_NAME" 2>/dev/null | head -5)
            if echo "$MEMINFO" | grep -q "Applications Memory Usage"; then
                PROCESS="Found via dumpsys"
            fi
        fi
    fi
    
    if [ -n "$PROCESS" ] || [ -n "$PID" ]; then
        echo "✓ Adversarial APK: Process is running"
        PROCESS_STATUS="success"
    else
        echo "⚠ Adversarial APK: Process not found"
        PROCESS_STATUS="warning"
    fi
    
    # Monkey测试（与原始APK相同的测试）
    echo "  Running Monkey stress test on adversarial APK..."
    adb logcat -c > /dev/null 2>&1
    adb shell monkey -p "$PACKAGE_NAME" -v 100 -s 2025 > "$OUTPUT_DIR/adversarial_monkey_test.txt" 2>&1
    ADVERSARIAL_MONKEY_EXIT=$?
    
    ADVERSARIAL_MONKEY_CRASHES=$(grep -iE "(crash|exception|fatal)" "$OUTPUT_DIR/adversarial_monkey_test.txt" | wc -l | tr -d ' ')
    
    if [ $ADVERSARIAL_MONKEY_EXIT -eq 0 ] && [ "$ADVERSARIAL_MONKEY_CRASHES" -eq 0 ]; then
        echo "✓ Adversarial APK Monkey test passed (100 events, no crashes)"
        ADVERSARIAL_MONKEY_STATUS="success"
    else
        echo "⚠ Adversarial APK Monkey test: $ADVERSARIAL_MONKEY_CRASHES potential issues"
        ADVERSARIAL_MONKEY_STATUS="warning"
    fi
    
    # 收集monkey测试期间的日志
    adb logcat -d > "$OUTPUT_DIR/adversarial_monkey_logcat.txt" 2>/dev/null
    
    # 对比Monkey测试结果
    echo "  Comparing Monkey test results..."
    compare_monkey_tests "$OUTPUT_DIR/original_monkey_test.txt" "$OUTPUT_DIR/adversarial_monkey_test.txt" "$OUTPUT_DIR/monkey_comparison.txt"
    
    add_json_step "adversarial_validation" "success" "Validation completed"
else
    echo "✗ Failed to install adversarial APK"
    add_json_step "adversarial_apk_install" "error" "Installation failed"
    exit 1
fi
echo ""

# 步骤6：生成报告
echo "=== Step 7: Generating Report ==="
echo "[7/7] Generating final report..."

# 完成JSON报告
echo "  ]," >> "$JSON_REPORT"
echo "  \"summary\": {" >> "$JSON_REPORT"
echo "    \"package_name\": \"$PACKAGE_NAME\"," >> "$JSON_REPORT"
echo "    \"original_crash_check\": \"$ORIGINAL_CRASH_STATUS\"," >> "$JSON_REPORT"
echo "    \"adversarial_crash_check\": \"$ADVERSARIAL_CRASH_STATUS\"," >> "$JSON_REPORT"
echo "    \"process_status\": \"$PROCESS_STATUS\"," >> "$JSON_REPORT"
echo "    \"original_monkey_test\": \"${ORIGINAL_MONKEY_STATUS:-unknown}\"," >> "$JSON_REPORT"
echo "    \"adversarial_monkey_test\": \"${ADVERSARIAL_MONKEY_STATUS:-unknown}\"," >> "$JSON_REPORT"
echo "    \"monkey_comparison\": \"${COMPARISON_STATUS:-unknown}\"," >> "$JSON_REPORT"

# 计算总体状态（考虑对比结果）
# 如果对抗性APK的错误数量与原始APK相同或更少，认为验证通过
# 这是主要判断标准：只要对抗性APK没有引入新错误，就认为验证成功
if [ "$COMPARISON_STATUS" = "consistent" ] || [ "$COMPARISON_STATUS" = "better" ]; then
    # 对抗性APK的错误数量 <= 原始APK，验证通过
    OVERALL_STATUS="success"
    echo "    \"overall_status\": \"success\"," >> "$JSON_REPORT"
    echo "    \"validation_passed\": true" >> "$JSON_REPORT"
    echo "    \"reason\": \"Adversarial APK has same or fewer errors than original\"" >> "$JSON_REPORT"
elif [ "$COMPARISON_STATUS" = "worse" ]; then
    # 对抗性APK的错误数量 > 原始APK，验证失败
    OVERALL_STATUS="failed"
    echo "    \"overall_status\": \"failed\"," >> "$JSON_REPORT"
    echo "    \"validation_passed\": false" >> "$JSON_REPORT"
    echo "    \"reason\": \"Adversarial APK has more errors than original\"" >> "$JSON_REPORT"
else
    # 如果无法对比（COMPARISON_STATUS未知），使用备用逻辑
    # 检查基本功能：安装成功、进程运行、Monkey测试没有严重失败
    if [ "$ADVERSARIAL_CRASH_STATUS" != "failed" ] && \
       [ "$PROCESS_STATUS" != "warning" ] && \
       [ "$ADVERSARIAL_MONKEY_STATUS" != "failed" ]; then
        OVERALL_STATUS="success"
        echo "    \"overall_status\": \"success\"," >> "$JSON_REPORT"
        echo "    \"validation_passed\": true" >> "$JSON_REPORT"
        echo "    \"reason\": \"Basic validation passed (comparison unavailable)\"" >> "$JSON_REPORT"
    else
        OVERALL_STATUS="failed"
        echo "    \"overall_status\": \"failed\"," >> "$JSON_REPORT"
        echo "    \"validation_passed\": false" >> "$JSON_REPORT"
        echo "    \"reason\": \"Basic validation failed or comparison unavailable\"" >> "$JSON_REPORT"
    fi
fi
echo "  }" >> "$JSON_REPORT"
echo "}" >> "$JSON_REPORT"

# 文本报告摘要
echo "" >> "$REPORT_FILE"
echo "=== Validation Summary ===" >> "$REPORT_FILE"
echo "Package Name: $PACKAGE_NAME" >> "$REPORT_FILE"
echo "Original APK Crash Check: $ORIGINAL_CRASH_STATUS" >> "$REPORT_FILE"
echo "Adversarial APK Crash Check: $ADVERSARIAL_CRASH_STATUS" >> "$REPORT_FILE"
echo "Process Status: $PROCESS_STATUS" >> "$REPORT_FILE"
echo "Original APK Monkey Test: ${ORIGINAL_MONKEY_STATUS:-unknown}" >> "$REPORT_FILE"
echo "Adversarial APK Monkey Test: ${ADVERSARIAL_MONKEY_STATUS:-unknown}" >> "$REPORT_FILE"
echo "Monkey Test Comparison: ${COMPARISON_STATUS:-unknown}" >> "$REPORT_FILE"
echo "Overall Status: $OVERALL_STATUS" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "Output Files:" >> "$REPORT_FILE"
echo "  - Logs: $OUTPUT_DIR/original_logcat.txt, $OUTPUT_DIR/adversarial_logcat_errors.txt" >> "$REPORT_FILE"
echo "  - Original Monkey Test: $OUTPUT_DIR/original_monkey_test.txt" >> "$REPORT_FILE"
echo "  - Adversarial Monkey Test: $OUTPUT_DIR/adversarial_monkey_test.txt" >> "$REPORT_FILE"
echo "  - Monkey Comparison: $OUTPUT_DIR/monkey_comparison.txt" >> "$REPORT_FILE"
echo "  - JSON Report: $JSON_REPORT" >> "$REPORT_FILE"

# 显示摘要
echo ""
echo "=== Validation Summary ==="
echo "Package Name: $PACKAGE_NAME"
echo "Original APK Crash Check: $ORIGINAL_CRASH_STATUS"
echo "Adversarial APK Crash Check: $ADVERSARIAL_CRASH_STATUS"
echo "Process Status: $PROCESS_STATUS"
echo "Original APK Monkey Test: ${ORIGINAL_MONKEY_STATUS:-unknown}"
echo "Adversarial APK Monkey Test: ${ADVERSARIAL_MONKEY_STATUS:-unknown}"
echo "Monkey Test Comparison: ${COMPARISON_STATUS:-unknown}"
echo "Overall Status: $OVERALL_STATUS"
echo ""
if [ -f "$OUTPUT_DIR/monkey_comparison.txt" ]; then
    echo "=== Monkey Test Comparison ==="
    cat "$OUTPUT_DIR/monkey_comparison.txt"
    echo ""
fi
echo "Reports saved to:"
echo "  - Text: $REPORT_FILE"
echo "  - JSON: $JSON_REPORT"
echo "  - Logs: $OUTPUT_DIR/"

# 退出码
if [ "$OVERALL_STATUS" = "success" ]; then
    exit 0
else
    exit 1
fi
