#!/bin/bash

# APK签名脚本
# 用于手动签名未签名的APK文件

APK_PATH="$1"

if [ -z "$APK_PATH" ]; then
    echo "Usage: $0 <apk_path>"
    echo "Example: $0 output/iter_0/adversarial_final.apk"
    exit 1
fi

if [ ! -f "$APK_PATH" ]; then
    echo "Error: APK file not found: $APK_PATH"
    exit 1
fi

# 查找Android SDK
ANDROID_HOME="${ANDROID_HOME:-${ANDROID_SDK_ROOT}}"
if [ -z "$ANDROID_HOME" ]; then
    # 尝试常见路径
    if [ -d "$HOME/Library/Android/sdk" ]; then
        ANDROID_HOME="$HOME/Library/Android/sdk"
    elif [ -d "$HOME/.android/sdk" ]; then
        ANDROID_HOME="$HOME/.android/sdk"
    else
        echo "Error: ANDROID_HOME not set and Android SDK not found"
        echo "Please set ANDROID_HOME environment variable"
        exit 1
    fi
fi

# 查找apksigner（优先）或jarsigner
APKSIGNER=""
JARSIGNER=""

# 查找最新版本的apksigner
BUILD_TOOLS_DIR="$ANDROID_HOME/build-tools"
if [ -d "$BUILD_TOOLS_DIR" ]; then
    LATEST_VERSION=$(ls -1 "$BUILD_TOOLS_DIR" | sort -V | tail -1)
    APKSIGNER="$BUILD_TOOLS_DIR/$LATEST_VERSION/apksigner"
    if [ ! -f "$APKSIGNER" ]; then
        APKSIGNER=""
    fi
fi

# 查找jarsigner（Java JDK自带）
JAVA_HOME="${JAVA_HOME:-$(dirname $(dirname $(readlink -f $(which java))))}"
if [ -f "$JAVA_HOME/bin/jarsigner" ]; then
    JARSIGNER="$JAVA_HOME/bin/jarsigner"
elif [ -f "$JAVA_HOME/bin/jarsigner.exe" ]; then
    JARSIGNER="$JAVA_HOME/bin/jarsigner.exe"
else
    # 从PATH查找
    JARSIGNER=$(which jarsigner)
fi

# 创建调试密钥（如果不存在）
KEYSTORE_PATH="$HOME/.android/debug.keystore"
if [ ! -f "$KEYSTORE_PATH" ]; then
    echo "Creating debug keystore..."
    KEYTOOL="$JAVA_HOME/bin/keytool"
    if [ ! -f "$KEYTOOL" ]; then
        KEYTOOL=$(which keytool)
    fi
    
    if [ -z "$KEYTOOL" ]; then
        echo "Error: keytool not found"
        exit 1
    fi
    
    mkdir -p "$(dirname "$KEYSTORE_PATH")"
    "$KEYTOOL" -genkey -v -keystore "$KEYSTORE_PATH" \
        -storepass android -alias androiddebugkey \
        -keypass android -keyalg RSA -keysize 2048 \
        -validity 10000 -dname "CN=Android Debug,O=Android,C=US"
    
    if [ $? -ne 0 ]; then
        echo "Error: Failed to create debug keystore"
        exit 1
    fi
    echo "Debug keystore created: $KEYSTORE_PATH"
fi

# 签名APK
if [ -n "$APKSIGNER" ] && [ -f "$APKSIGNER" ]; then
    echo "Signing APK with apksigner..."
    "$APKSIGNER" sign \
        --ks "$KEYSTORE_PATH" \
        --ks-pass pass:android \
        --ks-key-alias androiddebugkey \
        --key-pass pass:android \
        "$APK_PATH"
    
    if [ $? -eq 0 ]; then
        echo "APK signed successfully: $APK_PATH"
        exit 0
    else
        echo "Warning: apksigner failed, trying jarsigner..."
    fi
fi

if [ -n "$JARSIGNER" ] && [ -f "$JARSIGNER" ]; then
    echo "Signing APK with jarsigner..."
    "$JARSIGNER" -verbose -sigalg SHA256withRSA -digestalg SHA-256 \
        -keystore "$KEYSTORE_PATH" \
        -storepass android \
        -keypass android \
        "$APK_PATH" \
        androiddebugkey
    
    if [ $? -eq 0 ]; then
        echo "APK signed successfully: $APK_PATH"
        exit 0
    else
        echo "Error: jarsigner failed"
        exit 1
    fi
else
    echo "Error: Neither apksigner nor jarsigner found"
    exit 1
fi
