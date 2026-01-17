package com.libpass.attack.apk;

import com.libpass.attack.util.Logger;

import java.io.*;
import java.nio.file.*;
import java.util.*;

/**
 * APK签名工具
 * 使用jarsigner或apksigner对APK进行签名
 */
public class APKSigner {
    private String keystorePath;
    private String keystorePassword;
    private String keyAlias;
    private String keyPassword;
    
    /**
     * 使用默认调试密钥签名（用于测试）
     */
    public APKSigner() {
        // 使用Android默认调试密钥路径
        String userHome = System.getProperty("user.home");
        this.keystorePath = userHome + File.separator + ".android" + File.separator + "debug.keystore";
        this.keystorePassword = "android";
        this.keyAlias = "androiddebugkey";
        this.keyPassword = "android";
    }
    
    /**
     * 使用自定义密钥签名
     */
    public APKSigner(String keystorePath, String keystorePassword, 
                    String keyAlias, String keyPassword) {
        this.keystorePath = keystorePath;
        this.keystorePassword = keystorePassword;
        this.keyAlias = keyAlias;
        this.keyPassword = keyPassword;
    }
    
    /**
     * 签名APK
     * @param apkPath APK文件路径
     * @return 是否签名成功
     */
    public boolean signAPK(String apkPath) {
        // 优先使用apksigner（Android SDK Build Tools 24.0.3+）
        if (signWithApksigner(apkPath)) {
            return true;
        }
        
        // 回退到jarsigner（Java JDK自带）
        if (signWithJarsigner(apkPath)) {
            return true;
        }
        
        Logger.error("Failed to sign APK: %s", apkPath);
        return false;
    }
    
    /**
     * 使用apksigner签名（推荐，Android官方工具）
     */
    private boolean signWithApksigner(String apkPath) {
        String apksignerPath = findApksigner();
        if (apksignerPath == null) {
            Logger.debug("apksigner not found, will try jarsigner");
            return false;
        }
        
        try {
            List<String> command = new ArrayList<>();
            
            // 如果是JAR文件，使用java -jar方式执行
            if (apksignerPath.startsWith("JAR:")) {
                String jarPath = apksignerPath.substring(4);
                command.add("java");
                command.add("-jar");
                command.add(jarPath);
            } else {
                command.add(apksignerPath);
            }
            
            command.add("sign");
            command.add("--ks");
            command.add(keystorePath);
            command.add("--ks-pass");
            command.add("pass:" + keystorePassword);
            command.add("--ks-key-alias");
            command.add(keyAlias);
            command.add("--key-pass");
            command.add("pass:" + keyPassword);
            command.add(apkPath);
            
            ProcessBuilder pb = new ProcessBuilder(command);
            pb.redirectErrorStream(true);
            Process process = pb.start();
            
            // 读取输出
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                Logger.debug("apksigner: %s", line);
            }
            
            int exitCode = process.waitFor();
            if (exitCode == 0) {
                Logger.info("APK signed successfully with apksigner: %s", apkPath);
                return true;
            } else {
                Logger.warning("apksigner failed with exit code: %d", exitCode);
                return false;
            }
        } catch (Exception e) {
            Logger.warning("Failed to sign with apksigner: %s", e.getMessage());
            return false;
        }
    }
    
    /**
     * 使用jarsigner签名（Java JDK自带）
     */
    private boolean signWithJarsigner(String apkPath) {
        String jarsignerPath = findJarsigner();
        if (jarsignerPath == null) {
            Logger.error("jarsigner not found in JDK");
            return false;
        }
        
        try {
            List<String> command = new ArrayList<>();
            command.add(jarsignerPath);
            command.add("-verbose");
            command.add("-sigalg");
            command.add("SHA256withRSA");
            command.add("-digestalg");
            command.add("SHA-256");
            command.add("-keystore");
            command.add(keystorePath);
            command.add("-storepass");
            command.add(keystorePassword);
            command.add("-keypass");
            command.add(keyPassword);
            command.add(apkPath);
            command.add(keyAlias);
            
            ProcessBuilder pb = new ProcessBuilder(command);
            pb.redirectErrorStream(true);
            Process process = pb.start();
            
            // 读取输出
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                Logger.debug("jarsigner: %s", line);
            }
            
            int exitCode = process.waitFor();
            if (exitCode == 0) {
                Logger.info("APK signed successfully with jarsigner: %s", apkPath);
                return true;
            } else {
                Logger.error("jarsigner failed with exit code: %d", exitCode);
                return false;
            }
        } catch (Exception e) {
            Logger.error("Failed to sign with jarsigner: %s", e.getMessage(), e);
            return false;
        }
    }
    
    /**
     * 查找apksigner工具
     */
    private String findApksigner() {
        String androidHome = System.getenv("ANDROID_HOME");
        if (androidHome == null) {
            androidHome = System.getenv("ANDROID_SDK_ROOT");
        }
        
        if (androidHome == null) {
            String userHome = System.getProperty("user.home");
            String[] commonPaths = {
                userHome + File.separator + "Library" + File.separator + "Android" + File.separator + "sdk",
                userHome + File.separator + ".android" + File.separator + "sdk",
                userHome + File.separator + "Android" + File.separator + "Sdk",
                "/opt/android-sdk",
                "/usr/local/android-sdk"
            };
            
            for (String path : commonPaths) {
                if (new File(path).exists()) {
                    androidHome = path;
                    break;
                }
            }
        }
        
        if (androidHome != null) {
            File buildToolsDir = new File(androidHome, "build-tools");
            if (buildToolsDir.exists()) {
                File[] versions = buildToolsDir.listFiles();
                if (versions != null && versions.length > 0) {
                    // 按版本号排序，使用最新版本
                    Arrays.sort(versions, (a, b) -> {
                        try {
                            String[] aParts = a.getName().split("\\.");
                            String[] bParts = b.getName().split("\\.");
                            int maxLen = Math.max(aParts.length, bParts.length);
                            for (int i = 0; i < maxLen; i++) {
                                int aVal = i < aParts.length ? Integer.parseInt(aParts[i]) : 0;
                                int bVal = i < bParts.length ? Integer.parseInt(bParts[i]) : 0;
                                if (aVal != bVal) {
                                    return Integer.compare(bVal, aVal);
                                }
                            }
                            return 0;
                        } catch (Exception e) {
                            return a.getName().compareTo(b.getName());
                        }
                    });
                    
                    for (File versionDir : versions) {
                        String apksigner = versionDir.getAbsolutePath() + 
                                         File.separator + "apksigner";
                        String apksignerJar = versionDir.getAbsolutePath() + 
                                            File.separator + "lib" + 
                                            File.separator + "apksigner.jar";
                        
                        if (new File(apksigner).exists() && new File(apksigner).canExecute()) {
                            return apksigner;
                        }
                        if (new File(apksignerJar).exists()) {
                            // 返回特殊标记，在signWithApksigner中处理
                            return "JAR:" + apksignerJar;
                        }
                    }
                }
            }
        }
        
        return null;
    }
    
    /**
     * 查找jarsigner工具（Java JDK自带）
     */
    private String findJarsigner() {
        String javaHome = System.getProperty("java.home");
        if (javaHome != null) {
            String jarsigner = javaHome + File.separator + "bin" + File.separator + "jarsigner";
            if (new File(jarsigner).exists()) {
                return jarsigner;
            }
            // Windows系统
            jarsigner = javaHome + File.separator + "bin" + File.separator + "jarsigner.exe";
            if (new File(jarsigner).exists()) {
                return jarsigner;
            }
        }
        
        // 尝试从PATH中查找
        String[] paths = System.getenv("PATH").split(File.pathSeparator);
        for (String path : paths) {
            String jarsigner = path + File.separator + "jarsigner";
            if (new File(jarsigner).exists() && new File(jarsigner).canExecute()) {
                return jarsigner;
            }
            jarsigner = path + File.separator + "jarsigner.exe";
            if (new File(jarsigner).exists()) {
                return jarsigner;
            }
        }
        
        return null;
    }
    
    /**
     * 创建默认调试密钥（如果不存在）
     */
    public static boolean createDebugKeystoreIfNeeded() {
        String userHome = System.getProperty("user.home");
        String keystorePath = userHome + File.separator + ".android" + File.separator + "debug.keystore";
        File keystoreFile = new File(keystorePath);
        
        if (keystoreFile.exists()) {
            return true;
        }
        
        // 创建.android目录
        keystoreFile.getParentFile().mkdirs();
        
        // 使用keytool创建调试密钥
        String keytoolPath = findKeytool();
        if (keytoolPath == null) {
            Logger.error("keytool not found, cannot create debug keystore");
            return false;
        }
        
        try {
            List<String> command = new ArrayList<>();
            command.add(keytoolPath);
            command.add("-genkey");
            command.add("-v");
            command.add("-keystore");
            command.add(keystorePath);
            command.add("-storepass");
            command.add("android");
            command.add("-alias");
            command.add("androiddebugkey");
            command.add("-keypass");
            command.add("android");
            command.add("-keyalg");
            command.add("RSA");
            command.add("-keysize");
            command.add("2048");
            command.add("-validity");
            command.add("10000");
            command.add("-dname");
            command.add("CN=Android Debug,O=Android,C=US");
            
            ProcessBuilder pb = new ProcessBuilder(command);
            Process process = pb.start();
            
            int exitCode = process.waitFor();
            if (exitCode == 0) {
                Logger.info("Created debug keystore: %s", keystorePath);
                return true;
            } else {
                Logger.error("Failed to create debug keystore, exit code: %d", exitCode);
                return false;
            }
        } catch (Exception e) {
            Logger.error("Failed to create debug keystore: %s", e.getMessage(), e);
            return false;
        }
    }
    
    /**
     * 查找keytool工具
     */
    private static String findKeytool() {
        String javaHome = System.getProperty("java.home");
        if (javaHome != null) {
            String keytool = javaHome + File.separator + "bin" + File.separator + "keytool";
            if (new File(keytool).exists()) {
                return keytool;
            }
            keytool = javaHome + File.separator + "bin" + File.separator + "keytool.exe";
            if (new File(keytool).exists()) {
                return keytool;
            }
        }
        
        String[] paths = System.getenv("PATH").split(File.pathSeparator);
        for (String path : paths) {
            String keytool = path + File.separator + "keytool";
            if (new File(keytool).exists() && new File(keytool).canExecute()) {
                return keytool;
            }
            keytool = path + File.separator + "keytool.exe";
            if (new File(keytool).exists()) {
                return keytool;
            }
        }
        
        return null;
    }
}
