package com.libpass.attack.apk;

import soot.*;
import soot.options.Options;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.jar.*;
import java.util.zip.*;

import com.libpass.attack.util.Logger;
/**
 * APK重新打包器
 * 将修改后的Jimple代码转换为DEX并重新打包为APK
 */
public class APKRepackager {
    private boolean signAPK = true; // 默认签名APK
    private String jimpleDir;
    private String outputApkPath;
    private String androidJarPath;
    private String originalApkPath;
    private Scene scene; // 保存Scene引用，以便后续使用
    
    public APKRepackager(String jimpleDir, String outputApkPath, String androidJarPath, String originalApkPath) {
        this.jimpleDir = jimpleDir;
        this.outputApkPath = outputApkPath;
        this.androidJarPath = androidJarPath;
        this.originalApkPath = originalApkPath;
        this.scene = Scene.v(); // 保存当前Scene引用
    }
    
    /**
     * 设置是否签名APK
     */
    public void setSignAPK(boolean signAPK) {
        this.signAPK = signAPK;
    }
    
    /**
     * 重新打包APK（从class文件开始）
     */
    public boolean repackage() {
        try {
            // 1. 将Jimple转换为Java类文件
            Logger.debug("Converting Jimple to class files...");
            String classesDir = convertJimpleToClasses();
            
            // 2. 将类文件转换为DEX
            Logger.debug("Converting classes to DEX...");
            String dexPath = convertClassesToDex(classesDir);
            
            // 3. 提取原始APK资源
            Logger.debug("Extracting resources from original APK...");
            String resourcesDir = extractResources();
            
            // 4. 重新打包APK
            Logger.debug("Repackaging APK...");
            packageAPK(dexPath, resourcesDir, outputApkPath);
            
            // 5. 签名APK
            if (signAPK) {
                Logger.debug("Signing APK...");
                if (!signAPK(outputApkPath)) {
                    Logger.warning("APK repackaged but signing failed: %s", outputApkPath);
                    Logger.warning("You may need to sign it manually before installation");
                }
            }
            
            Logger.debug("APK repackaged successfully: %s", outputApkPath);
            
            return true;
        } catch (Exception e) {
            Logger.error("Failed to repackage APK: %s", e.getMessage(), e);
            e.printStackTrace();
            return false;
        }
    }
    
    /**
     * 从已生成的DEX文件重新打包APK（参考参考项目的做法）
     * DEX文件应该在jimpleDir目录下（Soot直接输出的DEX文件）
     */
    public boolean repackageFromDex() {
        try {
            // 1. 查找DEX文件（jimpleDir就是包含DEX文件的目录）
            Logger.debug("Looking for DEX files in: %s", jimpleDir);
            File dexDir = new File(jimpleDir);
            if (!dexDir.exists()) {
                throw new IOException("DEX output directory does not exist: " + jimpleDir);
            }
            
            // 查找所有DEX文件
            File[] dexFiles = dexDir.listFiles((dir, name) -> name.endsWith(".dex"));
            if (dexFiles == null || dexFiles.length == 0) {
                throw new IOException("No DEX files found in " + jimpleDir);
            }
            
            Logger.debug("Found %d DEX file(s)", dexFiles.length);
            
            // 如果只有一个classes.dex，直接使用它
            // 如果有多个DEX文件（classes.dex, classes2.dex等），需要合并处理
            String primaryDexPath = null;
            if (dexFiles.length == 1) {
                primaryDexPath = dexFiles[0].getAbsolutePath();
            } else {
                // 找到classes.dex（主DEX文件）
                for (File dexFile : dexFiles) {
                    if (dexFile.getName().equals("classes.dex")) {
                        primaryDexPath = dexFile.getAbsolutePath();
                        break;
                    }
                }
                // 如果没有找到classes.dex，使用第一个
                if (primaryDexPath == null) {
                    primaryDexPath = dexFiles[0].getAbsolutePath();
                }
                Logger.debug("Using primary DEX: %s", primaryDexPath);
                // TODO: 如果有多个DEX文件，需要将它们都打包进APK
            }
            
            // 2. 提取原始APK资源
            Logger.debug("Extracting resources from original APK...");
            String resourcesDir = extractResources();
            
            // 3. 重新打包APK（包含所有DEX文件）
            Logger.debug("Repackaging APK with DEX files...");
            if (dexFiles.length == 1) {
                // 单个DEX文件
                packageAPK(primaryDexPath, resourcesDir, outputApkPath);
            } else {
                // 多个DEX文件，需要全部打包
                packageAPKWithMultipleDex(jimpleDir, resourcesDir, outputApkPath);
            }
            
            // 4. 签名APK
            if (signAPK) {
                Logger.debug("Signing APK...");
                if (!signAPK(outputApkPath)) {
                    Logger.warning("APK repackaged but signing failed: %s", outputApkPath);
                    Logger.warning("You may need to sign it manually before installation");
                }
            }
            
            Logger.debug("APK repackaged successfully: %s", outputApkPath);
            
            return true;
        } catch (Exception e) {
            Logger.error("Failed to repackage APK from DEX: %s", e.getMessage(), e);
            e.printStackTrace();
            return false;
        }
    }
    
    /**
     * 将Jimple转换为类文件
     * 注意：class文件应该已经在LibPassAttackEngine中生成
     * 这个方法主要是验证和返回class文件目录
     */
    private String convertJimpleToClasses() throws IOException {
        String classesDir = jimpleDir + File.separator + "classes";
        File classesDirFile = new File(classesDir);
        
        // 检查class文件是否已经存在（应该在LibPassAttackEngine中已经生成）
        if (!classesDirFile.exists()) {
            // 如果目录不存在，尝试生成
            classesDirFile.mkdirs();
            
            // 检查Scene中是否有已加载的类
            Scene currentScene = (this.scene != null) ? this.scene : Scene.v();
            if (currentScene != null && !currentScene.getApplicationClasses().isEmpty()) {
                Logger.debug("Generating class files from Scene (%d classes)...", currentScene.getApplicationClasses().size());
                
                // 设置Soot输出为class文件
                Options.v().set_output_format(Options.output_format_class);
                Options.v().set_output_dir(classesDir);
                
                // 运行Soot以生成class文件
                soot.PackManager.v().runPacks();
            } else {
                throw new IOException("No classes in Scene and class files directory does not exist: " + classesDir);
            }
        }
        
        // 验证是否生成了class文件
        File[] classFiles = classesDirFile.listFiles((dir, name) -> name.endsWith(".class"));
        if (classFiles == null || classFiles.length == 0) {
            // 检查子目录
            File[] subDirs = classesDirFile.listFiles(File::isDirectory);
            if (subDirs != null) {
                for (File subDir : subDirs) {
                    File[] subClassFiles = subDir.listFiles((dir, name) -> name.endsWith(".class"));
                    if (subClassFiles != null && subClassFiles.length > 0) {
                        System.out.println("Found " + subClassFiles.length + " class files in " + subDir.getName());
                        return classesDir; // 返回根目录，d8会递归查找
                    }
                }
            }
            throw new IOException("No class files found in " + classesDir + ". Please ensure class files were generated in LibPassAttackEngine.");
        } else {
            Logger.debug("Found %d class files in root directory", classFiles.length);
        }
        
        return classesDir;
    }
    
    /**
     * 手动从Jimple文件转换为class文件（备用方法）
     */
    private String convertJimpleToClassesManually(String classesDir) throws IOException {
        // 这是一个简化的实现，实际可能需要更复杂的处理
        // 目前返回空目录，让调用者知道转换失败
        Logger.error("Manual Jimple to class conversion not fully implemented.");
        return classesDir;
    }
    
    /**
     * 将类文件转换为DEX
     * 使用d8工具（优先）或dx工具（Android SDK的一部分）
     */
    private String convertClassesToDex(String classesDir) throws IOException, InterruptedException {
        String dexPath = outputApkPath.replace(".apk", ".dex");
        
        // 查找d8或dx工具
        ToolInfo toolInfo = findDxTool();
        if (toolInfo == null) {
            throw new IOException("dx/d8 tool not found. Please set ANDROID_HOME environment variable or install Android SDK.");
        }
        
        // 构建命令
        List<String> command = new ArrayList<>();
        
        if (toolInfo.isJar) {
            // 使用JAR文件（仅dx.jar，d8.jar不支持这种方式）
            command.add("java");
            command.add("-jar");
            command.add(toolInfo.path);
            command.add("--dex");
            command.add("--output=" + dexPath);
            command.add(classesDir);
        } else {
            // 使用脚本（d8或dx脚本）
            command.add(toolInfo.path);
            
            if (toolInfo.isD8) {
                // d8命令格式：d8 --output <dir> <class-files-or-dirs>
                command.add("--output");
                command.add(new File(dexPath).getParent());
                // d8可以接受目录，会自动递归查找class文件
                File classesDirFile = new File(classesDir);
                if (classesDirFile.exists()) {
                    command.add(classesDirFile.getAbsolutePath());
                } else {
                    throw new IOException("Classes directory not found: " + classesDir);
                }
            } else {
                // dx命令格式：dx --dex --output=<file> <dir>
                command.add("--dex");
                command.add("--output=" + dexPath);
                command.add(classesDir);
            }
        }
        
        // 执行命令
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);
        Process process = pb.start();
        
        // 读取输出
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        String line;
        while ((line = reader.readLine()) != null) {
            Logger.debug("%s: %s", toolInfo.isD8 ? "d8" : "dx", line);
        }
        
        int exitCode = process.waitFor();
        if (exitCode != 0) {
            throw new IOException((toolInfo.isD8 ? "d8" : "dx") + " tool failed with exit code: " + exitCode);
        }
        
        // d8输出文件名可能不同，需要检查
        if (toolInfo.isD8) {
            File outputDir = new File(dexPath).getParentFile();
            File[] dexFiles = outputDir.listFiles((dir, name) -> name.endsWith(".dex"));
            if (dexFiles != null && dexFiles.length > 0) {
                // 重命名为期望的文件名
                File actualDex = dexFiles[0];
                File expectedDex = new File(dexPath);
                if (!actualDex.equals(expectedDex)) {
                    actualDex.renameTo(expectedDex);
                }
            } else {
                // d8可能输出到classes.dex
                File classesDex = new File(outputDir, "classes.dex");
                if (classesDex.exists()) {
                    classesDex.renameTo(new File(dexPath));
                }
            }
        }
        
        return dexPath;
    }
    
    /**
     * 递归收集所有class文件
     */
    private void collectClassFiles(File dir, List<File> classFiles) {
        File[] files = dir.listFiles();
        if (files != null) {
            for (File file : files) {
                if (file.isDirectory()) {
                    collectClassFiles(file, classFiles);
                } else if (file.getName().endsWith(".class")) {
                    classFiles.add(file);
                }
            }
        }
    }
    
    /**
     * 工具信息类
     */
    private static class ToolInfo {
        String path;
        boolean isD8;
        boolean isJar;
        
        ToolInfo(String path, boolean isD8, boolean isJar) {
            this.path = path;
            this.isD8 = isD8;
            this.isJar = isJar;
        }
    }
    
    /**
     * 查找dx工具或d8工具（d8是dx的替代品）
     * 优先使用d8脚本，如果找不到则使用dx
     */
    private ToolInfo findDxTool() {
        // 尝试从环境变量获取
        String androidHome = System.getenv("ANDROID_HOME");
        if (androidHome == null) {
            androidHome = System.getenv("ANDROID_SDK_ROOT");
        }
        
        // 尝试常见的Android SDK路径
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
                            // 简单版本比较（假设格式为 "XX.YY.ZZ"）
                            String[] aParts = a.getName().split("\\.");
                            String[] bParts = b.getName().split("\\.");
                            int maxLen = Math.max(aParts.length, bParts.length);
                            for (int i = 0; i < maxLen; i++) {
                                int aVal = i < aParts.length ? Integer.parseInt(aParts[i]) : 0;
                                int bVal = i < bParts.length ? Integer.parseInt(bParts[i]) : 0;
                                if (aVal != bVal) {
                                    return Integer.compare(bVal, aVal); // 降序
                                }
                            }
                            return 0;
                        } catch (Exception e) {
                            return a.getName().compareTo(b.getName());
                        }
                    });
                    
                    // 优先查找d8脚本（较新的工具，推荐方式）
                    for (File versionDir : versions) {
                        String version = versionDir.getName();
                        String versionPath = buildToolsDir.getAbsolutePath() + File.separator + version;
                        
                        // 优先使用d8脚本（推荐方式，d8.jar不是可执行JAR）
                        String d8Script = versionPath + File.separator + "d8";
                        if (new File(d8Script).exists() && new File(d8Script).canExecute()) {
                            Logger.info("Found d8 script: %s", d8Script);
                            return new ToolInfo(d8Script, true, false);
                        }
                        
                        // 尝试dx工具（旧版本）
                        String dx = versionPath + File.separator + "dx";
                        String dxJar = versionPath + File.separator + "lib" + File.separator + "dx.jar";
                        
                        if (new File(dx).exists() && new File(dx).canExecute()) {
                            Logger.info("Found dx tool: %s", dx);
                            return new ToolInfo(dx, false, false);
                        }
                        if (new File(dxJar).exists()) {
                            Logger.info("Found dx.jar: %s", dxJar);
                            return new ToolInfo(dxJar, false, true);
                        }
                    }
                }
            }
        }
        
        Logger.error("Android SDK not found. Please set ANDROID_HOME or ANDROID_SDK_ROOT environment variable.");
        Logger.error("Or install Android SDK at: ~/Library/Android/sdk (macOS) or ~/.android/sdk (Linux)");
        return null;
    }
    
    /**
     * 提取原始APK的资源
     */
    private String extractResources() throws IOException {
        String resourcesDir = jimpleDir + File.separator + "resources";
        new File(resourcesDir).mkdirs();
        
        // 使用Java的ZipFile解压APK
        try (ZipFile zipFile = new ZipFile(originalApkPath)) {
            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String name = entry.getName();
                
                // 跳过classes.dex，只提取资源
                if (name.equals("classes.dex") || name.startsWith("META-INF/")) {
                    continue;
                }
                
                File file = new File(resourcesDir, name);
                if (entry.isDirectory()) {
                    file.mkdirs();
                } else {
                    file.getParentFile().mkdirs();
                    try (InputStream is = zipFile.getInputStream(entry);
                         FileOutputStream fos = new FileOutputStream(file)) {
                        byte[] buffer = new byte[1024];
                        int len;
                        while ((len = is.read(buffer)) > 0) {
                            fos.write(buffer, 0, len);
                        }
                    }
                }
            }
        }
        
        return resourcesDir;
    }
    
    /**
     * 打包APK
     */
    private void packageAPK(String dexPath, String resourcesDir, String outputApk) throws IOException {
        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(outputApk))) {
            // 添加DEX文件
            addFileToZip(zos, new File(dexPath), "classes.dex");
            
            // 添加资源文件
            addDirectoryToZip(zos, new File(resourcesDir), "");
            
            // 添加AndroidManifest.xml（如果需要）
            // 这里简化处理，实际应该从原始APK复制
        }
    }
    
    /**
     * 打包APK（包含多个DEX文件）
     */
    private void packageAPKWithMultipleDex(String dexDir, String resourcesDir, String outputApk) throws IOException {
        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(outputApk))) {
            // 添加所有DEX文件（按名称排序，classes.dex在前）
            File dexDirFile = new File(dexDir);
            File[] dexFiles = dexDirFile.listFiles((dir, name) -> name.endsWith(".dex"));
            if (dexFiles != null && dexFiles.length > 0) {
                // 排序：classes.dex在前，然后是classes2.dex, classes3.dex等
                Arrays.sort(dexFiles, (a, b) -> {
                    String nameA = a.getName();
                    String nameB = b.getName();
                    // classes.dex始终在前
                    if (nameA.equals("classes.dex")) return -1;
                    if (nameB.equals("classes.dex")) return 1;
                    return nameA.compareTo(nameB);
                });
                
                for (File dexFile : dexFiles) {
                    String entryName = dexFile.getName(); // classes.dex, classes2.dex等
                    Logger.debug("Adding DEX file to APK: %s", entryName);
                    addFileToZip(zos, dexFile, entryName);
                }
            }
            
            // 添加资源文件
            addDirectoryToZip(zos, new File(resourcesDir), "");
        }
    }
    
    /**
     * 添加文件到ZIP
     */
    private void addFileToZip(ZipOutputStream zos, File file, String entryName) throws IOException {
        try (FileInputStream fis = new FileInputStream(file)) {
            ZipEntry entry = new ZipEntry(entryName);
            zos.putNextEntry(entry);
            
            byte[] buffer = new byte[1024];
            int len;
            while ((len = fis.read(buffer)) > 0) {
                zos.write(buffer, 0, len);
            }
            
            zos.closeEntry();
        }
    }
    
    /**
     * 添加目录到ZIP
     */
    private void addDirectoryToZip(ZipOutputStream zos, File directory, String basePath) throws IOException {
        File[] files = directory.listFiles();
        if (files != null) {
            for (File file : files) {
                String path = basePath + file.getName();
                if (file.isDirectory()) {
                    path += "/";
                    zos.putNextEntry(new ZipEntry(path));
                    zos.closeEntry();
                    addDirectoryToZip(zos, file, path);
                } else {
                    addFileToZip(zos, file, path);
                }
            }
        }
    }
    
    /**
     * 签名APK
     */
    private boolean signAPK(String apkPath) {
        try {
            // 确保调试密钥存在
            if (!APKSigner.createDebugKeystoreIfNeeded()) {
                Logger.warning("Failed to create debug keystore, signing may fail");
            }
            
            // 使用默认调试密钥签名
            APKSigner signer = new APKSigner();
            return signer.signAPK(apkPath);
        } catch (Exception e) {
            Logger.error("Failed to sign APK: %s", e.getMessage(), e);
            return false;
        }
    }
}
