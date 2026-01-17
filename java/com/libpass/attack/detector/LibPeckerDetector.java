package com.libpass.attack.detector;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

import com.libpass.attack.util.Logger;

/**
 * LibPecker检测工具适配器
 * LibPecker支持版本级检测，会输出版本候选
 */
public class LibPeckerDetector implements TPLDetector {
    private static final String NAME = "LibPecker";
    private String libpeckerJarPath;
    private String libpeckerBinDir;
    private String libpeckerSdkDir;
    private String libpeckerBaseDir;
    private String tempOutputDir;
    private Map<String, Object> config;
    
    public LibPeckerDetector() {
        this.config = new HashMap<>();
    }
    
    @Override
    public String getName() {
        return NAME;
    }
    
    @Override
    public void initialize(Map<String, Object> config) {
        this.config = config;
        String libpeckerJarPathConfig = (String) config.getOrDefault("libpecker_jar_path", 
            "TPL_Detectors/LibPecker/LibPecker.jar");
        String libpeckerBinDirConfig = (String) config.getOrDefault("libpecker_bin_dir",
            "TPL_Detectors/LibPecker/bin");
        String libpeckerSdkDirConfig = (String) config.getOrDefault("libpecker_sdk_dir",
            "TPL_Detectors/LibPecker/sdk");
        
        // 转换为绝对路径
        File libpeckerJarFile = new File(libpeckerJarPathConfig);
        if (!libpeckerJarFile.isAbsolute()) {
            String currentDir = System.getProperty("user.dir");
            File absPath = new File(currentDir, libpeckerJarPathConfig);
            if (absPath.exists()) {
                this.libpeckerJarPath = absPath.getAbsolutePath();
            } else {
                this.libpeckerJarPath = libpeckerJarPathConfig;
            }
        } else {
            this.libpeckerJarPath = libpeckerJarPathConfig;
        }
        
        // 获取LibPecker基础目录（JAR文件所在目录）
        File libpeckerJarFileForDir = new File(this.libpeckerJarPath);
        this.libpeckerBaseDir = libpeckerJarFileForDir.getParent();
        
        File libpeckerBinDirFile = new File(libpeckerBinDirConfig);
        if (!libpeckerBinDirFile.isAbsolute()) {
            String currentDir = System.getProperty("user.dir");
            File absPath = new File(currentDir, libpeckerBinDirConfig);
            if (absPath.exists()) {
                this.libpeckerBinDir = absPath.getAbsolutePath();
            } else {
                this.libpeckerBinDir = libpeckerBinDirConfig;
            }
        } else {
            this.libpeckerBinDir = libpeckerBinDirConfig;
        }
        
        File libpeckerSdkDirFile = new File(libpeckerSdkDirConfig);
        if (!libpeckerSdkDirFile.isAbsolute()) {
            String currentDir = System.getProperty("user.dir");
            File absPath = new File(currentDir, libpeckerSdkDirConfig);
            if (absPath.exists()) {
                this.libpeckerSdkDir = absPath.getAbsolutePath();
            } else {
                this.libpeckerSdkDir = libpeckerSdkDirConfig;
            }
        } else {
            this.libpeckerSdkDir = libpeckerSdkDirConfig;
        }
        
        this.tempOutputDir = (String) config.getOrDefault("temp_output_dir",
            System.getProperty("java.io.tmpdir") + "/libpecker_output");
        
        // 创建临时输出目录
        new File(tempOutputDir).mkdirs();
        
        // 验证路径
        File libpeckerJarFileCheck = new File(this.libpeckerJarPath);
        if (!libpeckerJarFileCheck.exists()) {
            Logger.warning("LibPecker.jar not found at: %s", this.libpeckerJarPath);
        } else {
            Logger.debug("LibPecker JAR path resolved to: %s", this.libpeckerJarPath);
        }
        
        File binDirFile = new File(this.libpeckerBinDir);
        if (!binDirFile.exists()) {
            Logger.warning("LibPecker bin directory not found at: %s", this.libpeckerBinDir);
        } else {
            Logger.debug("LibPecker bin directory: %s", this.libpeckerBinDir);
        }
        
        File sdkDirFile = new File(this.libpeckerSdkDir);
        if (!sdkDirFile.exists()) {
            Logger.warning("LibPecker SDK directory not found at: %s", this.libpeckerSdkDir);
        } else {
            Logger.debug("LibPecker SDK directory: %s", this.libpeckerSdkDir);
        }
        
        Logger.debug("LibPecker base directory: %s", this.libpeckerBaseDir);
    }
    
    @Override
    public boolean isAvailable() {
        if (libpeckerJarPath == null) {
            return false;
        }
        File libpeckerJarFile = new File(libpeckerJarPath);
        boolean exists = libpeckerJarFile.exists();
        boolean readable = libpeckerJarFile.canRead();
        
        if (!exists) {
            Logger.error("LibPecker.jar not found at: %s", libpeckerJarPath);
        } else if (!readable) {
            Logger.error("LibPecker.jar is not readable: %s", libpeckerJarPath);
        }
        
        return exists && readable;
    }
    
    @Override
    public DetectionResult detectTPL(String apkPath, String tplPath, String tplName) {
        DetectionResult result = new DetectionResult();
        result.setApkPath(apkPath);
        result.setTplName(tplName != null ? tplName : extractTPLName(tplPath));
        
        try {
            // 创建临时目录用于LibPecker检测
            // 使用UUID确保唯一性，避免多线程环境下目录冲突
            String uniqueId = UUID.randomUUID().toString().replace("-", "");
            String tempDir = tempOutputDir + "/" + System.currentTimeMillis() + "_" + uniqueId;
            new File(tempDir).mkdirs();
            
            // 准备APK文件
            String tempApkPath = tempDir + "/" + new File(apkPath).getName();
            Files.copy(Paths.get(apkPath), Paths.get(tempApkPath), 
                StandardCopyOption.REPLACE_EXISTING);
            
            // 准备TPL文件（DEX格式）
            String tempTplDexPath = prepareTPLForDetection(tplPath, tempDir);
            if (tempTplDexPath == null) {
                result.setDetected(false);
                result.setMessage("Failed to prepare TPL for detection");
                return result;
            }
            
            // 运行LibPecker检测
            boolean success = runLibPeckerDetection(tempApkPath, tempTplDexPath, tempDir);
            
            if (success) {
                // 解析检测结果
                Logger.debug("LibPecker detection completed, parsing results...");
                result = parseLibPeckerResult(tempDir, tempApkPath, result);
                // 输出检测结果（DEBUG级别）
                Logger.debug("LibPecker result: detected=%s, confidence=%.6f", 
                    result.isDetected(), result.getConfidence());
            } else {
                Logger.error("LibPecker detection process failed");
                result.setDetected(false);
                result.setConfidence(0.0);
                result.setMessage("LibPecker detection process failed");
            }
            
            // 清理临时目录
            cleanupTempDir(tempDir);
            
        } catch (Exception e) {
            Logger.error("Failed to detect TPL with LibPecker: %s", e.getMessage());
            e.printStackTrace();
            result.setDetected(false);
            result.setConfidence(0.0);
            result.setMessage("Exception: " + e.getMessage());
        }
        
        return result;
    }
    
    @Override
    public Map<String, DetectionResult> detectTPLBatch(List<String> apkPaths, String tplPath, String tplName) {
        Map<String, DetectionResult> results = new HashMap<>();
        for (String apkPath : apkPaths) {
            DetectionResult result = detectTPL(apkPath, tplPath, tplName);
            results.put(apkPath, result);
        }
        return results;
    }
    
    /**
     * 准备TPL文件用于检测（转换为DEX格式）
     */
    private String prepareTPLForDetection(String tplPath, String tempDir) {
        try {
            File tplFile = new File(tplPath);
            String fileName = tplFile.getName();
            String extension = fileName.substring(fileName.lastIndexOf('.') + 1);
            
            String tplDexPath;
            
            if (extension.equals("dex")) {
                // 已经是DEX格式，直接复制
                tplDexPath = tempDir + "/" + fileName;
                Files.copy(Paths.get(tplPath), Paths.get(tplDexPath), 
                    StandardCopyOption.REPLACE_EXISTING);
            } else if (extension.equals("jar") || extension.equals("aar")) {
                // 需要转换为DEX
                String dexFileName = fileName.substring(0, fileName.lastIndexOf('.')) + ".dex";
                tplDexPath = tempDir + "/" + dexFileName;
                
                // 使用LibPecker的dx工具转换
                boolean converted = convertJarToDex(tplPath, tplDexPath);
                if (!converted) {
                    Logger.error("Failed to convert JAR/AAR to DEX for LibPecker");
                    return null;
                }
            } else {
                Logger.error("Unsupported TPL format for LibPecker: %s", extension);
                return null;
            }
            
            return tplDexPath;
            
        } catch (Exception e) {
            Logger.error("Failed to prepare TPL: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }
    
    /**
     * 将JAR/AAR转换为DEX（使用LibPecker的dx工具）
     */
    private boolean convertJarToDex(String jarPath, String dexPath) {
        try {
            // 确定dx命令路径
            String dxCommand;
            String os = System.getProperty("os.name").toLowerCase();
            if (os.contains("win")) {
                dxCommand = libpeckerBinDir + "/dx.sh";
            } else {
                dxCommand = libpeckerBinDir + "/dx";
            }
            
            File dxFile = new File(dxCommand);
            if (!dxFile.exists()) {
                Logger.error("dx tool not found at: %s", dxCommand);
                return false;
            }
            
            // 确保dx可执行
            if (!os.contains("win")) {
                dxFile.setExecutable(true);
            }
            
            Logger.debug("Converting JAR to DEX: %s -> %s", jarPath, dexPath);
            
            ProcessBuilder pb = new ProcessBuilder(
                dxCommand,
                "--dex",
                "--output=" + dexPath,
                jarPath
            );
            
            pb.redirectErrorStream(true);
            Process process = pb.start();
            
            // 读取输出
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            String line;
            while ((line = reader.readLine()) != null) {
                Logger.debug("dx: %s", line);
            }
            
            boolean finished = process.waitFor(60, TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                Logger.error("dx conversion timeout");
                return false;
            }
            
            int exitCode = process.exitValue();
            if (exitCode != 0) {
                Logger.error("dx conversion failed with exit code: %d", exitCode);
                return false;
            }
            
            boolean success = new File(dexPath).exists();
            if (!success) {
                Logger.error("DEX file not created: %s", dexPath);
            }
            
            return success;
            
        } catch (Exception e) {
            Logger.error("Failed to convert JAR to DEX: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }
    
    /**
     * 运行LibPecker检测
     */
    private boolean runLibPeckerDetection(String apkPath, String tplDexPath, String tempDir) {
        try {
            // 确保使用绝对路径
            File apkFile = new File(apkPath);
            String absApkPath = apkFile.isAbsolute() ? apkPath : apkFile.getAbsolutePath();
            
            File tplDexFile = new File(tplDexPath);
            String absTplDexPath = tplDexFile.isAbsolute() ? tplDexPath : tplDexFile.getAbsolutePath();
            
            File libpeckerJarFile = new File(libpeckerJarPath);
            String absLibpeckerJarPath = libpeckerJarFile.isAbsolute() ? libpeckerJarPath : libpeckerJarFile.getAbsolutePath();
            
            Logger.debug("Executing LibPecker:");
            Logger.debug("  JAR: %s", absLibpeckerJarPath);
            Logger.debug("  APK: %s", absApkPath);
            Logger.debug("  TPL DEX: %s", absTplDexPath);
            
            // LibPecker命令：java -jar LibPecker.jar <apk_path> <lib_path>
            // 根据README，LibPecker测试时使用 -Xmx4G，这里也设置足够的内存
            ProcessBuilder pb = new ProcessBuilder(
                "java",
                "-Xmx4G",  // 设置最大堆内存为4GB（与README中的测试命令一致）
                "-jar",
                absLibpeckerJarPath,
                absApkPath,
                absTplDexPath
            );
            
            // 设置工作目录为LibPecker基础目录，这样LibPecker可以找到sdk子目录
            // LibPecker会在当前工作目录下查找sdk目录
            if (libpeckerBaseDir != null) {
                File baseDirFile = new File(libpeckerBaseDir);
                if (baseDirFile.exists() && baseDirFile.isDirectory()) {
                    pb.directory(baseDirFile);
                    Logger.debug("LibPecker working directory set to: %s", libpeckerBaseDir);
                } else {
                    Logger.warning("LibPecker base directory not found: %s", libpeckerBaseDir);
                }
            }
            
            // 设置输出文件
            String outputFile = tempDir + "/libpecker_result.txt";
            String errorFile = tempDir + "/libpecker_error.txt";
            pb.redirectOutput(new File(outputFile));
            pb.redirectError(new File(errorFile));
            
            Process process = pb.start();
            
            // 实时读取错误输出（如果可能）
            // 注意：由于重定向到文件，这里无法实时读取，但可以在进程结束后读取
            
            boolean finished = process.waitFor(300, TimeUnit.SECONDS); // 5分钟超时
            if (!finished) {
                process.destroyForcibly();
                Logger.error("LibPecker detection timeout");
                // 读取错误输出
                readAndLogErrorOutput(errorFile, outputFile);
                return false;
            }
            
            int exitCode = process.exitValue();
            if (exitCode != 0) {
                Logger.error("LibPecker exited with non-zero code: %d", exitCode);
                // 读取并输出错误信息
                readAndLogErrorOutput(errorFile, outputFile);
                // 即使退出码非0，也尝试解析结果（可能部分成功）
                return new File(outputFile).exists();
            }
            
            return true;
            
        } catch (Exception e) {
            Logger.error("Failed to run LibPecker: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }
    
    /**
     * 读取并输出错误信息
     */
    private void readAndLogErrorOutput(String errorFile, String outputFile) {
        try {
            // 读取错误文件
            File errorFileObj = new File(errorFile);
            if (errorFileObj.exists() && errorFileObj.length() > 0) {
                List<String> errorLines = Files.readAllLines(Paths.get(errorFile));
                if (!errorLines.isEmpty()) {
                    Logger.error("LibPecker error output:");
                    for (String line : errorLines) {
                        Logger.error("  %s", line);
                    }
                }
            }
            
            // 也读取输出文件（可能包含错误信息，因为某些工具会将错误输出到stdout）
            File outputFileObj = new File(outputFile);
            if (outputFileObj.exists() && outputFileObj.length() > 0) {
                List<String> outputLines = Files.readAllLines(Paths.get(outputFile));
                if (!outputLines.isEmpty()) {
                    // 检查是否包含错误信息（不是正常的similarity输出）
                    boolean hasError = true;
                    for (String line : outputLines) {
                        if (line.contains("similarity:")) {
                            hasError = false;
                            break;
                        }
                    }
                    
                    if (hasError) {
                        Logger.error("LibPecker output (may contain errors):");
                        for (String line : outputLines) {
                            Logger.error("  %s", line);
                        }
                    } else {
                        // 正常输出，记录为DEBUG
                        Logger.debug("LibPecker output:");
                        for (String line : outputLines) {
                            Logger.debug("  %s", line);
                        }
                    }
                }
            } else {
                Logger.error("LibPecker output file not found or empty: %s", outputFile);
            }
        } catch (Exception e) {
            Logger.error("Failed to read LibPecker error output: %s", e.getMessage());
        }
    }
    
    /**
     * 解析LibPecker检测结果
     * LibPecker输出格式：similarity: 0.5920433145009416
     * 版本信息可能包含在库名称中，或者需要从其他输出中提取
     */
    private DetectionResult parseLibPeckerResult(String outputDir, String apkPath, DetectionResult result) {
        try {
            String outputFile = outputDir + "/libpecker_result.txt";
            File file = new File(outputFile);
            
            if (!file.exists()) {
                Logger.error("LibPecker result file not found: %s", outputFile);
                result.setDetected(false);
                result.setConfidence(0.0);
                result.setMessage("Result file not found");
                return result;
            }
            
            // 读取并打印原始检测结果
            List<String> lines = Files.readAllLines(Paths.get(outputFile));
            Logger.debug("=== LibPecker原始检测结果 (libpecker_result.txt) ===");
            Logger.debug("文件路径: %s", file.getAbsolutePath());
            Logger.debug("文件行数: %d", lines.size());
            Logger.debug("原始内容:");
            for (int i = 0; i < lines.size(); i++) {
                Logger.debug("  [%d] %s", i + 1, lines.get(i));
            }
            Logger.debug("=== LibPecker原始检测结果结束 ===");
            
            boolean detected = false;
            double confidence = 0.0;
            
            // 解析输出，查找similarity行
            Pattern similarityPattern = Pattern.compile("similarity:\\s*([0-9.]+)");
            
            for (String line : lines) {
                Matcher matcher = similarityPattern.matcher(line);
                if (matcher.find()) {
                    try {
                        confidence = Double.parseDouble(matcher.group(1));
                        // LibPecker的相似度阈值：通常0.5以上认为检测到
                        detected = confidence >= 0.5;
                        Logger.debug("LibPecker similarity: %.6f, detected: %s", confidence, detected);
                    } catch (NumberFormatException e) {
                        Logger.error("Failed to parse similarity score: %s", matcher.group(1));
                    }
                }
                
                // 尝试从输出中提取版本信息（如果LibPecker输出了版本信息）
                // 版本信息可能在库名称中，或者在其他输出行中
                // 这里先尝试从TPL名称中提取版本信息
            }
            
            // 如果检测到了，尝试从TPL名称中提取版本信息
            if (detected) {
                String tplName = result.getTplName();
                if (tplName != null && !tplName.isEmpty()) {
                    extractVersionFromTPLName(tplName, result);
                }
            }
            
            result.setDetected(detected);
            result.setConfidence(confidence);
            result.setMessage("LibPecker detection completed");
            
            Logger.debug("LibPecker detection result: detected=%s, confidence=%.6f, versions=%s", 
                detected, confidence, result.getDetectedVersions());
            
        } catch (Exception e) {
            Logger.error("Failed to parse LibPecker result: %s", e.getMessage());
            e.printStackTrace();
            result.setDetected(false);
            result.setConfidence(0.0);
            result.setMessage("Failed to parse result: " + e.getMessage());
        }
        
        return result;
    }
    
    /**
     * 从TPL名称中提取版本信息
     * 支持格式：库名-版本、库名_版本、库名.版本
     * 版本格式：数字.数字.数字 或 数字.数字 或 v数字.数字.数字
     * 例如：com.android.support.support-v4.22.2.1 -> 22.2.1
     */
    private void extractVersionFromTPLName(String tplName, DetectionResult result) {
        if (tplName == null || tplName.isEmpty()) {
            return;
        }
        
        // 先移除文件扩展名（.dex, .jar, .aar等）
        String tplNameWithoutExt = tplName;
        int lastDot = tplName.lastIndexOf('.');
        if (lastDot > 0) {
            String ext = tplName.substring(lastDot + 1).toLowerCase();
            // 如果是常见的文件扩展名，移除它
            if (ext.equals("dex") || ext.equals("jar") || ext.equals("aar") || ext.equals("zip")) {
                tplNameWithoutExt = tplName.substring(0, lastDot);
            }
        }
        
        Logger.debug("Extracting version from TPL name '%s' (without ext: '%s')", tplName, tplNameWithoutExt);
        
        // 尝试匹配版本号模式：数字.数字.数字 或 数字.数字
        // 支持分隔符：-、_、.
        // 注意：需要按从复杂到简单的顺序匹配，避免误匹配
        String[] patterns = {
            // 模式1: 处理类似 "support-v4.22.2.1" 的情况，提取 "22.2.1"
            // 匹配格式：库名-v数字.版本号 或 库名-数字.版本号
            ".*[-_]v\\d+\\.(\\d+\\.\\d+(?:\\.\\d+)*(?:[-_.]?\\w+)?)$",  // support-v4.22.2.1 -> 22.2.1
            ".*[-_](\\d+\\.\\d+(?:\\.\\d+)+(?:[-_.]?\\w+)?)$",          // library-22.2.1 -> 22.2.1（三个或更多数字段）
            ".*\\.(\\d+\\.\\d+(?:\\.\\d+)+(?:[-_.]?\\w+)?)$",           // library.22.2.1 -> 22.2.1（三个或更多数字段）
            // 模式2: 标准版本号格式（两个或三个数字段）
            ".*[-_](\\d+\\.\\d+(?:\\.\\d+)?(?:[-_]?\\w+)?)$",           // 库名-2.8.6 或 库名_2.8.6
            ".*\\.(\\d+\\.\\d+(?:\\.\\d+)?(?:[-_]?\\w+)?)$",            // 库名.2.8.6（但需要确保不是文件扩展名）
            ".*[-_]v(\\d+\\.\\d+(?:\\.\\d+)?(?:[-_]?\\w+)?)$",          // 库名-v2.8.6
            // 模式3: 简单版本号（单个数字）
            ".*[-_](\\d+)$"                                              // 库名-2（简单版本号）
        };
        
        for (String pattern : patterns) {
            Pattern p = Pattern.compile(pattern);
            Matcher m = p.matcher(tplNameWithoutExt);
            if (m.find()) {
                String version = m.group(1);
                if (version != null && !version.isEmpty()) {
                    result.addDetectedVersion(version);
                    Logger.debug("Extracted version '%s' from TPL name '%s' using pattern '%s'", 
                        version, tplName, pattern);
                    return;
                }
            }
        }
        
        Logger.debug("Could not extract version from TPL name '%s'", tplName);
    }
    
    /**
     * 提取TPL名称
     */
    private String extractTPLName(String tplPath) {
        String fileName = new File(tplPath).getName();
        int lastDot = fileName.lastIndexOf('.');
        return lastDot > 0 ? fileName.substring(0, lastDot) : fileName;
    }
    
    /**
     * 清理临时目录
     */
    private void cleanupTempDir(String tempDir) {
        try {
            // 延迟删除，给LibPecker一些时间完成
            Thread.sleep(1000);
            deleteDirectory(new File(tempDir));
        } catch (Exception e) {
            Logger.error("Failed to cleanup temp directory: " + e.getMessage());
        }
    }
    
    /**
     * 递归删除目录
     */
    private void deleteDirectory(File directory) {
        if (directory.exists()) {
            File[] files = directory.listFiles();
            if (files != null) {
                for (File file : files) {
                    if (file.isDirectory()) {
                        deleteDirectory(file);
                    } else {
                        file.delete();
                    }
                }
            }
            directory.delete();
        }
    }
}
