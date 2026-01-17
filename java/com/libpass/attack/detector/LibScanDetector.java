package com.libpass.attack.detector;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.TimeUnit;

import com.libpass.attack.util.Logger;
/**
 * LibScan检测工具适配器
 */
public class LibScanDetector implements TPLDetector {
    private static final String NAME = "LibScan";
    private String libScanPath;
    private String libScanToolDir;
    private String tempOutputDir;
    private Map<String, Object> config;
    
    public LibScanDetector() {
        this.config = new HashMap<>();
    }
    
    @Override
    public String getName() {
        return NAME;
    }
    
    @Override
    public void initialize(Map<String, Object> config) {
        this.config = config;
        String libScanPathConfig = (String) config.getOrDefault("libscan_path", 
            "TPL_Detectors/LibScan/tool/LibScan.py");
        String libScanToolDirConfig = (String) config.getOrDefault("libscan_tool_dir",
            "TPL_Detectors/LibScan/tool");
        
        // 转换为绝对路径
        File libScanPathFile = new File(libScanPathConfig);
        if (!libScanPathFile.isAbsolute()) {
            // 尝试从当前工作目录或类路径解析
            String currentDir = System.getProperty("user.dir");
            File absPath = new File(currentDir, libScanPathConfig);
            if (absPath.exists()) {
                this.libScanPath = absPath.getAbsolutePath();
            } else {
                // 尝试从类路径解析（假设在src目录下运行）
                File srcPath = new File(currentDir, libScanPathConfig);
                if (srcPath.exists()) {
                    this.libScanPath = srcPath.getAbsolutePath();
                } else {
                    this.libScanPath = libScanPathConfig; // 保持原路径
                }
            }
        } else {
            this.libScanPath = libScanPathConfig;
        }
        
        File libScanToolDirFile = new File(libScanToolDirConfig);
        if (!libScanToolDirFile.isAbsolute()) {
            String currentDir = System.getProperty("user.dir");
            File absPath = new File(currentDir, libScanToolDirConfig);
            if (absPath.exists()) {
                this.libScanToolDir = absPath.getAbsolutePath();
            } else {
                this.libScanToolDir = libScanToolDirConfig;
            }
        } else {
            this.libScanToolDir = libScanToolDirConfig;
        }
        
        this.tempOutputDir = (String) config.getOrDefault("temp_output_dir",
            System.getProperty("java.io.tmpdir") + "/libscan_output");
        
        // 创建临时输出目录
        new File(tempOutputDir).mkdirs();
        
        // 验证路径
        File libScanFile = new File(this.libScanPath);
        if (!libScanFile.exists()) {
            Logger.warning("LibScan.py not found at: %s", this.libScanPath);
            Logger.error("Current working directory: %s", System.getProperty("user.dir"));
        } else {
            Logger.debug("LibScan path resolved to: %s", this.libScanPath);
        }
        
        File toolDirFile = new File(this.libScanToolDir);
        if (!toolDirFile.exists()) {
            Logger.warning("LibScan tool directory not found at: %s", this.libScanToolDir);
        } else {
            Logger.debug("LibScan tool directory: %s", this.libScanToolDir);
        }
    }
    
    @Override
    public boolean isAvailable() {
        if (libScanPath == null) {
            return false;
        }
        File libScanFile = new File(libScanPath);
        boolean exists = libScanFile.exists();
        boolean readable = libScanFile.canRead();
        
        if (!exists) {
            Logger.error("LibScan.py not found at: %s", libScanPath);
        } else if (!readable) {
            Logger.error("LibScan.py is not readable: %s", libScanPath);
        }
        
        return exists && readable;
    }
    
    @Override
    public DetectionResult detectTPL(String apkPath, String tplPath, String tplName) {
        DetectionResult result = new DetectionResult();
        result.setApkPath(apkPath);
        result.setTplName(tplName != null ? tplName : extractTPLName(tplPath));
        
        try {
            // 创建临时目录用于LibScan检测
            // 使用UUID确保唯一性，避免多线程环境下目录冲突
            String uniqueId = UUID.randomUUID().toString().replace("-", "");
            String tempDir = tempOutputDir + "/" + System.currentTimeMillis() + "_" + uniqueId;
            new File(tempDir).mkdirs();
            
            // 准备TPL DEX文件
            String tplDexPath = prepareTPLForDetection(tplPath, tempDir);
            if (tplDexPath == null) {
                result.setDetected(false);
                result.setMessage("Failed to prepare TPL for detection");
                return result;
            }
            
            // 创建APK目录
            String apkDir = tempDir + "/apks";
            new File(apkDir).mkdirs();
            
            // 复制APK到临时目录
            String tempApkPath = apkDir + "/" + new File(apkPath).getName();
            Files.copy(Paths.get(apkPath), Paths.get(tempApkPath), 
                StandardCopyOption.REPLACE_EXISTING);
            
            // 创建输出目录
            String outputDir = tempDir + "/outputs";
            new File(outputDir).mkdirs();
            
            // 调用LibScan检测
            Logger.debug("Running LibScan detection...");
            Logger.debug("  TPL DEX: %s", tplDexPath);
            Logger.debug("  APK Dir: %s", apkDir);
            Logger.debug("  Output Dir: %s", outputDir);
            
            boolean success = runLibScanDetection(tplDexPath, apkDir, outputDir);
            
            if (success) {
                // 解析检测结果
                Logger.debug("LibScan detection completed, parsing results...");
                result = parseLibScanResult(outputDir, tempApkPath, result);
                // 输出检测结果（DEBUG级别）
                Logger.debug("LibScan result: detected=%s, confidence=%.6f", 
                    result.isDetected(), result.getConfidence());
            } else {
                Logger.error("LibScan detection process failed");
                result.setDetected(false);
                result.setMessage("LibScan detection failed");
                
                // 即使进程失败，也尝试解析结果（可能部分成功）
                Logger.debug("Attempting to parse results despite process failure...");
                result = parseLibScanResult(outputDir, tempApkPath, result);
                // 即使失败也输出结果（DEBUG级别）
                Logger.debug("LibScan result: detected=%s, confidence=%.6f", 
                    result.isDetected(), result.getConfidence());
            }
            
            // 清理临时文件
            cleanupTempDir(tempDir);
            
        } catch (Exception e) {
            result.setDetected(false);
            result.setMessage("Error during detection: " + e.getMessage());
            e.printStackTrace();
        }
        
        return result;
    }
    
    @Override
    public Map<String, DetectionResult> detectTPLBatch(List<String> apkPaths, 
                                                       String tplPath, String tplName) {
        Map<String, DetectionResult> results = new HashMap<>();
        
        for (String apkPath : apkPaths) {
            DetectionResult result = detectTPL(apkPath, tplPath, tplName);
            results.put(apkPath, result);
        }
        
        return results;
    }
    
    /**
     * 准备TPL用于检测（转换为DEX格式）
     */
    private String prepareTPLForDetection(String tplPath, String tempDir) {
        try {
            File tplFile = new File(tplPath);
            String fileName = tplFile.getName();
            String extension = fileName.substring(fileName.lastIndexOf('.') + 1);
            
            String tplDexPath;
            
            if (extension.equals("dex")) {
                // 已经是DEX格式，直接复制
                String libDexDir = tempDir + "/libs_dex";
                new File(libDexDir).mkdirs();
                tplDexPath = libDexDir + "/" + fileName;
                Files.copy(Paths.get(tplPath), Paths.get(tplDexPath), 
                    StandardCopyOption.REPLACE_EXISTING);
            } else if (extension.equals("jar")) {
                // 首先尝试查找对应的DEX文件（在ground_truth_libs_dex目录中）
                String dexPath = findCorrespondingDexFile(tplPath);
                
                if (dexPath != null && new File(dexPath).exists()) {
                    // 使用已有的DEX文件
                    String libDexDir = tempDir + "/libs_dex";
                    new File(libDexDir).mkdirs();
                    String dexFileName = new File(dexPath).getName();
                    tplDexPath = libDexDir + "/" + dexFileName;
                    Files.copy(Paths.get(dexPath), Paths.get(tplDexPath), 
                        StandardCopyOption.REPLACE_EXISTING);
                    Logger.debug("Using existing DEX file: %s", dexPath);
                } else {
                    // 需要转换为DEX
                    String libDexDir = tempDir + "/libs_dex";
                    new File(libDexDir).mkdirs();
                    String dexFileName = fileName.substring(0, fileName.lastIndexOf('.')) + ".dex";
                    tplDexPath = libDexDir + "/" + dexFileName;
                    
                    // 使用dex2jar工具转换
                    boolean converted = convertJarToDex(tplPath, tplDexPath);
                    if (!converted) {
                        Logger.error("Failed to convert JAR to DEX, and no corresponding DEX file found");
                        return null;
                    }
                }
            } else {
                Logger.error("Unsupported TPL format: %s", extension);
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
     * 查找对应的DEX文件（在ground_truth_libs_dex目录中）
     */
    private String findCorrespondingDexFile(String jarPath) {
        try {
            File jarFile = new File(jarPath);
            String jarName = jarFile.getName();
            String baseName = jarName.substring(0, jarName.lastIndexOf('.'));
            
            // 构建绝对路径
            File toolDirFile = new File(libScanToolDir);
            String absToolDir = toolDirFile.isAbsolute() ? libScanToolDir : toolDirFile.getAbsolutePath();
            
            // 查找可能的DEX文件位置
            String[] possiblePaths = {
                absToolDir + "/../data/ground_truth_libs_dex/" + baseName + ".dex",
                absToolDir + "/data/ground_truth_libs_dex/" + baseName + ".dex",
                absToolDir + "/libs_dex/" + baseName + ".dex",
                jarFile.getParent() + "/../ground_truth_libs_dex/" + baseName + ".dex",
                jarFile.getParent().replace("ground_truth_libs", "ground_truth_libs_dex") + "/" + baseName + ".dex"
            };
            
            for (String path : possiblePaths) {
                File dexFile = new File(path);
                if (dexFile.exists()) {
                    Logger.debug("Found corresponding DEX file: %s", dexFile.getAbsolutePath());
                    return dexFile.getAbsolutePath();
                }
            }
            
            Logger.debug("No corresponding DEX file found for: %s", baseName);
            return null;
        } catch (Exception e) {
            Logger.error("Error finding corresponding DEX file: " + e.getMessage());
            return null;
        }
    }
    
    /**
     * 将JAR转换为DEX
     */
    private boolean convertJarToDex(String jarPath, String dexPath) {
        try {
            // 使用dex2jar工具
            String d2jJar2dex = libScanToolDir + "/module/dex2jar/d2j-jar2dex.sh";
            if (!new File(d2jJar2dex).exists()) {
                d2jJar2dex = libScanToolDir + "/module/dex2jar/d2j-jar2dex.bat";
            }
            
            if (!new File(d2jJar2dex).exists()) {
                Logger.error("dex2jar tool not found at: %s", d2jJar2dex);
                return false;
            }
            
            ProcessBuilder pb = new ProcessBuilder(
                "bash", d2jJar2dex, jarPath, "-o", dexPath
            );
            pb.directory(new File(libScanToolDir));
            pb.redirectErrorStream(true);
            
            Process process = pb.start();
            
            // 读取输出以便调试
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            String line;
            while ((line = reader.readLine()) != null) {
                Logger.info("dex2jar: %s", line);
            }
            
            boolean finished = process.waitFor(60, TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                return false;
            }
            
            boolean success = process.exitValue() == 0 && new File(dexPath).exists();
            if (!success) {
                Logger.error("JAR to DEX conversion failed. Exit code: " + process.exitValue());
            }
            return success;
            
        } catch (Exception e) {
            Logger.error("Failed to convert JAR to DEX: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }
    
    /**
     * 运行LibScan检测
     */
    private boolean runLibScanDetection(String tplDexPath, String apkDir, String outputDir) {
        try {
            // 构建LibScan命令
            String libDexDir = new File(tplDexPath).getParent();
            String libName = new File(tplDexPath).getName();
            
            // 创建只包含目标TPL的目录（使用绝对路径）
            File singleLibDexDirFile = new File(outputDir, "single_lib_dex");
            String singleLibDexDir = singleLibDexDirFile.getAbsolutePath();
            
            // 确保目录存在
            if (!singleLibDexDirFile.exists()) {
                boolean created = singleLibDexDirFile.mkdirs();
                if (!created) {
                    Logger.error("Failed to create single_lib_dex directory: %s", singleLibDexDir);
                    return false;
                }
            }
            
            // 复制TPL DEX文件
            File tplDexFile = new File(tplDexPath);
            File targetDexFile = new File(singleLibDexDir, libName);
            try {
                Files.copy(tplDexFile.toPath(), targetDexFile.toPath(), 
                    StandardCopyOption.REPLACE_EXISTING);
                Logger.debug("Copied TPL DEX to: %s", targetDexFile.getAbsolutePath());
            } catch (Exception e) {
                Logger.error("Failed to copy TPL DEX file: " + e.getMessage());
                return false;
            }
            
            // 确保使用绝对路径
            File libScanFile = new File(libScanPath);
            String absLibScanPath = libScanFile.isAbsolute() ? libScanPath : 
                new File(libScanToolDir, libScanFile.getName()).getAbsolutePath();
            
            File toolDir = new File(libScanToolDir);
            String absToolDir = toolDir.isAbsolute() ? libScanToolDir : toolDir.getAbsolutePath();
            
            // 确保APK目录和输出目录使用绝对路径
            File apkDirFile = new File(apkDir);
            String absApkDir = apkDirFile.isAbsolute() ? apkDir : apkDirFile.getAbsolutePath();
            
            File outputDirFile = new File(outputDir);
            String absOutputDir = outputDirFile.isAbsolute() ? outputDir : outputDirFile.getAbsolutePath();
            
            // LibScan的module目录包含修改过的androguard，需要优先于系统安装的包
            String moduleDir = absToolDir + "/module";
            File moduleDirFile = new File(moduleDir);
            if (!moduleDirFile.exists()) {
                Logger.warning("LibScan module directory not found: %s", moduleDir);
            }
            
            Logger.debug("Executing LibScan:");
            Logger.debug("  Script: %s", absLibScanPath);
            Logger.debug("  Working dir: %s", absToolDir);
            Logger.debug("  Module dir: %s", moduleDir);
            Logger.debug("  APK Dir: %s", absApkDir);
            Logger.debug("  Lib DEX Dir: %s", singleLibDexDir);
            Logger.debug("  Output Dir: %s", absOutputDir);
            
            ProcessBuilder pb = new ProcessBuilder(
                "python3",
                absLibScanPath,
                "detect_one",
                "-af", absApkDir,
                "-ld", singleLibDexDir,
                "-o", absOutputDir,
                "-p", "1"
            );
            
            pb.directory(new File(absToolDir));
            
            // 设置PYTHONPATH，确保LibScan的module目录优先于系统安装的包
            Map<String, String> env = pb.environment();
            String currentPythonPath = env.get("PYTHONPATH");
            if (currentPythonPath != null && !currentPythonPath.isEmpty()) {
                // 将LibScan的module目录放在最前面
                env.put("PYTHONPATH", moduleDir + File.pathSeparator + currentPythonPath);
            } else {
                // 如果PYTHONPATH不存在，只设置LibScan的module目录
                env.put("PYTHONPATH", moduleDir);
            }
            
            Logger.debug("PYTHONPATH set to: %s", env.get("PYTHONPATH"));
            pb.redirectErrorStream(true);
            
            Process process = pb.start();
            
            // 读取输出
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            String line;
            while ((line = reader.readLine()) != null) {
                Logger.debug("LibScan: %s", line);
            }
            
            boolean finished = process.waitFor(300, TimeUnit.SECONDS); // 5分钟超时
            if (!finished) {
                Logger.error("LibScan process timed out");
                process.destroyForcibly();
                return false;
            }
            
            int exitCode = process.exitValue();
            Logger.debug("LibScan process finished with exit code: %s", exitCode);
            
            // 即使退出码不为0，也尝试解析结果（可能部分成功）
            if (exitCode != 0) {
                Logger.error("LibScan exited with non-zero code: %s", exitCode);
            }
            
            // 检查输出目录是否有结果文件
            File outputDirFileCheck = new File(absOutputDir);
            if (outputDirFileCheck.exists() && outputDirFileCheck.listFiles() != null) {
                Logger.debug("Output directory contains %d files", outputDirFileCheck.listFiles().length);
            }
            
            return true; // 返回true以便尝试解析结果
            
        } catch (Exception e) {
            Logger.error("Failed to run LibScan: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }
    
    /**
     * 解析LibScan检测结果
     */
    private DetectionResult parseLibScanResult(String outputDir, String apkPath, 
                                              DetectionResult result) {
        try {
            String apkName = new File(apkPath).getName();
            String apkBaseName = apkName;
            if (apkName.contains(".")) {
                apkBaseName = apkName.substring(0, apkName.lastIndexOf('.'));
            }
            
            Logger.debug("Parsing LibScan results for APK: %s (base: %s)", apkName, apkBaseName);
            Logger.debug("Output directory: %s", outputDir);
            
            // 首先检查results.txt（detect_one模式的输出）
            String resultsFile = outputDir + "/results.txt";
            File file = new File(resultsFile);
            Logger.debug("Checking results file: %s (exists: %s)", resultsFile, file.exists());
            
            if (file.exists()) {
                // 读取并打印原始检测结果
                List<String> lines = Files.readAllLines(Paths.get(resultsFile));
                Logger.debug("=== LibScan原始检测结果 (results.txt) ===");
                Logger.debug("文件路径: %s", file.getAbsolutePath());
                Logger.debug("文件行数: %d", lines.size());
                Logger.debug("原始内容:");
                for (int i = 0; i < lines.size(); i++) {
                    Logger.debug("  [%d] %s", i + 1, lines.get(i));
                }
                Logger.debug("=== LibScan原始检测结果结束 ===");
                
                // 解析results.txt格式：apk名称     库名称     版本候选（可选）     相似度得分
                // 或者：apk名称     库名称     相似度得分
                // 版本候选可能是多个，用逗号分隔，或者可能包含在库名称中
                
                boolean detected = false;
                double confidence = 0.0;
                
                for (String line : lines) {
                    if (line.trim().isEmpty() || line.startsWith("apk名称") || line.startsWith("apk")) {
                        continue; // 跳过标题行
                    }
                    
                    // 解析格式：apk名称     库名称     版本候选（可选）     相似度得分（用多个空格分隔）
                    // 使用正则表达式分割多个空格
                    String[] parts = line.trim().split("\\s{2,}"); // 至少2个空格
                    if (parts.length < 3) {
                        // 如果分割失败，尝试单个空格分割
                        parts = line.trim().split("\\s+");
                    }
                    
                    if (parts.length >= 3) {
                        String resultApkName = parts[0].trim();
                        String libName = parts[1].trim();
                        String scoreStr;
                        String versionStr = null;
                        
                        // 判断是否有版本信息字段
                        // 如果parts.length >= 4，说明有版本信息字段
                        if (parts.length >= 4) {
                            // 格式：apk名称     库名称     版本候选     相似度得分
                            versionStr = parts[2].trim();
                            scoreStr = parts[3].trim();
                        } else {
                            // 格式：apk名称     库名称     相似度得分
                            scoreStr = parts[2].trim();
                        }
                        
                        // 检查是否是当前APK的结果（更宽松的匹配）
                        String apkNameOnly = apkBaseName;
                        String resultApkNameOnly = resultApkName;
                        // 移除可能的路径前缀
                        if (resultApkNameOnly.contains("/")) {
                            resultApkNameOnly = resultApkNameOnly.substring(resultApkNameOnly.lastIndexOf('/') + 1);
                        }
                        if (resultApkNameOnly.contains(".")) {
                            resultApkNameOnly = resultApkNameOnly.substring(0, resultApkNameOnly.lastIndexOf('.'));
                        }
                        if (apkNameOnly.contains(".")) {
                            apkNameOnly = apkNameOnly.substring(0, apkNameOnly.lastIndexOf('.'));
                        }
                        
                        // 检查APK名称匹配
                        boolean apkMatches = resultApkNameOnly.equals(apkNameOnly) ||
                                           resultApkNameOnly.contains(apkNameOnly) ||
                                           apkNameOnly.contains(resultApkNameOnly) ||
                                           resultApkName.contains(apkBaseName) ||
                                           apkBaseName.contains(resultApkName);
                        
                        if (apkMatches) {
                            try {
                                confidence = Double.parseDouble(scoreStr);
                                // LibScan的相似度阈值：通常0.5以上认为检测到
                                // 但为了更准确，我们降低阈值到0.3，因为有些TPL可能相似度较低但仍被集成
                                detected = confidence >= 0.3;
                                
                                // 解析版本信息（如果存在）
                                // LibScan支持版本级检测，版本信息可能在单独字段中，也可能在库名称中
                                if (versionStr != null && !versionStr.isEmpty()) {
                                    // 版本候选可能是多个，用逗号分隔
                                    String[] versions = versionStr.split(",");
                                    for (String version : versions) {
                                        String v = version.trim();
                                        if (!v.isEmpty()) {
                                            result.addDetectedVersion(v);
                                        }
                                    }
                                    Logger.debug("LibScan detection result: APK=%s, TPL=%s, versions=%s, confidence=%.6f, detected=%s", 
                                        resultApkName, libName, versionStr, confidence, detected);
                                } else {
                                    // 尝试从库名称中提取版本信息（如果库名称包含版本号）
                                    // LibScan输出的库名称可能包含版本信息，例如：库名-2.8.6 或 库名_2.8.6
                                    extractVersionFromLibName(libName, result);
                                    List<String> extractedVersions = result.getDetectedVersions();
                                    if (extractedVersions != null && !extractedVersions.isEmpty()) {
                                        Logger.debug("LibScan detection result: APK=%s, TPL=%s, extracted versions=%s, confidence=%.6f, detected=%s", 
                                            resultApkName, libName, extractedVersions, confidence, detected);
                                    } else {
                                        Logger.debug("LibScan detection result: APK=%s, TPL=%s, no version info, confidence=%.6f, detected=%s", 
                                            resultApkName, libName, confidence, detected);
                                    }
                                }
                                break;
                            } catch (NumberFormatException e) {
                                Logger.error("Failed to parse confidence score: %s", scoreStr);
                                // 继续解析
                            }
                        }
                    }
                }
                
                result.setDetected(detected);
                result.setConfidence(confidence);
                result.setMessage("LibScan detection completed");
                
            } else {
                // 检查单个APK的结果文件
                String resultFile = outputDir + "/" + apkBaseName + ".txt";
                file = new File(resultFile);
                
                if (file.exists()) {
                    List<String> lines = Files.readAllLines(Paths.get(resultFile));
                    
                    boolean detected = false;
                    double confidence = 0.0;
                    
                    // 解析单个APK结果文件
                    for (String line : lines) {
                        // 查找相似度信息
                        if (line.contains("similarity:")) {
                            String[] parts = line.split(":");
                            if (parts.length >= 2) {
                                try {
                                    confidence = Double.parseDouble(parts[1].trim());
                                    detected = confidence >= 0.5; // 阈值
                                } catch (NumberFormatException e) {
                                    // 继续
                                }
                            }
                        }
                    }
                    
                    result.setDetected(detected);
                    result.setConfidence(confidence);
                    result.setMessage("LibScan detection completed");
                    
                } else {
                    // 没有找到结果文件，检查是否有其他格式的结果文件
                    // LibScan可能生成其他格式的结果文件
                    File outputDirFile = new File(outputDir);
                    File[] files = outputDirFile.listFiles();
                    if (files != null) {
                        for (File f : files) {
                            if (f.getName().endsWith(".txt") && f.getName().contains(apkBaseName)) {
                                Logger.debug("Found alternative result file: %s", f.getName());
                                // 尝试解析这个文件
                                List<String> altLines = Files.readAllLines(Paths.get(f.getAbsolutePath()));
                                for (String altLine : altLines) {
                                    // 查找任何数字（可能是相似度）
                                    if (altLine.matches(".*\\d+\\.\\d+.*")) {
                                        String[] numbers = altLine.split("\\D+");
                                        for (String num : numbers) {
                                            if (!num.isEmpty()) {
                                                try {
                                                    double altConfidence = Double.parseDouble(num);
                                                    if (altConfidence > 0) {
                                                        result.setDetected(altConfidence >= 0.3);
                                                        result.setConfidence(altConfidence);
                                                        result.setMessage("Found in alternative result file");
                                                        return result;
                                                    }
                                                } catch (NumberFormatException e) {
                                                    // 继续
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    
                    // 没有找到结果文件，认为未检测到
                    result.setDetected(false);
                    result.setConfidence(0.0);
                    result.setMessage("No result file found - TPL not detected. Checked: " + resultsFile + " and " + resultFile);
                }
            }
            
        } catch (Exception e) {
            result.setDetected(false);
            result.setMessage("Failed to parse result: " + e.getMessage());
            e.printStackTrace();
        }
        
        return result;
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
     * 从库名称中提取版本信息
     * 支持格式：库名-版本、库名_版本、库名.版本
     * 版本格式：数字.数字.数字 或 数字.数字 或 v数字.数字.数字
     * 例如：com.android.support.support-v4.22.2.1.dex -> 22.2.1
     */
    private void extractVersionFromLibName(String libName, DetectionResult result) {
        if (libName == null || libName.isEmpty()) {
            return;
        }
        
        // 先移除文件扩展名（.dex, .jar, .aar等）
        String libNameWithoutExt = libName;
        int lastDot = libName.lastIndexOf('.');
        if (lastDot > 0) {
            String ext = libName.substring(lastDot + 1).toLowerCase();
            // 如果是常见的文件扩展名，移除它
            if (ext.equals("dex") || ext.equals("jar") || ext.equals("aar") || ext.equals("zip")) {
                libNameWithoutExt = libName.substring(0, lastDot);
            }
        }
        
        Logger.debug("Extracting version from lib name '%s' (without ext: '%s')", libName, libNameWithoutExt);
        
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
            java.util.regex.Pattern p = java.util.regex.Pattern.compile(pattern);
            java.util.regex.Matcher m = p.matcher(libNameWithoutExt);
            if (m.find()) {
                String version = m.group(1);
                if (version != null && !version.isEmpty()) {
                    result.addDetectedVersion(version);
                    Logger.debug("Extracted version '%s' from lib name '%s' using pattern '%s'", 
                        version, libName, pattern);
                    return;
                }
            }
        }
        
        Logger.debug("Could not extract version from lib name '%s'", libName);
    }
    
    /**
     * 清理临时目录
     */
    private void cleanupTempDir(String tempDir) {
        try {
            // 延迟删除，给LibScan一些时间完成
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
