package com.libpass.attack.detector;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import com.google.gson.JsonObject;
import com.google.gson.JsonArray;
import com.google.gson.JsonParser;
import com.google.gson.JsonElement;

import com.libpass.attack.util.Logger;

/**
 * LIBLOOM检测工具适配器
 * LIBLOOM使用两步流程：profile -> detect
 */
public class LibLoomDetector implements TPLDetector {
    private static final String NAME = "LibLoom";
    private String libloomJarPath;
    private String libloomConfigDir;
    private String tempOutputDir;
    private Map<String, Object> config;
    
    public LibLoomDetector() {
        this.config = new HashMap<>();
    }
    
    @Override
    public String getName() {
        return NAME;
    }
    
    @Override
    public void initialize(Map<String, Object> config) {
        this.config = config;
        String libloomJarPathConfig = (String) config.getOrDefault("libloom_jar_path", 
            "TPL_Detectors/LIBLOOM/artifacts/LIBLOOM.jar");
        String libloomConfigDirConfig = (String) config.getOrDefault("libloom_config_dir",
            "TPL_Detectors/LIBLOOM/artifacts/config");
        
        // 转换为绝对路径
        File libloomJarFile = new File(libloomJarPathConfig);
        if (!libloomJarFile.isAbsolute()) {
            String currentDir = System.getProperty("user.dir");
            File absPath = new File(currentDir, libloomJarPathConfig);
            if (absPath.exists()) {
                this.libloomJarPath = absPath.getAbsolutePath();
            } else {
                this.libloomJarPath = libloomJarPathConfig;
            }
        } else {
            this.libloomJarPath = libloomJarPathConfig;
        }
        
        File libloomConfigDirFile = new File(libloomConfigDirConfig);
        if (!libloomConfigDirFile.isAbsolute()) {
            String currentDir = System.getProperty("user.dir");
            File absPath = new File(currentDir, libloomConfigDirConfig);
            if (absPath.exists()) {
                this.libloomConfigDir = absPath.getAbsolutePath();
            } else {
                this.libloomConfigDir = libloomConfigDirConfig;
            }
        } else {
            this.libloomConfigDir = libloomConfigDirConfig;
        }
        
        this.tempOutputDir = (String) config.getOrDefault("temp_output_dir",
            System.getProperty("java.io.tmpdir") + "/libloom_output");
        
        // 创建临时输出目录
        new File(tempOutputDir).mkdirs();
        
        // 验证路径
        File libloomJarFileCheck = new File(this.libloomJarPath);
        if (!libloomJarFileCheck.exists()) {
            Logger.warning("LIBLOOM.jar not found at: %s", this.libloomJarPath);
        } else {
            Logger.debug("LibLoom JAR path resolved to: %s", this.libloomJarPath);
        }
        
        File configDirFile = new File(this.libloomConfigDir);
        if (!configDirFile.exists()) {
            Logger.warning("LibLoom config directory not found at: %s", this.libloomConfigDir);
        } else {
            Logger.debug("LibLoom config directory: %s", this.libloomConfigDir);
        }
    }
    
    @Override
    public boolean isAvailable() {
        if (libloomJarPath == null) {
            return false;
        }
        File libloomJarFile = new File(libloomJarPath);
        boolean exists = libloomJarFile.exists();
        boolean readable = libloomJarFile.canRead();
        
        if (!exists) {
            Logger.error("LIBLOOM.jar not found at: %s", libloomJarPath);
        } else if (!readable) {
            Logger.error("LIBLOOM.jar is not readable: %s", libloomJarPath);
        }
        
        return exists && readable;
    }
    
    @Override
    public DetectionResult detectTPL(String apkPath, String tplPath, String tplName) {
        DetectionResult result = new DetectionResult();
        result.setApkPath(apkPath);
        result.setTplName(tplName != null ? tplName : extractTPLName(tplPath));
        
        try {
            // 创建临时目录用于LIBLOOM检测
            // 使用UUID确保唯一性，避免多线程环境下目录冲突
            String uniqueId = UUID.randomUUID().toString().replace("-", "");
            String tempDir = tempOutputDir + "/" + System.currentTimeMillis() + "_" + uniqueId;
            new File(tempDir).mkdirs();
            
            // 创建目录结构
            String apkDir = tempDir + "/apks";
            String libDir = tempDir + "/libs";
            String profileDir = tempDir + "/profiles";
            String appProfileDir = profileDir + "/apps";
            String libProfileDir = profileDir + "/libs";
            String resultDir = tempDir + "/results";
            
            new File(apkDir).mkdirs();
            new File(libDir).mkdirs();
            new File(appProfileDir).mkdirs();
            new File(libProfileDir).mkdirs();
            new File(resultDir).mkdirs();
            
            // 准备APK和TPL文件
            String tempApkPath = apkDir + "/" + new File(apkPath).getName();
            Files.copy(Paths.get(apkPath), Paths.get(tempApkPath), 
                StandardCopyOption.REPLACE_EXISTING);
            
            // 准备TPL文件（JAR格式）
            String tempTplPath = prepareTPLForDetection(tplPath, libDir);
            if (tempTplPath == null) {
                result.setDetected(false);
                result.setMessage("Failed to prepare TPL for detection");
                return result;
            }
            
            // 验证文件已复制
            File tempTplFile = new File(tempTplPath);
            if (!tempTplFile.exists()) {
                Logger.error("TPL file was not copied to: %s", tempTplPath);
                result.setDetected(false);
                result.setMessage("TPL file not found after preparation");
                return result;
            }
            Logger.debug("TPL file prepared: %s (size: %d bytes)", tempTplPath, tempTplFile.length());
            
            // 验证APK目录中有文件
            File apkDirFile = new File(apkDir);
            File[] apkFiles = apkDirFile.listFiles();
            if (apkFiles == null || apkFiles.length == 0) {
                Logger.error("APK directory is empty: %s", apkDir);
                result.setDetected(false);
                result.setMessage("APK directory is empty");
                return result;
            }
            Logger.debug("APK directory contains %d file(s)", apkFiles.length);
            
            // 验证TPL目录中有文件
            File libDirFile = new File(libDir);
            File[] libFiles = libDirFile.listFiles();
            if (libFiles == null || libFiles.length == 0) {
                Logger.error("TPL directory is empty: %s", libDir);
                result.setDetected(false);
                result.setMessage("TPL directory is empty");
                return result;
            }
            Logger.debug("TPL directory contains %d file(s)", libFiles.length);
            
            // Step 1: 生成profile
            Logger.debug("Running LibLoom profile...");
            Logger.debug("  APK Dir: %s", apkDir);
            Logger.debug("  Lib Dir: %s", libDir);
            
            boolean profileSuccess = runLibLoomProfile(apkDir, appProfileDir);
            if (!profileSuccess) {
                Logger.error("LibLoom profile step failed for APK: %s", apkDir);
                result.setDetected(false);
                result.setMessage("LibLoom profile failed for APK");
                cleanupTempDir(tempDir);
                return result;
            }
            
            // 检查APK profile是否生成
            File appProfileDirFile = new File(appProfileDir);
            File[] appProfileFiles = appProfileDirFile.listFiles();
            if (appProfileFiles == null || appProfileFiles.length == 0) {
                Logger.error("LibLoom profile step for APK generated no profile files in: %s", appProfileDir);
                result.setDetected(false);
                result.setMessage("LibLoom profile generated no files for APK");
                cleanupTempDir(tempDir);
                return result;
            }
            Logger.debug("Generated %d profile file(s) for APK", appProfileFiles.length);
            
            profileSuccess = runLibLoomProfile(libDir, libProfileDir);
            if (!profileSuccess) {
                Logger.error("LibLoom profile step failed for TPL: %s", libDir);
                result.setDetected(false);
                result.setMessage("LibLoom profile failed for TPL");
                cleanupTempDir(tempDir);
                return result;
            }
            
            // 检查TPL profile是否生成
            File libProfileDirFile = new File(libProfileDir);
            File[] libProfileFiles = libProfileDirFile.listFiles();
            if (libProfileFiles == null || libProfileFiles.length == 0) {
                Logger.error("LibLoom profile step for TPL generated no profile files in: %s", libProfileDir);
                result.setDetected(false);
                result.setMessage("LibLoom profile generated no files for TPL");
                cleanupTempDir(tempDir);
                return result;
            }
            Logger.debug("Generated %d profile file(s) for TPL", libProfileFiles.length);
            
            // Step 2: 执行检测
            Logger.debug("Running LibLoom detection...");
            Logger.debug("  App Profile Dir: %s", appProfileDir);
            Logger.debug("  Lib Profile Dir: %s", libProfileDir);
            Logger.debug("  Result Dir: %s", resultDir);
            
            boolean detectSuccess = runLibLoomDetection(appProfileDir, libProfileDir, resultDir);
            
            if (detectSuccess) {
                // 解析检测结果
                Logger.debug("LibLoom detection completed, parsing results...");
                result = parseLibLoomResult(resultDir, tempApkPath, result);
                // 输出检测结果（DEBUG级别）
                Logger.debug("LibLoom result: detected=%s, confidence=%.6f", 
                    result.isDetected(), result.getConfidence());
            } else {
                Logger.error("LibLoom detection process failed");
                result.setDetected(false);
                result.setMessage("LibLoom detection failed");
                
                // 即使进程失败，也尝试解析结果（可能部分成功）
                Logger.debug("Attempting to parse results despite process failure...");
                result = parseLibLoomResult(resultDir, tempApkPath, result);
                // 即使失败也输出结果（DEBUG级别）
                Logger.debug("LibLoom result: detected=%s, confidence=%.6f", 
                    result.isDetected(), result.getConfidence());
            }
            
            // 清理临时文件
            cleanupTempDir(tempDir);
            
        } catch (Exception e) {
            result.setDetected(false);
            result.setMessage("Error during detection: " + e.getMessage());
            Logger.error("Error during LibLoom detection: %s", e.getMessage(), e);
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
     * 运行LIBLOOM profile命令
     */
    private boolean runLibLoomProfile(String inputDir, String outputDir) {
        try {
            // 验证输入目录存在且包含文件
            File inputDirFile = new File(inputDir);
            if (!inputDirFile.exists() || !inputDirFile.isDirectory()) {
                Logger.error("Input directory does not exist or is not a directory: %s", inputDir);
                return false;
            }
            
            File[] inputFiles = inputDirFile.listFiles();
            if (inputFiles == null || inputFiles.length == 0) {
                Logger.error("Input directory is empty: %s", inputDir);
                return false;
            }
            
            Logger.debug("Input directory contains %d file(s):", inputFiles.length);
            for (File f : inputFiles) {
                Logger.debug("  - %s (size: %d bytes)", f.getName(), f.length());
            }
            
            File absLibloomJar = new File(libloomJarPath);
            String absLibloomJarPath = absLibloomJar.getAbsolutePath();
            
            Logger.debug("Executing LibLoom profile:");
            Logger.debug("  JAR: %s", absLibloomJarPath);
            Logger.debug("  Input Dir: %s", inputDir);
            Logger.debug("  Output Dir: %s", outputDir);
            
            // 获取Java可执行文件路径
            String javaHome = System.getProperty("java.home");
            String javaExec = javaHome + File.separator + "bin" + File.separator + "java";
            if (System.getProperty("os.name").toLowerCase().startsWith("win")) {
                javaExec += ".exe";
            }
            
            // 转换为绝对路径（LIBLOOM可能需要绝对路径）
            File inputDirFileAbs = new File(inputDir);
            String absInputDir = inputDirFileAbs.getAbsolutePath();
            File outputDirFileAbs = new File(outputDir);
            String absOutputDir = outputDirFileAbs.getAbsolutePath();
            
            Logger.debug("Using absolute paths:");
            Logger.debug("  Input Dir (abs): %s", absInputDir);
            Logger.debug("  Output Dir (abs): %s", absOutputDir);
            
            ProcessBuilder pb = new ProcessBuilder(
                javaExec,
                "-jar",
                absLibloomJarPath,
                "profile",
                "-d", absInputDir,
                "-o", absOutputDir
            );
            
            // 设置工作目录为配置文件目录（LIBLOOM需要访问配置文件）
            // LIBLOOM会从当前工作目录查找config目录
            File configParentDir = new File(libloomConfigDir).getParentFile();
            pb.directory(configParentDir);
            Logger.debug("Working directory set to: %s", configParentDir.getAbsolutePath());
            
            pb.redirectErrorStream(true);
            
            Process process = pb.start();
            
            // 读取输出（DEBUG级别）
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            String line;
            while ((line = reader.readLine()) != null) {
                Logger.debug("LibLoom: %s", line);
            }
            
            boolean finished = process.waitFor(300, TimeUnit.SECONDS); // 5分钟超时
            if (!finished) {
                Logger.error("LibLoom profile process timed out");
                process.destroyForcibly();
                return false;
            }
            
            int exitCode = process.exitValue();
            Logger.debug("LibLoom profile process finished with exit code: %s", exitCode);
            
            if (exitCode != 0) {
                Logger.error("LibLoom profile exited with non-zero code: %s", exitCode);
                return false;
            }
            
            // 验证输出目录中是否生成了profile文件
            File outputDirFile = new File(outputDir);
            File[] outputFiles = outputDirFile.listFiles();
            if (outputFiles == null || outputFiles.length == 0) {
                Logger.error("LibLoom profile generated no output files in: %s", outputDir);
                return false;
            }
            
            Logger.debug("LibLoom profile generated %d file(s) in output directory", outputFiles.length);
            for (File f : outputFiles) {
                Logger.debug("  - %s (size: %d bytes)", f.getName(), f.length());
            }
            
            return true;
            
        } catch (Exception e) {
            Logger.error("Failed to run LibLoom profile: %s", e.getMessage());
            e.printStackTrace();
            return false;
        }
    }
    
    /**
     * 运行LIBLOOM detect命令
     */
    private boolean runLibLoomDetection(String appProfileDir, String libProfileDir, 
                                       String resultDir) {
        try {
            File absLibloomJar = new File(libloomJarPath);
            String absLibloomJarPath = absLibloomJar.getAbsolutePath();
            
            // 转换为绝对路径（LIBLOOM可能需要绝对路径）
            File appProfileDirFileAbs = new File(appProfileDir);
            String absAppProfileDir = appProfileDirFileAbs.getAbsolutePath();
            File libProfileDirFileAbs = new File(libProfileDir);
            String absLibProfileDir = libProfileDirFileAbs.getAbsolutePath();
            File resultDirFileAbs = new File(resultDir);
            String absResultDir = resultDirFileAbs.getAbsolutePath();
            
            Logger.debug("Executing LibLoom detect:");
            Logger.debug("  JAR: %s", absLibloomJarPath);
            Logger.debug("  App Profile Dir: %s (abs: %s)", appProfileDir, absAppProfileDir);
            Logger.debug("  Lib Profile Dir: %s (abs: %s)", libProfileDir, absLibProfileDir);
            Logger.debug("  Result Dir: %s (abs: %s)", resultDir, absResultDir);
            
            // 获取Java可执行文件路径
            String javaHome = System.getProperty("java.home");
            String javaExec = javaHome + File.separator + "bin" + File.separator + "java";
            if (System.getProperty("os.name").toLowerCase().startsWith("win")) {
                javaExec += ".exe";
            }
            
            ProcessBuilder pb = new ProcessBuilder(
                javaExec,
                "-jar",
                absLibloomJarPath,
                "detect",
                "-ad", absAppProfileDir,
                "-ld", absLibProfileDir,
                "-o", absResultDir
            );
            
            // 设置工作目录为配置文件目录
            File configParentDir = new File(libloomConfigDir).getParentFile();
            pb.directory(configParentDir);
            Logger.debug("Working directory set to: %s", configParentDir.getAbsolutePath());
            
            pb.redirectErrorStream(true);
            
            Process process = pb.start();
            
            // 读取输出（DEBUG级别）
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            String line;
            while ((line = reader.readLine()) != null) {
                Logger.debug("LibLoom: %s", line);
            }
            
            boolean finished = process.waitFor(300, TimeUnit.SECONDS); // 5分钟超时
            if (!finished) {
                Logger.error("LibLoom detect process timed out");
                process.destroyForcibly();
                return false;
            }
            
            int exitCode = process.exitValue();
            Logger.debug("LibLoom detect process finished with exit code: %s", exitCode);
            
            if (exitCode != 0) {
                Logger.error("LibLoom detect exited with non-zero code: %s", exitCode);
                // 即使退出码不为0，也尝试解析结果（可能部分成功）
            }
            
            return true; // 返回true以便尝试解析结果
            
        } catch (Exception e) {
            Logger.error("Failed to run LibLoom detect: %s", e.getMessage());
            e.printStackTrace();
            return false;
        }
    }
    
    /**
     * 解析LIBLOOM检测结果（JSON格式）
     */
    private DetectionResult parseLibLoomResult(String resultDir, String apkPath, 
                                              DetectionResult result) {
        try {
            String apkName = new File(apkPath).getName();
            String apkBaseName = apkName;
            if (apkName.contains(".")) {
                apkBaseName = apkName.substring(0, apkName.lastIndexOf('.'));
            }
            
            Logger.debug("Parsing LibLoom results for APK: %s (base: %s)", apkName, apkBaseName);
            Logger.debug("Result directory: %s", resultDir);
            
            // LIBLOOM输出JSON文件，文件名格式：apk_base_name.json
            String resultJsonFile = resultDir + "/" + apkBaseName + ".json";
            File jsonFile = new File(resultJsonFile);
            
            // 如果找不到精确匹配的文件，尝试查找所有JSON文件
            if (!jsonFile.exists()) {
                File resultDirFile = new File(resultDir);
                File[] jsonFiles = resultDirFile.listFiles((dir, name) -> 
                    name.endsWith(".json"));
                if (jsonFiles != null && jsonFiles.length > 0) {
                    // 使用第一个JSON文件（通常只有一个）
                    jsonFile = jsonFiles[0];
                    Logger.debug("Using alternative JSON file: %s", jsonFile.getName());
                }
            }
            
            if (!jsonFile.exists()) {
                Logger.warning("LibLoom result JSON file not found: %s", resultJsonFile);
                // 列出结果目录中的所有文件，帮助调试
                File resultDirFile = new File(resultDir);
                File[] allFiles = resultDirFile.listFiles();
                if (allFiles != null && allFiles.length > 0) {
                    Logger.debug("Files in result directory:");
                    for (File f : allFiles) {
                        Logger.debug("  - %s (size: %d bytes)", f.getName(), f.length());
                    }
                } else {
                    Logger.warning("Result directory is empty: %s", resultDir);
                }
                result.setDetected(false);
                result.setConfidence(0.0);
                result.setMessage("LibLoom result file not found");
                return result;
            }
            
            Logger.debug("Found LibLoom result JSON file: %s (size: %d bytes)", 
                jsonFile.getName(), jsonFile.length());
            
            // 读取并打印原始检测结果
            String jsonContent = new String(Files.readAllBytes(Paths.get(jsonFile.getAbsolutePath())));
            Logger.debug("=== LibLoom原始检测结果 (JSON) ===");
            Logger.debug("文件路径: %s", jsonFile.getAbsolutePath());
            Logger.debug("文件大小: %d bytes", jsonFile.length());
            Logger.debug("原始内容:");
            // 如果JSON内容太长，分行打印
            if (jsonContent.length() > 10000) {
                // 超长内容只打印前5000个字符
                Logger.debug("  (内容过长，仅显示前5000字符)");
                Logger.debug("  %s...", jsonContent.substring(0, 5000));
            } else {
                // 较短内容完整打印
                String[] jsonLines = jsonContent.split("\n");
                for (int i = 0; i < jsonLines.length; i++) {
                    Logger.debug("  [%d] %s", i + 1, jsonLines[i]);
                }
            }
            Logger.debug("=== LibLoom原始检测结果结束 ===");
            
            JsonParser parser = new JsonParser();
            JsonObject jsonObject;
            try {
                jsonObject = parser.parse(jsonContent).getAsJsonObject();
            } catch (Exception e) {
                Logger.error("Failed to parse JSON: %s", e.getMessage());
                result.setDetected(false);
                result.setConfidence(0.0);
                result.setMessage("Failed to parse JSON: " + e.getMessage());
                return result;
            }
            
            JsonArray libraries = jsonObject.getAsJsonArray("libraries");
            if (libraries == null) {
                Logger.warning("'libraries' field not found in JSON result");
                libraries = new JsonArray();
            }
            
            boolean detected = false;
            double maxConfidence = 0.0;
            double matchedConfidence = 0.0; // 匹配的TPL的相似度
            String targetTplName = result.getTplName();
            
            Logger.debug("Target TPL name: %s", targetTplName);
            
            if (libraries != null && libraries.size() > 0) {
                Logger.debug("Found %d libraries in LibLoom result", libraries.size());
                
                // 遍历所有检测到的库
                for (JsonElement libElement : libraries) {
                    JsonObject lib = libElement.getAsJsonObject();
                    String libName = lib.get("name").getAsString();
                    double similarity = lib.get("similarity").getAsDouble();
                    
                    // 解析版本信息
                    List<String> versions = new ArrayList<>();
                    JsonArray versionArray = lib.getAsJsonArray("version");
                    if (versionArray != null) {
                        for (JsonElement versionElement : versionArray) {
                            versions.add(versionElement.getAsString());
                        }
                    }
                    
                    Logger.debug("  Library: %s, similarity: %.6f, versions: %s", 
                        libName, similarity, versions);
                    
                    // 更新最高相似度
                    if (similarity > maxConfidence) {
                        maxConfidence = similarity;
                    }
                    
                    // 检查是否匹配目标TPL（模糊匹配）
                    if (targetTplName != null && !targetTplName.isEmpty()) {
                        // 多种匹配方式：精确匹配、包含匹配、忽略大小写
                        boolean nameMatches = libName.equalsIgnoreCase(targetTplName) || 
                                             libName.toLowerCase().contains(targetTplName.toLowerCase()) || 
                                             targetTplName.toLowerCase().contains(libName.toLowerCase());
                        
                        // 也尝试匹配文件名（去除版本号后）
                        if (!nameMatches) {
                            // 从libName中提取库名（去除版本号）
                            String libNameOnly = extractLibNameFromLibLoomName(libName);
                            String tplNameOnly = extractLibNameFromLibLoomName(targetTplName);
                            nameMatches = libNameOnly.equalsIgnoreCase(tplNameOnly) ||
                                         libNameOnly.toLowerCase().contains(tplNameOnly.toLowerCase()) ||
                                         tplNameOnly.toLowerCase().contains(libNameOnly.toLowerCase());
                        }
                        
                        if (nameMatches) {
                            Logger.debug("  Matched TPL: %s (similarity: %.6f, versions: %s)", 
                                libName, similarity, versions);
                            if (similarity > matchedConfidence) {
                                matchedConfidence = similarity;
                                detected = true;
                                // 保存检测到的版本信息
                                for (String version : versions) {
                                    result.addDetectedVersion(version);
                                }
                            }
                        }
                    }
                }
                
                // 如果没有指定TPL名称，使用最高相似度（如果>=阈值）
                if (targetTplName == null || targetTplName.isEmpty()) {
                    detected = maxConfidence >= 0.6; // LIBLOOM默认阈值是0.6
                } else {
                    // 如果指定了TPL名称但没有匹配到，不修改detected状态
                    // 只记录调试信息
                    if (!detected) {
                        Logger.debug("TPL name '%s' not matched in LibLoom results. Max similarity: %.6f", 
                            targetTplName, maxConfidence);
                    }
                }
            } else {
                Logger.debug("No libraries found in LibLoom result");
            }
            
            // 使用匹配的相似度（如果有），否则使用最高相似度
            double finalConfidence = matchedConfidence > 0 ? matchedConfidence : maxConfidence;
            
            result.setDetected(detected);
            result.setConfidence(finalConfidence);
            result.setMessage("LibLoom detection completed");
            
            Logger.debug("LibLoom detection result: detected=%s, confidence=%.6f", 
                detected, finalConfidence);
            
        } catch (Exception e) {
            Logger.error("Failed to parse LibLoom result: %s", e.getMessage());
            e.printStackTrace();
            result.setDetected(false);
            result.setConfidence(0.0);
            result.setMessage("Failed to parse result: " + e.getMessage());
        }
        
        return result;
    }
    
    /**
     * 准备TPL用于检测（确保是JAR格式）
     */
    private String prepareTPLForDetection(String tplPath, String libDir) {
        try {
            File tplFile = new File(tplPath);
            String fileName = tplFile.getName();
            String extension = fileName.substring(fileName.lastIndexOf('.') + 1);
            
            String targetTplPath;
            
            if (extension.equals("jar")) {
                // 已经是JAR格式，直接复制
                targetTplPath = libDir + "/" + fileName;
                Files.copy(Paths.get(tplPath), Paths.get(targetTplPath), 
                    StandardCopyOption.REPLACE_EXISTING);
            } else if (extension.equals("dex")) {
                // DEX格式需要转换为JAR（LIBLOOM主要支持JAR/AAR/APK）
                // 简化处理：尝试直接复制，LIBLOOM可能会处理
                String jarFileName = fileName.substring(0, fileName.lastIndexOf('.')) + ".jar";
                targetTplPath = libDir + "/" + jarFileName;
                // 注意：DEX转JAR可能需要dex2jar工具，这里简化处理
                Files.copy(Paths.get(tplPath), Paths.get(targetTplPath), 
                    StandardCopyOption.REPLACE_EXISTING);
                Logger.warning("DEX file copied as JAR for LibLoom (may not work correctly): %s", 
                    fileName);
            } else {
                Logger.error("Unsupported TPL format for LibLoom: %s (only JAR/AAR/APK supported)", 
                    extension);
                return null;
            }
            
            return targetTplPath;
            
        } catch (Exception e) {
            Logger.error("Failed to prepare TPL for LibLoom: %s", e.getMessage());
            e.printStackTrace();
            return null;
        }
    }
    
    /**
     * 从TPL路径提取TPL名称
     */
    private String extractTPLName(String tplPath) {
        String fileName = new File(tplPath).getName();
        // 移除扩展名
        int lastDot = fileName.lastIndexOf('.');
        if (lastDot > 0) {
            fileName = fileName.substring(0, lastDot);
        }
        // LIBLOOM的命名格式：libname-version，提取libname部分
        int dashIndex = fileName.lastIndexOf('-');
        if (dashIndex > 0) {
            return fileName.substring(0, dashIndex);
        }
        return fileName;
    }
    
    /**
     * 从LIBLOOM输出的库名中提取库名（去除版本号）
     * LIBLOOM输出的格式可能是：libname-version 或 libname_version 或 libname.version
     */
    private String extractLibNameFromLibLoomName(String libLoomName) {
        if (libLoomName == null || libLoomName.isEmpty()) {
            return libLoomName;
        }
        
        // 尝试多种分隔符：-、_、.
        String[] separators = {"-", "_", "."};
        for (String sep : separators) {
            int index = libLoomName.lastIndexOf(sep);
            if (index > 0) {
                // 检查后面是否是版本号（数字开头）
                String after = libLoomName.substring(index + 1);
                if (after.matches("^\\d.*")) {
                    return libLoomName.substring(0, index);
                }
            }
        }
        
        return libLoomName;
    }
    
    /**
     * 清理临时目录
     */
    private void cleanupTempDir(String tempDir) {
        try {
            File tempDirFile = new File(tempDir);
            if (tempDirFile.exists() && tempDirFile.isDirectory()) {
                deleteDirectory(tempDirFile);
            }
        } catch (Exception e) {
            Logger.debug("Failed to cleanup temp directory: %s", e.getMessage());
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
