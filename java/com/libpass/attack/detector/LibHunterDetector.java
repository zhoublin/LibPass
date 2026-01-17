package com.libpass.attack.detector;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

import com.libpass.attack.util.Logger;

/**
 * LibHunter检测工具适配器
 * LibHunter支持版本级检测，会输出版本候选
 */
public class LibHunterDetector implements TPLDetector {
    private static final String NAME = "LibHunter";
    private String libHunterPath;
    private String libHunterToolDir;
    private String tempOutputDir;
    private Map<String, Object> config;
    
    public LibHunterDetector() {
        this.config = new HashMap<>();
    }
    
    @Override
    public String getName() {
        return NAME;
    }
    
    @Override
    public void initialize(Map<String, Object> config) {
        this.config = config;
        String libHunterPathConfig = (String) config.getOrDefault("libhunter_path", 
            "TPL_Detectors/LibHunter/LibHunter/LibHunter.py");
        String libHunterToolDirConfig = (String) config.getOrDefault("libhunter_tool_dir",
            "TPL_Detectors/LibHunter/LibHunter");
        
        // 转换为绝对路径
        File libHunterPathFile = new File(libHunterPathConfig);
        if (!libHunterPathFile.isAbsolute()) {
            String currentDir = System.getProperty("user.dir");
            File absPath = new File(currentDir, libHunterPathConfig);
            if (absPath.exists()) {
                this.libHunterPath = absPath.getAbsolutePath();
            } else {
                this.libHunterPath = libHunterPathConfig;
            }
        } else {
            this.libHunterPath = libHunterPathConfig;
        }
        
        File libHunterToolDirFile = new File(libHunterToolDirConfig);
        if (!libHunterToolDirFile.isAbsolute()) {
            String currentDir = System.getProperty("user.dir");
            File absPath = new File(currentDir, libHunterToolDirConfig);
            if (absPath.exists()) {
                this.libHunterToolDir = absPath.getAbsolutePath();
            } else {
                this.libHunterToolDir = libHunterToolDirConfig;
            }
        } else {
            this.libHunterToolDir = libHunterToolDirConfig;
        }
        
        this.tempOutputDir = (String) config.getOrDefault("temp_output_dir",
            System.getProperty("java.io.tmpdir") + "/libhunter_output");
        
        // 创建临时输出目录
        new File(tempOutputDir).mkdirs();
        
        // 验证路径
        File libHunterFile = new File(this.libHunterPath);
        if (!libHunterFile.exists()) {
            Logger.warning("LibHunter.py not found at: %s", this.libHunterPath);
        } else {
            Logger.debug("LibHunter path resolved to: %s", this.libHunterPath);
        }
        
        File toolDirFile = new File(this.libHunterToolDir);
        if (!toolDirFile.exists()) {
            Logger.warning("LibHunter tool directory not found at: %s", this.libHunterToolDir);
        } else {
            Logger.debug("LibHunter tool directory: %s", this.libHunterToolDir);
        }
    }
    
    @Override
    public boolean isAvailable() {
        if (libHunterPath == null) {
            return false;
        }
        File libHunterFile = new File(libHunterPath);
        boolean exists = libHunterFile.exists();
        boolean readable = libHunterFile.canRead();
        
        if (!exists) {
            Logger.error("LibHunter.py not found at: %s", libHunterPath);
        } else if (!readable) {
            Logger.error("LibHunter.py is not readable: %s", libHunterPath);
        }
        
        return exists && readable;
    }
    
    @Override
    public DetectionResult detectTPL(String apkPath, String tplPath, String tplName) {
        DetectionResult result = new DetectionResult();
        result.setApkPath(apkPath);
        result.setTplName(tplName != null ? tplName : extractTPLName(tplPath));
        
        try {
            // 创建临时目录用于LibHunter检测
            // 使用UUID确保唯一性，避免多线程环境下目录冲突
            String uniqueId = UUID.randomUUID().toString().replace("-", "");
            String tempDir = tempOutputDir + "/" + System.currentTimeMillis() + "_" + uniqueId;
            new File(tempDir).mkdirs();
            
            // 创建目录结构
            String apkDir = tempDir + "/apks";
            String libJarDir = tempDir + "/tpls_jar";
            String libDexDir = tempDir + "/tpls_dex";
            String outputDir = tempDir + "/outputs";
            
            new File(apkDir).mkdirs();
            new File(libJarDir).mkdirs();
            new File(libDexDir).mkdirs();
            new File(outputDir).mkdirs();
            
            // 准备APK文件
            String tempApkPath = apkDir + "/" + new File(apkPath).getName();
            Files.copy(Paths.get(apkPath), Paths.get(tempApkPath), 
                StandardCopyOption.REPLACE_EXISTING);
            
            // 准备TPL文件
            String tempTplPath = prepareTPLForDetection(tplPath, libJarDir);
            if (tempTplPath == null) {
                result.setDetected(false);
                result.setMessage("Failed to prepare TPL for detection");
                return result;
            }
            
            // 将TPL JAR转换为DEX（如果需要）
            String tplDexPath = convertJarToDexIfNeeded(tempTplPath, libDexDir);
            if (tplDexPath == null) {
                result.setDetected(false);
                result.setMessage("Failed to convert TPL to DEX");
                return result;
            }
            
            // 运行LibHunter检测
            boolean success = runLibHunterDetection(apkDir, libJarDir, libDexDir, outputDir);
            
            if (success) {
                // 解析检测结果
                Logger.debug("LibHunter detection completed, parsing results...");
                result = parseLibHunterResult(outputDir, tempApkPath, result);
                // 输出检测结果（DEBUG级别）
                Logger.debug("LibHunter result: detected=%s, confidence=%.6f", 
                    result.isDetected(), result.getConfidence());
            } else {
                Logger.error("LibHunter detection process failed");
                result.setDetected(false);
                result.setConfidence(0.0);
                result.setMessage("LibHunter detection process failed");
            }
            
            // 清理临时目录
            cleanupTempDir(tempDir);
            
        } catch (Exception e) {
            Logger.error("Failed to detect TPL with LibHunter: %s", e.getMessage());
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
     * 准备TPL文件用于检测
     */
    private String prepareTPLForDetection(String tplPath, String libJarDir) {
        try {
            File tplFile = new File(tplPath);
            if (!tplFile.exists()) {
                Logger.error("TPL file not found: %s", tplPath);
                return null;
            }
            
            String fileName = tplFile.getName();
            String extension = fileName.substring(fileName.lastIndexOf('.') + 1);
            
            // 确保目标目录存在
            File libJarDirFile = new File(libJarDir);
            if (!libJarDirFile.exists()) {
                libJarDirFile.mkdirs();
            }
            
            String tempTplPath;
            
            if (extension.equals("jar") || extension.equals("aar")) {
                // 直接复制JAR/AAR文件
                tempTplPath = libJarDir + "/" + fileName;
                Files.copy(Paths.get(tplPath), Paths.get(tempTplPath), 
                    StandardCopyOption.REPLACE_EXISTING);
                
                // 验证文件已复制
                File copiedFile = new File(tempTplPath);
                if (!copiedFile.exists()) {
                    Logger.error("Failed to copy TPL file to: %s", tempTplPath);
                    return null;
                }
                Logger.debug("TPL file copied: %s -> %s (size: %d bytes)", 
                    tplPath, tempTplPath, copiedFile.length());
            } else if (extension.equals("dex")) {
                // DEX文件需要先转换为JAR（LibHunter需要JAR格式作为输入）
                // 但LibHunter实际上会从JAR转换为DEX，所以我们可以直接使用DEX
                // 为了简化，我们将DEX文件复制到JAR目录，但使用.jar扩展名
                // 实际上LibHunter会检查文件类型，所以我们需要确保正确处理
                Logger.warning("LibHunter expects JAR format, but DEX file provided: %s", fileName);
                // 将DEX文件复制，但使用.jar扩展名（LibHunter会处理）
                String jarFileName = fileName.substring(0, fileName.lastIndexOf('.')) + ".jar";
                tempTplPath = libJarDir + "/" + jarFileName;
                Files.copy(Paths.get(tplPath), Paths.get(tempTplPath), 
                    StandardCopyOption.REPLACE_EXISTING);
                
                // 验证文件已复制
                File copiedFile = new File(tempTplPath);
                if (!copiedFile.exists()) {
                    Logger.error("Failed to copy DEX file to: %s", tempTplPath);
                    return null;
                }
                Logger.debug("DEX file copied as JAR: %s -> %s (size: %d bytes)", 
                    tplPath, tempTplPath, copiedFile.length());
            } else {
                Logger.error("Unsupported TPL format for LibHunter: %s", extension);
                return null;
            }
            
            return tempTplPath;
            
        } catch (Exception e) {
            Logger.error("Failed to prepare TPL: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }
    
    /**
     * 将JAR转换为DEX（如果需要）
     * LibHunter使用d8工具进行转换
     */
    private String convertJarToDexIfNeeded(String jarPath, String libDexDir) {
        try {
            // 确保使用绝对路径
            File jarFile = new File(jarPath);
            if (!jarFile.exists()) {
                Logger.error("JAR file not found: %s", jarPath);
                return null;
            }
            String absJarPath = jarFile.getAbsolutePath();
            
            File libDexDirFile = new File(libDexDir);
            // 确保输出目录存在
            if (!libDexDirFile.exists()) {
                boolean created = libDexDirFile.mkdirs();
                if (!created) {
                    Logger.error("Failed to create output directory: %s", libDexDir);
                    return null;
                }
            }
            // 验证目录确实存在且是目录
            if (!libDexDirFile.isDirectory()) {
                Logger.error("Output path is not a directory: %s", libDexDir);
                return null;
            }
            String absLibDexDir = libDexDirFile.getAbsolutePath();
            
            String fileName = jarFile.getName();
            String baseName = fileName.substring(0, fileName.lastIndexOf('.'));
            String dexFileName = baseName + ".dex";
            String dexPath = absLibDexDir + File.separator + dexFileName;
            
            // 如果DEX文件已存在，直接返回
            File dexFile = new File(dexPath);
            if (dexFile.exists()) {
                Logger.debug("DEX file already exists: %s", dexPath);
                return dexPath;
            }
            
            // 使用LibHunter的d8工具转换
            File d8JarFile = new File(libHunterToolDir, "libs/d8.jar");
            File androidJarFile = new File(libHunterToolDir, "libs/android.jar");
            
            if (!d8JarFile.exists()) {
                Logger.error("d8.jar not found at: %s", d8JarFile.getAbsolutePath());
                return null;
            }
            
            if (!androidJarFile.exists()) {
                Logger.error("android.jar not found at: %s", androidJarFile.getAbsolutePath());
                return null;
            }
            
            // 再次验证JAR文件存在（使用绝对路径）
            if (!jarFile.exists()) {
                Logger.error("JAR file does not exist: %s", absJarPath);
                return null;
            }
            
            Logger.debug("Converting JAR to DEX:");
            Logger.debug("  JAR file: %s (exists: %s, size: %d)", absJarPath, jarFile.exists(), jarFile.length());
            Logger.debug("  Output dir: %s (exists: %s, isDir: %s)", absLibDexDir, libDexDirFile.exists(), libDexDirFile.isDirectory());
            Logger.debug("  d8.jar: %s", d8JarFile.getAbsolutePath());
            Logger.debug("  android.jar: %s", androidJarFile.getAbsolutePath());
            
            ProcessBuilder pb = new ProcessBuilder(
                "java",
                "-cp",
                d8JarFile.getAbsolutePath(),
                "com.android.tools.r8.D8",
                "--lib",
                androidJarFile.getAbsolutePath(),
                "--output",
                absLibDexDir,  // 使用绝对路径
                absJarPath    // 使用绝对路径
            );
            
            // 设置工作目录为当前工作目录，避免相对路径解析问题
            // 使用绝对路径，不依赖工作目录
            pb.directory(new File(System.getProperty("user.dir")));
            pb.redirectErrorStream(true);
            
            Process process = pb.start();
            
            // 读取输出
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            String line;
            boolean hasError = false;
            while ((line = reader.readLine()) != null) {
                // 过滤掉常见的警告信息（这些警告不影响转换结果）
                if (line.contains("Warning") && 
                    (line.contains("was not found") || 
                     line.contains("required for default or static interface methods desugaring"))) {
                    // 这些是d8的常见警告，不影响转换结果，降级为DEBUG或忽略
                    Logger.debug("d8 warning (ignored): %s", line);
                    continue;
                }
                
                // 记录错误和重要信息
                if (line.contains("Error") || line.contains("Exception") || 
                    line.contains("Compilation failed") || line.contains("failed")) {
                    Logger.error("d8: %s", line);
                    hasError = true;
                } else {
                    Logger.debug("d8: %s", line);
                }
            }
            
            boolean finished = process.waitFor(60, TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                Logger.error("d8 conversion timeout");
                return null;
            }
            
            int exitCode = process.exitValue();
            
            // d8默认生成classes.dex，需要检查并重命名
            // dexFile已在前面定义（第299行），这里直接使用
            File classesDexFile = new File(absLibDexDir, "classes.dex");
            
            // 首先检查期望的文件名是否已生成
            if (dexFile.exists() && dexFile.length() > 0) {
                // 期望的文件已生成
                if (exitCode != 0) {
                    Logger.warning("d8 conversion completed with warnings (exit code: %d), but DEX file was generated: %s (size: %d bytes)", 
                        exitCode, dexPath, dexFile.length());
                } else {
                    Logger.debug("d8 conversion successful: %s (size: %d bytes)", dexPath, dexFile.length());
                }
                return dexPath;
            } else if (classesDexFile.exists() && classesDexFile.length() > 0) {
                // d8生成了默认的classes.dex，需要重命名为期望的文件名
                Logger.debug("d8 generated classes.dex, renaming to: %s", dexFileName);
                try {
                    Files.move(classesDexFile.toPath(), dexFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
                    Logger.debug("Renamed classes.dex to %s (size: %d bytes)", dexPath, dexFile.length());
                    return dexPath;
                } catch (Exception e) {
                    Logger.error("Failed to rename classes.dex to %s: %s", dexPath, e.getMessage());
                    // 即使重命名失败，也返回classes.dex的路径（LibHunter可能也能使用）
                    return classesDexFile.getAbsolutePath();
                }
            } else {
                // DEX文件未生成，转换失败
                if (exitCode != 0) {
                    Logger.error("d8 conversion failed with exit code: %d, DEX file not created: %s", exitCode, dexPath);
                } else {
                    Logger.error("d8 conversion completed (exit code: 0), but DEX file not found: %s", dexPath);
                }
                // 检查输出目录中是否有其他DEX文件
                File outputDir = new File(absLibDexDir);
                if (outputDir.exists() && outputDir.isDirectory()) {
                    File[] files = outputDir.listFiles((dir, name) -> name.endsWith(".dex"));
                    if (files != null && files.length > 0) {
                        Logger.debug("Found %d DEX file(s) in output directory, but expected file not found", files.length);
                        for (File f : files) {
                            Logger.debug("  Found DEX file: %s (size: %d bytes)", f.getName(), f.length());
                        }
                        // 如果只有一个DEX文件，使用它（可能是classes.dex）
                        if (files.length == 1) {
                            Logger.warning("Using found DEX file: %s", files[0].getAbsolutePath());
                            // 尝试重命名为期望的文件名
                            try {
                                Files.move(files[0].toPath(), dexFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
                                Logger.debug("Renamed %s to %s", files[0].getName(), dexPath);
                                return dexPath;
                            } catch (Exception e) {
                                Logger.warning("Failed to rename, using original file: %s", files[0].getAbsolutePath());
                                return files[0].getAbsolutePath();
                            }
                        }
                    } else {
                        Logger.debug("No DEX files found in output directory: %s", absLibDexDir);
                    }
                }
                return null;
            }
            
        } catch (Exception e) {
            Logger.error("Failed to convert JAR to DEX: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }
    
    /**
     * 运行LibHunter检测
     */
    private boolean runLibHunterDetection(String apkDir, String libJarDir, String libDexDir, String outputDir) {
        try {
            // 确保使用绝对路径
            File apkDirFile = new File(apkDir);
            String absApkDir = apkDirFile.getAbsolutePath();
            
            File libJarDirFile = new File(libJarDir);
            String absLibJarDir = libJarDirFile.getAbsolutePath();
            
            File libDexDirFile = new File(libDexDir);
            String absLibDexDir = libDexDirFile.getAbsolutePath();
            
            File outputDirFile = new File(outputDir);
            String absOutputDir = outputDirFile.getAbsolutePath();
            
            File libHunterFile = new File(libHunterPath);
            String absLibHunterPath = libHunterFile.getAbsolutePath();
            
            Logger.debug("Executing LibHunter:");
            Logger.debug("  Script: %s", absLibHunterPath);
            Logger.debug("  Working dir: %s", libHunterToolDir);
            Logger.debug("  APK Dir: %s", absApkDir);
            Logger.debug("  Lib JAR Dir: %s", absLibJarDir);
            Logger.debug("  Lib DEX Dir: %s", absLibDexDir);
            Logger.debug("  Output Dir: %s", absOutputDir);
            
            ProcessBuilder pb = new ProcessBuilder(
                "python3",
                absLibHunterPath,
                "detect_one",
                "-o", absOutputDir,
                "-af", absApkDir,
                "-lf", absLibJarDir,
                "-ld", absLibDexDir,
                "-p", "1"
            );
            
            pb.directory(new File(libHunterToolDir));
            
            // 设置PYTHONPATH，确保LibHunter的module目录优先于系统包
            // 这样可以避免使用环境中安装的androguard，而是使用LibHunter自定义的androguard包
            Map<String, String> env = pb.environment();
            String moduleDir = libHunterToolDir + "/module";
            
            // 获取当前PYTHONPATH
            String currentPythonPath = env.get("PYTHONPATH");
            
            // 将module目录放在最前面，确保优先使用LibHunter的自定义包
            if (currentPythonPath != null && !currentPythonPath.isEmpty()) {
                // 如果module目录已经在PYTHONPATH中，先移除它
                String[] paths = currentPythonPath.split(File.pathSeparator);
                List<String> pathList = new ArrayList<>(Arrays.asList(paths));
                pathList.remove(moduleDir);
                // 将module目录插入到最前面
                pathList.add(0, moduleDir);
                env.put("PYTHONPATH", String.join(File.pathSeparator, pathList));
            } else {
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
                Logger.debug("LibHunter: %s", line);
            }
            
            boolean finished = process.waitFor(300, TimeUnit.SECONDS); // 5分钟超时
            if (!finished) {
                Logger.error("LibHunter process timed out");
                process.destroyForcibly();
                return false;
            }
            
            int exitCode = process.exitValue();
            Logger.debug("LibHunter process finished with exit code: %s", exitCode);
            
            // 即使退出码不为0，也尝试解析结果（可能部分成功）
            if (exitCode != 0) {
                Logger.error("LibHunter exited with non-zero code: %s", exitCode);
            }
            
            return true; // 返回true以便尝试解析结果
            
        } catch (Exception e) {
            Logger.error("Failed to run LibHunter: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }
    
    /**
     * 解析LibHunter检测结果
     * LibHunter输出格式：results.txt文件，每行格式为 "apk name library name similarity score"
     */
    private DetectionResult parseLibHunterResult(String outputDir, String apkPath, DetectionResult result) {
        try {
            String apkName = new File(apkPath).getName();
            String apkBaseName = apkName;
            if (apkName.contains(".")) {
                apkBaseName = apkName.substring(0, apkName.lastIndexOf('.'));
            }
            
            Logger.debug("Parsing LibHunter results for APK: %s (base: %s)", apkName, apkBaseName);
            Logger.debug("Output directory: %s", outputDir);
            
            // LibHunter输出统一的results.txt文件
            String resultFile = outputDir + "/results.txt";
            File file = new File(resultFile);
            
            if (!file.exists()) {
                Logger.error("LibHunter result file not found: %s", resultFile);
                result.setDetected(false);
                result.setConfidence(0.0);
                result.setMessage("Result file not found: " + resultFile);
                return result;
            }
            
            // 读取并打印原始检测结果
            List<String> lines = Files.readAllLines(Paths.get(file.getAbsolutePath()));
            Logger.debug("=== LibHunter原始检测结果 (results.txt) ===");
            Logger.debug("文件路径: %s", file.getAbsolutePath());
            Logger.debug("文件行数: %d", lines.size());
            Logger.debug("原始内容:");
            for (int i = 0; i < lines.size(); i++) {
                Logger.debug("  [%d] %s", i + 1, lines.get(i));
            }
            Logger.debug("=== LibHunter原始检测结果结束 ===");
            
            boolean detected = false;
            double confidence = 0.0;
            String targetTplName = result.getTplName();
            
            // 解析results.txt文件
            // 格式：第一行是标题 "apk name library name similarity score"
            // 后续每行：apk_name   library_name   similarity_score
            boolean isFirstLine = true;
            for (String line : lines) {
                if (line.trim().isEmpty()) {
                    continue;
                }
                
                // 跳过标题行
                if (isFirstLine) {
                    isFirstLine = false;
                    if (line.contains("apk name") || line.contains("library name")) {
                        continue;
                    }
                }
                
                // 解析行：apk_name   library_name   similarity_score
                // 使用多个空格或制表符分割
                String[] parts = line.trim().split("\\s+");
                if (parts.length < 3) {
                    Logger.debug("Skipping invalid line in results.txt: %s", line);
                    continue;
                }
                
                String detectedApkName = parts[0].trim();
                String detectedLibName = parts[1].trim();
                String similarityStr = parts[2].trim();
                
                // 检查APK名称是否匹配（支持完整名称或基础名称）
                boolean apkMatches = detectedApkName.equals(apkName) || 
                                   detectedApkName.equals(apkBaseName) ||
                                   apkName.equals(detectedApkName) ||
                                   apkBaseName.equals(detectedApkName);
                
                if (!apkMatches) {
                    continue; // 不是当前APK的结果，跳过
                }
                
                Logger.debug("Found matching APK in results: %s, library: %s, similarity: %s", 
                    detectedApkName, detectedLibName, similarityStr);
                
                // 检查是否匹配目标TPL
                if (targetTplName != null && !targetTplName.isEmpty()) {
                    // 提取库名（去除版本部分）进行匹配
                    String detectedLibBase = extractLibNameFromLibHunterName(detectedLibName);
                    String targetLibBase = extractLibNameFromLibHunterName(targetTplName);
                    
                    // 规范化库名：移除常见的前缀/后缀，统一格式
                    String normalizedDetected = normalizeLibName(detectedLibBase);
                    String normalizedTarget = normalizeLibName(targetLibBase);
                    String normalizedDetectedFull = normalizeLibName(detectedLibName);
                    String normalizedTargetFull = normalizeLibName(targetTplName);
                    
                    Logger.debug("LibHunter name matching: detectedLibName=%s, detectedLibBase=%s, normalizedDetected=%s", 
                        detectedLibName, detectedLibBase, normalizedDetected);
                    Logger.debug("LibHunter name matching: targetTplName=%s, targetLibBase=%s, normalizedTarget=%s", 
                        targetTplName, targetLibBase, normalizedTarget);
                    
                    // 更宽松的匹配策略：支持多种匹配方式
                    boolean nameMatches = 
                        // 精确匹配（忽略大小写）
                        normalizedDetected.equalsIgnoreCase(normalizedTarget) ||
                        normalizedDetectedFull.equalsIgnoreCase(normalizedTargetFull) ||
                        // 包含匹配
                        normalizedDetected.toLowerCase().contains(normalizedTarget.toLowerCase()) ||
                        normalizedTarget.toLowerCase().contains(normalizedDetected.toLowerCase()) ||
                        normalizedDetectedFull.toLowerCase().contains(normalizedTargetFull.toLowerCase()) ||
                        normalizedTargetFull.toLowerCase().contains(normalizedDetectedFull.toLowerCase()) ||
                        // 原始名称匹配（作为兜底）
                        detectedLibBase.equalsIgnoreCase(targetLibBase) ||
                        detectedLibName.toLowerCase().contains(targetTplName.toLowerCase()) ||
                        targetTplName.toLowerCase().contains(detectedLibName.toLowerCase());
                    
                    Logger.debug("LibHunter name match result: %s", nameMatches);
                    
                    if (nameMatches) {
                        detected = true;
                        // 解析相似度分数作为置信度
                        try {
                            confidence = Double.parseDouble(similarityStr);
                        } catch (NumberFormatException e) {
                            confidence = 1.0; // 如果无法解析，默认1.0
                        }
                        
                        // 提取版本信息
                        String version = extractVersionFromLibHunterName(detectedLibName);
                        if (version != null && !version.isEmpty()) {
                            result.addDetectedVersion(version);
                        }
                        
                        Logger.debug("LibHunter detection result: APK=%s, TPL=%s, version=%s, similarity=%.6f, detected=%s", 
                            apkName, detectedLibName, version, confidence, detected);
                        // 不break，继续查找是否有其他版本
                    }
                } else {
                    // 没有指定TPL名称，只要检测到任何TPL就算检测到
                    detected = true;
                    try {
                        confidence = Double.parseDouble(similarityStr);
                    } catch (NumberFormatException e) {
                        confidence = 1.0;
                    }
                    
                    // 提取版本信息
                    String version = extractVersionFromLibHunterName(detectedLibName);
                    if (version != null && !version.isEmpty()) {
                        result.addDetectedVersion(version);
                    }
                    
                    Logger.debug("LibHunter detection result: APK=%s, TPL=%s, version=%s, similarity=%.6f, detected=%s", 
                        apkName, detectedLibName, version, confidence, detected);
                    break; // 没有指定TPL，找到第一个就退出
                }
            }
            
            result.setDetected(detected);
            result.setConfidence(confidence);
            result.setMessage("LibHunter detection completed");
            
            Logger.debug("LibHunter detection result: detected=%s, confidence=%.6f, versions=%s", 
                detected, confidence, result.getDetectedVersions());
            
        } catch (Exception e) {
            Logger.error("Failed to parse LibHunter result: %s", e.getMessage());
            e.printStackTrace();
            result.setDetected(false);
            result.setConfidence(0.0);
            result.setMessage("Failed to parse result: " + e.getMessage());
        }
        
        return result;
    }
    
    /**
     * 从LibHunter输出的库名中提取库名（去除版本部分）
     * LibHunter格式：com.squareup.okhttp3.okhttp_3.12.0 或 com.squareup.okhttp3.okhttp-3.12.0
     */
    private String extractLibNameFromLibHunterName(String libHunterName) {
        if (libHunterName == null || libHunterName.isEmpty()) {
            return libHunterName;
        }
        
        // 尝试匹配版本号模式并移除
        // 支持格式：库名_版本、库名-版本、库名.版本
        Pattern pattern = Pattern.compile("^(.+?)[-_](\\d+\\.\\d+(?:\\.\\d+)?(?:[-_]?\\w+)?)$");
        Matcher matcher = pattern.matcher(libHunterName);
        if (matcher.find()) {
            return matcher.group(1);
        }
        
        // 如果没有匹配，返回原名称
        return libHunterName;
    }
    
    /**
     * 从LibHunter输出的库名中提取版本信息
     * 支持格式：
     * - com.squareup.okhttp3.okhttp_3.12.0 -> 3.12.0
     * - com.squareup.okhttp3.okhttp-3.12.0 -> 3.12.0
     * - com.android.support.support-v4.22.2.1 -> 22.2.1
     * - com.android.support.appcompat-v7.21.0.3 -> 21.0.3 (注意：v7是库名的一部分，不是版本)
     * - library-2.8.6 -> 2.8.6
     */
    private String extractVersionFromLibHunterName(String libHunterName) {
        if (libHunterName == null || libHunterName.isEmpty()) {
            return null;
        }
        
        // 先移除文件扩展名（.dex, .jar, .aar等）
        String libNameWithoutExt = libHunterName;
        int lastDot = libHunterName.lastIndexOf('.');
        if (lastDot > 0) {
            String ext = libHunterName.substring(lastDot + 1).toLowerCase();
            // 如果是常见的文件扩展名，移除它
            if (ext.equals("dex") || ext.equals("jar") || ext.equals("aar") || ext.equals("zip")) {
                libNameWithoutExt = libHunterName.substring(0, lastDot);
            }
        }
        
        Logger.debug("Extracting version from LibHunter name '%s' (without ext: '%s')", 
            libHunterName, libNameWithoutExt);
        
        // 尝试多种版本号模式，按从复杂到简单的顺序匹配
        // 模式1: 处理类似 "support-v4.22.2.1" 的情况，提取 "22.2.1"
        // 匹配格式：库名-v数字.版本号 或 库名-数字.版本号
        Pattern patternV = Pattern.compile(".*[-_]v\\d+\\.(\\d+\\.\\d+(?:\\.\\d+)*(?:[-_.]?\\w+)?)$");
        Matcher matcherV = patternV.matcher(libNameWithoutExt);
        if (matcherV.find()) {
            String version = matcherV.group(1);
            Logger.debug("Extracted version '%s' from LibHunter name '%s' using pattern v\\d+\\.", 
                version, libHunterName);
            return version;
        }
        
        // 模式1b: 处理类似 "support-v4.22.2.1" 的情况，匹配三个或更多数字段
        Pattern patternVMulti = Pattern.compile(".*[-_](\\d+\\.\\d+(?:\\.\\d+)+(?:[-_.]?\\w+)?)$");
        Matcher matcherVMulti = patternVMulti.matcher(libNameWithoutExt);
        if (matcherVMulti.find()) {
            String version = matcherVMulti.group(1);
            Logger.debug("Extracted version '%s' from LibHunter name '%s' using multi-segment pattern", 
                version, libHunterName);
            return version;
        }
        
        // 模式2: 库名_版本 或 库名-版本（版本以数字开头，如 3.12.0）
        Pattern pattern1 = Pattern.compile(".*[-_](\\d+\\.\\d+(?:\\.\\d+)*(?:[-_.]?\\w+)?)$");
        Matcher matcher1 = pattern1.matcher(libNameWithoutExt);
        if (matcher1.find()) {
            String version = matcher1.group(1);
            Logger.debug("Extracted version '%s' from LibHunter name '%s' using dash/underscore pattern", 
                version, libHunterName);
            return version;
        }
        
        // 模式3: 库名.版本（版本以数字开头）
        Pattern pattern2 = Pattern.compile(".*\\.(\\d+\\.\\d+(?:\\.\\d+)*(?:[-_.]?\\w+)?)$");
        Matcher matcher2 = pattern2.matcher(libNameWithoutExt);
        if (matcher2.find()) {
            String version = matcher2.group(1);
            Logger.debug("Extracted version '%s' from LibHunter name '%s' using dot pattern", 
                version, libHunterName);
            return version;
        }
        
        Logger.debug("Could not extract version from LibHunter name '%s'", libHunterName);
        return null;
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
     * 规范化库名，用于匹配
     * 移除版本号、统一分隔符、移除常见前缀等
     */
    private String normalizeLibName(String libName) {
        if (libName == null || libName.isEmpty()) {
            return libName;
        }
        
        String normalized = libName;
        
        // 移除版本号模式（如果存在）
        normalized = normalized.replaceAll("[-_]\\d+\\.\\d+(?:\\.\\d+)*(?:[-_.]?\\w+)?$", "");
        normalized = normalized.replaceAll("\\.\\d+\\.\\d+(?:\\.\\d+)*(?:[-_.]?\\w+)?$", "");
        
        // 统一分隔符：将下划线和连字符统一为点
        normalized = normalized.replaceAll("[-_]", ".");
        
        // 移除常见前缀
        normalized = normalized.replaceFirst("^com\\.", "");
        normalized = normalized.replaceFirst("^org\\.", "");
        normalized = normalized.replaceFirst("^android\\.", "");
        
        // 移除文件扩展名（如果存在）
        normalized = normalized.replaceFirst("\\.[a-z]+$", "");
        
        // 转换为小写并去除首尾空白
        normalized = normalized.toLowerCase().trim();
        
        return normalized;
    }
    
    /**
     * 清理临时目录
     */
    private void cleanupTempDir(String tempDir) {
        try {
            // 延迟删除，给LibHunter一些时间完成
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
