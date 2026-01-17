package com.libpass.attack.detector;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

import com.google.gson.*;
import com.libpass.attack.util.Logger;

/**
 * LiteRadar检测工具适配器
 * LiteRadar不支持版本级检测，只输出库名称
 * 需要智能匹配检测结果和给定TPL名字的相似度
 */
public class LiteRadarDetector implements TPLDetector {
    private static final String NAME = "LiteRadar";
    private String liteRadarPath;
    private String liteRadarToolDir;
    private String tempOutputDir;
    private Map<String, Object> config;
    
    // 相似度阈值：如果相似度超过此值，认为检测到
    private static final double SIMILARITY_THRESHOLD = 0.6;
    
    public LiteRadarDetector() {
        this.config = new HashMap<>();
    }
    
    @Override
    public String getName() {
        return NAME;
    }
    
    @Override
    public void initialize(Map<String, Object> config) {
        this.config = config;
        String liteRadarPathConfig = (String) config.getOrDefault("literadar_path", 
            "TPL_Detectors/LiteRadar/LiteRadar/literadar.py");
        String liteRadarToolDirConfig = (String) config.getOrDefault("literadar_tool_dir",
            "TPL_Detectors/LiteRadar/LiteRadar");
        
        // 转换为绝对路径
        File liteRadarPathFile = new File(liteRadarPathConfig);
        if (!liteRadarPathFile.isAbsolute()) {
            String currentDir = System.getProperty("user.dir");
            File absPath = new File(currentDir, liteRadarPathConfig);
            if (absPath.exists()) {
                this.liteRadarPath = absPath.getAbsolutePath();
            } else {
                this.liteRadarPath = liteRadarPathConfig;
            }
        } else {
            this.liteRadarPath = liteRadarPathConfig;
        }
        
        File liteRadarToolDirFile = new File(liteRadarToolDirConfig);
        if (!liteRadarToolDirFile.isAbsolute()) {
            String currentDir = System.getProperty("user.dir");
            File absPath = new File(currentDir, liteRadarToolDirConfig);
            if (absPath.exists()) {
                this.liteRadarToolDir = absPath.getAbsolutePath();
            } else {
                this.liteRadarToolDir = liteRadarToolDirConfig;
            }
        } else {
            this.liteRadarToolDir = liteRadarToolDirConfig;
        }
        
        this.tempOutputDir = (String) config.getOrDefault("temp_output_dir",
            System.getProperty("java.io.tmpdir") + "/literadar_output");
        
        // 创建临时输出目录
        new File(tempOutputDir).mkdirs();
        
        // 验证路径
        File liteRadarFile = new File(this.liteRadarPath);
        if (!liteRadarFile.exists()) {
            Logger.warning("literadar.py not found at: %s", this.liteRadarPath);
        } else {
            Logger.debug("LiteRadar path resolved to: %s", this.liteRadarPath);
        }
        
        File toolDirFile = new File(this.liteRadarToolDir);
        if (!toolDirFile.exists()) {
            Logger.warning("LiteRadar tool directory not found at: %s", this.liteRadarToolDir);
        } else {
            Logger.debug("LiteRadar tool directory: %s", this.liteRadarToolDir);
        }
    }
    
    @Override
    public boolean isAvailable() {
        if (liteRadarPath == null) {
            return false;
        }
        File liteRadarFile = new File(liteRadarPath);
        boolean exists = liteRadarFile.exists();
        boolean readable = liteRadarFile.canRead();
        
        if (!exists) {
            Logger.error("literadar.py not found at: %s", liteRadarPath);
        } else if (!readable) {
            Logger.error("literadar.py is not readable: %s", liteRadarPath);
        }
        
        return exists && readable;
    }
    
    @Override
    public DetectionResult detectTPL(String apkPath, String tplPath, String tplName) {
        DetectionResult result = new DetectionResult();
        result.setApkPath(apkPath);
        result.setTplName(tplName != null ? tplName : extractTPLName(tplPath));
        
        try {
            // 创建临时目录用于LiteRadar检测
            String uniqueId = UUID.randomUUID().toString().replace("-", "");
            String tempDir = tempOutputDir + "/" + System.currentTimeMillis() + "_" + uniqueId;
            new File(tempDir).mkdirs();
            
            // 准备APK文件
            String tempApkPath = tempDir + "/" + new File(apkPath).getName();
            Files.copy(Paths.get(apkPath), Paths.get(tempApkPath), 
                StandardCopyOption.REPLACE_EXISTING);
            
            // 运行LiteRadar检测
            boolean success = runLiteRadarDetection(tempApkPath, tempDir);
            
            if (success) {
                // 解析检测结果
                Logger.debug("LiteRadar detection completed, parsing results...");
                result = parseLiteRadarResult(tempDir, tempApkPath, result);
                Logger.debug("LiteRadar result: detected=%s, confidence=%.6f", 
                    result.isDetected(), result.getConfidence());
            } else {
                Logger.error("LiteRadar detection process failed");
                result.setDetected(false);
                result.setConfidence(0.0);
                result.setMessage("LiteRadar detection process failed");
            }
            
            // 清理临时目录
            cleanupTempDir(tempDir);
            
        } catch (Exception e) {
            Logger.error("Failed to detect TPL with LiteRadar: %s", e.getMessage());
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
     * 运行LiteRadar检测
     */
    private boolean runLiteRadarDetection(String apkPath, String outputDir) {
        try {
            File apkFile = new File(apkPath);
            String absApkPath = apkFile.getAbsolutePath();
            
            File liteRadarFile = new File(liteRadarPath);
            String absLiteRadarPath = liteRadarFile.getAbsolutePath();
            
            Logger.debug("Executing LiteRadar:");
            Logger.debug("  Script: %s", absLiteRadarPath);
            Logger.debug("  APK: %s", absApkPath);
            Logger.debug("  Working dir: %s", liteRadarToolDir);
            
            // 尝试使用python2（LiteRadar可能对Python 2更兼容）
            // 如果python2不可用，回退到python3
            String pythonCmd = "python3"; // 默认使用python3
            try {
                // 先检查python2
                Process checkPython2 = new ProcessBuilder("python2", "--version").start();
                if (checkPython2.waitFor(2, TimeUnit.SECONDS)) {
                    if (checkPython2.exitValue() == 0) {
                        pythonCmd = "python2";
                        Logger.debug("Using python2 for LiteRadar");
                        checkPython2.destroy();
                    } else {
                        checkPython2.destroy();
                    }
                } else {
                    checkPython2.destroyForcibly();
                }
                
                // 如果python2不可用，尝试python（可能是Python 2或3）
                if (!"python2".equals(pythonCmd)) {
                    try {
                        Process checkPython = new ProcessBuilder("python", "--version").start();
                        if (checkPython.waitFor(2, TimeUnit.SECONDS)) {
                            if (checkPython.exitValue() == 0) {
                                pythonCmd = "python";
                                Logger.debug("Using python for LiteRadar");
                            }
                            checkPython.destroy();
                        } else {
                            checkPython.destroyForcibly();
                        }
                    } catch (Exception e) {
                        // 忽略检查失败
                    }
                }
            } catch (Exception e) {
                // 如果检查失败，使用python3作为默认
                Logger.debug("Python version check failed, using python3 as default: %s", e.getMessage());
            }
            
            ProcessBuilder pb = new ProcessBuilder(
                pythonCmd,
                absLiteRadarPath,
                absApkPath
            );
            
            pb.directory(new File(liteRadarToolDir));
            
            // 设置PYTHONPATH，确保LiteRadar的目录优先
            Map<String, String> env = pb.environment();
            String currentPythonPath = env.get("PYTHONPATH");
            if (currentPythonPath != null && !currentPythonPath.isEmpty()) {
                env.put("PYTHONPATH", liteRadarToolDir + File.pathSeparator + currentPythonPath);
            } else {
                env.put("PYTHONPATH", liteRadarToolDir);
            }
            
            Logger.debug("PYTHONPATH set to: %s", env.get("PYTHONPATH"));
            pb.redirectErrorStream(true);
            
            // 将输出重定向到文件
            String outputFile = outputDir + "/literadar_output.json";
            pb.redirectOutput(new File(outputFile));
            
            Process process = pb.start();
            
            boolean finished = process.waitFor(300, TimeUnit.SECONDS); // 5分钟超时
            if (!finished) {
                Logger.error("LiteRadar process timed out");
                process.destroyForcibly();
                return false;
            }
            
            int exitCode = process.exitValue();
            Logger.debug("LiteRadar process finished with exit code: %s", exitCode);
            
            if (exitCode != 0) {
                Logger.error("LiteRadar exited with non-zero code: %s", exitCode);
                // 读取错误输出
                try {
                    if (new File(outputFile).exists()) {
                        String content = new String(Files.readAllBytes(Paths.get(outputFile)));
                        List<String> errorLines = Arrays.asList(content.split("\n"));
                        
                        boolean hasDataFileError = false;
                        for (String line : errorLines) {
                            // 过滤掉Python语法警告（这些不影响功能）
                            if (line.contains("SyntaxWarning") || 
                                (line.contains("is not") && line.contains("Did you mean"))) {
                                Logger.debug("LiteRadar warning (ignored): %s", line);
                            } else if (line.contains("FileNotFoundError") && line.contains("lite_dataset_10.csv")) {
                                hasDataFileError = true;
                                Logger.error("LiteRadar: %s", line);
                            } else {
                                Logger.error("LiteRadar: %s", line);
                            }
                        }
                        
                        // 如果数据文件缺失，提供下载提示
                        if (hasDataFileError) {
                            Logger.error("LiteRadar data file not found: lite_dataset_10.csv");
                            Logger.error("Please download the data file from: https://github.com/pkumza/Data_for_LibRadar/blob/master/lite_dataset_10.csv");
                            Logger.error("And place it in: %s/Data/", liteRadarToolDir);
                        }
                    }
                } catch (Exception e) {
                    Logger.error("Failed to read LiteRadar error output: %s", e.getMessage());
                }
                return false;
            }
            
            return true;
            
        } catch (Exception e) {
            Logger.error("Failed to run LiteRadar: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }
    
    /**
     * 解析LiteRadar检测结果（JSON格式）
     */
    private DetectionResult parseLiteRadarResult(String outputDir, String apkPath, DetectionResult result) {
        try {
            String outputFile = outputDir + "/literadar_output.json";
            File file = new File(outputFile);
            
            if (!file.exists()) {
                Logger.error("LiteRadar result file not found: %s", outputFile);
                result.setDetected(false);
                result.setConfidence(0.0);
                result.setMessage("Result file not found");
                return result;
            }
            
            // 读取并打印原始检测结果
            String rawContent = new String(Files.readAllBytes(Paths.get(file.getAbsolutePath())));
            Logger.debug("=== LiteRadar原始检测结果 (JSON) ===");
            Logger.debug("文件路径: %s", file.getAbsolutePath());
            Logger.debug("文件大小: %d bytes", file.length());
            Logger.debug("原始内容:");
            if (rawContent.length() > 10000) {
                Logger.debug("  (内容过长，仅显示前5000字符)");
                Logger.debug("  %s...", rawContent.substring(0, 5000));
            } else {
                String[] rawLines = rawContent.split("\n");
                for (int i = 0; i < rawLines.length; i++) {
                    Logger.debug("  [%d] %s", i + 1, rawLines[i]);
                }
            }
            Logger.debug("=== LiteRadar原始检测结果结束 ===");
            
            // 清理JSON内容：移除Python警告和语法错误信息
            String jsonContent = rawContent;
            
            // 按行清理：逐行处理，移除所有非JSON行
            String[] lines = rawContent.split("\n");
            StringBuilder cleaned = new StringBuilder();
            boolean foundJsonStart = false;
            
            for (String line : lines) {
                String trimmedLine = line.trim();
                
                // 跳过空行
                if (trimmedLine.isEmpty()) {
                    continue;
                }
                
                // 跳过Python警告、错误行和非JSON内容
                // 匹配模式：
                // - SyntaxWarning相关
                // - Traceback相关
                // - File路径相关
                // - Python代码行（如 "if class_name[0] is not 'L':"）
                // - 类似 "[0] is not 'L':" 的行（Python代码输出）
                // - 纯数字或数字]开头的行（可能是行号）
                if (trimmedLine.contains("SyntaxWarning") ||
                    trimmedLine.contains("Traceback") ||
                    trimmedLine.startsWith("File \"") ||
                    trimmedLine.contains("if class_name[0] is not") ||
                    trimmedLine.matches(".*is not.*Did you mean.*") ||
                    trimmedLine.matches("^\\s*if .* is not .*:$") ||
                    trimmedLine.matches("^\\[\\d+\\]\\s+.*is not.*") ||  // [0] is not 'L':
                    trimmedLine.matches("^\\s*\\d+\\]\\s+.*") ||          // 0] ...
                    trimmedLine.matches("^\\[\\d+\\]\\s*$")) {             // [0]
                    continue;
                }
                
                // 检查是否是JSON开始标记（必须是行首的 [ 或 {）
                if (trimmedLine.startsWith("[") || trimmedLine.startsWith("{")) {
                    foundJsonStart = true;
                    cleaned.append(line).append("\n");
                    continue;
                }
                
                // 如果已经找到了JSON开始，保留所有后续行（直到遇到非JSON内容）
                if (foundJsonStart) {
                    cleaned.append(line).append("\n");
                } else if (trimmedLine.startsWith("\"")) {
                    // 如果看到以引号开头的行，可能是JSON对象字段，但需要先找到开始标记
                    // 这种情况下，尝试查找JSON开始位置
                    break; // 退出循环，使用备用方法
                }
            }
            
            jsonContent = cleaned.toString().trim();
            
            // 如果清理后仍然找不到JSON数组开始，尝试直接查找第一个 '['
            // 并移除前面的所有内容
            if (jsonContent.isEmpty() || (!jsonContent.startsWith("[") && !jsonContent.startsWith("{"))) {
                int jsonStart = -1;
                for (int i = 0; i < rawContent.length(); i++) {
                    char c = rawContent.charAt(i);
                    // 确保 '[' 或 '{' 之前是空白或换行，避免匹配到字符串中的字符
                    if ((c == '[' || c == '{') && (i == 0 || Character.isWhitespace(rawContent.charAt(i - 1)) || rawContent.charAt(i - 1) == '\n')) {
                        jsonStart = i;
                        break;
                    }
                }
                
                if (jsonStart >= 0) {
                    jsonContent = rawContent.substring(jsonStart).trim();
                    Logger.debug("Found JSON start at position %d by character search", jsonStart);
                } else {
                    Logger.error("Could not find JSON start marker in LiteRadar output");
                    Logger.error("Raw content preview (first 500 chars): %s", 
                        rawContent.length() > 500 ? rawContent.substring(0, 500) : rawContent);
                    result.setDetected(false);
                    result.setConfidence(0.0);
                    result.setMessage("Could not find JSON start marker");
                    return result;
                }
            }
            
            // 最终清理：移除任何残留的非JSON行（特别是那些以数字开头的行）
            // 再次按行处理，确保完全移除警告行
            if (!jsonContent.isEmpty()) {
                String[] finalLines = jsonContent.split("\n");
                StringBuilder finalCleaned = new StringBuilder();
                boolean jsonStarted = false;
                
                for (String line : finalLines) {
                    String trimmed = line.trim();
                    if (trimmed.isEmpty()) {
                        if (jsonStarted) {
                            finalCleaned.append(line).append("\n");
                        }
                        continue;
                    }
                    
                    // 跳过类似 "[0] is not 'L':" 的行（Python代码输出）
                    // 检查是否是真正的JSON数组开始（即 '[{' 或 '[ ' 后跟JSON对象）
                    if (trimmed.matches("^\\[\\d+\\]\\s+.*") || 
                        trimmed.matches("^\\d+\\]\\s+.*") ||
                        (trimmed.contains("is not") && !trimmed.startsWith("\"") && !trimmed.startsWith("{"))) {
                        continue;
                    }
                    
                    // 检查是否是JSON开始标记：'[' 或 '{'
                    // 但如果是 "[0]" 这种格式，不是真正的JSON开始
                    if ((trimmed.startsWith("[") && !trimmed.matches("^\\[\\d+\\]")) || 
                        trimmed.startsWith("{")) {
                        jsonStarted = true;
                    }
                    
                    if (jsonStarted || trimmed.startsWith("\"")) {
                        finalCleaned.append(line).append("\n");
                    }
                }
                
                jsonContent = finalCleaned.toString().trim();
                
                // 如果还是没有JSON开始标记，强制查找真正的JSON开始位置
                // 真正的JSON数组开始应该是 '[{' 或 '[ "Library"' 等形式
                if (!jsonContent.startsWith("[") && !jsonContent.startsWith("{")) {
                    // 查找第一个真正的JSON开始位置
                    // 即 '[' 后跟 '{' 或空白+换行+'{'
                    int bestStart = -1;
                    for (int i = 0; i < jsonContent.length() - 1; i++) {
                        char c = jsonContent.charAt(i);
                        char nextC = jsonContent.charAt(i + 1);
                        // 检查是否是 "[{" 或 "[ " 后跟有效的JSON内容
                        if (c == '[' && (nextC == '{' || nextC == ' ' || nextC == '\n')) {
                            // 验证后面确实是JSON对象
                            int objStart = i + 1;
                            while (objStart < jsonContent.length() && 
                                   Character.isWhitespace(jsonContent.charAt(objStart))) {
                                objStart++;
                            }
                            if (objStart < jsonContent.length() && jsonContent.charAt(objStart) == '{') {
                                bestStart = i;
                                break;
                            }
                        }
                    }
                    
                    if (bestStart >= 0) {
                        jsonContent = jsonContent.substring(bestStart);
                    } else {
                        // 如果找不到 "[{" 模式，至少找到第一个 '['
                        int firstBracket = jsonContent.indexOf('[');
                        if (firstBracket >= 0) {
                            jsonContent = jsonContent.substring(firstBracket);
                        }
                    }
                }
                
                // 最后再检查一次，移除开头的非JSON行
                if (!jsonContent.isEmpty() && !jsonContent.startsWith("[") && !jsonContent.startsWith("{")) {
                    String[] checkLines = jsonContent.split("\n", 2);
                    if (checkLines.length > 0) {
                        String firstLine = checkLines[0].trim();
                        // 如果第一行不是JSON内容，跳过它
                        if (firstLine.contains("is not") || 
                            firstLine.matches("^\\[\\d+\\]\\s+.*") ||
                            firstLine.matches("^\\d+\\]\\s+.*")) {
                            if (checkLines.length > 1) {
                                jsonContent = checkLines[1].trim();
                            } else {
                                jsonContent = "";
                            }
                        }
                    }
                }
            }
            
            Logger.debug("Cleaned JSON content (length: %d chars, first 500 chars: %s)", 
                jsonContent.length(), 
                jsonContent.length() > 500 ? jsonContent.substring(0, 500) + "..." : jsonContent);
            
            // 解析JSON（使用宽松模式以容忍轻微的格式问题）
            JsonParser parser = new JsonParser();
            JsonArray jsonArray;
            try {
                // 使用JsonReader的宽松模式
                com.google.gson.stream.JsonReader reader = new com.google.gson.stream.JsonReader(
                    new java.io.StringReader(jsonContent));
                reader.setLenient(true);
                JsonElement jsonElement = parser.parse(reader);
                jsonArray = jsonElement.getAsJsonArray();
            } catch (Exception e) {
                // 如果宽松模式也失败，尝试标准解析
                try {
                    jsonArray = parser.parse(jsonContent).getAsJsonArray();
                } catch (Exception e2) {
                    Logger.error("Failed to parse JSON: %s", e2.getMessage());
                    Logger.error("JSON content (first 1000 chars): %s", 
                        jsonContent.length() > 1000 ? jsonContent.substring(0, 1000) : jsonContent);
                    result.setDetected(false);
                    result.setConfidence(0.0);
                    result.setMessage("Failed to parse JSON: " + e2.getMessage());
                    return result;
                }
            }
            
            boolean detected = false;
            double maxSimilarity = 0.0;
            String targetTplName = result.getTplName();
            
            // 遍历检测结果，查找匹配的TPL
            for (JsonElement element : jsonArray) {
                if (!element.isJsonObject()) {
                    continue;
                }
                
                JsonObject libObj = element.getAsJsonObject();
                
                // LiteRadar输出的库名在"Library"字段中（首字母大写）
                // 也尝试其他可能的字段名
                String detectedLibName = null;
                if (libObj.has("Library")) {
                    detectedLibName = libObj.get("Library").getAsString();
                } else if (libObj.has("library")) {
                    detectedLibName = libObj.get("library").getAsString();
                } else if (libObj.has("lib")) {
                    detectedLibName = libObj.get("lib").getAsString();
                } else if (libObj.has("name")) {
                    detectedLibName = libObj.get("name").getAsString();
                } else if (libObj.has("lib_name")) {
                    detectedLibName = libObj.get("lib_name").getAsString();
                } else {
                    // 尝试获取第一个字符串字段作为库名
                    for (Map.Entry<String, JsonElement> entry : libObj.entrySet()) {
                        if (entry.getValue().isJsonPrimitive() && 
                            entry.getValue().getAsJsonPrimitive().isString()) {
                            detectedLibName = entry.getValue().getAsString();
                            break;
                        }
                    }
                }
                
                if (detectedLibName == null || detectedLibName.isEmpty()) {
                    continue;
                }
                
                // 输出检测到的库名（DEBUG级别）
                Logger.debug("LiteRadar detected library: %s", detectedLibName);
                Logger.debug("LiteRadar detected library details: %s", libObj.toString());
                
                // 计算相似度
                if (targetTplName != null && !targetTplName.isEmpty()) {
                    double similarity = calculateSimilarity(targetTplName, detectedLibName);
                    Logger.debug("Similarity between '%s' and '%s': %.6f", 
                        targetTplName, detectedLibName, similarity);
                    
                    // 更新最大相似度（只有相似度 >= 0 才更新，因为 -1.0 表示版本号明确不同）
                    if (similarity >= 0.0 && similarity > maxSimilarity) {
                        maxSimilarity = similarity;
                    }
                    
                    if (similarity >= SIMILARITY_THRESHOLD) {
                        detected = true;
                        Logger.debug("LiteRadar matched TPL: target='%s', detected='%s', similarity=%.6f", 
                            targetTplName, detectedLibName, similarity);
                    } else {
                        // 如果相似度是 -1.0，表示版本号明确不同（如 v4 vs v7），应该输出明确的日志
                        if (similarity == -1.0) {
                            Logger.debug("LiteRadar library '%s' did not match target TPL '%s' (version mismatch, similarity=0.0)", 
                                detectedLibName, targetTplName);
                        } else {
                            Logger.debug("LiteRadar library '%s' did not match target TPL '%s' (similarity=%.6f < threshold=%.6f)", 
                                detectedLibName, targetTplName, similarity, SIMILARITY_THRESHOLD);
                        }
                    }
                } else {
                    // 没有指定TPL名称，只要检测到任何TPL就算检测到
                    detected = true;
                    maxSimilarity = 1.0;
                    Logger.debug("LiteRadar detected library (no target TPL specified): %s", detectedLibName);
                    break;
                }
            }
            
            result.setDetected(detected);
            result.setConfidence(maxSimilarity);
            result.setMessage("LiteRadar detection completed");
            
            Logger.debug("LiteRadar detection result: detected=%s, confidence=%.6f, target_TPL='%s'", 
                detected, maxSimilarity, targetTplName != null ? targetTplName : "N/A");
            
        } catch (Exception e) {
            Logger.error("Failed to parse LiteRadar result: %s", e.getMessage());
            e.printStackTrace();
            result.setDetected(false);
            result.setConfidence(0.0);
            result.setMessage("Failed to parse result: " + e.getMessage());
        }
        
        return result;
    }
    
    /**
     * 计算两个库名的相似度
     * 使用多种启发式方法：编辑距离、包含关系、规范化后的匹配、Android Support Library特殊处理等
     */
    private double calculateSimilarity(String tplName, String detectedLibName) {
        if (tplName == null || detectedLibName == null) {
            return 0.0;
        }
        
        // 先移除TPL名字中的版本号，然后再规范化
        // 例如：'com.android.support.support-v4.22.2.1' -> 'com.android.support.support-v4'
        String tplNameWithoutVersion = removeVersionFromLibName(tplName);
        
        // 规范化库名
        String normalizedTpl = normalizeLibName(tplNameWithoutVersion);
        String normalizedDetected = normalizeLibName(detectedLibName);
        
        // 方法1: 精确匹配（忽略大小写）
        if (normalizedTpl.equalsIgnoreCase(normalizedDetected)) {
            return 1.0;
        }
        
        // 方法2: Android Support Library特殊处理
        // 例如：'com.android.support.support-v4.22.2.1' 和 'Android Support v4' 应该匹配
        // 但如果版本号不同（v4 vs v7），应该直接返回0.0，避免误报
        double supportLibSimilarity = calculateSupportLibrarySimilarity(tplName, detectedLibName);
        
        // 如果Support Library相似度明确为0.0（版本号不同），直接返回，不计算其他方法
        // 这样可以避免核心单词匹配等方法给出高相似度，导致误报
        if (supportLibSimilarity == -1.0) {
            // -1.0 表示版本号明确不同，应该直接返回0.0
            Logger.debug("Support Library version mismatch: tpl='%s', detected='%s', similarity=0.0",
                tplName, detectedLibName);
            return 0.0;
        }
        
        if (supportLibSimilarity > 0.8) {
            Logger.debug("Support Library similarity match: tpl='%s', detected='%s', similarity=%.3f",
                tplName, detectedLibName, supportLibSimilarity);
            return supportLibSimilarity;
        }
        
        // 方法3: 包含关系（改进：考虑关键单词）
        double containSimilarity = calculateContainSimilarity(normalizedTpl, normalizedDetected);
        if (containSimilarity > 0.7) {
            return containSimilarity;
        }
        
        // 方法4: 单词匹配（按分隔符分割后匹配，改进：考虑核心单词）
        double wordSimilarity = calculateWordSimilarity(normalizedTpl, normalizedDetected);
        
        // 方法5: 编辑距离（Levenshtein距离）
        double editDistance = calculateLevenshteinDistance(normalizedTpl.toLowerCase(), 
            normalizedDetected.toLowerCase());
        int maxLen = Math.max(normalizedTpl.length(), normalizedDetected.length());
        if (maxLen == 0) {
            return 1.0;
        }
        double similarityByEdit = 1.0 - (editDistance / maxLen);
        
        // 方法6: 核心单词匹配（提取关键单词进行匹配）
        double coreWordSimilarity = calculateCoreWordSimilarity(normalizedTpl, normalizedDetected);
        
        // 综合相似度：取多个方法的最大值
        // 但如果 Support Library 版本号不匹配（返回0.0），不与其他方法取最大值
        double finalSimilarity = Math.max(Math.max(similarityByEdit, wordSimilarity), 
            Math.max(containSimilarity, coreWordSimilarity));
        
        // 硬编码规则：如果 Support Library 版本号不同（supportLibSimilarity == -1.0），
        // 已经在上面的检查中直接返回0.0，所以这里不需要再处理
        // 但如果 Support Library 都包含 "support" 但版本号不明确（supportLibSimilarity == 0.0），
        // 仍然要降低最终相似度，避免误报
        if (supportLibSimilarity == 0.0 && 
            tplName.toLowerCase().contains("support") && 
            detectedLibName.toLowerCase().contains("support")) {
            // 如果其他方法给出的相似度较高，仍然要降低，因为版本号不明确
            finalSimilarity = Math.min(finalSimilarity, 0.5); // 限制在0.5以下
            Logger.debug("Support Library detected but version unclear, limiting similarity to 0.5: tpl='%s', detected='%s', original=%.3f, limited=%.3f",
                tplName, detectedLibName, Math.max(Math.max(similarityByEdit, wordSimilarity), 
                Math.max(containSimilarity, coreWordSimilarity)), finalSimilarity);
        }
        
        Logger.debug("Similarity calculation: tpl='%s', detected='%s', editDist=%.3f, wordSim=%.3f, containSim=%.3f, coreWordSim=%.3f, final=%.3f",
            tplName, detectedLibName, similarityByEdit, wordSimilarity, containSimilarity, coreWordSimilarity, finalSimilarity);
        
        return finalSimilarity;
    }
    
    /**
     * 计算Android Support Library的特殊相似度
     * 处理类似 'com.android.support.support-v4.22.2.1' 和 'Android Support v4' 的情况
     * 注意：只有当版本号相同或都无版本号时，才认为是同一个库
     */
    private double calculateSupportLibrarySimilarity(String tplName, String detectedLibName) {
        // 提取Support Library的版本号（v4, v7等）
        Pattern supportPattern1 = Pattern.compile("support[-_]?v(\\d+)", Pattern.CASE_INSENSITIVE);
        Pattern supportPattern2 = Pattern.compile("support\\s+v(\\d+)", Pattern.CASE_INSENSITIVE);
        
        Matcher tplMatcher1 = supportPattern1.matcher(tplName);
        Matcher tplMatcher2 = supportPattern2.matcher(tplName);
        String tplVersion = null;
        if (tplMatcher1.find()) {
            tplVersion = tplMatcher1.group(1);
        } else if (tplMatcher2.find()) {
            tplVersion = tplMatcher2.group(1);
        }
        
        Matcher detectedMatcher1 = supportPattern1.matcher(detectedLibName);
        Matcher detectedMatcher2 = supportPattern2.matcher(detectedLibName);
        String detectedVersion = null;
        if (detectedMatcher1.find()) {
            detectedVersion = detectedMatcher1.group(1);
        } else if (detectedMatcher2.find()) {
            detectedVersion = detectedMatcher2.group(1);
        }
        
        // 检查是否都包含"support"
        boolean tplHasSupport = tplName.toLowerCase().contains("support");
        boolean detectedHasSupport = detectedLibName.toLowerCase().contains("support");
        
        if (tplHasSupport && detectedHasSupport) {
            // 情况1：版本号都明确，且相同 -> 高度相似（同一个库）
            if (tplVersion != null && detectedVersion != null) {
                if (tplVersion.equals(detectedVersion)) {
                    return 0.95; // 相同版本号，高度相似
                } else {
                    // 版本号不同，不是同一个库，返回特殊值 -1.0 表示版本号明确不同
                    // 例如：support-v4 和 Support v7 不应匹配
                    // 使用 -1.0 而不是 0.0，以便在 calculateSimilarity 中能够区分
                    // "版本号明确不同" 和 "不是 Support Library"
                    return -1.0; // 明确不同版本，不应匹配，使用 -1.0 来标记
                }
            }
            // 情况2：版本号都明确，但不同 -> 不相似（已在上面的else分支处理）
            
            // 情况3：至少一个没有明确的版本号（例如只有"support"但没有"v4"）
            // 这种情况需要谨慎处理，可能确实没有版本信息，也可能版本信息在其他位置
            // 但我们仍然给予一定的相似度，因为都包含"support"
            if ((tplVersion == null || detectedVersion == null) && 
                !(tplVersion != null && detectedVersion != null)) {
                // 如果一方有版本号，另一方没有，则给予中等相似度
                // 让其他方法（如核心单词匹配）来决定最终相似度
                return 0.75; // 中等相似度，留待其他方法判断
            }
            
            // 情况4：都没有版本号，都是"support" -> 高度相似
            if (tplVersion == null && detectedVersion == null) {
                return 0.90;
            }
        }
        
        return 0.0;
    }
    
    /**
     * 计算包含关系相似度（改进版）
     * 不仅检查包含关系，还检查关键单词的匹配度
     */
    private double calculateContainSimilarity(String normalizedTpl, String normalizedDetected) {
        String tplLower = normalizedTpl.toLowerCase();
        String detectedLower = normalizedDetected.toLowerCase();
        
        // 完全包含关系
        if (tplLower.contains(detectedLower) || detectedLower.contains(tplLower)) {
            // 如果较短的字符串长度占较长的字符串长度的比例高，相似度更高
            int minLen = Math.min(tplLower.length(), detectedLower.length());
            int maxLen = Math.max(tplLower.length(), detectedLower.length());
            if (maxLen > 0) {
                double ratio = (double) minLen / maxLen;
                return 0.75 + ratio * 0.2; // 0.75-0.95之间
            }
            return 0.8;
        }
        
        // 检查关键单词的包含关系
        // 注意：在字符类中，- 必须放在开头或结尾，否则需要转义
        String[] tplWords = tplLower.split("[\\._\\s-]+");
        String[] detectedWords = detectedLower.split("[\\._\\s-]+");
        
        int commonWords = 0;
        for (String tplWord : tplWords) {
            if (tplWord.length() >= 3) { // 只考虑长度>=3的单词（忽略"v4"等短词）
                for (String detectedWord : detectedWords) {
                    if (detectedWord.length() >= 3 && 
                        (tplWord.equals(detectedWord) || tplWord.contains(detectedWord) || detectedWord.contains(tplWord))) {
                        commonWords++;
                        break;
                    }
                }
            }
        }
        
        if (tplWords.length > 0 && detectedWords.length > 0) {
            double wordRatio = (double) commonWords / Math.max(tplWords.length, detectedWords.length);
            if (wordRatio >= 0.5) {
                return 0.7 + wordRatio * 0.2; // 0.7-0.9之间
            }
        }
        
        return 0.0;
    }
    
    /**
     * 计算核心单词相似度
     * 提取关键单词（去除常见前缀、后缀、版本号）进行匹配
     */
    private double calculateCoreWordSimilarity(String normalizedTpl, String normalizedDetected) {
        // 提取核心单词（移除版本号、扩展名、常见前缀后缀）
        // 注意：在字符类中，- 必须放在开头或结尾，否则需要转义
        String[] tplWords = normalizedTpl.split("[\\._\\s-]+");
        String[] detectedWords = normalizedDetected.split("[\\._\\s-]+");
        
        Set<String> tplCoreWords = new HashSet<>();
        Set<String> detectedCoreWords = new HashSet<>();
        
        // 过滤出核心单词（长度>=3，不是版本号、不是常见后缀）
        for (String word : tplWords) {
            word = word.toLowerCase().trim();
            if (word.length() >= 3 && !word.matches("^v\\d+$") && 
                !word.matches("^\\d+$") && !word.matches("^\\d+\\.\\d+.*$")) {
                tplCoreWords.add(word);
            }
        }
        
        for (String word : detectedWords) {
            word = word.toLowerCase().trim();
            if (word.length() >= 3 && !word.matches("^v\\d+$") && 
                !word.matches("^\\d+$") && !word.matches("^\\d+\\.\\d+.*$")) {
                detectedCoreWords.add(word);
            }
        }
        
        if (tplCoreWords.isEmpty() || detectedCoreWords.isEmpty()) {
            return 0.0;
        }
        
        // 计算交集和并集
        int intersection = 0;
        for (String word : tplCoreWords) {
            if (detectedCoreWords.contains(word)) {
                intersection++;
            } else {
                // 也检查部分匹配（例如 "support" 和 "supportv4"）
                for (String detectedWord : detectedCoreWords) {
                    if (word.contains(detectedWord) || detectedWord.contains(word)) {
                        intersection++;
                        break;
                    }
                }
            }
        }
        
        int union = tplCoreWords.size() + detectedCoreWords.size() - intersection;
        if (union == 0) {
            return 0.0;
        }
        
        // Jaccard相似度
        double jaccardSimilarity = (double) intersection / union;
        
        // 如果核心单词匹配度高，给予较高权重
        if (jaccardSimilarity >= 0.5) {
            return 0.7 + jaccardSimilarity * 0.3; // 0.7-1.0之间
        }
        
        return jaccardSimilarity * 0.7; // 0.0-0.35之间
    }
    
    /**
     * 从库名中移除版本号（但保留版本标识如v4, v7等）
     * 例如：'com.android.support.support-v4.22.2.1' -> 'com.android.support.support-v4'
     *       'support-v4.22.2.1' -> 'support-v4'
     *       'library-1.2.3' -> 'library'
     */
    private String removeVersionFromLibName(String libName) {
        if (libName == null || libName.isEmpty()) {
            return libName;
        }
        
        String result = libName;
        
        // 移除文件扩展名（.jar, .aar, .dex等）
        result = result.replaceFirst("\\.[a-z]+$", "");
        
        // 移除版本号模式（如 .22.2.1, -22.2.1, _22.2.1）
        // 但要保留版本标识（如 v4, v7 在 support-v4 中）
        // 先移除数字版本号：.22.2.1, -22.2.1, _22.2.1
        result = result.replaceAll("[-_\\.]\\d+\\.\\d+(?:\\.\\d+)*(?:[-_.]?\\w+)?$", "");
        // 再移除单个点开头的数字版本号（前面已经有分隔符的情况）
        result = result.replaceAll("\\.\\d+\\.\\d+(?:\\.\\d+)*(?:[-_.]?\\w+)?$", "");
        // 移除以点结尾的版本号片段（例如 .RELEASE, .SNAPSHOT）
        result = result.replaceAll("[-_\\.][A-Z]+$", "");
        
        // 保留版本标识（如 support-v4 中的 v4），移除后面的详细版本号
        // 例如：support-v4.22.2.1 -> support-v4（这个已经在上面处理了）
        
        return result.trim();
    }
    
    /**
     * 规范化库名，用于匹配
     */
    private String normalizeLibName(String libName) {
        if (libName == null || libName.isEmpty()) {
            return libName;
        }
        
        String normalized = libName;
        
        // 移除版本号模式
        normalized = normalized.replaceAll("[-_]\\d+\\.\\d+(?:\\.\\d+)*(?:[-_.]?\\w+)?$", "");
        normalized = normalized.replaceAll("\\.\\d+\\.\\d+(?:\\.\\d+)*(?:[-_.]?\\w+)?$", "");
        
        // 移除文件扩展名
        normalized = normalized.replaceFirst("\\.[a-z]+$", "");
        
        // 统一分隔符：将下划线和连字符统一为点
        normalized = normalized.replaceAll("[-_]", ".");
        
        // 移除常见前缀
        normalized = normalized.replaceFirst("^com\\.", "");
        normalized = normalized.replaceFirst("^org\\.", "");
        normalized = normalized.replaceFirst("^android\\.", "");
        
        // 转换为小写并去除首尾空白
        normalized = normalized.toLowerCase().trim();
        
        return normalized;
    }
    
    /**
     * 计算Levenshtein编辑距离
     */
    private int calculateLevenshteinDistance(String s1, String s2) {
        int len1 = s1.length();
        int len2 = s2.length();
        
        int[][] dp = new int[len1 + 1][len2 + 1];
        
        for (int i = 0; i <= len1; i++) {
            dp[i][0] = i;
        }
        for (int j = 0; j <= len2; j++) {
            dp[0][j] = j;
        }
        
        for (int i = 1; i <= len1; i++) {
            for (int j = 1; j <= len2; j++) {
                if (s1.charAt(i - 1) == s2.charAt(j - 1)) {
                    dp[i][j] = dp[i - 1][j - 1];
                } else {
                    dp[i][j] = Math.min(Math.min(dp[i - 1][j], dp[i][j - 1]), dp[i - 1][j - 1]) + 1;
                }
            }
        }
        
        return dp[len1][len2];
    }
    
    /**
     * 计算单词相似度（按分隔符分割后匹配）
     */
    private double calculateWordSimilarity(String s1, String s2) {
        // 注意：在字符类中，- 必须放在开头或结尾，否则需要转义
        String[] words1 = s1.split("[\\._-]");
        String[] words2 = s2.split("[\\._-]");
        
        if (words1.length == 0 || words2.length == 0) {
            return 0.0;
        }
        
        int matches = 0;
        for (String w1 : words1) {
            for (String w2 : words2) {
                if (w1.equalsIgnoreCase(w2) && !w1.isEmpty()) {
                    matches++;
                    break;
                }
            }
        }
        
        // 相似度 = 匹配的单词数 / 平均单词数
        double avgWords = (words1.length + words2.length) / 2.0;
        return avgWords > 0 ? matches / avgWords : 0.0;
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
