package com.libpass.attack;

import com.libpass.attack.automation.*;
import com.libpass.attack.detector.*;
import com.libpass.attack.util.Logger;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.*;
import java.nio.file.*;
import java.util.*;

/**
 * 自动化攻击主入口
 * 集成TPL检测工具，实现自动化、批量攻击
 */
public class AutomatedAttackMain {
    
    public static void main(String[] args) {
        // 初始化日志系统
        Logger.initializeFromSystemProperties();
        
        if (args.length < 5) {
            Logger.error("Usage: AutomatedAttackMain <mode> <apk_input|groundtruth_file> <tpl_path|apk_base_dir> <tpl_name|tpl_base_dir> <android_jar_path> <output_dir> [detector_type] [max_iterations] [log_level] [parallel_workers] [attack_mode] [attack_level]");
            Logger.error("Mode 1 (Single/Batch APK Attack):");
            Logger.error("  mode: 'apk'");
            Logger.error("  apk_input: 单个APK文件路径或APK目录（批量攻击）");
            Logger.error("  tpl_path: TPL文件路径（JAR或DEX）");
            Logger.error("  tpl_name: TPL名称");
            Logger.error("  android_jar_path: Android JAR文件路径");
            Logger.error("  output_dir: 输出目录");
            Logger.error("  detector_type: 检测工具类型（LibScan、LibLoom、LibPecker、LibHunter或LiteRadar，默认：LibScan）");
            Logger.error("  max_iterations: 最大迭代次数（默认：100）");
            Logger.error("  log_level: 日志级别 ERROR|WARNING|INFO|DEBUG（默认：INFO）");
            Logger.error("  parallel_workers: 并行工作进程数（默认：1，即串行执行）");
            Logger.error("  attack_mode: 攻击模式 black_box|black_box_plus（默认：black_box）");
            Logger.error("  attack_level: 攻击级别 library_level|version_level（默认：library_level）");
            Logger.error("");
            Logger.error("Mode 2 (GroundTruth Batch Attack):");
            Logger.error("  mode: 'groundtruth'");
            Logger.error("  groundtruth_file: GroundTruth文件路径（格式：apk:tpl1,tpl2,...）");
            Logger.error("  apk_base_dir: APK文件的基础目录");
            Logger.error("  tpl_base_dir: TPL文件的基础目录");
            Logger.error("  android_jar_path: Android JAR文件路径");
            Logger.error("  output_dir: 输出目录");
            Logger.error("  detector_type: 检测工具类型（LibScan、LibLoom、LibPecker、LibHunter或LiteRadar，默认：LibScan）");
            Logger.error("  max_iterations: 最大迭代次数（默认：100）");
            Logger.error("  log_level: 日志级别 ERROR|WARNING|INFO|DEBUG（默认：INFO）");
            Logger.error("  parallel_workers: 并行工作进程数（默认：1，即串行执行；建议：CPU核心数）");
            Logger.error("  attack_mode: 攻击模式 black_box|black_box_plus（默认：black_box）");
            Logger.error("  attack_level: 攻击级别 library_level|version_level（默认：library_level）");
            System.exit(1);
        }
        
        String mode = args[0];
        String input1 = args[1];
        String input2 = args[2];
        String input3 = args[3];
        String androidJarPath = args[4];
        String outputDir = args[5];
        String detectorType = args.length > 6 ? args[6] : "LibScan";
        int maxIterations = args.length > 7 ? Integer.parseInt(args[7]) : 100;
        String logLevel = args.length > 8 ? args[8] : null;
        int parallelWorkers = args.length > 9 ? Integer.parseInt(args[9]) : 1;
        String attackMode = args.length > 10 ? args[10] : "black_box";
        String attackLevel = args.length > 11 ? args[11] : "library_level";
        
        // 设置日志级别（如果指定）
        if (logLevel != null && !logLevel.isEmpty()) {
            Logger.setLogLevel(logLevel);
            Logger.info("Log level set to: %s", logLevel);
        }
        
        try {
            // 创建输出目录
            Files.createDirectories(Paths.get(outputDir));
            
            // 创建检测工具
            TPLDetector detector = createDetector(detectorType);
            if (detector == null) {
                Logger.error("Failed to create detector: %s", detectorType);
                System.exit(1);
            }
            
            // 初始化检测工具
            Map<String, Object> detectorConfig = new HashMap<>();
            
            // 获取项目根目录（假设从src目录运行）
            String projectRoot = System.getProperty("user.dir");
            File projectRootFile = new File(projectRoot);
            
            // 公共配置（所有检测工具共享）
            detectorConfig.put("temp_output_dir", outputDir + "/temp_detection");
            
            // 根据检测工具类型设置不同的配置
            if ("libscan".equalsIgnoreCase(detectorType)) {
                // LibScan配置
                File libScanPathFile = new File(projectRootFile, "TPL_Detectors/LibScan/tool/LibScan.py");
                File libScanToolDirFile = new File(projectRootFile, "TPL_Detectors/LibScan/tool");
                
                detectorConfig.put("libscan_path", libScanPathFile.getAbsolutePath());
                detectorConfig.put("libscan_tool_dir", libScanToolDirFile.getAbsolutePath());
                
                Logger.debug("Detector configuration (LibScan):");
                Logger.debug("  LibScan path: %s", libScanPathFile.getAbsolutePath());
                Logger.debug("  LibScan tool dir: %s", libScanToolDirFile.getAbsolutePath());
                
            } else if ("libloom".equalsIgnoreCase(detectorType)) {
                // LibLoom配置
                File libloomJarFile = new File(projectRootFile, "TPL_Detectors/LIBLOOM/artifacts/LIBLOOM.jar");
                File libloomConfigDirFile = new File(projectRootFile, "TPL_Detectors/LIBLOOM/artifacts/config");
                
                detectorConfig.put("libloom_jar_path", libloomJarFile.getAbsolutePath());
                detectorConfig.put("libloom_config_dir", libloomConfigDirFile.getAbsolutePath());
                
                Logger.debug("Detector configuration (LibLoom):");
                Logger.debug("  LibLoom JAR path: %s", libloomJarFile.getAbsolutePath());
                Logger.debug("  LibLoom config dir: %s", libloomConfigDirFile.getAbsolutePath());
                
            } else if ("libpecker".equalsIgnoreCase(detectorType)) {
                // LibPecker配置
                File libpeckerJarFile = new File(projectRootFile, "TPL_Detectors/LibPecker/LibPecker.jar");
                File libpeckerBinDirFile = new File(projectRootFile, "TPL_Detectors/LibPecker/bin");
                File libpeckerSdkDirFile = new File(projectRootFile, "TPL_Detectors/LibPecker/sdk");
                
                detectorConfig.put("libpecker_jar_path", libpeckerJarFile.getAbsolutePath());
                detectorConfig.put("libpecker_bin_dir", libpeckerBinDirFile.getAbsolutePath());
                detectorConfig.put("libpecker_sdk_dir", libpeckerSdkDirFile.getAbsolutePath());
                
                Logger.debug("Detector configuration (LibPecker):");
                Logger.debug("  LibPecker JAR path: %s", libpeckerJarFile.getAbsolutePath());
                Logger.debug("  LibPecker bin dir: %s", libpeckerBinDirFile.getAbsolutePath());
                Logger.debug("  LibPecker SDK dir: %s", libpeckerSdkDirFile.getAbsolutePath());
                
            } else if ("libhunter".equalsIgnoreCase(detectorType)) {
                // LibHunter配置
                File libHunterPathFile = new File(projectRootFile, "TPL_Detectors/LibHunter/LibHunter/LibHunter.py");
                File libHunterToolDirFile = new File(projectRootFile, "TPL_Detectors/LibHunter/LibHunter");
                
                detectorConfig.put("libhunter_path", libHunterPathFile.getAbsolutePath());
                detectorConfig.put("libhunter_tool_dir", libHunterToolDirFile.getAbsolutePath());
                
                Logger.debug("Detector configuration (LibHunter):");
                Logger.debug("  LibHunter path: %s", libHunterPathFile.getAbsolutePath());
                Logger.debug("  LibHunter tool dir: %s", libHunterToolDirFile.getAbsolutePath());
                
            } else if ("literadar".equalsIgnoreCase(detectorType)) {
                // LiteRadar配置
                File liteRadarPathFile = new File(projectRootFile, "TPL_Detectors/LiteRadar/LiteRadar/literadar.py");
                File liteRadarToolDirFile = new File(projectRootFile, "TPL_Detectors/LiteRadar/LiteRadar");
                
                detectorConfig.put("literadar_path", liteRadarPathFile.getAbsolutePath());
                detectorConfig.put("literadar_tool_dir", liteRadarToolDirFile.getAbsolutePath());
                
                Logger.debug("Detector configuration (LiteRadar):");
                Logger.debug("  LiteRadar path: %s", liteRadarPathFile.getAbsolutePath());
                Logger.debug("  LiteRadar tool dir: %s", liteRadarToolDirFile.getAbsolutePath());
            }
            
            detector.initialize(detectorConfig);
            
            if (!detector.isAvailable()) {
                Logger.error("Detector is not available. Please check configuration.");
                System.exit(1);
            }
            
            // 解析攻击模式
            com.libpass.attack.attack.AttackMode attackModeEnum;
            if ("black_box_plus".equalsIgnoreCase(attackMode)) {
                attackModeEnum = com.libpass.attack.attack.AttackMode.BLACK_BOX_PLUS;
            } else if ("black_box".equalsIgnoreCase(attackMode)) {
                attackModeEnum = com.libpass.attack.attack.AttackMode.BLACK_BOX;
            } else {
                Logger.warning("Unknown attack mode: %s, using default: black_box", attackMode);
                attackModeEnum = com.libpass.attack.attack.AttackMode.BLACK_BOX;
            }
            Logger.info("Attack mode: %s", attackModeEnum.toString());
            
            // 解析攻击级别
            com.libpass.attack.attack.AttackLevel attackLevelEnum;
            if ("version_level".equalsIgnoreCase(attackLevel)) {
                attackLevelEnum = com.libpass.attack.attack.AttackLevel.VERSION_LEVEL;
            } else if ("library_level".equalsIgnoreCase(attackLevel)) {
                attackLevelEnum = com.libpass.attack.attack.AttackLevel.LIBRARY_LEVEL;
            } else {
                Logger.warning("Unknown attack level: %s, using default: library_level", attackLevel);
                attackLevelEnum = com.libpass.attack.attack.AttackLevel.LIBRARY_LEVEL;
            }
            Logger.info("Attack level: %s", attackLevelEnum.toString());
            
            // 创建自动化攻击引擎
            AutomatedAttackEngine engine = new AutomatedAttackEngine(
                androidJarPath, outputDir, detector
            );
            engine.setAttackMode(attackModeEnum);
            engine.setAttackLevel(attackLevelEnum);
            
            // 根据模式执行不同的攻击
            if ("groundtruth".equalsIgnoreCase(mode)) {
                // GroundTruth批量攻击
                String groundTruthFile = input1;
                String apkBaseDir = input2;
                String tplBaseDir = input3;
                
                if (parallelWorkers > 1) {
                    Logger.info("=== GroundTruth Batch Attack (Parallel: %d workers) ===", parallelWorkers);
                    GroundTruthBatchAttackResult batchResult = engine.executeGroundTruthBatchAttackParallel(
                        groundTruthFile, apkBaseDir, tplBaseDir, androidJarPath, 
                        maxIterations, detectorType, parallelWorkers, outputDir
                    );
                    // 输出结果
                    outputGroundTruthBatchResult(batchResult, outputDir);
                } else {
                    Logger.info("=== GroundTruth Batch Attack (Serial) ===");
                    GroundTruthBatchAttackResult batchResult = engine.executeGroundTruthBatchAttack(
                        groundTruthFile, apkBaseDir, tplBaseDir, androidJarPath, maxIterations
                    );
                    // 输出结果
                    outputGroundTruthBatchResult(batchResult, outputDir);
                    engine.printStatistics();
                }
                
            } else if ("apk".equalsIgnoreCase(mode)) {
                // APK攻击模式（单个或批量）
                String apkInput = input1;
                String tplPath = input2;
                String tplName = input3;
                
                // 判断是单个APK还是批量
                File apkInputFile = new File(apkInput);
                if (apkInputFile.isFile() && apkInput.endsWith(".apk")) {
                    // 单个APK攻击
                    Logger.info("=== Single APK Attack ===");
                    AutomatedAttackResult result = engine.executeAutomatedAttack(
                        apkInput, tplPath, tplName, maxIterations
                    );
                    
                    // 输出结果
                    outputAutomatedResult(result, outputDir);
                    engine.printStatistics();
                    
                } else if (apkInputFile.isDirectory()) {
                    // 批量APK攻击
                    if (parallelWorkers > 1) {
                        Logger.info("=== Batch APK Attack (Parallel: %d workers) ===", parallelWorkers);
                        // 查找所有APK文件
                        List<String> apkPaths = findApkFiles(apkInput);
                        Logger.debug("Found %d APK files", apkPaths.size());
                        
                        BatchAttackResult batchResult = engine.executeBatchAttackParallel(
                            apkPaths, tplPath, tplName, maxIterations, detectorType, 
                            parallelWorkers, androidJarPath, outputDir
                        );
                        
                        // 输出结果
                        outputBatchResult(batchResult, outputDir);
                    } else {
                        Logger.info("=== Batch APK Attack (Serial) ===");
                        // 查找所有APK文件
                        List<String> apkPaths = findApkFiles(apkInput);
                        Logger.debug("Found %d APK files", apkPaths.size());
                        
                        BatchAttackResult batchResult = engine.executeBatchAttack(
                            apkPaths, tplPath, tplName, maxIterations
                        );
                        
                        // 输出结果
                        outputBatchResult(batchResult, outputDir);
                        engine.printStatistics();
                    }
                    
                } else {
                    Logger.error("Invalid APK input: %s", apkInput);
                    System.exit(1);
                }
            } else {
                Logger.error("Unknown mode: %s (must be 'apk' or 'groundtruth')", mode);
                System.exit(1);
            }
            
        } catch (Exception e) {
            Logger.error("Error: %s", e.getMessage(), e);
            System.exit(1);
        }
    }
    
    /**
     * 创建检测工具实例
     */
    private static TPLDetector createDetector(String detectorType) {
        switch (detectorType.toLowerCase()) {
            case "libscan":
                return new LibScanDetector();
            case "libloom":
                return new LibLoomDetector();
            case "libpecker":
                return new LibPeckerDetector();
            case "libhunter":
                return new LibHunterDetector();
            case "literadar":
                return new LiteRadarDetector();
            // 可以添加其他检测工具
            // case "libscout":
            //     return new LibScoutDetector();
            // case "libid":
            //     return new LibIDDetector();
            default:
                Logger.error("Unknown detector type: %s", detectorType);
                return null;
        }
    }
    
    /**
     * 查找APK文件
     */
    private static List<String> findApkFiles(String apkDir) {
        List<String> apkPaths = new ArrayList<>();
        File dir = new File(apkDir);
        
        if (dir.exists() && dir.isDirectory()) {
            File[] files = dir.listFiles((d, name) -> name.endsWith(".apk"));
            if (files != null) {
                for (File file : files) {
                    apkPaths.add(file.getAbsolutePath());
                }
            }
        }
        
        return apkPaths;
    }
    
    /**
     * 输出自动化攻击结果
     */
    private static void outputAutomatedResult(AutomatedAttackResult result, String outputDir) 
            throws IOException {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        String json = gson.toJson(result);
        
        File resultFile = new File(outputDir, "automated_attack_result.json");
        try (PrintWriter writer = new PrintWriter(resultFile)) {
            writer.println(json);
        }
        
        Logger.info("\n=== Attack Result ===");
        Logger.info(result.toString());
        Logger.debug("Result saved to: %s", resultFile.getAbsolutePath());
    }
    
    /**
     * 输出批量攻击结果
     */
    private static void outputBatchResult(BatchAttackResult batchResult, String outputDir) 
            throws IOException {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        String json = gson.toJson(batchResult);
        
        File resultFile = new File(outputDir, "batch_attack_result.json");
        try (PrintWriter writer = new PrintWriter(resultFile)) {
            writer.println(json);
        }
        
        Logger.info("\n=== Batch Attack Result ===");
        Logger.info(batchResult.toString());
        Logger.debug("Result saved to: %s", resultFile.getAbsolutePath());
        
        // 输出详细统计
        Logger.info("\n=== Detailed Statistics ===");
        for (AutomatedAttackResult result : batchResult.getResults()) {
            Logger.info("  %s: %s", 
                new File(result.getApkPath()).getName(),
                result.isAttackSuccess() ? "SUCCESS" : "FAILED");
        }
    }
    
    /**
     * 输出GroundTruth批量攻击结果
     */
    private static void outputGroundTruthBatchResult(GroundTruthBatchAttackResult batchResult, 
                                                     String outputDir) throws IOException {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        String json = gson.toJson(batchResult);
        
        File resultFile = new File(outputDir, "groundtruth_batch_attack_result.json");
        try (PrintWriter writer = new PrintWriter(resultFile)) {
            writer.println(json);
        }
        
        Logger.info("\n=== GroundTruth Batch Attack Result ===");
        Logger.info(batchResult.toString());
        Logger.debug("Result saved to: %s", resultFile.getAbsolutePath());
        
        // 输出详细统计信息
        Logger.info("\n=== Summary Statistics ===");
        Logger.info("Total attacks (APK-TPL pairs): %d", batchResult.getTotalAttacks());
        Logger.info("Successful attacks: %d", batchResult.getSuccessCount());
        Logger.info("Failed attacks: %d", batchResult.getFailureCount());
        Logger.info("Success rate: %.2f%%", batchResult.getSuccessRate() * 100);
        Logger.info("Average perturbations for successful attacks: %.2f", 
            batchResult.getAvgSuccessPerturbations());
        Logger.info("Average time for successful attacks: %.2f ms (%.2f seconds)", 
            batchResult.getAvgSuccessTimeMs(), 
            batchResult.getAvgSuccessTimeMs() / 1000.0);
    }
}
