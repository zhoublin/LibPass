package com.libpass.attack.automation;

import com.libpass.attack.attack.LibPassAttackEngine;
import com.libpass.attack.attack.AttackResult;
import com.libpass.attack.detector.*;
import com.libpass.attack.util.Logger;
import soot.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

/**
 * 自动化攻击引擎
 * 集成TPL检测工具，实现自动化、批量攻击
 */
public class AutomatedAttackEngine {
    // 静态锁，用于保护Soot的全局状态（Scene、G等），确保多线程安全
    private static final Object SOOT_LOCK = new Object();
    
    // 任务计数器，为每个攻击任务分配唯一编号（从0开始）
    private static final AtomicInteger taskCounter = new AtomicInteger(0);
    
    private String androidJarPath;
    private String outputBaseDir;
    private TPLDetector detector;
    private Map<String, Object> config;
    private com.libpass.attack.attack.AttackMode attackMode = com.libpass.attack.attack.AttackMode.BLACK_BOX; // 默认黑盒攻击
    private com.libpass.attack.attack.AttackLevel attackLevel = com.libpass.attack.attack.AttackLevel.LIBRARY_LEVEL; // 默认库级别攻击
    
    // 统计信息
    private int totalAttacks = 0;
    private int successfulAttacks = 0;
    private int failedAttacks = 0;
    private List<AttackStatistics> attackStatistics;
    
    public AutomatedAttackEngine(String androidJarPath, String outputBaseDir, 
                                 TPLDetector detector) {
        this.androidJarPath = androidJarPath;
        this.outputBaseDir = outputBaseDir;
        this.detector = detector;
        this.config = new HashMap<>();
        this.attackStatistics = new ArrayList<>();
    }
    
    /**
     * 设置攻击模式
     */
    public void setAttackMode(com.libpass.attack.attack.AttackMode mode) {
        this.attackMode = mode;
    }
    
    /**
     * 设置攻击级别
     */
    public void setAttackLevel(com.libpass.attack.attack.AttackLevel level) {
        this.attackLevel = level;
    }
    
    /**
     * 执行自动化攻击（内部方法，带任务编号）
     */
    private AutomatedAttackResult executeAutomatedAttackInternal(String apkPath, String tplPath, 
            String tplName, int maxIterations, int taskId) {
        long startTime = System.currentTimeMillis();
        String apkName = new File(apkPath).getName();
        
        AutomatedAttackResult result = new AutomatedAttackResult();
        result.setApkPath(apkPath);
        result.setTplPath(tplPath);
        result.setTplName(tplName);
        
        try {
            // 1. 初始检测：检查原始APK是否包含TPL
            Logger.debug("Task #%d: Step 1 - Initial detection...", taskId);
            
            // 验证检测器是否可用
            if (detector == null) {
                Logger.error("Task #%d: Detector is null, cannot perform initial detection", taskId);
                result.setAttackSuccess(false);
                result.setMessage("Detector is null");
                return result;
            }
            
            if (!detector.isAvailable()) {
                Logger.error("Task #%d: Detector is not available, cannot perform initial detection", taskId);
                result.setAttackSuccess(false);
                result.setMessage("Detector is not available");
                return result;
            }
            
            Logger.debug("Task #%d: Calling detector.detectTPL(apk=%s, tpl=%s, tplName=%s)", 
                taskId, apkPath, tplPath, tplName);
            DetectionResult initialDetection = detector.detectTPL(apkPath, tplPath, tplName);
            result.setInitialDetection(initialDetection);
            
            // 提取原始TPL版本（用于版本级攻击）
            String originalTplVersion = extractTPLVersion(tplPath, tplName);
            Logger.debug("Task #%d: Original TPL version: %s", taskId, originalTplVersion != null ? originalTplVersion : "unknown");
            
            // 输出任务输入信息（关键信息）
            Logger.info("Task #%d: APK=%s, TPL=%s, initial_confidence=%.6f", 
                taskId, apkName, tplName, initialDetection.getConfidence());
            
            // 详细记录检测结果（DEBUG级别）
            Logger.debug("Task #%d: Initial detection result: detected=%s, confidence=%.6f, versions=%s, message=%s", 
                taskId, initialDetection.isDetected(), initialDetection.getConfidence(), 
                initialDetection.getDetectedVersions(),
                initialDetection.getMessage() != null ? initialDetection.getMessage() : "null");
            
            // 检查是否需要攻击（根据攻击级别）
            boolean attackNeeded = isAttackNeeded(initialDetection, originalTplVersion);
            if (!attackNeeded) {
                Logger.debug("Task #%d: Attack not necessary (attack level: %s)", taskId, attackLevel);
                result.setAttackSuccess(true);
                result.setFinalDetection(initialDetection);
                long endTime = System.currentTimeMillis();
                Logger.info("Task #%d: SKIPPED (not needed), time=%d ms", taskId, endTime - startTime);
                return result;
            }
            
            // 2. 加载TPL类（用于解耦和扰动范围限制）
            // 注意：loadTPLClasses内部已经使用同步锁保护Soot操作
            Logger.debug("Task #%d: Step 2 - Loading TPL classes...", taskId);
            Set<SootClass> tplClasses;
            synchronized (SOOT_LOCK) {
                tplClasses = loadTPLClasses(tplPath);
            }
            if (tplClasses.isEmpty()) {
                result.setAttackSuccess(false);
                result.setMessage("Failed to load TPL classes");
                long endTime = System.currentTimeMillis();
                Logger.info("Task #%d: FAILED (cannot load TPL classes), time=%d ms", taskId, endTime - startTime);
                return result;
            }
            Logger.debug("Task #%d: Loaded %d TPL classes", taskId, tplClasses.size());
            
            // 3. 执行攻击迭代
            Logger.debug("Task #%d: Starting attack iterations (max: %d)...", taskId, maxIterations);
            String currentApkPath = apkPath;
            boolean attackSuccess = false;
            List<com.libpass.attack.perturbation.ModificationLogger> iterationLoggers = new ArrayList<>();
            
            for (int iter = 0; iter < maxIterations; iter++) {
                // 显示进度条（仅DEBUG级别）
                Logger.debug("Task #%d: Progress %d/%d", taskId, iter + 1, maxIterations);
                
                // 3.1 执行攻击
                // 注意：LibPassAttackEngine内部使用Soot，需要在同步块中初始化
                // 输出目录包含攻击模式和级别，避免不同配置的输出文件冲突
                String modeLevelDir = outputBaseDir + "/" + attackMode.toString() + "_" + attackLevel.toString();
                String iterOutputDir = modeLevelDir + "/iter_" + iter;
                Files.createDirectories(Paths.get(iterOutputDir));
                
                LibPassAttackEngine engine;
                AttackResult attackResult;
                synchronized (SOOT_LOCK) {
                    // 在同步块内创建和初始化引擎，确保Soot状态隔离
                    // 注意：虽然使用了同步，但每个任务的输出目录是独立的，结果仍然可靠
                    engine = new LibPassAttackEngine(
                        currentApkPath, androidJarPath, iterOutputDir
                    );
                    engine.initializeSoot();
                    // 设置目标TPL，确保扰动范围限制在TPL内
                    engine.setTargetTPL(tplClasses);
                    engine.setMaxIterations(1); // 每次迭代只执行一次扰动
                    engine.setTargetSuccessRate(0.90);
                    
                    // 设置攻击模式
                    engine.setAttackMode(this.attackMode);
                    // 黑盒模式需要设置检测器
                    if (this.attackMode == com.libpass.attack.attack.AttackMode.BLACK_BOX) {
                        engine.setDetector(detector, tplPath, tplName);
                    }
                    
                    attackResult = engine.execute();
                    
                    // 保存ModificationLogger用于后续统计扰动类型
                    com.libpass.attack.perturbation.PerturbationApplier perturbationApplier = engine.getPerturbationApplier();
                    if (perturbationApplier != null) {
                        iterationLoggers.add(perturbationApplier.getLogger());
                    } else {
                        iterationLoggers.add(null);
                    }
                }
                result.addIterationResult(attackResult);
                
                // 3.2 获取生成的对抗APK
                String adversarialApkPath = attackResult.getOutputApkPath();
                if (adversarialApkPath == null || !new File(adversarialApkPath).exists()) {
                    Logger.debug("Iteration %d/%d: Failed to generate adversarial APK", iter + 1, maxIterations);
                    continue;
                }
                
                // 3.3 检测对抗APK
                // 如果LibPassAttackEngine已经在黑盒模式下执行了检测，直接使用其结果，避免重复检测
                DetectionResult detection = attackResult.getDetectionResult();
                if (detection == null) {
                    // 黑盒Plus模式或检测结果未设置，需要执行检测
                    Logger.debug("Iteration %d/%d: Detecting adversarial APK...", iter + 1, maxIterations);
                    detection = detector.detectTPL(adversarialApkPath, tplPath, tplName);
                } else {
                    // 黑盒模式下，LibPassAttackEngine已经执行了检测，直接使用结果
                    Logger.debug("Iteration %d/%d: Using detection result from LibPassAttackEngine (black-box mode)", 
                        iter + 1, maxIterations);
                }
                result.addDetectionResult(detection);
                
                // 输出对抗性检测分数（DEBUG级别，最终结果会在方法结束时输出）
                Logger.debug("Task #%d: Iteration %d/%d - confidence=%.6f", 
                    taskId, iter + 1, maxIterations, detection.getConfidence());
                
                // 3.4 检查攻击是否成功（根据攻击级别）
                boolean attackSuccessful = isAttackSuccessful(detection, originalTplVersion);
                if (attackSuccessful) {
                    attackSuccess = true;
                    result.setAttackSuccess(true);
                    result.setFinalDetection(detection);
                    result.setSuccessfulIteration(iter);
                    result.setFinalApkPath(adversarialApkPath);
                    long endTime = System.currentTimeMillis();
                    long timeMs = endTime - startTime;
                    int perturbations = iter + 1;
                    
                    // 收集所有迭代的扰动类型统计（只统计已完成的迭代）
                    Map<String, Integer> perturbationTypes = collectPerturbationTypes(iterationLoggers, iter + 1);
                    
                    // 格式化扰动类型信息
                    String perturbationTypesStr = formatPerturbationTypes(perturbationTypes);
                    
                    // 输出攻击成功的关键信息（包含扰动类型）
                    Logger.info("Task #%d: SUCCESS - final_confidence=%.6f, perturbations=%d, time=%d ms%s", 
                        taskId, detection.getConfidence(), perturbations, timeMs, perturbationTypesStr);
                    break;
                }
                
                // 3.5 如果仍被检测到，继续下一轮攻击
                // 确保使用有效的APK路径
                if (adversarialApkPath != null && new File(adversarialApkPath).exists()) {
                    currentApkPath = adversarialApkPath;
                } else {
                    Logger.warning("Iteration %d/%d: Generated APK path is invalid, keeping previous APK", 
                        iter + 1, maxIterations);
                    // 如果生成的APK路径无效，保持使用当前的APK路径，但攻击可能会失败
                    // 为了避免无限循环，我们跳过后续迭代
                    break;
                }
            }
            
            // 输出攻击失败结果（关键信息）
            if (!attackSuccess) {
                double finalConfidence = result.getDetectionResults().isEmpty() ? 
                    initialDetection.getConfidence() : 
                    result.getDetectionResults().get(result.getDetectionResults().size() - 1).getConfidence();
                long endTime = System.currentTimeMillis();
                long timeMs = endTime - startTime;
                int perturbations = result.getIterationResults().size();
                result.setAttackSuccess(false);
                result.setMessage("Failed to evade detection after " + maxIterations + " iterations");
                
                // 收集所有迭代的扰动类型统计
                Map<String, Integer> perturbationTypes = collectPerturbationTypes(iterationLoggers, perturbations);
                
                // 格式化扰动类型信息
                String perturbationTypesStr = formatPerturbationTypes(perturbationTypes);
                
                // 输出攻击失败的关键信息（包含扰动类型）
                Logger.info("Task #%d: FAILED - final_confidence=%.6f, perturbations=%d, time=%d ms%s", 
                    taskId, finalConfidence, perturbations, timeMs, perturbationTypesStr);
            }
            
            // 4. 记录统计信息
            totalAttacks++;
            if (attackSuccess) {
                successfulAttacks++;
            } else {
                failedAttacks++;
            }
            
            AttackStatistics stats = new AttackStatistics();
            stats.setApkPath(apkPath);
            stats.setTplName(tplName);
            stats.setSuccess(attackSuccess);
            stats.setIterations(result.getIterationResults().size());
            stats.setInitialDetected(initialDetection.isDetected());
            stats.setFinalDetected(result.getFinalDetection() != null ? 
                result.getFinalDetection().isDetected() : false);
            attackStatistics.add(stats);
            
        } catch (Exception e) {
            Logger.error("Task #%d: Error during automated attack: %s", taskId, e.getMessage(), e);
            long endTime = System.currentTimeMillis();
            long timeMs = endTime - startTime;
            result.setAttackSuccess(false);
            result.setMessage("Error: " + e.getMessage());
            failedAttacks++;
            Logger.info("Task #%d: ERROR - time=%d ms", taskId, timeMs);
        }
        
        return result;
    }
    
    /**
     * 执行自动化攻击（公开方法，自动分配任务编号）
     * 
     * @param apkPath 目标APK路径
     * @param tplPath TPL文件路径（JAR或DEX）
     * @param tplName TPL名称
     * @param maxIterations 最大迭代次数
     * @return 攻击结果
     */
    public AutomatedAttackResult executeAutomatedAttack(String apkPath, String tplPath, 
                                                        String tplName, int maxIterations) {
        int taskId = taskCounter.getAndIncrement();
        return executeAutomatedAttackInternal(apkPath, tplPath, tplName, maxIterations, taskId);
    }
    
    /**
     * 批量执行自动化攻击
     */
    public BatchAttackResult executeBatchAttack(List<String> apkPaths, String tplPath, 
                                                String tplName, int maxIterations) {
        Logger.debug("=== Batch Automated Attack ===");
        Logger.debug("APKs: %d", apkPaths.size());
        Logger.debug("TPL: %s", tplName);
        
        BatchAttackResult batchResult = new BatchAttackResult();
        batchResult.setTplName(tplName);
        batchResult.setTotalApks(apkPaths.size());
        
        List<AutomatedAttackResult> results = new ArrayList<>();
        
        for (int i = 0; i < apkPaths.size(); i++) {
            String apkPath = apkPaths.get(i);
            Logger.debug("[%d/%d] Processing: %s", i + 1, apkPaths.size(), apkPath);
            
            AutomatedAttackResult result = executeAutomatedAttack(apkPath, tplPath, tplName, maxIterations);
            results.add(result);
            
            if (result.isAttackSuccess()) {
                batchResult.incrementSuccessCount();
            } else {
                batchResult.incrementFailureCount();
            }
        }
        
        batchResult.setResults(results);
        batchResult.calculateSuccessRate();
        
        return batchResult;
    }
    
    /**
     * 并行批量执行自动化攻击（使用线程池）
     */
    public BatchAttackResult executeBatchAttackParallel(List<String> apkPaths, String tplPath, 
            String tplName, int maxIterations, String detectorType, int parallelWorkers,
            String androidJarPath, String outputDir) {
        Logger.debug("=== Parallel Batch Automated Attack ===");
        Logger.debug("APKs: %d, Workers: %d", apkPaths.size(), parallelWorkers);
        Logger.debug("TPL: %s", tplName);
        
        BatchAttackResult batchResult = new BatchAttackResult();
        batchResult.setTplName(tplName);
        batchResult.setTotalApks(apkPaths.size());
        
        // 创建线程池
        ExecutorService executor = Executors.newFixedThreadPool(parallelWorkers);
        List<Future<AutomatedAttackResult>> futures = new ArrayList<>();
        
        // 提交任务
        for (int i = 0; i < apkPaths.size(); i++) {
            String apkPath = apkPaths.get(i);
            int index = i;
            
            Future<AutomatedAttackResult> future = executor.submit(() -> {
                // 为每个任务创建唯一的输出目录，避免并行执行时冲突
                String apkName = new File(apkPath).getName().replace(".apk", "");
                String taskId = Thread.currentThread().getId() + "_" + System.currentTimeMillis();
                String taskOutputDir = outputDir + "/task_" + index + "_" + apkName + "_" + taskId;
                
                try {
                    // 创建任务专用输出目录
                    Files.createDirectories(Paths.get(taskOutputDir));
                    
                    // 创建任务专用的攻击引擎实例（使用独立输出目录）
                    AutomatedAttackEngine taskEngine = new AutomatedAttackEngine(
                        androidJarPath, taskOutputDir, detector
                    );
                    
                    // 注意：Soot使用静态状态，并行执行可能不完全线程安全
                    // 但通过在每个任务前重置Soot状态（G.reset()），可以降低冲突风险
                    Logger.debug("[%d/%d] Processing: %s (output: %s)", index + 1, apkPaths.size(), 
                        new File(apkPath).getName(), taskOutputDir);
                    return taskEngine.executeAutomatedAttack(apkPath, tplPath, tplName, maxIterations);
                } catch (Exception e) {
                    Logger.error("Error processing APK %s: %s", apkPath, e.getMessage(), e);
                    // 返回失败结果
                    AutomatedAttackResult failedResult = new AutomatedAttackResult();
                    failedResult.setApkPath(apkPath);
                    failedResult.setTplName(tplName);
                    failedResult.setAttackSuccess(false);
                    return failedResult;
                }
            });
            
            futures.add(future);
        }
        
        // 收集结果
        List<AutomatedAttackResult> results = new ArrayList<>();
        for (int i = 0; i < futures.size(); i++) {
            try {
                AutomatedAttackResult result = futures.get(i).get();
                results.add(result);
                
                if (result.isAttackSuccess()) {
                    batchResult.incrementSuccessCount();
                } else {
                    batchResult.incrementFailureCount();
                }
                // 详细结果已在executeAutomatedAttackInternal中输出，这里不重复输出
            } catch (Exception e) {
                Logger.error("Error getting result for APK %d: %s", i + 1, e.getMessage());
                batchResult.incrementFailureCount();
            }
        }
        
        // 关闭线程池
        executor.shutdown();
        try {
            if (!executor.awaitTermination(60, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
        
        batchResult.setResults(results);
        batchResult.calculateSuccessRate();
        
        return batchResult;
    }
    
    /**
     * 加载TPL类
     */
    private Set<SootClass> loadTPLClasses(String tplPath) {
        Set<SootClass> classes = new HashSet<>();
        
        try {
            File tplFile = new File(tplPath);
            String fileName = tplFile.getName();
            String extension = fileName.substring(fileName.lastIndexOf('.') + 1);
            
            if (extension.equals("jar")) {
                // 确保使用ASM 9.6（支持Java 21）
                // 在加载类之前，强制加载ASM 9.6的ClassReader，确保类加载器使用新版本
                try {
                    Class<?> asmClassReader = Class.forName("org.objectweb.asm.ClassReader");
                    Package asmPackage = asmClassReader.getPackage();
                    if (asmPackage != null) {
                        String version = asmPackage.getImplementationVersion();
                        Logger.debug("ASM version in use: %s", version != null ? version : "unknown");
                    }
                    // 预加载ASM类，确保使用新版本
                    asmClassReader.getDeclaredConstructor(byte[].class);
                    Logger.debug("ASM ClassReader loaded successfully");
                } catch (Exception e) {
                    Logger.warning("Could not verify ASM version: %s", e.getMessage());
                }
                
                // 加载JAR文件
                G.reset();
                soot.options.Options.v().set_src_prec(soot.options.Options.src_prec_class);
                
                // 设置Android JAR路径（必需，否则无法加载基本类）
                String absAndroidJarPath = new File(androidJarPath).getAbsolutePath();
                soot.options.Options.v().set_android_jars(absAndroidJarPath);
                
                // 获取Java运行时类路径
                String javaHome = System.getProperty("java.home");
                String javaRtPath = findJavaRuntimeClasses(javaHome);
                
                // 设置类路径：Android JAR + TPL JAR
                // 注意：对于Java 9+，Soot应该能够自动从系统类加载器获取基本类
                String absTplPath = new File(tplPath).getAbsolutePath();
                String sootClasspath = absAndroidJarPath + File.pathSeparator + absTplPath;
                soot.options.Options.v().set_soot_classpath(sootClasspath);
                
                // 设置处理目录
                soot.options.Options.v().set_process_dir(Collections.singletonList(absTplPath));
                
                // 允许phantom引用（某些类可能找不到）
                soot.options.Options.v().set_allow_phantom_refs(true);
                
                // 对于Java 9+，Soot 4.5.0应该能够自动处理模块系统
                // 但为了确保能够加载基本类，尝试设置prepend_classpath选项
                try {
                    // Soot 4.5.0可能支持prepend_classpath选项
                    // 这会将系统类路径添加到Soot类路径前面，确保能够加载基本类
                    java.lang.reflect.Method prependMethod = null;
                    try {
                        prependMethod = soot.options.Options.v().getClass().getMethod("set_prepend_classpath", boolean.class);
                        prependMethod.invoke(soot.options.Options.v(), true);
                        Logger.debug("Enabled prepend_classpath option");
                    } catch (NoSuchMethodException e) {
                        // Soot 4.5.0可能不支持此方法，尝试其他方式
                        Logger.debug("prepend_classpath option not available, Soot will use default behavior");
                    }
                } catch (Exception e) {
                    // 忽略，Soot 4.5.0应该能够自动处理
                    Logger.warning("Could not set prepend_classpath: %s", e.getMessage());
                }
                
                Logger.debug("Loading TPL classes from: %s", absTplPath);
                Logger.debug("Android JAR: %s", absAndroidJarPath);
                Logger.debug("Java version: %s", System.getProperty("java.version"));
                Logger.debug("Java home: %s", System.getProperty("java.home"));
                Logger.debug("Soot classpath: %s", sootClasspath);
                
                Scene.v().loadNecessaryClasses();
                
                int loadedCount = 0;
                for (SootClass sc : Scene.v().getApplicationClasses()) {
                    if (!sc.isPhantom() && !sc.isJavaLibraryClass()) {
                        classes.add(sc);
                        loadedCount++;
                    }
                }
                Logger.debug("Loaded %d TPL classes from JAR", loadedCount);
            } else if (extension.equals("dex")) {
                // DEX文件需要先转换为JAR或直接处理
                // 简化：假设可以通过Soot处理
                // 实际可能需要使用dex2jar
                Logger.error("DEX format TPL loading not fully implemented");
            }
            
        } catch (Exception e) {
            Logger.error("Failed to load TPL classes: %s", e.getMessage(), e);
            e.printStackTrace();
            
            // 输出调试信息
            Logger.error("Android JAR path: %s", androidJarPath);
            Logger.error("TPL path: %s", tplPath);
            File androidJarFile = new File(androidJarPath);
            File tplFile = new File(tplPath);
            Logger.error("Android JAR exists: %s", androidJarFile.exists());
            Logger.error("TPL file exists: %s", tplFile.exists());
        }
        
        return classes;
    }
    
    /**
     * 查找Java运行时类路径
     * 对于Java 8及以下：返回rt.jar路径
     * 对于Java 9+：返回jmods目录或让Soot自动处理
     */
    private String findJavaRuntimeClasses(String javaHome) {
        if (javaHome == null || javaHome.isEmpty()) {
            return null;
        }
        
        File javaHomeFile = new File(javaHome);
        
        // Java 8及以下：查找rt.jar
        File rtJar = new File(javaHomeFile, "jre/lib/rt.jar");
        if (rtJar.exists()) {
            return rtJar.getAbsolutePath();
        }
        
        // 尝试其他可能的路径
        rtJar = new File(javaHomeFile, "lib/rt.jar");
        if (rtJar.exists()) {
            return rtJar.getAbsolutePath();
        }
        
        // Java 9+：Soot应该能够自动处理模块系统
        // 但我们可以尝试添加jmods目录（虽然Soot可能不支持直接使用jmods）
        // 对于Java 9+，Soot 4.5.0应该能够自动从系统类加载器中获取基本类
        // 返回null让Soot自动处理
        Logger.debug("Java 9+ detected, Soot will use module system automatically");
        return null;
    }
    
    /**
     * 获取攻击成功率
     */
    public double getSuccessRate() {
        return totalAttacks > 0 ? (double) successfulAttacks / totalAttacks : 0.0;
    }
    
    /**
     * 获取统计信息
     */
    public List<AttackStatistics> getStatistics() {
        return new ArrayList<>(attackStatistics);
    }
    
    /**
     * 执行基于GroundTruth文件的批量攻击
     * @param groundTruthFile GroundTruth文件路径
     * @param apkBaseDir APK文件的基础目录
     * @param tplBaseDir TPL文件的基础目录
     * @param androidJarPath Android JAR路径
     * @param maxIterations 最大迭代次数
     * @return 批量攻击结果
     */
    public GroundTruthBatchAttackResult executeGroundTruthBatchAttack(
            String groundTruthFile, String apkBaseDir, String tplBaseDir,
            String androidJarPath, int maxIterations) {
        
        GroundTruthBatchAttackResult batchResult = new GroundTruthBatchAttackResult();
        batchResult.setGroundTruthFile(groundTruthFile);
        
        Logger.debug("=== GroundTruth Batch Attack ===");
        Logger.debug("GroundTruth file: %s", groundTruthFile);
        Logger.debug("APK base directory: %s", apkBaseDir);
        Logger.debug("TPL base directory: %s", tplBaseDir);
        
        try {
            // 解析GroundTruth文件
            List<GroundTruthEntry> entries = parseGroundTruthFile(groundTruthFile, apkBaseDir, tplBaseDir);
            Logger.debug("Parsed %d entries from GroundTruth file", entries.size());
            
            int totalCombinations = 0;
            for (GroundTruthEntry entry : entries) {
                totalCombinations += entry.getTplNames().size();
            }
            Logger.debug("Total attack combinations (APK-TPL pairs): %d", totalCombinations);
            
            // 遍历所有APK-TPL组合进行攻击
            int currentCombination = 0;
            for (GroundTruthEntry entry : entries) {
                String apkPath = entry.getApkPath();
                Logger.debug("Processing APK: %s", new File(apkPath).getName());
                
                for (String tplName : entry.getTplNames()) {
                    currentCombination++;
                    
                    // 查找TPL JAR文件
                    String tplPath = findTplJarFile(tplBaseDir, tplName);
                    if (tplPath == null) {
                        Logger.warning("TPL JAR file not found for: %s, skipping...", tplName);
                        continue;
                    }
                    
                    // 显示进度（DEBUG级别）
                    Logger.debug("Processing attack %d/%d: APK=%s, TPL=%s", 
                        currentCombination, totalCombinations,
                        new File(apkPath).getName(), tplName);
                    
                    // 执行攻击（任务编号会在executeAutomatedAttack中自动分配）
                    long startTime = System.currentTimeMillis();
                    AutomatedAttackResult result = executeAutomatedAttack(
                        apkPath, tplPath, tplName, maxIterations
                    );
                    long endTime = System.currentTimeMillis();
                    long timeMs = endTime - startTime;
                    
                    // 添加结果
                    batchResult.addResult(result, timeMs);
                    
                    // 详细结果已在executeAutomatedAttackInternal中输出，这里不重复输出
                }
            }
            
            // 输出统计信息（DEBUG级别）
            Logger.debug("\n=== GroundTruth Batch Attack Statistics ===");
            Logger.debug("Total attacks: %d", batchResult.getTotalAttacks());
            Logger.debug("Successful: %d", batchResult.getSuccessCount());
            Logger.debug("Failed: %d", batchResult.getFailureCount());
            Logger.debug("Success rate: %.2f%%", batchResult.getSuccessRate() * 100);
            Logger.debug("Average perturbations for successful attacks: %.2f", 
                batchResult.getAvgSuccessPerturbations());
            Logger.debug("Average time for successful attacks: %.2f ms", 
                batchResult.getAvgSuccessTimeMs());
            
        } catch (Exception e) {
            Logger.error("Error during groundtruth batch attack: %s", e.getMessage(), e);
            e.printStackTrace();
        }
        
        return batchResult;
    }
    
    /**
     * 并行执行GroundTruth批量攻击（使用线程池）
     */
    public GroundTruthBatchAttackResult executeGroundTruthBatchAttackParallel(
            String groundTruthFile, String apkBaseDir, String tplBaseDir,
            String androidJarPath, int maxIterations, String detectorType, 
            int parallelWorkers, String outputDir) {
        
        GroundTruthBatchAttackResult batchResult = new GroundTruthBatchAttackResult();
        batchResult.setGroundTruthFile(groundTruthFile);
        
        Logger.debug("=== Parallel GroundTruth Batch Attack ===");
        Logger.debug("GroundTruth file: %s", groundTruthFile);
        Logger.debug("Workers: %d", parallelWorkers);
        
        try {
            // 解析GroundTruth文件，收集所有任务
            List<GroundTruthEntry> entries = parseGroundTruthFile(groundTruthFile, apkBaseDir, tplBaseDir);
            Logger.debug("Parsed %d entries from GroundTruth file", entries.size());
            
            // 创建任务列表
            List<AttackTask> tasks = new ArrayList<>();
            for (GroundTruthEntry entry : entries) {
                String apkPath = entry.getApkPath();
                for (String tplName : entry.getTplNames()) {
                    String tplPath = findTplJarFile(tplBaseDir, tplName);
                    if (tplPath != null) {
                        tasks.add(new AttackTask(apkPath, tplPath, tplName));
                    } else {
                        Logger.warning("TPL JAR file not found for: %s, skipping...", tplName);
                    }
                }
            }
            
            int totalTasks = tasks.size();
            Logger.debug("Total attack tasks: %d", totalTasks);
            
            // 创建线程池
            ExecutorService executor = Executors.newFixedThreadPool(parallelWorkers);
            List<Future<TaskResult>> futures = new ArrayList<>();
            
            // 提交任务
            for (int i = 0; i < tasks.size(); i++) {
                AttackTask task = tasks.get(i);
                int index = i;
                
                Future<TaskResult> future = executor.submit(() -> {
                    // 为每个任务创建唯一的输出目录，避免并行执行时冲突
                    String apkName = new File(task.apkPath).getName().replace(".apk", "");
                    String taskId = Thread.currentThread().getId() + "_" + System.currentTimeMillis();
                    String taskOutputDir = outputDir + "/task_" + index + "_" + apkName + "_" + task.tplName + "_" + taskId;
                    
                    try {
                        // 创建任务专用输出目录
                        Files.createDirectories(Paths.get(taskOutputDir));
                        
                        // 创建任务专用的攻击引擎实例（使用独立输出目录）
                        AutomatedAttackEngine taskEngine = new AutomatedAttackEngine(
                            androidJarPath, taskOutputDir, detector
                        );
                        
                        // 注意：Soot使用静态状态，并行执行可能不完全线程安全
                        // 但通过在每个任务前重置Soot状态（G.reset()），可以降低冲突风险
                        // 任务编号会在executeAutomatedAttack中自动分配
                        long taskStartTime = System.currentTimeMillis();
                        AutomatedAttackResult result = taskEngine.executeAutomatedAttack(
                            task.apkPath, task.tplPath, task.tplName, maxIterations
                        );
                        long taskEndTime = System.currentTimeMillis();
                        long timeMs = taskEndTime - taskStartTime;
                        
                        // 详细结果已在executeAutomatedAttackInternal中输出，这里不重复输出
                        // 时间已在executeAutomatedAttackInternal中计算，这里用于统计
                        
                        return new TaskResult(result, timeMs);
                    } catch (Exception e) {
                        Logger.error("Error processing task %d: %s", index + 1, e.getMessage(), e);
                        AutomatedAttackResult failedResult = new AutomatedAttackResult();
                        failedResult.setApkPath(task.apkPath);
                        failedResult.setTplName(task.tplName);
                        failedResult.setAttackSuccess(false);
                        return new TaskResult(failedResult, 0);
                    }
                });
                
                futures.add(future);
            }
            
            // 收集结果
            for (Future<TaskResult> future : futures) {
                try {
                    TaskResult taskResult = future.get();
                    batchResult.addResult(taskResult.result, taskResult.timeMs);
                } catch (Exception e) {
                    Logger.error("Error getting task result: %s", e.getMessage());
                }
            }
            
            // 关闭线程池
            executor.shutdown();
            try {
                if (!executor.awaitTermination(60, TimeUnit.SECONDS)) {
                    executor.shutdownNow();
                }
            } catch (InterruptedException e) {
                executor.shutdownNow();
                Thread.currentThread().interrupt();
            }
            
            // 输出统计信息（DEBUG级别）
            Logger.debug("\n=== Parallel GroundTruth Batch Attack Statistics ===");
            Logger.debug("Total attacks: %d", batchResult.getTotalAttacks());
            Logger.debug("Successful: %d", batchResult.getSuccessCount());
            Logger.debug("Failed: %d", batchResult.getFailureCount());
            Logger.debug("Success rate: %.2f%%", batchResult.getSuccessRate() * 100);
            Logger.debug("Average perturbations for successful attacks: %.2f", 
                batchResult.getAvgSuccessPerturbations());
            Logger.debug("Average time for successful attacks: %.2f ms", 
                batchResult.getAvgSuccessTimeMs());
            
        } catch (Exception e) {
            Logger.error("Error during parallel groundtruth batch attack: %s", e.getMessage(), e);
            e.printStackTrace();
        }
        
        return batchResult;
    }
    
    /**
     * 攻击任务
     */
    private static class AttackTask {
        String apkPath;
        String tplPath;
        String tplName;
        
        AttackTask(String apkPath, String tplPath, String tplName) {
            this.apkPath = apkPath;
            this.tplPath = tplPath;
            this.tplName = tplName;
        }
    }
    
    /**
     * 任务结果
     */
    private static class TaskResult {
        AutomatedAttackResult result;
        long timeMs;
        
        TaskResult(AutomatedAttackResult result, long timeMs) {
            this.result = result;
            this.timeMs = timeMs;
        }
    }
    
    /**
     * 解析GroundTruth文件
     * 格式：apk_name.apk:tpl1,tpl2,tpl3,...
     */
    private List<GroundTruthEntry> parseGroundTruthFile(String groundTruthFile, 
                                                        String apkBaseDir, String tplBaseDir) 
            throws IOException {
        List<GroundTruthEntry> entries = new ArrayList<>();
        
        try (BufferedReader reader = Files.newBufferedReader(Paths.get(groundTruthFile))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) {
                    continue; // 跳过空行和注释
                }
                
                // 解析格式：apk_name.apk:tpl1,tpl2,tpl3,...
                int colonIndex = line.indexOf(':');
                if (colonIndex < 0) {
                    Logger.warning("Invalid groundtruth line format (missing ':'): %s", line);
                    continue;
                }
                
                String apkFileName = line.substring(0, colonIndex).trim();
                String tplListStr = line.substring(colonIndex + 1).trim();
                
                // 构建APK文件路径
                String apkPath = new File(apkBaseDir, apkFileName).getAbsolutePath();
                if (!new File(apkPath).exists()) {
                    Logger.warning("APK file not found: %s, skipping entry...", apkPath);
                    continue;
                }
                
                // 解析TPL名称列表
                String[] tplNames = tplListStr.split(",");
                List<String> tplNameList = new ArrayList<>();
                for (String tplName : tplNames) {
                    String trimmed = tplName.trim();
                    if (!trimmed.isEmpty()) {
                        tplNameList.add(trimmed);
                    }
                }
                
                if (tplNameList.isEmpty()) {
                    Logger.warning("No TPL names found for APK: %s, skipping entry...", apkFileName);
                    continue;
                }
                
                entries.add(new GroundTruthEntry(apkPath, tplNameList));
            }
        }
        
        return entries;
    }
    
    /**
     * 查找TPL JAR文件
     */
    private String findTplJarFile(String tplBaseDir, String tplName) {
        // 尝试多种可能的文件名格式
        String[] possibleNames = {
            tplName + ".jar",
            tplName.replace("-", "_") + ".jar",
            tplName.replace("_", "-") + ".jar"
        };
        
        for (String fileName : possibleNames) {
            String filePath = new File(tplBaseDir, fileName).getAbsolutePath();
            File file = new File(filePath);
            if (file.exists()) {
                return filePath;
            }
        }
        
        // 如果找不到，尝试在目录中搜索（大小写不敏感）
        File baseDir = new File(tplBaseDir);
        if (baseDir.exists() && baseDir.isDirectory()) {
            File[] files = baseDir.listFiles((dir, name) -> 
                name.toLowerCase().endsWith(".jar") && 
                name.toLowerCase().contains(tplName.toLowerCase().replace("-", "").replace("_", ""))
            );
            
            if (files != null && files.length > 0) {
                return files[0].getAbsolutePath();
            }
        }
        
        return null;
    }
    
    /**
     * GroundTruth条目
     */
    private static class GroundTruthEntry {
        private String apkPath;
        private List<String> tplNames;
        
        public GroundTruthEntry(String apkPath, List<String> tplNames) {
            this.apkPath = apkPath;
            this.tplNames = tplNames;
        }
        
        public String getApkPath() {
            return apkPath;
        }
        
        public List<String> getTplNames() {
            return tplNames;
        }
    }
    
    /**
     * 打印进度条
     */
    private void printProgressBar(int current, int total) {
        int barWidth = 50;
        int filled = (int) ((double) current / total * barWidth);
        StringBuilder bar = new StringBuilder();
        bar.append("[");
        for (int i = 0; i < barWidth; i++) {
            if (i < filled) {
                bar.append("=");
            } else if (i == filled) {
                bar.append(">");
            } else {
                bar.append(" ");
            }
        }
        bar.append("]");
        double percentage = (double) current / total * 100;
        Logger.debug("Progress: %s %d/%d (%.1f%%)", bar.toString(), current, total, percentage);
    }
    
    /**
     * 收集所有迭代的扰动类型统计
     */
    private Map<String, Integer> collectPerturbationTypes(
            List<com.libpass.attack.perturbation.ModificationLogger> iterationLoggers, 
            int numIterations) {
        Map<String, Integer> typeCounts = new HashMap<>();
        
        // 统计前numIterations个迭代的扰动类型
        for (int i = 0; i < numIterations && i < iterationLoggers.size(); i++) {
            com.libpass.attack.perturbation.ModificationLogger logger = iterationLoggers.get(i);
            if (logger != null) {
                List<com.libpass.attack.perturbation.ModificationLogger.ModificationRecord> records = 
                    logger.getRecords();
                for (com.libpass.attack.perturbation.ModificationLogger.ModificationRecord record : records) {
                    String typeName = getPerturbationTypeName(record.operation);
                    typeCounts.put(typeName, typeCounts.getOrDefault(typeName, 0) + 1);
                }
            }
        }
        
        return typeCounts;
    }
    
    /**
     * 获取扰动类型的可读名称
     */
    private String getPerturbationTypeName(
            com.libpass.attack.perturbation.ModificationLogger.ModificationRecord.OperationType operation) {
        switch (operation) {
            case ADD_CLASS:
                return "add_class";
            case ADD_METHOD:
                return "add_method";
            case ADD_FIELD:
                return "add_field";
            case ADD_PARAMETER:
                return "add_parameter";
            case ADD_PACKAGE:
                return "add_package";
            case MERGE_CLASS:
                return "merge_class";
            case MERGE_METHOD:
                return "merge_method";
            case MERGE_FIELD:
                return "merge_field";
            case MERGE_PARAMETER:
                return "merge_parameter";
            case MERGE_PACKAGE:
                return "merge_package";
            default:
                return operation.toString().toLowerCase();
        }
    }
    
    /**
     * 从TPL路径或名称中提取版本信息
     * 支持格式：
     * - libname-2.8.6 -> 2.8.6
     * - libname_3.12.0 -> 3.12.0
     * - libname-v7.21.0.3 -> 21.0.3 (注意：v7是库名的一部分，不是版本)
     * - com.android.support.appcompat-v7.21.0.3 -> 21.0.3
     */
    private String extractTPLVersion(String tplPath, String tplName) {
        // 尝试从TPL名称中提取版本（如果名称包含版本信息）
        if (tplName != null && !tplName.isEmpty()) {
            // 首先尝试处理类似 "appcompat-v7.21.0.3" 的情况
            java.util.regex.Pattern vPattern = java.util.regex.Pattern.compile("[-_]v\\d+\\.(\\d+\\.\\d+(?:\\.\\d+)*(?:[-_.]?\\w+)?)$");
            java.util.regex.Matcher vMatcher = vPattern.matcher(tplName);
            if (vMatcher.find()) {
                return vMatcher.group(1);
            }
            
            // 尝试匹配格式：libname-version 或 libname_version 或 libname.version
            String[] separators = {"-", "_", "."};
            for (String sep : separators) {
                int lastIndex = tplName.lastIndexOf(sep);
                if (lastIndex > 0) {
                    String after = tplName.substring(lastIndex + 1);
                    // 检查后面是否是版本号（数字开头）
                    if (after.matches("^\\d.*")) {
                        return after;
                    }
                }
            }
        }
        
        // 尝试从文件路径中提取版本
        if (tplPath != null && !tplPath.isEmpty()) {
            String fileName = new File(tplPath).getName();
            // 移除扩展名
            int lastDot = fileName.lastIndexOf('.');
            if (lastDot > 0) {
                fileName = fileName.substring(0, lastDot);
            }
            
            // 首先尝试处理类似 "appcompat-v7.21.0.3" 的情况
            java.util.regex.Pattern vPattern = java.util.regex.Pattern.compile("[-_]v\\d+\\.(\\d+\\.\\d+(?:\\.\\d+)*(?:[-_.]?\\w+)?)$");
            java.util.regex.Matcher vMatcher = vPattern.matcher(fileName);
            if (vMatcher.find()) {
                return vMatcher.group(1);
            }
            
            // 尝试匹配格式：libname-version 或 libname_version 或 libname.version
            String[] separators = {"-", "_", "."};
            for (String sep : separators) {
                int lastIndex = fileName.lastIndexOf(sep);
                if (lastIndex > 0) {
                    String after = fileName.substring(lastIndex + 1);
                    // 检查后面是否是版本号（数字开头）
                    if (after.matches("^\\d.*")) {
                        return after;
                    }
                }
            }
        }
        
        return null; // 无法提取版本
    }
    
    /**
     * 检查是否需要攻击（根据攻击级别）
     */
    private boolean isAttackNeeded(DetectionResult detection, String originalVersion) {
        if (attackLevel == com.libpass.attack.attack.AttackLevel.LIBRARY_LEVEL) {
            // 库级别攻击：如果未被检测到，不需要攻击（已经成功）
            return detection.isDetected();
        } else if (attackLevel == com.libpass.attack.attack.AttackLevel.VERSION_LEVEL) {
            // 版本级别攻击：如果未被检测到或版本错误，不需要攻击（已经成功）
            if (!detection.isDetected()) {
                // 未被检测到，版本级攻击已经成功，不需要攻击
                return false;
            }
            // 如果检测到了，检查版本是否正确
            // LibScan和LIBLOOM都支持版本级检测，会输出版本候选
            List<String> detectedVersions = detection.getDetectedVersions();
            Logger.debug("Version-level attack check: detected=%s, detectedVersions=%s, originalVersion=%s", 
                detection.isDetected(), detectedVersions, originalVersion);
            
            if (detectedVersions != null && !detectedVersions.isEmpty()) {
                // 有版本信息，检查是否检测到了原始版本
                if (originalVersion != null && !originalVersion.isEmpty()) {
                    boolean hasOriginalVersion = detectedVersions.stream()
                        .anyMatch(v -> v != null && v.equals(originalVersion));
                    Logger.debug("Version-level attack: hasOriginalVersion=%s (detectedVersions=%s, originalVersion=%s)", 
                        hasOriginalVersion, detectedVersions, originalVersion);
                    // 如果检测到了原始版本，需要攻击；如果版本不同，不需要攻击（已经成功）
                    return hasOriginalVersion;
                } else {
                    // 没有原始版本信息，但检测到了且有版本信息
                    // 这种情况可能是输入TPL没有版本号，但检测器输出了版本候选
                    // 对于版本级攻击，如果输入TPL没有版本号，我们无法判断版本是否正确
                    // 应该继续攻击，直到库无法检测到（版本级攻击只要无法检测到就算成功）
                    Logger.debug("Version-level attack: detected with versions %s but no original version, need to attack until undetected", detectedVersions);
                    return true;
                }
            } else {
                // 检测到了但没有版本信息
                // 这种情况可能是检测器不支持版本信息，或者版本信息解析失败
                // 对于版本级攻击，如果检测器不支持版本信息，我们需要继续攻击
                // 直到库无法检测到（版本级攻击只要无法检测到就算成功）
                Logger.debug("Version-level attack: detected but no version info available, need to attack until undetected");
                return true;
            }
        }
        return detection.isDetected(); // 默认使用库级别判断
    }
    
    /**
     * 检查攻击是否成功（根据攻击级别）
     */
    private boolean isAttackSuccessful(DetectionResult detection, String originalVersion) {
        if (attackLevel == com.libpass.attack.attack.AttackLevel.LIBRARY_LEVEL) {
            // 库级别攻击：未被检测到就算成功
            return !detection.isDetected();
        } else if (attackLevel == com.libpass.attack.attack.AttackLevel.VERSION_LEVEL) {
            // 版本级别攻击：无法检测到库也算成功，或者检测到但版本错误也算成功
            if (!detection.isDetected()) {
                // 未被检测到，版本级攻击成功（比库级别更容易）
                return true;
            }
            // 如果检测到了，检查版本是否正确
            // LibScan和LIBLOOM都支持版本级检测，会输出版本候选
            List<String> detectedVersions = detection.getDetectedVersions();
            if (detectedVersions != null && !detectedVersions.isEmpty()) {
                // 有版本信息，检查是否检测到了原始版本
                if (originalVersion != null && !originalVersion.isEmpty()) {
                    boolean hasOriginalVersion = detectedVersions.stream()
                        .anyMatch(v -> v != null && v.equals(originalVersion));
                    // 如果检测到的版本中没有原始版本，攻击成功
                    return !hasOriginalVersion;
                } else {
                    // 没有原始版本信息，但检测到了且有版本信息
                    // 这种情况可能是输入TPL没有版本号，但检测器输出了版本候选
                    // 版本级攻击的目标是让版本错误或无法检测，如果检测到了版本，说明攻击未成功
                    Logger.debug("Version-level attack: detected with versions %s but no original version, attack not successful", detectedVersions);
                    return false;
                }
            } else {
                // 检测到了但没有版本信息
                // 这种情况可能是检测器不支持版本信息，或者版本信息解析失败
                // 版本级攻击的目标是"版本错误或无法检测"，如果检测器不支持版本，我们需要继续攻击
                // 直到库无法检测到（这样更容易成功，因为版本级攻击只要无法检测到就算成功）
                Logger.debug("Version-level attack: detected but no version info available, need to attack until undetected");
                return false;
            }
        }
        // 默认使用库级别判断
        return !detection.isDetected();
    }
    
    /**
     * 格式化扰动类型信息
     */
    private String formatPerturbationTypes(Map<String, Integer> perturbationTypes) {
        if (perturbationTypes.isEmpty()) {
            return "";
        }
        
        // 只显示扰动类型，不显示数量
        List<String> typeStrs = new ArrayList<>();
        for (Map.Entry<String, Integer> entry : perturbationTypes.entrySet()) {
            if (entry.getValue() > 0) {
                typeStrs.add(entry.getKey());
            }
        }
        
        if (typeStrs.isEmpty()) {
            return "";
        }
        
        StringBuilder sb = new StringBuilder(", perturbations=[");
        sb.append(String.join(", ", typeStrs));
        sb.append("]");
        
        return sb.toString();
    }
    
    /**
     * 输出统计报告
     */
    public void printStatistics() {
        Logger.debug("\n=== Attack Statistics ===");
        Logger.debug("Total attacks: %d", totalAttacks);
        Logger.debug("Successful: %d", successfulAttacks);
        Logger.debug("Failed: %d", failedAttacks);
        Logger.debug("Success rate: %.2f%%", getSuccessRate() * 100);
    }
}
