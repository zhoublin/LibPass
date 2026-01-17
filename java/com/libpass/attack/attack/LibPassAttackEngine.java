package com.libpass.attack.attack;

import com.libpass.attack.graph.*;
import com.libpass.attack.entropy.GraphEntropyCalculator;
import com.libpass.attack.firefly.*;
import com.libpass.attack.decoupling.TPLDecoupler;
import com.libpass.attack.perturbation.PerturbationApplier;
import com.libpass.attack.perturbation.ModificationLogger;
import com.libpass.attack.apk.APKRepackager;
import com.libpass.attack.detector.TPLDetector;
import com.libpass.attack.detector.DetectionResult;
import com.libpass.attack.util.Logger;
import soot.*;
import soot.options.Options;
import soot.jimple.*;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.*;
import java.util.stream.Collectors;

/**
 * LibPass攻击引擎
 * 端到端攻击流程
 */
public class LibPassAttackEngine {
    private String apkPath;
    private String androidJarPath;
    private String outputDir;
    private Set<SootClass> targetTPLClasses;
    private Scene scene;
    private HeterogeneousGraph graph;
    private FireflyAlgorithm fireflyAlgorithm;
    private GraphEntropyCalculator entropyCalculator;
    private TPLDecoupler decoupler;
    private PerturbationApplier perturbationApplier;
    
    // 攻击模式相关
    private AttackMode attackMode = AttackMode.BLACK_BOX_PLUS; // 默认黑盒Plus攻击
    private TPLDetector detector; // 黑盒攻击模式使用的检测器
    private String tplPath; // TPL文件路径
    private String tplName; // TPL名称
    
    static {
        // 初始化PerturbationApplier的Scene
        // 这将在initializeSoot后设置
    }
    
    // 攻击参数
    private int maxIterations = 100;
    private double targetSuccessRate = 0.90;
    private double mu = 0.5; // 熵平衡系数
    
    public LibPassAttackEngine(String apkPath, String androidJarPath, String outputDir) {
        this.apkPath = apkPath;
        this.androidJarPath = androidJarPath;
        this.outputDir = outputDir;
        this.entropyCalculator = new GraphEntropyCalculator();
        this.fireflyAlgorithm = new FireflyAlgorithm(30, maxIterations);
        this.perturbationApplier = new PerturbationApplier();
    }
    
    /**
     * 初始化Soot环境
     */
    public void initializeSoot() {
        // 禁用Soot内部日志输出（减少干扰）
        // 通过系统属性设置SLF4J SimpleLogger只输出ERROR级别
        System.setProperty("org.slf4j.simpleLogger.log.soot", "error");
        System.setProperty("org.slf4j.simpleLogger.log.soot.toDex", "error");
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "error");
        
        G.reset();
        
        // 确保使用ASM 9.6（支持Java 21）
        try {
            Class<?> asmClassReader = Class.forName("org.objectweb.asm.ClassReader");
            Package asmPackage = asmClassReader.getPackage();
            if (asmPackage != null) {
                String version = asmPackage.getImplementationVersion();
                Logger.debug("ASM version in use: %s", version != null ? version : "unknown");
            }
            asmClassReader.getDeclaredConstructor(byte[].class);
            Logger.debug("ASM ClassReader loaded successfully");
        } catch (Exception e) {
            Logger.warning("Could not verify ASM version: %s", e.getMessage());
        }
        
        Options.v().set_src_prec(Options.src_prec_apk);
        
        // 设置Android JAR路径（必需，否则无法加载基本类）
        String absAndroidJarPath = new File(androidJarPath).getAbsolutePath();
        Options.v().set_android_jars(absAndroidJarPath);
        
        // 获取Java运行时类路径
        String javaHome = System.getProperty("java.home");
        String javaRtPath = findJavaRuntimeClasses(javaHome);
        
        // 设置类路径：只包含 Android JAR 目录和 Java 运行时类
        // 注意：不要将 APK 文件添加到类路径中，否则 Soot 会认为有多个 Android 应用
        // APK 应该通过 set_process_dir 来指定
        String absApkPath = new File(apkPath).getAbsolutePath();
        String sootClasspath = absAndroidJarPath;
        if (javaRtPath != null && !javaRtPath.isEmpty()) {
            sootClasspath = javaRtPath + File.pathSeparator + sootClasspath;
        }
        Options.v().set_soot_classpath(sootClasspath);
        
        // 通过 set_process_dir 指定要处理的 APK（只能是一个）
        Options.v().set_process_dir(Collections.singletonList(absApkPath));
        Options.v().set_whole_program(true);
        Options.v().set_allow_phantom_refs(true);
        Options.v().set_throw_analysis(Options.throw_analysis_dalvik);
        Options.v().set_ignore_resolution_errors(true);
        Options.v().set_wrong_staticness(3);
        Options.v().set_process_multiple_dex(true);
        Options.v().set_include_all(true);
        // 参考参考项目：设置输出格式为dex（直接输出DEX文件，避免class到dex转换）
        // 注意：这里先设置为none，在需要生成时再设置为dex
        Options.v().set_output_format(Options.output_format_none);
        Options.v().set_output_dir(outputDir);
        
        // 对于Java 9+，尝试设置prepend_classpath选项
        // 这会将系统类路径添加到Soot类路径前面，确保能够加载基本类
        try {
            java.lang.reflect.Method prependMethod = null;
            try {
                prependMethod = Options.v().getClass().getMethod("set_prepend_classpath", boolean.class);
                prependMethod.invoke(Options.v(), true);
                Logger.debug("Enabled prepend_classpath option");
            } catch (NoSuchMethodException e) {
                // Soot 4.5.0可能不支持此方法，尝试其他方式
                Logger.debug("prepend_classpath option not available, Soot will use default behavior");
            }
        } catch (Exception e) {
            // 忽略，Soot 4.5.0应该能够自动处理
            Logger.debug("Could not set prepend_classpath: %s", e.getMessage());
        }
        
        Logger.debug("Initializing Soot...");
        Logger.debug("Android JAR: %s", absAndroidJarPath);
        Logger.debug("APK: %s", absApkPath);
        Logger.debug("Java version: %s", System.getProperty("java.version"));
        Logger.debug("Java home: %s", System.getProperty("java.home"));
        Logger.debug("Soot classpath: %s", sootClasspath);
        
        Scene.v().loadNecessaryClasses();
        Scene.v().loadBasicClasses();
        this.scene = Scene.v();
        this.decoupler = new TPLDecoupler(scene);
        this.perturbationApplier = new PerturbationApplier();
        this.perturbationApplier.setScene(scene);
        
        // 参考参考项目：在初始化时设置输出格式为dex并调用runPacks()
        // 这样后续调用writeOutput()时才能正确输出
        Options.v().set_output_format(Options.output_format_dex);
        // 注意：这里不设置输出目录，因为在生成APK时会设置
        // runPacks()会在初始化时处理所有类，但不会输出（因为没有设置输出目录）
        // 或者，我们可以在生成APK时再调用runPacks()，但需要确保类已经被处理
        
        // 暂时不在这里调用runPacks()，因为可能会输出文件
        // 我们在generateAdversarialAPK()中处理
    }
    
    /**
     * 查找Java运行时类路径
     * 对于Java 8及以下：返回rt.jar路径
     * 对于Java 9+：返回null，让Soot自动处理模块系统
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
        // 返回null让Soot自动处理
        Logger.debug("Java 9+ detected, Soot will use module system automatically");
        return null;
    }
    
    /**
     * 设置目标TPL类
     */
    public void setTargetTPL(Set<SootClass> tplClasses) {
        this.targetTPLClasses = tplClasses;
    }
    
    /**
     * 设置攻击模式
     * @param mode 攻击模式（BLACK_BOX或BLACK_BOX_PLUS）
     */
    public void setAttackMode(AttackMode mode) {
        this.attackMode = mode;
    }

    /**
     * 设置TPL检测器（用于黑盒攻击模式）
     * @param detector 检测器
     * @param tplPath TPL文件路径
     * @param tplName TPL名称
     */
    public void setDetector(TPLDetector detector, String tplPath, String tplName) {
        this.detector = detector;
        this.tplPath = tplPath;
        this.tplName = tplName;
        // 如果设置了检测器，自动切换到黑盒模式
        if (detector != null) {
            this.attackMode = AttackMode.BLACK_BOX;
        }
    }
    
    /**
     * 执行攻击
     */
    public AttackResult execute() {
        Logger.debug("=== LibPass Attack Engine ===");
        
        // 1. 解耦TPL（确保扰动范围限制在TPL内）
        Logger.debug("Step 1: Decoupling TPL from app...");
        Set<SootClass> identifiedTPLClasses = decoupler.decoupleTPL(targetTPLClasses);
        Logger.debug("Identified %d TPL classes", identifiedTPLClasses.size());
        
        // 验证：确保只对TPL类进行扰动
        if (identifiedTPLClasses.isEmpty()) {
            Logger.warning("No TPL classes identified. Attack may affect app code.");
            // 如果无法识别TPL类，使用提供的TPL类集合
            identifiedTPLClasses = targetTPLClasses;
        }
        
        // 2. 构建异构图
        Logger.debug("Step 2: Building heterogeneous graph...");
        GraphBuilder graphBuilder = new GraphBuilder(scene);
        this.graph = graphBuilder.buildGraph(identifiedTPLClasses);
        Logger.debug("Graph built: %d nodes", graph.getNodeCount());
        
        // 3. 初始化Firefly算法
        Logger.debug("Step 3: Initializing Firefly algorithm...");
        fireflyAlgorithm.initialize();
        
        // 4. 迭代搜索
        Logger.debug("Step 4: Starting perturbation search (%s mode)...", attackMode);
        AttackResult result = new AttackResult();
        result.setTotalIterations(maxIterations);
        
        // 验证黑盒模式配置
        if (attackMode == AttackMode.BLACK_BOX && (detector == null || tplPath == null || tplName == null)) {
            Logger.warning("Black-box mode requires detector, tplPath, and tplName. Switching to black-box-plus mode.");
            attackMode = AttackMode.BLACK_BOX_PLUS;
        }
        
        String currentApkPath = apkPath; // 保存当前APK路径（黑盒模式需要）
        
        for (int iter = 0; iter < maxIterations; iter++) {
            Logger.debug("Iteration %d/%d", iter + 1, maxIterations);
            
            // 4.1 执行Firefly迭代
            if (attackMode == AttackMode.BLACK_BOX) {
                // 黑盒模式：只更新位置，intensity由检测分数更新
                fireflyAlgorithm.iterateWithoutIntensityUpdate(graph);
            } else {
                // 黑盒Plus模式：使用图熵更新intensity
                fireflyAlgorithm.iterate(graph);
            }
            
            // 4.2 获取最佳firefly
            Firefly best = fireflyAlgorithm.getBestFirefly();
            
            // 4.3 应用扰动（设置日志迭代次数）
            perturbationApplier.setLoggerIteration(iter);
            HeterogeneousGraph perturbedGraph = perturbationApplier.applyPerturbation(
                graph, best, identifiedTPLClasses, scene);
            
            // 打印修改汇总（debug级别）
            ModificationLogger logger = perturbationApplier.getLogger();
            if (logger != null && !logger.getRecords().isEmpty()) {
                Logger.debug("\n%s", logger.generateSummary());
            }
            
            boolean acceptPerturbation = false;
            double evaluationScore = 0.0;
            
            if (attackMode == AttackMode.BLACK_BOX) {
                // 黑盒攻击：使用检测分数指导搜索
                // 注意：applyPerturbation已经修改了Scene，所以直接生成APK即可
                Logger.debug("  [Black-box] Generating adversarial APK for detection...");
                String adversarialApkPath;
                try {
                    adversarialApkPath = generateAdversarialAPK(iter);
                } catch (IOException e) {
                    Logger.error("Error generating adversarial APK: %s", e.getMessage());
                    e.printStackTrace();
                    // 如果生成失败，跳过这次迭代
                    continue;
                }
                
                if (adversarialApkPath != null && new File(adversarialApkPath).exists()) {
                    Logger.debug("  [Black-box] Detecting adversarial APK...");
                    DetectionResult detectionResult = detector.detectTPL(adversarialApkPath, tplPath, tplName);
                    double detectionConfidence = detectionResult.getConfidence();
                    
                    // 将检测结果存储到AttackResult中，避免AutomatedAttackEngine重复检测
                    result.setDetectionResult(detectionResult);
                    
                    Logger.debug("  [Black-box] Detection result: %s (confidence: %.6f)", 
                        detectionResult.isDetected() ? "DETECTED" : "NOT DETECTED", detectionConfidence);
                    
                    // 4.4 使用检测分数更新firefly的intensity
                    // confidence越低，intensity越高（攻击越成功）
                    fireflyAlgorithm.updateIntensityWithDetectionScore(best, detectionConfidence);
                    
                    // 4.5 如果不再被检测到，攻击成功
                    if (!detectionResult.isDetected()) {
                        Logger.debug("  [Black-box] Attack SUCCESS! TPL no longer detected.");
                        this.graph = perturbedGraph;
                        result.setOutputApkPath(adversarialApkPath);
                        result.setSuccessfulIterations(result.getSuccessfulIterations() + 1);
                        result.setBestIteration(iter + 1);
                        acceptPerturbation = true;
                        break; // 攻击成功，退出循环
                    }
                    
                    // 4.6 如果检测分数降低（攻击有效），接受扰动
                    // 检测分数越低越好，所以如果confidence < 0.5（低于阈值），接受扰动
                    if (detectionConfidence < 0.5) {
                        Logger.debug("  [Black-box] Detection confidence decreased, accepting perturbation.");
                        this.graph = perturbedGraph;
                        currentApkPath = adversarialApkPath;
                        result.setSuccessfulIterations(result.getSuccessfulIterations() + 1);
                        acceptPerturbation = true;
                        evaluationScore = 1.0 - detectionConfidence; // 转换为适应度分数
                    } else {
                        Logger.debug("  [Black-box] Detection confidence still high, rejecting perturbation.");
                        evaluationScore = 1.0 - detectionConfidence;
                    }
                } else {
                    Logger.error("  [Black-box] Warning: Failed to generate adversarial APK");
                    // 如果生成APK失败，回退到图熵评估
                    attackMode = AttackMode.BLACK_BOX_PLUS;
                }
            }
            
            if (attackMode == AttackMode.BLACK_BOX_PLUS) {
                // 黑盒Plus攻击：使用图熵指导搜索
                double newEntropy = entropyCalculator.calculateGraphEntropy(perturbedGraph, mu);
                double oldEntropy = entropyCalculator.calculateGraphEntropy(graph, mu);
                
                Logger.debug("  [Black-box] Graph entropy: %.4f -> %.4f", oldEntropy, newEntropy);
                
                // 4.4 如果熵增加，接受扰动
                if (newEntropy > oldEntropy) {
                    this.graph = perturbedGraph;
                    result.setSuccessfulIterations(result.getSuccessfulIterations() + 1);
                    acceptPerturbation = true;
                    evaluationScore = newEntropy;
                } else {
                    evaluationScore = newEntropy;
                }
            }
            
            // 4.7 检查是否达到目标成功率
            double currentSuccessRate = (double) result.getSuccessfulIterations() / (iter + 1);
            if (currentSuccessRate >= targetSuccessRate && acceptPerturbation) {
                Logger.debug("Target success rate achieved: %.2f", currentSuccessRate);
                break;
            }
        }
        
        // 5. 生成最终APK（如果还没有生成）
        if (result.getOutputApkPath() == null) {
            Logger.debug("Step 5: Generating final adversarial APK...");
            String outputApk = generateAdversarialAPK();
            result.setOutputApkPath(outputApk);
        }
        result.setFinalEntropy(entropyCalculator.calculateGraphEntropy(graph, mu));
        
        Logger.debug("=== Attack Complete ===");
        return result;
    }
    
    /**
     * 生成对抗APK（基于当前Scene状态，用于黑盒攻击的迭代检测）
     * @param iteration 迭代次数（用于生成唯一文件名）
     * @return 生成的APK路径
     */
    private String generateAdversarialAPK(int iteration) throws IOException {
        // 如果iteration为-1，表示这是最终输出（从generateAdversarialAPK()调用）
        // 在这种情况下，使用"final"作为迭代标识
        String iterSuffix = (iteration >= 0) ? ("iter_" + iteration) : "final";
        
        // 应用所有修改（确保所有方法体都已加载）
        for (SootClass sc : scene.getApplicationClasses()) {
            if (sc.isPhantom()) continue;
            
            for (SootMethod method : sc.getMethods()) {
                if (!method.isAbstract() && !method.isNative()) {
                    try {
                        if (!method.hasActiveBody()) {
                            method.retrieveActiveBody();
                        }
                    } catch (Exception e) {
                        // 忽略无法加载的方法
                    }
                }
            }
        }
        
        // 重新打包APK（使用迭代次数生成唯一文件名）
        // 参考参考项目：直接输出DEX文件，避免class到dex转换
        String dexOutputDir = outputDir + File.separator + iterSuffix;
            String outputApk = outputDir + File.separator + "adversarial_" + iterSuffix + ".apk";
        
        // 确保输出目录存在
        File dexOutputDirFile = new File(dexOutputDir);
        dexOutputDirFile.mkdirs();
        
        // 参考参考项目：在调用writeOutput()之前，删除输出目录中已存在的APK/DEX文件
        // 因为Soot不会覆盖已存在的文件
        // 注意：Soot在输出APK文件时，会使用原始APK文件的文件名
            Logger.debug("Cleaning output directory: %s", dexOutputDir);
        if (dexOutputDirFile.exists() && dexOutputDirFile.isDirectory()) {
            // 获取原始APK文件名（不带路径）
            String originalApkName = new File(apkPath).getName();
            
            // 删除所有APK和DEX文件
            File[] existingFiles = dexOutputDirFile.listFiles((dir, name) -> 
                name.endsWith(".apk") || name.endsWith(".dex"));
            if (existingFiles != null) {
                for (File existingFile : existingFiles) {
                    Logger.debug("  Deleting existing file: %s", existingFile.getName());
                    if (!existingFile.delete()) {
                        Logger.error("    Warning: Failed to delete %s", existingFile.getName());
                        // 如果删除失败，尝试在退出时删除或重命名
                        existingFile.renameTo(new File(existingFile.getAbsolutePath() + ".old"));
                    }
                }
            }
            
            // 特别检查原始APK文件名对应的文件（Soot可能会使用这个文件名）
            File originalApkFile = new File(dexOutputDirFile, originalApkName);
            if (originalApkFile.exists()) {
                Logger.debug("  Deleting file with original APK name: %s", originalApkName);
                if (!originalApkFile.delete()) {
                    Logger.error("    Warning: Failed to delete %s", originalApkName);
                    originalApkFile.renameTo(new File(originalApkFile.getAbsolutePath() + ".old"));
                }
            }
        }
        
        // 保存当前设置
        int oldFormat = Options.v().output_format();
        String oldOutputDir = Options.v().output_dir();
        
        try {
            // 参考参考项目：设置输出格式为dex（直接输出DEX文件）
            Options.v().set_output_format(Options.output_format_dex);
            Options.v().set_output_dir(dexOutputDir);
            
            Logger.debug("Generating DEX files from Scene (%d classes)...", scene.getApplicationClasses().size());
            Logger.debug("Output format: DEX (%d)", Options.output_format_dex);
            Logger.debug("Output dir: %s", dexOutputDir);
            
            // 参考参考项目：先调用runPacks()处理所有类，然后调用writeOutput()输出
            // 注意：参考项目在SootEnvironment.init()中调用了runPacks()，然后在Main.Run()中调用writeOutput()
            // 但是参考项目的注释说："runPacks的话mergeclass就报错"，所以他们在应用修改后不使用runPacks()
            // 我们这里需要在应用修改后，先处理类（但不使用runPacks()，避免mergeclass错误），然后调用writeOutput()
            
            // 确保所有应用类的方法体都已加载（但跳过native和abstract方法）
            // 这样可以避免在writeOutput()时出现"No method source set"错误
            Logger.debug("Ensuring method bodies are loaded...");
            int loadedMethods = 0;
            int skippedMethods = 0;
            Set<SootMethod> methodsWithoutBody = new HashSet<>(); // 记录无法加载方法体的方法
            
            for (SootClass sc : scene.getApplicationClasses()) {
                if (sc.isPhantom()) continue;
                for (SootMethod method : sc.getMethods()) {
                    if (method.isAbstract() || method.isNative() || method.isPhantom()) {
                        skippedMethods++;
                        continue;
                    }
                    try {
                        if (!method.hasActiveBody()) {
                            method.retrieveActiveBody();
                            loadedMethods++;
                        } else {
                            loadedMethods++;
                        }
                    } catch (Exception e) {
                        // 记录无法加载的方法（通常是库类方法）
                        skippedMethods++;
                        methodsWithoutBody.add(method);
                        Logger.debug("Cannot load method body for: %s (%s)", 
                            method.getSignature(), e.getMessage());
                    }
                }
            }
            Logger.debug("Loaded %d method bodies, skipped %d methods", loadedMethods, skippedMethods);
            
            // 对于无法加载方法体的方法，尝试创建一个空的方法体，避免DEX转换失败
            // 这对于构造函数和其他必需的方法特别重要
            int createdEmptyBodies = 0;
            for (SootMethod method : methodsWithoutBody) {
                try {
                    // 跳过abstract和native方法，它们不应该有方法体
                    if (method.isAbstract() || method.isNative()) {
                        continue;
                    }
                    
                    // 尝试创建一个空的方法体
                    // 对于构造函数，创建一个只调用super()的空方法体
                    // 对于其他方法，创建一个只返回默认值的空方法体
                    Logger.debug("Creating empty body for method without source: %s", 
                        method.getSignature());
                    
                    Body body = Jimple.v().newBody(method);
                    method.setActiveBody(body);
                    
                    // 如果是构造函数，添加super()调用
                    if (method.isConstructor()) {
                        SootClass declaringClass = method.getDeclaringClass();
                        boolean addedSuperCall = false;
                        if (declaringClass.hasSuperclass()) {
                            SootClass superclass = declaringClass.getSuperclass();
                            try {
                                SootMethod superInit = superclass.getMethod("void <init>()");
                                if (superInit != null && superInit.isPublic()) {
                                    // 创建this Local变量（用于super调用）
                                    Local thisLocal = Jimple.v().newLocal("this", declaringClass.getType());
                                    body.getLocals().add(thisLocal);
                                    
                                    // 创建super()调用
                                    InvokeStmt superCall = Jimple.v().newInvokeStmt(
                                        Jimple.v().newSpecialInvokeExpr(
                                            thisLocal,
                                            superInit.makeRef()
                                        )
                                    );
                                    body.getUnits().add(superCall);
                                    addedSuperCall = true;
                                }
                            } catch (Exception e) {
                                // 如果无法找到super构造函数，跳过super调用
                                Logger.debug("Cannot find super constructor for %s: %s", 
                                    declaringClass.getName(), e.getMessage());
                            }
                        }
                        // 注意：在Jimple中，构造函数必须显式地有return语句
                        // 如果无法添加super()调用，至少添加return语句以确保方法体有效
                        if (!addedSuperCall) {
                            // 对于无参数构造函数且无法调用super()的情况，添加return语句
                            ReturnVoidStmt returnVoidStmt = Jimple.v().newReturnVoidStmt();
                            body.getUnits().add(returnVoidStmt);
                        }
                    } else {
                        // 对于非构造函数方法，添加return语句
                        Type returnType = method.getReturnType();
                        if (!returnType.equals(VoidType.v())) {
                            // 有返回值的方法，返回默认值
                            Value defaultValue = getDefaultValueForType(returnType);
                            ReturnStmt returnStmt = Jimple.v().newReturnStmt(defaultValue);
                            body.getUnits().add(returnStmt);
                        } else {
                            // void方法，添加return语句
                            ReturnVoidStmt returnVoidStmt = Jimple.v().newReturnVoidStmt();
                            body.getUnits().add(returnVoidStmt);
                        }
                    }
                    
                    createdEmptyBodies++;
                    Logger.debug("Created empty body for method: %s", method.getSignature());
                } catch (Exception e) {
                    // 如果无法创建方法体，记录警告
                    Logger.warning("Cannot create empty body for method %s: %s", 
                        method.getSignature(), e.getMessage());
                }
            }
            if (createdEmptyBodies > 0) {
                Logger.debug("Created %d empty method bodies for methods without source", 
                    createdEmptyBodies);
            }
            
            // 参考参考项目：使用writeOutput()来输出
            // 注意：writeOutput()可能会根据输出格式生成DEX文件或APK文件
            // 即使某些方法无法加载方法体，writeOutput()也会尝试处理它们
            // 如果遇到异常，我们会捕获并尝试继续
            try {
                Logger.debug("Calling PackManager.writeOutput()...");
                soot.PackManager.v().writeOutput();
                Logger.debug("PackManager.writeOutput() completed successfully");
            } catch (soot.toDex.DexPrinterException e) {
                // 捕获DEX打印异常，如果是因为方法体无法加载，记录警告并继续
                String errorMsg = e.getMessage();
                if (errorMsg != null && errorMsg.contains("No method source set")) {
                    Logger.warning("PackManager.writeOutput() encountered methods without method body: %s", 
                        errorMsg);
                    // 对于无法加载方法体的方法，尝试跳过它们并继续处理其他类
                    // 这可能需要重写writeOutput的逻辑，或者接受某些类无法输出的情况
                    Logger.warning("Some classes may not be included in the output due to missing method bodies");
                    // 抛出异常，让调用者决定如何处理
                    throw new IOException("Failed to generate output files due to missing method bodies: " + 
                        errorMsg, e);
                } else {
                    // 其他类型的DEX打印异常，直接抛出
                    Logger.error("PackManager.writeOutput() failed: %s", e.getMessage());
                    e.printStackTrace();
                    throw new IOException("Failed to generate output files: " + e.getMessage(), e);
                }
            } catch (Exception e) {
                Logger.error("PackManager.writeOutput() failed: %s", e.getMessage());
                e.printStackTrace();
                throw new IOException("Failed to generate output files: " + e.getMessage(), e);
            }
            
            // 验证输出文件是否生成（可能是DEX文件或APK文件）
            // 注意：dexOutputDirFile在前面已经定义了
            File[] dexFiles = dexOutputDirFile.listFiles((dir, name) -> name.endsWith(".dex"));
            File[] apkFiles = dexOutputDirFile.listFiles((dir, name) -> name.endsWith(".apk"));
            
            // 如果生成了APK文件，直接使用它
            if (apkFiles != null && apkFiles.length > 0) {
                Logger.debug("Generated %d APK file(s) (Soot directly generated APK)", apkFiles.length);
                for (File apkFile : apkFiles) {
                    Logger.debug("  - %s (%d bytes)", apkFile.getName(), apkFile.length());
                }
                // 如果生成的APK文件路径就是我们要输出的路径，直接返回
                // 否则，复制到目标位置
                File firstApk = apkFiles[0];
                if (firstApk.getAbsolutePath().equals(new File(outputApk).getAbsolutePath())) {
                    // 文件已经在正确位置
                    return outputApk;
                } else {
                    // 复制第一个APK文件到目标位置
                    File targetApk = new File(outputApk);
                    if (targetApk.exists()) {
                        targetApk.delete();
                    }
                    Files.copy(firstApk.toPath(), targetApk.toPath(), StandardCopyOption.REPLACE_EXISTING);
                    Logger.debug("Copied generated APK to: %s", outputApk);
                    return outputApk;
                }
            } else if (dexFiles != null && dexFiles.length > 0) {
                // 如果生成了DEX文件，需要打包成APK
                Logger.debug("Generated %d DEX file(s)", dexFiles.length);
                for (File dexFile : dexFiles) {
                    Logger.debug("  - %s (%d bytes)", dexFile.getName(), dexFile.length());
                }
                // 继续执行下面的打包逻辑
            } else {
                Logger.warning("No DEX or APK files generated. Checking output directory...");
                Logger.error("Output dir exists: %s", dexOutputDirFile.exists());
                Logger.error("Output dir is directory: %s", dexOutputDirFile.isDirectory());
                if (dexOutputDirFile.exists()) {
                    File[] allFiles = dexOutputDirFile.listFiles();
                    Logger.error("Files in output dir: %s", (allFiles != null ? allFiles.length : 0));
                    if (allFiles != null) {
                        for (File f : allFiles) {
                            Logger.error("  - %s", f.getName());
                        }
                    }
                }
                throw new IOException("No DEX or APK files generated in " + dexOutputDir);
            }
        } finally {
            // 恢复原始输出格式
            if (oldFormat >= 0) {
                Options.v().set_output_format(oldFormat);
            }
            if (oldOutputDir != null && !oldOutputDir.isEmpty()) {
                Options.v().set_output_dir(oldOutputDir);
            }
        }
        
        // 使用生成的DEX文件重新打包APK
        APKRepackager repackager = new APKRepackager(dexOutputDir, outputApk, androidJarPath, apkPath);
        // 注意：APKRepackager需要修改以支持直接从DEX文件打包
        if (repackager.repackageFromDex()) {
            return outputApk;
        } else {
            Logger.warning("APK repackaging failed");
            throw new IOException("Failed to repackage APK from DEX files");
        }
    }
    
    /**
     * 手动生成class文件
     * 当PackManager无法生成class文件时，使用此方法手动遍历Scene并输出类文件
     */
    private void generateClassFilesManually(Scene scene, String classesDir) {
        try {
            Logger.debug("Manually generating class files from Scene...");
            
            // 设置输出目录和格式
            Options.v().set_output_format(Options.output_format_class);
            Options.v().set_output_dir(classesDir);
            
            // 确保所有方法都有active body
            int processedMethods = 0;
            for (SootClass sootClass : scene.getApplicationClasses()) {
                if (!sootClass.isPhantom()) {
                    for (SootMethod method : sootClass.getMethods()) {
                        if (!method.isAbstract() && !method.isNative()) {
                            try {
                                if (!method.hasActiveBody()) {
                                    method.retrieveActiveBody();
                                    processedMethods++;
                                }
                            } catch (Exception e) {
                                // 忽略无法获取body的方法
                            }
                        }
                    }
                }
            }
            Logger.debug("Processed %d methods for class file generation", processedMethods);
            
            // 尝试使用PackManager的输出pack
            try {
                // 获取输出pack并应用
                soot.Pack outputPack = soot.PackManager.v().getPack("wjop");
                if (outputPack != null) {
                    Logger.debug("Found output pack 'wjop', applying...");
                    outputPack.apply();
                } else {
                    // 尝试其他可能的pack名称
                    outputPack = soot.PackManager.v().getPack("wjap");
                    if (outputPack != null) {
                        Logger.debug("Found output pack 'wjap', applying...");
                        outputPack.apply();
                    } else {
                        Logger.warning("Could not find output pack");
                        // 最后尝试：直接调用writeOutput
                        try {
                            java.lang.reflect.Method writeOutputMethod = 
                                soot.PackManager.v().getClass().getMethod("writeOutput");
                            writeOutputMethod.invoke(soot.PackManager.v());
                        } catch (Exception e) {
                            Logger.error("writeOutput method not available: %s", e.getMessage());
                        }
                    }
                }
            } catch (Exception e) {
                Logger.warning("Failed to apply output pack: %s", e.getMessage());
            }
            
            // 验证生成的文件
            File classesDirFile = new File(classesDir);
            int generatedCount = countClassFiles(classesDirFile);
            Logger.debug("Manually generated %d class files", generatedCount);
            
        } catch (Exception e) {
            Logger.error("Error in manual class file generation: %s", e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * 递归计算class文件数量
     */
    private int countClassFiles(File dir) {
        if (!dir.exists() || !dir.isDirectory()) {
            return 0;
        }
        int count = 0;
        File[] files = dir.listFiles();
        if (files != null) {
            for (File file : files) {
                if (file.isDirectory()) {
                    count += countClassFiles(file);
                } else if (file.getName().endsWith(".class")) {
                    count++;
                }
            }
        }
        return count;
    }
    
    /**
     * 生成对抗APK（使用当前图，用于最终输出）
     */
    private String generateAdversarialAPK() {
        // 使用与generateAdversarialAPK(int iteration)相同的逻辑，避免runPacks()导致的方法体加载问题
        // 直接调用generateAdversarialAPK(int)方法，使用迭代次数-1表示最终输出
        try {
            return generateAdversarialAPK(-1);
        } catch (IOException e) {
            Logger.error("Failed to generate adversarial APK: %s", e.getMessage(), e);
            // 如果失败，返回Jimple输出目录
            String jimpleDir = outputDir + File.separator + "jimple";
            return jimpleDir;
        }
    }
    
    public HeterogeneousGraph getGraph() {
        return graph;
    }
    
    public PerturbationApplier getPerturbationApplier() {
        return perturbationApplier;
    }
    
    public void setMaxIterations(int maxIterations) {
        this.maxIterations = maxIterations;
        this.fireflyAlgorithm = new FireflyAlgorithm(30, maxIterations);
    }
    
    public void setTargetSuccessRate(double targetSuccessRate) {
        this.targetSuccessRate = targetSuccessRate;
    }
    
    /**
     * 加载TPL类（从JAR文件）
     */
    public Set<SootClass> loadTPLClasses(String tplPath, String androidJarPath) {
        Set<SootClass> classes = new HashSet<>();
        
        try {
            File tplFile = new File(tplPath);
            String fileName = tplFile.getName();
            String extension = fileName.substring(fileName.lastIndexOf('.') + 1);
            
            if (extension.equals("jar")) {
                // 临时设置Soot以加载TPL JAR
                G.reset();
                Options.v().set_src_prec(Options.src_prec_class);
                Options.v().set_android_jars(androidJarPath);
                Options.v().set_process_dir(Collections.singletonList(tplPath));
                Options.v().set_soot_classpath(androidJarPath + File.pathSeparator + tplPath);
                
                Scene.v().loadNecessaryClasses();
                
                for (SootClass sc : Scene.v().getApplicationClasses()) {
                    if (!sc.isPhantom() && !sc.isJavaLibraryClass()) {
                        classes.add(sc);
                    }
                }
            } else if (extension.equals("dex")) {
                // DEX文件需要先转换为JAR或直接处理
                Logger.error("DEX format TPL loading not fully implemented");
            }
            
        } catch (Exception e) {
            Logger.error("Failed to load TPL classes: %s", e.getMessage());
            e.printStackTrace();
        }
        
        return classes;
    }
    
    /**
     * 为类型获取默认值（用于创建空方法体）
     */
    private Value getDefaultValueForType(Type type) {
        if (type instanceof PrimType) {
            // 基本类型
            if (type.equals(IntType.v()) || type.equals(ByteType.v()) || 
                type.equals(ShortType.v()) || type.equals(CharType.v())) {
                return IntConstant.v(0);
            } else if (type.equals(LongType.v())) {
                return LongConstant.v(0L);
            } else if (type.equals(FloatType.v())) {
                return FloatConstant.v(0.0f);
            } else if (type.equals(DoubleType.v())) {
                return DoubleConstant.v(0.0);
            } else if (type.equals(BooleanType.v())) {
                return IntConstant.v(0); // boolean在JVM中是int
            }
        } else if (type instanceof RefType || type instanceof ArrayType) {
            // 引用类型（对象、数组），返回null
            return NullConstant.v();
        }
        // 默认返回null
        return NullConstant.v();
    }
}
