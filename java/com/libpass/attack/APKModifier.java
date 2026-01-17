package com.libpass.attack;

import soot.*;
import soot.options.Options;
import soot.jimple.JimpleBody;
import soot.jimple.Stmt;
import soot.util.Chain;
import soot.PackManager;
import soot.Transform;

import java.io.File;
import java.util.*;
import java.util.stream.Collectors;

import com.libpass.attack.util.Logger;
/**
 * APK修改器核心类
 * 使用Soot框架进行APK分析和修改
 */
public class APKModifier {
    private String apkPath;
    private String androidJarPath;
    private String outputDir;
    private Scene scene;
    private List<AttackStrategy> strategies;
    private AttackConfig config;
    
    public APKModifier(String apkPath, String androidJarPath, String outputDir, AttackConfig config) {
        this.apkPath = apkPath;
        this.androidJarPath = androidJarPath;
        this.outputDir = outputDir;
        this.config = config;
        this.strategies = new ArrayList<>();
        initializeSoot();
    }
    
    /**
     * 初始化Soot环境
     */
    private void initializeSoot() {
        G.reset();
        
        Options.v().set_src_prec(Options.src_prec_apk);
        Options.v().set_android_jars(androidJarPath);
        Options.v().set_process_dir(Collections.singletonList(apkPath));
        Options.v().set_whole_program(true);
        Options.v().set_allow_phantom_refs(true);
        Options.v().set_output_format(Options.output_format_jimple);
        Options.v().set_output_dir(outputDir);
        
        // 设置类路径：只包含 Android JAR 目录
        // 注意：不要将 APK 文件添加到类路径中，否则 Soot 会认为有多个 Android 应用
        // APK 应该通过 set_process_dir 来指定
        Options.v().set_soot_classpath(androidJarPath);
        
        Scene.v().loadNecessaryClasses();
        this.scene = Scene.v();
    }
    
    /**
     * 添加攻击策略
     */
    public void addStrategy(AttackStrategy strategy) {
        this.strategies.add(strategy);
    }
    
    /**
     * 执行所有攻击策略
     */
    public List<AttackResult> executeAttacks() {
        List<AttackResult> results = new ArrayList<>();
        
        // 获取所有应用类（排除Android框架类）
        List<SootClass> appClasses = getApplicationClasses();
        
        System.out.println("Found " + appClasses.size() + " application classes");
        
        // 执行每个策略
        for (AttackStrategy strategy : strategies) {
            if (shouldApplyStrategy(strategy)) {
                System.out.println("Executing strategy: " + strategy.getName());
                AttackResult result = strategy.execute(appClasses, config);
                results.add(result);
                System.out.println(result);
            }
        }
        
        return results;
    }
    
    /**
     * 获取应用程序类（排除Android框架和库类）
     */
    private List<SootClass> getApplicationClasses() {
        return scene.getApplicationClasses().stream()
                .filter(cls -> !cls.isJavaLibraryClass())
                .filter(cls -> !cls.isPhantom())
                .filter(cls -> !cls.getName().startsWith("android."))
                .filter(cls -> !cls.getName().startsWith("java."))
                .filter(cls -> !cls.getName().startsWith("javax."))
                .collect(Collectors.toList());
    }
    
    /**
     * 判断是否应该应用该策略
     */
    private boolean shouldApplyStrategy(AttackStrategy strategy) {
        if (config.getTargetTools() == null || config.getTargetTools().isEmpty()) {
            return true;
        }
        
        return config.getTargetTools().stream()
                .anyMatch(strategy::isApplicable);
    }
    
    /**
     * 应用所有修改并生成输出
     */
    public void applyModificationsAndOutput() {
        // 确保所有方法都有body
        for (SootClass sc : scene.getApplicationClasses()) {
            if (sc.isPhantom()) continue;
            
            for (SootMethod method : sc.getMethods()) {
                if (!method.isAbstract() && !method.isNative()) {
                    try {
                        if (!method.hasActiveBody()) {
                            method.retrieveActiveBody();
                        }
                    } catch (Exception e) {
                        // 某些方法可能无法获取body，跳过
                    }
                }
            }
        }
        
        // 输出修改后的代码
        PackManager.v().runPacks();
    }
    
    /**
     * 获取当前场景
     */
    public Scene getScene() {
        return scene;
    }
    
    /**
     * 获取策略列表
     */
    public List<AttackStrategy> getStrategies() {
        return strategies;
    }
}
