package com.libpass.attack;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.libpass.attack.attack.LibPassAttackEngine;
import com.libpass.attack.attack.AttackResult;
import soot.*;
import soot.options.Options;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

import com.libpass.attack.util.Logger;
/**
 * LibPass攻击框架主入口
 * 使用新的攻击引擎（异构图+Firefly算法）
 */
public class LibPassAttackMain {
    private static final String CONFIG_FILE = "config.yaml";
    
    public static void main(String[] args) {
        if (args.length < 3) {
            Logger.error("Usage: LibPassAttackMain <apk_path> <android_jar_path> <output_dir> [tpl_jar_path]");
            Logger.error("  apk_path: 目标APK文件路径");
            Logger.error("  android_jar_path: Android JAR文件路径");
            Logger.error("  output_dir: 输出目录");
            Logger.error("  tpl_jar_path: (可选) 目标TPL的JAR文件路径，用于解耦");
            System.exit(1);
        }
        
        String apkPath = args[0];
        String androidJarPath = args[1];
        String outputDir = args[2];
        String tplJarPath = args.length > 3 ? args[3] : null;
        
        try {
            // 创建输出目录
            Files.createDirectories(Paths.get(outputDir));
            
            // 创建攻击引擎
            LibPassAttackEngine engine = new LibPassAttackEngine(apkPath, androidJarPath, outputDir);
            
            // 初始化Soot
            engine.initializeSoot();
            
            // 加载目标TPL类（如果提供了TPL JAR）
            Set<SootClass> tplClasses = new HashSet<>();
            if (tplJarPath != null && new File(tplJarPath).exists()) {
                Logger.debug("Loading TPL classes from: %s", tplJarPath);
                tplClasses = loadTPLClasses(tplJarPath, androidJarPath);
            } else {
                Logger.info("Warning: No TPL JAR provided. Using all application classes as target.");
                // 如果没有提供TPL，使用所有应用类（简化处理）
                for (SootClass sc : Scene.v().getApplicationClasses()) {
                    if (!sc.isPhantom() && !sc.isJavaLibraryClass()) {
                        tplClasses.add(sc);
                    }
                }
            }
            
            engine.setTargetTPL(tplClasses);
            engine.setMaxIterations(100);
            engine.setTargetSuccessRate(0.90);
            
            // 执行攻击
            AttackResult result = engine.execute();
            
            // 输出结果
            outputResult(result, outputDir);
            
            Logger.info("\n=== Attack Complete ===");
            System.out.println(result);
            
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
    
    /**
     * 加载TPL类
     */
    private static Set<SootClass> loadTPLClasses(String tplJarPath, String androidJarPath) {
        Set<SootClass> classes = new HashSet<>();
        
        try {
            // 临时设置Soot以加载TPL JAR
            G.reset();
            Options.v().set_src_prec(Options.src_prec_class);
            Options.v().set_android_jars(androidJarPath);
            Options.v().set_process_dir(Collections.singletonList(tplJarPath));
            Options.v().set_soot_classpath(androidJarPath + File.pathSeparator + tplJarPath);
            
            Scene.v().loadNecessaryClasses();
            
            for (SootClass sc : Scene.v().getApplicationClasses()) {
                if (!sc.isPhantom() && !sc.isJavaLibraryClass()) {
                    classes.add(sc);
                }
            }
            
            System.out.println("Loaded " + classes.size() + " TPL classes");
        } catch (Exception e) {
            System.err.println("Failed to load TPL classes: " + e.getMessage());
        }
        
        return classes;
    }
    
    /**
     * 输出结果
     */
    private static void outputResult(AttackResult result, String outputDir) throws IOException {
        // 输出JSON格式结果
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        String json = gson.toJson(result);
        
        File resultFile = new File(outputDir, "attack_result.json");
        try (PrintWriter writer = new PrintWriter(resultFile)) {
            writer.println(json);
        }
        
        System.out.println("\nResults saved to: " + resultFile.getAbsolutePath());
    }
}
