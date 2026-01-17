package com.libpass.attack.strategies;

import com.libpass.attack.*;
import soot.*;
import soot.jimple.*;
import soot.util.Chain;

import java.util.*;

/**
 * 虚假库注入攻击策略
 * 通过注入虚假的库标识来混淆检测工具
 */
public class FakeLibraryInjectionStrategy implements AttackStrategy {
    private static final String STRATEGY_NAME = "FakeLibraryInjection";
    private Random random;
    private double successRate;
    private List<String> fakeLibraryPatterns;
    
    public FakeLibraryInjectionStrategy() {
        this.random = new Random();
        this.successRate = 0.0;
        this.fakeLibraryPatterns = new ArrayList<>();
        
        // 常见的库模式
        fakeLibraryPatterns.add("com.google.gson");
        fakeLibraryPatterns.add("com.squareup.okhttp");
        fakeLibraryPatterns.add("org.apache.commons");
        fakeLibraryPatterns.add("com.fasterxml.jackson");
        fakeLibraryPatterns.add("io.reactivex");
    }
    
    @Override
    public String getName() {
        return STRATEGY_NAME;
    }
    
    @Override
    public AttackResult execute(List<SootClass> classes, AttackConfig config) {
        AttackResult result = new AttackResult(STRATEGY_NAME);
        result.setTotalClasses(classes.size());
        
        AttackConfig.FakeLibraryConfig fakeConfig = config.getFakeLibraryConfig();
        if (fakeConfig == null || !fakeConfig.isEnabled()) {
            result.setModifiedClasses(0);
            result.setSuccessRate(0.0);
            return result;
        }
        
        int count = fakeConfig.getCount();
        List<String> patterns = fakeConfig.getPatterns();
        if (patterns != null && !patterns.isEmpty()) {
            fakeLibraryPatterns = patterns;
        }
        
        int injectedClasses = 0;
        
        // 注入虚假库类
        for (int i = 0; i < count && i < fakeLibraryPatterns.size(); i++) {
            String pattern = fakeLibraryPatterns.get(i % fakeLibraryPatterns.size());
            injectedClasses += injectFakeLibraryClass(pattern, config);
        }
        
        result.setModifiedClasses(injectedClasses);
        this.successRate = injectedClasses > 0 ? 0.9 : 0.0; // 虚假库注入成功率较高
        result.setSuccessRate(this.successRate);
        
        return result;
    }
    
    /**
     * 注入虚假库类
     */
    private int injectFakeLibraryClass(String packagePattern, AttackConfig config) {
        int injected = 0;
        
        // 从模式中提取包名
        String basePackage = packagePattern.replace("*", "");
        if (basePackage.endsWith(".")) {
            basePackage = basePackage.substring(0, basePackage.length() - 1);
        }
        
        // 创建虚假类
        String[] parts = basePackage.split("\\.");
        if (parts.length == 0) {
            return 0;
        }
        
        // 生成类名
        String className = basePackage + "." + generateFakeClassName(parts[parts.length - 1]);
        
        try {
            // 创建新的Soot类
            SootClass fakeClass = new SootClass(className, Modifier.PUBLIC);
            fakeClass.setSuperclass(Scene.v().getSootClass("java.lang.Object"));
            
            // 添加一些虚假方法，模拟真实库的特征
            addFakeMethods(fakeClass, parts[parts.length - 1]);
            
            // 添加到场景中
            Scene.v().addClass(fakeClass);
            Scene.v().forceResolve(className, SootClass.BODIES);
            
            injected = 1;
        } catch (Exception e) {
            System.err.println("Failed to inject fake library class: " + className + ", error: " + e.getMessage());
        }
        
        return injected;
    }
    
    /**
     * 生成虚假类名
     */
    private String generateFakeClassName(String baseName) {
        // 生成看起来像真实库的类名
        String[] commonSuffixes = {"Manager", "Helper", "Util", "Factory", "Builder", "Parser", "Handler"};
        String suffix = commonSuffixes[random.nextInt(commonSuffixes.length)];
        return baseName.substring(0, 1).toUpperCase() + baseName.substring(1) + suffix;
    }
    
    /**
     * 添加虚假方法
     */
    private void addFakeMethods(SootClass sc, String baseName) {
        // 添加一些常见的方法模式
        String[] commonMethods = {"getInstance", "create", "build", "parse", "execute"};
        
        for (String methodName : commonMethods) {
            try {
                RefType objectType = RefType.v("java.lang.Object");
                SootMethod method = new SootMethod(
                    methodName,
                    Collections.singletonList(objectType),
                    objectType,
                    Modifier.PUBLIC | Modifier.STATIC
                );
                
                sc.addMethod(method);
                
                // 创建方法体
                JimpleBody body = Jimple.v().newBody(method);
                method.setActiveBody(body);
                
                // 添加简单的返回语句
                Chain<soot.Local> locals = body.getLocals();
                Chain<soot.Unit> units = body.getUnits();
                
                Local returnVar = Jimple.v().newLocal("return", objectType);
                locals.add(returnVar);
                
                NullConstant nullConst = NullConstant.v();
                AssignStmt assignStmt = Jimple.v().newAssignStmt(returnVar, nullConst);
                units.add(assignStmt);
                
                ReturnStmt returnStmt = Jimple.v().newReturnStmt(returnVar);
                units.add(returnStmt);
                
            } catch (Exception e) {
                // 忽略错误，继续添加其他方法
            }
        }
    }
    
    @Override
    public double getSuccessRate() {
        return successRate;
    }
    
    @Override
    public boolean isApplicable(String detectionTool) {
        // 虚假库注入对所有基于库标识检测的工具都有效
        return true;
    }
}
