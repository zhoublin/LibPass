package com.libpass.attack.decoupling;

import soot.*;
import java.util.*;

/**
 * TPL解耦器
 * 从APK中识别和解耦目标第三方库
 */
public class TPLDecoupler {
    private Scene scene;
    private static final double MATCHING_THRESHOLD = 0.6; // 匹配阈值T
    
    public TPLDecoupler(Scene scene) {
        this.scene = scene;
    }
    
    /**
     * 解耦目标TPL
     * @param tplClasses 目标TPL的类集合（从库文件中提取）
     * @return 在APK中识别出的TPL类集合
     */
    public Set<SootClass> decoupleTPL(Set<SootClass> tplClasses) {
        Set<SootClass> identifiedClasses = new HashSet<>();
        
        // 为TPL类生成签名集
        Map<SootClass, Set<String>> tplSignatures = generateClassSignatures(tplClasses);
        
        // 获取所有应用类
        List<SootClass> appClasses = new ArrayList<>(scene.getApplicationClasses());
        
        // 对每个应用类，与每个TPL类比较
        for (SootClass appClass : appClasses) {
            if (appClass.isPhantom() || appClass.isJavaLibraryClass()) {
                continue;
            }
            
            Set<String> appSignatures = generateClassSignature(appClass);
            
            // 与所有TPL类比较，取最高匹配分数
            double maxScore = 0.0;
            for (Map.Entry<SootClass, Set<String>> entry : tplSignatures.entrySet()) {
                Set<String> tplSig = entry.getValue();
                double score = calculateMatchingScore(appSignatures, tplSig);
                if (score > maxScore) {
                    maxScore = score;
                }
            }
            
            // 如果匹配分数超过阈值，认为是TPL类
            if (maxScore >= MATCHING_THRESHOLD) {
                identifiedClasses.add(appClass);
            }
        }
        
        return identifiedClasses;
    }
    
    /**
     * 生成类的签名集
     */
    private Map<SootClass, Set<String>> generateClassSignatures(Set<SootClass> classes) {
        Map<SootClass, Set<String>> signatures = new HashMap<>();
        for (SootClass sc : classes) {
            signatures.put(sc, generateClassSignature(sc));
        }
        return signatures;
    }
    
    /**
     * 为单个类生成签名集
     */
    private Set<String> generateClassSignature(SootClass sc) {
        Set<String> signatures = new HashSet<>();
        
        // (a) 模糊访问标志
        signatures.add("modifier:" + fuzzifyModifiers(sc.getModifiers()));
        
        // (b) 模糊继承类签名
        if (sc.hasSuperclass()) {
            signatures.add("super:" + fuzzifyType(sc.getSuperclass().getName()));
        }
        
        // (c) 模糊实现的接口签名
        for (SootClass iface : sc.getInterfaces()) {
            signatures.add("interface:" + fuzzifyType(iface.getName()));
        }
        
        // (d) 模糊方法签名
        for (SootMethod method : sc.getMethods()) {
            signatures.add("method:" + fuzzifyMethodSignature(method));
        }
        
        // (e) 模糊字段签名
        for (SootField field : sc.getFields()) {
            signatures.add("field:" + fuzzifyFieldSignature(field));
        }
        
        return signatures;
    }
    
    /**
     * 模糊化修饰符
     */
    private String fuzzifyModifiers(int modifiers) {
        // 简化：只保留关键修饰符
        StringBuilder sb = new StringBuilder();
        if ((modifiers & Modifier.PUBLIC) != 0) sb.append("public,");
        if ((modifiers & Modifier.PRIVATE) != 0) sb.append("private,");
        if ((modifiers & Modifier.PROTECTED) != 0) sb.append("protected,");
        if ((modifiers & Modifier.STATIC) != 0) sb.append("static,");
        if ((modifiers & Modifier.FINAL) != 0) sb.append("final,");
        return sb.toString();
    }
    
    /**
     * 模糊化类型
     */
    private String fuzzifyType(String typeName) {
        // 标准库类型保留，自定义类型模糊化
        if (typeName.startsWith("java.") || typeName.startsWith("android.")) {
            return typeName;
        }
        // 模糊化：只保留包结构，移除类名
        int lastDot = typeName.lastIndexOf('.');
        if (lastDot > 0) {
            return typeName.substring(0, lastDot) + ".*";
        }
        return "*";
    }
    
    /**
     * 模糊化方法签名
     */
    private String fuzzifyMethodSignature(SootMethod method) {
        StringBuilder sb = new StringBuilder();
        sb.append(fuzzifyModifiers(method.getModifiers()));
        sb.append("(");
        for (Type paramType : method.getParameterTypes()) {
            sb.append(fuzzifyType(paramType.toString())).append(",");
        }
        sb.append(")");
        sb.append(fuzzifyType(method.getReturnType().toString()));
        return sb.toString();
    }
    
    /**
     * 模糊化字段签名
     */
    private String fuzzifyFieldSignature(SootField field) {
        return fuzzifyModifiers(field.getModifiers()) + 
               fuzzifyType(field.getType().toString());
    }
    
    /**
     * 计算匹配分数
     */
    private double calculateMatchingScore(Set<String> appSig, Set<String> tplSig) {
        if (tplSig.isEmpty()) {
            return 0.0;
        }
        
        Set<String> intersection = new HashSet<>(appSig);
        intersection.retainAll(tplSig);
        
        return (double) intersection.size() / tplSig.size();
    }
}
