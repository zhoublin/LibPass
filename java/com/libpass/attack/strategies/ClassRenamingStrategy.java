package com.libpass.attack.strategies;

import com.libpass.attack.*;
import soot.*;
import java.util.*;
import com.libpass.attack.util.Logger;

/**
 * 类重命名攻击策略
 * 通过重命名类名来混淆检测工具
 */
public class ClassRenamingStrategy implements AttackStrategy {
    private static final String STRATEGY_NAME = "ClassRenaming";
    private Map<String, String> classMapping;
    private Random random;
    private double successRate;
    
    public ClassRenamingStrategy() {
        this.classMapping = new HashMap<>();
        this.random = new Random();
        this.successRate = 0.0;
    }
    
    @Override
    public String getName() {
        return STRATEGY_NAME;
    }
    
    @Override
    public AttackResult execute(List<SootClass> classes, AttackConfig config) {
        AttackResult result = new AttackResult(STRATEGY_NAME);
        result.setTotalClasses(classes.size());
        
        int modifiedClasses = 0;
        
        for (SootClass sc : classes) {
            if (sc.isPhantom() || sc.getName().startsWith("android.") || sc.getName().startsWith("java.")) {
                continue;
            }
            
            try {
                String oldName = sc.getName();
                String newName = generateNewClassName(oldName, config);
                
                // 在Soot中，类重命名需要通过Transform实现
                // 这里先记录映射关系，实际重命名在输出阶段通过BodyTransformer处理
                // 创建一个新的类名映射，在后续处理中应用
                classMapping.put(oldName, newName);
                Logger.debug("Mapping class: %s -> %s", oldName, newName);
                modifiedClasses++;
            } catch (Exception e) {
                System.err.println("Failed to rename class: " + sc.getName() + ", error: " + e.getMessage());
            }
        }
        
        result.setModifiedClasses(modifiedClasses);
        this.successRate = calculateSuccessRate(modifiedClasses, classes.size());
        result.setSuccessRate(this.successRate);
        
        return result;
    }
    
    /**
     * 生成新的类名
     */
    private String generateNewClassName(String oldName, AttackConfig config) {
        if (classMapping.containsKey(oldName)) {
            return classMapping.get(oldName);
        }
        
        AttackConfig.RenamingConfig renamingConfig = config.getRenamingConfig();
        boolean useRandom = renamingConfig == null || renamingConfig.isUseRandom();
        
        String packageName = "";
        String simpleName = oldName;
        
        int lastDot = oldName.lastIndexOf('.');
        if (lastDot > 0) {
            packageName = oldName.substring(0, lastDot + 1);
            simpleName = oldName.substring(lastDot + 1);
        }
        
        String newSimpleName;
        if (useRandom) {
            newSimpleName = "C" + Math.abs(random.nextInt(100000));
        } else {
            newSimpleName = obfuscateClassName(simpleName);
        }
        
        return packageName + newSimpleName;
    }
    
    /**
     * 混淆类名
     */
    private String obfuscateClassName(String className) {
        // 使用ROT13等简单混淆
        StringBuilder obfuscated = new StringBuilder();
        for (char c : className.toCharArray()) {
            if (Character.isUpperCase(c)) {
                obfuscated.append((char) ('A' + (c - 'A' + 13) % 26));
            } else if (Character.isLowerCase(c)) {
                obfuscated.append((char) ('a' + (c - 'a' + 13) % 26));
            } else {
                obfuscated.append(c);
            }
        }
        return obfuscated.toString();
    }
    
    private double calculateSuccessRate(int modified, int total) {
        return total > 0 ? (double) modified / total : 0.0;
    }
    
    @Override
    public double getSuccessRate() {
        return successRate;
    }
    
    @Override
    public boolean isApplicable(String detectionTool) {
        return true;
    }
}
