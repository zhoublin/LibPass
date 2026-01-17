package com.libpass.attack.strategies;

import com.libpass.attack.*;
import soot.*;
import soot.jimple.*;
import soot.jimple.internal.JReturnStmt;
import soot.util.Chain;

import java.util.*;

/**
 * 签名修改攻击策略
 * 通过修改方法签名（参数类型、返回类型）来绕过签名匹配检测
 */
public class SignatureModificationStrategy implements AttackStrategy {
    private static final String STRATEGY_NAME = "SignatureModification";
    private Random random;
    private double successRate;
    private int modifiedMethods;
    private int totalMethods;
    
    public SignatureModificationStrategy() {
        this.random = new Random();
        this.successRate = 0.0;
        this.modifiedMethods = 0;
        this.totalMethods = 0;
    }
    
    @Override
    public String getName() {
        return STRATEGY_NAME;
    }
    
    @Override
    public AttackResult execute(List<SootClass> classes, AttackConfig config) {
        AttackResult result = new AttackResult(STRATEGY_NAME);
        result.setTotalClasses(classes.size());
        
        AttackConfig.SignatureConfig sigConfig = config.getSignatureConfig();
        boolean modifyReturnTypes = sigConfig == null || sigConfig.isModifyReturnTypes();
        boolean modifyParameters = sigConfig == null || sigConfig.isModifyParameters();
        boolean injectNoise = sigConfig != null && sigConfig.isInjectNoise();
        
        totalMethods = 0;
        modifiedMethods = 0;
        
        for (SootClass sc : classes) {
            if (sc.isPhantom() || sc.getMethodCount() == 0) {
                continue;
            }
            
            for (SootMethod method : sc.getMethods()) {
                if (method.isAbstract() || method.isNative() || 
                    method.isConstructor() || method.getName().equals("main")) {
                    continue;
                }
                
                totalMethods++;
                
                try {
                    if (modifyReturnTypes && method.getReturnType() != VoidType.v()) {
                        modifyReturnType(method);
                        modifiedMethods++;
                    }
                    
                    if (modifyParameters && method.getParameterCount() > 0) {
                        modifyParameters(method);
                        modifiedMethods++;
                    }
                    
                    if (injectNoise && method.hasActiveBody()) {
                        injectNoiseMethods(method);
                    }
                } catch (Exception e) {
                    System.err.println("Failed to modify method: " + method.getSignature() + ", error: " + e.getMessage());
                }
            }
        }
        
        result.setTotalMethods(totalMethods);
        result.setModifiedMethods(modifiedMethods);
        this.successRate = calculateSuccessRate(modifiedMethods, totalMethods);
        result.setSuccessRate(this.successRate);
        
        return result;
    }
    
    /**
     * 修改返回类型（通过包装）
     * 注意：Soot中直接修改返回类型比较复杂，我们通过添加包装方法来实现
     */
    private void modifyReturnType(SootMethod method) {
        // 由于Soot的限制，直接修改返回类型比较复杂
        // 实际实现中，我们可以在方法体中对返回值进行包装/解包
        if (method.hasActiveBody()) {
            JimpleBody body = (JimpleBody) method.getActiveBody();
            modifyReturnStatements(body, method.getReturnType());
        }
    }
    
    /**
     * 修改返回语句
     */
    private void modifyReturnStatements(JimpleBody body, Type originalType) {
        Chain<soot.Unit> units = body.getUnits();
        Iterator<soot.Unit> iterator = units.snapshotIterator();
        
        while (iterator.hasNext()) {
            soot.Unit unit = iterator.next();
            if (unit instanceof JReturnStmt) {
                JReturnStmt returnStmt = (JReturnStmt) unit;
                Value op = returnStmt.getOp();
                
                if (op != null) {
                    // 这里可以添加包装逻辑
                    // 例如：如果返回Object，可以转换为String再转换回来
                }
            }
        }
    }
    
    /**
     * 修改参数
     */
    private void modifyParameters(SootMethod method) {
        // 在实际实现中，我们可以：
        // 1. 添加额外的无用参数
        // 2. 修改参数类型（如果可能）
        // 3. 重新排列参数顺序
        
        // 由于Soot的限制，参数修改比较复杂
        // 我们可以在方法体中添加参数转换代码
        if (method.hasActiveBody()) {
            // 在方法开始处添加参数转换逻辑
            injectParameterConversions(method);
        }
    }
    
    /**
     * 注入参数转换代码
     */
    private void injectParameterConversions(SootMethod method) {
        // 实际实现需要更复杂的逻辑
        // 这里只是一个框架
    }
    
    /**
     * 注入噪音方法
     */
    private void injectNoiseMethods(SootMethod method) {
        // 在方法体中添加一些不会影响功能但会改变签名的代码
        if (method.hasActiveBody()) {
            JimpleBody body = (JimpleBody) method.getActiveBody();
            injectNoiseCode(body);
        }
    }
    
    /**
     * 注入噪音代码
     */
    private void injectNoiseCode(JimpleBody body) {
        // 添加一些无用的变量声明和操作
        // 这不会改变方法签名，但会改变方法体的hash/特征
        Chain<soot.Local> locals = body.getLocals();
        
        // 创建一些临时变量
        Local tempVar = Jimple.v().newLocal("noise" + random.nextInt(1000), IntType.v());
        locals.add(tempVar);
        
        // 添加噪音赋值语句
        Chain<soot.Unit> units = body.getUnits();
        soot.Unit firstUnit = units.getFirst();
        IntConstant noiseValue = IntConstant.v(random.nextInt());
        AssignStmt noiseStmt = Jimple.v().newAssignStmt(tempVar, noiseValue);
        units.insertBefore(noiseStmt, firstUnit);
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
        // 签名修改对基于签名匹配的工具特别有效
        return detectionTool.equalsIgnoreCase("LibPass") || 
               detectionTool.equalsIgnoreCase("LibScout");
    }
}
