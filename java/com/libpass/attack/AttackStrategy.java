package com.libpass.attack;

import soot.SootClass;
import soot.SootMethod;
import java.util.List;
import java.util.Map;

/**
 * 通用攻击策略接口
 * 所有攻击策略都必须实现此接口
 */
public interface AttackStrategy {
    /**
     * 策略名称
     */
    String getName();
    
    /**
     * 执行攻击
     * @param classes 目标类列表
     * @param config 攻击配置
     * @return 攻击统计信息
     */
    AttackResult execute(List<SootClass> classes, AttackConfig config);
    
    /**
     * 获取攻击成功率
     */
    double getSuccessRate();
    
    /**
     * 检查该策略是否适用于给定的检测工具
     */
    boolean isApplicable(String detectionTool);
}
