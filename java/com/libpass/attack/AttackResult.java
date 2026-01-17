package com.libpass.attack;

import java.util.Map;

/**
 * 攻击结果统计
 */
public class AttackResult {
    private String strategyName;
    private int totalClasses;
    private int modifiedClasses;
    private int totalMethods;
    private int modifiedMethods;
    private Map<String, Object> statistics;
    private double successRate;
    
    public AttackResult(String strategyName) {
        this.strategyName = strategyName;
        this.statistics = new java.util.HashMap<>();
    }
    
    public String getStrategyName() {
        return strategyName;
    }
    
    public int getTotalClasses() {
        return totalClasses;
    }
    
    public void setTotalClasses(int totalClasses) {
        this.totalClasses = totalClasses;
    }
    
    public int getModifiedClasses() {
        return modifiedClasses;
    }
    
    public void setModifiedClasses(int modifiedClasses) {
        this.modifiedClasses = modifiedClasses;
    }
    
    public int getTotalMethods() {
        return totalMethods;
    }
    
    public void setTotalMethods(int totalMethods) {
        this.totalMethods = totalMethods;
    }
    
    public int getModifiedMethods() {
        return modifiedMethods;
    }
    
    public void setModifiedMethods(int modifiedMethods) {
        this.modifiedMethods = modifiedMethods;
    }
    
    public Map<String, Object> getStatistics() {
        return statistics;
    }
    
    public double getSuccessRate() {
        return successRate;
    }
    
    public void setSuccessRate(double successRate) {
        this.successRate = successRate;
    }
    
    @Override
    public String toString() {
        return String.format("AttackResult[%s]: %d/%d classes, %d/%d methods, successRate=%.2f%%",
                strategyName, modifiedClasses, totalClasses, modifiedMethods, totalMethods, successRate * 100);
    }
}
