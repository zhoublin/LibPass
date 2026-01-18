package com.libpass.attack.automation;

import java.util.*;

/**
 * 批量攻击结果
 */
public class BatchAttackResult {
    private String tplName;
    private int totalApks;
    private int detectableCount = 0; // 原始可检测的数量（分母）
    private int successCount = 0; // 成功次数（分子：攻击后无法检测到的数量，且原始能检测到）
    private int failureCount = 0; // 失败次数
    private double successRate = 0.0; // 成功率（分子/分母，分母是原始可检测的数量）
    private List<AutomatedAttackResult> results;
    
    public BatchAttackResult() {
        this.results = new ArrayList<>();
    }
    
    /**
     * 添加攻击结果（根据原始检测状态决定是否计入统计）
     */
    public void addResult(AutomatedAttackResult result) {
        results.add(result);
        
        // 检查原始APK是否可检测到TPL
        // 只有原始能检测到的，才计入分母和分子
        boolean originallyDetectable = result.getInitialDetection() != null && 
                                      result.getInitialDetection().isDetected();
        
        if (originallyDetectable) {
            // 原始可检测到，计入分母
            detectableCount++;
            
            if (result.isAttackSuccess()) {
                // 攻击成功（攻击后无法检测到），计入分子
                successCount++;
            } else {
                // 攻击失败（攻击后仍可检测到）
                failureCount++;
            }
        }
        // 原始就检测不到的，不计入分母和分子
        
        calculateSuccessRate();
    }
    
    /**
     * 增加成功计数（已废弃，使用addResult代替）
     * @deprecated 使用addResult方法代替，它会自动根据原始检测状态决定是否计入统计
     */
    @Deprecated
    public void incrementSuccessCount() {
        successCount++;
        calculateSuccessRate();
    }
    
    /**
     * 增加失败计数（已废弃，使用addResult代替）
     * @deprecated 使用addResult方法代替，它会自动根据原始检测状态决定是否计入统计
     */
    @Deprecated
    public void incrementFailureCount() {
        failureCount++;
        calculateSuccessRate();
    }
    
    /**
     * 计算成功率
     * 分母是原始可检测的数量，分子是攻击成功的数量（攻击后无法检测到，且原始能检测到）
     */
    public void calculateSuccessRate() {
        successRate = detectableCount > 0 ? (double) successCount / detectableCount : 0.0;
    }
    
    public String getTplName() {
        return tplName;
    }
    
    public void setTplName(String tplName) {
        this.tplName = tplName;
    }
    
    public int getTotalApks() {
        return totalApks;
    }
    
    public void setTotalApks(int totalApks) {
        this.totalApks = totalApks;
    }
    
    public int getSuccessCount() {
        return successCount;
    }
    
    public int getFailureCount() {
        return failureCount;
    }
    
    public int getDetectableCount() {
        return detectableCount;
    }
    
    public double getSuccessRate() {
        return successRate;
    }
    
    public List<AutomatedAttackResult> getResults() {
        return results;
    }
    
    public void setResults(List<AutomatedAttackResult> results) {
        this.results = results;
    }
    
    @Override
    public String toString() {
        return String.format("BatchAttackResult[tpl=%s, total=%d, detectable=%d, success=%d, failure=%d, rate=%.2f%%]",
                tplName, totalApks, detectableCount, successCount, failureCount, successRate * 100);
    }
}
