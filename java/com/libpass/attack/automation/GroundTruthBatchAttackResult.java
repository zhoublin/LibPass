package com.libpass.attack.automation;

import java.util.*;

/**
 * 基于GroundTruth的批量攻击结果
 */
public class GroundTruthBatchAttackResult {
    private String groundTruthFile;
    private int totalAttacks = 0; // 总攻击次数（APK-TPL组合数）
    private int detectableCount = 0; // 原始可检测的数量（分母）
    private int successCount = 0; // 成功次数（分子：攻击后无法检测到的数量，且原始能检测到）
    private int failureCount = 0; // 失败次数
    private double successRate = 0.0; // 成功率（分子/分母，分母是原始可检测的数量）
    
    // 攻击成功的统计信息
    private int successAttackCount = 0; // 成功攻击的数量（用于计算平均值）
    private long totalSuccessPerturbations = 0; // 成功攻击的总扰动数量（迭代次数）
    private double avgSuccessPerturbations = 0.0; // 成功攻击的平均扰动数量
    private long totalSuccessTimeMs = 0; // 成功攻击的总耗时（毫秒）
    private double avgSuccessTimeMs = 0.0; // 成功攻击的平均耗时（毫秒）
    
    private List<AutomatedAttackResult> results; // 所有攻击结果
    
    public GroundTruthBatchAttackResult() {
        this.results = new ArrayList<>();
    }
    
    /**
     * 添加攻击结果
     */
    public void addResult(AutomatedAttackResult result, long timeMs) {
        results.add(result);
        totalAttacks++;
        
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
                successAttackCount++;
                
                // 累加扰动数量（迭代次数）
                int iterations = result.getSuccessfulIteration() > 0 ? 
                    result.getSuccessfulIteration() + 1 : 0;
                totalSuccessPerturbations += iterations;
                
                // 累加耗时
                totalSuccessTimeMs += timeMs;
                
                // 更新平均值
                updateAverages();
            } else {
                // 攻击失败（攻击后仍可检测到）
                failureCount++;
            }
        } else {
            // 原始就检测不到，不计入分母和分子
            // 这种情况可能是：
            // 1. TPL检测器本身就无法检测到这个TPL
            // 2. APK中确实没有这个TPL
            // 这些情况不应该影响成功率计算
        }
        
        updateSuccessRate();
    }
    
    /**
     * 更新成功率
     * 分母是原始可检测的数量，分子是攻击成功的数量（攻击后无法检测到，且原始能检测到）
     */
    private void updateSuccessRate() {
        successRate = detectableCount > 0 ? (double) successCount / detectableCount : 0.0;
    }
    
    /**
     * 更新平均值
     */
    private void updateAverages() {
        if (successAttackCount > 0) {
            avgSuccessPerturbations = (double) totalSuccessPerturbations / successAttackCount;
            avgSuccessTimeMs = (double) totalSuccessTimeMs / successAttackCount;
        }
    }
    
    public String getGroundTruthFile() {
        return groundTruthFile;
    }
    
    public void setGroundTruthFile(String groundTruthFile) {
        this.groundTruthFile = groundTruthFile;
    }
    
    public int getTotalAttacks() {
        return totalAttacks;
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
    
    public double getAvgSuccessPerturbations() {
        return avgSuccessPerturbations;
    }
    
    public double getAvgSuccessTimeMs() {
        return avgSuccessTimeMs;
    }
    
    public List<AutomatedAttackResult> getResults() {
        return results;
    }
    
    @Override
    public String toString() {
        return String.format(
            "GroundTruthBatchAttackResult[total=%d, detectable=%d, success=%d, failure=%d, successRate=%.2f%%, " +
            "avgPerturbations=%.2f, avgTimeMs=%.2f]",
            totalAttacks, detectableCount, successCount, failureCount, successRate * 100,
            avgSuccessPerturbations, avgSuccessTimeMs
        );
    }
}
