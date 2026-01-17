package com.libpass.attack.automation;

import java.util.*;

/**
 * 批量攻击结果
 */
public class BatchAttackResult {
    private String tplName;
    private int totalApks;
    private int successCount = 0;
    private int failureCount = 0;
    private double successRate = 0.0;
    private List<AutomatedAttackResult> results;
    
    public BatchAttackResult() {
        this.results = new ArrayList<>();
    }
    
    public void incrementSuccessCount() {
        successCount++;
        calculateSuccessRate();
    }
    
    public void incrementFailureCount() {
        failureCount++;
        calculateSuccessRate();
    }
    
    public void calculateSuccessRate() {
        successRate = totalApks > 0 ? (double) successCount / totalApks : 0.0;
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
        return String.format("BatchAttackResult[tpl=%s, total=%d, success=%d, failure=%d, rate=%.2f%%]",
                tplName, totalApks, successCount, failureCount, successRate * 100);
    }
}
