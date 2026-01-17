package com.libpass.attack.attack;

import com.libpass.attack.detector.DetectionResult;

/**
 * 攻击结果
 */
public class AttackResult {
    private int totalIterations;
    private int successfulIterations;
    private double finalEntropy;
    private String outputApkPath;
    private boolean success;
    private int bestIteration = -1; // 最佳迭代次数（攻击成功的迭代）
    private DetectionResult detectionResult; // 检测结果（黑盒模式下由LibPassAttackEngine填充，避免重复检测）
    
    public AttackResult() {
        this.successfulIterations = 0;
        this.success = false;
    }
    
    public int getTotalIterations() {
        return totalIterations;
    }
    
    public void setTotalIterations(int totalIterations) {
        this.totalIterations = totalIterations;
    }
    
    public int getSuccessfulIterations() {
        return successfulIterations;
    }
    
    public void setSuccessfulIterations(int successfulIterations) {
        this.successfulIterations = successfulIterations;
    }
    
    public double getSuccessRate() {
        return totalIterations > 0 ? (double) successfulIterations / totalIterations : 0.0;
    }
    
    public double getFinalEntropy() {
        return finalEntropy;
    }
    
    public void setFinalEntropy(double finalEntropy) {
        this.finalEntropy = finalEntropy;
    }
    
    public String getOutputApkPath() {
        return outputApkPath;
    }
    
    public void setOutputApkPath(String outputApkPath) {
        this.outputApkPath = outputApkPath;
    }
    
    public boolean isSuccess() {
        return success;
    }
    
    public void setSuccess(boolean success) {
        this.success = success;
    }
    
    public int getBestIteration() {
        return bestIteration;
    }
    
    public void setBestIteration(int bestIteration) {
        this.bestIteration = bestIteration;
    }
    
    public DetectionResult getDetectionResult() {
        return detectionResult;
    }
    
    public void setDetectionResult(DetectionResult detectionResult) {
        this.detectionResult = detectionResult;
    }
    
    @Override
    public String toString() {
        return String.format("AttackResult[iterations=%d/%d, successRate=%.2f%%, entropy=%.4f, apk=%s]",
                successfulIterations, totalIterations, getSuccessRate() * 100, finalEntropy, outputApkPath);
    }
}
