package com.libpass.attack.automation;

import com.libpass.attack.attack.AttackResult;
import com.libpass.attack.detector.DetectionResult;
import java.util.*;

/**
 * 自动化攻击结果
 */
public class AutomatedAttackResult {
    private String apkPath;
    private String tplPath;
    private String tplName;
    private boolean attackSuccess;
    private String message;
    private DetectionResult initialDetection;
    private DetectionResult finalDetection;
    private String finalApkPath;
    private int successfulIteration = -1;
    private List<AttackResult> iterationResults;
    private List<DetectionResult> detectionResults;
    
    public AutomatedAttackResult() {
        this.iterationResults = new ArrayList<>();
        this.detectionResults = new ArrayList<>();
    }
    
    public String getApkPath() {
        return apkPath;
    }
    
    public void setApkPath(String apkPath) {
        this.apkPath = apkPath;
    }
    
    public String getTplPath() {
        return tplPath;
    }
    
    public void setTplPath(String tplPath) {
        this.tplPath = tplPath;
    }
    
    public String getTplName() {
        return tplName;
    }
    
    public void setTplName(String tplName) {
        this.tplName = tplName;
    }
    
    public boolean isAttackSuccess() {
        return attackSuccess;
    }
    
    public void setAttackSuccess(boolean attackSuccess) {
        this.attackSuccess = attackSuccess;
    }
    
    public String getMessage() {
        return message;
    }
    
    public void setMessage(String message) {
        this.message = message;
    }
    
    public DetectionResult getInitialDetection() {
        return initialDetection;
    }
    
    public void setInitialDetection(DetectionResult initialDetection) {
        this.initialDetection = initialDetection;
    }
    
    public DetectionResult getFinalDetection() {
        return finalDetection;
    }
    
    public void setFinalDetection(DetectionResult finalDetection) {
        this.finalDetection = finalDetection;
    }
    
    public String getFinalApkPath() {
        return finalApkPath;
    }
    
    public void setFinalApkPath(String finalApkPath) {
        this.finalApkPath = finalApkPath;
    }
    
    public int getSuccessfulIteration() {
        return successfulIteration;
    }
    
    public void setSuccessfulIteration(int successfulIteration) {
        this.successfulIteration = successfulIteration;
    }
    
    public List<AttackResult> getIterationResults() {
        return iterationResults;
    }
    
    public void addIterationResult(AttackResult result) {
        this.iterationResults.add(result);
    }
    
    public List<DetectionResult> getDetectionResults() {
        return detectionResults;
    }
    
    public void addDetectionResult(DetectionResult result) {
        this.detectionResults.add(result);
    }
    
    @Override
    public String toString() {
        return String.format("AutomatedAttackResult[success=%s, tpl=%s, iterations=%d, finalDetected=%s]",
                attackSuccess, tplName, iterationResults.size(),
                finalDetection != null ? finalDetection.isDetected() : "unknown");
    }
}
