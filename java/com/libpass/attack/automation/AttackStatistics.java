package com.libpass.attack.automation;

/**
 * 攻击统计信息
 */
public class AttackStatistics {
    private String apkPath;
    private String tplName;
    private boolean success;
    private int iterations;
    private boolean initialDetected;
    private boolean finalDetected;
    
    public String getApkPath() {
        return apkPath;
    }
    
    public void setApkPath(String apkPath) {
        this.apkPath = apkPath;
    }
    
    public String getTplName() {
        return tplName;
    }
    
    public void setTplName(String tplName) {
        this.tplName = tplName;
    }
    
    public boolean isSuccess() {
        return success;
    }
    
    public void setSuccess(boolean success) {
        this.success = success;
    }
    
    public int getIterations() {
        return iterations;
    }
    
    public void setIterations(int iterations) {
        this.iterations = iterations;
    }
    
    public boolean isInitialDetected() {
        return initialDetected;
    }
    
    public void setInitialDetected(boolean initialDetected) {
        this.initialDetected = initialDetected;
    }
    
    public boolean isFinalDetected() {
        return finalDetected;
    }
    
    public void setFinalDetected(boolean finalDetected) {
        this.finalDetected = finalDetected;
    }
}
