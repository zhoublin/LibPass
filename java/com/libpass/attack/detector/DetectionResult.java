package com.libpass.attack.detector;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 检测结果
 */
public class DetectionResult {
    private boolean detected;  // 是否检测到TPL
    private double confidence; // 置信度/相似度
    private String tplName;   // TPL名称
    private String apkPath;   // APK路径
    private String message;   // 详细信息
    private Map<String, Object> metadata; // 额外元数据
    private List<String> detectedVersions; // 检测到的版本列表（用于版本级攻击）
    
    public DetectionResult() {
        this.detected = false;
        this.confidence = 0.0;
        this.detectedVersions = new ArrayList<>();
    }
    
    public DetectionResult(boolean detected, double confidence) {
        this.detected = detected;
        this.confidence = confidence;
        this.detectedVersions = new ArrayList<>();
    }
    
    public boolean isDetected() {
        return detected;
    }
    
    public void setDetected(boolean detected) {
        this.detected = detected;
    }
    
    public double getConfidence() {
        return confidence;
    }
    
    public void setConfidence(double confidence) {
        this.confidence = confidence;
    }
    
    public String getTplName() {
        return tplName;
    }
    
    public void setTplName(String tplName) {
        this.tplName = tplName;
    }
    
    public String getApkPath() {
        return apkPath;
    }
    
    public void setApkPath(String apkPath) {
        this.apkPath = apkPath;
    }
    
    public String getMessage() {
        return message;
    }
    
    public void setMessage(String message) {
        this.message = message;
    }
    
    public Map<String, Object> getMetadata() {
        return metadata;
    }
    
    public void setMetadata(Map<String, Object> metadata) {
        this.metadata = metadata;
    }
    
    public List<String> getDetectedVersions() {
        return detectedVersions;
    }
    
    public void setDetectedVersions(List<String> detectedVersions) {
        this.detectedVersions = detectedVersions != null ? detectedVersions : new ArrayList<>();
    }
    
    public void addDetectedVersion(String version) {
        if (this.detectedVersions == null) {
            this.detectedVersions = new ArrayList<>();
        }
        if (version != null && !version.isEmpty() && !this.detectedVersions.contains(version)) {
            this.detectedVersions.add(version);
        }
    }
    
    @Override
    public String toString() {
        return String.format("DetectionResult[detected=%s, confidence=%.2f, tpl=%s, apk=%s]",
                detected, confidence, tplName, apkPath);
    }
}
