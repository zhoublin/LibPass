package com.libpass.attack;

import java.util.List;
import java.util.Map;

/**
 * 攻击配置类
 */
public class AttackConfig {
    private List<String> strategies;
    private List<String> targetTools;
    private double targetSuccessRate;
    private RenamingConfig renamingConfig;
    private SignatureConfig signatureConfig;
    private FakeLibraryConfig fakeLibraryConfig;
    private Map<String, Object> customConfig;
    
    public AttackConfig() {
        this.customConfig = new java.util.HashMap<>();
    }
    
    public List<String> getStrategies() {
        return strategies;
    }
    
    public void setStrategies(List<String> strategies) {
        this.strategies = strategies;
    }
    
    public List<String> getTargetTools() {
        return targetTools;
    }
    
    public void setTargetTools(List<String> targetTools) {
        this.targetTools = targetTools;
    }
    
    public double getTargetSuccessRate() {
        return targetSuccessRate;
    }
    
    public void setTargetSuccessRate(double targetSuccessRate) {
        this.targetSuccessRate = targetSuccessRate;
    }
    
    public RenamingConfig getRenamingConfig() {
        return renamingConfig;
    }
    
    public void setRenamingConfig(RenamingConfig renamingConfig) {
        this.renamingConfig = renamingConfig;
    }
    
    public SignatureConfig getSignatureConfig() {
        return signatureConfig;
    }
    
    public void setSignatureConfig(SignatureConfig signatureConfig) {
        this.signatureConfig = signatureConfig;
    }
    
    public FakeLibraryConfig getFakeLibraryConfig() {
        return fakeLibraryConfig;
    }
    
    public void setFakeLibraryConfig(FakeLibraryConfig fakeLibraryConfig) {
        this.fakeLibraryConfig = fakeLibraryConfig;
    }
    
    public Map<String, Object> getCustomConfig() {
        return customConfig;
    }
    
    public static class RenamingConfig {
        private String prefix;
        private boolean useRandom;
        private boolean preserveHierarchy;
        
        public String getPrefix() {
            return prefix;
        }
        
        public void setPrefix(String prefix) {
            this.prefix = prefix;
        }
        
        public boolean isUseRandom() {
            return useRandom;
        }
        
        public void setUseRandom(boolean useRandom) {
            this.useRandom = useRandom;
        }
        
        public boolean isPreserveHierarchy() {
            return preserveHierarchy;
        }
        
        public void setPreserveHierarchy(boolean preserveHierarchy) {
            this.preserveHierarchy = preserveHierarchy;
        }
    }
    
    public static class SignatureConfig {
        private boolean modifyReturnTypes;
        private boolean modifyParameters;
        private boolean injectNoise;
        
        public boolean isModifyReturnTypes() {
            return modifyReturnTypes;
        }
        
        public void setModifyReturnTypes(boolean modifyReturnTypes) {
            this.modifyReturnTypes = modifyReturnTypes;
        }
        
        public boolean isModifyParameters() {
            return modifyParameters;
        }
        
        public void setModifyParameters(boolean modifyParameters) {
            this.modifyParameters = modifyParameters;
        }
        
        public boolean isInjectNoise() {
            return injectNoise;
        }
        
        public void setInjectNoise(boolean injectNoise) {
            this.injectNoise = injectNoise;
        }
    }
    
    public static class FakeLibraryConfig {
        private boolean enabled;
        private int count;
        private List<String> patterns;
        
        public boolean isEnabled() {
            return enabled;
        }
        
        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }
        
        public int getCount() {
            return count;
        }
        
        public void setCount(int count) {
            this.count = count;
        }
        
        public List<String> getPatterns() {
            return patterns;
        }
        
        public void setPatterns(List<String> patterns) {
            this.patterns = patterns;
        }
    }
}
