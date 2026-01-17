package com.libpass.attack.detector;

import java.io.File;
import java.util.List;
import java.util.Map;

/**
 * TPL检测工具抽象接口
 * 用于支持不同的第三方库检测工具
 */
public interface TPLDetector {
    /**
     * 检测工具名称
     */
    String getName();
    
    /**
     * 检测APK中是否包含指定的TPL
     * 
     * @param apkPath APK文件路径
     * @param tplPath TPL文件路径（JAR或DEX）
     * @param tplName TPL名称（可选，用于标识）
     * @return 检测结果
     */
    DetectionResult detectTPL(String apkPath, String tplPath, String tplName);
    
    /**
     * 批量检测APK中的TPL
     * 
     * @param apkPaths APK文件路径列表
     * @param tplPath TPL文件路径
     * @param tplName TPL名称
     * @return 检测结果映射（APK路径 -> 检测结果）
     */
    Map<String, DetectionResult> detectTPLBatch(List<String> apkPaths, String tplPath, String tplName);
    
    /**
     * 初始化检测工具
     * 
     * @param config 配置参数
     */
    void initialize(Map<String, Object> config);
    
    /**
     * 检查检测工具是否可用
     */
    boolean isAvailable();
}
