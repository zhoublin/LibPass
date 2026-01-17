package com.libpass.attack.attack;

/**
 * 攻击级别枚举
 */
public enum AttackLevel {
    /**
     * 库级别攻击：要使TPLDetector无法检测到整个库（不论什么版本）才算攻击成功
     */
    LIBRARY_LEVEL,
    
    /**
     * 版本级别攻击：只要使TPLDetector检测出的TPL的版本错误就算攻击成功
     */
    VERSION_LEVEL
}
