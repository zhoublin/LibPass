package com.libpass.attack.attack;

/**
 * 攻击模式枚举
 */
public enum AttackMode {
    /**
     * 黑盒攻击：使用TPL检测器的检测分数来指导Firefly算法搜索
     * 检测分数越低（confidence越低），攻击越成功，intensity越高
     */
    BLACK_BOX,
    
    /**
     * 黑盒Plus攻击：使用图熵来指导Firefly算法搜索
     * 图熵越高，攻击越成功，intensity越高
     */
    BLACK_BOX_PLUS
}
