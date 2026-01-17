package com.libpass.attack.firefly;

import java.util.Arrays;

/**
 * Firefly个体
 * 7维向量：(p_action, p_num, p_pkg, p_clz, p_mtd, p_fld, p_param)
 */
public class Firefly {
    // 维度定义
    public static final int DIM_ACTION = 0;  // 操作类型：0=add, 1=merge
    public static final int DIM_NUM = 1;      // 扰动节点数量比例
    public static final int DIM_PKG = 2;      // 包节点概率
    public static final int DIM_CLZ = 3;      // 类节点概率
    public static final int DIM_MTD = 4;      // 方法节点概率
    public static final int DIM_FLD = 5;      // 字段节点概率
    public static final int DIM_PARAM = 6;    // 参数节点概率
    
    public static final int DIMENSION = 7;
    
    private double[] position;  // 位置向量
    private double intensity;   // 亮度（适应度）
    private double[] velocity;  // 速度向量（用于动量）
    
    public Firefly() {
        this.position = new double[DIMENSION];
        this.velocity = new double[DIMENSION];
        this.intensity = 0.0;
        initializeRandom();
    }
    
    public Firefly(double[] position) {
        this.position = Arrays.copyOf(position, DIMENSION);
        this.velocity = new double[DIMENSION];
        this.intensity = 0.0;
        normalize();
    }
    
    /**
     * 随机初始化
     */
    private void initializeRandom() {
        for (int i = 0; i < DIMENSION; i++) {
            position[i] = Math.random();
        }
        normalize();
    }
    
    /**
     * 归一化位置到[0,1]
     */
    private void normalize() {
        for (int i = 0; i < DIMENSION; i++) {
            if (position[i] < 0) position[i] = 0;
            if (position[i] > 1) position[i] = 1;
        }
    }
    
    /**
     * 获取操作类型
     */
    public boolean isAddOperation() {
        return position[DIM_ACTION] < 0.5;
    }
    
    /**
     * 获取扰动数量比例
     */
    public double getPerturbationRatio() {
        return position[DIM_NUM];
    }
    
    /**
     * 获取节点类型选择
     * 返回概率最高的节点类型索引
     */
    public int getSelectedNodeType() {
        double maxProb = position[DIM_PKG];
        int selected = 0; // PACKAGE
        
        if (position[DIM_CLZ] > maxProb) {
            maxProb = position[DIM_CLZ];
            selected = 1; // CLASS
        }
        if (position[DIM_MTD] > maxProb) {
            maxProb = position[DIM_MTD];
            selected = 2; // METHOD
        }
        if (position[DIM_FLD] > maxProb) {
            maxProb = position[DIM_FLD];
            selected = 3; // FIELD
        }
        if (position[DIM_PARAM] > maxProb) {
            selected = 4; // PARAMETER
        }
        
        return selected;
    }
    
    /**
     * 更新位置
     */
    public void updatePosition(double[] delta, double alpha) {
        for (int i = 0; i < DIMENSION; i++) {
            // 添加随机扰动
            double random = (Math.random() - 0.5) * alpha;
            position[i] += delta[i] + random;
        }
        normalize();
    }
    
    /**
     * 更新速度（动量）
     */
    public void updateVelocity(double[] delta, double eta) {
        for (int i = 0; i < DIMENSION; i++) {
            velocity[i] = eta * velocity[i] + (1 - eta) * delta[i];
        }
    }
    
    /**
     * 计算到另一个firefly的距离
     */
    public double distanceTo(Firefly other) {
        double sum = 0.0;
        for (int i = 0; i < DIMENSION; i++) {
            double diff = position[i] - other.position[i];
            sum += diff * diff;
        }
        return Math.sqrt(sum);
    }
    
    public double[] getPosition() {
        return Arrays.copyOf(position, DIMENSION);
    }
    
    public void setPosition(double[] position) {
        this.position = Arrays.copyOf(position, DIMENSION);
        normalize();
    }
    
    public double getIntensity() {
        return intensity;
    }
    
    public void setIntensity(double intensity) {
        this.intensity = intensity;
    }
    
    public double[] getVelocity() {
        return Arrays.copyOf(velocity, DIMENSION);
    }
    
    @Override
    public String toString() {
        return String.format("Firefly[intensity=%.4f, action=%s, ratio=%.2f, type=%d]",
                intensity, isAddOperation() ? "ADD" : "MERGE", 
                getPerturbationRatio(), getSelectedNodeType());
    }
}
