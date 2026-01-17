package com.libpass.attack.firefly;

import com.libpass.attack.graph.HeterogeneousGraph;
import com.libpass.attack.entropy.GraphEntropyCalculator;
import java.util.*;

/**
 * 增强的Firefly算法
 * 使用KDTree进行空间索引，自适应参数调整
 */
public class FireflyAlgorithm {
    private static final int DEFAULT_POPULATION_SIZE = 30;
    private static final int DEFAULT_MAX_ITERATIONS = 100;
    private static final double DEFAULT_BETA0 = 1.0;  // 初始吸引力
    private static final double DEFAULT_GAMMA0 = 1.0;  // 初始光吸收系数
    private static final double DEFAULT_ALPHA0 = 0.2;  // 初始随机扰动强度
    private static final double DEFAULT_ETA = 0.5;     // 动量衰减系数
    private static final double DEFAULT_MU = 0.5;       // 熵平衡系数
    
    private int populationSize;
    private int maxIterations;
    private double beta0;
    private double gamma;
    private double alpha;
    private double eta;
    private double mu;
    
    private List<Firefly> population;
    private Firefly bestFirefly;
    private GraphEntropyCalculator entropyCalculator;
    private KDTree kdTree;
    
    public FireflyAlgorithm() {
        this(DEFAULT_POPULATION_SIZE, DEFAULT_MAX_ITERATIONS);
    }
    
    public FireflyAlgorithm(int populationSize, int maxIterations) {
        this.populationSize = populationSize;
        this.maxIterations = maxIterations;
        this.beta0 = DEFAULT_BETA0;
        this.gamma = DEFAULT_GAMMA0;
        this.alpha = DEFAULT_ALPHA0;
        this.eta = DEFAULT_ETA;
        this.mu = DEFAULT_MU;
        this.population = new ArrayList<>();
        this.entropyCalculator = new GraphEntropyCalculator();
    }
    
    /**
     * 初始化种群
     */
    public void initialize() {
        population.clear();
        for (int i = 0; i < populationSize; i++) {
            population.add(new Firefly());
        }
        buildKDTree();
        updateIntensities();
    }
    
    /**
     * 构建KDTree
     */
    private void buildKDTree() {
        List<double[]> points = new ArrayList<>();
        for (Firefly firefly : population) {
            points.add(firefly.getPosition());
        }
        kdTree = new KDTree(points);
    }
    
    /**
     * 更新所有firefly的亮度
     */
    private void updateIntensities() {
        // 这里应该根据实际的适应度函数更新
        // 简化实现：使用随机值
        for (Firefly firefly : population) {
            firefly.setIntensity(Math.random());
        }
        updateBest();
    }
    
    /**
     * 更新最佳firefly
     */
    private void updateBest() {
        bestFirefly = population.get(0);
        for (Firefly firefly : population) {
            if (firefly.getIntensity() > bestFirefly.getIntensity()) {
                bestFirefly = firefly;
            }
        }
    }
    
    /**
     * 执行一次迭代（黑盒模式：使用图熵）
     */
    public void iterate(HeterogeneousGraph graph) {
        // 1. 计算当前图熵
        double currentEntropy = entropyCalculator.calculateGraphEntropy(graph, mu);
        
        // 2. 对每个firefly
        for (Firefly firefly : population) {
            // 2.1 查找邻居
            double radius = calculateRadius();
            List<Firefly> neighbors = findSuperiorNeighbors(firefly, radius);
            
            // 2.2 计算移动方向
            double[] delta = calculateMovementVector(firefly, neighbors);
            
            // 2.3 更新速度和位置
            firefly.updateVelocity(delta, eta);
            firefly.updatePosition(delta, alpha);
        }
        
        // 3. 更新KDTree
        buildKDTree();
        
        // 4. 更新亮度（基于图熵，黑盒模式）
        updateIntensitiesWithEntropy(graph);
        
        // 5. 自适应参数调整
        adaptParameters();
        
        // 6. 更新最佳
        updateBest();
    }
    
    /**
     * 执行一次迭代（仅更新位置，不更新intensity）
     * 用于黑盒模式，intensity由外部根据检测分数更新
     */
    public void iterateWithoutIntensityUpdate(HeterogeneousGraph graph) {
        // 1. 对每个firefly
        for (Firefly firefly : population) {
            // 1.1 查找邻居
            double radius = calculateRadius();
            List<Firefly> neighbors = findSuperiorNeighbors(firefly, radius);
            
            // 1.2 计算移动方向
            double[] delta = calculateMovementVector(firefly, neighbors);
            
            // 1.3 更新速度和位置
            firefly.updateVelocity(delta, eta);
            firefly.updatePosition(delta, alpha);
        }
        
        // 2. 更新KDTree
        buildKDTree();
        
        // 3. 自适应参数调整
        adaptParameters();
        
        // 注意：不更新intensity，由外部根据检测分数更新
        // 但需要更新最佳firefly（基于当前intensity）
        updateBest();
    }
    
    /**
     * 查找更优的邻居
     */
    private List<Firefly> findSuperiorNeighbors(Firefly firefly, double radius) {
        List<Firefly> neighbors = new ArrayList<>();
        List<double[]> neighborPoints = kdTree.rangeQuery(firefly.getPosition(), radius);
        
        for (double[] point : neighborPoints) {
            for (Firefly other : population) {
                if (Arrays.equals(other.getPosition(), point) && 
                    other.getIntensity() > firefly.getIntensity()) {
                    neighbors.add(other);
                }
            }
        }
        
        return neighbors;
    }
    
    /**
     * 计算移动向量
     */
    private double[] calculateMovementVector(Firefly firefly, List<Firefly> neighbors) {
        double[] delta = new double[Firefly.DIMENSION];
        
        if (neighbors.isEmpty()) {
            // 没有更优邻居，使用随机游走
            for (int i = 0; i < Firefly.DIMENSION; i++) {
                delta[i] = (Math.random() - 0.5) * alpha;
            }
        } else {
            // 多源方向引导
            for (Firefly neighbor : neighbors) {
                double distance = firefly.distanceTo(neighbor);
                double attractiveness = beta0 * Math.exp(-gamma * distance * distance);
                
                double[] neighborPos = neighbor.getPosition();
                double[] fireflyPos = firefly.getPosition();
                
                for (int i = 0; i < Firefly.DIMENSION; i++) {
                    delta[i] += attractiveness * (neighborPos[i] - fireflyPos[i]);
                }
            }
            
            // 平均化
            for (int i = 0; i < Firefly.DIMENSION; i++) {
                delta[i] /= neighbors.size();
            }
            
            // 添加动量
            double[] velocity = firefly.getVelocity();
            for (int i = 0; i < Firefly.DIMENSION; i++) {
                delta[i] += eta * velocity[i];
            }
        }
        
        return delta;
    }
    
    /**
     * 计算搜索半径
     */
    private double calculateRadius() {
        // 简化实现：使用固定半径
        // 实际应该根据迭代次数动态调整
        return 0.5;
    }
    
    /**
     * 基于图熵更新亮度（黑盒攻击模式）
     */
    private void updateIntensitiesWithEntropy(HeterogeneousGraph graph) {
        // 为每个firefly生成扰动后的图并计算熵
        for (Firefly firefly : population) {
            // 这里应该应用firefly的扰动并计算新图的熵
            // 简化实现：使用当前图熵加上随机扰动
            double baseEntropy = entropyCalculator.calculateGraphEntropy(graph, mu);
            firefly.setIntensity(baseEntropy + Math.random() * 0.1);
        }
    }
    
    /**
     * 基于检测分数更新指定firefly的亮度（黑盒攻击模式）
     * 检测分数越低（confidence越低），攻击越成功，intensity应该越高
     * 
     * @param firefly 要更新的firefly
     * @param detectionConfidence 检测分数（0.0-1.0，越低越好）
     */
    public void updateIntensityWithDetectionScore(Firefly firefly, double detectionConfidence) {
        // 将检测分数转换为intensity
        // confidence越低（攻击越成功），intensity越高
        // 使用 1.0 - confidence 作为intensity，这样confidence=0时intensity=1.0（最好）
        double intensity = 1.0 - detectionConfidence;
        firefly.setIntensity(intensity);
    }
    
    /**
     * 更新所有firefly的亮度（基于检测分数，黑盒攻击模式）
     * 注意：这个方法需要在外部为每个firefly生成APK并检测后才能调用
     * 
     * @param detectionScores 每个firefly对应的检测分数映射
     */
    public void updateIntensitiesWithDetectionScores(java.util.Map<Firefly, Double> detectionScores) {
        for (Firefly firefly : population) {
            Double confidence = detectionScores.get(firefly);
            if (confidence != null) {
                updateIntensityWithDetectionScore(firefly, confidence);
            } else {
                // 如果没有检测分数，使用默认值（假设被检测到）
                firefly.setIntensity(0.0);
            }
        }
        updateBest();
    }
    
    /**
     * 自适应参数调整
     */
    private void adaptParameters() {
        // 计算种群多样性
        double[] meanPosition = calculateMeanPosition();
        double diversity = calculateDiversity(meanPosition);
        
        // 自适应gamma
        double sigma0 = 1.0; // 初始多样性
        double lambda = 0.1;
        gamma = gamma * Math.exp(-lambda * diversity / sigma0);
        
        // 自适应alpha（指数衰减）
        double decayRate = 0.95;
        alpha = alpha * decayRate;
        
        // 限制范围
        if (gamma < 0.1) gamma = 0.1;
        if (gamma > 10.0) gamma = 10.0;
        if (alpha < 0.01) alpha = 0.01;
        if (alpha > 0.5) alpha = 0.5;
    }
    
    /**
     * 计算平均位置
     */
    private double[] calculateMeanPosition() {
        double[] mean = new double[Firefly.DIMENSION];
        for (Firefly firefly : population) {
            double[] pos = firefly.getPosition();
            for (int i = 0; i < Firefly.DIMENSION; i++) {
                mean[i] += pos[i];
            }
        }
        for (int i = 0; i < Firefly.DIMENSION; i++) {
            mean[i] /= populationSize;
        }
        return mean;
    }
    
    /**
     * 计算种群多样性
     */
    private double calculateDiversity(double[] meanPosition) {
        double sum = 0.0;
        for (Firefly firefly : population) {
            double[] pos = firefly.getPosition();
            for (int i = 0; i < Firefly.DIMENSION; i++) {
                double diff = pos[i] - meanPosition[i];
                sum += diff * diff;
            }
        }
        return Math.sqrt(sum / populationSize);
    }
    
    public Firefly getBestFirefly() {
        return bestFirefly;
    }
    
    public List<Firefly> getPopulation() {
        return new ArrayList<>(population);
    }
    
    public double getGamma() {
        return gamma;
    }
    
    public double getAlpha() {
        return alpha;
    }
}
