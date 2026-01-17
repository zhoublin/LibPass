package com.libpass.attack.perturbation;

import com.libpass.attack.graph.HeterogeneousGraph;
import com.libpass.attack.graph.GraphNode;
import com.libpass.attack.firefly.Firefly;
import com.libpass.attack.entropy.GraphEntropyCalculator;
import soot.*;
import java.util.*;

import com.libpass.attack.util.Logger;
/**
 * 扰动应用器
 * 根据Firefly的决策应用扰动操作
 */
public class PerturbationApplier {
    private GraphEntropyCalculator entropyCalculator;
    private AddingPerturbation addingPerturbation;
    private MergingPerturbation mergingPerturbation;
    private Scene scene;
    private ModificationLogger logger;
    private static final double MU = 0.5;
    
    public PerturbationApplier() {
        this.entropyCalculator = new GraphEntropyCalculator();
        this.logger = new ModificationLogger();
    }
    
    public void setScene(Scene scene) {
        this.scene = scene;
        this.addingPerturbation = new AddingPerturbation(scene, logger);
        this.mergingPerturbation = new MergingPerturbation(scene, logger);
    }
    
    public void setLoggerIteration(int iteration) {
        if (logger != null) {
            logger.setIteration(iteration);
        }
    }
    
    public ModificationLogger getLogger() {
        return logger;
    }
    
    /**
     * 应用扰动
     */
    public HeterogeneousGraph applyPerturbation(
            HeterogeneousGraph graph, 
            Firefly firefly,
            Set<SootClass> tplClasses,
            Scene scene) {
        
        // 记录扰动前的图状态
        HeterogeneousGraph.NodeType nodeTypeEnum = getNodeType(firefly.getSelectedNodeType());
        int beforeCount = graph.getNodeCount(nodeTypeEnum);
        
        // 创建图的副本
        HeterogeneousGraph perturbedGraph = cloneGraph(graph);
        
        // 确定操作类型
        boolean isAdd = firefly.isAddOperation();
        double ratio = firefly.getPerturbationRatio();
        int nodeType = firefly.getSelectedNodeType();
        
        // 计算扰动数量
        int k = calculatePerturbationCount(perturbedGraph, nodeType, ratio);
        
        Logger.debug("\n=== 应用扰动操作 ===");
        Logger.debug("操作类型: %s", isAdd ? "添加" : "合并");
        Logger.debug("节点类型: %s", nodeTypeEnum);
        Logger.debug("扰动前节点数: %d", beforeCount);
        Logger.debug("扰动数量: %d", k);
        Logger.debug("扰动比例: %s", ratio);
        
        if (isAdd) {
            applyAddingPerturbation(perturbedGraph, nodeType, k, scene);
        } else {
            applyMergingPerturbation(perturbedGraph, nodeType, k, scene);
        }
        
        // 记录扰动后的图状态
        int afterCount = perturbedGraph.getNodeCount(nodeTypeEnum);
        Logger.debug("扰动后节点数: %d", afterCount);
        Logger.debug("节点数变化: %d", afterCount - beforeCount);
        Logger.debug("===================\n");
        
        return perturbedGraph;
    }
    
    /**
     * 克隆图
     */
    private HeterogeneousGraph cloneGraph(HeterogeneousGraph graph) {
        // 创建新图并复制所有节点和边
        HeterogeneousGraph cloned = new HeterogeneousGraph();
        
        // 复制所有节点
        for (String nodeId : graph.getAllNodeIds()) {
            com.libpass.attack.graph.GraphNode originalNode = graph.getNode(nodeId);
            com.libpass.attack.graph.GraphNode clonedNode = new com.libpass.attack.graph.GraphNode(
                nodeId, originalNode.getType()
            );
            
            // 复制属性
            for (Map.Entry<String, Object> attr : originalNode.getAttributes().entrySet()) {
                clonedNode.setAttribute(attr.getKey(), attr.getValue());
            }
            
            cloned.addNode(clonedNode);
        }
        
        // 复制所有边（简化：通过遍历所有节点对）
        for (String sourceId : graph.getAllNodeIds()) {
            Set<String> neighbors = graph.getAllNeighbors(sourceId);
            for (String targetId : neighbors) {
                // 尝试添加所有可能的边类型
                for (HeterogeneousGraph.EdgeType edgeType : HeterogeneousGraph.EdgeType.values()) {
                    Set<String> typeNeighbors = graph.getNeighbors(sourceId, edgeType);
                    if (typeNeighbors.contains(targetId)) {
                        cloned.addEdge(sourceId, targetId, edgeType);
                    }
                }
            }
        }
        
        return cloned;
    }
    
    /**
     * 计算扰动数量
     */
    private int calculatePerturbationCount(HeterogeneousGraph graph, int nodeType, double ratio) {
        HeterogeneousGraph.NodeType type = getNodeType(nodeType);
        int totalNodes = graph.getNodeCount(type);
        double omega = 0.5; // 控制系数
        return (int) (omega * ratio * totalNodes);
    }
    
    /**
     * 获取节点类型
     */
    private HeterogeneousGraph.NodeType getNodeType(int index) {
        switch (index) {
            case 0: return HeterogeneousGraph.NodeType.PACKAGE;
            case 1: return HeterogeneousGraph.NodeType.CLASS;
            case 2: return HeterogeneousGraph.NodeType.METHOD;
            case 3: return HeterogeneousGraph.NodeType.FIELD;
            case 4: return HeterogeneousGraph.NodeType.PARAMETER;
            default: return HeterogeneousGraph.NodeType.CLASS;
        }
    }
    
    /**
     * 应用添加扰动
     */
    private void applyAddingPerturbation(
            HeterogeneousGraph graph, 
            int nodeType, 
            int k,
            Scene scene) {
        
        if (addingPerturbation == null) {
            addingPerturbation = new AddingPerturbation(scene, logger);
        }
        
        // 获取TPL类集合（从图中提取）
        Set<SootClass> tplClasses = extractTPLClassesFromGraph(graph);
        
        // 根据节点类型执行不同的添加操作
        switch (nodeType) {
            case 0: // PACKAGE
                addingPerturbation.addPackages(graph, k);
                break;
            case 1: // CLASS
                addingPerturbation.addClasses(graph, k, tplClasses);
                break;
            case 2: // METHOD
                addingPerturbation.addMethods(graph, k, tplClasses);
                break;
            case 3: // FIELD
                addingPerturbation.addFields(graph, k, tplClasses);
                break;
            case 4: // PARAMETER
                addingPerturbation.addParameters(graph, k, tplClasses);
                break;
        }
    }
    
    /**
     * 应用合并扰动
     */
    private void applyMergingPerturbation(
            HeterogeneousGraph graph,
            int nodeType,
            int k,
            Scene scene) {
        
        if (mergingPerturbation == null) {
            mergingPerturbation = new MergingPerturbation(scene, logger);
        }
        
        // 获取TPL类集合
        Set<SootClass> tplClasses = extractTPLClassesFromGraph(graph);
        
        // 根据节点类型执行不同的合并操作
        switch (nodeType) {
            case 0: // PACKAGE
                mergingPerturbation.mergePackages(graph, k);
                break;
            case 1: // CLASS
                mergingPerturbation.mergeClasses(graph, k, tplClasses);
                break;
            case 2: // METHOD
                mergingPerturbation.mergeMethods(graph, k, tplClasses);
                break;
            case 3: // FIELD
                mergingPerturbation.mergeFields(graph, k, tplClasses);
                break;
            case 4: // PARAMETER
                mergingPerturbation.mergeParameters(graph, k, tplClasses);
                break;
        }
    }
    
    /**
     * 从图中提取TPL类
     */
    private Set<SootClass> extractTPLClassesFromGraph(HeterogeneousGraph graph) {
        Set<SootClass> tplClasses = new HashSet<>();
        Set<String> classIds = graph.getNodesByType(HeterogeneousGraph.NodeType.CLASS);
        
        for (String classId : classIds) {
            GraphNode classNode = graph.getNode(classId);
            if (classNode != null) {
                String className = (String) classNode.getAttribute("name");
                if (className != null) {
                    try {
                        SootClass sc = Scene.v().getSootClass(className);
                        if (sc != null && !sc.isPhantom()) {
                            tplClasses.add(sc);
                        }
                    } catch (Exception e) {
                        // 忽略
                    }
                }
            }
        }
        
        return tplClasses;
    }
}
