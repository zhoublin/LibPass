package com.libpass.attack.entropy;

import com.libpass.attack.graph.HeterogeneousGraph;
import com.libpass.attack.graph.GraphNode;
import java.util.*;
import java.util.stream.Collectors;

/**
 * 图熵计算器
 * 计算依赖熵和结构熵
 */
public class GraphEntropyCalculator {
    private static final double EPSILON = 1e-10;
    private static final double DEFAULT_MU = 0.5; // 平衡系数
    
    /**
     * 计算图的总体熵
     */
    public double calculateGraphEntropy(HeterogeneousGraph graph, double mu) {
        if (mu < 0 || mu > 1) {
            mu = DEFAULT_MU;
        }
        
        Set<String> classNodes = graph.getNodesByType(HeterogeneousGraph.NodeType.CLASS);
        if (classNodes.isEmpty()) {
            return 0.0;
        }
        
        double totalEntropy = 0.0;
        for (String classId : classNodes) {
            double hd = calculateDependencyEntropy(graph, classId);
            double hs = calculateStructuralEntropy(graph, classId);
            totalEntropy += mu * hs + (1 - mu) * hd;
        }
        
        return totalEntropy / classNodes.size();
    }
    
    /**
     * 计算类的依赖熵 H_d
     */
    public double calculateDependencyEntropy(HeterogeneousGraph graph, String classId) {
        GraphNode classNode = graph.getNode(classId);
        if (classNode == null) {
            return 0.0;
        }
        
        // 获取5种依赖类型
        List<String> paramTypes = getParameterTypes(graph, classId);
        List<String> returnTypes = getReturnTypes(graph, classId);
        List<String> fieldTypes = getFieldTypes(graph, classId);
        List<String> invocationTypes = getInvocationTypes(graph, classId);
        List<String> referenceTypes = getReferenceTypes(graph, classId);
        
        List<List<String>> relations = Arrays.asList(
            paramTypes, returnTypes, fieldTypes, invocationTypes, referenceTypes
        );
        
        double totalEntropy = 0.0;
        int validRelations = 0;
        
        for (List<String> relation : relations) {
            if (!relation.isEmpty()) {
                double entropy = calculateListEntropy(relation);
                totalEntropy += entropy;
                validRelations++;
            }
        }
        
        return validRelations > 0 ? totalEntropy / validRelations : 0.0;
    }
    
    /**
     * 计算类的结构熵 H_s
     */
    public double calculateStructuralEntropy(HeterogeneousGraph graph, String classId) {
        Set<HeterogeneousGraph.EdgeType> edgeTypes = EnumSet.allOf(HeterogeneousGraph.EdgeType.class);
        double totalEntropy = 0.0;
        int validEdgeTypes = 0;
        
        for (HeterogeneousGraph.EdgeType edgeType : edgeTypes) {
            Set<String> neighbors = graph.getNeighbors(classId, edgeType);
            if (!neighbors.isEmpty()) {
                double entropy = calculateNeighborEntropy(graph, classId, neighbors, edgeType);
                totalEntropy += entropy;
                validEdgeTypes++;
            }
        }
        
        return validEdgeTypes > 0 ? totalEntropy / validEdgeTypes : 0.0;
    }
    
    /**
     * 计算列表的熵
     */
    private double calculateListEntropy(List<String> list) {
        if (list.isEmpty()) {
            return 0.0;
        }
        
        Map<String, Integer> counts = new HashMap<>();
        for (String item : list) {
            counts.put(item, counts.getOrDefault(item, 0) + 1);
        }
        
        Set<String> unique = new HashSet<>(list);
        if (unique.size() == 1) {
            return 0.0; // 所有元素相同，熵为0
        }
        
        double entropy = 0.0;
        for (String item : unique) {
            double p = (double) counts.get(item) / list.size();
            entropy -= p * Math.log(p + EPSILON);
        }
        
        double normalization = Math.log(unique.size() + EPSILON);
        return normalization > 0 ? entropy / normalization : 0.0;
    }
    
    /**
     * 计算邻居熵
     */
    private double calculateNeighborEntropy(HeterogeneousGraph graph, String classId, 
                                           Set<String> neighbors, HeterogeneousGraph.EdgeType edgeType) {
        if (neighbors.isEmpty()) {
            return 0.0;
        }
        
        // 计算每个邻居的连接概率
        Map<String, Integer> edgeCounts = new HashMap<>();
        int totalEdges = 0;
        
        for (String neighbor : neighbors) {
            // 计算从classId到neighbor的边数量
            int count = 1; // 简化：假设每条边只出现一次
            edgeCounts.put(neighbor, count);
            totalEdges += count;
        }
        
        if (totalEdges == 0) {
            return 0.0;
        }
        
        double entropy = 0.0;
        for (String neighbor : neighbors) {
            double p = (double) edgeCounts.get(neighbor) / totalEdges;
            entropy -= p * Math.log(p + EPSILON);
        }
        
        double normalization = Math.log(neighbors.size() + EPSILON);
        return normalization > 0 ? entropy / normalization : 0.0;
    }
    
    /**
     * 获取参数类型列表
     */
    private List<String> getParameterTypes(HeterogeneousGraph graph, String classId) {
        List<String> types = new ArrayList<>();
        Set<String> methodIds = graph.getNeighbors(classId, HeterogeneousGraph.EdgeType.CLASS_CONTAINS_METHOD);
        
        for (String methodId : methodIds) {
            Set<String> paramIds = graph.getNeighbors(methodId, HeterogeneousGraph.EdgeType.METHOD_CONTAINS_PARAMETER);
            for (String paramId : paramIds) {
                GraphNode paramNode = graph.getNode(paramId);
                if (paramNode != null) {
                    String type = (String) paramNode.getAttribute("type");
                    if (type != null) {
                        types.add(type);
                    }
                }
            }
        }
        
        return types;
    }
    
    /**
     * 获取返回类型列表
     */
    private List<String> getReturnTypes(HeterogeneousGraph graph, String classId) {
        List<String> types = new ArrayList<>();
        Set<String> methodIds = graph.getNeighbors(classId, HeterogeneousGraph.EdgeType.CLASS_CONTAINS_METHOD);
        
        for (String methodId : methodIds) {
            GraphNode methodNode = graph.getNode(methodId);
            if (methodNode != null) {
                String returnType = (String) methodNode.getAttribute("returnType");
                if (returnType != null) {
                    types.add(returnType);
                }
            }
        }
        
        return types;
    }
    
    /**
     * 获取字段类型列表
     */
    private List<String> getFieldTypes(HeterogeneousGraph graph, String classId) {
        List<String> types = new ArrayList<>();
        Set<String> fieldIds = graph.getNeighbors(classId, HeterogeneousGraph.EdgeType.CLASS_CONTAINS_FIELD);
        
        for (String fieldId : fieldIds) {
            GraphNode fieldNode = graph.getNode(fieldId);
            if (fieldNode != null) {
                String fieldType = (String) fieldNode.getAttribute("type");
                if (fieldType != null) {
                    types.add(fieldType);
                }
            }
        }
        
        return types;
    }
    
    /**
     * 获取调用类型列表
     */
    private List<String> getInvocationTypes(HeterogeneousGraph graph, String classId) {
        List<String> types = new ArrayList<>();
        Set<String> methodIds = graph.getNeighbors(classId, HeterogeneousGraph.EdgeType.CLASS_CONTAINS_METHOD);
        
        for (String methodId : methodIds) {
            Set<String> invokedMethods = graph.getNeighbors(methodId, HeterogeneousGraph.EdgeType.METHOD_INVOKES_METHOD);
            for (String invokedMethodId : invokedMethods) {
                GraphNode invokedMethod = graph.getNode(invokedMethodId);
                if (invokedMethod != null) {
                    String returnType = (String) invokedMethod.getAttribute("returnType");
                    if (returnType != null) {
                        types.add(returnType);
                    }
                }
            }
        }
        
        return types;
    }
    
    /**
     * 获取引用类型列表
     */
    private List<String> getReferenceTypes(HeterogeneousGraph graph, String classId) {
        List<String> types = new ArrayList<>();
        Set<String> fieldIds = graph.getNeighbors(classId, HeterogeneousGraph.EdgeType.CLASS_CONTAINS_FIELD);
        
        for (String fieldId : fieldIds) {
            Set<String> referencedClasses = graph.getNeighbors(fieldId, HeterogeneousGraph.EdgeType.FIELD_REFERENCES_CLASS);
            for (String refClassId : referencedClasses) {
                types.add(refClassId);
            }
        }
        
        return types;
    }
    
    /**
     * 计算所有类的熵值并排序
     */
    public Map<String, Double> calculateClassEntropies(HeterogeneousGraph graph, double mu) {
        Map<String, Double> entropies = new HashMap<>();
        Set<String> classNodes = graph.getNodesByType(HeterogeneousGraph.NodeType.CLASS);
        
        for (String classId : classNodes) {
            double hd = calculateDependencyEntropy(graph, classId);
            double hs = calculateStructuralEntropy(graph, classId);
            double total = mu * hs + (1 - mu) * hd;
            entropies.put(classId, total);
        }
        
        return entropies;
    }
    
    /**
     * 获取按熵值排序的类列表（升序）
     */
    public List<String> getClassesSortedByEntropy(HeterogeneousGraph graph, double mu) {
        Map<String, Double> entropies = calculateClassEntropies(graph, mu);
        return entropies.entrySet().stream()
                .sorted(Map.Entry.comparingByValue())
                .map(Map.Entry::getKey)
                .collect(Collectors.toList());
    }
}
