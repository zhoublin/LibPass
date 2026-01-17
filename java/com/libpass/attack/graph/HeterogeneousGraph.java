package com.libpass.attack.graph;

import soot.SootClass;
import soot.SootMethod;
import soot.SootField;
import java.util.*;

/**
 * 异构图表示
 * 包含6种节点类型：package, class, interface, method, field, parameter
 * 8种边类型：包含类型和依赖类型
 */
public class HeterogeneousGraph {
    // 节点类型
    public enum NodeType {
        PACKAGE, CLASS, INTERFACE, METHOD, FIELD, PARAMETER
    }
    
    // 边类型
    public enum EdgeType {
        // 包含类型
        PACKAGE_CONTAINS_PACKAGE,
        PACKAGE_CONTAINS_CLASS,
        CLASS_CONTAINS_METHOD,
        CLASS_CONTAINS_FIELD,
        METHOD_CONTAINS_PARAMETER,
        // 依赖类型
        CLASS_INHERITS_CLASS,
        CLASS_IMPLEMENTS_INTERFACE,
        METHOD_INVOKES_METHOD,
        FIELD_REFERENCES_CLASS
    }
    
    // 节点集合
    private Map<String, GraphNode> nodes;
    // 边集合：source -> target -> edge type
    private Map<String, Map<String, Set<EdgeType>>> edges;
    // 按类型索引的节点
    private Map<NodeType, Set<String>> nodesByType;
    
    public HeterogeneousGraph() {
        this.nodes = new HashMap<>();
        this.edges = new HashMap<>();
        this.nodesByType = new HashMap<>();
        for (NodeType type : NodeType.values()) {
            nodesByType.put(type, new HashSet<>());
        }
    }
    
    /**
     * 添加节点
     */
    public void addNode(GraphNode node) {
        nodes.put(node.getId(), node);
        nodesByType.get(node.getType()).add(node.getId());
    }
    
    /**
     * 获取节点
     */
    public GraphNode getNode(String nodeId) {
        return nodes.get(nodeId);
    }
    
    /**
     * 添加边
     */
    public void addEdge(String sourceId, String targetId, EdgeType edgeType) {
        edges.putIfAbsent(sourceId, new HashMap<>());
        edges.get(sourceId).putIfAbsent(targetId, new HashSet<>());
        edges.get(sourceId).get(targetId).add(edgeType);
    }
    
    /**
     * 获取节点的邻居
     */
    public Set<String> getNeighbors(String nodeId, EdgeType edgeType) {
        Set<String> neighbors = new HashSet<>();
        if (edges.containsKey(nodeId)) {
            for (Map.Entry<String, Set<EdgeType>> entry : edges.get(nodeId).entrySet()) {
                if (entry.getValue().contains(edgeType)) {
                    neighbors.add(entry.getKey());
                }
            }
        }
        return neighbors;
    }
    
    /**
     * 获取所有邻居（不考虑边类型）
     */
    public Set<String> getAllNeighbors(String nodeId) {
        Set<String> neighbors = new HashSet<>();
        if (edges.containsKey(nodeId)) {
            neighbors.addAll(edges.get(nodeId).keySet());
        }
        // 反向查找
        for (Map.Entry<String, Map<String, Set<EdgeType>>> entry : edges.entrySet()) {
            if (entry.getValue().containsKey(nodeId)) {
                neighbors.add(entry.getKey());
            }
        }
        return neighbors;
    }
    
    /**
     * 获取指定类型的所有节点
     */
    public Set<String> getNodesByType(NodeType type) {
        return new HashSet<>(nodesByType.get(type));
    }
    
    /**
     * 获取所有节点ID
     */
    public Set<String> getAllNodeIds() {
        return new HashSet<>(nodes.keySet());
    }
    
    /**
     * 获取节点数量
     */
    public int getNodeCount() {
        return nodes.size();
    }
    
    /**
     * 获取指定类型的节点数量
     */
    public int getNodeCount(NodeType type) {
        return nodesByType.get(type).size();
    }
    
    /**
     * 检查节点是否存在
     */
    public boolean containsNode(String nodeId) {
        return nodes.containsKey(nodeId);
    }
    
    /**
     * 移除节点及其所有边
     */
    public void removeNode(String nodeId) {
        nodes.remove(nodeId);
        for (NodeType type : NodeType.values()) {
            nodesByType.get(type).remove(nodeId);
        }
        edges.remove(nodeId);
        // 移除指向该节点的边
        for (Map<String, Set<EdgeType>> targets : edges.values()) {
            targets.remove(nodeId);
        }
    }
    
    /**
     * 获取图的统计信息
     */
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalNodes", nodes.size());
        for (NodeType type : NodeType.values()) {
            stats.put(type.name() + "_count", nodesByType.get(type).size());
        }
        int totalEdges = 0;
        for (Map<String, Set<EdgeType>> targets : edges.values()) {
            for (Set<EdgeType> edgeTypes : targets.values()) {
                totalEdges += edgeTypes.size();
            }
        }
        stats.put("totalEdges", totalEdges);
        return stats;
    }
}
