package com.libpass.attack.graph;

import java.util.Map;
import java.util.HashMap;

/**
 * 图节点
 */
public class GraphNode {
    private String id;
    private HeterogeneousGraph.NodeType type;
    private Map<String, Object> attributes;
    
    public GraphNode(String id, HeterogeneousGraph.NodeType type) {
        this.id = id;
        this.type = type;
        this.attributes = new HashMap<>();
    }
    
    public String getId() {
        return id;
    }
    
    public HeterogeneousGraph.NodeType getType() {
        return type;
    }
    
    public void setAttribute(String key, Object value) {
        attributes.put(key, value);
    }
    
    public Object getAttribute(String key) {
        return attributes.get(key);
    }
    
    public Map<String, Object> getAttributes() {
        return new HashMap<>(attributes);
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        GraphNode graphNode = (GraphNode) o;
        return id.equals(graphNode.id);
    }
    
    @Override
    public int hashCode() {
        return id.hashCode();
    }
    
    @Override
    public String toString() {
        return "GraphNode{" +
                "id='" + id + '\'' +
                ", type=" + type +
                '}';
    }
}
