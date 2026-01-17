package com.libpass.attack.firefly;

import java.util.*;
import java.util.Arrays;

/**
 * 简化的KDTree实现
 * 用于快速查找邻居
 */
public class KDTree {
    private Node root;
    private int dimension;
    
    private class Node {
        double[] point;
        Node left, right;
        
        Node(double[] point) {
            this.point = Arrays.copyOf(point, point.length);
        }
    }
    
    public KDTree(List<double[]> points) {
        if (points == null || points.isEmpty()) {
            return;
        }
        this.dimension = points.get(0).length;
        this.root = buildTree(points, 0);
    }
    
    /**
     * 构建KDTree
     */
    private Node buildTree(List<double[]> points, int depth) {
        if (points.isEmpty()) {
            return null;
        }
        
        int axis = depth % dimension;
        points.sort(Comparator.comparingDouble(p -> p[axis]));
        
        int median = points.size() / 2;
        Node node = new Node(points.get(median));
        
        List<double[]> leftPoints = new ArrayList<>(points.subList(0, median));
        List<double[]> rightPoints = new ArrayList<>(points.subList(median + 1, points.size()));
        
        node.left = buildTree(leftPoints, depth + 1);
        node.right = buildTree(rightPoints, depth + 1);
        
        return node;
    }
    
    /**
     * 范围查询
     */
    public List<double[]> rangeQuery(double[] center, double radius) {
        List<double[]> results = new ArrayList<>();
        rangeQuery(root, center, radius, 0, results);
        return results;
    }
    
    private void rangeQuery(Node node, double[] center, double radius, int depth, List<double[]> results) {
        if (node == null) {
            return;
        }
        
        double distance = euclideanDistance(node.point, center);
        if (distance <= radius) {
            results.add(node.point);
        }
        
        int axis = depth % dimension;
        double diff = center[axis] - node.point[axis];
        
        if (diff <= 0) {
            rangeQuery(node.left, center, radius, depth + 1, results);
            if (Math.abs(diff) <= radius) {
                rangeQuery(node.right, center, radius, depth + 1, results);
            }
        } else {
            rangeQuery(node.right, center, radius, depth + 1, results);
            if (Math.abs(diff) <= radius) {
                rangeQuery(node.left, center, radius, depth + 1, results);
            }
        }
    }
    
    /**
     * 计算欧氏距离
     */
    private double euclideanDistance(double[] a, double[] b) {
        double sum = 0.0;
        for (int i = 0; i < a.length; i++) {
            double diff = a[i] - b[i];
            sum += diff * diff;
        }
        return Math.sqrt(sum);
    }
}
