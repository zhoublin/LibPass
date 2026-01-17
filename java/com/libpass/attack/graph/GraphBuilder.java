package com.libpass.attack.graph;

import soot.*;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import java.util.*;

/**
 * 异构图构建器
 * 从Soot的类层次结构构建异构图
 */
public class GraphBuilder {
    private Scene scene;
    private HeterogeneousGraph graph;
    private Map<String, String> classToPackage;
    private Map<String, String> methodToClass;
    private Map<String, String> fieldToClass;
    
    public GraphBuilder(Scene scene) {
        this.scene = scene;
        this.graph = new HeterogeneousGraph();
        this.classToPackage = new HashMap<>();
        this.methodToClass = new HashMap<>();
        this.fieldToClass = new HashMap<>();
    }
    
    /**
     * 构建异构图
     */
    public HeterogeneousGraph buildGraph(Set<SootClass> targetClasses) {
        // 1. 构建包节点
        buildPackageNodes(targetClasses);
        
        // 2. 构建类节点
        buildClassNodes(targetClasses);
        
        // 3. 构建方法节点
        buildMethodNodes(targetClasses);
        
        // 4. 构建字段节点
        buildFieldNodes(targetClasses);
        
        // 5. 构建参数节点
        buildParameterNodes(targetClasses);
        
        // 6. 构建边
        buildEdges(targetClasses);
        
        return graph;
    }
    
    /**
     * 构建包节点
     */
    private void buildPackageNodes(Set<SootClass> classes) {
        Set<String> packages = new HashSet<>();
        
        for (SootClass sc : classes) {
            String className = sc.getName();
            String packageName = getPackageName(className);
            packages.add(packageName);
            
            // 构建包层次结构
            String[] parts = packageName.split("\\.");
            StringBuilder currentPackage = new StringBuilder();
            for (String part : parts) {
                if (currentPackage.length() > 0) {
                    currentPackage.append(".");
                }
                currentPackage.append(part);
                String pkgId = "pkg:" + currentPackage.toString();
                if (!graph.containsNode(pkgId)) {
                    GraphNode pkgNode = new GraphNode(pkgId, HeterogeneousGraph.NodeType.PACKAGE);
                    pkgNode.setAttribute("name", currentPackage.toString());
                    graph.addNode(pkgNode);
                }
            }
        }
    }
    
    /**
     * 构建类节点
     */
    private void buildClassNodes(Set<SootClass> classes) {
        for (SootClass sc : classes) {
            String className = sc.getName();
            String classId = "cls:" + className;
            
            GraphNode classNode = new GraphNode(classId, HeterogeneousGraph.NodeType.CLASS);
            classNode.setAttribute("name", className);
            classNode.setAttribute("modifiers", sc.getModifiers());
            classNode.setAttribute("isInterface", sc.isInterface());
            
            if (sc.hasSuperclass()) {
                classNode.setAttribute("superclass", sc.getSuperclass().getName());
            }
            
            graph.addNode(classNode);
            
            // 记录类到包的映射
            String packageName = getPackageName(className);
            String pkgId = "pkg:" + packageName;
            classToPackage.put(classId, pkgId);
        }
    }
    
    /**
     * 构建方法节点
     */
    private void buildMethodNodes(Set<SootClass> classes) {
        for (SootClass sc : classes) {
            String classId = "cls:" + sc.getName();
            
            for (SootMethod method : sc.getMethods()) {
                String methodId = "mtd:" + method.getSignature();
                
                GraphNode methodNode = new GraphNode(methodId, HeterogeneousGraph.NodeType.METHOD);
                methodNode.setAttribute("name", method.getName());
                methodNode.setAttribute("signature", method.getSignature());
                methodNode.setAttribute("returnType", method.getReturnType().toString());
                methodNode.setAttribute("modifiers", method.getModifiers());
                
                graph.addNode(methodNode);
                methodToClass.put(methodId, classId);
            }
        }
    }
    
    /**
     * 构建字段节点
     */
    private void buildFieldNodes(Set<SootClass> classes) {
        for (SootClass sc : classes) {
            String classId = "cls:" + sc.getName();
            
            for (SootField field : sc.getFields()) {
                String fieldId = "fld:" + sc.getName() + "." + field.getName();
                
                GraphNode fieldNode = new GraphNode(fieldId, HeterogeneousGraph.NodeType.FIELD);
                fieldNode.setAttribute("name", field.getName());
                fieldNode.setAttribute("type", field.getType().toString());
                fieldNode.setAttribute("modifiers", field.getModifiers());
                
                graph.addNode(fieldNode);
                fieldToClass.put(fieldId, classId);
            }
        }
    }
    
    /**
     * 构建参数节点
     */
    private void buildParameterNodes(Set<SootClass> classes) {
        for (SootClass sc : classes) {
            for (SootMethod method : sc.getMethods()) {
                String methodId = "mtd:" + method.getSignature();
                List<Type> paramTypes = method.getParameterTypes();
                
                for (int i = 0; i < paramTypes.size(); i++) {
                    Type paramType = paramTypes.get(i);
                    String paramId = "param:" + methodId + ":" + i;
                    
                    GraphNode paramNode = new GraphNode(paramId, HeterogeneousGraph.NodeType.PARAMETER);
                    paramNode.setAttribute("index", i);
                    paramNode.setAttribute("type", paramType.toString());
                    paramNode.setAttribute("methodId", methodId);
                    
                    graph.addNode(paramNode);
                }
            }
        }
    }
    
    /**
     * 构建边
     */
    private void buildEdges(Set<SootClass> classes) {
        // 包包含包
        buildPackageContainmentEdges();
        
        // 包包含类
        for (Map.Entry<String, String> entry : classToPackage.entrySet()) {
            graph.addEdge(entry.getValue(), entry.getKey(), 
                HeterogeneousGraph.EdgeType.PACKAGE_CONTAINS_CLASS);
        }
        
        // 类包含方法
        for (Map.Entry<String, String> entry : methodToClass.entrySet()) {
            graph.addEdge(entry.getValue(), entry.getKey(), 
                HeterogeneousGraph.EdgeType.CLASS_CONTAINS_METHOD);
        }
        
        // 类包含字段
        for (Map.Entry<String, String> entry : fieldToClass.entrySet()) {
            graph.addEdge(entry.getValue(), entry.getKey(), 
                HeterogeneousGraph.EdgeType.CLASS_CONTAINS_FIELD);
        }
        
        // 方法包含参数
        buildMethodParameterEdges();
        
        // 类继承关系
        buildInheritanceEdges(classes);
        
        // 类实现接口
        buildInterfaceEdges(classes);
        
        // 方法调用关系
        buildMethodInvocationEdges();
        
        // 字段引用关系
        buildFieldReferenceEdges(classes);
    }
    
    /**
     * 构建包包含包的关系
     */
    private void buildPackageContainmentEdges() {
        Set<String> packageIds = graph.getNodesByType(HeterogeneousGraph.NodeType.PACKAGE);
        for (String pkgId : packageIds) {
            String packageName = (String) graph.getNode(pkgId).getAttribute("name");
            if (packageName.contains(".")) {
                String parentPackage = packageName.substring(0, packageName.lastIndexOf("."));
                String parentPkgId = "pkg:" + parentPackage;
                if (graph.containsNode(parentPkgId)) {
                    graph.addEdge(parentPkgId, pkgId, 
                        HeterogeneousGraph.EdgeType.PACKAGE_CONTAINS_PACKAGE);
                }
            }
        }
    }
    
    /**
     * 构建方法参数边
     */
    private void buildMethodParameterEdges() {
        Set<String> paramIds = graph.getNodesByType(HeterogeneousGraph.NodeType.PARAMETER);
        for (String paramId : paramIds) {
            GraphNode paramNode = graph.getNode(paramId);
            String methodId = (String) paramNode.getAttribute("methodId");
            if (methodId != null && graph.containsNode(methodId)) {
                graph.addEdge(methodId, paramId, 
                    HeterogeneousGraph.EdgeType.METHOD_CONTAINS_PARAMETER);
            }
        }
    }
    
    /**
     * 构建继承边
     */
    private void buildInheritanceEdges(Set<SootClass> classes) {
        for (SootClass sc : classes) {
            if (sc.hasSuperclass() && !sc.getSuperclass().getName().equals("java.lang.Object")) {
                String classId = "cls:" + sc.getName();
                String superClassId = "cls:" + sc.getSuperclass().getName();
                if (graph.containsNode(superClassId)) {
                    graph.addEdge(classId, superClassId, 
                        HeterogeneousGraph.EdgeType.CLASS_INHERITS_CLASS);
                }
            }
        }
    }
    
    /**
     * 构建接口实现边
     */
    private void buildInterfaceEdges(Set<SootClass> classes) {
        for (SootClass sc : classes) {
            String classId = "cls:" + sc.getName();
            for (SootClass iface : sc.getInterfaces()) {
                String interfaceId = "cls:" + iface.getName();
                if (graph.containsNode(interfaceId)) {
                    graph.addEdge(classId, interfaceId, 
                        HeterogeneousGraph.EdgeType.CLASS_IMPLEMENTS_INTERFACE);
                }
            }
        }
    }
    
    /**
     * 构建方法调用边
     */
    private void buildMethodInvocationEdges() {
        // 简化实现：遍历所有方法，查找调用关系
        // 实际应该使用Soot的CallGraph
        try {
            CallGraph cg = scene.getCallGraph();
            if (cg != null) {
                for (Edge edge : cg) {
                    SootMethod src = edge.src();
                    SootMethod tgt = edge.tgt();
                    
                    String srcMethodId = "mtd:" + src.getSignature();
                    String tgtMethodId = "mtd:" + tgt.getSignature();
                    
                    if (graph.containsNode(srcMethodId) && graph.containsNode(tgtMethodId)) {
                        graph.addEdge(srcMethodId, tgtMethodId, 
                            HeterogeneousGraph.EdgeType.METHOD_INVOKES_METHOD);
                    }
                }
            }
        } catch (Exception e) {
            // CallGraph可能未构建，跳过
        }
    }
    
    /**
     * 构建字段引用边
     */
    private void buildFieldReferenceEdges(Set<SootClass> classes) {
        // 简化实现：字段类型引用
        Set<String> fieldIds = graph.getNodesByType(HeterogeneousGraph.NodeType.FIELD);
        for (String fieldId : fieldIds) {
            GraphNode fieldNode = graph.getNode(fieldId);
            String fieldType = (String) fieldNode.getAttribute("type");
            if (fieldType != null && !isPrimitiveType(fieldType)) {
                String referencedClassId = "cls:" + fieldType.replace("/", ".");
                if (graph.containsNode(referencedClassId)) {
                    graph.addEdge(fieldId, referencedClassId, 
                        HeterogeneousGraph.EdgeType.FIELD_REFERENCES_CLASS);
                }
            }
        }
    }
    
    /**
     * 获取包名
     */
    private String getPackageName(String className) {
        int lastDot = className.lastIndexOf('.');
        if (lastDot > 0) {
            return className.substring(0, lastDot);
        }
        return "";
    }
    
    /**
     * 判断是否为原始类型
     */
    private boolean isPrimitiveType(String type) {
        return type.equals("int") || type.equals("long") || type.equals("float") ||
               type.equals("double") || type.equals("boolean") || type.equals("byte") ||
               type.equals("char") || type.equals("short") || type.equals("void");
    }
}
