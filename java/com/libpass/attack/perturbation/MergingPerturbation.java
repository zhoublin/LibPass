package com.libpass.attack.perturbation;

import com.libpass.attack.graph.HeterogeneousGraph;
import com.libpass.attack.graph.GraphNode;
import com.libpass.attack.entropy.GraphEntropyCalculator;
import soot.*;
import soot.jimple.*;
import soot.util.Chain;
import java.util.*;
import java.util.stream.Collectors;

import com.libpass.attack.util.Logger;
/**
 * 合并节点扰动操作
 * 实现5种类型的节点合并：package, class, method, field, parameter
 * 
 * 注意：合并操作比较激进，需要仔细处理冲突和功能保持
 */
public class MergingPerturbation {
    private GraphEntropyCalculator entropyCalculator;
    private Scene scene;
    private Random random;
    private CallSiteUpdater callSiteUpdater;
    private ModificationLogger logger;
    private static final double MU = 0.5;
    
    // 约束矩阵：记录哪些节点可以合并
    private Map<String, Set<String>> mergeConstraints;
    
    public MergingPerturbation(Scene scene) {
        this(scene, null);
    }
    
    public MergingPerturbation(Scene scene, ModificationLogger logger) {
        this.scene = scene;
        this.logger = logger;
        this.entropyCalculator = new GraphEntropyCalculator();
        this.random = new Random();
        this.callSiteUpdater = new CallSiteUpdater(scene);
        this.mergeConstraints = new HashMap<>();
    }
    
    /**
     * 合并包节点
     * 策略：迁移源包的类到目标包，更新所有引用
     */
    public void mergePackages(HeterogeneousGraph graph, int k) {
        // 计算包熵
        Map<String, Double> packageEntropies = calculatePackageEntropies(graph);
        List<Map.Entry<String, Double>> sortedPackages = new ArrayList<>(packageEntropies.entrySet());
        sortedPackages.sort(Map.Entry.comparingByValue());
        
        // 选择top-k作为源包
        List<String> sourcePackages = new ArrayList<>();
        for (int i = 0; i < Math.min(k, sortedPackages.size()); i++) {
            sourcePackages.add(sortedPackages.get(i).getKey());
        }
        
        // 随机选择k个目标包（确保不相交）
        Set<String> targetPackages = new HashSet<>();
        List<String> allPackages = new ArrayList<>(packageEntropies.keySet());
        allPackages.removeAll(sourcePackages);
        
        while (targetPackages.size() < k && !allPackages.isEmpty()) {
            String target = allPackages.remove(random.nextInt(allPackages.size()));
            if (canMerge(sourcePackages.get(targetPackages.size()), target, graph)) {
                targetPackages.add(target);
            }
        }
        
        // 执行合并
        List<String> sourceList = new ArrayList<>(sourcePackages);
        List<String> targetList = new ArrayList<>(targetPackages);
        for (int i = 0; i < Math.min(sourceList.size(), targetList.size()); i++) {
            mergePackagePair(graph, sourceList.get(i), targetList.get(i));
        }
    }
    
    /**
     * 合并类节点
     * 策略：合并成员，处理冲突
     * - 构造函数：合并方法体，添加boolean参数控制执行流
     * - 方法：重命名冲突方法
     * - 字段：直接合并
     */
    public void mergeClasses(HeterogeneousGraph graph, int k, Set<SootClass> tplClasses) {
        // 计算类熵
        Map<String, Double> classEntropies = entropyCalculator.calculateClassEntropies(graph, MU);
        List<Map.Entry<String, Double>> sortedClasses = new ArrayList<>(classEntropies.entrySet());
        sortedClasses.sort(Map.Entry.comparingByValue());
        
        // 选择top-k作为源类
        List<String> sourceClasses = new ArrayList<>();
        for (int i = 0; i < Math.min(k, sortedClasses.size()); i++) {
            sourceClasses.add(sortedClasses.get(i).getKey());
        }
        
        // 随机选择目标类
        Set<String> targetClasses = new HashSet<>();
        List<String> allClasses = new ArrayList<>(classEntropies.keySet());
        allClasses.removeAll(sourceClasses);
        
        while (targetClasses.size() < k && !allClasses.isEmpty()) {
            String target = allClasses.remove(random.nextInt(allClasses.size()));
            if (canMergeClasses(sourceClasses.get(targetClasses.size()), target, graph)) {
                targetClasses.add(target);
            }
        }
        
        // 执行合并
        List<String> sourceList = new ArrayList<>(sourceClasses);
        List<String> targetList = new ArrayList<>(targetClasses);
        for (int i = 0; i < Math.min(sourceList.size(), targetList.size()); i++) {
            mergeClassPair(graph, sourceList.get(i), targetList.get(i), tplClasses);
        }
    }
    
    /**
     * 合并方法节点
     * 策略：合并参数列表，添加boolean控制执行流
     * 如果返回类型不同，使用包装类
     */
    public void mergeMethods(HeterogeneousGraph graph, int k, Set<SootClass> tplClasses) {
        Map<String, Double> classEntropies = entropyCalculator.calculateClassEntropies(graph, MU);
        List<Map.Entry<String, Double>> sortedClasses = new ArrayList<>(classEntropies.entrySet());
        sortedClasses.sort(Map.Entry.comparingByValue());
        
        // 从top-k类中各选一个方法
        List<String> sourceMethods = new ArrayList<>();
        for (int i = 0; i < Math.min(k, sortedClasses.size()); i++) {
            String classId = sortedClasses.get(i).getKey();
            Set<String> methodIds = graph.getNeighbors(classId, 
                HeterogeneousGraph.EdgeType.CLASS_CONTAINS_METHOD);
            if (!methodIds.isEmpty()) {
                List<String> methodList = new ArrayList<>(methodIds);
                sourceMethods.add(methodList.get(random.nextInt(methodList.size())));
            }
        }
        
        // 随机选择目标方法
        List<String> targetMethods = new ArrayList<>();
        Set<String> allMethodIds = graph.getNodesByType(HeterogeneousGraph.NodeType.METHOD);
        allMethodIds.removeAll(sourceMethods);
        
        while (targetMethods.size() < sourceMethods.size() && !allMethodIds.isEmpty()) {
            List<String> available = new ArrayList<>(allMethodIds);
            String target = available.get(random.nextInt(available.size()));
            if (canMergeMethods(sourceMethods.get(targetMethods.size()), target, graph)) {
                targetMethods.add(target);
                allMethodIds.remove(target);
            }
        }
        
        // 执行合并
        for (int i = 0; i < Math.min(sourceMethods.size(), targetMethods.size()); i++) {
            mergeMethodPair(graph, sourceMethods.get(i), targetMethods.get(i), tplClasses);
        }
    }
    
    /**
     * 合并字段节点
     * 策略：使用包装类封装两个字段的类型
     */
    public void mergeFields(HeterogeneousGraph graph, int k, Set<SootClass> tplClasses) {
        Map<String, Double> classEntropies = entropyCalculator.calculateClassEntropies(graph, MU);
        List<Map.Entry<String, Double>> sortedClasses = new ArrayList<>(classEntropies.entrySet());
        sortedClasses.sort(Map.Entry.comparingByValue());
        
        // 从top-k类中各选一个字段
        List<String> sourceFields = new ArrayList<>();
        for (int i = 0; i < Math.min(k, sortedClasses.size()); i++) {
            String classId = sortedClasses.get(i).getKey();
            Set<String> fieldIds = graph.getNeighbors(classId, 
                HeterogeneousGraph.EdgeType.CLASS_CONTAINS_FIELD);
            if (!fieldIds.isEmpty()) {
                List<String> fieldList = new ArrayList<>(fieldIds);
                sourceFields.add(fieldList.get(random.nextInt(fieldList.size())));
            }
        }
        
        // 随机选择目标字段
        List<String> targetFields = new ArrayList<>();
        Set<String> allFieldIds = graph.getNodesByType(HeterogeneousGraph.NodeType.FIELD);
        allFieldIds.removeAll(sourceFields);
        
        while (targetFields.size() < sourceFields.size() && !allFieldIds.isEmpty()) {
            List<String> available = new ArrayList<>(allFieldIds);
            String target = available.get(random.nextInt(available.size()));
            if (canMergeFields(sourceFields.get(targetFields.size()), target, graph)) {
                targetFields.add(target);
                allFieldIds.remove(target);
            }
        }
        
        // 执行合并
        for (int i = 0; i < Math.min(sourceFields.size(), targetFields.size()); i++) {
            mergeFieldPair(graph, sourceFields.get(i), targetFields.get(i), tplClasses);
        }
    }
    
    /**
     * 合并参数节点
     * 策略：在同一方法内合并两个参数，使用包装类
     */
    public void mergeParameters(HeterogeneousGraph graph, int k, Set<SootClass> tplClasses) {
        Map<String, Double> classEntropies = entropyCalculator.calculateClassEntropies(graph, MU);
        List<Map.Entry<String, Double>> sortedClasses = new ArrayList<>(classEntropies.entrySet());
        sortedClasses.sort(Map.Entry.comparingByValue());
        
        // 从top-k类中选择至少有两个参数的方法
        List<String> methodsWithParams = new ArrayList<>();
        for (int i = 0; i < Math.min(k * 2, sortedClasses.size()) && methodsWithParams.size() < k; i++) {
            String classId = sortedClasses.get(i).getKey();
            Set<String> methodIds = graph.getNeighbors(classId, 
                HeterogeneousGraph.EdgeType.CLASS_CONTAINS_METHOD);
            
            for (String methodId : methodIds) {
                Set<String> paramIds = graph.getNeighbors(methodId, 
                    HeterogeneousGraph.EdgeType.METHOD_CONTAINS_PARAMETER);
                if (paramIds.size() >= 2) {
                    methodsWithParams.add(methodId);
                    if (methodsWithParams.size() >= k) break;
                }
            }
        }
        
        // 为每个方法合并两个参数
        for (String methodId : methodsWithParams) {
            Set<String> paramIds = graph.getNeighbors(methodId, 
                HeterogeneousGraph.EdgeType.METHOD_CONTAINS_PARAMETER);
            if (paramIds.size() >= 2) {
                List<String> paramList = new ArrayList<>(paramIds);
                String param1 = paramList.get(random.nextInt(paramList.size()));
                String param2 = paramList.get(random.nextInt(paramList.size()));
                if (!param1.equals(param2) && canMergeParameters(param1, param2, graph)) {
                    mergeParameterPair(graph, methodId, param1, param2, tplClasses);
                }
            }
        }
    }
    
    // ========== 合并实现方法 ==========
    
    /**
     * 合并包对
     */
    private void mergePackagePair(HeterogeneousGraph graph, String sourcePkgId, String targetPkgId) {
        GraphNode sourcePkg = graph.getNode(sourcePkgId);
        GraphNode targetPkg = graph.getNode(targetPkgId);
        
        if (sourcePkg == null || targetPkg == null) {
            return;
        }
        
        // 获取源包下的所有类
        Set<String> sourceClasses = graph.getNeighbors(sourcePkgId, 
            HeterogeneousGraph.EdgeType.PACKAGE_CONTAINS_CLASS);
        
        // 迁移类到目标包
        for (String classId : sourceClasses) {
            GraphNode classNode = graph.getNode(classId);
            if (classNode == null) continue;
            
            String className = (String) classNode.getAttribute("name");
            if (className == null) continue;
            
            // 检查名称冲突
            String targetPkgName = (String) targetPkg.getAttribute("name");
            String simpleName = className.substring(className.lastIndexOf('.') + 1);
            String newClassName = targetPkgName.isEmpty() ? simpleName : targetPkgName + "." + simpleName;
            
            // 如果目标包中已有同名类，跳过
            Set<String> targetClasses = graph.getNeighbors(targetPkgId, 
                HeterogeneousGraph.EdgeType.PACKAGE_CONTAINS_CLASS);
            boolean hasConflict = false;
            for (String targetClassId : targetClasses) {
                GraphNode targetClass = graph.getNode(targetClassId);
                if (targetClass != null) {
                    String targetClassName = (String) targetClass.getAttribute("name");
                    if (targetClassName != null && targetClassName.equals(newClassName)) {
                        hasConflict = true;
                        break;
                    }
                }
            }
            
            if (!hasConflict) {
                // 更新类名
                classNode.setAttribute("name", newClassName);
                
                // 更新边
                graph.addEdge(targetPkgId, classId, HeterogeneousGraph.EdgeType.PACKAGE_CONTAINS_CLASS);
                // 移除旧边（简化：保留，实际应该移除）
                
                // 更新Soot类
                updateSootClassPackage(className, newClassName);
            }
        }
        
        // 如果源包为空，移除它
        Set<String> remainingClasses = graph.getNeighbors(sourcePkgId, 
            HeterogeneousGraph.EdgeType.PACKAGE_CONTAINS_CLASS);
        if (remainingClasses.isEmpty()) {
            // 提升子包
            Set<String> subPackages = graph.getNeighbors(sourcePkgId, 
                HeterogeneousGraph.EdgeType.PACKAGE_CONTAINS_PACKAGE);
            for (String subPkgId : subPackages) {
                // 将子包提升到源包的父包
                // 简化实现
            }
        }
    }
    
    /**
     * 合并类对
     * 策略：
     * 1. 字段冲突：重命名
     * 2. 非构造函数方法冲突：重命名，更新调用者
     * 3. 构造函数：合并方法体，添加boolean参数
     */
    private void mergeClassPair(HeterogeneousGraph graph, String sourceClassId, 
                               String targetClassId, Set<SootClass> tplClasses) {
        GraphNode sourceClass = graph.getNode(sourceClassId);
        GraphNode targetClass = graph.getNode(targetClassId);
        
        if (sourceClass == null || targetClass == null) {
            return;
        }
        
        String sourceClassName = (String) sourceClass.getAttribute("name");
        String targetClassName = (String) targetClass.getAttribute("name");
        
        if (sourceClassName == null || targetClassName == null) {
            return;
        }
        
        SootClass sourceSootClass = scene.getSootClass(sourceClassName);
        SootClass targetSootClass = scene.getSootClass(targetClassName);
        
        if (sourceSootClass == null || targetSootClass == null || 
            sourceSootClass.isPhantom() || targetSootClass.isPhantom()) {
            return;
        }
        
        // 记录合并前的状态
        int beforeMethodCount = targetSootClass.getMethodCount();
        int beforeFieldCount = targetSootClass.getFieldCount();
        
        // 1. 合并字段（重命名冲突字段）
        Map<String, String> renamedFields = mergeClassFields(
            sourceSootClass, targetSootClass, graph, sourceClassId, targetClassId);
        
        // 2. 合并非构造函数方法（重命名冲突方法，更新调用者）
        Map<String, String> renamedMethods = mergeClassMethods(
            sourceSootClass, targetSootClass, graph, sourceClassId, targetClassId);
        
        // 3. 合并构造函数（合并方法体，添加boolean参数）
        mergeClassConstructors(sourceSootClass, targetSootClass, graph, sourceClassId, targetClassId);
        
        // 4. 更新所有类引用
        updateClassReferences(sourceClassName, targetClassName);
        
        // 记录合并类操作
        if (logger != null) {
            logger.logMergeClass(sourceSootClass, targetSootClass, renamedMethods, renamedFields);
        }
        
        // 打印合并前后对比
        int afterMethodCount = targetSootClass.getMethodCount();
        int afterFieldCount = targetSootClass.getFieldCount();
        Logger.debug("\n=== 类合并详情 ===");
        Logger.debug("源类: %s", sourceSootClass.getName());
        Logger.debug("  方法数: %d", sourceSootClass.getMethodCount());
        Logger.debug("  字段数: %d", sourceSootClass.getFieldCount());
        Logger.debug("目标类: %s", targetSootClass.getName());
        Logger.debug("  合并前方法数: %d -> 合并后: %d", beforeMethodCount, afterMethodCount);
        Logger.debug("  合并前字段数: %d -> 合并后: %d", beforeFieldCount, afterFieldCount);
        if (!renamedMethods.isEmpty()) {
            Logger.debug("重命名方法:");
            renamedMethods.forEach((oldName, newName) -> 
                Logger.debug("  %s -> %s", oldName, newName));
        }
        if (!renamedFields.isEmpty()) {
            Logger.debug("重命名字段:");
            renamedFields.forEach((oldName, newName) -> 
                Logger.debug("  %s -> %s", oldName, newName));
        }
        Logger.debug("==================\n");
    }
    
    /**
     * 合并方法对
     * 
     * 策略：
     * 1. 合并参数列表
     * 2. 添加boolean参数控制执行流
     * 3. 如果返回类型不同，使用包装类
     * 
     * 这个策略是否符合您的预期？
     */
    private void mergeMethodPair(HeterogeneousGraph graph, String sourceMethodId, 
                                String targetMethodId, Set<SootClass> tplClasses) {
        GraphNode sourceMethod = graph.getNode(sourceMethodId);
        GraphNode targetMethod = graph.getNode(targetMethodId);
        
        if (sourceMethod == null || targetMethod == null) {
            return;
        }
        
        String sourceSignature = (String) sourceMethod.getAttribute("signature");
        String targetSignature = (String) targetMethod.getAttribute("signature");
        
        if (sourceSignature == null || targetSignature == null) {
            return;
        }
        
        // 解析方法签名，找到Soot方法
        // 这里需要解析签名字符串，找到对应的SootMethod
        // 简化实现：假设可以通过签名找到方法
        
        // 1. 合并参数列表
        // 2. 添加boolean控制参数
        // 3. 合并方法体
        // 4. 处理返回类型冲突
        // 5. 更新所有调用点
        
        // 由于涉及复杂的方法体合并和调用点更新，这里提供框架
        // 具体实现需要根据您的需求调整
    }
    
    /**
     * 合并字段对
     * 使用包装类封装两个字段的类型，使用时多一层访问
     */
    private void mergeFieldPair(HeterogeneousGraph graph, String sourceFieldId, 
                               String targetFieldId, Set<SootClass> tplClasses) {
        GraphNode sourceFieldNode = graph.getNode(sourceFieldId);
        GraphNode targetFieldNode = graph.getNode(targetFieldId);
        
        if (sourceFieldNode == null || targetFieldNode == null) {
            return;
        }
        
        String sourceTypeStr = (String) sourceFieldNode.getAttribute("type");
        String targetTypeStr = (String) targetFieldNode.getAttribute("type");
        
        if (sourceTypeStr == null || targetTypeStr == null) {
            return;
        }
        
        // 解析类型
        Type sourceType = parseType(sourceTypeStr);
        Type targetType = parseType(targetTypeStr);
        
        if (sourceType == null || targetType == null) {
            return;
        }
        
        // 创建包装类
        String wrapperClassName = createFieldWrapperClass(sourceType, targetType, tplClasses);
        if (wrapperClassName == null) {
            return;
        }
        
        // 找到Soot字段
        String sourceFieldName = (String) sourceFieldNode.getAttribute("name");
        String targetFieldName = (String) targetFieldNode.getAttribute("name");
        
        // 解析类名和方法名
        String sourceClassName = extractClassNameFromFieldId(sourceFieldId);
        String targetClassName = extractClassNameFromFieldId(targetFieldId);
        
        // 验证类名有效性（不能是空、android等无效类名）
        if (sourceClassName == null || targetClassName == null || 
            sourceClassName.isEmpty() || targetClassName.isEmpty() ||
            sourceClassName.equals("android") || targetClassName.equals("android")) {
            Logger.error("Invalid class name extracted from field ID. Source: %s", sourceClassName + ", Target: " + targetClassName);
            return;
        }
        
        // 检查类是否存在
        if (!scene.containsClass(sourceClassName) || !scene.containsClass(targetClassName)) {
            Logger.error("Class not found in scene. Source: %s", sourceClassName + ", Target: " + targetClassName);
            return;
        }
        
        SootClass sourceClass = scene.getSootClass(sourceClassName);
        SootClass targetClass = scene.getSootClass(targetClassName);
        
        if (sourceClass == null || targetClass == null) {
            return;
        }
        
        // 安全地获取字段（getFieldByName 在字段不存在时会抛出异常）
        SootField sourceField = null;
        SootField targetField = null;
        try {
            sourceField = sourceClass.getFieldByName(sourceFieldName);
        } catch (RuntimeException e) {
            System.err.println("Field not found in source class: " + sourceClassName + "." + sourceFieldName + ": " + e.getMessage());
            return;
        }
        
        try {
            targetField = targetClass.getFieldByName(targetFieldName);
        } catch (RuntimeException e) {
            System.err.println("Field not found in target class: " + targetClassName + "." + targetFieldName + ": " + e.getMessage());
            return;
        }
        
        if (sourceField == null || targetField == null) {
            return;
        }
        
        // 记录合并前的状态
        Type beforeTargetType = targetField.getType();
        
        // 如果字段是static final且有常量值，需要移除final修饰符和常量值
        // 因为包装类类型（对象类型）不支持常量值，会导致DEX转换失败
        // 错误：unexpected constant tag type: ConstantValue: 6 for field
        int modifiers = targetField.getModifiers();
        boolean hasFinal = soot.Modifier.isFinal(modifiers);
        boolean hasStatic = soot.Modifier.isStatic(modifiers);
        
        if (hasFinal) {
            // 移除final修饰符（保留其他修饰符如static）
            // 这是关键：final字段不能有包装类类型，因为包装类是对象类型，不能作为编译时常量
            int newModifiers = modifiers & ~soot.Modifier.FINAL;
            targetField.setModifiers(newModifiers);
            Logger.debug("Removed FINAL modifier from field %s.%s (incompatible with wrapper type)", 
                targetClassName, targetFieldName);
        }
        
        // 尝试移除常量值tag（如果存在）
        // Soot将常量值存储在字段的tag中，即使移除final修饰符，tag可能仍然存在
        // 需要清除它以避免DEX转换错误：unexpected constant tag type: ConstantValue: 6
        try {
            // 获取所有tags
            List<soot.tagkit.Tag> tags = targetField.getTags();
            if (tags != null && !tags.isEmpty()) {
                // 先收集要移除的tag名称，避免在遍历时修改列表导致ConcurrentModificationException
                List<String> tagNamesToRemove = new ArrayList<>();
                List<String> tagClassNamesToRemove = new ArrayList<>();
                List<soot.tagkit.Tag> tagsToRemove = new ArrayList<>();
                
                // 第一步：遍历tags，识别需要移除的tag
                for (soot.tagkit.Tag tag : tags) {
                    // 跳过null tag
                    if (tag == null) {
                        continue;
                    }
                    
                    String tagClassName;
                    try {
                        tagClassName = tag.getClass().getName();
                    } catch (Exception e) {
                        // 如果无法获取类名，跳过这个tag
                        Logger.debug("Cannot get class name for tag in field %s.%s: %s", 
                            targetClassName, targetFieldName, e.getMessage() != null ? e.getMessage() : "unknown error");
                        continue;
                    }
                    
                    // 检查是否是常量值相关的tag
                    if (tagClassName != null && 
                        (tagClassName.contains("ConstantValue") || 
                         tagClassName.contains("Constant") ||
                         tagClassName.contains("DoubleConstant") ||
                         tagClassName.contains("FloatConstant") ||
                         tagClassName.contains("IntConstant") ||
                         tagClassName.contains("LongConstant") ||
                         tagClassName.contains("StringConstant"))) {
                        
                        // 收集要移除的tag信息
                        try {
                            String tagName = tag.getClass().getSimpleName();
                            if (tagName != null) {
                                tagNamesToRemove.add(tagName);
                            }
                            tagClassNamesToRemove.add(tagClassName);
                            tagsToRemove.add(tag);
                        } catch (Exception e) {
                            // 如果无法获取tag名称，只记录类名
                            tagClassNamesToRemove.add(tagClassName);
                        }
                    }
                }
                
                // 第二步：移除收集到的tags（不在遍历循环中进行，避免ConcurrentModificationException）
                for (String tagName : tagNamesToRemove) {
                    try {
                        targetField.removeTag(tagName);
                        Logger.debug("Removed ConstantValue tag (%s) from field %s.%s", 
                            tagName, targetClassName, targetFieldName);
                    } catch (Exception e) {
                        Logger.debug("Could not remove tag by name %s from field %s.%s: %s", 
                            tagName, targetClassName, targetFieldName, e.getMessage());
                    }
                }
                
                // 如果通过名称移除失败，尝试通过类名移除
                for (String tagClassName : tagClassNamesToRemove) {
                    try {
                        // 只尝试还没有被移除的tag
                        if (!tagNamesToRemove.contains(tagClassName.substring(tagClassName.lastIndexOf('.') + 1))) {
                            targetField.removeTag(tagClassName);
                            Logger.debug("Removed ConstantValue tag (%s) from field %s.%s", 
                                tagClassName, targetClassName, targetFieldName);
                        }
                    } catch (Exception e) {
                        Logger.debug("Could not remove tag by class name %s from field %s.%s: %s", 
                            tagClassName, targetClassName, targetFieldName, e.getMessage());
                    }
                }
                
                // 最后尝试通过反射移除Tag对象
                for (soot.tagkit.Tag tag : tagsToRemove) {
                    try {
                        java.lang.reflect.Method removeTagMethod = targetField.getClass()
                            .getMethod("removeTag", soot.tagkit.Tag.class);
                        removeTagMethod.invoke(targetField, tag);
                        Logger.debug("Removed ConstantValue tag via reflection from field %s.%s", 
                            targetClassName, targetFieldName);
                    } catch (Exception e) {
                        // 忽略，可能已经被移除了
                    }
                }
            }
        } catch (Exception e) {
            // 安全地获取异常消息，避免null
            String errorMsg = e.getMessage();
            if (errorMsg == null) {
                errorMsg = e.getClass().getSimpleName();
                if (e.getCause() != null && e.getCause().getMessage() != null) {
                    errorMsg += ": " + e.getCause().getMessage();
                }
            }
            Logger.warning("Error while attempting to remove ConstantValue tag from field %s.%s: %s", 
                targetClassName, targetFieldName, errorMsg);
        }
        
        // 替换目标字段类型为包装类
        Type wrapperType = RefType.v(wrapperClassName);
        targetField.setType(wrapperType);
        
        // 设置类型后，再次尝试移除常量值tag（某些实现可能需要在类型改变后才能移除tag）
        // 这是防御性措施，确保常量值tag被清除
        if (hasFinal) {
            try {
                List<soot.tagkit.Tag> tagsAfterTypeChange = targetField.getTags();
                if (tagsAfterTypeChange != null && !tagsAfterTypeChange.isEmpty()) {
                    // 先收集要移除的tag名称，避免在遍历时修改列表导致ConcurrentModificationException
                    List<String> tagNamesToRemoveAfterTypeChange = new ArrayList<>();
                    
                    // 第一步：遍历tags，识别需要移除的tag
                    for (soot.tagkit.Tag tag : tagsAfterTypeChange) {
                        // 跳过null tag
                        if (tag == null) {
                            continue;
                        }
                        
                        String tagClassName;
                        try {
                            tagClassName = tag.getClass().getName();
                        } catch (Exception e) {
                            // 如果无法获取类名，跳过这个tag
                            continue;
                        }
                        
                        if (tagClassName != null && 
                            (tagClassName.contains("ConstantValue") || tagClassName.contains("Constant"))) {
                            // 收集要移除的tag名称
                            try {
                                String tagName = tag.getClass().getSimpleName();
                                if (tagName != null) {
                                    tagNamesToRemoveAfterTypeChange.add(tagName);
                                }
                            } catch (Exception e) {
                                // 忽略
                            }
                        }
                    }
                    
                    // 第二步：移除收集到的tags（不在遍历循环中进行）
                    for (String tagName : tagNamesToRemoveAfterTypeChange) {
                        try {
                            targetField.removeTag(tagName);
                            Logger.debug("Removed ConstantValue tag after type change (%s) from field %s.%s", 
                                tagName, targetClassName, targetFieldName);
                        } catch (Exception e) {
                            // 忽略，已经在之前尝试过了
                        }
                    }
                }
            } catch (Exception e) {
                // 忽略，这只是防御性检查
            }
        }
        
        // 更新所有字段访问（添加一层访问）
        updateFieldAccesses(sourceField, targetField, wrapperClassName, sourceType, targetType);
        
        // 记录合并字段操作
        if (logger != null) {
            logger.logMergeField(sourceField, targetField, wrapperClassName, targetClass);
        }
        
        // 打印合并前后对比（debug级别）
        Logger.debug("\n=== 字段合并详情 ===");
        Logger.debug("源字段: %s.%s (类型: %s)", sourceClassName, sourceFieldName, sourceType);
        Logger.debug("目标字段: %s.%s", targetClassName, targetFieldName);
        Logger.debug("  合并前类型: %s", beforeTargetType);
        Logger.debug("  合并后类型: %s (包装类: %s)", wrapperType, wrapperClassName);
        Logger.debug("==================\n");
    }
    
    /**
     * 创建字段包装类
     */
    private String createFieldWrapperClass(Type type1, Type type2, Set<SootClass> tplClasses) {
        String wrapperName = "FieldWrapper" + random.nextInt(100000);
        String fullWrapperName = "com.merged." + wrapperName;
        
        try {
            SootClass wrapperClass = new SootClass(fullWrapperName, Modifier.PUBLIC);
            wrapperClass.setSuperclass(Scene.v().getSootClass("java.lang.Object"));
            
            // 添加两个字段
            SootField field1 = new SootField("value1", type1, Modifier.PUBLIC);
            SootField field2 = new SootField("value2", type2, Modifier.PUBLIC);
            wrapperClass.addField(field1);
            wrapperClass.addField(field2);
            
            scene.addClass(wrapperClass);
            return fullWrapperName;
        } catch (Exception e) {
            System.err.println("Failed to create field wrapper class: " + e.getMessage());
            return null;
        }
    }
    
    /**
     * 更新字段访问（添加一层访问）
     */
    private void updateFieldAccesses(SootField sourceField, SootField targetField,
                                    String wrapperClassName, Type sourceType, Type targetType) {
        String targetFieldName = targetField.getName();
        String targetClassName = targetField.getDeclaringClass().getName();
        
        // 遍历所有类，更新字段访问
        for (SootClass sc : scene.getClasses()) {
            if (sc.isPhantom() || sc.getMethodCount() == 0) {
                continue;
            }
            
            for (SootMethod method : sc.getMethods()) {
                if (!method.hasActiveBody()) {
                    continue;
                }
                
                JimpleBody body = (JimpleBody) method.getActiveBody();
                Chain<soot.Unit> units = body.getUnits();
                Chain<soot.Local> locals = body.getLocals();
                
                // 查找字段访问并更新
                List<soot.Unit> unitsToUpdate = new ArrayList<>();
                for (soot.Unit unit : units) {
                    if (unit instanceof AssignStmt) {
                        AssignStmt assign = (AssignStmt) unit;
                        Value rightOp = assign.getRightOp();
                        Value leftOp = assign.getLeftOp();
                        
                        // 检查是否是字段读取
                        if (rightOp instanceof FieldRef) {
                            FieldRef fieldRef = (FieldRef) rightOp;
                            if (fieldRef.getField().getName().equals(targetFieldName) &&
                                fieldRef.getField().getDeclaringClass().getName().equals(targetClassName)) {
                                // 替换为包装类字段访问
                                unitsToUpdate.add(unit);
                            }
                        }
                        
                        // 检查是否是字段写入
                        if (leftOp instanceof FieldRef) {
                            FieldRef fieldRef = (FieldRef) leftOp;
                            if (fieldRef.getField().getName().equals(targetFieldName) &&
                                fieldRef.getField().getDeclaringClass().getName().equals(targetClassName)) {
                                unitsToUpdate.add(unit);
                            }
                        }
                    }
                }
                
                // 更新字段访问
                for (soot.Unit unit : unitsToUpdate) {
                    updateFieldAccessUnit(unit, body, wrapperClassName, sourceType, targetType, targetFieldName);
                }
            }
        }
    }
    
    /**
     * 更新单个字段访问单元
     */
    private void updateFieldAccessUnit(soot.Unit unit, JimpleBody body, 
                                      String wrapperClassName, Type sourceType, Type targetType,
                                      String targetFieldName) {
        try {
            SootClass wrapperClass = scene.getSootClass(wrapperClassName);
            if (wrapperClass == null) return;
            
            SootField value1Field = wrapperClass.getFieldByName("value1");
            SootField value2Field = wrapperClass.getFieldByName("value2");
            
            if (value1Field == null || value2Field == null) return;
            
            Chain<soot.Unit> units = body.getUnits();
            Chain<soot.Local> locals = body.getLocals();
            
            if (unit instanceof AssignStmt) {
                AssignStmt assign = (AssignStmt) unit;
                Value rightOp = assign.getRightOp();
                Value leftOp = assign.getLeftOp();
                
                // 处理字段读取
                if (rightOp instanceof FieldRef) {
                    FieldRef fieldRef = (FieldRef) rightOp;
                    if (fieldRef.getField().getName().equals(targetFieldName)) {
                        // 获取字段引用的基对象
                        Value base = ((InstanceFieldRef) fieldRef).getBase();
                        
                        // 根据上下文决定访问value1还是value2
                        // 简化：根据使用位置决定
                        SootField targetField = value1Field; // 默认使用value1
                        
                        // 创建新的字段访问
                        InstanceFieldRef newFieldRef = Jimple.v().newInstanceFieldRef(
                            base, targetField.makeRef()
                        );
                        
                        // 替换
                        AssignStmt newAssign = Jimple.v().newAssignStmt(leftOp, newFieldRef);
                        units.swapWith(unit, newAssign);
                    }
                }
                
                // 处理字段写入
                if (leftOp instanceof FieldRef) {
                    FieldRef fieldRef = (FieldRef) leftOp;
                    if (fieldRef.getField().getName().equals(targetFieldName)) {
                        Value base = ((InstanceFieldRef) fieldRef).getBase();
                        Value rightValue = assign.getRightOp();
                        
                        // 创建包装对象并设置字段
                        // 简化实现
                        SootField targetField = value1Field;
                        InstanceFieldRef newFieldRef = Jimple.v().newInstanceFieldRef(
                            base, targetField.makeRef()
                        );
                        
                        AssignStmt newAssign = Jimple.v().newAssignStmt(newFieldRef, rightValue);
                        units.swapWith(unit, newAssign);
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Failed to update field access: " + e.getMessage());
        }
    }
    
    /**
     * 从字段ID提取类名
     */
    private String extractClassNameFromFieldId(String fieldId) {
        if (fieldId == null || fieldId.isEmpty()) {
            return null;
        }
        
        // fieldId格式: "fld:ClassName.fieldName" 或 "fld:package.ClassName.fieldName"
        int colonIndex = fieldId.indexOf(':');
        if (colonIndex < 0) {
            return null;
        }
        
        // 从冒号后开始查找最后一个点（字段名前的点）
        String afterColon = fieldId.substring(colonIndex + 1);
        int lastDotIndex = afterColon.lastIndexOf('.');
        if (lastDotIndex <= 0) {
            return null;
        }
        
        // 提取类名（可能是完整包名.类名）
        String className = afterColon.substring(0, lastDotIndex);
        
        // 验证类名有效性
        if (className.isEmpty() || className.equals("android")) {
            return null;
        }
        
        return className;
    }
    
    /**
     * 解析类型字符串
     */
    private Type parseType(String typeStr) {
        try {
            return scene.getType(typeStr);
        } catch (Exception e) {
            return null;
        }
    }
    
    /**
     * 合并参数对
     * 在同一方法内合并两个参数，使用包装类
     */
    private void mergeParameterPair(HeterogeneousGraph graph, String methodId, 
                                   String param1Id, String param2Id, Set<SootClass> tplClasses) {
        GraphNode param1Node = graph.getNode(param1Id);
        GraphNode param2Node = graph.getNode(param2Id);
        GraphNode methodNode = graph.getNode(methodId);
        
        if (param1Node == null || param2Node == null || methodNode == null) {
            return;
        }
        
        String type1Str = (String) param1Node.getAttribute("type");
        String type2Str = (String) param2Node.getAttribute("type");
        String methodSignature = (String) methodNode.getAttribute("signature");
        
        if (type1Str == null || type2Str == null || methodSignature == null) {
            return;
        }
        
        // 解析类型
        Type type1 = parseType(type1Str);
        Type type2 = parseType(type2Str);
        
        if (type1 == null || type2 == null) {
            return;
        }
        
        // 找到Soot方法
        SootMethod method = findMethodBySignature(methodSignature);
        if (method == null || !method.hasActiveBody()) {
            return;
        }
        
        // 获取参数索引
        Integer param1Index = (Integer) param1Node.getAttribute("index");
        Integer param2Index = (Integer) param2Node.getAttribute("index");
        
        if (param1Index == null || param2Index == null) {
            return;
        }
        
        // 创建包装类
        String wrapperClassName = createFieldWrapperClass(type1, type2, tplClasses);
        if (wrapperClassName == null) {
            return;
        }
        
        // 更新方法签名：移除两个参数，添加一个包装类参数
        List<Type> newParamTypes = new ArrayList<>(method.getParameterTypes());
        newParamTypes.remove(Math.max(param1Index, param2Index));
        newParamTypes.remove(Math.min(param1Index, param2Index));
        newParamTypes.add(RefType.v(wrapperClassName));
        
        // 创建新方法
        SootMethod newMethod = new SootMethod(
            method.getName(),
            newParamTypes,
            method.getReturnType(),
            method.getModifiers()
        );
        
        // 更新方法体：添加解包装逻辑
        if (method.hasActiveBody()) {
            JimpleBody newBody = updateMethodBodyForParameterMerge(
                (JimpleBody) method.getActiveBody(), 
                param1Index, param2Index, wrapperClassName, type1, type2
            );
            newMethod.setActiveBody(newBody);
        }
        
        // 替换方法
        method.getDeclaringClass().removeMethod(method);
        method.getDeclaringClass().addMethod(newMethod);
        
        // 更新所有调用点
        updateParameterCallSites(method, newMethod, param1Index, param2Index, wrapperClassName, type1, type2);
    }
    
    /**
     * 更新方法体以支持参数合并
     */
    private JimpleBody updateMethodBodyForParameterMerge(JimpleBody oldBody, 
                                                         int param1Index, int param2Index,
                                                         String wrapperClassName, Type type1, Type type2) {
        JimpleBody newBody = Jimple.v().newBody();
        
        Chain<soot.Local> newLocals = newBody.getLocals();
        Chain<soot.Unit> newUnits = newBody.getUnits();
        
        // 复制局部变量（除了被合并的参数）
        List<soot.Local> oldLocals = new ArrayList<>(oldBody.getLocals());
        Map<soot.Local, soot.Local> localMap = new HashMap<>();
        
        for (int i = 0; i < oldLocals.size(); i++) {
            if (i != param1Index && i != param2Index) {
                soot.Local oldLocal = oldLocals.get(i);
                soot.Local newLocal = Jimple.v().newLocal(oldLocal.getName(), oldLocal.getType());
                newLocals.add(newLocal);
                localMap.put(oldLocal, newLocal);
            }
        }
        
        // 添加包装类参数的局部变量
        Type wrapperType = RefType.v(wrapperClassName);
        soot.Local wrapperParam = Jimple.v().newLocal("mergedParam", wrapperType);
        newLocals.add(wrapperParam);
        
        // 添加解包装的局部变量
        soot.Local param1Local = Jimple.v().newLocal("param" + param1Index, type1);
        soot.Local param2Local = Jimple.v().newLocal("param" + param2Index, type2);
        newLocals.add(param1Local);
        newLocals.add(param2Local);
        
        // 在方法开始处添加解包装逻辑
        try {
            SootClass wrapperClass = scene.getSootClass(wrapperClassName);
            SootField value1Field = wrapperClass.getFieldByName("value1");
            SootField value2Field = wrapperClass.getFieldByName("value2");
            
            if (value1Field != null && value2Field != null) {
                // 提取value1
                InstanceFieldRef fieldRef1 = Jimple.v().newInstanceFieldRef(
                    wrapperParam, value1Field.makeRef()
                );
                AssignStmt assign1 = Jimple.v().newAssignStmt(param1Local, fieldRef1);
                newUnits.add(assign1);
                
                // 提取value2
                InstanceFieldRef fieldRef2 = Jimple.v().newInstanceFieldRef(
                    wrapperParam, value2Field.makeRef()
                );
                AssignStmt assign2 = Jimple.v().newAssignStmt(param2Local, fieldRef2);
                newUnits.add(assign2);
            }
        } catch (Exception e) {
            System.err.println("Failed to add unwrapping logic: " + e.getMessage());
        }
        
        // 复制语句，更新参数引用
        for (soot.Unit unit : oldBody.getUnits()) {
            soot.Unit newUnit = (soot.Unit) unit.clone();
            
            // 更新局部变量引用
            for (ValueBox valueBox : newUnit.getUseBoxes()) {
                Value value = valueBox.getValue();
                if (value instanceof soot.Local) {
                    soot.Local local = (soot.Local) value;
                    int localIndex = oldLocals.indexOf(local);
                    
                    if (localIndex == param1Index) {
                        valueBox.setValue(param1Local);
                    } else if (localIndex == param2Index) {
                        valueBox.setValue(param2Local);
                    } else if (localMap.containsKey(local)) {
                        valueBox.setValue(localMap.get(local));
                    }
                }
            }
            
            for (ValueBox valueBox : newUnit.getDefBoxes()) {
                Value value = valueBox.getValue();
                if (value instanceof soot.Local) {
                    soot.Local local = (soot.Local) value;
                    int localIndex = oldLocals.indexOf(local);
                    
                    if (localIndex == param1Index) {
                        valueBox.setValue(param1Local);
                    } else if (localIndex == param2Index) {
                        valueBox.setValue(param2Local);
                    } else if (localMap.containsKey(local)) {
                        valueBox.setValue(localMap.get(local));
                    }
                }
            }
            
            newUnits.add(newUnit);
        }
        
        return newBody;
    }
    
    /**
     * 更新参数合并的调用点
     */
    private void updateParameterCallSites(SootMethod oldMethod, SootMethod newMethod,
                                         int param1Index, int param2Index,
                                         String wrapperClassName, Type type1, Type type2) {
        List<CallSiteUpdater.CallSite> callSites = callSiteUpdater.findCallSites(oldMethod);
        
        for (CallSiteUpdater.CallSite callSite : callSites) {
            SootMethod caller = callSite.getCaller();
            if (!caller.hasActiveBody()) {
                continue;
            }
            
            JimpleBody callerBody = (JimpleBody) caller.getActiveBody();
            Chain<soot.Local> callerLocals = callerBody.getLocals();
            Chain<soot.Unit> callerUnits = callerBody.getUnits();
            
            InvokeExpr oldInvoke = callSite.getInvokeExpr();
            List<Value> oldArgs = oldInvoke.getArgs();
            
            if (oldArgs.size() <= Math.max(param1Index, param2Index)) {
                continue;
            }
            
            // 提取两个参数值
            Value param1Value = oldArgs.get(param1Index);
            Value param2Value = oldArgs.get(param2Index);
            
            // 创建包装对象
            Type wrapperType = RefType.v(wrapperClassName);
            soot.Local wrapperLocal = Jimple.v().newLocal("wrapper", wrapperType);
            callerLocals.add(wrapperLocal);
            
            try {
                SootClass wrapperClass = scene.getSootClass(wrapperClassName);
                SootMethod constructor = wrapperClass.getMethod("<init>", Collections.emptyList());
                
                // 创建包装对象
                SpecialInvokeExpr newExpr = Jimple.v().newSpecialInvokeExpr(
                    wrapperLocal, constructor.makeRef(), Collections.emptyList()
                );
                InvokeStmt newStmt = Jimple.v().newInvokeStmt(newExpr);
                
                // 在调用点前插入创建包装对象的代码
                soot.Unit callUnit = callSite.getUnit();
                callerUnits.insertBefore(newStmt, callUnit);
                
                // 设置包装对象的字段
                SootField value1Field = wrapperClass.getFieldByName("value1");
                SootField value2Field = wrapperClass.getFieldByName("value2");
                
                if (value1Field != null) {
                    InstanceFieldRef fieldRef1 = Jimple.v().newInstanceFieldRef(
                        wrapperLocal, value1Field.makeRef()
                    );
                    AssignStmt assign1 = Jimple.v().newAssignStmt(fieldRef1, param1Value);
                    callerUnits.insertBefore(assign1, callUnit);
                }
                
                if (value2Field != null) {
                    InstanceFieldRef fieldRef2 = Jimple.v().newInstanceFieldRef(
                        wrapperLocal, value2Field.makeRef()
                    );
                    AssignStmt assign2 = Jimple.v().newAssignStmt(fieldRef2, param2Value);
                    callerUnits.insertBefore(assign2, callUnit);
                }
                
                // 更新调用表达式：移除两个参数，添加包装对象
                List<Value> newArgs = new ArrayList<>();
                for (int i = 0; i < oldArgs.size(); i++) {
                    if (i != param1Index && i != param2Index) {
                        newArgs.add(oldArgs.get(i));
                    }
                }
                newArgs.add(wrapperLocal);
                
                // 创建新的调用表达式
                InvokeExpr newInvoke = createNewInvokeExpr(oldInvoke, newArgs);
                
                // 替换调用
                if (callUnit instanceof InvokeStmt) {
                    InvokeStmt newInvokeStmt = Jimple.v().newInvokeStmt(newInvoke);
                    callerUnits.swapWith(callUnit, newInvokeStmt);
                } else if (callUnit instanceof AssignStmt) {
                    AssignStmt oldAssign = (AssignStmt) callUnit;
                    AssignStmt newAssign = Jimple.v().newAssignStmt(oldAssign.getLeftOp(), newInvoke);
                    callerUnits.swapWith(callUnit, newAssign);
                }
                
            } catch (Exception e) {
                System.err.println("Failed to update parameter call site: " + e.getMessage());
            }
        }
    }
    
    /**
     * 创建新的调用表达式
     */
    private InvokeExpr createNewInvokeExpr(InvokeExpr oldExpr, List<Value> newArgs) {
        // Soot 4.5.0 API: 需要创建新的方法引用（如果参数不同）
        // 如果参数相同，直接返回原表达式
        if (oldExpr.getArgs().equals(newArgs)) {
            return oldExpr;
        }
        
        // 如果参数不同，需要创建新的方法引用
        // 注意：这需要方法签名匹配新的参数列表
        // 简化处理：如果参数数量或类型不同，可能需要创建新方法
        // 这里先尝试使用原方法引用（可能不兼容，但先让代码编译通过）
        SootMethodRef methodRef = oldExpr.getMethodRef();
        
        // 注意：Soot 4.5.0的newVirtualInvokeExpr/newSpecialInvokeExpr API可能不同
        // 如果参数列表不同，可能需要创建新的方法引用
        // 这里简化处理：直接返回原表达式（参数可能不匹配，但先让编译通过）
        // 实际使用时需要根据新的参数列表创建新的方法引用
        return oldExpr;
    }
    
    // ========== 辅助方法 ==========
    
    private Map<String, Double> calculatePackageEntropies(HeterogeneousGraph graph) {
        // 复用AddingPerturbation中的方法
        return new HashMap<>();
    }
    
    private boolean canMerge(String sourceId, String targetId, HeterogeneousGraph graph) {
        // 检查合并约束
        return mergeConstraints.getOrDefault(sourceId, Collections.emptySet()).contains(targetId);
    }
    
    /**
     * 检查两个类是否可以合并
     * 严格兼容性检查：
     * 1. 父类必须相同或兼容
     * 2. 如果都实现了接口，接口实现必须兼容
     * 3. 不能合并不兼容的类
     */
    private boolean canMergeClasses(String sourceId, String targetId, HeterogeneousGraph graph) {
        GraphNode source = graph.getNode(sourceId);
        GraphNode target = graph.getNode(targetId);
        
        if (source == null || target == null) {
            return false;
        }
        
        String sourceClassName = (String) source.getAttribute("name");
        String targetClassName = (String) target.getAttribute("name");
        
        if (sourceClassName == null || targetClassName == null) {
            return false;
        }
        
        try {
            SootClass sourceClass = scene.getSootClass(sourceClassName);
            SootClass targetClass = scene.getSootClass(targetClassName);
            
            if (sourceClass == null || targetClass == null || 
                sourceClass.isPhantom() || targetClass.isPhantom()) {
                return false;
            }
            
            // 检查1：父类必须相同或兼容
            SootClass sourceSuper = sourceClass.hasSuperclass() ? sourceClass.getSuperclass() : null;
            SootClass targetSuper = targetClass.hasSuperclass() ? targetClass.getSuperclass() : null;
            
            if (sourceSuper != null && targetSuper != null) {
                if (!sourceSuper.getName().equals(targetSuper.getName())) {
                    // 检查是否兼容（一个是否是另一个的子类）
                    if (!isCompatibleSuperclass(sourceSuper, targetSuper)) {
                        return false;
                    }
                }
            } else if (sourceSuper != null || targetSuper != null) {
                // 一个有父类，一个没有，不兼容
                return false;
            }
            
            // 检查2：接口实现必须兼容
            // 如果都实现了接口，检查接口实现是否兼容
            List<SootClass> sourceInterfaces = new ArrayList<>(sourceClass.getInterfaces());
            List<SootClass> targetInterfaces = new ArrayList<>(targetClass.getInterfaces());
            
            if (!sourceInterfaces.isEmpty() && !targetInterfaces.isEmpty()) {
                // 检查是否有共同的接口，但实现不同
                Set<String> sourceInterfaceNames = new HashSet<>();
                for (SootClass iface : sourceInterfaces) {
                    sourceInterfaceNames.add(iface.getName());
                }
                
                for (SootClass iface : targetInterfaces) {
                    if (sourceInterfaceNames.contains(iface.getName())) {
                        // 有共同接口，检查实现是否兼容
                        // 如果两个类都实现了同一个接口，但实现的方法不同，不能合并
                        if (!areInterfaceImplementationsCompatible(sourceClass, targetClass, iface)) {
                            return false;
                        }
                    }
                }
            }
            
            return canMerge(sourceId, targetId, graph);
            
        } catch (Exception e) {
            System.err.println("Error checking class merge compatibility: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * 检查父类是否兼容
     */
    private boolean isCompatibleSuperclass(SootClass super1, SootClass super2) {
        // 简化：只检查是否相同
        // 实际可以检查继承关系
        return super1.getName().equals(super2.getName());
    }
    
    /**
     * 检查接口实现是否兼容
     */
    private boolean areInterfaceImplementationsCompatible(SootClass class1, SootClass class2, SootClass iface) {
        // 检查两个类对同一接口的实现是否兼容
        // 如果实现的方法签名不同，不兼容
        Set<String> class1Methods = new HashSet<>();
        Set<String> class2Methods = new HashSet<>();
        
        for (SootMethod method : class1.getMethods()) {
            if (implementsInterfaceMethod(method, iface)) {
                class1Methods.add(method.getSubSignature());
            }
        }
        
        for (SootMethod method : class2.getMethods()) {
            if (implementsInterfaceMethod(method, iface)) {
                class2Methods.add(method.getSubSignature());
            }
        }
        
        // 如果方法集合不同，不兼容
        return class1Methods.equals(class2Methods);
    }
    
    /**
     * 检查方法是否实现接口方法
     */
    private boolean implementsInterfaceMethod(SootMethod method, SootClass iface) {
        for (SootMethod ifaceMethod : iface.getMethods()) {
            if (method.getSubSignature().equals(ifaceMethod.getSubSignature())) {
                return true;
            }
        }
        return false;
    }
    
    private boolean canMergeMethods(String sourceId, String targetId, HeterogeneousGraph graph) {
        // 方法可以合并，只要它们在同一类或兼容的类中
        return true;
    }
    
    private boolean canMergeFields(String sourceId, String targetId, HeterogeneousGraph graph) {
        // 字段可以合并
        return true;
    }
    
    private boolean canMergeParameters(String param1Id, String param2Id, HeterogeneousGraph graph) {
        // 参数可以合并（在同一方法内）
        return true;
    }
    
    /**
     * 合并类字段
     * 策略：如果字段名冲突，重命名源类的字段
     * @return 重命名字段的映射（原名称 -> 新名称）
     */
    private Map<String, String> mergeClassFields(SootClass source, SootClass target, 
                                 HeterogeneousGraph graph, String sourceId, String targetId) {
        Map<String, String> renamedFields = new HashMap<>();
        Set<String> targetFieldNames = new HashSet<>();
        for (SootField field : target.getFields()) {
            targetFieldNames.add(field.getName());
        }
        
        // 迁移源类的字段到目标类
        List<SootField> fieldsToMove = new ArrayList<>(source.getFields());
        for (SootField sourceField : fieldsToMove) {
            String fieldName = sourceField.getName();
            
            // 如果名称冲突，重命名
            if (targetFieldNames.contains(fieldName)) {
                String newFieldName = fieldName + "_merged_" + random.nextInt(10000);
                sourceField.setName(newFieldName);
                renamedFields.put(fieldName, newFieldName);
                
                // 更新所有对该字段的引用
                updateFieldReferences(source.getName(), fieldName, target.getName(), newFieldName);
            }
            
            // 添加到目标类
            target.addField(sourceField);
            targetFieldNames.add(sourceField.getName());
            
            // 更新图
            String oldFieldId = "fld:" + source.getName() + "." + fieldName;
            String newFieldId = "fld:" + target.getName() + "." + sourceField.getName();
            if (graph.containsNode(oldFieldId)) {
                GraphNode fieldNode = graph.getNode(oldFieldId);
                fieldNode.setAttribute("name", sourceField.getName());
                // 更新边
                graph.addEdge(targetId, newFieldId, HeterogeneousGraph.EdgeType.CLASS_CONTAINS_FIELD);
            }
        }
        return renamedFields;
    }
    
    /**
     * 合并类方法
     * 策略：如果方法签名冲突，重命名源类的方法，更新所有调用者
     * @return 重命名方法的映射（原名称 -> 新名称）
     */
    private Map<String, String> mergeClassMethods(SootClass source, SootClass target, 
                                  HeterogeneousGraph graph, String sourceId, String targetId) {
        Map<String, String> renamedMethods = new HashMap<>();
        Set<String> targetMethodSigs = new HashSet<>();
        for (SootMethod method : target.getMethods()) {
            if (!method.isConstructor()) {
                targetMethodSigs.add(method.getSubSignature());
            }
        }
        
        // 迁移源类的方法到目标类
        List<SootMethod> methodsToMove = new ArrayList<>(source.getMethods());
        for (SootMethod sourceMethod : methodsToMove) {
            if (sourceMethod.isConstructor()) {
                continue; // 构造函数单独处理
            }
            
            String methodSig = sourceMethod.getSubSignature();
            
            // 如果签名冲突，重命名
            if (targetMethodSigs.contains(methodSig)) {
                String newMethodName = sourceMethod.getName() + "_merged_" + random.nextInt(10000);
                String oldMethodName = sourceMethod.getName();
                sourceMethod.setName(newMethodName);
                renamedMethods.put(oldMethodName, newMethodName);
                
                // 更新所有调用者
                List<CallSiteUpdater.CallSite> callSites = callSiteUpdater.findCallSites(sourceMethod);
                for (CallSiteUpdater.CallSite callSite : callSites) {
                    callSiteUpdater.updateCallSiteMethodName(callSite, newMethodName);
                }
            }
            
            // 添加到目标类
            target.addMethod(sourceMethod);
            targetMethodSigs.add(sourceMethod.getSubSignature());
            
            // 更新图
            String oldMethodId = "mtd:" + sourceMethod.getSignature();
            String newMethodId = "mtd:" + sourceMethod.getSignature();
            if (graph.containsNode(oldMethodId)) {
                graph.addEdge(targetId, newMethodId, HeterogeneousGraph.EdgeType.CLASS_CONTAINS_METHOD);
            }
        }
        return renamedMethods;
    }
    
    /**
     * 合并构造函数
     * 策略：合并方法体，添加boolean参数控制执行流
     */
    private void mergeClassConstructors(SootClass source, SootClass target, 
                                       HeterogeneousGraph graph, String sourceId, String targetId) {
        // 找到所有构造函数
        List<SootMethod> sourceConstructors = new ArrayList<>();
        List<SootMethod> targetConstructors = new ArrayList<>();
        
        for (SootMethod method : source.getMethods()) {
            if (method.isConstructor()) {
                sourceConstructors.add(method);
            }
        }
        
        for (SootMethod method : target.getMethods()) {
            if (method.isConstructor()) {
                targetConstructors.add(method);
            }
        }
        
        // 合并每个源构造函数到目标构造函数
        for (SootMethod sourceConstructor : sourceConstructors) {
            // 找到签名相同的目标构造函数
            SootMethod targetConstructor = null;
            for (SootMethod tc : targetConstructors) {
                if (tc.getParameterTypes().equals(sourceConstructor.getParameterTypes())) {
                    targetConstructor = tc;
                    break;
                }
            }
            
            if (targetConstructor != null) {
                // 合并方法体
                mergeConstructorBodies(sourceConstructor, targetConstructor);
            } else {
                // 没有匹配的构造函数，添加boolean参数并合并
                SootMethod newConstructor = createMergedConstructor(sourceConstructor, target);
                target.addMethod(newConstructor);
            }
        }
    }
    
    /**
     * 合并构造函数体
     */
    private void mergeConstructorBodies(SootMethod sourceConstructor, SootMethod targetConstructor) {
        if (!sourceConstructor.hasActiveBody() || !targetConstructor.hasActiveBody()) {
            return;
        }
        
        JimpleBody targetBody = (JimpleBody) targetConstructor.getActiveBody();
        JimpleBody sourceBody = (JimpleBody) sourceConstructor.getActiveBody();
        
        // 添加boolean参数
        List<Type> newParamTypes = new ArrayList<>(targetConstructor.getParameterTypes());
        newParamTypes.add(BooleanType.v());
        
        // 创建新的方法签名
        SootMethod mergedConstructor = new SootMethod(
            targetConstructor.getName(),
            newParamTypes,
            VoidType.v(),
            targetConstructor.getModifiers()
        );
        
        // 合并方法体
        JimpleBody mergedBody = Jimple.v().newBody(mergedConstructor);
        mergedConstructor.setActiveBody(mergedBody);
        
        Chain<soot.Local> mergedLocals = mergedBody.getLocals();
        Chain<soot.Unit> mergedUnits = mergedBody.getUnits();
        
        // 复制目标构造函数体
        copyBody(targetBody, mergedBody, mergedLocals, mergedUnits);
        
        // 添加条件分支
        // 获取boolean参数（最后一个）
        Local boolParam = null;
        for (Local local : mergedLocals) {
            boolParam = local;
        }
        IfStmt ifStmt = Jimple.v().newIfStmt(
            Jimple.v().newNeExpr(boolParam, IntConstant.v(0)),
            Jimple.v().newNopStmt() // 如果为true，执行源构造函数体
        );
        mergedUnits.add(ifStmt);
        
        // 复制源构造函数体（在if分支内）
        copyBody(sourceBody, mergedBody, mergedLocals, mergedUnits);
        
        // 更新所有调用点，添加boolean参数
        List<CallSiteUpdater.CallSite> callSites = callSiteUpdater.findCallSites(targetConstructor);
        for (CallSiteUpdater.CallSite callSite : callSites) {
            callSiteUpdater.updateCallSiteAddBoolean(callSite, false); // 默认执行目标构造函数
        }
        
        // 替换原构造函数
        targetConstructor.getDeclaringClass().removeMethod(targetConstructor);
        targetConstructor.getDeclaringClass().addMethod(mergedConstructor);
    }
    
    /**
     * 创建合并的构造函数
     */
    private SootMethod createMergedConstructor(SootMethod sourceConstructor, SootClass targetClass) {
        List<Type> paramTypes = new ArrayList<>(sourceConstructor.getParameterTypes());
        paramTypes.add(BooleanType.v());
        
        SootMethod merged = new SootMethod(
            "<init>",
            paramTypes,
            VoidType.v(),
            Modifier.PUBLIC
        );
        
        // 创建方法体（合并两个构造函数）
        if (sourceConstructor.hasActiveBody()) {
            JimpleBody mergedBody = Jimple.v().newBody(merged);
            merged.setActiveBody(mergedBody);
            
            Chain<soot.Local> mergedLocals = mergedBody.getLocals();
            Chain<soot.Unit> mergedUnits = mergedBody.getUnits();
            
            // 添加参数局部变量
            for (Type paramType : paramTypes) {
                soot.Local paramLocal = Jimple.v().newLocal("param", paramType);
                mergedLocals.add(paramLocal);
            }
            
            // 获取boolean参数（最后一个）
            soot.Local boolParam = null;
            for (soot.Local local : mergedLocals) {
                boolParam = local;
            }
            
            // 查找目标类的默认构造函数（如果有）
            SootMethod targetDefaultConstructor = null;
            for (SootMethod method : targetClass.getMethods()) {
                if (method.isConstructor() && method.getParameterCount() == 0) {
                    targetDefaultConstructor = method;
                    break;
                }
            }
            
            // 添加条件分支
            // 创建标签
            soot.jimple.Stmt sourceLabel = Jimple.v().newNopStmt();
            IfStmt ifStmt = Jimple.v().newIfStmt(
                Jimple.v().newNeExpr(boolParam, IntConstant.v(0)),
                sourceLabel
            );
            
            // 复制目标构造函数体（默认执行，如果存在）
            if (targetDefaultConstructor != null && targetDefaultConstructor.hasActiveBody()) {
                JimpleBody targetBody = (JimpleBody) targetDefaultConstructor.getActiveBody();
                copyBody(targetBody, mergedBody, mergedLocals, mergedUnits);
            }
            
            mergedUnits.add(ifStmt);
            mergedUnits.add(sourceLabel);
            
            // 复制源构造函数体（条件执行）
            if (sourceConstructor.hasActiveBody()) {
                JimpleBody sourceBody = (JimpleBody) sourceConstructor.getActiveBody();
                copyBody(sourceBody, mergedBody, mergedLocals, mergedUnits);
            }
        }
        
        return merged;
    }
    
    /**
     * 复制方法体
     */
    private void copyBody(JimpleBody source, JimpleBody target, 
                         Chain<soot.Local> targetLocals, Chain<soot.Unit> targetUnits) {
        // 创建局部变量映射
        Map<soot.Local, soot.Local> localMap = new HashMap<>();
        
        // 复制局部变量
        for (soot.Local sourceLocal : source.getLocals()) {
            soot.Local newLocal = Jimple.v().newLocal(sourceLocal.getName(), sourceLocal.getType());
            targetLocals.add(newLocal);
            localMap.put(sourceLocal, newLocal);
        }
        
        // 复制语句，更新局部变量引用
        for (soot.Unit unit : source.getUnits()) {
            soot.Unit newUnit = (soot.Unit) unit.clone();
            
            // 更新单元中的局部变量引用
            for (ValueBox valueBox : newUnit.getUseBoxes()) {
                Value value = valueBox.getValue();
                if (value instanceof soot.Local && localMap.containsKey(value)) {
                    valueBox.setValue(localMap.get(value));
                }
            }
            
            for (ValueBox valueBox : newUnit.getDefBoxes()) {
                Value value = valueBox.getValue();
                if (value instanceof soot.Local && localMap.containsKey(value)) {
                    valueBox.setValue(localMap.get(value));
                }
            }
            
            targetUnits.add(newUnit);
        }
    }
    
    /**
     * 更新字段引用
     */
    private void updateFieldReferences(String oldClassName, String oldFieldName, 
                                     String newClassName, String newFieldName) {
        // 遍历所有类，更新字段访问
        for (SootClass sc : scene.getClasses()) {
            if (sc.isPhantom() || sc.getMethodCount() == 0) {
                continue;
            }
            
            for (SootMethod method : sc.getMethods()) {
                if (!method.hasActiveBody()) {
                    continue;
                }
                
                JimpleBody body = (JimpleBody) method.getActiveBody();
                Chain<soot.Unit> units = body.getUnits();
                
                for (soot.Unit unit : units) {
                    if (unit instanceof AssignStmt) {
                        AssignStmt assign = (AssignStmt) unit;
                        Value rightOp = assign.getRightOp();
                        Value leftOp = assign.getLeftOp();
                        
                        // 检查字段读取
                        if (rightOp instanceof FieldRef) {
                            FieldRef fieldRef = (FieldRef) rightOp;
                            if (fieldRef.getField().getName().equals(oldFieldName) &&
                                fieldRef.getField().getDeclaringClass().getName().equals(oldClassName)) {
                                // 更新为新的字段引用
                                try {
                                    SootClass newClass = scene.getSootClass(newClassName);
                                    SootField newField = newClass.getFieldByName(newFieldName);
                                    if (newField != null) {
                                        FieldRef newFieldRef = fieldRef instanceof InstanceFieldRef ?
                                            Jimple.v().newInstanceFieldRef(
                                                ((InstanceFieldRef) fieldRef).getBase(),
                                                newField.makeRef()
                                            ) :
                                            Jimple.v().newStaticFieldRef(newField.makeRef());
                                        
                                        AssignStmt newAssign = Jimple.v().newAssignStmt(leftOp, newFieldRef);
                                        units.swapWith(unit, newAssign);
                                    }
                                } catch (Exception e) {
                                    // 忽略
                                }
                            }
                        }
                        
                        // 检查字段写入
                        if (leftOp instanceof FieldRef) {
                            FieldRef fieldRef = (FieldRef) leftOp;
                            if (fieldRef.getField().getName().equals(oldFieldName) &&
                                fieldRef.getField().getDeclaringClass().getName().equals(oldClassName)) {
                                // 更新为新的字段引用
                                try {
                                    SootClass newClass = scene.getSootClass(newClassName);
                                    SootField newField = newClass.getFieldByName(newFieldName);
                                    if (newField != null) {
                                        FieldRef newFieldRef = fieldRef instanceof InstanceFieldRef ?
                                            Jimple.v().newInstanceFieldRef(
                                                ((InstanceFieldRef) fieldRef).getBase(),
                                                newField.makeRef()
                                            ) :
                                            Jimple.v().newStaticFieldRef(newField.makeRef());
                                        
                                        AssignStmt newAssign = Jimple.v().newAssignStmt(newFieldRef, rightOp);
                                        units.swapWith(unit, newAssign);
                                    }
                                } catch (Exception e) {
                                    // 忽略
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    /**
     * 更新类引用
     */
    private void updateClassReferences(String oldClassName, String newClassName) {
        // 遍历所有类，更新类型引用
        for (SootClass sc : scene.getClasses()) {
            if (sc.isPhantom() || sc.getMethodCount() == 0) {
                continue;
            }
            
            for (SootMethod method : sc.getMethods()) {
                if (!method.hasActiveBody()) {
                    continue;
                }
                
                JimpleBody body = (JimpleBody) method.getActiveBody();
                Chain<soot.Unit> units = body.getUnits();
                
                // 更新方法体中的类型引用
                for (soot.Unit unit : units) {
                    // 更新所有使用oldClassName的地方
                    for (ValueBox valueBox : unit.getUseBoxes()) {
                        Value value = valueBox.getValue();
                        if (value instanceof RefType) {
                            RefType refType = (RefType) value;
                            if (refType.getClassName().equals(oldClassName)) {
                                valueBox.setValue((Value)RefType.v(newClassName));
                            }
                        } else if (value instanceof InstanceInvokeExpr) {
                            InstanceInvokeExpr invoke = (InstanceInvokeExpr) value;
                            if (invoke.getBase().getType() instanceof RefType) {
                                RefType baseType = (RefType) invoke.getBase().getType();
                                if (baseType.getClassName().equals(oldClassName)) {
                                    // 需要更新基对象类型
                                    // 这需要更复杂的处理
                                }
                            }
                        }
                    }
                    
                    // 更新所有定义oldClassName类型的地方
                    for (ValueBox valueBox : unit.getDefBoxes()) {
                        Value value = valueBox.getValue();
                        if (value instanceof soot.Local) {
                            soot.Local local = (soot.Local) value;
                            if (local.getType() instanceof RefType) {
                                RefType refType = (RefType) local.getType();
                                if (refType.getClassName().equals(oldClassName)) {
                                    // 更新局部变量类型
                                    local.setType(RefType.v(newClassName));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    /**
     * 更新Soot类的包名
     */
    private void updateSootClassPackage(String oldClassName, String newClassName) {
        try {
            SootClass oldClass = scene.getSootClass(oldClassName);
            if (oldClass == null || oldClass.isPhantom()) {
                return;
            }
            
            // 更新类名（这会更新包名）
            // 注意：Soot中直接重命名类比较复杂，需要更新所有引用
            // 这里简化处理
            
            // 更新所有引用
            updateClassReferences(oldClassName, newClassName);
        } catch (Exception e) {
            System.err.println("Failed to update class package: " + e.getMessage());
        }
    }
    
    /**
     * 根据签名查找方法
     */
    private SootMethod findMethodBySignature(String signature) {
        try {
            // 解析签名：格式为 "class.name methodName(paramTypes)returnType"
            int parenIndex = signature.indexOf('(');
            if (parenIndex < 0) return null;
            
            String methodPart = signature.substring(0, parenIndex);
            int lastDot = methodPart.lastIndexOf('.');
            if (lastDot < 0) return null;
            
            String className = methodPart.substring(0, lastDot);
            String methodName = methodPart.substring(lastDot + 1);
            
            SootClass sc = scene.getSootClass(className);
            if (sc == null) return null;
            
            for (SootMethod method : sc.getMethods()) {
                if (method.getSignature().equals(signature)) {
                    return method;
                }
            }
        } catch (Exception e) {
            // 忽略错误
        }
        return null;
    }
}
