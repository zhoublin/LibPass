package com.libpass.attack.perturbation;

import com.libpass.attack.graph.HeterogeneousGraph;
import com.libpass.attack.graph.GraphNode;
import com.libpass.attack.entropy.GraphEntropyCalculator;
import soot.*;
import soot.jimple.*;
import soot.util.Chain;
import java.util.*;
import com.libpass.attack.perturbation.CallSiteUpdater;

import com.libpass.attack.util.Logger;
/**
 * 添加节点扰动操作
 * 实现5种类型的节点添加：package, class, method, field, parameter
 */
public class AddingPerturbation {
    private GraphEntropyCalculator entropyCalculator;
    private Scene scene;
    private Random random;
    private ModificationLogger logger;
    private static final double MU = 0.5;
    
    public AddingPerturbation(Scene scene) {
        this(scene, null);
    }
    
    public AddingPerturbation(Scene scene, ModificationLogger logger) {
        this.scene = scene;
        this.logger = logger;
        this.entropyCalculator = new GraphEntropyCalculator();
        this.random = new Random();
    }
    
    /**
     * 添加包节点
     */
    public void addPackages(HeterogeneousGraph graph, int k) {
        // 计算包熵（聚合类熵）
        Map<String, Double> packageEntropies = calculatePackageEntropies(graph);
        
        // 按熵值排序（升序）
        List<Map.Entry<String, Double>> sortedPackages = new ArrayList<>(packageEntropies.entrySet());
        sortedPackages.sort(Map.Entry.comparingByValue());
        
        // 选择top-k包作为目标
        int count = Math.min(k, sortedPackages.size());
        for (int i = 0; i < count; i++) {
            String targetPkgId = sortedPackages.get(i).getKey();
            GraphNode targetPkg = graph.getNode(targetPkgId);
            
            if (targetPkg == null || !canAddChild(targetPkg)) {
                continue;
            }
            
            // 创建新包节点
            String newPackageName = generatePackageName(targetPkg);
            String newPkgId = "pkg:" + newPackageName;
            
            GraphNode newPkg = new GraphNode(newPkgId, HeterogeneousGraph.NodeType.PACKAGE);
            newPkg.setAttribute("name", newPackageName);
            graph.addNode(newPkg);
            
            // 建立包含关系
            graph.addEdge(targetPkgId, newPkgId, 
                HeterogeneousGraph.EdgeType.PACKAGE_CONTAINS_PACKAGE);
        }
    }
    
    /**
     * 添加类节点
     * 要求：添加默认构造函数，与已有类建立依赖关系
     */
    public void addClasses(HeterogeneousGraph graph, int k, Set<SootClass> tplClasses) {
        // 计算包熵
        Map<String, Double> packageEntropies = calculatePackageEntropies(graph);
        List<Map.Entry<String, Double>> sortedPackages = new ArrayList<>(packageEntropies.entrySet());
        sortedPackages.sort(Map.Entry.comparingByValue());
        
        int count = Math.min(k, sortedPackages.size());
        for (int i = 0; i < count; i++) {
            String targetPkgId = sortedPackages.get(i).getKey();
            GraphNode targetPkg = graph.getNode(targetPkgId);
            
            if (targetPkg == null || !canAddChild(targetPkg)) {
                continue;
            }
            
            // 创建新类
            String packageName = (String) targetPkg.getAttribute("name");
            String className = generateClassName(packageName);
            String fullClassName = packageName.isEmpty() ? className : packageName + "." + className;
            String classId = "cls:" + fullClassName;
            
            // 在Soot中创建类
            SootClass newClass = createSootClass(fullClassName, tplClasses);
            if (newClass == null) {
                continue;
            }
            
            // 添加到图
            GraphNode classNode = new GraphNode(classId, HeterogeneousGraph.NodeType.CLASS);
            classNode.setAttribute("name", fullClassName);
            classNode.setAttribute("modifiers", newClass.getModifiers());
            graph.addNode(classNode);
            
            // 建立包包含类的关系
            graph.addEdge(targetPkgId, classId, HeterogeneousGraph.EdgeType.PACKAGE_CONTAINS_CLASS);
            
            // 建立依赖关系：让新类继承或实现已有类/接口，避免成为孤岛
            establishClassDependencies(graph, classId, newClass, tplClasses);
            
            // 记录添加类操作
            if (logger != null) {
                List<SootField> fields = new ArrayList<>();
                List<SootMethod> methods = new ArrayList<>();
                for (SootField field : newClass.getFields()) {
                    fields.add(field);
                }
                for (SootMethod method : newClass.getMethods()) {
                    methods.add(method);
                }
                logger.logAddClass(newClass, fields, methods);
            }
            
            // 打印添加类详情（debug级别）
            Logger.debug("\n=== 添加类详情 ===");
            Logger.debug("新建类: %s", fullClassName);
            Logger.debug("  包: %s", packageName);
            Logger.debug("  修饰符: %d", newClass.getModifiers());
            Logger.debug("  字段数: %d", newClass.getFieldCount());
            Logger.debug("  方法数: %d", newClass.getMethodCount());
            if (!newClass.getFields().isEmpty()) {
                Logger.debug("  字段列表:");
                for (SootField field : newClass.getFields()) {
                    Logger.debug("    - %s (%s)", field.getName(), field.getType());
                }
            }
            if (!newClass.getMethods().isEmpty()) {
                Logger.debug("  方法列表:");
                for (SootMethod method : newClass.getMethods()) {
                    Logger.debug("    - %s -> %s", method.getName(), method.getReturnType());
                }
            }
            Logger.debug("==================\n");
        }
    }
    
    /**
     * 添加方法节点
     * 要求：使用反射调用参数，建立依赖关系，避免死代码
     */
    public void addMethods(HeterogeneousGraph graph, int k, Set<SootClass> tplClasses) {
        // 获取按熵排序的类
        List<String> sortedClasses = entropyCalculator.getClassesSortedByEntropy(graph, MU);
        
        int count = Math.min(k, sortedClasses.size());
        for (int i = 0; i < count; i++) {
            String targetClassId = sortedClasses.get(i);
            GraphNode targetClassNode = graph.getNode(targetClassId);
            
            if (targetClassNode == null || !canAddChild(targetClassNode)) {
                continue;
            }
            
            // 获取Soot类
            String className = (String) targetClassNode.getAttribute("name");
            SootClass sootClass = scene.getSootClass(className);
            if (sootClass == null || sootClass.isPhantom()) {
                continue;
            }
            
            // 创建新方法
            SootMethod newMethod = createMethodWithDependencies(sootClass, tplClasses);
            if (newMethod == null) {
                continue;
            }
            
            // 添加到图
            String methodId = "mtd:" + newMethod.getSignature();
            GraphNode methodNode = new GraphNode(methodId, HeterogeneousGraph.NodeType.METHOD);
            methodNode.setAttribute("name", newMethod.getName());
            methodNode.setAttribute("signature", newMethod.getSignature());
            methodNode.setAttribute("returnType", newMethod.getReturnType().toString());
            graph.addNode(methodNode);
            
            // 建立类包含方法的关系
            graph.addEdge(targetClassId, methodId, HeterogeneousGraph.EdgeType.CLASS_CONTAINS_METHOD);
            
            // 建立方法调用关系（通过反射调用参数）
            establishMethodDependencies(graph, methodId, newMethod, tplClasses);
            
            // 记录添加方法操作
            if (logger != null) {
                logger.logAddMethod(newMethod, sootClass);
            }
            
            // 打印添加方法详情（debug级别）
            Logger.debug("\n=== 添加方法详情 ===");
            Logger.debug("所属类: %s", className);
            Logger.debug("新建方法: %s", newMethod.getName());
            Logger.debug("  签名: %s", newMethod.getSignature());
            Logger.debug("  返回类型: %s", newMethod.getReturnType());
            Logger.debug("  参数数量: %d", newMethod.getParameterCount());
            if (newMethod.getParameterCount() > 0) {
                Logger.debug("  参数列表:");
                List<Type> paramTypes = newMethod.getParameterTypes();
                for (int paramIdx = 0; paramIdx < paramTypes.size(); paramIdx++) {
                    Logger.debug("    - param%d: %s", paramIdx, paramTypes.get(paramIdx));
                }
            }
            Logger.debug("  修饰符: %d", newMethod.getModifiers());
            Logger.debug("==================\n");
        }
    }
    
    /**
     * 添加字段节点
     * 要求：建立类型依赖关系
     */
    public void addFields(HeterogeneousGraph graph, int k, Set<SootClass> tplClasses) {
        List<String> sortedClasses = entropyCalculator.getClassesSortedByEntropy(graph, MU);
        
        int count = Math.min(k, sortedClasses.size());
        for (int i = 0; i < count; i++) {
            String targetClassId = sortedClasses.get(i);
            GraphNode targetClassNode = graph.getNode(targetClassId);
            
            if (targetClassNode == null || !canAddChild(targetClassNode)) {
                continue;
            }
            
            String className = (String) targetClassNode.getAttribute("name");
            SootClass sootClass = scene.getSootClass(className);
            if (sootClass == null || sootClass.isPhantom()) {
                continue;
            }
            
            // 创建新字段
            SootField newField = createFieldWithDependencies(sootClass, tplClasses);
            if (newField == null) {
                continue;
            }
            
            // 添加到图
            String fieldId = "fld:" + className + "." + newField.getName();
            GraphNode fieldNode = new GraphNode(fieldId, HeterogeneousGraph.NodeType.FIELD);
            fieldNode.setAttribute("name", newField.getName());
            fieldNode.setAttribute("type", newField.getType().toString());
            graph.addNode(fieldNode);
            
            // 建立类包含字段的关系
            graph.addEdge(targetClassId, fieldId, HeterogeneousGraph.EdgeType.CLASS_CONTAINS_FIELD);
            
            // 建立字段类型引用关系
            establishFieldDependencies(graph, fieldId, newField);
            
            // 记录添加字段操作
            if (logger != null) {
                logger.logAddField(newField, sootClass);
            }
            
            // 打印添加字段详情（debug级别）
            Logger.debug("\n=== 添加字段详情 ===");
            Logger.debug("所属类: %s", className);
            Logger.debug("新建字段: %s", newField.getName());
            Logger.debug("  类型: %s", newField.getType());
            Logger.debug("  修饰符: %d", newField.getModifiers());
            Logger.debug("==================\n");
        }
    }
    
    /**
     * 添加参数节点
     * 要求：更新所有调用点
     */
    public void addParameters(HeterogeneousGraph graph, int k, Set<SootClass> tplClasses) {
        List<String> sortedClasses = entropyCalculator.getClassesSortedByEntropy(graph, MU);
        
        // 从top-k类中随机选择k个方法
        Set<String> selectedMethods = new HashSet<>();
        Random random = new Random();
        
        for (int i = 0; i < Math.min(k * 2, sortedClasses.size()) && selectedMethods.size() < k; i++) {
            String classId = sortedClasses.get(i);
            Set<String> methodIds = graph.getNeighbors(classId, 
                HeterogeneousGraph.EdgeType.CLASS_CONTAINS_METHOD);
            
            if (!methodIds.isEmpty()) {
                List<String> methodList = new ArrayList<>(methodIds);
                String selectedMethod = methodList.get(random.nextInt(methodList.size()));
                selectedMethods.add(selectedMethod);
            }
        }
        
        // 为每个选中的方法添加参数
        for (String methodId : selectedMethods) {
            GraphNode methodNode = graph.getNode(methodId);
            if (methodNode == null) {
                continue;
            }
            
            String signature = (String) methodNode.getAttribute("signature");
            if (signature == null) {
                continue;
            }
            
            // 解析方法签名，添加参数
            addParameterToMethod(graph, methodId, signature, tplClasses);
        }
    }
    
    // ========== 辅助方法 ==========
    
    /**
     * 计算包熵（聚合类熵）
     */
    private Map<String, Double> calculatePackageEntropies(HeterogeneousGraph graph) {
        Map<String, Double> packageEntropies = new HashMap<>();
        Map<String, Double> classEntropies = entropyCalculator.calculateClassEntropies(graph, MU);
        
        // 聚合类熵到包级别
        for (Map.Entry<String, Double> entry : classEntropies.entrySet()) {
            String classId = entry.getKey();
            GraphNode classNode = graph.getNode(classId);
            if (classNode == null) continue;
            
            String className = (String) classNode.getAttribute("name");
            if (className == null) continue;
            
            int lastDot = className.lastIndexOf('.');
            String packageName = lastDot > 0 ? className.substring(0, lastDot) : "";
            String pkgId = "pkg:" + packageName;
            
            if (!graph.containsNode(pkgId)) {
                continue;
            }
            
            packageEntropies.merge(pkgId, entry.getValue(), Double::sum);
        }
        
        // 平均化
        for (String pkgId : packageEntropies.keySet()) {
            Set<String> classes = graph.getNeighbors(pkgId, 
                HeterogeneousGraph.EdgeType.PACKAGE_CONTAINS_CLASS);
            if (!classes.isEmpty()) {
                packageEntropies.put(pkgId, packageEntropies.get(pkgId) / classes.size());
            }
        }
        
        return packageEntropies;
    }
    
    /**
     * 检查是否可以添加子节点
     */
    private boolean canAddChild(GraphNode node) {
        // 简化：所有节点都可以添加子节点
        // 实际应该检查约束条件
        return true;
    }
    
    /**
     * 生成包名
     */
    private String generatePackageName(GraphNode parentPkg) {
        String parentName = (String) parentPkg.getAttribute("name");
        String subPackage = "p" + random.nextInt(10000);
        return parentName.isEmpty() ? subPackage : parentName + "." + subPackage;
    }
    
    /**
     * 生成类名
     */
    private String generateClassName(String packageName) {
        return "C" + random.nextInt(10000);
    }
    
    /**
     * 创建Soot类
     */
    private SootClass createSootClass(String className, Set<SootClass> tplClasses) {
        try {
            // 检查类是否已存在
            if (scene.containsClass(className)) {
                return scene.getSootClass(className);
            }
            
            // 创建新类
            SootClass newClass = new SootClass(className, Modifier.PUBLIC);
            newClass.setSuperclass(Scene.v().getSootClass("java.lang.Object"));
            
            // 添加默认构造函数
            SootMethod constructor = new SootMethod(
                "<init>",
                Collections.emptyList(),
                VoidType.v(),
                Modifier.PUBLIC
            );
            
            // 创建构造函数体
            JimpleBody body = Jimple.v().newBody(constructor);
            constructor.setActiveBody(body);
            
            Chain<soot.Local> locals = body.getLocals();
            Chain<soot.Unit> units = body.getUnits();
            
            // 添加this参数
            Local thisLocal = Jimple.v().newLocal("this", RefType.v(className));
            locals.add(thisLocal);
            
            // 调用super()
            SootMethod superInit = Scene.v().getSootClass("java.lang.Object")
                .getMethod("<init>", Collections.emptyList());
            InvokeStmt superCall = Jimple.v().newInvokeStmt(
                Jimple.v().newSpecialInvokeExpr(thisLocal, superInit.makeRef())
            );
            units.add(superCall);
            
            // 返回
            units.add(Jimple.v().newReturnVoidStmt());
            
            newClass.addMethod(constructor);
            
            // 添加到Scene
            scene.addClass(newClass);
            scene.forceResolve(className, SootClass.BODIES);
            
            return newClass;
        } catch (Exception e) {
            System.err.println("Failed to create Soot class: " + className + ", error: " + e.getMessage());
            return null;
        }
    }
    
    /**
     * 建立类的依赖关系（避免成为孤岛）
     */
    private void establishClassDependencies(HeterogeneousGraph graph, String classId, 
                                           SootClass newClass, Set<SootClass> tplClasses) {
        // 策略1：让新类实现一个已有接口
        Set<String> interfaceIds = graph.getNodesByType(HeterogeneousGraph.NodeType.INTERFACE);
        if (!interfaceIds.isEmpty()) {
            List<String> interfaceList = new ArrayList<>(interfaceIds);
            String selectedInterface = interfaceList.get(random.nextInt(interfaceList.size()));
            GraphNode interfaceNode = graph.getNode(selectedInterface);
            if (interfaceNode != null) {
                String interfaceName = (String) interfaceNode.getAttribute("name");
                if (interfaceName != null) {
                    try {
                        SootClass iface = scene.getSootClass(interfaceName);
                        if (iface != null && !iface.isPhantom()) {
                            newClass.addInterface(iface);
                            graph.addEdge(classId, selectedInterface, 
                                HeterogeneousGraph.EdgeType.CLASS_IMPLEMENTS_INTERFACE);
                        }
                    } catch (Exception e) {
                        // 忽略
                    }
                }
            }
        }
        
        // 策略2：让新类包含一个字段，引用已有类
        Set<String> existingClassIds = graph.getNodesByType(HeterogeneousGraph.NodeType.CLASS);
        if (!existingClassIds.isEmpty() && !existingClassIds.contains(classId)) {
            List<String> classList = new ArrayList<>(existingClassIds);
            String refClassId = classList.get(random.nextInt(classList.size()));
            GraphNode refClassNode = graph.getNode(refClassId);
            if (refClassNode != null) {
                String refClassName = (String) refClassNode.getAttribute("name");
                if (refClassName != null) {
                    try {
                        SootClass refClass = scene.getSootClass(refClassName);
                        if (refClass != null && !refClass.isPhantom()) {
                            // 添加字段引用该类
                            SootField refField = new SootField(
                                "ref" + random.nextInt(1000),
                                RefType.v(refClassName),
                                Modifier.PRIVATE
                            );
                            newClass.addField(refField);
                            
                            String fieldId = "fld:" + newClass.getName() + "." + refField.getName();
                            GraphNode fieldNode = new GraphNode(fieldId, HeterogeneousGraph.NodeType.FIELD);
                            fieldNode.setAttribute("name", refField.getName());
                            fieldNode.setAttribute("type", refClassName);
                            graph.addNode(fieldNode);
                            graph.addEdge(classId, fieldId, HeterogeneousGraph.EdgeType.CLASS_CONTAINS_FIELD);
                            graph.addEdge(fieldId, refClassId, HeterogeneousGraph.EdgeType.FIELD_REFERENCES_CLASS);
                        }
                    } catch (Exception e) {
                        // 忽略
                    }
                }
            }
        }
    }
    
    /**
     * 创建带依赖的方法
     */
    private SootMethod createMethodWithDependencies(SootClass ownerClass, Set<SootClass> tplClasses) {
        try {
            // 构建类型列表（增加类熵）
            List<Type> availableTypes = buildTypeList(tplClasses);
            
            // 确保类型列表不为空
            if (availableTypes.isEmpty()) {
                Logger.error("No available types for method creation. Adding default types.");
                availableTypes.add(IntType.v());
                availableTypes.add(RefType.v("java.lang.Object"));
            }
            
            // 随机选择参数类型
            int paramCount = 1 + random.nextInt(3); // 1-3个参数
            List<Type> paramTypes = new ArrayList<>();
            for (int i = 0; i < paramCount; i++) {
                paramTypes.add(availableTypes.get(random.nextInt(availableTypes.size())));
            }
            
            // 随机选择返回类型
            Type returnType = availableTypes.get(random.nextInt(availableTypes.size()));
            
            // 创建方法
            String methodName = "method" + random.nextInt(10000);
            SootMethod method = new SootMethod(
                methodName,
                paramTypes,
                returnType,
                Modifier.PUBLIC
            );
            
            // 创建方法体，使用反射调用参数（避免死代码）
            JimpleBody body = Jimple.v().newBody(method);
            method.setActiveBody(body);
            
            Chain<soot.Local> locals = body.getLocals();
            Chain<soot.Unit> units = body.getUnits();
            
            // 添加参数局部变量
            for (int i = 0; i < paramTypes.size(); i++) {
                Local paramLocal = Jimple.v().newLocal("param" + i, paramTypes.get(i));
                locals.add(paramLocal);
            }
            
            // 使用反射调用参数（try-catch包装）
            addReflectiveInvocation(body, paramTypes, locals, units);
            
            // 返回
            if (returnType != VoidType.v()) {
                Local returnLocal = Jimple.v().newLocal("ret", returnType);
                locals.add(returnLocal);
                
                // 初始化返回值
                if (returnType instanceof PrimType) {
                    units.add(Jimple.v().newAssignStmt(returnLocal, 
                        getDefaultValue((PrimType) returnType)));
                } else {
                    units.add(Jimple.v().newAssignStmt(returnLocal, NullConstant.v()));
                }
                
                units.add(Jimple.v().newReturnStmt(returnLocal));
            } else {
                units.add(Jimple.v().newReturnVoidStmt());
            }
            
            ownerClass.addMethod(method);
            return method;
            
        } catch (Exception e) {
            String errorMsg = e.getMessage();
            if (errorMsg == null) {
                errorMsg = e.getClass().getSimpleName();
            }
            Logger.error("Failed to create method: %s", errorMsg);
            if (e.getCause() != null) {
                System.err.println("  Caused by: " + e.getCause().getMessage());
            }
            e.printStackTrace();
            return null;
        }
    }
    
    /**
     * 添加反射调用代码
     */
    private void addReflectiveInvocation(JimpleBody body, List<Type> paramTypes, 
                                       Chain<soot.Local> locals, Chain<soot.Unit> units) {
        // 简化实现：添加对参数的toString调用（确保参数被使用）
        // 注意：不能在遍历locals时修改它，会导致ConcurrentModificationException
        // 先收集需要处理的参数Local和对应的类型
        List<Local> paramLocals = new ArrayList<>();
        List<Type> paramTypesToProcess = new ArrayList<>();
        
        int paramIndex = 0;
        for (Local paramLocal : locals) {
            if (paramIndex >= paramTypes.size()) break;
            paramLocals.add(paramLocal);
            paramTypesToProcess.add(paramTypes.get(paramIndex));
            paramIndex++;
        }
        
        // 现在遍历收集的参数，添加toString调用
        // 先收集所有需要添加的Local和Unit，然后一次性添加，避免任何并发修改问题
        List<Local> newLocalsToAdd = new ArrayList<>();
        List<soot.Unit> newUnitsToAdd = new ArrayList<>();
        
        for (int i = 0; i < paramLocals.size(); i++) {
            Local paramLocal = paramLocals.get(i);
            Type paramType = paramTypesToProcess.get(i);
            
            // 如果参数是对象类型，调用toString
            if (paramType instanceof RefType) {
                try {
                    SootClass paramClass = ((RefType) paramType).getSootClass();
                    SootMethod toStringMethod = paramClass.getMethod("java.lang.String toString()");
                    
                    // 创建Local和Unit，先收集起来
                    Local strLocal = Jimple.v().newLocal("str" + i, 
                        RefType.v("java.lang.String"));
                    
                    InvokeStmt invoke = Jimple.v().newInvokeStmt(
                        Jimple.v().newVirtualInvokeExpr(paramLocal, toStringMethod.makeRef())
                    );
                    
                    // 收集起来，稍后一次性添加
                    newLocalsToAdd.add(strLocal);
                    newUnitsToAdd.add(invoke);
                } catch (Exception e) {
                    // 如果toString不存在，忽略
                }
            }
        }
        
        // 一次性添加所有新创建的Local和Unit
        for (Local newLocal : newLocalsToAdd) {
            locals.add(newLocal);
        }
        for (soot.Unit newUnit : newUnitsToAdd) {
            units.add(newUnit);
        }
    }
    
    /**
     * 建立方法依赖关系
     */
    private void establishMethodDependencies(HeterogeneousGraph graph, String methodId, 
                                           SootMethod method, Set<SootClass> tplClasses) {
        // 方法已经通过参数类型和返回类型建立了依赖
        // 这里可以添加方法调用关系
        List<Type> paramTypes = method.getParameterTypes();
        for (Type paramType : paramTypes) {
            if (paramType instanceof RefType) {
                String refClassName = ((RefType) paramType).getClassName();
                String refClassId = "cls:" + refClassName.replace("/", ".");
                if (graph.containsNode(refClassId)) {
                    // 建立参数类型依赖
                    // 这已经在图构建时处理了
                }
            }
        }
    }
    
    /**
     * 创建带依赖的字段
     */
    private SootField createFieldWithDependencies(SootClass ownerClass, Set<SootClass> tplClasses) {
        List<Type> availableTypes = buildTypeList(tplClasses);
        
        // 确保类型列表不为空
        if (availableTypes.isEmpty()) {
            Logger.error("No available types for field creation. Adding default types.");
            availableTypes.add(IntType.v());
            availableTypes.add(RefType.v("java.lang.Object"));
        }
        
        Type fieldType = availableTypes.get(random.nextInt(availableTypes.size()));
        
        String fieldName = "field" + random.nextInt(10000);
        SootField field = new SootField(fieldName, fieldType, Modifier.PRIVATE);
        ownerClass.addField(field);
        
        return field;
    }
    
    /**
     * 建立字段依赖关系
     */
    private void establishFieldDependencies(HeterogeneousGraph graph, String fieldId, SootField field) {
        Type fieldType = field.getType();
        if (fieldType instanceof RefType) {
            String refClassName = ((RefType) fieldType).getClassName();
            String refClassId = "cls:" + refClassName.replace("/", ".");
            if (graph.containsNode(refClassId)) {
                graph.addEdge(fieldId, refClassId, HeterogeneousGraph.EdgeType.FIELD_REFERENCES_CLASS);
            }
        }
    }
    
    /**
     * 为方法添加参数
     */
    private void addParameterToMethod(HeterogeneousGraph graph, String methodId, 
                                     String signature, Set<SootClass> tplClasses) {
        // 解析方法签名，找到Soot方法
        SootMethod method = findMethodBySignature(signature);
        if (method == null || method.isAbstract() || method.isNative()) {
            return;
        }
        
        // 构建类型列表
        List<Type> availableTypes = buildTypeList(tplClasses);
        
        // 确保类型列表不为空
        if (availableTypes.isEmpty()) {
            Logger.error("No available types for parameter creation. Adding default types.");
            availableTypes.add(IntType.v());
            availableTypes.add(RefType.v("java.lang.Object"));
        }
        
        Type newParamType = availableTypes.get(random.nextInt(availableTypes.size()));
        
        // 创建新参数
        List<Type> newParamTypes = new ArrayList<>(method.getParameterTypes());
        newParamTypes.add(newParamType);
        
        // 创建新方法
        SootMethod newMethod = new SootMethod(
            method.getName(),
            newParamTypes,
            method.getReturnType(),
            method.getModifiers()
        );
        
        // 更新方法体：添加反射调用新参数
        if (method.hasActiveBody()) {
            JimpleBody newBody = updateMethodBodyForNewParameter(
                (JimpleBody) method.getActiveBody(), newParamType, newParamTypes.size() - 1
            );
            newMethod.setActiveBody(newBody);
        }
        
        // 替换原方法
        method.getDeclaringClass().removeMethod(method);
        method.getDeclaringClass().addMethod(newMethod);
        
        // 更新所有调用点
        updateCallSitesForNewParameter(method, newMethod, newParamType);
        
        // 更新图
        String newMethodId = "mtd:" + newMethod.getSignature();
        GraphNode newMethodNode = new GraphNode(newMethodId, HeterogeneousGraph.NodeType.METHOD);
        newMethodNode.setAttribute("name", newMethod.getName());
        newMethodNode.setAttribute("signature", newMethod.getSignature());
        newMethodNode.setAttribute("returnType", newMethod.getReturnType().toString());
        graph.addNode(newMethodNode);
        
        // 添加参数节点
        String paramId = "param:" + newMethodId + ":" + (newParamTypes.size() - 1);
        GraphNode paramNode = new GraphNode(paramId, HeterogeneousGraph.NodeType.PARAMETER);
        paramNode.setAttribute("index", newParamTypes.size() - 1);
        paramNode.setAttribute("type", newParamType.toString());
        paramNode.setAttribute("methodId", newMethodId);
        graph.addNode(paramNode);
        graph.addEdge(newMethodId, paramId, HeterogeneousGraph.EdgeType.METHOD_CONTAINS_PARAMETER);
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
            Logger.error("Failed to find method by signature: %s", signature);
        }
        return null;
    }
    
    /**
     * 更新方法体以支持新参数
     */
    private JimpleBody updateMethodBodyForNewParameter(JimpleBody oldBody, Type newParamType, int paramIndex) {
        JimpleBody newBody = Jimple.v().newBody();
        
        // 复制局部变量
        for (soot.Local local : oldBody.getLocals()) {
            newBody.getLocals().add(local);
        }
        
        // 添加新参数的局部变量
        soot.Local newParamLocal = Jimple.v().newLocal("param" + paramIndex, newParamType);
        newBody.getLocals().add(newParamLocal);
        
        // 复制语句，并在开始处添加反射调用
        Chain<soot.Unit> newUnits = newBody.getUnits();
        Chain<soot.Unit> oldUnits = oldBody.getUnits();
        
        // 在方法开始处添加反射调用新参数
        if (!oldUnits.isEmpty()) {
            soot.Unit firstUnit = oldUnits.getFirst();
            
            // 使用反射调用新参数（try-catch包装）
            addReflectiveInvocationForParameter(newBody, newParamLocal, newParamType);
            
            // 复制原有语句
            for (soot.Unit unit : oldUnits) {
                newUnits.add(unit);
            }
        }
        
        return newBody;
    }
    
    /**
     * 为新参数添加反射调用
     */
    private void addReflectiveInvocationForParameter(JimpleBody body, soot.Local paramLocal, Type paramType) {
        Chain<soot.Local> locals = body.getLocals();
        Chain<soot.Unit> units = body.getUnits();
        
        // 如果参数是对象类型，调用toString
        if (paramType instanceof RefType) {
            try {
                SootClass paramClass = ((RefType) paramType).getSootClass();
                if (paramClass != null && !paramClass.isPhantom()) {
                    SootMethod toStringMethod = paramClass.getMethod("java.lang.String toString()");
                    
                    Local strLocal = Jimple.v().newLocal("str", RefType.v("java.lang.String"));
                    locals.add(strLocal);
                    
                    InvokeStmt invoke = Jimple.v().newInvokeStmt(
                        Jimple.v().newVirtualInvokeExpr(paramLocal, toStringMethod.makeRef())
                    );
                    units.add(invoke);
                }
            } catch (Exception e) {
                // 如果toString不存在，忽略
            }
        }
    }
    
    /**
     * 更新调用点以支持新参数
     */
    private void updateCallSitesForNewParameter(SootMethod oldMethod, SootMethod newMethod, Type newParamType) {
        CallSiteUpdater updater = new CallSiteUpdater(scene);
        List<CallSiteUpdater.CallSite> callSites = updater.findCallSites(oldMethod);
        
        for (CallSiteUpdater.CallSite callSite : callSites) {
            // 创建新参数的默认值
            Value paramValue = createDefaultValueForType(newParamType, callSite.getCaller());
            
            // 更新调用点，添加新参数
            updater.updateCallSiteAddParameter(callSite, newParamType, paramValue);
        }
    }
    
    /**
     * 为类型创建默认值
     */
    private Value createDefaultValueForType(Type type, SootMethod caller) {
        if (type instanceof PrimType) {
            return getDefaultValue((PrimType) type);
        } else if (type instanceof RefType) {
            // 返回null
            return NullConstant.v();
        }
        return NullConstant.v();
    }
    
    /**
     * 构建类型列表
     */
    private List<Type> buildTypeList(Set<SootClass> tplClasses) {
        List<Type> types = new ArrayList<>();
        
        // 添加原始类型
        types.add(IntType.v());
        types.add(LongType.v());
        types.add(BooleanType.v());
        types.add(RefType.v("java.lang.String"));
        types.add(RefType.v("java.lang.Object"));
        
        // 添加TPL类类型
        for (SootClass sc : tplClasses) {
            if (!sc.isPhantom()) {
                types.add(RefType.v(sc.getName()));
            }
        }
        
        return types;
    }
    
    /**
     * 获取默认值
     */
    private Constant getDefaultValue(PrimType type) {
        if (type == IntType.v()) {
            return IntConstant.v(0);
        } else if (type == LongType.v()) {
            return LongConstant.v(0L);
        } else if (type == BooleanType.v()) {
            return IntConstant.v(0); // false
        } else {
            return IntConstant.v(0);
        }
    }
}
