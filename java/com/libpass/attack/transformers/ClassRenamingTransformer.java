package com.libpass.attack.transformers;

import soot.*;
import soot.util.Chain;
import java.util.Map;
import com.libpass.attack.util.Logger;

/**
 * 类重命名转换器
 * 使用Soot的Transform机制实现类名重命名
 */
public class ClassRenamingTransformer extends SceneTransformer {
    private Map<String, String> classMapping;
    
    public ClassRenamingTransformer(Map<String, String> classMapping) {
        this.classMapping = classMapping;
    }
    
    @Override
    protected void internalTransform(String phaseName, Map<String, String> options) {
        if (classMapping == null || classMapping.isEmpty()) {
            return;
        }
        
        // 遍历所有需要重命名的类
        for (Map.Entry<String, String> entry : classMapping.entrySet()) {
            String oldName = entry.getKey();
            String newName = entry.getValue();
            
            try {
                SootClass oldClass = Scene.v().getSootClass(oldName);
                
                // 创建新类
                SootClass newClass = new SootClass(newName);
                newClass.setModifiers(oldClass.getModifiers());
                newClass.setSuperclass(oldClass.getSuperclass());
                
                // 复制接口
                for (SootClass iface : oldClass.getInterfaces()) {
                    newClass.addInterface(iface);
                }
                
                // 复制字段
                for (SootField field : oldClass.getFields()) {
                    SootField newField = new SootField(
                        field.getName(),
                        updateType(field.getType()),
                        field.getModifiers()
                    );
                    newClass.addField(newField);
                }
                
                // 复制方法
                for (SootMethod method : oldClass.getMethods()) {
                    SootMethod newMethod = new SootMethod(
                        method.getName(),
                        updateParameterTypes(method.getParameterTypes()),
                        updateType(method.getReturnType()),
                        method.getModifiers()
                    );
                    
                    if (method.hasActiveBody()) {
                        // 复制方法体（需要更复杂的处理）
                        // 这里简化处理，实际需要更新body中的所有类型引用
                        newMethod.setActiveBody(method.getActiveBody());
                    }
                    
                    newClass.addMethod(newMethod);
                }
                
                // 添加到Scene
                Scene.v().addClass(newClass);
                
                // 更新所有引用（需要遍历所有类的方法体）
                updateReferences(oldName, newName);
                
            } catch (Exception e) {
                Logger.error("Failed to rename class in transform: %s", oldName + " -> " + newName);
                System.err.println("Error: " + e.getMessage());
            }
        }
    }
    
    /**
     * 更新类型引用
     */
    private Type updateType(Type type) {
        if (type instanceof RefType) {
            RefType refType = (RefType) type;
            String className = refType.getClassName();
            if (classMapping.containsKey(className)) {
                return RefType.v(classMapping.get(className));
            }
        }
        return type;
    }
    
    /**
     * 更新参数类型列表
     */
    private java.util.List<Type> updateParameterTypes(java.util.List<Type> paramTypes) {
        java.util.List<Type> newTypes = new java.util.ArrayList<>();
        for (Type type : paramTypes) {
            newTypes.add(updateType(type));
        }
        return newTypes;
    }
    
    /**
     * 更新所有引用
     */
    private void updateReferences(String oldName, String newName) {
        // 遍历所有类，更新方法体中的类型引用
        for (SootClass sc : Scene.v().getClasses()) {
            if (sc.isPhantom() || sc.getMethodCount() == 0) {
                continue;
            }
            
            for (SootMethod method : sc.getMethods()) {
                if (method.hasActiveBody()) {
                    // 更新方法体中的类型引用
                    // 这需要遍历所有语句和表达式
                    // 实际实现需要更详细的代码
                }
            }
        }
    }
}
