package com.libpass.attack.perturbation;

import soot.*;
import java.util.*;
import java.util.stream.Collectors;

import com.libpass.attack.util.Logger;
/**
 * 修改日志记录器
 * 记录所有扰动操作的详细信息，包括前后对比
 */
public class ModificationLogger {
    private static final boolean ENABLED = true;
    private List<ModificationRecord> records;
    private int currentIteration;
    
    public ModificationLogger() {
        this.records = new ArrayList<>();
        this.currentIteration = 0;
    }
    
    public void setIteration(int iteration) {
        this.currentIteration = iteration;
    }
    
    /**
     * 修改记录
     */
    public static class ModificationRecord {
        public enum OperationType {
            ADD_CLASS, ADD_METHOD, ADD_FIELD, ADD_PARAMETER, ADD_PACKAGE,
            MERGE_CLASS, MERGE_METHOD, MERGE_FIELD, MERGE_PARAMETER, MERGE_PACKAGE
        }
        
        public OperationType operation;
        public String targetName; // 目标名称（类名、方法名等）
        public String beforeState; // 修改前状态
        public String afterState;  // 修改后状态
        public String details;     // 详细信息
        public List<String> affectedElements; // 受影响的元素
        
        public ModificationRecord(OperationType operation, String targetName) {
            this.operation = operation;
            this.targetName = targetName;
            this.affectedElements = new ArrayList<>();
        }
        
        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("[").append(operation).append("] ").append(targetName).append("\n");
            if (beforeState != null) {
                sb.append("  修改前: ").append(beforeState).append("\n");
            }
            if (afterState != null) {
                sb.append("  修改后: ").append(afterState).append("\n");
            }
            if (details != null && !details.isEmpty()) {
                sb.append("  详情: ").append(details).append("\n");
            }
            if (!affectedElements.isEmpty()) {
                sb.append("  受影响元素: ").append(String.join(", ", affectedElements)).append("\n");
            }
            return sb.toString();
        }
    }
    
    /**
     * 记录添加类操作
     */
    public void logAddClass(SootClass newClass, List<SootField> fields, List<SootMethod> methods) {
        if (!ENABLED) return;
        
        ModificationRecord record = new ModificationRecord(
            ModificationRecord.OperationType.ADD_CLASS, 
            newClass.getName()
        );
        record.beforeState = "类不存在";
        record.afterState = String.format("类: %s (包: %s, 修饰符: %d)", 
            newClass.getName(), newClass.getPackageName(), newClass.getModifiers());
        record.details = String.format("字段数: %d, 方法数: %d", fields.size(), methods.size());
        
        fields.forEach(f -> record.affectedElements.add("字段: " + f.getName() + " (" + f.getType() + ")"));
        methods.forEach(m -> record.affectedElements.add("方法: " + m.getSignature()));
        
        records.add(record);
        printRecord(record);
    }
    
    /**
     * 记录添加方法操作
     */
    public void logAddMethod(SootMethod method, SootClass ownerClass) {
        if (!ENABLED) return;
        
        ModificationRecord record = new ModificationRecord(
            ModificationRecord.OperationType.ADD_METHOD,
            method.getSignature()
        );
        record.beforeState = String.format("类 %s 中不存在方法 %s", ownerClass.getName(), method.getName());
        
        StringBuilder after = new StringBuilder();
        after.append("方法签名: ").append(method.getSignature()).append("\n");
        after.append("  返回类型: ").append(method.getReturnType()).append("\n");
        after.append("  参数: ");
        if (method.getParameterCount() > 0) {
            after.append(method.getParameterTypes().stream()
                .map(Type::toString)
                .collect(Collectors.joining(", ")));
        } else {
            after.append("无");
        }
        after.append("\n");
        after.append("  修饰符: ").append(method.getModifiers());
        
        record.afterState = after.toString();
        record.affectedElements.add("所属类: " + ownerClass.getName());
        
        records.add(record);
        printRecord(record);
    }
    
    /**
     * 记录添加字段操作
     */
    public void logAddField(SootField field, SootClass ownerClass) {
        if (!ENABLED) return;
        
        ModificationRecord record = new ModificationRecord(
            ModificationRecord.OperationType.ADD_FIELD,
            field.getName()
        );
        record.beforeState = String.format("类 %s 中不存在字段 %s", ownerClass.getName(), field.getName());
        record.afterState = String.format("字段: %s (类型: %s, 修饰符: %d)", 
            field.getName(), field.getType(), field.getModifiers());
        record.affectedElements.add("所属类: " + ownerClass.getName());
        
        records.add(record);
        printRecord(record);
    }
    
    /**
     * 记录合并类操作
     */
    public void logMergeClass(SootClass sourceClass, SootClass targetClass, 
                             Map<String, String> renamedMethods, 
                             Map<String, String> renamedFields) {
        if (!ENABLED) return;
        
        ModificationRecord record = new ModificationRecord(
            ModificationRecord.OperationType.MERGE_CLASS,
            targetClass.getName()
        );
        
        StringBuilder before = new StringBuilder();
        before.append("源类: ").append(sourceClass.getName()).append("\n");
        before.append("  方法数: ").append(sourceClass.getMethodCount()).append("\n");
        before.append("  字段数: ").append(sourceClass.getFieldCount()).append("\n");
        before.append("目标类: ").append(targetClass.getName()).append("\n");
        before.append("  方法数: ").append(targetClass.getMethodCount()).append("\n");
        before.append("  字段数: ").append(targetClass.getFieldCount());
        record.beforeState = before.toString();
        
        StringBuilder after = new StringBuilder();
        after.append("合并后类: ").append(targetClass.getName()).append("\n");
        after.append("  方法数: ").append(targetClass.getMethodCount()).append("\n");
        after.append("  字段数: ").append(targetClass.getFieldCount());
        record.afterState = after.toString();
        
        if (!renamedMethods.isEmpty()) {
            record.details = "重命名方法: " + renamedMethods.size() + " 个";
            renamedMethods.forEach((oldName, newName) -> 
                record.affectedElements.add("方法: " + oldName + " -> " + newName));
        }
        if (!renamedFields.isEmpty()) {
            if (record.details == null) record.details = "";
            record.details += "; 重命名字段: " + renamedFields.size() + " 个";
            renamedFields.forEach((oldName, newName) -> 
                record.affectedElements.add("字段: " + oldName + " -> " + newName));
        }
        
        records.add(record);
        printRecord(record);
    }
    
    /**
     * 记录合并方法操作
     */
    public void logMergeMethod(SootMethod sourceMethod, SootMethod targetMethod, 
                              SootClass ownerClass, boolean hasBooleanParam, 
                              String wrapperType) {
        if (!ENABLED) return;
        
        ModificationRecord record = new ModificationRecord(
            ModificationRecord.OperationType.MERGE_METHOD,
            targetMethod.getSignature()
        );
        
        StringBuilder before = new StringBuilder();
        before.append("源方法: ").append(sourceMethod.getSignature()).append("\n");
        before.append("  返回类型: ").append(sourceMethod.getReturnType()).append("\n");
        before.append("目标方法: ").append(targetMethod.getSignature()).append("\n");
        before.append("  返回类型: ").append(targetMethod.getReturnType());
        record.beforeState = before.toString();
        
        StringBuilder after = new StringBuilder();
        after.append("合并后方法: ").append(targetMethod.getSignature()).append("\n");
        after.append("  返回类型: ").append(wrapperType != null ? wrapperType : targetMethod.getReturnType());
        if (hasBooleanParam) {
            after.append("\n  添加布尔参数用于区分方法体");
        }
        record.afterState = after.toString();
        
        record.affectedElements.add("所属类: " + ownerClass.getName());
        record.affectedElements.add("源方法: " + sourceMethod.getSignature());
        
        records.add(record);
        printRecord(record);
    }
    
    /**
     * 记录合并字段操作
     */
    public void logMergeField(SootField sourceField, SootField targetField, 
                             String wrapperClassName, SootClass ownerClass) {
        if (!ENABLED) return;
        
        ModificationRecord record = new ModificationRecord(
            ModificationRecord.OperationType.MERGE_FIELD,
            targetField.getName()
        );
        
        record.beforeState = String.format("源字段: %s (%s), 目标字段: %s (%s)",
            sourceField.getName(), sourceField.getType(),
            targetField.getName(), targetField.getType());
        record.afterState = String.format("字段: %s (包装类型: %s)",
            targetField.getName(), wrapperClassName);
        record.details = String.format("使用包装类 %s 容纳两种类型", wrapperClassName);
        record.affectedElements.add("所属类: " + ownerClass.getName());
        record.affectedElements.add("源字段: " + sourceField.getName());
        
        records.add(record);
        printRecord(record);
    }
    
    /**
     * 打印记录（debug级别）
     */
    private void printRecord(ModificationRecord record) {
        Logger.debug("==========================================");
        Logger.debug("修改记录 #%d (迭代 %d)", records.size(), currentIteration);
        Logger.debug(record.toString());
        Logger.debug("==========================================");
    }
    
    /**
     * 获取所有记录
     */
    public List<ModificationRecord> getRecords() {
        return new ArrayList<>(records);
    }
    
    /**
     * 获取当前迭代的记录
     */
    public List<ModificationRecord> getCurrentIterationRecords() {
        return records; // 简化：所有记录都在当前迭代中
    }
    
    /**
     * 清空记录
     */
    public void clear() {
        records.clear();
    }
    
    /**
     * 生成汇总报告
     */
    public String generateSummary() {
        if (records.isEmpty()) {
            return "没有修改记录";
        }
        
        Map<ModificationRecord.OperationType, Integer> counts = new HashMap<>();
        for (ModificationRecord record : records) {
            counts.put(record.operation, counts.getOrDefault(record.operation, 0) + 1);
        }
        
        StringBuilder summary = new StringBuilder();
        summary.append("=== 修改汇总 ===\n");
        summary.append("总修改数: ").append(records.size()).append("\n");
        summary.append("操作类型统计:\n");
        counts.forEach((op, count) -> 
            summary.append("  ").append(op).append(": ").append(count).append("\n"));
        
        return summary.toString();
    }
}
