package com.libpass.attack.util;

import java.io.PrintStream;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * 统一日志工具类
 * 支持不同日志级别：ERROR, WARNING, INFO, DEBUG
 * 每条日志包含时间戳和位置信息（类名、方法名）
 */
public class Logger {
    
    /**
     * 日志级别枚举
     */
    public enum LogLevel {
        ERROR(0, "ERROR"),
        WARNING(1, "WARNING"),
        INFO(2, "INFO"),
        DEBUG(3, "DEBUG");
        
        private final int level;
        private final String name;
        
        LogLevel(int level, String name) {
            this.level = level;
            this.name = name;
        }
        
        public int getLevel() {
            return level;
        }
        
        public String getName() {
            return name;
        }
    }
    
    private static LogLevel currentLogLevel = LogLevel.INFO;
    private static final DateTimeFormatter DATE_FORMATTER = 
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");
    
    /**
     * 设置日志级别
     * @param level 日志级别字符串：ERROR, WARNING, INFO, DEBUG
     */
    public static void setLogLevel(String level) {
        if (level == null) {
            return;
        }
        String upperLevel = level.toUpperCase().trim();
        switch (upperLevel) {
            case "ERROR":
                currentLogLevel = LogLevel.ERROR;
                break;
            case "WARNING":
            case "WARN":
                currentLogLevel = LogLevel.WARNING;
                break;
            case "INFO":
                currentLogLevel = LogLevel.INFO;
                break;
            case "DEBUG":
                currentLogLevel = LogLevel.DEBUG;
                break;
            default:
                System.err.println("Unknown log level: " + level + ", using INFO");
                currentLogLevel = LogLevel.INFO;
        }
    }
    
    /**
     * 设置日志级别
     * @param level 日志级别
     */
    public static void setLogLevel(LogLevel level) {
        if (level != null) {
            currentLogLevel = level;
        }
    }
    
    /**
     * 获取当前日志级别
     */
    public static LogLevel getLogLevel() {
        return currentLogLevel;
    }
    
    /**
     * 从系统属性或环境变量读取日志级别
     */
    public static void initializeFromSystemProperties() {
        String logLevel = System.getProperty("libpass.log.level");
        if (logLevel == null || logLevel.isEmpty()) {
            logLevel = System.getenv("LIBPASS_LOG_LEVEL");
        }
        if (logLevel != null && !logLevel.isEmpty()) {
            setLogLevel(logLevel);
        }
    }
    
    /**
     * 记录ERROR级别日志
     */
    public static void error(String message) {
        log(LogLevel.ERROR, message, System.err);
    }
    
    /**
     * 记录ERROR级别日志（带异常）
     */
    public static void error(String message, Throwable throwable) {
        log(LogLevel.ERROR, message, System.err);
        if (throwable != null) {
            throwable.printStackTrace(System.err);
        }
    }
    
    /**
     * 记录WARNING级别日志
     */
    public static void warning(String message) {
        log(LogLevel.WARNING, message, System.err);
    }
    
    /**
     * 记录INFO级别日志
     */
    public static void info(String message) {
        log(LogLevel.INFO, message, System.out);
    }
    
    /**
     * 记录DEBUG级别日志
     */
    public static void debug(String message) {
        log(LogLevel.DEBUG, message, System.out);
    }
    
    /**
     * 格式化日志并输出
     */
    private static void log(LogLevel level, String message, PrintStream stream) {
        if (level.getLevel() > currentLogLevel.getLevel()) {
            return; // 日志级别不足，不输出
        }
        
        // 获取调用者信息（跳过Logger类本身的方法）
        StackTraceElement caller = getCaller();
        String location = formatLocation(caller);
        
        // 格式化时间戳
        String timestamp = LocalDateTime.now().format(DATE_FORMATTER);
        
        // 构建日志消息
        String logMessage = String.format("[%s] [%s] %s - %s", 
            timestamp, level.getName(), location, message);
        
        // 输出日志
        stream.println(logMessage);
    }
    
    /**
     * 获取调用者信息
     */
    private static StackTraceElement getCaller() {
        StackTraceElement[] stackTrace = Thread.currentThread().getStackTrace();
        // stackTrace[0] = Thread.getStackTrace
        // stackTrace[1] = Logger.getCaller
        // stackTrace[2] = Logger.log
        // stackTrace[3] = Logger.error/warning/info/debug
        // stackTrace[4] = 实际的调用者
        
        for (int i = 4; i < stackTrace.length; i++) {
            StackTraceElement element = stackTrace[i];
            String className = element.getClassName();
            // 跳过Logger类本身和反射相关类
            if (!className.equals(Logger.class.getName()) && 
                !className.startsWith("java.lang.reflect") &&
                !className.startsWith("sun.reflect")) {
                return element;
            }
        }
        
        // 如果找不到，返回栈顶元素
        return stackTrace.length > 3 ? stackTrace[3] : stackTrace[2];
    }
    
    /**
     * 格式化位置信息
     */
    private static String formatLocation(StackTraceElement element) {
        if (element == null) {
            return "Unknown";
        }
        
        String className = element.getClassName();
        // 提取简单类名（去掉包名）
        String simpleClassName = className;
        int lastDot = className.lastIndexOf('.');
        if (lastDot >= 0) {
            simpleClassName = className.substring(lastDot + 1);
        }
        
        String methodName = element.getMethodName();
        int lineNumber = element.getLineNumber();
        
        return String.format("%s.%s:%d", simpleClassName, methodName, lineNumber);
    }
    
    /**
     * 记录格式化的错误日志（类似printf）
     */
    public static void error(String format, Object... args) {
        error(String.format(format, args));
    }
    
    /**
     * 记录格式化的警告日志（类似printf）
     */
    public static void warning(String format, Object... args) {
        warning(String.format(format, args));
    }
    
    /**
     * 记录格式化的信息日志（类似printf）
     */
    public static void info(String format, Object... args) {
        info(String.format(format, args));
    }
    
    /**
     * 记录格式化的调试日志（类似printf）
     */
    public static void debug(String format, Object... args) {
        debug(String.format(format, args));
    }
}
