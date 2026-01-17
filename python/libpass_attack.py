#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LibPass攻击框架 - Python主控制器
提供统一的接口来执行针对第三方库检测工具的攻击
"""

import os
import sys
import subprocess
import yaml
import click
import json
from pathlib import Path
from typing import List, Dict, Optional
from tqdm import tqdm
import logging

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class LibPassAttackFramework:
    """LibPass攻击框架主类"""
    
    def __init__(self, config_path: str = "config.yaml"):
        """
        初始化攻击框架
        
        Args:
            config_path: 配置文件路径
        """
        self.config = self.load_config(config_path)
        self.java_main_class = "com.libpass.attack.LibPassAttackMain"
        self.base_dir = Path(__file__).parent.parent
        
    def load_config(self, config_path: str) -> Dict:
        """加载配置文件"""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
            logger.info(f"配置加载成功: {config_path}")
            return config
        except FileNotFoundError:
            logger.warning(f"配置文件不存在: {config_path}，使用默认配置")
            return self.get_default_config()
        except Exception as e:
            logger.error(f"加载配置文件失败: {e}")
            return self.get_default_config()
    
    def get_default_config(self) -> Dict:
        """获取默认配置"""
        return {
            'attack': {
                'strategies': [
                    'rename_packages',
                    'rename_classes',
                    'modify_signatures',
                    'inject_fake_libraries'
                ],
                'target_success_rate': 0.85,
                'target_tools': ['LibPass', 'LibScout', 'LibRadar', 'LibID']
            },
            'soot': {
                'android_jar': '/opt/android-sdk/platforms/android-30/android.jar',
                'output_dir': './output',
                'process_dir': './process',
                'verbose': False
            }
        }
    
    def build_java_project(self) -> bool:
        """编译Java项目"""
        logger.info("开始编译Java项目...")
        try:
            gradle_cmd = ['gradle', 'build', '--quiet']
            result = subprocess.run(
                gradle_cmd,
                cwd=self.base_dir,
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                logger.info("Java项目编译成功")
                return True
            else:
                logger.error(f"Java项目编译失败: {result.stderr}")
                return False
        except FileNotFoundError:
            logger.warning("Gradle未找到，尝试使用gradlew...")
            try:
                gradlew_cmd = ['./gradlew', 'build', '--quiet']
                result = subprocess.run(
                    gradlew_cmd,
                    cwd=self.base_dir,
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0:
                    logger.info("Java项目编译成功")
                    return True
                else:
                    logger.error(f"Java项目编译失败: {result.stderr}")
                    return False
            except Exception as e:
                logger.error(f"编译失败: {e}")
                return False
    
    def attack_single_apk(
        self,
        apk_path: str,
        android_jar: Optional[str] = None,
        output_dir: Optional[str] = None,
        strategies: Optional[List[str]] = None
    ) -> Dict:
        """
        攻击单个APK文件
        
        Args:
            apk_path: APK文件路径
            android_jar: Android JAR路径
            output_dir: 输出目录
            strategies: 攻击策略列表
            
        Returns:
            攻击结果字典
        """
        logger.info(f"开始攻击APK: {apk_path}")
        
        # 获取配置
        if android_jar is None:
            android_jar = self.config.get('soot', {}).get('android_jar', 
                '/opt/android-sdk/platforms/android-30/android.jar')
        
        if output_dir is None:
            output_dir = self.config.get('soot', {}).get('output_dir', './output')
        
        if strategies is None:
            strategies = self.config.get('attack', {}).get('strategies', [])
        
        # 创建输出目录
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        # 构建Java命令
        java_cmd = self._build_java_command(
            apk_path=apk_path,
            android_jar=android_jar,
            output_dir=output_dir
        )
        
        logger.info(f"执行命令: {' '.join(java_cmd)}")
        
        try:
            # 执行Java程序
            result = subprocess.run(
                java_cmd,
                cwd=self.base_dir,
                capture_output=True,
                text=True,
                timeout=600  # 10分钟超时
            )
            
            if result.returncode == 0:
                logger.info("攻击执行成功")
                
                # 解析结果
                result_file = Path(output_dir) / "attack_results.json"
                if result_file.exists():
                    with open(result_file, 'r', encoding='utf-8') as f:
                        attack_results = json.load(f)
                else:
                    attack_results = []
                
                # 计算总体成功率
                overall_success_rate = self._calculate_success_rate(attack_results)
                
                return {
                    'success': True,
                    'apk_path': apk_path,
                    'output_dir': output_dir,
                    'results': attack_results,
                    'overall_success_rate': overall_success_rate,
                    'stdout': result.stdout,
                    'stderr': result.stderr
                }
            else:
                logger.error(f"攻击执行失败: {result.stderr}")
                return {
                    'success': False,
                    'apk_path': apk_path,
                    'error': result.stderr,
                    'stdout': result.stdout
                }
                
        except subprocess.TimeoutExpired:
            logger.error("攻击执行超时")
            return {
                'success': False,
                'apk_path': apk_path,
                'error': '执行超时'
            }
        except Exception as e:
            logger.error(f"攻击执行异常: {e}")
            return {
                'success': False,
                'apk_path': apk_path,
                'error': str(e)
            }
    
    def _build_java_command(
        self,
        apk_path: str,
        android_jar: str,
        output_dir: str
    ) -> List[str]:
        """构建Java执行命令"""
        # 查找编译后的jar文件
        jar_path = self.base_dir / "build" / "libs" / "libpass-attack-1.0.0.jar"
        
        if not jar_path.exists():
            # 尝试其他可能的路径
            jar_path = self.base_dir / "build" / "libs" / "libpass-attack-all.jar"
        
        if jar_path.exists():
            cmd = [
                'java',
                '-cp',
                str(jar_path),
                self.java_main_class,
                apk_path,
                android_jar,
                output_dir
            ]
        else:
            # 使用classpath方式
            cmd = [
                'java',
                '-cp',
                f'{self.base_dir}/build/classes/java/main:{self._get_soot_classpath()}',
                self.java_main_class,
                apk_path,
                android_jar,
                output_dir
            ]
        
        return cmd
    
    def _get_soot_classpath(self) -> str:
        """获取Soot相关的classpath"""
        # 这里需要根据实际依赖配置classpath
        # 简化版本，实际应该从gradle获取
        return str(self.base_dir / "libs" / "*")
    
    def _calculate_success_rate(self, results: List[Dict]) -> float:
        """计算总体成功率"""
        if not results:
            return 0.0
        
        total_rate = sum(result.get('successRate', 0.0) for result in results)
        return total_rate / len(results) if results else 0.0
    
    def attack_batch(
        self,
        apk_dir: str,
        output_base_dir: str,
        strategies: Optional[List[str]] = None
    ) -> List[Dict]:
        """
        批量攻击APK文件
        
        Args:
            apk_dir: APK文件目录
            output_base_dir: 输出基础目录
            strategies: 攻击策略列表
            
        Returns:
            所有攻击结果列表
        """
        logger.info(f"开始批量攻击，APK目录: {apk_dir}")
        
        apk_path = Path(apk_dir)
        if not apk_path.exists():
            logger.error(f"APK目录不存在: {apk_dir}")
            return []
        
        # 查找所有APK文件
        apk_files = list(apk_path.glob("*.apk"))
        logger.info(f"找到 {len(apk_files)} 个APK文件")
        
        results = []
        
        # 使用进度条
        for apk_file in tqdm(apk_files, desc="攻击APK"):
            output_dir = Path(output_base_dir) / apk_file.stem
            result = self.attack_single_apk(
                apk_path=str(apk_file),
                output_dir=str(output_dir),
                strategies=strategies
            )
            results.append(result)
        
        # 输出汇总结果
        self._output_batch_summary(results, output_base_dir)
        
        return results
    
    def _output_batch_summary(self, results: List[Dict], output_dir: str):
        """输出批量攻击汇总结果"""
        total = len(results)
        success_count = sum(1 for r in results if r.get('success', False))
        
        success_rates = [
            r.get('overall_success_rate', 0.0) 
            for r in results 
            if r.get('success', False)
        ]
        
        avg_success_rate = sum(success_rates) / len(success_rates) if success_rates else 0.0
        
        summary = {
            'total_apks': total,
            'successful_attacks': success_count,
            'failed_attacks': total - success_count,
            'average_success_rate': avg_success_rate,
            'detailed_results': results
        }
        
        summary_file = Path(output_dir) / "batch_summary.json"
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
        
        logger.info(f"\n=== 批量攻击汇总 ===")
        logger.info(f"总APK数: {total}")
        logger.info(f"成功攻击: {success_count}")
        logger.info(f"失败攻击: {total - success_count}")
        logger.info(f"平均成功率: {avg_success_rate:.2%}")
        logger.info(f"汇总结果保存至: {summary_file}")


@click.command()
@click.option('--apk', '-a', help='单个APK文件路径')
@click.option('--apk-dir', '-d', help='APK文件目录（批量攻击）')
@click.option('--output', '-o', default='./output', help='输出目录')
@click.option('--android-jar', '-j', help='Android JAR路径')
@click.option('--config', '-c', default='config.yaml', help='配置文件路径')
@click.option('--build', is_flag=True, help='编译Java项目')
@click.option('--strategies', '-s', multiple=True, help='攻击策略（可多次指定）')
def main(apk, apk_dir, output, android_jar, config, build, strategies):
    """LibPass攻击框架命令行工具"""
    
    framework = LibPassAttackFramework(config_path=config)
    
    # 如果需要编译
    if build:
        if not framework.build_java_project():
            logger.error("编译失败，退出")
            sys.exit(1)
    
    # 检查策略
    if strategies:
        strategies = list(strategies)
    else:
        strategies = None
    
    # 单个APK攻击
    if apk:
        if not Path(apk).exists():
            logger.error(f"APK文件不存在: {apk}")
            sys.exit(1)
        
        result = framework.attack_single_apk(
            apk_path=apk,
            android_jar=android_jar,
            output_dir=output,
            strategies=strategies
        )
        
        if result['success']:
            logger.info(f"\n攻击成功！成功率: {result['overall_success_rate']:.2%}")
            sys.exit(0)
        else:
            logger.error(f"攻击失败: {result.get('error', '未知错误')}")
            sys.exit(1)
    
    # 批量APK攻击
    elif apk_dir:
        if not Path(apk_dir).exists():
            logger.error(f"APK目录不存在: {apk_dir}")
            sys.exit(1)
        
        results = framework.attack_batch(
            apk_dir=apk_dir,
            output_base_dir=output,
            strategies=strategies
        )
        
        success_count = sum(1 for r in results if r.get('success', False))
        logger.info(f"\n批量攻击完成，成功: {success_count}/{len(results)}")
        sys.exit(0 if success_count > 0 else 1)
    
    else:
        logger.error("请指定 --apk 或 --apk-dir 参数")
        click.echo(click.get_current_context().get_help())
        sys.exit(1)


if __name__ == '__main__':
    main()
