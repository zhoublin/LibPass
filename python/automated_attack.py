#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
自动化攻击脚本
集成TPL检测工具，实现自动化、批量攻击和成功率统计
"""

import os
import sys
import subprocess
import json
import yaml
import click
import logging
from pathlib import Path
from typing import List, Dict, Optional
from tqdm import tqdm

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class AutomatedAttackFramework:
    """自动化攻击框架"""
    
    def __init__(self, config_path: str = "config.yaml"):
        """初始化框架"""
        self.config = self.load_config(config_path)
        self.java_main_class = "com.libpass.attack.AutomatedAttackMain"
        self.base_dir = Path(__file__).parent.parent
        
    def load_config(self, config_path: str) -> Dict:
        """加载配置"""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
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
            'detector': {
                'type': 'LibScan',
                'libscan_path': 'TPL_Detectors/LibScan/tool/LibScan.py',
                'libscan_tool_dir': 'TPL_Detectors/LibScan/tool'
            },
            'attack': {
                'max_iterations': 100,
                'target_success_rate': 0.90
            }
        }
    
    def attack_single_apk(
        self,
        apk_path: str,
        tpl_path: str,
        tpl_name: str,
        android_jar: str,
        output_dir: str,
        max_iterations: Optional[int] = None,
        detector_type: Optional[str] = None
    ) -> Dict:
        """
        攻击单个APK
        
        Args:
            apk_path: APK文件路径
            tpl_path: TPL文件路径
            tpl_name: TPL名称
            android_jar: Android JAR路径
            output_dir: 输出目录
            max_iterations: 最大迭代次数
            detector_type: 检测工具类型
            
        Returns:
            攻击结果字典
        """
        logger.info(f"开始攻击APK: {apk_path}")
        logger.info(f"目标TPL: {tpl_name} ({tpl_path})")
        
        if max_iterations is None:
            max_iterations = self.config.get('attack', {}).get('max_iterations', 100)
        
        if detector_type is None:
            detector_type = self.config.get('detector', {}).get('type', 'LibScan')
        
        # 构建Java命令
        java_cmd = self._build_java_command(
            apk_path=apk_path,
            tpl_path=tpl_path,
            tpl_name=tpl_name,
            android_jar=android_jar,
            output_dir=output_dir,
            detector_type=detector_type,
            max_iterations=max_iterations
        )
        
        logger.info(f"执行命令: {' '.join(java_cmd)}")
        
        try:
            result = subprocess.run(
                java_cmd,
                cwd=self.base_dir,
                capture_output=True,
                text=True,
                timeout=3600  # 1小时超时
            )
            
            if result.returncode == 0:
                logger.info("攻击执行成功")
                
                # 解析结果
                result_file = Path(output_dir) / "automated_attack_result.json"
                if result_file.exists():
                    with open(result_file, 'r', encoding='utf-8') as f:
                        attack_result = json.load(f)
                else:
                    attack_result = {}
                
                return {
                    'success': True,
                    'apk_path': apk_path,
                    'tpl_name': tpl_name,
                    'result': attack_result,
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
    
    def attack_batch(
        self,
        apk_dir: str,
        tpl_path: str,
        tpl_name: str,
        android_jar: str,
        output_base_dir: str,
        max_iterations: Optional[int] = None,
        detector_type: Optional[str] = None
    ) -> Dict:
        """
        批量攻击APK
        
        Args:
            apk_dir: APK文件目录
            tpl_path: TPL文件路径
            tpl_name: TPL名称
            android_jar: Android JAR路径
            output_base_dir: 输出基础目录
            max_iterations: 最大迭代次数
            detector_type: 检测工具类型
            
        Returns:
            批量攻击结果
        """
        logger.info(f"开始批量攻击，APK目录: {apk_dir}")
        
        apk_path = Path(apk_dir)
        if not apk_path.exists():
            logger.error(f"APK目录不存在: {apk_dir}")
            return {}
        
        # 查找所有APK文件
        apk_files = list(apk_path.glob("*.apk"))
        logger.info(f"找到 {len(apk_files)} 个APK文件")
        
        if max_iterations is None:
            max_iterations = self.config.get('attack', {}).get('max_iterations', 100)
        
        if detector_type is None:
            detector_type = self.config.get('detector', {}).get('type', 'LibScan')
        
        # 使用Java批量攻击（更高效）
        java_cmd = self._build_java_command(
            apk_path=str(apk_path),  # 传递目录
            tpl_path=tpl_path,
            tpl_name=tpl_name,
            android_jar=android_jar,
            output_dir=output_base_dir,
            detector_type=detector_type,
            max_iterations=max_iterations
        )
        
        logger.info(f"执行批量攻击命令: {' '.join(java_cmd)}")
        
        try:
            result = subprocess.run(
                java_cmd,
                cwd=self.base_dir,
                capture_output=True,
                text=True,
                timeout=7200  # 2小时超时
            )
            
            if result.returncode == 0:
                logger.info("批量攻击执行成功")
                
                # 解析结果
                result_file = Path(output_base_dir) / "batch_attack_result.json"
                if result_file.exists():
                    with open(result_file, 'r', encoding='utf-8') as f:
                        batch_result = json.load(f)
                else:
                    batch_result = {}
                
                # 计算统计信息
                success_rate = batch_result.get('successRate', 0.0)
                success_count = batch_result.get('successCount', 0)
                total_apks = batch_result.get('totalApks', len(apk_files))
                
                logger.info(f"\n=== 批量攻击完成 ===")
                logger.info(f"总APK数: {total_apks}")
                logger.info(f"成功攻击: {success_count}")
                logger.info(f"失败攻击: {total_apks - success_count}")
                logger.info(f"成功率: {success_rate * 100:.2f}%")
                
                return {
                    'success': True,
                    'batch_result': batch_result,
                    'success_rate': success_rate,
                    'success_count': success_count,
                    'total_apks': total_apks,
                    'stdout': result.stdout
                }
            else:
                logger.error(f"批量攻击执行失败: {result.stderr}")
                return {
                    'success': False,
                    'error': result.stderr,
                    'stdout': result.stdout
                }
                
        except subprocess.TimeoutExpired:
            logger.error("批量攻击执行超时")
            return {
                'success': False,
                'error': '执行超时'
            }
        except Exception as e:
            logger.error(f"批量攻击执行异常: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _build_java_command(
        self,
        apk_path: str,
        tpl_path: str,
        tpl_name: str,
        android_jar: str,
        output_dir: str,
        detector_type: str,
        max_iterations: int
    ) -> List[str]:
        """构建Java执行命令"""
        # 查找编译后的jar文件
        jar_path = self.base_dir / "build" / "libs" / "src-1.0.0.jar"
        
        if not jar_path.exists():
            jar_path = self.base_dir / "build" / "libs" / "src-all.jar"
        
        if jar_path.exists():
            cmd = [
                'java',
                '-cp',
                str(jar_path),
                self.java_main_class,
                apk_path,
                tpl_path,
                tpl_name,
                android_jar,
                output_dir,
                detector_type,
                str(max_iterations)
            ]
        else:
            # 使用classpath方式
            cmd = [
                'java',
                '-cp',
                f'{self.base_dir}/build/classes/java/main:{self._get_classpath()}',
                self.java_main_class,
                apk_path,
                tpl_path,
                tpl_name,
                android_jar,
                output_dir,
                detector_type,
                str(max_iterations)
            ]
        
        return cmd
    
    def _get_classpath(self) -> str:
        """获取classpath"""
        # 简化实现
        return str(self.base_dir / "libs" / "*")


@click.command()
@click.option('--apk', '-a', help='单个APK文件路径')
@click.option('--apk-dir', '-d', help='APK文件目录（批量攻击）')
@click.option('--tpl', '-t', required=True, help='TPL文件路径（JAR或DEX）')
@click.option('--tpl-name', '-n', required=True, help='TPL名称')
@click.option('--android-jar', '-j', required=True, help='Android JAR路径')
@click.option('--output', '-o', default='./output', help='输出目录')
@click.option('--detector', default='LibScan', help='检测工具类型（默认：LibScan）')
@click.option('--max-iterations', '-m', default=100, type=int, help='最大迭代次数')
@click.option('--config', '-c', default='config.yaml', help='配置文件路径')
def main(apk, apk_dir, tpl, tpl_name, android_jar, output, detector, max_iterations, config):
    """自动化攻击框架命令行工具"""
    
    framework = AutomatedAttackFramework(config_path=config)
    
    if apk:
        if not Path(apk).exists():
            logger.error(f"APK文件不存在: {apk}")
            sys.exit(1)
        
        result = framework.attack_single_apk(
            apk_path=apk,
            tpl_path=tpl,
            tpl_name=tpl_name,
            android_jar=android_jar,
            output_dir=output,
            max_iterations=max_iterations,
            detector_type=detector
        )
        
        if result['success']:
            logger.info(f"\n攻击完成！")
            if 'result' in result and result['result'].get('attackSuccess'):
                logger.info("攻击成功：TPL已无法被检测到")
            else:
                logger.info("攻击失败：TPL仍可被检测到")
            sys.exit(0)
        else:
            logger.error(f"攻击失败: {result.get('error', '未知错误')}")
            sys.exit(1)
    
    elif apk_dir:
        if not Path(apk_dir).exists():
            logger.error(f"APK目录不存在: {apk_dir}")
            sys.exit(1)
        
        result = framework.attack_batch(
            apk_dir=apk_dir,
            tpl_path=tpl,
            tpl_name=tpl_name,
            android_jar=android_jar,
            output_base_dir=output,
            max_iterations=max_iterations,
            detector_type=detector
        )
        
        if result['success']:
            logger.info(f"\n批量攻击完成！")
            logger.info(f"成功率: {result.get('success_rate', 0) * 100:.2f}%")
            sys.exit(0)
        else:
            logger.error(f"批量攻击失败: {result.get('error', '未知错误')}")
            sys.exit(1)
    
    else:
        logger.error("请指定 --apk 或 --apk-dir 参数")
        click.echo(click.get_current_context().get_help())
        sys.exit(1)


if __name__ == '__main__':
    main()
