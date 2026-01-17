#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
攻击成功率评估模块
用于评估攻击效果和成功率
"""

import json
import logging
from pathlib import Path
from typing import List, Dict, Optional
import statistics

logger = logging.getLogger(__name__)


class AttackEvaluator:
    """攻击效果评估器"""
    
    def __init__(self):
        self.results = []
        self.metrics = {}
    
    def load_results(self, result_file: str):
        """加载攻击结果文件"""
        try:
            with open(result_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, list):
                    self.results = data
                else:
                    self.results = [data]
            logger.info(f"加载了 {len(self.results)} 条攻击结果")
            return True
        except Exception as e:
            logger.error(f"加载结果文件失败: {e}")
            return False
    
    def evaluate(self) -> Dict:
        """评估攻击效果"""
        if not self.results:
            logger.warning("没有可评估的结果")
            return {}
        
        metrics = {
            'total_attacks': len(self.results),
            'successful_attacks': 0,
            'failed_attacks': 0,
            'success_rates': [],
            'average_success_rate': 0.0,
            'median_success_rate': 0.0,
            'max_success_rate': 0.0,
            'min_success_rate': 1.0,
            'strategy_performance': {},
            'tool_specific_performance': {}
        }
        
        # 统计基本信息
        for result in self.results:
            if result.get('success', False):
                metrics['successful_attacks'] += 1
                
                success_rate = result.get('overall_success_rate', 0.0)
                metrics['success_rates'].append(success_rate)
                
                if success_rate > metrics['max_success_rate']:
                    metrics['max_success_rate'] = success_rate
                if success_rate < metrics['min_success_rate']:
                    metrics['min_success_rate'] = success_rate
                
                # 统计各策略表现
                for strategy_result in result.get('results', []):
                    strategy_name = strategy_result.get('strategyName', 'unknown')
                    strategy_rate = strategy_result.get('successRate', 0.0)
                    
                    if strategy_name not in metrics['strategy_performance']:
                        metrics['strategy_performance'][strategy_name] = []
                    metrics['strategy_performance'][strategy_name].append(strategy_rate)
            else:
                metrics['failed_attacks'] += 1
        
        # 计算统计数据
        if metrics['success_rates']:
            metrics['average_success_rate'] = statistics.mean(metrics['success_rates'])
            metrics['median_success_rate'] = statistics.median(metrics['success_rates'])
            
            # 计算各策略的平均成功率
            for strategy_name, rates in metrics['strategy_performance'].items():
                metrics['strategy_performance'][strategy_name] = {
                    'average': statistics.mean(rates),
                    'median': statistics.median(rates),
                    'count': len(rates)
                }
        
        self.metrics = metrics
        return metrics
    
    def print_report(self):
        """打印评估报告"""
        if not self.metrics:
            self.evaluate()
        
        print("\n" + "="*60)
        print("攻击效果评估报告")
        print("="*60)
        
        print(f"\n总体统计:")
        print(f"  总攻击次数: {self.metrics['total_attacks']}")
        print(f"  成功次数: {self.metrics['successful_attacks']}")
        print(f"  失败次数: {self.metrics['failed_attacks']}")
        print(f"  成功率: {self.metrics['successful_attacks'] / self.metrics['total_attacks'] * 100:.2f}%")
        
        if self.metrics['success_rates']:
            print(f"\n成功率统计:")
            print(f"  平均成功率: {self.metrics['average_success_rate'] * 100:.2f}%")
            print(f"  中位数成功率: {self.metrics['median_success_rate'] * 100:.2f}%")
            print(f"  最高成功率: {self.metrics['max_success_rate'] * 100:.2f}%")
            print(f"  最低成功率: {self.metrics['min_success_rate'] * 100:.2f}%")
        
        if self.metrics['strategy_performance']:
            print(f"\n策略表现:")
            for strategy_name, perf in self.metrics['strategy_performance'].items():
                print(f"  {strategy_name}:")
                print(f"    平均成功率: {perf['average'] * 100:.2f}%")
                print(f"    使用次数: {perf['count']}")
        
        print("\n" + "="*60)
    
    def save_report(self, output_file: str):
        """保存评估报告"""
        report = {
            'metrics': self.metrics,
            'detailed_results': self.results
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        logger.info(f"评估报告已保存至: {output_file}")


def main():
    """命令行入口"""
    import argparse
    
    parser = argparse.ArgumentParser(description='攻击效果评估工具')
    parser.add_argument('result_file', help='攻击结果JSON文件')
    parser.add_argument('-o', '--output', help='输出报告文件')
    parser.add_argument('-p', '--print', action='store_true', help='打印报告')
    
    args = parser.parse_args()
    
    evaluator = AttackEvaluator()
    evaluator.load_results(args.result_file)
    evaluator.evaluate()
    
    if args.print:
        evaluator.print_report()
    
    if args.output:
        evaluator.save_report(args.output)
    else:
        # 默认保存到结果文件同目录
        result_path = Path(args.result_file)
        output_path = result_path.parent / f"{result_path.stem}_evaluation.json"
        evaluator.save_report(str(output_path))


if __name__ == '__main__':
    main()
