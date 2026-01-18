# LibPass: An Entropy-Guided Black-Box Adversarial Attack against Third-Party Library Detection Tools

[![License](https://img.shields.io/badge/license-Academic-blue.svg)](LICENSE)
[![Java](https://img.shields.io/badge/Java-11+-orange.svg)](https://www.oracle.com/java/)
[![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://www.python.org/)

**LibPass** is a black-box adversarial attack framework designed to evade third-party library (TPL) detection tools. It uses entropy-guided perturbation strategies to generate adversarial APKs that can bypass state-of-the-art TPL detection tools while maintaining functionality.

## 📄 Paper

This repository contains the implementation of the following paper:

**"LibPass: An Entropy-Guided Black-Box Adversarial Attack against Third-Party Library Detection Tools in the Wild"**

- **Published in**: IEEE Transactions on Dependable and Secure Computing (TDSC)
- **Paper Link**: [https://www.computer.org/csdl/journal/tq/5555/01/11275815/2c9ntOyAxRC](https://www.computer.org/csdl/journal/tq/5555/01/11275815/2c9ntOyAxRC)
- **Status**: Accepted (TDSC-2025-04-0554.R2)

### Citation

If you use LibPass in your research, please cite our paper:

```bibtex
@article{libpass2025,
  title={LibPass: An Entropy-Guided Black-Box Adversarial Attack against Third-Party Library Detection Tools in the Wild},
  author={Zhou, Jian and others},
  journal={IEEE Transactions on Dependable and Secure Computing},
  year={2025},
  publisher={IEEE Computer Society}
}
```

## ✨ Features

- **🎯 Black-Box Attack**: Works without knowledge of the detection tool's internal mechanisms
- **📊 Entropy-Guided Search**: Uses graph entropy (dependency entropy and structural entropy) to guide perturbation search
- **🔄 Firefly Algorithm**: Enhanced Firefly algorithm with KDTree spatial indexing for efficient perturbation search
- **🛡️ Function-Preserving Perturbations**: Adds and merges nodes while maintaining APK functionality
- **🔍 Multi-Detector Support**: Supports multiple TPL detection tools:
  - **LibScan**: Signature-based detection
  - **LibLoom**: Bloom filter-based detection
  - **LibPecker**: Profile-based detection
  - **LibHunter**: Graph-based detection
  - **LiteRadar**: Lightweight detection
- **⚡ Parallel Execution**: Multi-threaded batch processing for efficient large-scale attacks
- **📈 Attack Modes**: 
  - `black_box`: Uses detector confidence scores
  - `black_box_plus`: Uses graph entropy for guidance
- **🎚️ Attack Levels**:
  - `library_level`: Evade entire library detection
  - `version_level`: Evade specific version detection
- **📝 Comprehensive Logging**: Configurable log levels with detailed attack statistics

## 🏗️ Architecture

### Core Components

1. **TPL Decoupler**: Identifies and isolates third-party library classes from app code
2. **Heterogeneous Graph Builder**: Constructs multi-typed graphs capturing semantic and structural information
3. **Entropy Calculator**: Computes dependency entropy and structural entropy to quantify graph complexity
4. **Perturbation Applier**: Applies function-preserving perturbations (add/merge operations)
5. **Firefly Algorithm**: Searches for optimal perturbation sequences using entropy as fitness function
6. **APK Repackager**: Converts modified Jimple code back to DEX and repackages APK

### Attack Flow

```
APK Input → TPL Decoupling → Graph Construction → Entropy Calculation 
    → Firefly Search → Perturbation Application → APK Repackaging 
    → Detection Verification → Adversarial APK Output
```

## 📋 Requirements

- **Java**: 11 or higher
- **Python**: 3.7 or higher
- **Gradle**: 6.0+ (or use included Gradle Wrapper)
- **Android SDK**: For `android.jar` files (API level 20+)
- **Soot Framework**: 4.5.0

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/LibPass.git
cd LibPass/src
```

### 2. Install Dependencies

```bash
# Install Python dependencies
pip install -r requirements.txt

# Build Java project
./gradlew build
```

### 3. Configure Android SDK

Download Android SDK and set the path to `android.jar`:

```bash
# Example: Android API 30
export ANDROID_JAR=/path/to/android-sdk/platforms/android-30/android.jar
```

### 4. Run a Single Attack

```bash
java -cp build/libs/src-1.0.0.jar \
    com.libpass.attack.AutomatedAttackMain \
    apk \
    /path/to/app.apk \
    /path/to/library.jar \
    library-name \
    /path/to/android.jar \
    ./output \
    LibScan \
    100 \
    INFO \
    1 \
    black_box \
    library_level
```

### 5. Run Batch Attacks

```bash
java -cp build/libs/src-1.0.0.jar \
    com.libpass.attack.AutomatedAttackMain \
    groundtruth \
    /path/to/groundtruth.txt \
    /path/to/apks/ \
    /path/to/libraries/ \
    /path/to/android.jar \
    ./output \
    LibScan \
    100 \
    INFO \
    4 \
    black_box \
    library_level
```

## 📖 Usage

### Command-Line Interface

#### Single APK Attack

```bash
java -cp build/libs/src-1.0.0.jar \
    com.libpass.attack.AutomatedAttackMain \
    <mode> <apk_path> <tpl_path> <tpl_name> <android_jar> <output_dir> \
    [detector_type] [max_iterations] [log_level] [parallel_workers] \
    [attack_mode] [attack_level]
```

**Parameters:**
- `mode`: `apk` for single/batch APK attack
- `apk_path`: Path to APK file or directory
- `tpl_path`: Path to TPL JAR/DEX file
- `tpl_name`: Name of the target library
- `android_jar`: Path to Android JAR file
- `output_dir`: Output directory for adversarial APKs
- `detector_type`: `LibScan`, `LibLoom`, `LibPecker`, `LibHunter`, or `LiteRadar` (default: `LibScan`)
- `max_iterations`: Maximum attack iterations (default: 100)
- `log_level`: `ERROR`, `WARNING`, `INFO`, or `DEBUG` (default: `INFO`)
- `parallel_workers`: Number of parallel workers (default: 1)
- `attack_mode`: `black_box` or `black_box_plus` (default: `black_box`)
- `attack_level`: `library_level` or `version_level` (default: `library_level`)

#### GroundTruth Batch Attack

```bash
java -cp build/libs/src-1.0.0.jar \
    com.libpass.attack.AutomatedAttackMain \
    groundtruth \
    <groundtruth_file> <apk_base_dir> <tpl_base_dir> <android_jar> <output_dir> \
    [detector_type] [max_iterations] [log_level] [parallel_workers] \
    [attack_mode] [attack_level]
```

**GroundTruth File Format:**
```
apk1.apk:library1,library2
apk2.apk:library3
...
```

### Attack Modes

#### Black-Box Mode (`black_box`)
- Uses detector confidence scores to guide attacks
- Stops when confidence drops below threshold
- Faster execution

#### Black-Box Plus Mode (`black_box_plus`)
- Uses graph entropy for perturbation guidance
- More sophisticated search strategy
- Higher success rate

### Attack Levels

#### Library-Level Attack (`library_level`)
- Goal: Make the entire library undetectable
- Success: Library not detected by the detector

#### Version-Level Attack (`version_level`)
- Goal: Change detected version or make library undetectable
- Success: Library not detected OR wrong version detected

## 📁 Project Structure

```
src/
├── java/                                    # Java source code
│   └── com/libpass/attack/
│       ├── attack/                          # Core attack engine and configuration
│       │   ├── LibPassAttackEngine.java     
│       │   ├── AttackMode.java              
│       │   ├── AttackLevel.java             
│       │   └── AttackResult.java            
│       ├── automation/                      # Automated attack orchestration and batch processing
│       │   ├── AutomatedAttackEngine.java   
│       │   ├── AutomatedAttackMain.java     
│       │   ├── AutomatedAttackResult.java   
│       │   ├── BatchAttackResult.java       
│       │   ├── GroundTruthBatchAttackResult.java  
│       │   └── AttackStatistics.java        
│       ├── detector/                        # TPL detector adapters and interfaces
│       │   ├── TPLDetector.java             
│       │   ├── DetectionResult.java         
│       │   ├── LibScanDetector.java         
│       │   ├── LibLoomDetector.java         
│       │   ├── LibPeckerDetector.java       
│       │   ├── LibHunterDetector.java       
│       │   └── LiteRadarDetector.java       
│       ├── perturbation/                    # Perturbation operations and application
│       │   ├── AddingPerturbation.java      
│       │   ├── MergingPerturbation.java     
│       │   ├── PerturbationApplier.java     
│       │   ├── ModificationLogger.java      
│       │   └── CallSiteUpdater.java         
│       ├── apk/                             # APK processing utilities
│       │   ├── APKRepackager.java           
│       │   └── APKSigner.java               
│       ├── graph/                           # Graph structures for dependency analysis
│       │   ├── HeterogeneousGraph.java      
│       │   ├── GraphNode.java               
│       │   └── GraphBuilder.java            
│       ├── firefly/                         # Firefly algorithm for optimization
│       │   ├── FireflyAlgorithm.java        
│       │   ├── Firefly.java                 
│       │   └── KDTree.java                  
│       ├── entropy/                         # Entropy calculation for code metrics
│       │   └── GraphEntropyCalculator.java  
│       ├── decoupling/                      # TPL decoupling utilities
│       │   └── TPLDecoupler.java            
│       ├── util/                            # Utility classes
│       │   └── Logger.java                  
│       ├── AttackStrategy.java              # Attack strategy interface
│       ├── AttackConfig.java                # Attack configuration
│       ├── AttackResult.java                # Attack result (legacy)
│       ├── APKModifier.java                 # APK modification utilities
│       └── AutomatedAttackMain.java         # Main entry point for automated attacks (command line)
├── TPL_Detectors/                 # Third-party detection tools
│   ├── LibScan/                   # LibScan tool
│   ├── LIBLOOM/                   # LibLoom tool
│   ├── LibPecker/                 # LibPecker tool
│   ├── LibHunter/                 # LibHunter tool
│   └── LiteRadar/                 # LiteRadar tool
├── python/                        # Python scripts
│   ├── automated_attack.py
│   └── evaluator.py
├── build.gradle                   # Build configuration
├── requirements.txt               # Python dependencies
├── validate_apk.sh                # End-to-end APK functionality validation
├── sign_apk.sh                    # APK signing tool
├── LICENSE
└── README.md                      
```



## 📊 Results

The attack generates:
- **Adversarial APKs**: Modified APKs that evade detection
- **Attack Statistics**: Success rate, perturbation count, execution time
- **Detailed Logs**: Per-iteration attack progress and results

Example output:
```
Task #1: SUCCESS - final_confidence=0.000000, perturbations=5, time=12000 ms, types=[add_class, merge_method]
Task #2: FAILED - final_confidence=0.850000, perturbations=100, time=45000 ms
```


## ⚠️ Important Notice

**This tool is intended for academic research and security testing purposes only.**

- Use only with proper authorization
- Comply with applicable laws and regulations
- Follow ethical guidelines for security research

