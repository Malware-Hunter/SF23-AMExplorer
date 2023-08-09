# AMExplore

  

![enter image description here](https://github.com/Malware-Hunter/dataset-build/blob/main/images/amexplorer.jpeg)

  

## Overview

  

This repository houses AMExplore, an innovative tool for generating datasets. Through the integration of metadata from different sources, such as AndroGuard, which makes it possible to extract information such as application names, permissions and API calls, along with obtaining data from APKs from AndroZoo and scan reports from VirusTotal, this tool produces three distinct types of datasets. These sets encompass comprehensive metadata about applications, binary and discrete information, all built to be used in a variety of contexts, from machine learning enhancement to malware analysis.

  
  

⚠️⚠️ **Attention, the files must be unzipped before running the tool.** ⚠️⚠️

  
  

## ⚙️ Automated test tool

  

This script will handle the installation of necessary dependencies, extract the required files, and execute the Python code with the appropriate arguments. It will also provide informative messages during each step of the process.

  

Please make sure you have the appropriate permissions and prerequisites, such as Python 3 and `pip`, to run the automated test successfully. Additionally, ensure that the repository contains the necessary files, including `tool_test.zip` and `adbuilder_dataset.py`.

  

**To perform an automated test of the tool, follow these steps in your Linux terminal:**

  

## ✅ Step 1: Clone the repository:

```

git clone https://github.com/Malware-Hunter/SF23-AMExplorer.git

```

  

## ✅ Step 2: Navigate to the repository directory:

```

cd SF23-AMExplorer

```

  

## ✅ Step 3: Run the script for automated testing:

```

./run_test_tool.sh

```
**Datasets will be generated in a directory called output**
  

## ⚙️ Running the tool with Docker

  

This guide outlines the steps to build and run the tool using Docker.

  

## Prerequisites

  

- Docker installed: [Docker Installation Instructions](https://docs.docker.com/get-docker/)

- Clone the repository:

```
git clone https://github.com/Malware-Hunter/SF23-AMExplorer.git
```

- Navigate to the repository directory:

```
cd SF23-AMExplorer
```

  

## ✅ Step 1: Build the Docker Image

  

Execute the following command to build the Docker image from the Dockerfile:

  

```bash
docker  build  -t  AMExplorer  .
```

  

## ✅ Step 2: Run the Docker Container

  

Start an interactive terminal inside the Docker container using the following command:

  

```bash
docker  run  -it  AMExplorer  /bin/bash
```

  

## ✅ Step 3: Execute the Script

  

Inside the container, execute the execution script with the following command:

  

```bash
./run_test_tool.sh
```

  

## ✅ Step 4: Access the Output Directory

  

After the script execution, you can access the output directory using the following command:

  

```bash
cd  output
```

  
  
  

## Manual Usage

  

The tool can be executed from the command line, providing various parameters:

  
  
  

**--dataset-type**

Type of Dataset To Be Generated. Choices: ['metadata', 'binary', 'discrete']

  

**--dataset-type-all**

Generate All Dataset Types

  

**--output-dir [PATH]**

Dataset Output Directory (Default: 'adb_output')

  

**--prefix [PREFIX]**

Prefix To Be Used in Output Dataset

  

## Metadata Dataset

  

**--androguard-features [PATH], -agf [PATH]**

Directory Path of AndroGuard Features JSON Files

  

**--androguard-metadata [PATH], -agm [PATH]**

Directory Path of AndroGuard Metadata JSON Files

  

**--virustotal-metadata [PATH], -vtm [PATH]**

Directory Path of VirusTotal JSON Files

  

**--androzoo-metadata [FILE_PATH], -azm [FILE_PATH]**

AndroZoo CSV File Path

  

## Binary or Discrete Dataset

  

**--metadata-dataset [FILE_PATH], -md [FILE_PATH]**

Metadata Dataset CSV File Path

  

**--threshold [INT], -th [INT]**

Number of VirusTotal Scanners to Define Malware (Default: 4)

  

With these updated usage instructions, users can now easily understand the available parameters and their functionalities.

  

**Generating all Datasets:**

  

To generate all datasets, use the following command:

  

```

python3 adbuilder_dataset.py --dataset-type-all --androguard-features androguard/features --androguard-metadata androguard/metadata --virustotal-metadata virustotal --androzoo-metadata androzoo/selected_n_1200.csv --output-dir output

```

  

**Generating Dataset Metadata:**

  

To generate the dataset metadata, use the following command:

  

```

python3 adbuilder_dataset.py --dataset-type metadata -agf androguard/features -agm androguard/metadata -vtm virustotal -azm androzoo/selected_n_1200.csv --output-dir output

```

  

OR:

  

```

python3 adbuilder_dataset.py --dataset-type metadata --androguard-features androguard/features --androguard-metadata androguard/metadata --virustotal-metadata virustotal --androzoo-metadata androzoo/selected_n_1200.csv --output-dir output

```

  

**Generating Dataset Binary:**

  

To generate the dataset with binary data, use the following command:

  

```

python3 adbuilder_dataset.py --dataset-type binary -md output\metadata.csv -th 5 --output-dir output

```

  

OR:

  

```

python3 adbuilder_dataset.py --dataset-type binary --metadata-dataset output\metadata.csv --threshold 5 --output-dir output

```

  

**Generating Dataset Discrete:**

  

To generate the dataset with discrete data, use the following command:

  

```

python3 adbuilder_dataset.py --dataset-type discrete -md output\metadata.csv -th 5 --output-dir output

```

OR:

  

```

python3 adbuilder_dataset.py --dataset-type discrete --metadata-dataset output\metadata.csv --threshold 5 --output-dir output

```
## 🖱️ Test Environment
The tool has been tested and used in practice in the following environments:

Ubuntu 22.04 LTS

Kernel = 5.15.0-41 generic
Python = 3.10.4
Pandas (version 1.3.5)
Termcolor (version 2.3.0)
