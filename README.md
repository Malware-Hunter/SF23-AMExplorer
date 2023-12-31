# AMExplorer

  

[AMExplorer Overview](https://github.com/Malware-Hunter/SF23-AMExplorer/blob/main/OVERVIEW.md)


## Clonning the GitHub repository

```bash

git clone https://github.com/Malware-Hunter/SF23-AMExplorer.git

cd SF23-AMExplorer

```

## Running **demo** scripts
  


**Option 1**: script will install requirements in your system and run amexplorer.py app
```bash
./run_demo_app.sh

```

**Option 2**: script will just download and execute the Docker image **sf23/amexplorer:latest** from [hub.docker.com](hub.docker.com)
```bash
./run_demo_docker.sh

```
**Datasets will be generated in the directory called outputs**
  

## Building and running your own Docker image


### Installing Docker and building the image
```bash

sudo apt install docker docker.io

docker  build  -t  sf23/amexplorer:latest  .

```

## Starting a Docker container

```bash

docker  run  -it  sf23/amexplorer

ls output_amexplorer

```

  

## Manual Usage


The tool can be executed from the command line, providing various parameters:

  
  

**--dataset-type**

Type of Dataset To Be Generated. Choices: ['metadata', 'binary', 'discrete']

  

**--dataset-type-all**

Generate All Dataset Types

  

**--output-dir [PATH]**

Dataset Output Directory (Default: 'output_amexplorer')

  

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

python3 amexplorer.py --dataset-type-all --androguard-features metadata/androguard/features --androguard-metadata metadata/androguard/metadata --virustotal-metadata metadata/virustotal --androzoo-metadata metadata/androzoo/androzoo_metadata.csv --output-dir output_amexplorer

```

  

**Generating Dataset Metadata:**

  

To generate the dataset metadata, use the following command:

  

```

python3 amexplorer.py --dataset-type metadata -agf metadata/androguard/features -agm metadata/androguard/metadata -vtm metadata/virustotal -azm metadata/androzoo/androzoo_metadata.csv --output-dir output_amexplorer

```

  

OR:

  

```

python3 amexplorer.py --dataset-type metadata --androguard-features metadata/androguard/features --androguard-metadata metadata/androguard/metadata --virustotal-metadata metadata/virustotal --androzoo-metadata metadata/androzoo/androzoo_metadata.csv --output-dir output_amexplorer

```

  

**Generating Dataset Binary:**

  

To generate the dataset with binary data, use the following command:

  

```

python3 amexplorer.py --dataset-type binary -md output_amexplorer\[file_metadata].csv -th 5 --output-dir output_amexplorer

```

  

OR:

  

```

python3 amexplorer.py --dataset-type binary --metadata-dataset output_amexplorer\[file_metadata].csv --threshold 5 --output-dir output_amexplorer

```

  

**Generating Dataset Discrete:**

  

To generate the dataset with discrete data, use the following command:

  

```

python3 amexplorer.py --dataset-type discrete -md output_amexplorer\[file_metadata].csv -th 5 --output-dir output_amexplorer

```

OR:

  

```

python3 amexplorer.py --dataset-type discrete --metadata-dataset output_amexplorer\[file_metadata].csv --threshold 5 --output-dir output_amexplorer

```
## 🖱️ Test Environment
The tool has been tested and used in practice in the following environments:

Ubuntu 22.04 LTS

Kernel = 5.15.0-41 generic
Python = 3.10.4
Pandas (version 1.3.5)
Termcolor (version 2.3.0)
