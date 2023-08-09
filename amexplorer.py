import json
import os
import pandas as pd
import argparse
from datetime import datetime
import time
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import pandas as pd
import ast
import glob
import sys
import tempfile
from termcolor import colored
from utils import *

# process_features_json_files_AG carrega e processa os JSONs de features do Androguard
def process_features_json_files_AG(androguard_features):
    print("Starting processing JSONs from Features Androguard...")
    global temp_file_dict
    # Create an empty list to store the extracted information
    data_list_features = list()
    # Iterate over files in the directory
    for filename in os.listdir(androguard_features):
        if filename.endswith('.json'):
            file_path = os.path.join(androguard_features, filename)
            try:
                # Opening JSON file
                with open(file_path) as file:
                    data = json.load(file)
                # Acessar o valor como lista
                sha256 = data['SHA256']
                permissions = data['PERMISSIONS']
                # Add 1 to each item in the 'PERMISSIONS' list
                # Create a list of dictionaries with the name and value for each permission
                modified_permissions = [{'name': perm, 'value': 1} for perm in permissions]
                activities = data['ACTIVITIES']
                services = data['SERVICES']
                receivers = data['RECEIVERS']
                providers = data['PROVIDERS']
                intents = data['INTENTS']
                opcodes = data['OPCODES']
                apicalls = data['APICALLS']
                # Append the row data to the list
                data_list_features.append({
                    'SHA256': sha256,
                    'AG_PERMISSIONS': permissions,
                    'AG_ACTIVITIES': activities,
                    'AG_SERVICES': services,
                    'AG_RECEIVERS': receivers,
                    'AG_PROVIDERS': providers,
                    'AG_INTENTS': intents,
                    'AG_OPCODES': opcodes,
                    'AG_APICALLS': apicalls
                })
            except Exception as e:
                print_exception(e, 'Androguard Features')
    df = pd.DataFrame(data_list_features)
    with tempfile.NamedTemporaryFile(suffix = '.csv', delete = False) as tmp_file:
        # Salvar o DataFrame como arquivo CSV temporário
        df.to_csv(tmp_file.name, index = False)
        # Armazenar o nome do arquivo temporário na variável global
        temp_file_dict['androguard_features'] = tmp_file.name
        # Exibir as listas
        # df.to_csv("dataset_features.csv", index=False)
    print("Processing of Androguard Features JSONs completed.")

# process_metadata_json_files_AG carrega e processa os JSONs de metadata do Androguard
def process_metadata_json_files_AG(androguard_metadata):
    print("Starting processing JSONs from Metadata Androguard...")
    global temp_file_dict
    # Create an empty list to store the extracted information
    data_list = list()

    # Iterate over files in the directory
    for filename in os.listdir(androguard_metadata):
        if filename.endswith('.json'):
            file_path1 = os.path.join(androguard_metadata, filename)
            # Opening JSON file
            with open(file_path1) as file:
                json_data = json.load(file)
            # Extract the relevant data from the JSON file
            sha256 = json_data['SHA256']
            app_name = json_data['APP_NAME']
            package = json_data['PACKAGE']
            target_api = json_data['TARGET_API']
            min_api = json_data['MIN_API']
            # Append the row data to the list
            data_list.append({
                'SHA256': sha256,
                'AG_APP_NAME': app_name,
                'AG_PACKAGE': package,
                'AG_TARGET_API': target_api,
                'AG_MIN_API': min_api
            })

    # Specify the columns for the CSV file
    columns = ['SHA256', 'AG_APP_NAME', 'AG_PACKAGE', 'AG_TARGET_API', 'AG_MIN_API']

    df = pd.DataFrame(data_list)
    with tempfile.NamedTemporaryFile(suffix='.csv', delete=False) as tmp_file:
        # Salvar o DataFrame como arquivo CSV temporário
        df.to_csv(tmp_file.name, index=False)
        # Armazenar o nome do arquivo temporário na variável global
        temp_file_dict['androguard_metadata'] = tmp_file.name
        # Exibir as listas
        #df.to_csv("dataset_metadata.csv", index=False)
        print("Processing of Androguard Metadata JSONs completed.")

# process_json_files_VT carrega e processa os JSONs do VirusTotal
def process_json_files_VT(virustotal_metadata, threshold):
    print("Starting processing JSONs from Virustotal...")
    # Create an empty list to store the extracted information
    global temp_file_dict
    data_list = list()
    # Iterate over files in the directory
    for filename in os.listdir(virustotal_metadata):
        if filename.endswith('.json'):
            file_path = os.path.join(virustotal_metadata, filename)

            # Read JSON file
            with open(file_path) as file:
                json_data = file.read()

            # Parse JSON data
            data = json.loads(json_data)

            # Extract relevant information
            attributes = data['data']['attributes']

            last_analysis = attributes.get('last_analysis_date')
            last_analysis_date = datetime.fromtimestamp(last_analysis)
            first_submission = attributes.get('first_submission_date')
            first_submission_date = datetime.fromtimestamp(first_submission)
            size = attributes.get('size')
            sha256 = attributes.get('sha256').upper()
            md5 = attributes.get('md5')
            times_submitted = attributes.get('times_submitted')
            #last_analysis_stats = attributes.get('last_analysis_stats')
            last_analysis_results = attributes.get('last_analysis_results', {})
            #engine_names = [result['engine_name'] for result in last_analysis_results.values() if result is not None]
            #Pega apenas os scanners que detectaram como malwares
            engine_names = [result['engine_name'] for result in last_analysis_results.values() if result is not None and result.get('category') == 'malicious']
            ####################################################################
            last_analysis_stats = attributes.get('last_analysis_stats', {})
            harmless = last_analysis_stats.get('harmless', 0)
            type_unsupported = last_analysis_stats.get('type-unsupported', 0)
            suspicious = last_analysis_stats.get('suspicious', 0)
            confirmed_timeout = last_analysis_stats.get('confirmed-timeout', 0)
            timeout = last_analysis_stats.get('timeout', 0)
            failure = last_analysis_stats.get('failure', 0)
            malicious = last_analysis_stats.get('malicious', 0)
            undetected = last_analysis_stats.get('undetected', 0)

            # Extract suggested threat label
            popular_threat_classification = attributes.get('popular_threat_classification', {})
            suggested_threat_label = popular_threat_classification.get('suggested_threat_label')

            # Extract popular threat category and name (optional)
            popular_threat_category = popular_threat_classification.get('popular_threat_category', [])
            popular_threat_name = popular_threat_classification.get('popular_threat_name', [])
            # Determine the class based on the threshold
            #class_value = 0
            #if malicious >= threshold:
            #    class_value = 1
            #else:
            #    class_value = 0
            # Iterate over the AndroidAPICall dictionary
            row_data = {
                'VT_LAST_ANALYSIS_DATE': last_analysis_date,
                #'VT_FIRST_SUBMISSION_DATE': first_submission_date,
                'VT_SIZE': size,
                'SHA256': sha256,
                'VT_MD5': md5,
                'VT_TIMES_SUBMITTED':times_submitted,
                #'Last Analysis Stats': last_analysis_stats,
                #'VT_Harmless': harmless,
                #'VT_Type_Unsupported': type_unsupported,
                #'VT_Suspicious': suspicious,
                #'VT_Confirmed_Timeout': confirmed_timeout,
                #'VT_Timeout': timeout,
                'VT_SCANNERS_FAILURE': failure,
                'VT_SCANNERS_MALICIOUS': malicious,
                'VT_SCANNERS_UNDETECTED': undetected,
                'VT_SCANNERS_SUGGESTED_THREAT_LABEL': suggested_threat_label,
                #'VT_CLASS_'+str(threshold)+'_SCANNERS': class_value,
                #'VT_CLASS_SCANNERS': class_value,
                'VT_SCANNERS_NAMES': engine_names
            }

            # Append the row data to the list
            data_list.append(row_data)

    # Create a DataFrame from the list of dictionaries
    df = pd.DataFrame(data_list)
    with tempfile.NamedTemporaryFile(suffix='.csv', delete=False) as tmp_file:
        # Salvar o DataFrame como arquivo CSV temporário
        df.to_csv(tmp_file.name, index=False)
        # Armazenar o nome do arquivo temporário na variável global
        temp_file_dict['virustotal'] = tmp_file.name
        # Save DataFrame to CSV file
        #df.to_csv("virustotal.csv", index=False)
        print("Processing of VirusTotal JSONs completed.")

# process_csv_AZ carrega e processa o CSV do Androzoo
def process_csv_AZ(androzoo_metadata):
    global temp_file_dict
    print("Starting AndroZoo CSV processing...")
    try:
        # Specify the columns to read from the input CSV
        columns = ["sha256", "vt_detection", "vt_scan_date", "markets"]

        # Read the specified columns from the input CSV into a DataFrame
        df = pd.read_csv(androzoo_metadata, usecols=columns)

        # Perform any necessary processing on the DataFrame here

        # Rename the "sha256" column to "SHA256"
        df.rename(columns={"sha256": "SHA256", "vt_detection": "AZ_DETECTION", "vt_scan_date": "AZ_SCAN_DATE", "markets": "AZ_MARKETS"}, inplace=True)

        with tempfile.NamedTemporaryFile(suffix='.csv', delete=False) as tmp_file:
            # Salvar o DataFrame como arquivo CSV temporário
            df.to_csv(tmp_file.name, index=False)
            # Armazenar o nome do arquivo temporário na variável global
            temp_file_dict['androzoo'] = tmp_file.name
            # Save the processed DataFrame to the output CSV file
            #df.to_csv("androzoo.csv", index=False)

            print("AndroZoo CSV processing completed.")
    except FileNotFoundError:
        print(f"Error: The input file '{androzoo_metadata}' does not exist or was not found.")

# merge_datasets gera o dataset de matadata juntando os dados processados nas funções acima
def merge_datasets(dataset_file):
    global temp_file_dict
    # Read the JSON output file VirusTotal
    df_json_vt = pd.read_csv(temp_file_dict['virustotal'])

    # Read the CSV output file AndroZoo
    df_csv_az = pd.read_csv(temp_file_dict['androzoo'])
    # Read the CSV output file Features Androguard
    df_features_csv_ag = pd.read_csv(temp_file_dict['androguard_features'])

    # Read the CSV output file Metadatas androguard
    df_metadata_csv_ag = pd.read_csv(temp_file_dict['androguard_metadata'])

    df_metadata_csv_ag['AG_APP_NAME'] = df_metadata_csv_ag['AG_APP_NAME'].apply(lambda x: 'suppressed' if re.search(r'[^\x00-\x7F]', str(x)) else x)

    # Merge the DataFrames based on the SHA256 column
    df_merged = pd.merge(df_json_vt, df_csv_az, on = 'SHA256')
    df_merged = pd.merge(df_merged, df_features_csv_ag, on = 'SHA256')
    df_merged = pd.merge(df_merged, df_metadata_csv_ag, on = 'SHA256')

    # Save the merged DataFrame to the dataset file
    df_merged.to_csv(dataset_file, sep=';', index=False)
    # Cleanup: Remove temp files
    for key in temp_file_dict.keys():
        os.remove(temp_file_dict[key])

# set_permissions gera um dataset de permissões legivel para ML
def set_permissions(dataset_metadata):
    list_modified_permissions = list()
    for permissions_str in dataset_metadata['AG_PERMISSIONS']:

        # Converter a string de permissões em uma lista de strings
        permissions_list = permissions_str.strip("[]").replace("'", "").split(", ")

        # Criar a lista de permissões modificadas
        modified_permissions = [{'name': perm, 'value': 1} for perm in permissions_list]
        list_modified_permissions.append(modified_permissions)
    # Criar um dicionário para construir o DataFrame
    dataset_dict = dict()

    # Encontrar todos os nomes únicos
    unique_names = set(entry['name'] for d in list_modified_permissions for entry in d)

    # Inicializar o dicionário
    for name in unique_names:
        dataset_dict[name] = list()

    # Preencher o dicionário
    for item in list_modified_permissions:
        name_value_dict = {entry['name']: entry['value'] for entry in item}
        for name in unique_names:
            dataset_dict[name].append(name_value_dict.get(name, 0))

    # Criar o DataFrame com as permissões
    df_features = pd.DataFrame(dataset_dict)
    # Adiciona o prefixo aos nomes das colunas
    df_features = df_features.add_prefix("PERMISSION_")
    # Em seguida, concatenamos o DataFrame df_features ao dataset original
    df_features_permission = pd.concat([dataset_metadata['SHA256'], df_features], axis=1)
    #df_features_permission.to_csv("Dataset/df_features_permission.csv", index=False)

    return df_features_permission.drop_duplicates(subset='SHA256')

# set_permissions gera um dataset de activities legivel para ML
def set_activities(dataset_metadata):
    list_modified_activities = list()

    for activities_str in dataset_metadata['AG_ACTIVITIES']:
        # Converter a string de permissões em uma lista de strings
        activities_list = activities_str.strip("[]").replace("'", "").split(", ")

        # Criar a lista de permissões modificadas
        modified_activities = [{'name': act, 'value': 1} for act in activities_list]
        list_modified_activities.append(modified_activities)
    # Criar um dicionário para construir o DataFrame
    dataset_dict = dict()

    # Encontrar todos os nomes únicos
    unique_names = set(entry['name'] for d in list_modified_activities for entry in d)

    # Inicializar o dicionário
    for name in unique_names:
        dataset_dict[name] = list()

    # Preencher o dicionário
    for item in list_modified_activities:
        name_value_dict = {entry['name']: entry['value'] for entry in item}
        for name in unique_names:
            dataset_dict[name].append(name_value_dict.get(name, 0))

    # Criar o DataFrame com as permissões
    df_features = pd.DataFrame(dataset_dict)
    # Adiciona o prefixo aos nomes das colunas
    df_features = df_features.add_prefix("ACTIVITY_")
    # Em seguida, concatenamos o DataFrame df_features ao dataset original
    dataset_activities = pd.concat([dataset_metadata['SHA256'], df_features], axis=1)
    return dataset_activities.drop_duplicates(subset='SHA256')

# set_permissions gera um dataset de services legivel para ML
def set_services(dataset_metadata):
    list_modified_services = list()

    for services_str in dataset_metadata['AG_SERVICES']:
        # Converter a string de permissões em uma lista de strings
        services_list = services_str.strip("[]").replace("'", "").split(", ")

        # Criar a lista de permissões modificadas
        modified_services = [{'name': act, 'value': 1} for act in services_list]
        list_modified_services.append(modified_services)
    # Criar um dicionário para construir o DataFrame
    dataset_dict = dict()

    # Encontrar todos os nomes únicos
    unique_names = set(entry['name'] for d in list_modified_services for entry in d)

    # Inicializar o dicionário
    for name in unique_names:
        dataset_dict[name] = list()

    # Preencher o dicionário
    for item in list_modified_services:
        name_value_dict = {entry['name']: entry['value'] for entry in item}
        for name in unique_names:
            dataset_dict[name].append(name_value_dict.get(name, 0))

    # Criar o DataFrame com as permissões
    df_features = pd.DataFrame(dataset_dict)
    # Adiciona o prefixo aos nomes das colunas
    df_features = df_features.add_prefix("SERVICE_")
    # Em seguida, concatenamos o DataFrame df_features ao dataset original
    dataset_services = pd.concat([dataset_metadata['SHA256'], df_features], axis=1)
    return dataset_services.drop_duplicates(subset='SHA256')

# set_permissions gera um dataset de receivers legivel para ML
def set_receivers(dataset_metadata):
    list_modified_receivers = list()

    for receivers_str in dataset_metadata['AG_RECEIVERS']:
        # Converter a string de permissões em uma lista de strings
        receivers_list = receivers_str.strip("[]").replace("'", "").split(", ")

        # Criar a lista de permissões modificadas
        modified_receivers = [{'name': act, 'value': 1} for act in receivers_list]
        list_modified_receivers.append(modified_receivers)
    # Criar um dicionário para construir o DataFrame
    dataset_dict = dict()

    # Encontrar todos os nomes únicos
    unique_names = set(entry['name'] for d in list_modified_receivers for entry in d)

    # Inicializar o dicionário
    for name in unique_names:
        dataset_dict[name] = list()

    # Preencher o dicionário
    for item in list_modified_receivers:
        name_value_dict = {entry['name']: entry['value'] for entry in item}
        for name in unique_names:
            dataset_dict[name].append(name_value_dict.get(name, 0))

    # Criar o DataFrame com as permissões
    df_features = pd.DataFrame(dataset_dict)
    # Adiciona o prefixo aos nomes das colunas
    df_features = df_features.add_prefix("RECEIVER_")
    # Em seguida, concatenamos o DataFrame df_features ao dataset original
    dataset_receivers = pd.concat([dataset_metadata['SHA256'], df_features], axis=1)
    return dataset_receivers.drop_duplicates(subset='SHA256')

# set_permissions gera um dataset de providers legivel para ML
def set_providers(dataset_metadata):
    list_modified_provider = list()

    for provider_str in dataset_metadata['AG_PROVIDERS']:
        # Converter a string de permissões em uma lista de strings
        provider_list = provider_str.strip("[]").replace("'", "").split(", ")

        # Criar a lista de permissões modificadas
        modified_provider = [{'name': act, 'value': 1} for act in provider_list]
        list_modified_provider.append(modified_provider)
    # Criar um dicionário para construir o DataFrame
    dataset_dict = dict()

    # Encontrar todos os nomes únicos
    unique_names = set(entry['name'] for d in list_modified_provider for entry in d)

    # Inicializar o dicionário
    for name in unique_names:
        dataset_dict[name] = list()

    # Preencher o dicionário
    for item in list_modified_provider:
        name_value_dict = {entry['name']: entry['value'] for entry in item}
        for name in unique_names:
            dataset_dict[name].append(name_value_dict.get(name, 0))

    # Criar o DataFrame com as permissões
    df_features = pd.DataFrame(dataset_dict)
    # Adiciona o prefixo aos nomes das colunas
    df_features = df_features.add_prefix("PROVIDER_")
    # Em seguida, concatenamos o DataFrame df_features ao dataset original
    dataset_providers = pd.concat([dataset_metadata['SHA256'], df_features], axis=1)
    return dataset_providers.drop_duplicates(subset='SHA256')

# set_permissions gera um dataset de intents legivel para ML
def set_intents(dataset_metadata):
    list_modified_intents = list()

    for intents_str in dataset_metadata['AG_INTENTS']:
        # Converter a string de permissões em uma lista de strings
        intents_list = intents_str.strip("[]").replace("'", "").split(", ")

        # Criar a lista de permissões modificadas
        modified_intents = [{'name': act, 'value': 1} for act in intents_list]
        list_modified_intents.append(modified_intents)
    # Criar um dicionário para construir o DataFrame
    dataset_dict = dict()

    # Encontrar todos os nomes únicos
    unique_names = set(entry['name'] for d in list_modified_intents for entry in d)

    # Inicializar o dicionário
    for name in unique_names:
        dataset_dict[name] = list()

    # Preencher o dicionário
    for item in list_modified_intents:
        name_value_dict = {entry['name']: entry['value'] for entry in item}
        for name in unique_names:
            dataset_dict[name].append(name_value_dict.get(name, 0))

    # Criar o DataFrame com as permissões
    df_features = pd.DataFrame(dataset_dict)
    # Adiciona o prefixo aos nomes das colunas
    df_features = df_features.add_prefix("INTENT_")
    # Em seguida, concatenamos o DataFrame df_features ao dataset original
    dataset_intents = pd.concat([dataset_metadata['SHA256'], df_features], axis=1)
    return dataset_intents.drop_duplicates(subset='SHA256')

# set_apicalls gera um dataset de apicalls legivel para ML
def set_apicalls(dataset_metadata):
    list_modified_apicalls = list()

    for apicalls_str in dataset_metadata['AG_APICALLS']:
        # Convert the string of API calls into a list of dictionaries
        apicalls_list = eval(apicalls_str)  # Assuming the input is a valid Python dictionary string

        # Criar a lista de apicalls modificadas
        modified_apicalls = [{'name': call, 'value': count} for call, count in apicalls_list.items()]
        list_modified_apicalls.append(modified_apicalls)

    # Criar um dicionário para construir o DataFrame
    dataset_dict = dict()

    # Encontrar todos os nomes únicos
    unique_names = set(entry['name'] for d in list_modified_apicalls for entry in d)

    # Inicializar o dicionário
    for name in unique_names:
        dataset_dict[name] = list()

    # Preencher o dicionário
    for item in list_modified_apicalls:
        name_value_dict = {entry['name']: entry['value'] for entry in item}
        for name in unique_names:
            dataset_dict[name].append(name_value_dict.get(name, 0))

    # Criar o DataFrame com as apicalls
    df_features = pd.DataFrame(dataset_dict)
    df_features = df_features.add_prefix("APICALL_")
    # Transformar os valores em colunas binárias (0 ou 1) para cada chamada de API (categórico)
    df_features_binary = df_features.applymap(lambda x: 1 if x > 0 else 0)

    # Em seguida, concatenamos o DataFrame df_features ao dataset original
    dataset_discrete = pd.concat([dataset_metadata['SHA256'], df_features], axis=1)
    dataset_binary = pd.concat([dataset_metadata['SHA256'], df_features_binary], axis=1)

    return dataset_discrete.drop_duplicates(subset='SHA256'), dataset_binary.drop_duplicates(subset='SHA256')

# set_permissions gera um dataset de opcodes legivel para ML
def set_opcodes(dataset_metadata):
    list_modified_opcodes = list()

    for opcodes_str in dataset_metadata['AG_OPCODES']:
        # Convert the string of OPCODE into a list of dictionaries
        opcodes_list = eval(opcodes_str)  # Assuming the input is a valid Python dictionary string

        # Criar a lista de apicalls modificadas
        modified_opcodes = [{'name': opc, 'value': count} for opc, count in opcodes_list.items()]
        list_modified_opcodes.append(modified_opcodes)

    # Criar um dicionário para construir o DataFrame
    dataset_dict = dict()

    # Encontrar todos os nomes únicos
    unique_names = set(entry['name'] for d in list_modified_opcodes for entry in d)

    # Inicializar o dicionário
    for name in unique_names:
        dataset_dict[name] = list()

    # Preencher o dicionário
    for item in list_modified_opcodes:
        name_value_dict = {entry['name']: entry['value'] for entry in item}
        for name in unique_names:
            dataset_dict[name].append(name_value_dict.get(name, 0))


    # Criar o DataFrame com as apicalls
    df_features = pd.DataFrame(dataset_dict)
    df_features = df_features.add_prefix("OPCODE_")
    # Transformar os valores em colunas binárias (0 ou 1) para cada chamada de API (categórico)
    df_features_binary = df_features.applymap(lambda x: 1 if x > 0 else 0)

    # Em seguida, concatenamos o DataFrame df_features ao dataset original
    dataset_discrete = pd.concat([dataset_metadata['SHA256'], df_features], axis=1)
    dataset_binary = pd.concat([dataset_metadata['SHA256'], df_features_binary], axis=1)

    return dataset_discrete.drop_duplicates(subset='SHA256'), dataset_binary.drop_duplicates(subset='SHA256')

# process_dataset_metadata processa as funções em paralelo para metadata
def process_dataset_metadata(args):
    global dataset_file_dict
    dataset_file = dataset_file_dict['metadata']
    # Cria uma fila de execução com um ThreadPoolExecutor
    with ThreadPoolExecutor() as executor:

        # Chama a função process_metadata_json_files com os argumentos fornecidos e aguarda a conclusão
        features_json_processing_ag = executor.submit(process_features_json_files_AG, args.androguard_features)

        # Chama a função process_metadata_json_files com os argumentos fornecidos e aguarda a conclusão
        metadata_json_processing_ag = executor.submit(process_metadata_json_files_AG, args.androguard_metadata)

        # Chama a função process_json_files com os argumentos fornecidos e aguarda a conclusão
        json_processing = executor.submit(process_json_files_VT, args.virustotal_metadata, args.threshold)

        # Chama a função process_csv com os argumentos fornecidos e aguarda a conclusão
        csv_processing = executor.submit(process_csv_AZ, args.androzoo_metadata)

        # Chama a função merge
        dataset_processing = executor.submit(merge_datasets, dataset_file)

        # Aguarda a conclusão de ambas as tarefas
        completed_tasks = set([features_json_processing_ag, metadata_json_processing_ag,json_processing, csv_processing])
        while completed_tasks:
            # Verifica se todas as tarefas estão concluídas
            for completed_task in as_completed(completed_tasks):
                completed_tasks.remove(completed_task)

            # Verifica se ambas as tarefas estão concluídas
            if not completed_tasks:
                print("Starting the generation of the metadata dataset...")
                # Chama a função merge_datasets com os argumentos fornecidos
                dataset_processing = executor.submit(merge_datasets, dataset_file)
                dataset_processing.result()  # Aguarda a conclusão da tarefa dataset_processing
                print(f"Dataset metadata completed in: {dataset_file}")

def process_dataset_discrete(args):
    global dataset_file_dict
    dataset_file = dataset_file_dict['discrete']
    print("Starting the generation of datasets with discrete data...")
    # Remover tudo após o ponto na entrada do usuário args.dataset_features
    dataset_metadata = dataset_file_dict['metadata']
    # Verifica se o arquivo existe
    if os.path.exists(dataset_metadata):
        # Se o arquivo existe, leia-o com o Pandas
        dataset_final = pd.read_csv(dataset_metadata, sep=";")
        dataset_permissions = set_permissions(dataset_final)
        df_apicall_discrete, df_apicall_binary = set_apicalls(dataset_final)
        dataset_intents = set_intents(dataset_final)
        dataset_activities = set_activities(dataset_final)
        dataset_providers = set_providers(dataset_final)
        dataset_receivers = set_receivers(dataset_final)
        dataset_services = set_services(dataset_final)
        df_opcode_discrete, df_opcode_binary = set_opcodes(dataset_final)

        # merge com as características usando SHA256 e VT_CLASS_SCANNERS
        df_filter_columns = dataset_final[['SHA256', 'VT_SCANNERS_MALICIOUS']].copy()
        # Add the 'Novacoluna' column with the desired values based on the condition
        df_filter_columns.loc[:, 'VT_CLASS_SCANNERS'] = df_filter_columns['VT_SCANNERS_MALICIOUS'].apply(lambda x: 1 if x > args.threshold else 0)
        df_filter_columns.drop(columns = 'VT_SCANNERS_MALICIOUS', inplace = True)


        df_merged_features_discrete = pd.merge(dataset_permissions, dataset_intents, on = 'SHA256')
        df_merged_features_discrete = pd.merge(df_merged_features_discrete, dataset_intents, on = 'SHA256')
        df_merged_features_discrete = pd.merge(df_merged_features_discrete, dataset_activities, on = 'SHA256')
        df_merged_features_discrete = pd.merge(df_merged_features_discrete, dataset_providers, on = 'SHA256')
        df_merged_features_discrete = pd.merge(df_merged_features_discrete, dataset_receivers, on = 'SHA256')
        df_merged_features_discrete = pd.merge(df_merged_features_discrete, dataset_services, on = 'SHA256')
        df_merged_features_discrete = pd.merge(df_merged_features_discrete, df_apicall_discrete, on = 'SHA256')
        df_merged_features_discrete = pd.merge(df_merged_features_discrete, df_opcode_discrete, on = 'SHA256')
        df_merged_features_discrete = pd.merge(df_merged_features_discrete, df_filter_columns, on = 'SHA256')
        df_merged_features_discrete.to_csv(dataset_file, sep = ';', index = False)
        print(f'Dataset with discrete data completed in: {dataset_file}')

    else:
        # Se o arquivo não existe, informe ao usuário
        print('Metadata file not found! Check the path and try again')

    pass

def process_dataset_binary(args):
    global dataset_file_dict
    dataset_file = dataset_file_dict['binary']
    print('Starting the generation of datasets with binary data...')
    # Remover tudo após o ponto na entrada do usuário args.dataset_features
    dataset_metadata = dataset_file_dict['metadata']
    # Verifica se o arquivo existe
    if os.path.exists(dataset_metadata):
        # Se o arquivo existe, leia-o com o Pandas
        dataset_final = pd.read_csv(dataset_metadata, sep = ";")
        dataset_permissions = set_permissions(dataset_final)
        df_apicall_discrete, df_apicall_binary = set_apicalls(dataset_final)
        dataset_intents = set_intents(dataset_final)
        dataset_activities = set_activities(dataset_final)
        dataset_providers = set_providers(dataset_final)
        dataset_receivers = set_receivers(dataset_final)
        dataset_services = set_services(dataset_final)
        df_opcode_discrete, df_opcode_binary = set_opcodes(dataset_final)

        # merge com as características usando SHA256 e VT_CLASS_SCANNERS
        df_filter_columns = dataset_final[['SHA256', 'VT_SCANNERS_MALICIOUS']].copy()
        # Add the 'Novacoluna' column with the desired values based on the condition
        df_filter_columns.loc[:, 'VT_CLASS_SCANNERS'] = df_filter_columns['VT_SCANNERS_MALICIOUS'].apply(lambda x: 1 if x > args.threshold else 0)
        df_filter_columns.drop(columns = 'VT_SCANNERS_MALICIOUS', inplace = True)

        df_merged_features_binary = pd.merge(dataset_permissions, dataset_intents, on = 'SHA256')
        df_merged_features_binary = pd.merge(df_merged_features_binary, dataset_intents, on = 'SHA256')
        df_merged_features_binary = pd.merge(df_merged_features_binary, dataset_activities, on = 'SHA256')
        df_merged_features_binary = pd.merge(df_merged_features_binary, dataset_providers, on = 'SHA256')
        df_merged_features_binary = pd.merge(df_merged_features_binary, dataset_receivers, on = 'SHA256')
        df_merged_features_binary = pd.merge(df_merged_features_binary, dataset_services, on = 'SHA256')
        df_merged_features_binary = pd.merge(df_merged_features_binary, df_apicall_binary, on = 'SHA256')
        df_merged_features_binary = pd.merge(df_merged_features_binary, df_opcode_binary, on = 'SHA256')
        df_merged_features_binary = pd.merge(df_merged_features_binary, df_filter_columns, on = 'SHA256')
        df_merged_features_binary.to_csv(dataset_file, sep = ';', index = False)

        print(f'Dataset with binary data completed in: {dataset_file}')

    else:
        # Se o arquivo não existe, informe ao usuário
        print('Metadata file not found! Check the path and try again')

    pass

class DefaultHelpParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_help()
        print_error(message)
        exit(1)

def parse_args(argv):
    global dataset_types
    desc_msg = colored('*** First Generate METADATA Dataset ***', 'green')
    parser = DefaultHelpParser(formatter_class = argparse.RawTextHelpFormatter, description = desc_msg)
    parser._optionals.title = 'Show Help'

    parser_options = parser.add_argument_group('ADBuilder Parameters')
    dataset_type_group = parser_options.add_mutually_exclusive_group(required = True)
    dataset_type_group.add_argument('--dataset-type', nargs = '+', metavar = 'TYPE',
        type = str.lower, choices = dataset_types,
        help = f'Type of Dataset To Be Generated. Choices: {dataset_types}')
    dataset_type_group.add_argument('--dataset-type-all',
        help = 'Generate All Dataset Types', action = 'store_true')
    '''
    parser_options.add_argument('--dataset-type', metavar = 'TYPE',
        type = str, choices = dataset_types,
        help = f'Type of Dataset To Be Generated. Choices: {dataset_types}', required = True)
    '''
    parser_options.add_argument('--output-dir', metavar = 'PATH',
        type = str, default = 'outputs', help = 'Dataset Output Directory (Default: \'adb_output\')')
    parser_options.add_argument('--prefix', metavar = 'PREFIX',
        type = str, help = 'Prefix To Be Used in Output Dataset')

    # Adicionar nomes literais e Abreviações.
    metadata_parser = parser.add_argument_group('Metadata Dataset')
    metadata_parser.add_argument('--androguard-features', '-agf', metavar = 'PATH',
        type = str, help = 'Directory Path of AndroGuard Features JSON Files')
    metadata_parser.add_argument('--androguard-metadata', '-agm', metavar = 'PATH',
        type = str, help = 'Directory Path of AndroGuard Metadata JSON Files')
    metadata_parser.add_argument('--virustotal-metadata', '-vtm', metavar = 'PATH',
        type = str, help = 'Directory Path of VirusTotal JSON Files')
    metadata_parser.add_argument('--androzoo-metadata', '-azm', metavar = 'FILE_PATH',
        type = str, help = 'AndroZoo CSV File Path')

    binary_discrete_parser = parser.add_argument_group('Binary or Discrete Dataset')
    binary_discrete_parser.add_argument('--metadata-dataset','-md', metavar = 'FILE_PATH',
        type = str, help = 'Metadata Dataset CSV File Path')
    binary_discrete_parser.add_argument('--threshold', '-th', metavar = 'INT',
        type = int, default = 4, help = 'Number of VirusTotal Scanners to Define Malware (Default: 4)')

    args = parser.parse_args(argv)

    if args.dataset_type_all or 'metadata' in args.dataset_type:
        #checks if parameters for the metadata dataset have been assigned
        not_set_args = list()
        for action in metadata_parser._group_actions:
            if getattr(args, action.dest) is None:
                #if abbreviation (short flag) exists, show the abbreviation and the full name
                a = '/'.join(action.option_strings) if len(action.option_strings) > 1 else action.option_strings[0]
                not_set_args.append(a)
        if not_set_args:
            nsa = ', '.join(not_set_args)
            nsa_msg = '--dataset-type-all is set' if args.dataset_type_all else '--dataset-type is set with \'metadata\''
            parser.error(f'the following arguments are required when {nsa_msg}: {nsa}')

    if not args.dataset_type_all and 'metadata' not in args.dataset_type:
        if ('binary' in args.dataset_type or 'discrete' in args.dataset_type) and not args.metadata_dataset:
            nsa = '--metadata-dataset/-md'
            parser.error(f'the following arguments are required when --dataset-type is set with \'binary\' or \'discrete\': {nsa}')

    return args

def generate_dataset_files_path(args):
    global dataset_types
    global dataset_file_dict
    time_stamp = datetime.now().strftime('%Y%m%d%H%M%S')
    os.makedirs(args.output_dir, exist_ok = True)
    prefix = '' if not args.prefix else f'{args.prefix}_'
    selected_types = dataset_types if args.dataset_type_all else args.dataset_type
    for type in selected_types:
        filename = f'{prefix}{time_stamp}_{type}.csv'
        dataset_file_dict[type] = os.path.join(args.output_dir, filename)
    if not args.dataset_type_all and 'metadata' not in args.dataset_type:
        dataset_file_dict['metadata'] = args.metadata_dataset

if __name__ == '__main__':
    global temp_file_dict
    global dataset_file_dict
    #global dataset_files

    temp_file_dict = dict()
    dataset_file_dict = dict()
    dataset_types = ['metadata', 'binary', 'discrete']
    args = parse_args(sys.argv[1:])
    generate_dataset_files_path(args)

    if args.dataset_type_all or 'metadata' in args.dataset_type:
        # Create a list to store the missing or incorrect paths
        missing_paths = list()
        # Check if directories exists before proceeding
        if not is_directory_with_json_file(args.androguard_features):
            missing_paths.append('--androguard-features/-agf')
        if not is_directory_with_json_file(args.androguard_metadata):
            missing_paths.append('--androguard-metadata/-agm')
        if not is_directory_with_json_file(args.virustotal_metadata):
            missing_paths.append('--virustotal-metadata/-vtm')
        if not is_csv_file(args.androzoo_metadata):
            missing_paths.append('--androzoo-metadata/-azm')

        if missing_paths:
            p = ', '.join(missing_paths)
            print_error(f'The following paths are missing or incorrect: {p}')
            exit(1)
        else:
            process_dataset_metadata(args)

    if args.dataset_type_all or 'binary' in args.dataset_type:
        if not is_csv_file(dataset_file_dict['metadata']):
            print_error('The following paths are missing or incorrect: --metadata-dataset/-md')
            exit(1)
        else:
            process_dataset_binary(args)

    if args.dataset_type_all or 'discrete' in args.dataset_type:
        if not is_csv_file(dataset_file_dict['metadata']):
            print_error('The following paths are missing or incorrect: --metadata-dataset/-md')
            exit(1)
        else:
            process_dataset_discrete(args)
