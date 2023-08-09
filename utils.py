from termcolor import colored
import os

def print_exception(e, addicional_info, logger = None):
    error_type = type(e).__name__
    error_message = e.args[0]
    msg = colored(f'[EXCEPTION] {addicional_info} >> {error_type}: {error_message}', 'red', attrs = ['bold'])
    if logger:
        logger.exception(msg)
    else:
        print(msg)

def print_error(message, logger = None):
    msg = colored(f'[ERROR] {message}', 'red', attrs = ['bold'])
    if logger:
        logger.error(msg)
    else:
        print(msg)

def is_directory_with_json_file(dir_path):
    if not os.path.exists(dir_path) or not os.path.isdir(dir_path):
        print_error(f'The directory \'{dir_path}\' is invalid or not found')
        return False
    files_in_directory = os.listdir(dir_path)
    json_files = [file for file in files_in_directory if file.endswith('.json')]
    if len(json_files):
        return True
    else:
        print_error(f'The directory \'{dir_path}\' does not contain JSON files')
        return False

def is_csv_file(file_path):
    if not os.path.exists(file_path) or not os.path.isfile(file_path):
        print_error(f'The file \'{file_path}\' is invalid or not found')
        return False
    return True
