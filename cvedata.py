import csv
import json
import subprocess
import os
import shutil

#clears folder path before recopying it from github
def clearPath(folderPath):
    if os.path.exists(folderPath):
        shutil.rmtree(folderPath)
        print(f"Directory {folderPath} has been deleted.")
    else:
        print(f"Directory {folderPath} does not exist.")
#clones new repo
def cloneRepo(repoURL, folderPath):
    result = subprocess.run(['git', 'clone', repoURL, folderPath], capture_output=True, text=True)
    if result.returncode == 0:
        print(f"Repository cloned to {folderPath}")
    else:
        print(f"Error cloning repository: {result.stderr}")
#counts total JSON and amount that are enriched
def count_json_files_and_search_terms(local_repo_path, search_words):
    search_words = [word.lower() for word in search_words]
    json_file_count = 0
    files_with_word_count = 0

    for root, _, files in os.walk(local_repo_path):
        for file in files:
            if file.endswith('.json') and file.startswith('CVE'): #file validation
                json_file_count += 1
                file_path = os.path.join(root, file)
                if analyze_json_file(file_path, search_words):
                    files_with_word_count += 1

    return json_file_count, files_with_word_count

def analyze_json_file(file_path, search_words):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            file_content = json.load(f)
            file_content_str = json.dumps(file_content).lower()
            return any(word in file_content_str for word in search_words)
    except (json.JSONDecodeError, IOError) as e:
        print(f'Error reading or parsing file {file_path}: {e}')
        return False

def count_specific_search(local_repo_path, specificSearch):
    specificSearch = specificSearch.lower()
    files_with_specific_search = 0
    csv_file_path = str(specificSearch) + '.csv' #generates .csv file based on search word

    with open(csv_file_path, 'w',newline='') as csv_file:
        writer = csv.writer(csv_file)

        for root, _, files in os.walk(local_repo_path):
            for file in files:
                if file.endswith('.json') and file.startswith('CVE'): #file validation
                    file_path = os.path.join(root, file)
                    if analyze_json_search(file_path, specificSearch):
                        csvVal = file.removesuffix('.json') #removes file extension
                        files_with_specific_search += 1
                        writer.writerow([csvVal]) #[] sends value over as a list so stays on one line
        return files_with_specific_search

def analyze_json_search(file_path, searchWord):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            file_content = json.load(f)
            file_content_str = json.dumps(file_content).lower()
            return searchWord in file_content_str 
    except (json.JSONDecodeError, IOError) as e:
        print(f'Error reading or parsing file {file_path}: {e}')
        return False



def main():
    destination = 'vulnrichment/'
    vulnrichmentURL = 'https://github.com/cisagov/vulnrichment'
    search_words = ['poc', 'active', 'yes', 'total']  # Replace with the words you want to search for
    clearPath(destination)
    cloneRepo(vulnrichmentURL, destination)

    json_count, files_with_word_count = count_json_files_and_search_terms(destination, search_words)
    print(f'Total JSON files in the repository: {json_count}')
    print(f'Number of JSON files containing at least one of the words {search_words}: {files_with_word_count}')

    singleSearch = 'poc'
    jsonSearch = count_specific_search(destination, singleSearch)
    print(f'PoC: {jsonSearch}')
    
    singleSearch = 'active'
    jsonSearch = count_specific_search(destination, singleSearch)
    print(f'Active: {jsonSearch}')

    singleSearch = 'kev'
    jsonSearch = count_specific_search(destination, singleSearch)
    print(f'KEV: {jsonSearch}')

    singleSearch = 'yes'
    jsonSearch = count_specific_search(destination, singleSearch)
    print(f'Automatable: {jsonSearch}')

    singleSearch = 'total'
    jsonSearch = count_specific_search(destination, singleSearch)
    print(f'Total Impact: {jsonSearch}')

if __name__ == "__main__":
    main()





