import requests
import json
import re
import os
from datetime import date
import pandas as pd
from requests.exceptions import Timeout

# API Key
bd_api_key = 'token XXXXXXXXXXXXXXXXXXXXXXX'

# Connect to Blackduck via API key and get the bearer token
bd_url = 'https://demo.yourblackducksite.com/api/tokens/authenticate'
headers = {'Authorization': bd_api_key}
bdresponse = requests.post(bd_url, headers=headers)

# Variables
current_year = date.today().year
year_past_3 = current_year - 3
unique_component_versions = []
fiveYear_component_versions = []
high_comp_risk_details = []
medium_comp_risk_details = []
low_comp_risk_details = []

# Code
if bdresponse.status_code == 200:
    blackduck_response = bdresponse.text
    # print (blackduck_response)
    print("\nBlackduck is up and running! You have been authenticated via your API key.\n")

    # Step 1: Capture Bearer token for further requests
    bearertk = re.findall('\{"bearerToken":"(.*?)".*', blackduck_response)

    # Step 2: Form Authorization header with bearer token
    bd_bearer_token = 'Bearer ' + str(''.join(bearertk))
    headers_2 = {'Authorization': bd_bearer_token}

    # Step 3: Make API call with bearer token and fetch project ID and version ID
    project_url = 'https://demo.yourblackducksite.com/api/projects/?limit=5000'
    project_response = requests.get(project_url, headers=headers_2)
    project_names = ()
    project_names = (re.findall(r'"name":"(.*?)".*?"href":"(.*?)"', str(project_response.text), re.M))

    counter = 0
    while counter < (len(project_names)):
        print(str(counter) + ': ' + (project_names[counter][0]))
        counter = counter + 1

    project_index_number = input("\nPlease enter Project Number: ")
    print("\n")
    print("Starting analysis for the application : " + str(project_names[int(project_index_number)]))
    print("\n")
    # get project_id_number
    project_name_id = (re.findall(r'.*/(.*)', str(project_names[int(project_index_number)][1]), re.M))

    # Step 3: Make API call to get Project versions
    version_url = str(project_names[int(project_index_number)][1]) + '/versions'
    version_response = requests.get(version_url, headers=headers_2)
    version_names = ()
    version_names = (
        re.findall(r'.*"createdAt":"(.*?)".*?"versionName":"(.*?)".*?"href":"(.*?)"', str(version_response.text), re.M))
    print("Selected Application Code Release Version : " + str(version_names[0][1]) + ", Scan Date: " + str(
        version_names[0][0]))
    print("\n")
    project_version_id = re.findall(r'.*/(.*)', version_names[0][2], re.M)

    bd_project_id = str(project_name_id[0])
    bd_project_version_id = str(project_version_id[0])

    bom_url = 'https://demo.yourblackducksite.com/api/v1/releases/' + bd_project_version_id + '/component-bom-entries?limit=5000'

    # Step 3: Make API call with bearer token
    bom_url_response = requests.get(bom_url, headers=headers_2)
    fh = open("bom.txt", "w")
    fh.write(bom_url_response.text)
    fh.close()

    fh = open("bom.txt")
    bom_content = fh.read()
    fh.close()

    # bom_components=[]
    bom_components = ()
    direct_bom_components = []

    # Multiple Occurances..
    bom_components = (re.findall(
        r'"(projectId)":"(.*?)".*?"(projectName)":"(.*?)".*?"(releaseId)":"(.*?)".*?"(releaseVersion)":"(.*?)".*?"(usages)":\["(.*?)"\].*?"(matchTypes)":\["(.*?)"\]',
        bom_content, re.M))

    counter_1 = 0
    while counter_1 < (len(bom_components)):
        if (bom_components[counter_1][11] != 'FILE_DEPENDENCY_TRANSITIVE'):
            direct_bom_components.append(bom_components[counter_1])
        counter_1 = counter_1 + 1

    # print(direct_bom_components)

    unique_components = []
    component_version = ""
    counter_2 = 0
    unique_components.append(direct_bom_components[counter_2])

    while counter_2 < len(direct_bom_components):
        component_version = direct_bom_components[counter_2][1]
        counter_3 = 0
        match_found = 0
        while counter_3 < len(unique_components):
            if (component_version == unique_components[counter_3][1]):
                match_found += 1
            counter_3 = counter_3 + 1
        if match_found == 0:
            unique_components.append(direct_bom_components[counter_2])
        counter_2 = counter_2 + 1

    # print(unique_components)
    unique_components_dict = {}
    # print(type(unique_components_dict))
    fh = open("unique_direct_components.txt", "w")
    counter_4 = 0
    while counter_4 < len(unique_components):
        fh.write(unique_components[counter_4][1] + "\n")
        unique_components_dict[unique_components[counter_4][1]] = unique_components[counter_4][3]
        counter_4 += 1
    fh.close()

    # print(unique_components_dict)

    unique_componentID = set(open("unique_direct_components.txt").readlines())
    # print(unique_componentID)
    # print(unique_components_array)

    from openpyxl import Workbook

    wb = Workbook()
    ws = wb.active
    ws.append(
        ['APPLICATION NAME', 'COMPONENT NAME', 'VULN HIGH', 'VULN MEDIUM', 'VULN LOW'])

    # Iterate through components and capture all their versions
    print("Start ->")
    for component in (unique_componentID):
        print("--------------------------------------------------------")
        print('Step 1. Getting all versions associated with the component - ' + unique_components_dict[
            component.rstrip()])
        componentRISKurl = 'https://demo.yourblackducksite.com/api/components/' + component.rstrip() + '/versions?offset=0&limit=1000&sort=releasedOn%20DESC'
        try:
            bom_url_response_2 = requests.get(componentRISKurl, headers=headers_2, timeout=30.00)
        except Timeout:
            ws.append(
                [str(project_names[int(project_index_number)][0]), unique_components_dict[component.rstrip()],
                 'Unknown',
                 'Unknown', 'Unknown'
                 ])
        else:
            file_name = 'comp_versions.txt'
            fh = open(file_name, "w")
            fh.write(bom_url_response_2.text)
            fh.close()

            # Read content
            fh = open(file_name)
            bom_content_2 = fh.read()
            fh.close()

            component_versions = []
            unique_component_versions = []
            fiveYear_component_versions = []
            test = []
            high_comp_risk_details = []
            medium_comp_risk_details = []
            low_comp_risk_details = []

            # Capture Multiple Occurances..
            component_versions = (re.findall(r'.*"items":\[({.*?})\],"appliedFilters".*', bom_content_2, re.M))
            unique_component_versions = (re.findall(r'{.*?}]}}', component_versions[0]))

            # Iterate through versions and ignore components 3 years older
            print('Step 2. Selecting versions of last 3 years ONLY')
            for versions in (unique_component_versions):
                releaseYear = (re.findall(r'.*"releasedOn":"(.*?)-.*', versions))
                if (int(releaseYear[0]) > year_past_3):
                    test = (re.findall(r'"versionName":"(.*?)","releasedOn":"(.*?)".*?"risk-profile".*?"href":"(.*?)"',
                                       versions, re.M))
                    fiveYear_component_versions.append(test)
            # print(fiveYear_component_versions)

            # Gather Risk for each component
            print('Step 3. Gathering Risk for each of component versions')
            for a in fiveYear_component_versions:
                print("Selected Version for Analysis : " + str(a[0][0]))
                comp_risk_url = (a[0][2])
                comp_risk_url_response = requests.get(comp_risk_url, headers=headers_2)
                comp_high_risk = (re.findall(r'.*"HIGH","count":(.*?)}.*', comp_risk_url_response.text))
                high_comp_risk_details.append(int(comp_high_risk[0]))
                comp_medium_risk = (re.findall(r'.*"MEDIUM","count":(.*?)}.*', comp_risk_url_response.text))
                medium_comp_risk_details.append(int(comp_medium_risk[0]))
                comp_low_risk = (re.findall(r'.*"LOW","count":(.*?)}.*', comp_risk_url_response.text))
                low_comp_risk_details.append(int(comp_low_risk[0]))

            print("End")

            ws.append(
                [str(project_names[int(project_index_number)][0]), unique_components_dict[component.rstrip()],
                 sum(high_comp_risk_details),
                 sum(medium_comp_risk_details), sum(low_comp_risk_details)
                 ])
    print("--------------------------------------------------------")
    print("Step 4. Generating Excel Report")
    print("--------------------------------------------------------")
    excel_name = str(project_names[int(project_index_number)][0]) + '_Component_Risk_Report.xlsx'
    wb.save(excel_name)
    backup = "bak_" + excel_name
    wb.save(backup)
    os.remove("bom.txt")
    os.remove("comp_versions.txt")
    os.remove("unique_direct_components.txt")

    # Excel Data Sorting via PANDAS module
    df = pd.read_excel(excel_name, sheet_name='Sheet')
    sorted_by_values = df.sort_values(['VULN HIGH', 'VULN MEDIUM', 'VULN LOW'], ascending=False)
    app_report_name = str(project_names[int(project_index_number)][0]) + '_Component_Risk_Stat_Report.xlsx'
    sorted_by_values.to_excel(app_report_name, sheet_name='Blackduck Results')
    os.remove(excel_name)

else:
    print(bdresponse.text)
    print("Error! Check your API Key and please try again later..")
    exit()
