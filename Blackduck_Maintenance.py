import requests
import re

# API KeyKey
bd_api_key = 'token XXXXXXXXXXXXXXXXXXXXXXXXXXX'

# Connect to Blackduck via API key and get the bearer token
bd_url = 'https://demo.yourblackducksite.com/api/tokens/authenticate'
headers = {'Authorization': bd_api_key}
bdresponse = requests.post(bd_url, headers=headers)

if bdresponse.status_code == 200:
    blackduck_response = bdresponse.text
    print(blackduck_response)
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

    
    # Step 4: Delete Multiple Versions associated with each project and ONLY Retain the latest
    project_index_number = 0
    while project_index_number < (len(project_names)):
        # get project_id_number
        project_name_id = (re.findall(r'.*/(.*)', str(project_names[int(project_index_number)][1]), re.M))
        # Step 4: Make API call to get Project versions
        version_url = str(project_names[int(project_index_number)][1]) + '/versions'
        version_response = requests.get(version_url, headers=headers_2)
        total_versions_count=(re.findall(r'"totalCount":(\d+)', str(version_response.text), re.M))
       
        if (int(total_versions_count[0]) > 1):
            print((project_names[project_index_number][0])+ ': Total versions are ' +total_versions_count[0])
            print ("\n")
            version_details = ()
            version_details = (re.findall(r'"createdAt":"(.*?)".*?"versionName":"(.*?)".*?"href":"(.*?)"', str(version_response.text), re.M))

            counter = 0
            while counter < (int(total_versions_count[0]) - 1):
                
                delete_response = requests.delete(version_details[counter][2], headers=headers_2)
                counter = counter + 1
                
        project_index_number = project_index_number + 1


    # Step 5: Delete Unmapped Projects
    code_location_url = 'https://demo.yourblackducksite.com/api/codelocations?offset=0&limit=1000&sort=updatedAt%20DESC&includeErrors=true'
    code_location_response = requests.get(code_location_url, headers=headers_2)
    
    code_locations = ()
    code_locations = (re.findall(r'\{"totalCount":\d+,"items":\[(.*?)\],"appliedFilters":.*\}', str(code_location_response.text), re.M))
    
    unique_code_locations = (re.findall(r'\{.*?Z"\}\]\}', str(code_locations[0]), re.M))

    counter2 = 0
    while (counter2 < len(unique_code_locations)):
        mapped = (re.search(r'mappedProjectVersion', str(unique_code_locations[counter2]), re.M))
        if (mapped):
            print ("Skipping the project")
        else:
            hrefurl = (re.findall(r'"href":"(.*?)","links".*', str(unique_code_locations[counter2]), re.M))
            print ("Deleting a Unmapped Project")
            delete_response = requests.delete(hrefurl[0], headers=headers_2)
        
        counter2 = counter2 + 1
