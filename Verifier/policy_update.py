import json
from config import *

def update_sgx_policy(file_path, new_mrenclave, new_mrsigner):

    #  Updates the sgx_mrenclave and sgx_mrsigner values in an SGX policy JSON file.

    try:
        with open(file_path, 'r') as f:
            policy_data = json.load(f)
        if 'policy_array' in policy_data and len(policy_data['policy_array']) > 0:
            if 'reference' in policy_data['policy_array'][0]:
                policy_data['policy_array'][0]['reference']['sgx_mrenclave'] = new_mrenclave
                policy_data['policy_array'][0]['reference']['sgx_mrsigner'] = new_mrsigner
                # # Important: Remove the '#' prefix from the keys if they exist
                # # This makes the values "take effect" as per the JSON comment
                # if '#sgx_mrenclave' in policy_data['policy_array'][0]['reference']:
                #     policy_data['policy_array'][0]['reference']['sgx_mrenclave'] = policy_data['policy_array'][0]['reference'].pop('#sgx_mrenclave')
                # if '#sgx_mrsigner' in policy_data['policy_array'][0]['reference']:
                #     policy_data['policy_array'][0]['reference']['sgx_mrsigner'] = policy_data['policy_array'][0]['reference'].pop('#sgx_mrsigner')

        with open(file_path, 'w') as f:
            json.dump(policy_data, f, indent=4) 
        print(f"Policy file '{file_path}' updated successfully.")

    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON format in '{file_path}'.")
    except KeyError as e:
        print(f"Error: Missing key in JSON structure: {e}.")

policy_file = './QuoteAppraisal/Policies/sgx_enclave_policy.json' 

update_sgx_policy(policy_file, mrenclave_reference, mrsigner_reference)
