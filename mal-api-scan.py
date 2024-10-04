import pefile
import sys
import os
import argparse
from prettytable import PrettyTable
import csv
import cxxfilt  # For demangling C++ names
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Constant for API categories
API_CATEGORIES = [
    "Enumeration", "Injection", "Evasion", "Spying",
    "Internet", "Anti-Debugging", "Ransomware", "Helper"
]

def load_suspicious_apis():
    """
    Load suspicious APIs from category files into a dictionary.

    Returns:
        dict: A dictionary mapping category names to lists of APIs.
    """
    suspicious_apis = {}
    for category in API_CATEGORIES:
        filename = f"{category.lower()}.txt"
        if os.path.exists(filename):
            with open(filename, 'r') as file:
                apis = [line.strip() for line in file if line.strip() and not line.strip().startswith('#')]
                suspicious_apis[category] = apis
        else:
            print(Fore.YELLOW + f"Warning: API definition file '{filename}' not found.")
    return suspicious_apis

def list_imported_apis(file_path, suspicious_apis, analyzed_files=None, depth=0, caller_chain=None):
    """
    Analyze a PE file and list its imported APIs.

    Args:
        file_path (str): Path to the PE file.
        suspicious_apis (dict): Dictionary of suspicious APIs.
        analyzed_files (set, optional): Set of already analyzed files.
        depth (int, optional): Current depth of analysis.
        caller_chain (list, optional): Call chain for API calls.

    Returns:
        list: List of imported APIs along with their details.
    """
    if analyzed_files is None:
        analyzed_files = set()
    
    if caller_chain is None:
        caller_chain = []
    
    if file_path in analyzed_files:
        return []
    
    analyzed_files.add(file_path)
    results = []
    
    try:
        pe = pefile.PE(file_path)
        current_module = os.path.basename(file_path)
        current_chain = caller_chain + [current_module]
        
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode()
                for imp in entry.imports:
                    api_name = imp.name.decode() if imp.name else f"Ordinal {imp.ordinal}"
                    
                    # Demangle if it's a mangled name
                    try:
                        api_name = cxxfilt.demangle(api_name)
                    except Exception:
                        pass  # If demangling fails, keep the original name
                    
                    category = check_if_suspicious(api_name, suspicious_apis)
                    
                    # Create the chain representation
                    chain_representation = " -> ".join(current_chain + [f"{dll_name}:{api_name}"])
                    
                    results.append([current_module, dll_name, api_name, depth, category, chain_representation])
                
                # Recursively analyze the imported DLL
                dll_path = find_dll(dll_name)
                if dll_path:
                    new_results = list_imported_apis(dll_path, suspicious_apis, analyzed_files, depth + 1, current_chain)
                    results.extend(new_results)
        
    except pefile.PEFormatError:
        print(Fore.RED + f"Error: {file_path} is not a valid PE file.")
    except FileNotFoundError:
        print(Fore.RED + f"Error: File {file_path} not found.")
    except Exception as e:
        print(Fore.RED + f"An error occurred while analyzing {file_path}: {str(e)}")
    
    return results

def find_dll(dll_name):
    """
    Find the full path of a DLL in the system directories.

    Args:
        dll_name (str): Name of the DLL.

    Returns:
        str: Full path to the DLL if found, otherwise None.
    """
    system32_path = os.path.join(os.environ['SystemRoot'], 'System32', dll_name)
    if os.path.exists(system32_path):
        return system32_path
    
    syswow64_path = os.path.join(os.environ['SystemRoot'], 'SysWOW64', dll_name)
    if os.path.exists(syswow64_path):
        return syswow64_path
    
    return None

def check_if_suspicious(api_name, suspicious_apis):
    """
    Check if an API call is suspicious.

    Args:
        api_name (str): Name of the API call.
        suspicious_apis (dict): Dictionary of suspicious APIs.

    Returns:
        str: Category of the API if suspicious, otherwise "Normal".
    """
    for category, apis in suspicious_apis.items():
        if api_name in apis:
            return category
    return "Normal"

def create_table(data, show_depth=True):
    """
    Create a PrettyTable from the given data.

    Args:
        data (list): List of rows to include in the table.
        show_depth (bool): Whether to show the depth column.

    Returns:
        PrettyTable: Formatted table of data.
    """
    table = PrettyTable()

    # Set field names based on whether we want to show depth or not
    if show_depth:
        table.field_names = ["File", "Imported DLL", "API Call", "Depth", "Category", "Caller Chain"]
    else:
        table.field_names = ["File", "Imported DLL", "API Call", "Category", "Caller Chain"]

    table.align["File"] = "l"
    table.align["Imported DLL"] = "l"
    table.align["API Call"] = "l"
    if show_depth:
        table.align["Depth"] = "r"
    table.align["Category"] = "l"
    table.align["Caller Chain"] = "l"

    for row in data:
        # Adding the link for the API Call
        api_name = row[2]
        malapi_link = f"https://malapi.io/winapi/{api_name}"
        if show_depth:
            table.add_row([row[0], row[1], f"{api_name} ({malapi_link})", row[3], row[4], row[5]])
        else:
            table.add_row([row[0], row[1], f"{api_name} ({malapi_link})", row[4], row[5]])

    return table

def save_to_csv(results, filename):
    """
    Save the analysis results to a CSV file with improved readability.

    Args:
        results (list): Analysis results to save.
        filename (str): Name of the CSV file to save to.
    """
    with open(filename, mode='w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile, quoting=csv.QUOTE_NONNUMERIC)
        
        # Writing a header row with description
        writer.writerow(["# Analysis of API Calls", "", "", "", "", ""])
        writer.writerow(["File", "Imported DLL", "API Call", "Depth", "Category", "Caller Chain"])
        
        for row in results:
            # Clean and format the API Call
            api_name = row[2].strip() if row[2] else "N/A"
            dll_name = row[1].strip() if row[1] else "N/A"
            file_name = row[0].strip() if row[0] else "N/A"
            category = row[4].strip() if row[4] else "Normal"
            caller_chain = row[5].strip() if row[5] else "N/A"
            depth = row[3] if isinstance(row[3], int) else 0
            
            # Write the formatted row
            writer.writerow([file_name, dll_name, f"{api_name} ({'https://malapi.io/winapi/' + api_name})", depth, category, caller_chain])

def main():
    """
    Main function to parse arguments, load suspicious APIs, and analyze the specified executable.
    """
    parser = argparse.ArgumentParser(description="Analyze API calls in an executable file.")
    parser.add_argument("exe_path", help="Path to the executable file to analyze.")
    parser.add_argument("-s", "--suspicious", action="store_true", help="Show only suspicious API calls with depth 0.")
    parser.add_argument("-r", "--recursive", action="store_true", help="Show all suspicious API calls recursively.")
    parser.add_argument("-o", "--output", help="Output CSV file name.")

    args = parser.parse_args()

    # Validate the presence of at least one of the -s or -r options
    if not (args.suspicious or args.recursive):
        print(Fore.RED + "Error: At least one of the -s (suspicious) or -r (recursive) options must be specified.")
        sys.exit(1)  # Exit with error status

    # Validate output option
    if args.output and not (args.suspicious or args.recursive):
        print(Fore.RED + "Error: The -o option requires -s (suspicious) or -r (recursive) to be specified.")
        sys.exit(1)  # Exit with error status

    print(Fore.GREEN + f"Analyzing file: {args.exe_path}")
    suspicious_apis = load_suspicious_apis()
    total_suspicious_apis = sum(len(apis) for apis in suspicious_apis.values())
    print(Fore.GREEN + f"Successfully loaded a total of {total_suspicious_apis:,} suspicious APIs from the defined categories.")
    
    # Analyze the file
    results = list_imported_apis(args.exe_path, suspicious_apis)
    print(Fore.GREEN + f"Found {len(results)} total API calls.")

    suspicious_results = [r for r in results if r[4] != "Normal"]
    print(Fore.GREEN + f"Found {len(suspicious_results)} suspicious API calls.")

    # Prepare for saving to CSV based on flags
    table = None
    depth_zero_results = []

    if results:
        if args.recursive:
            # Filter only suspicious calls
            table = create_table(suspicious_results)
            print(Fore.YELLOW + "\nSuspicious API Calls (Recursive):")
            print(table)
        
        if args.suspicious:
            # Filter only depth 0 suspicious calls
            depth_zero_results = [r for r in suspicious_results if r[3] == 0]
            table = create_table(depth_zero_results, show_depth=False)  # Hide depth column
            print(Fore.YELLOW + "\nSuspicious API Calls (Depth 0 only):")
            print(table)

        # Save appropriate results based on flags
        if args.output:
            # Save to CSV
            if args.recursive:
                save_to_csv(suspicious_results, args.output)
            elif args.suspicious:
                save_to_csv(depth_zero_results, args.output)

            print(Fore.GREEN + f"Results saved to {args.output}.")
    else:
        print(Fore.RED + "No API calls found at all. This is unexpected and may indicate an error.")

    print(Fore.GREEN + "\nAnalysis complete.")

if __name__ == "__main__":
    main()
