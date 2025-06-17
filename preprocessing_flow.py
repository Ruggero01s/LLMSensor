import pandas as pd                 # For DataFrame operations on CSV files
import os                           # For file and directory operations
import random                       # For generating random numbers for batch sampling
import json                         # For JSON parsing of flow lines
import pickle                       # For serializing batches to a file

# Constants and configuration paths
SEARCH_ROOT = "./IOT_Flow"           # Directory containing original flow CSV files
OUTPUT_DIR = "./collected_flows"     # Directory to store processed CSV flows
BENIGN_FILE = f"{OUTPUT_DIR}/BenignTraffic.csv"  # CSV file containing benign traffic flows


class BatchFlow:
    def __init__(self, json_lines, labels=[]):
        # Initialize a flow batch with JSON lines and optionally provided labels
        self.lines = json_lines
        if labels:
            self.labels = labels
        else:
            self.labels = self.extract_labels()

    def __repr__(self):
        # Return a detailed string representation of the BatchFlow
        string = f"Batch:\n\tLabels: {self.labels}\n\tLines:\n"
        for line in self.lines:
            string += f"\t\t{line}\n"
        return string.strip()  # Remove trailing newline for cleaner output
        
    def __str__(self):
        # String conversion is the same as the detailed representation
        string = f"Batch:\n\tLabels: {self.labels}\n\tLines:\n"
        for line in self.lines:
            string += f"\t\t{line}\n"
        return string.strip()

    def get_batch_as_string(self):
        # Concatenates all JSON lines into a single string
        return ''.join(self.lines)

    def extract_labels(self):
        # Extract unique labels from the contained JSON lines
        labels = []
        for line in self.lines:
            try:
                json_line = json.loads(line)
                if "label" in json_line:
                    labels.append(json_line["label"])
            except json.JSONDecodeError:
                raise json.JSONDecodeError
        # Remove duplicate labels
        labels = list(set(labels))
        if "BenignTraffic" in labels:
            labels.remove("BenignTraffic")  # Exclude 'BenignTraffic' from the labels list, benign sample are expected to not have labels
        return labels
            

def read_csv(file, columns):
    # Read a CSV file using only the specified columns and return a DataFrame
    df = pd.read_csv(file, usecols=columns)
    return df     
    
    
def navigate_directory(paths, columns):
    # Process each file in paths:
    #  - Build an absolute path based on SEARCH_ROOT
    #  - Extract a label from the filename
    #  - Read the CSV and assign the extracted label as a new column
    #  - Write the updated DataFrame to OUTPUT_DIR
    for path in paths:
        path = os.path.join(SEARCH_ROOT, path)
        label = os.path.basename(path)
        label = label.split(".")[0]  # Assumes filename structure: label.something
        df = read_csv(path, columns)
        df = df.assign(label=label)
        df.to_csv(os.path.join(OUTPUT_DIR, label + ".csv"), index=False)
    
    
def prepare_batches_flow(num_batches, batch_size, max_benign_percentage=0.4):
    # Prepares flow batches from attack files and benign flows
    batches = []
    # List all CSV files in OUTPUT_DIR except the benign flows file
    flows_files = [f for f in os.listdir(OUTPUT_DIR) if (f.endswith('.csv') and f != "BenignTraffic.csv")]
    
    batches_benign = round(num_batches / 2)
    
    # Determine how many batches to create per file
    batches_per_task = (num_batches - batches_benign) // len(flows_files)
    
    
    # Read the benign flows CSV file into a DataFrame
    benign_df = pd.read_csv(BENIGN_FILE)

    # Process each attack file to construct batches mixing attack and benign flows
    for file in flows_files:
        attack_df = pd.read_csv(os.path.join(OUTPUT_DIR, file))

        for i in range(batches_per_task):
            # Determine a random benign percentage for the current batch up to the allowed maximum
            benign_percentage = random.uniform(0, max_benign_percentage)
            benign_sample_size = int(batch_size * benign_percentage)
            attack_sample_size = batch_size - benign_sample_size
            
            # Sample benign flows and attack flows
            benign_sample = benign_df.sample(n=benign_sample_size)
            attack_start_idx = attack_df.sample(n=1).index[0]  # Randomly choose a starting index for attack flows
            attack_sample = attack_df.iloc[attack_start_idx:attack_start_idx + attack_sample_size] # take the next lines as sample
            
            # Merge benign sample into attack sample at random positions
            for record in benign_sample.to_dict(orient='records'):
                random_row = random.randint(0, len(attack_sample) + 1)
                record = pd.DataFrame([record])
                # Insert benign record into attack_sample DataFrame at a random row
                attack_sample = pd.concat([attack_sample.iloc[:random_row], record, attack_sample.iloc[random_row:]]).reset_index(drop=True)
            
            attack_sample.reset_index(drop=True)  # resetting index without assignment might be redundant
            
            # Convert the attack_sample DataFrame to JSON lines (excluding the last empty line)
            # we build a ""fake" batch to take the labels 
            temp_batch_string = attack_sample.to_json(orient='records', lines=True)
            temp_batch_lines = temp_batch_string.split('\n')
            temp_batch_lines = temp_batch_lines[:-1]
            temp_BatchFlow = BatchFlow(temp_batch_lines)
            
            # Remove the 'label' column if it exists in the DataFrame
            attack_sample.drop(columns=['label'], inplace=True, errors='ignore')
            
            # Convert the modified attack sample into JSON lines for the final batch
            batch_string = attack_sample.to_json(orient='records', lines=True)
            batch_lines = batch_string.split('\n')
            batch_lines = batch_lines[:-1]
            
            # Create a BatchFlow object with the produced JSON lines (without labels) and target labels
            batches.append(BatchFlow(batch_lines, temp_BatchFlow.labels))
            
    # Additionally, build batches solely from benign flows, same process as above
    for i in range(batches_benign):
        benign_start_idx = benign_df.sample(n=1).index[0]
        benign_sample = benign_df.iloc[benign_start_idx:benign_start_idx + batch_size]
        benign_sample.reset_index(drop=True, inplace=True)
        
        temp_batch_string = benign_sample.to_json(orient='records', lines=True)
        temp_batch_lines = temp_batch_string.split('\n')
        temp_batch_lines = temp_batch_lines[:-1]
        temp_BatchFlow = BatchFlow(temp_batch_lines)
        
        benign_sample.drop(columns=['label'], inplace=True, errors='ignore')
        batch_string = benign_sample.to_json(orient='records', lines=True)
        batch_lines = batch_string.split('\n')
        batch_lines = batch_lines[:-1]
        
        batches.append(BatchFlow(batch_lines, temp_BatchFlow.labels))
    
    # Save the batches to a pickle file for later use.
    pickle.dump(batches, open(os.path.join("pickled_batches_flow", "batches_flow.pkl"), "wb"))
    return batches

    
if __name__ == "__main__":
    # Define columns to be used when reading CSV files
    cols = [
        "Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol",
        "Packet Length Mean", "Packet Length Std", "Flow Bytes/s", "Flow Packets/s",
        "Flow IAT Mean", "Flow IAT Std", "SYN Flag Count", "RST Flag Count", 
        "Down/Up Ratio", "Idle Mean"
    ]
    
    # List of relative paths to flow CSV files grouped by attack or benign traffic
    paths = [
        "Benign/BenignTraffic.pcap_Flow.csv",
        "Benign/BenignTraffic1.pcap_Flow.csv",
        "Benign/BenignTraffic2.pcap_Flow.csv",
        "Benign/BenignTraffic3.pcap_Flow.csv",
        "DDOS/DDOS_HTTP_Flood/DDoS-HTTP_Flood-.pcap_Flow.csv",
        "DDOS/DDOS_ICMP_Fragmentation/DDoS-ICMP_Fragmentation.pcap_Flow.csv",
        "DDOS/DDOS_ICMP_Fragmentation/DDoS-ICMP_Fragmentation1.pcap_Flow.csv",
        "DDOS/DDOS_ICMP_Fragmentation/DDoS-ICMP_Fragmentation2.pcap_Flow.csv",
        "DDOS/DDOS_ICMP_Fragmentation/DDoS-ICMP_Fragmentation3.pcap_Flow.csv",
        "DDOS/DDOS_ICMP_Fragmentation/DDoS-ICMP_Fragmentation4.pcap_Flow.csv",
        "DDOS/DDOS_ICMP_Fragmentation/DDoS-ICMP_Fragmentation5.pcap_Flow.csv",
        "DDOS/DDOS_ICMP_Fragmentation/DDoS-ICMP_Fragmentation6.pcap_Flow.csv",
        "DDOS/DDOS_ICMP_Fragmentation/DDoS-ICMP_Fragmentation7.pcap_Flow.csv",
        "DDOS/DDOS_ICMP_Fragmentation/DDoS-ICMP_Fragmentation8.pcap_Flow.csv",
        "DDOS/DDOS_ICMP_Fragmentation/DDoS-ICMP_Fragmentation9.pcap_Flow.csv",
        "DDOS/DDOS_ICMP_Fragmentation/DDoS-ICMP_Fragmentation10.pcap_Flow.csv",
        "DDOS/DDOS_ICMP_Fragmentation/DDoS-ICMP_Fragmentation11.pcap_Flow.csv",
        "DDOS/DDOS_ICMP_Fragmentation/DDoS-ICMP_Fragmentation12.pcap_Flow.csv",
        "DDOS/DDOS_ICMP_Fragmentation/DDoS-ICMP_Fragmentation13.pcap_Flow.csv",
        "DDOS/DDOS_ICMP_Fragmentation/DDoS-ICMP_Fragmentation14.pcap_Flow.csv",
        "DDOS/DDOS_ICMP_Fragmentation/DDoS-ICMP_Fragmentation15.pcap_Flow.csv",
        "DDOS/DDOS_ICMP_Fragmentation/DDoS-ICMP_Fragmentation16.pcap_Flow.csv",
        "DDOS/DDOS_ICMP_Fragmentation/DDoS-ICMP_Fragmentation17.pcap_Flow.csv",
        "DDOS/DDOS_ICMP_Fragmentation/DDoS-ICMP_Fragmentation18.pcap_Flow.csv",
        "DDOS/DDOS_ICMP_Fragmentation/DDoS-ICMP_Fragmentation19.pcap_Flow.csv",
        "Dictionary_bruteforce/DictionaryBruteForce.pcap_Flow.csv",
        "DNS_spoof/DNS_Spoofing.pcap_Flow.csv",
        "SQL_injection/SqlInjection.pcap_Flow.csv",
        "XSS/XSS.pcap_Flow.csv"
    ]
    
    num_batches = 500          # Total number of batches to prepare
    max_batch_size = 20         # Maximum number of records in each batch
    max_benign_percentage = 0.4  # Maximum allowed percentage of benign flows in a batch
    
    # preprocess the CSV files and add a label column.
    # navigate_directory(paths=paths, columns=cols)
    
    # Prepare the batches and optionally print them for verification.
    batches = prepare_batches_flow(num_batches=num_batches, batch_size=max_batch_size, max_benign_percentage=max_benign_percentage)
    # for i, batch in enumerate(batches):
    #     print(batch)
    