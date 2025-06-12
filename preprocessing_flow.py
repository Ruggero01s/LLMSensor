import pandas as pd
import os
import random
import json
import pickle
SEARCH_ROOT = "./IOT_Flow"
OUTPUT_DIR = "./collected_flows"
BENIGN_FILE =f"{OUTPUT_DIR}/BenignTraffic.csv"


class BatchFlow:
    def __init__(self, json_lines, labels=[]):
        self.lines = json_lines
        if labels:
            self.labels = labels
        else:
            self.labels = self.extract_labels()

    def __repr__(self):
        string = f"Batch:\n\tLabels: {self.labels}\n\tLines:\n"
        for line in self.lines:
            string += f"\t\t{line}\n"
        return string.strip()  # Remove trailing newline for cleaner output
        
    def __str__(self):
        string = f"Batch:\n\tLabels: {self.labels}\n\tLines:\n"
        for line in self.lines:
            string += f"\t\t{line}\n"
        return string.strip() 

    def get_batch_as_string(self):
        return ''.join(self.lines)

    def extract_labels(self):
        labels = []
        for line in self.lines:
            try:
                json_line = json.loads(line)
                if "label" in json_line:
                    labels.append(json_line["label"])
            except json.JSONDecodeError:
                print(f"Error decoding JSON from line: {line}")
        # print(labels)
        labels = list(set(labels))
        if "BenignTraffic" in labels:
            labels.remove("BenignTraffic")
            # print("Removed 'BenignTraffic' from labels")
        return labels
            


def read_csv(file, columns):
    df = pd.read_csv(file, usecols=columns)
    return df     
    
    
def navigate_directory(paths,columns):
    for path in paths:
        path=os.path.join(SEARCH_ROOT, path)
        label=os.path.basename(path)
        label= label.split(".")[0]
        df=read_csv(path, columns)
        df=df.assign(label=label)
        df.to_csv(os.path.join(OUTPUT_DIR, label+".csv"), index=False)
    
    
def prepare_batches_flow(num_batches, batch_size, max_benign_percentage=0.4):
    batches = []
    flows_files = [f for f in os.listdir(OUTPUT_DIR) if (f.endswith('.csv') and f != "BenignTraffic.csv")]
    
    batches_per_task = num_batches // len(flows_files)
    
    benign_df = pd.read_csv(BENIGN_FILE)

    for file in flows_files:
        attack_df = pd.read_csv(os.path.join(OUTPUT_DIR, file))

        for i in range(batches_per_task):
            benign_percentage = random.uniform(0, max_benign_percentage)
            benign_sample_size = int(batch_size * benign_percentage)
            attack_sample_size = batch_size - benign_sample_size
            
            benign_sample = benign_df.sample(n=benign_sample_size)
            attack_start_idx = attack_df.sample(n=1).index[0]
            attack_sample = attack_df.iloc[attack_start_idx:attack_start_idx + attack_sample_size]
            for record in benign_sample.to_dict(orient='records'):
                random_row = random.randint(0,len(attack_sample)+1)
                record = pd.DataFrame([record])
                attack_sample = pd.concat([attack_sample.iloc[:random_row], record, attack_sample.iloc[random_row:]]).reset_index(drop=True)
            
            attack_sample.reset_index(drop=True)
            
            #todo commentare questo scempio
            temp_batch_string = attack_sample.to_json(orient='records', lines=True)
            temp_batch_lines = temp_batch_string.split('\n')
            temp_batch_lines = temp_batch_lines[:-1]
            temp_BatchFlow = BatchFlow(temp_batch_lines)
            attack_sample.drop(columns=['label'], inplace=True, errors='ignore')  # Drop label column if it exists
            batch_string = attack_sample.to_json(orient='records', lines=True)
            batch_lines = batch_string.split('\n')
            batch_lines = batch_lines[:-1]
            batches.append(BatchFlow(batch_lines, temp_BatchFlow.labels))
            
    for i in range(batches_per_task):
        benign_start_idx = benign_df.sample(n=1).index[0]
        benign_sample = benign_df.iloc[benign_start_idx:benign_start_idx + batch_size]
        benign_sample.reset_index(drop=True, inplace=True)
        
        temp_batch_string = benign_sample.to_json(orient='records', lines=True)
        temp_batch_lines = temp_batch_string.split('\n')
        temp_batch_lines = temp_batch_lines[:-1]
        temp_BatchFlow = BatchFlow(temp_batch_lines)
        benign_sample.drop(columns=['label'], inplace=True, errors='ignore')  # Drop label column if it exists
        batch_string = benign_sample.to_json(orient='records', lines=True)
        batch_lines = batch_string.split('\n')
        batch_lines = batch_lines[:-1]
        batches.append(BatchFlow(batch_lines, temp_BatchFlow.labels))
    
    
    pickle.dump(batches, open(os.path.join("pickled_batches_flow", "batches_flow.pkl"), "wb"))
    return batches

if __name__ == "__main__":
    cols = ["Src IP","Src Port","Dst IP","Dst Port","Protocol",
            "Packet Length Mean", "Packet Length Std", "Flow Bytes/s", "Flow Packets/s",
            "Flow IAT Mean", "Flow IAT Std", "SYN Flag Count", "RST Flag Count", 
            "Down/Up Ratio", "Idle Mean"]
    
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
    
    num_batches = 1000
    max_batch_size = 20
    max_benign_percentage = 0.4
    #navigate_directory(paths=paths,columns=cols)
    batches = prepare_batches_flow(num_batches=num_batches, batch_size=max_batch_size, max_benign_percentage=max_benign_percentage)
    # for i, batch in enumerate(batches):
    #     print(batch)
#due modi, o si mischia nei file di attacco delle linee di benign, oppure si prende una batch intera da un file cambiando file ogni batch
#meccanismo per la scelta del file
#se benign, allora prendi solo quello
# se uno degli attacchi allora mischia dentro benign con probabilità, quanto della batch deve essere benign e quanto originale

# Packet Length Mean
# Packet Length Std
# Flow Bytes/s
# Flow Packets/s
# Flow IAT Mean
# Flow IAT Std
# SYN Flag Count
# RST Flag Count
# Down/Up Ratio
# Idle Mean
