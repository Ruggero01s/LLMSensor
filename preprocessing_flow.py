import pandas as pd
import os
import random
import json
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
        print(labels)
        labels = list(set(labels))
        labels.remove("BenignTraffic")
        print(labels)
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
    
    
def prepare_batches_flow(num_batches, batch_size, max_benign_percentage=0.9):
    batches = []
    flows_files = [f for f in os.listdir(OUTPUT_DIR) if f.endswith('.csv')]
    for i in range(num_batches):
        #randomize benign percentage
        benign_percentage = random.uniform(0, max_benign_percentage)  # Randomly choose a percentage between 10% and 90%
        file = random.choice(flows_files)
        if file.startswith("Benign"):
            df = pd.read_csv(os.path.join(OUTPUT_DIR, file))
            df = df.sample(n=batch_size)
        else:
            benign_df = pd.read_csv(BENIGN_FILE)
            benign_sample_size = int(batch_size * benign_percentage)
            attack_sample_size = batch_size - benign_sample_size
            
            benign_sample = benign_df.sample(n=benign_sample_size)
            attack_sample = pd.read_csv(os.path.join(OUTPUT_DIR, file)).sample(n=attack_sample_size)
            
        # Concatenate benign and attack samples
            df = pd.concat([benign_sample, attack_sample], ignore_index=True)
            df = df.sample(frac=1).reset_index(drop=True)  # Shuffle the DataFrame

        
        temp_batch_string = df.to_json(orient='records', lines=True)
        temp_batch_lines = temp_batch_string.split('\n')
        temp_batch_lines = temp_batch_lines[:-1]
        temp_BatchFlow = BatchFlow(temp_batch_lines)
        df.drop(columns=['label'], inplace=True, errors='ignore')  # Drop label column if it exists
        batch_string = df.to_json(orient='records', lines=True)
        batch_lines = batch_string.split('\n')
        batch_lines = batch_lines[:-1]
        batches.append(BatchFlow(batch_lines, temp_BatchFlow.labels))
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
    #navigate_directory(paths=paths,columns=cols)
    batches = prepare_batches_flow(num_batches=10, batch_size=20, max_benign_percentage=0.7)
    for i, batch in enumerate(batches):
        print(batch)
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
