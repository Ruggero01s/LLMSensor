import pandas as pd
import os
import random

SEARCH_ROOT = "./IOT_Flow"
OUTPUT_DIR = "./collected_flows"

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
    
    
def prepare_batches(num_batches, batch_size, benign_percentage):
    batches = []
    flows_files = [f for f in os.listdir(OUTPUT_DIR) if f.endswith('.csv')]
    for i in range(num_batches):
        file = random.sample(flows_files)
        if not file.startswith("Benign"):
            benign_file = random.choice([f for f in flows_files if f.startswith("Benign")])
            benign_df = pd.read_csv(os.path.join(OUTPUT_DIR, benign_file))
            benign_df = benign_df.sample(frac=benign_percentage)
            df = pd.read_csv(os.path.join(OUTPUT_DIR, file[0]))
            df = pd.concat([df, benign_df], ignore_index=True)
        else:
            df = pd.read_csv(os.path.join(OUTPUT_DIR, file))
            df = df.sample(n=batch_size)
            print(df.to_json())
            

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
    navigate_directory(paths=paths,columns=cols)

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
