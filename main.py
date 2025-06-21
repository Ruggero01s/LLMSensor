from datetime import timedelta, datetime
from preprocessing_russell import prepare_batches_russell, BatchRussell
from preprocessing_flow import prepare_batches_flow, BatchFlow
from model import model_call
import pickle
import json
import os
import time


def minute_range(start_datetime: datetime, end_datetime: datetime, step_minutes: int):
    total_minutes = int((end_datetime - start_datetime).total_seconds() / 60)
    for n in range(0, total_minutes + 1, step_minutes):
        yield start_datetime + timedelta(minutes=n)


def convert_to_bool(json_value):
    if isinstance(json_value,str):
        if json_value.lower().strip() in ["true"]:
            return True
        elif json_value.lower().strip() in ["false"]:
            return False
        else: 
            print("Errore nella conversione in bool")
            return -1
    return json_value        

def print_confusion_matrix(confusion_dict):
    #confusion_dict = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
    print("Confusion Matrix:")
    print("\tTP\tTN\tFP\tFN")
    print(f"\t{confusion_dict['TP']}\t{confusion_dict['TN']}\t{confusion_dict['FP']}\t{confusion_dict['FN']}")
    
def save_final_result(output_file, confusion_dict, confusion_dict_by_label,time_elapsed, batch_counter, malformed_counter, flagged_characters_percentage, model_name, system_prompt_main, system_prompt_rag="", multihost=True, rag_embedding=""):
    accuracy, precision, recall, f1 = calculate_metrics(confusion_dict=confusion_dict)
    str_to_write = (
        f"------------------------------\n"
        f"Confusion Matrix General:\n"
        f"TP\tTN\tFP\tFN\n"
        f"{confusion_dict['TP']}\t{confusion_dict['TN']}\t{confusion_dict['FP']}\t{confusion_dict['FN']}\n\n"
        f"------------------------------\n"
        )
    for label, conf_dict in confusion_dict_by_label.items():
        str_to_write += (
            f"Confusion Matrix for label {label}:\n"
            f"TP\tTN\tFP\tFN\n"
            f"{conf_dict['TP']}\t{conf_dict['TN']}\t{conf_dict['FP']}\t{conf_dict['FN']}\n\n"
            f"------------------------------\n"    
        )

    str_to_write += (
        f"Metrics General:\n"
        f"\tAccuracy: {accuracy}%\n"
        f"\tPrecision: {precision}%\n"
        f"\tRecall: {recall}%\n"
        f"\tF1: {f1}%\n"
        f"\tFlagged characters percentage: {flagged_characters_percentage}%\n\n"
        f"------------------------------\n"
        )
    for label, conf_dict in confusion_dict_by_label.items():
        accuracy_label, precision_label, recall_label, f1_label = calculate_metrics(confusion_dict=conf_dict)
        str_to_write += (
            f"Metrics for label {label}:\n"
            f"\tAccuracy: {accuracy_label}%\n"
            f"\tPrecision: {precision_label}%\n"
            f"\tRecall: {recall_label}%\n"
            f"\tF1: {f1_label}%\n\n"
        )
    str_to_write += (
        f"------------------------------\n"
        f"Time elapsed: {time_elapsed}\n"
        f"Batch processed: {batch_counter}\n"
        f"Malformed outputs: {malformed_counter}\n"
        f"------------------------------\n"
        f"Model: {model_name}\n"
        f"System prompt main: {system_prompt_main}\n"
        f"System prompt rag: {system_prompt_rag}\n"
        f"RAG embedding: {rag_embedding}\n"
    )
    if multihost:
        str_to_write += "Multihost: True\n------------------------------\n"
    else:
        str_to_write += "Multihost: False\n------------------------------\n"
    with open(output_file, "a") as out_file:
            out_file.write(str_to_write)

def check_model_output(batch, model_output):
    malicious = model_output.get("malicious")
    malicious = convert_to_bool(malicious)
    if malicious == -1:
        return -1
    if (batch.labels) and (malicious == True):
        return "TP"
    elif (not batch.labels) and (malicious == False):
        return "TN"
    elif (batch.labels) and (malicious == False):
        return "FN"
    else:
        return "FP"
        
def save_model_output(batch, model_output, out_path):
    with open(out_path, "a") as out_file:
        out_file.write(str(batch))
        out_file.write(f"\n{model_output}\n\n")
            
            
def calculate_metrics(confusion_dict):
    if (confusion_dict["TP"]+confusion_dict["TN"]+confusion_dict["FP"]+confusion_dict["FN"]) == 0:
        accuracy = -1
    else:
        accuracy = (confusion_dict["TP"]+confusion_dict["TN"])/(confusion_dict["TP"]+confusion_dict["TN"]+confusion_dict["FP"]+confusion_dict["FN"])
    if confusion_dict["TP"]+confusion_dict["FP"] == 0:
        precision = -1
    else:
        precision = confusion_dict["TP"]/(confusion_dict["TP"]+confusion_dict["FP"])
    if (confusion_dict["TP"]+confusion_dict["FN"]) == 0:
        recall = -1
    else:
        recall = confusion_dict["TP"]/(confusion_dict["TP"]+confusion_dict["FN"])
    if precision <= -1 or recall <= -1:
        f1 = -1
    else:
        f1=2*(precision*recall)/(precision+recall)
    
    return accuracy*100, precision*100, recall*100, f1*100

def calculate_character_counter(classification, batch):
    #todo should be done with model_output and not use the labels
    local_count=0
    flagged_character_count = 0
    for line in batch.lines:
        if line.count("|") > 0:
            local_count+= len(line.split("|")[2])
        else:
            local_count+= len(line)
    
    if classification== "TP" or classification== "FP":
        flagged_character_count = local_count
        
    return local_count, flagged_character_count

def process_russel():
    windows = [
               (datetime(2022, 1, 23, 7, 45, 0, 0),datetime(2022, 1, 23, 8, 0, 0, 0)), # Apache access log
               (datetime(2022, 1, 23, 10, 55, 0, 0),datetime(2022, 1, 23, 11, 10, 0, 0)), #lot of dns in every file
               (datetime(2022, 1, 24, 3, 45, 0, 0),datetime(2022, 1, 24, 4, 0, 0, 0)), # Apache error log & VPN
               (datetime(2022, 1, 21, 6, 20, 0, 0),datetime(2022, 1, 21, 6, 35, 0, 0)), #Suricata
               (datetime(2022, 1, 24, 1, 5, 0, 0),datetime(2022, 1, 24, 1, 20, 0, 0)), #Internal share audit
               (datetime(2022, 1, 23, 5, 3, 0, 0),datetime(2022, 1, 23, 5, 18, 0, 0)), #syslog
               ]
    # start_time = datetime(2022, 1, 21, 0, 0, 0, 0)
    # end_time = datetime(2022, 1, 25, 0, 0, 0, 0)
    # start_time = datetime(2022, 1, 23, 11, 00, 0, 0)
    # end_time = datetime(2022, 1, 23, 11, 10, 0, 0)
    
    step_minutes=10
    overlap_minutes=1
    max_batch_size=20
    overlap_percentage = 0.1
    
    # model_name = "mistral-nemo:latest"
    # model_name = "gemma3:12b"
    # model_name = "llama3.1:8b"
    # model_name = "qwen2.5-coder:14b"
    
    multihost = True #todo da controllare singlehost perchè sono molte meno batch?
    
    current_time = datetime.now()
    current_time = current_time.strftime("%Y%m%d_%H%M%S")
    model_output_dir_base = f"./model_output/model_output_{current_time}"    
    



    
    sys_prompt_SOC = 'You are part of a SOC team triaging log files. Your job is to flag logs that merit deeper investigation. Read the following logs and return this formatted JSON: {"malicious": "True|False", "reason": "Only if malicious is true"}.  Consider patterns such as failed logins, unusual access times, use of rare commands, suspicious IPs, etc. False negatives are worse than false positives in this context, but do not trigger on generic system noise or normal operations. Keep the threshold tuned for catching real threats without overwhelming responders. Output only the JSON.'
    
    sys_prompt_threat_hunting = 'Act as a threat hunter analyzing a batch of logs for early indicators of compromise. Review the logs carefully and decide whether there is any evidence suggesting malicious activity or behavior requiring further investigation. Return only a JSON like this: {"malicious": "True|False", "reason": "Only if malicious is true"}. Aim to catch as many real threats as possible (low false negatives), but avoid flagging benign activity unless there are clear signs of compromise. Keep your detection conservative but sensitive. If flagged as malicious, explain briefly why.'
    
    sys_prompt_cybersec_exp = 'You are a cybersecurity expert. You have received a batch of logs which you will analyze with great scrutiny and decide wheater they contain possible malicious activity and must be further investigated or not. Your output must be in JSON, following this format: {"malicious": "True|False", "reason": "Only if malicious is true"}. If the batch contains suspicious logs you must provide your reasoning. Output only the JSON.'
    
    sys_prompt_SOC_for_rag = 'You are part of a SOC team triaging log files. Your job is to flag logs that merit deeper investigation. Read the following logs and return: {"malicious": "True|False", "query": "Only if malicious is true"}. If you find the batch suspicious, provide a description of it in the query field of the JSON response. Consider patterns such as failed logins, unusual access times, use of rare commands, suspicious IPs, etc. False negatives are worse than false positives in this context, but do not trigger on generic system noise or normal operations. Keep the threshold tuned for catching real threats without overwhelming responders.'
    
    sys_prompt_threat_hunting_for_rag = 'Act as a threat hunter analyzing a batch of logs for early indicators of compromise. Review the logs carefully and decide whether there is any evidence suggesting malicious activity or behavior requiring further investigation. Return only a JSON like this: {"malicious": "True|False", "query": "Only if malicious is true"}. If you find the batch suspicious, provide a description of it in the query field of the JSON response. Aim to catch as many real threats as possible (low false negatives), but avoid flagging benign activity unless there are clear signs of compromise. Keep your detection conservative but sensitive. If flagged as malicious, explain briefly why.'
    
    sys_prompt_cybersec_exp_for_rag = 'You are a cybersecurity expert. You have received a batch of logs which you will analyze with great scrutiny and decide wheater they contain possible malicious activity and must be further investigated or not. Your output must be in JSON, following this format: {"malicious": "True|False", "query": "Only if malicious is true"}. If you find the batch suspicious, provide a description of it in the query field of the JSON response. Output only the JSON.'

    #RAG
    
    sys_prompt_SOC_rag = 'You are part of a SOC team triaging log files. Your job is to flag logs that merit deeper investigation. Read the following logs and an entry from MITRE ATT&CK database and return this formatted JSON: {"malicious": "True|False", "reason": "Only if malicious is true", "mitigation": "Some steps to take in order to protect against the identified threat"}. Consider patterns such as failed logins, unusual access times, use of rare commands, suspicious IPs, etc. False negatives are worse than false positives in this context, but do not trigger on generic system noise or normal operations. Keep the threshold tuned for catching real threats without overwhelming responders. Output only the JSON.'
    
    sys_prompt_threat_hunting_rag = 'Act as a threat hunter analyzing a batch of logs for early indicators of compromise. You have also received a possible match from MITRE ATT&CK database. Review the logs carefully and decide whether there is any evidence suggesting malicious activity or behavior requiring further investigation. Return only a JSON like this: {"malicious": "True|False", "reason": "Only if malicious is true"}. Aim to catch as many real threats as possible (low false negatives), but avoid flagging benign activity unless there are clear signs of compromise. Keep your detection conservative but sensitive. If flagged as malicious, explain briefly why.'
    
    sys_prompt_cybersec_exp_rag = 'You are a cybersecurity expert. You have received a batch of logs and a possible classification by MITRE ATT&CK database. You will analyze the logs with great scrutiny and decide wheater they contain possible malicious activity and must be further investigated or not. Your output must be in JSON, following this format: {"malicious": "True|False", "reason": "Only if malicious is true"}. If the batch contains suspicious logs you must provide your reasoning. Output only the JSON.'

    for multihost in [True]:
        for rag in [True]:
            if rag:
                prompt_main = sys_prompt_SOC_for_rag
                prompt_rag = sys_prompt_SOC_rag
            else:
                prompt_main = sys_prompt_SOC
                prompt_rag = ""
            
            print(f"Processing with multihost={multihost} and rag={rag}")
            for model_name in ["gemma3:12b"]:
                
                i = 0
                batch_counter = 0
                malformed_counter = 0
                total_character_count = 0 
                total_flagged_character_count=0  
                
                running_f1_sum = 0
                running_accuracy_sum = 0
                running_precision_sum = 0
                running_recall_sum = 0
                count_f1 = 0
                count_accuracy = 0
                count_precision = 0
                count_recall = 0
            
                model_output_dir = os.path.join(model_output_dir_base, f"{model_name.split(':')[0]}_multihost_{multihost}_rag_{rag}")
                
                print(f"Processing model: {model_name}")
                os.makedirs(model_output_dir, exist_ok=True)
                
                for start_time , end_time in windows:
                    
                    st_t = time.perf_counter()
                    confusion_dict_by_label = {}
                    confusion_dict = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}

                    output_file = os.path.join(model_output_dir, f"model_output_{start_time}-{end_time}.txt")
                    for current_time in minute_range(start_time, end_time, step_minutes):
                        batch_list=prepare_batches_russell(reference_time=current_time,
                                                lookback_minutes=step_minutes,
                                                batch_size=max_batch_size,
                                                overlap_minutes=overlap_minutes,
                                                overlap_percentage=overlap_percentage,
                                                multihost=multihost)
                        batch_counter += len(batch_list)
                        for batch in batch_list:
                            # print(batch)
                            
                            start_time = time.perf_counter()
                            response, json_content = model_call(model_name,batch.get_batch_as_string(), rag=rag,sys_prompt=prompt_main, sys_prompt_rag=prompt_rag)
                            end_time = time.perf_counter()
                            
                            time_taken = end_time - start_time
                            
                            print(f"Processed batch: {i}")
                            print(f"Time taken for model call: {time_taken:.2f} seconds\n")
                            
                            if response == -1:
                                malformed_counter += 1
                                i+=1
                                continue
                            
                            save_model_output(batch, json_content, output_file)
                            
                            classification = check_model_output(batch, json_content)
                            if classification == -1:
                                malformed_counter += 1
                                i+=1
                                continue
                            confusion_dict[classification] += 1
                            
                            for label in batch.labels:
                                if label not in confusion_dict_by_label:
                                    confusion_dict_by_label[label] = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
                                confusion_dict_by_label[label][classification] += 1
                                
                            
                            character_count, flagged_character_count = calculate_character_counter(classification=classification, batch=batch)

                            total_character_count += character_count
                            total_flagged_character_count += flagged_character_count
                            
                        
                            i+=1
                        #     if i > 10:
                        #         break
                        # if i>10:
                        #     break

                
                    en_t = time.perf_counter()
                    
                    time_elapsed = en_t - st_t
                    
                    
                    if total_character_count != 0:
                        flagged_characters_percentage=total_flagged_character_count/total_character_count*100
                    else:
                        flagged_characters_percentage = -1

                    save_final_result(output_file=output_file, confusion_dict=confusion_dict, time_elapsed=time_elapsed, 
                                                batch_counter=batch_counter, malformed_counter=malformed_counter,
                                                flagged_characters_percentage=flagged_characters_percentage,
                                                confusion_dict_by_label=confusion_dict_by_label,
                                                system_prompt_main=prompt_main,
                                                system_prompt_rag=prompt_rag,
                                                model_name=model_name,
                                                multihost=multihost,
                                                rag_embedding="bge-m3:latest")
                    accuracy, precision, recall, f1 = calculate_metrics(confusion_dict=confusion_dict)
                    
                    if f1 >= 0:
                        running_f1_sum += f1
                        count_f1 +=1
                    if accuracy>=0:
                        running_accuracy_sum += accuracy
                        count_accuracy += 1
                    if precision>=0:
                        running_precision_sum += precision
                        count_precision += 1
                    if recall>=0:
                        running_recall_sum += recall
                        count_recall += 1
                        
                    batch_counter = 0
                    malformed_counter = 0
                    total_character_count = 0
                    total_flagged_character_count=0
                    # if i>10:
                    #     break
                
                
                with open(os.path.join(model_output_dir, "merged_metrics.txt"), "w") as f:
                    f.write(f"Model: {model_name}\n")
                    f.write(f"Multihost: {multihost}\n")
                    f.write(f"RAG: {rag}\n")
                    f.write(f"Average F1: {running_f1_sum/count_f1:.2f}\n")
                    f.write(f"Average Accuracy: {running_accuracy_sum/count_accuracy:.2f}\n")
                    f.write(f"Average Precision: {running_precision_sum/count_precision:.2f}\n")
                    f.write(f"Average Recall: {running_recall_sum/count_recall:.2f}\n")
                    f.flush()
                    f.close()
                    
                os.rename(model_output_dir, f"{model_output_dir}_f1_{running_f1_sum/count_f1:.2f}")
            
            # if i>10:
            #     break

def process_flow():
    sys_prompt_network_exp = 'You are a network traffic analyst. You have received a batch of aggregated packet information, called network flows, which you will analyze with great scrutiny and decide wheater they contain possible malicious activity and must be further investigated or not. Your output must be in JSON, following this format: {"malicious": "True|False", "reason": "Only if malicious is true"}. If the batch contains suspicious flows you must provide your reasoning. Output only the JSON.' 
    
    sys_prompt_SOC = 'You are part of a SOC team triaging aggregated packet information, called network flows. Your job is to flag flows that merit deeper investigation. Read the following flows and return this formatted JSON: {"malicious": "True|False", "reason": "Only if malicious is true"}. Consider patterns indicating common attacks such as high number of connections with low packet rate, repeated connections from the same IP, long flows with very low data transfer, frequent resets or SYN-only flows, unbalanced down/up ratios, spikes in small packet sizes, unusual use of TCP flags etc. False negatives are worse than false positives in this context, but do not trigger on generic network noise or normal operations. Keep the threshold tuned for catching real threats without overwhelming responders. Output only the JSON.'
    
    sys_prompt_threat_hunting = 'Act as a threat hunter analyzing a batch of aggregated packet information, called network flows, for early indicators of compromise. Review the logs carefully and decide whether there is any evidence suggesting malicious activity or behavior requiring further investigation. Return only a JSON in this format: {"malicious": "True|False", "reason": "Only if malicious is true"}. Aim to catch as many real threats as possible (low false negatives), but avoid flagging benign activity unless there are clear signs of compromise. Keep your detection conservative but sensitive. If flagged as malicious, explain briefly why.'
    
    sys_prompt_threat_hunting_for_rag = 'Act as a threat hunter analyzing a batch of aggregated packet information, called network flows, for early indicators of compromise. Review the logs carefully and decide whether there is any evidence suggesting malicious activity or behavior requiring further investigation. Return only a JSON in this format: {"malicious": "True|False", "query": "Only if malicious is true"}. If you find the batch suspicious, provide a description of it in the query field of the JSON response. Aim to catch as many real threats as possible (low false negatives), but avoid flagging benign activity unless there are clear signs of compromise. Keep your detection conservative but sensitive.'
    
    sys_prompt_network_exp_for_rag = 'You are a network traffic analyst. You have received a batch of network flows which you will analyze with great scrutiny and decide wheater they contain possible malicious activity and must be further investigated or not. Your output must be in JSON, following this format: {"malicious": "True|False", "query": "Only if malicious is true"}. If you find the batch suspicious, provide a description of it in the query field of the JSON response. Output only the JSON.'
    
    sys_prompt_SOC_for_rag = 'You are part of a SOC team triaging aggregated packet information, called network flows. Your job is to flag flows that merit deeper investigation. Read the following flows and return: {"malicious": "True|False", "query": "Only if malicious is true"}. If you find the batch suspicious, provide a description of it in the query field of the JSON response. Consider patterns indicating common attacks such as high number of connections with low packet rate, repeated connections from the same IP, long flows with very low data transfer, frequent resets or SYN-only flows, unbalanced down/up ratios, spikes in small packet sizes, unusual use of TCP flags etc. False negatives are worse than false positives in this context, but do not trigger on generic network noise or normal operations. Keep the threshold tuned for catching real threats without overwhelming responders. Output only the JSON.'
    
    
    # RAG prompts
    
    sys_prompt_SOC_rag = 'You are part of a SOC team triaging aggregated packet information, called network flows. Your job is to flag flows that merit deeper investigation. Read the following flows and a possible linked entry from MITRE ATT&CK database and return this formatted JSON: {"malicious": "True|False", "reason": "Only if malicious is true"}. Consider patterns indicating common attacks such as high number of connections with low packet rate, repeated connections from the same IP, long flows with very low data transfer, frequent resets or SYN-only flows, unbalanced down/up ratios, spikes in small packet sizes, unusual use of TCP flags etc. False negatives are worse than false positives in this context, but do not trigger oon generic network noise or normal operations. Keep the threshold tuned for catching real threats without overwhelming responders. Output only the JSON.'
    
    sys_prompt_threat_hunting_rag = 'Act as a threat hunter analyzing a batch of aggregated packet information, called network flows, for early indicators of compromise. You have also received a possible match from MITRE ATT&CK database. Review the flows carefully and decide whether there is any evidence suggesting malicious activity or behavior requiring further investigation. Return only a JSON in this format: {"malicious": "True|False", "reason": "Only if malicious is true"}. Aim to catch as many real threats as possible (low false negatives), but avoid flagging benign activity unless there are clear signs of compromise. Keep your detection conservative but sensitive. If flagged as malicious, explain briefly why.'
    
    sys_prompt_network_exp_rag = 'You are a network traffic analyst. You have received a batch of logs and a possible classification by MITRE ATT&CK database. You will analyze the logs with great scrutiny and decide wheater they contain possible malicious activity and must be further investigated or not. Your output must be in JSON, following this format: {"malicious": "True|False", "reason": "Only if malicious is true"}. If the batch contains suspicious logs you must provide your reasoning. Output only the JSON.'
    
    num_batches = 500
    max_batch_size = 10
    max_benign_percentage = 0.4
    
    #model_name = "mistral-nemo:latest"
    #model_name = "gemma3:12b"
    
    current_time = datetime.now()
    current_time = current_time.strftime("%Y%m%d_%H%M%S")
    model_output_dir_base = f"./model_output_flow/model_output_{current_time}"  
     
    for rag in [False, True]:
        for p in [2]:
            if p == 1:
                if rag:
                    prompt_main = sys_prompt_SOC_for_rag
                    prompt_rag = sys_prompt_SOC_rag
                else:
                    prompt_main = sys_prompt_SOC
                    prompt_rag = ""
                prompt_name = "sys_prompt_SOC"
            elif p == 2:
                if rag:
                    prompt_main = sys_prompt_threat_hunting_for_rag
                    prompt_rag = sys_prompt_threat_hunting_rag
                else:
                    prompt_main = sys_prompt_threat_hunting
                    prompt_rag = ""
                prompt_name = "sys_prompt_threat_hunting"
            elif p == 3:
                if rag:
                    prompt_main = sys_prompt_network_exp_for_rag
                    prompt_rag = sys_prompt_network_exp_rag
                else:
                    prompt_main = sys_prompt_network_exp
                    prompt_rag = ""
                prompt_name = "sys_prompt_network_exp"
        
            for model_name in ["llama3.1:8b"]:

                current_time = datetime.now()
                current_time = current_time.strftime("%Y%m%d_%H%M%S")
                model_output_dir = f"./model_output_flow/"    
                
                os.makedirs(model_output_dir, exist_ok=True)

                i = 0
                batch_counter = 0
                malformed_counter = 0
                total_character_count = 0 
                total_flagged_character_count=0  
            
                model_output_dir = os.path.join(model_output_dir_base, f"{model_name.split(':')[0]}_rag_{rag}_prompt_{prompt_name}")
                
                print(f"Processing model: {model_name}")
                os.makedirs(model_output_dir, exist_ok=True)
                                    
                st_t = time.perf_counter()
                confusion_dict_by_label = {}
                confusion_dict = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}

                output_file = os.path.join(model_output_dir, f"model_output.txt")
                if not os.path.exists(os.path.join("pickled_batches_flow", "batches_flow.pkl")):
                    prepare_batches_flow(num_batches=num_batches, batch_size=max_batch_size, max_benign_percentage=max_benign_percentage)
                batch_list = pickle.load(open(os.path.join("pickled_batches_flow", "batches_flow.pkl"), "rb"))
                batch_counter += len(batch_list)
                for batch in batch_list:
                    # print(batch)
                    
                    start_time = time.perf_counter()
                    response, json_content = model_call(model_name,batch.get_batch_as_string(), rag=rag,sys_prompt=prompt_main, sys_prompt_rag=prompt_rag)
                    end_time = time.perf_counter()
                    
                    time_taken = end_time - start_time
                    
                    print(f"Processed batch: {i}")
                    print(f"Time taken for model call: {time_taken:.2f} seconds\n")
                    
                    if response == -1:
                        malformed_counter += 1
                        i+=1
                        continue
                    
                    save_model_output(batch, json_content, output_file)
                    
                    classification = check_model_output(batch, json_content)
                    if classification == -1:
                        malformed_counter += 1
                        i+=1
                        continue
                    confusion_dict[classification] += 1
                    
                    if batch.labels:
                        for label in batch.labels:
                            if label not in confusion_dict_by_label:
                                confusion_dict_by_label[label] = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
                            confusion_dict_by_label[label][classification] += 1
                    else:
                        if "benign" not in confusion_dict_by_label:
                            confusion_dict_by_label["benign"] = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
                        confusion_dict_by_label["benign"][classification] += 1

                    character_count, flagged_character_count = calculate_character_counter(classification=classification, batch=batch)

                    total_character_count += character_count
                    total_flagged_character_count += flagged_character_count
                    
                
                    i+=1
                    # if i > 2:
                    #     break


            
                en_t = time.perf_counter()
                
                time_elapsed = en_t - st_t
                
                
                if total_character_count != 0:
                    flagged_characters_percentage=total_flagged_character_count/total_character_count*100
                else:
                    flagged_characters_percentage = -1

                save_final_result(output_file=output_file, confusion_dict=confusion_dict, time_elapsed=time_elapsed, 
                                            batch_counter=batch_counter, malformed_counter=malformed_counter,
                                            flagged_characters_percentage=flagged_characters_percentage,
                                            confusion_dict_by_label=confusion_dict_by_label,
                                            system_prompt_main=prompt_main,
                                            system_prompt_rag=prompt_rag,
                                            model_name=model_name,
                                            multihost="",
                                            rag_embedding="bge-m3:latest")
                accuracy, precision, recall, f1 = calculate_metrics(confusion_dict=confusion_dict)
                        
                batch_counter = 0
                malformed_counter = 0
                total_character_count = 0
                total_flagged_character_count=0

                
                os.rename(model_output_dir, f"{model_output_dir}_f1_{f1:.2f}")
            #     if i>2:
            #         break
        
            # if i>2:
            #     break


if __name__ == "__main__": 
    
    process_russel()

        
    
    


    
