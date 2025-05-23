from datetime import timedelta, datetime
from prepocessing import prepare_batches, Batch
from model import model_call
import json
import os

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
            raise Exception("Errore nella conversione in bool") 
    return json_value        

def print_confusion_matrix(confusion_dict):
    #confusion_dict = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
    print("Confusion Matrix:")
    print("\tTP\tTN\tFP\tFN")
    print(f"\t{confusion_dict['TP']}\t{confusion_dict['TN']}\t{confusion_dict['FP']}\t{confusion_dict['FN']}")

def check_model_output(batch, model_output):
    malicious = model_output.get("malicious")
    malicious = convert_to_bool(malicious)
    print(f"malicious: {malicious}")
    print(f"malicious type: {type(malicious)}")
    print(f"labels: {batch.labels}") 
    print(f"labels_present: {batch.labels}") 
    if (batch.labels) and (malicious == True):
        print("TP\n")
        return "TP"
    elif (not batch.labels) and (malicious == False):
        print("TN\n")
        return "TN"
    elif (batch.labels) and (malicious == False):
        print("FN\n")
        return "FN"
    else:
        print("FP\n")
        return "FP"
        
def save_model_output(batch, model_output):
    malicious = model_output.get("malicious")
    if malicious:
        reason = model_output.get("reason")
        with open(os.path.join(model_output_dir,model_output_file), "a") as out_file:
            out_file.write(str(batch))
            out_file.write(f"\nMalicious:{malicious}\nReason:{reason}\n\n")

if __name__ == "__main__":
    # start_time = datetime(2022, 1, 21, 0, 0, 0, 0)
    # end_time = datetime(2022, 1, 25, 0, 0, 0, 0)
    start_time = datetime(2022, 1, 23, 11, 00, 0, 0)
    end_time = datetime(2022, 1, 23, 11, 10, 0, 0)
    
    step_minutes=10
    overlap_minutes=1
    max_batch_size=20
    overlap_percentage = 0.1
    
    model_output_dir = "./model_output"
    model_output_file = "model_output.txt"    
    
    confusion_dict = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
    
    os.makedirs(model_output_dir, exist_ok=True)
    if os.path.exists(os.path.join(model_output_dir,model_output_file)):
        os.remove(os.path.join(model_output_dir,model_output_file))
    
    batch_counter = 0
    malformed_counter = 0  
    i = 0  
    for current_time in minute_range(start_time, end_time, step_minutes):
        batch_list=prepare_batches(reference_time=current_time,
                                   lookback_minutes=step_minutes,
                                   batch_size=max_batch_size,
                                   overlap_minutes=overlap_minutes,
                                   overlap_percentage=overlap_percentage,
                                   multihost=True)
        batch_counter += len(batch_list)
        print(len(batch_list))
        for batch in batch_list:
            print(batch)
    #         response, json_content = model_call("qwen2.5-coder:14b",batch.get_batch_as_string())
    #         if response == -1:
    #             malformed_counter += 1
    #             continue
    #         json_content = convert_to_bool(json_content)
    #         save_model_output(batch, json_content)
    #         confusion_dict[check_model_output(batch, json_content)] += 1
    #         i+=1
    #         if i > 10:
    #             break
    #     if i>10:
    #         break

            

    print_confusion_matrix(confusion_dict)
    print(f"Number of Batches: {batch_counter}")
    print(f"Malformed outputs: {malformed_counter}")


    
    # batches = prepare_batches(dt2,10,10,True)
    # print("Finished batching")
    
    #todo encapsulate in a for each
    
    # response=model_call("llama3.1",batches[0].get_batch_as_string())
    # print(response.content) 
    

    
    # #todo try catch for malformed responses
    # response=test
    # json_response = json.loads(response)
    # classification = json_response.get("malicious")
    # print(f"Malicious: {classification}")
    # if classification.lower().strip() in ["true", "yes"]: #in case of strange behavior
    #     reason = json_response.get("reason")
    #     print(f"Reason: {reason}")
    #     with open(os.path.join(model_output_dir,model_output_file), "a") as out_file:
    #         out_file.write(str(batches[0]))
    #         out_file.write(f"\nMalicious:{classification}\n Reason:{reason}")
    

        
    
    


    
