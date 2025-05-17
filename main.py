from datetime import datetime
from prepocessing import prepare_batches
from model import model_call
if __name__ == "__main__":
    current_time = datetime(2022, 1, 20, 11, 15, 0, 0)
    batch_list=prepare_batches(current_time,1,10,True)
    
    # print(len(batch_list))
    # for batch in batch_list:
    #         print(batch)
    #         print("\n\n")
    for batch in batch_list:
        model_call("llama3.1",batch)
        print("\n")
        
    # model_call("llama3.1", "ciaooo")